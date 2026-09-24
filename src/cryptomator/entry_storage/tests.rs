use super::*;
use crate::core::{DirectoryContentLayout, NativeFileSystem, ReadAt, Utf8Path};
use tempfile::tempdir;

struct FixedDirectoryContentLayout {
    contents_path: VirtualPathBuf,
}

impl DirectoryContentLayout for FixedDirectoryContentLayout {
    fn detached_directory_contents_path(
        &self,
        _entry_path: &VirtualPath,
        _token: &[u8],
    ) -> crate::core::Result<VirtualPathBuf> {
        Ok(self.contents_path.clone())
    }

    fn is_detached_directory_contents_path(&self, path: &VirtualPath) -> bool {
        let mut components = path.components();
        matches!(components.next(), Some("d"))
            && components.next().is_some_and(|part| part.len() == 2)
            && components.next().is_some_and(|part| part.len() == 30)
            && components.next().is_none()
    }
}

impl DirectoryLayout for FixedDirectoryContentLayout {
    fn generate_directory_token(&self) -> Vec<u8> {
        b"12345678-1234-1234-1234-123456789abc".to_vec()
    }

    fn validate_directory_token(&self, token: &[u8], is_root: bool) -> crate::core::Result<()> {
        anyhow::ensure!(
            (is_root && token.is_empty()) || token.len() == 36,
            "expected an empty root token or a 36-byte token"
        );
        Ok(())
    }

    fn root_directory_token(&self) -> RootDirectoryToken {
        RootDirectoryToken::Implicit(Vec::new())
    }
}

/// Creates a native Cryptomator storage rooted in a temporary directory.
fn cryptomator_storage() -> (tempfile::TempDir, CryptomatorEntryStorage<NativeFileSystem>) {
    cryptomator_storage_with_threshold(DEFAULT_SHORTENING_THRESHOLD)
}

/// Creates a native Cryptomator storage with a custom shortening threshold.
fn cryptomator_storage_with_threshold(
    shortening_threshold: usize,
) -> (tempfile::TempDir, CryptomatorEntryStorage<NativeFileSystem>) {
    let temp_dir = tempdir().unwrap();
    let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
    (
        temp_dir,
        CryptomatorEntryStorage::with_options(
            NativeFileSystem::new(root),
            Arc::new(FixedDirectoryContentLayout {
                contents_path: child_contents_path(),
            }),
            CryptomatorEntryStorageOptions {
                shortening_threshold,
            },
        ),
    )
}

/// Returns a canonical-looking detached contents path for storage tests.
fn contents_path() -> VirtualPathBuf {
    "d/AB/ABCDEFGHIJKLMNOPQRSTUVWXYZ2345".into()
}

/// Returns a distinct contents location for a represented child directory.
fn child_contents_path() -> VirtualPathBuf {
    "d/CD/2345ABCDEFGHIJKLMNOPQRSTUVWXYZ".into()
}

#[test]
fn short_entries_are_classified_from_their_physical_representation() {
    let (_temp_dir, storage) = cryptomator_storage();
    let parent_contents = contents_path();
    storage.storage_fs.mkdir_all(&parent_contents).unwrap();
    let directory_path = parent_contents.join("encoded-directory");
    let symlink_path = parent_contents.join("encoded-link");

    let directory = storage
        .create_directory(
            directory_path.clone(),
            storage.generate_directory_token(),
            None,
        )
        .unwrap();
    assert!(directory.file_type == FileType::Directory);
    let symlink = storage.create_symlink(&symlink_path, b"target").unwrap();
    assert!(symlink.file_type == FileType::SymLink);

    let entries = storage
        .read_dir(parent_contents)
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert!(entries.iter().any(|entry| {
        entry.file_name == "encoded-directory" && entry.metadata.file_type == FileType::Directory
    }));
    assert!(entries.iter().any(|entry| {
        entry.file_name == "encoded-link" && entry.metadata.file_type == FileType::SymLink
    }));
}

#[test]
fn long_file_uses_and_validates_name_c9s() {
    let (_temp_dir, storage) = cryptomator_storage();
    let parent_contents = contents_path();
    storage.storage_fs.mkdir_all(&parent_contents).unwrap();
    let long_name = "a".repeat(DEFAULT_SHORTENING_THRESHOLD);
    let logical_path = parent_contents.join(&long_name);
    storage
        .create_file(&logical_path, b"ciphertext", None)
        .unwrap();

    let paths = storage.entry_paths(&logical_path);
    assert!(paths.is_shortened());
    assert!(storage.storage_fs.exists(&paths.entry).unwrap());
    assert_eq!(
        storage
            .storage_fs
            .read_all(&paths.entry.join(CRYPTOMATOR_NAME_FILE))
            .unwrap(),
        format!("{long_name}{CRYPTOMATOR_REGULAR_SUFFIX}").as_bytes()
    );

    let entries = storage
        .read_dir(parent_contents)
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_name, long_name);
    assert!(entries[0].metadata.file_type == FileType::File);

    let mut options = FileOpenOptions::default();
    options.read(true);
    let handle = storage.open_file_with(&logical_path, options).unwrap();
    let mut data = [0; 10];
    assert_eq!(handle.read_all_at(0, &mut data).unwrap(), data.len());
    assert_eq!(&data, b"ciphertext");

    storage
        .storage_fs
        .put(&paths.entry.join(CRYPTOMATOR_NAME_FILE), b"wrong.c9r")
        .unwrap();
    assert!(matches!(
        storage.metadata(&logical_path),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData
    ));
}

#[test]
fn read_dir_ignores_foreign_names_but_reports_malformed_entries() {
    let (_temp_dir, storage) = cryptomator_storage();
    let parent_contents = contents_path();
    storage.storage_fs.mkdir_all(&parent_contents).unwrap();
    storage
        .storage_fs
        .put(&parent_contents.join("sync-conflict"), b"foreign")
        .unwrap();

    let entries = storage
        .read_dir(parent_contents.clone())
        .unwrap()
        .collect::<Vec<_>>();
    assert!(entries.is_empty());

    storage
        .storage_fs
        .mkdir(&parent_contents.join("broken.c9s"), None)
        .unwrap();
    let entries = storage
        .read_dir(parent_contents)
        .unwrap()
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].is_err());
}

#[test]
fn long_directory_and_symlink_use_name_c9s() {
    let (_temp_dir, storage) = cryptomator_storage();
    let parent_contents = contents_path();
    storage.storage_fs.mkdir_all(&parent_contents).unwrap();
    let directory_path = parent_contents.join("d".repeat(DEFAULT_SHORTENING_THRESHOLD));
    let symlink_path = parent_contents.join("s".repeat(DEFAULT_SHORTENING_THRESHOLD));

    storage
        .create_directory(
            directory_path.clone(),
            storage.generate_directory_token(),
            None,
        )
        .unwrap();
    storage.create_symlink(&symlink_path, b"target").unwrap();

    for logical_path in [&directory_path, &symlink_path] {
        let paths = storage.entry_paths(logical_path);
        assert!(paths.is_shortened());
        assert!(
            storage
                .storage_fs
                .exists(&paths.entry.join(CRYPTOMATOR_NAME_FILE))
                .unwrap()
        );
    }
    assert!(storage.metadata(&directory_path).unwrap().file_type == FileType::Directory);
    assert!(storage.metadata(&symlink_path).unwrap().file_type == FileType::SymLink);
}

#[test]
fn directory_removal_removes_the_complete_shortened_representation() {
    let (_temp_dir, storage) = cryptomator_storage();
    let parent_contents = contents_path();
    storage.storage_fs.mkdir_all(&parent_contents).unwrap();
    let logical_path = parent_contents.join("d".repeat(DEFAULT_SHORTENING_THRESHOLD));
    storage
        .create_directory(
            logical_path.clone(),
            storage.generate_directory_token(),
            None,
        )
        .unwrap();
    let directory = storage.resolve_directory(&logical_path).unwrap();
    let token_backup = directory.contents_path.join(CRYPTOMATOR_DIR_ID_BACKUP_FILE);
    storage
        .storage_fs
        .put(&token_backup, &directory.token)
        .unwrap();

    storage.remove_directory(&directory).unwrap();

    assert!(!storage.storage_fs.exists(&directory.entry_path).unwrap());
    assert!(!storage.storage_fs.exists(&directory.contents_path).unwrap());
}

#[test]
fn directory_removal_preserves_representation_when_contents_are_not_empty() {
    let (_temp_dir, storage) = cryptomator_storage();
    let parent_contents = contents_path();
    storage.storage_fs.mkdir_all(&parent_contents).unwrap();
    let logical_path = parent_contents.join("directory");
    storage
        .create_directory(
            logical_path.clone(),
            storage.generate_directory_token(),
            None,
        )
        .unwrap();
    let directory = storage.resolve_directory(&logical_path).unwrap();
    let marker = directory.entry_path.join(CRYPTOMATOR_DIR_FILE);
    let unexpected = directory.contents_path.join("unexpected.c9r");
    storage.storage_fs.put(&unexpected, b"contents").unwrap();

    let error = storage.remove_directory(&directory).unwrap_err();

    assert_eq!(error.raw_os_error(), Some(libc::ENOTEMPTY));
    assert!(storage.storage_fs.exists(&directory.entry_path).unwrap());
    assert!(storage.storage_fs.exists(&directory.contents_path).unwrap());
    assert!(storage.storage_fs.exists(&marker).unwrap());
    assert!(storage.storage_fs.exists(&unexpected).unwrap());
}

#[test]
fn entry_removal_preserves_container_with_unexpected_contents() {
    let (_temp_dir, storage) = cryptomator_storage();
    let parent_contents = contents_path();
    storage.storage_fs.mkdir_all(&parent_contents).unwrap();
    let logical_path = parent_contents.join("s".repeat(DEFAULT_SHORTENING_THRESHOLD));
    storage.create_symlink(&logical_path, b"target").unwrap();
    let paths = storage.entry_paths(&logical_path);
    let symlink = paths.entry.join(CRYPTOMATOR_SYMLINK_FILE);
    let name = paths.entry.join(CRYPTOMATOR_NAME_FILE);
    let unexpected = paths.entry.join("unexpected");
    storage.storage_fs.put(&unexpected, b"contents").unwrap();

    let error = storage.remove_entry(&logical_path).unwrap_err();

    assert_eq!(error.raw_os_error(), Some(libc::ENOTEMPTY));
    assert!(storage.storage_fs.exists(&paths.entry).unwrap());
    assert!(storage.storage_fs.exists(&symlink).unwrap());
    assert!(storage.storage_fs.exists(&name).unwrap());
    assert!(storage.storage_fs.exists(&unexpected).unwrap());
}

#[test]
fn metadata_rejects_conflicting_container_markers() {
    let (_temp_dir, storage) = cryptomator_storage();
    let parent_contents = contents_path();
    storage.storage_fs.mkdir_all(&parent_contents).unwrap();
    let logical_path = parent_contents.join("encoded");
    storage.create_symlink(&logical_path, b"target").unwrap();
    let physical = storage.entry_paths(&logical_path).entry;
    storage
        .storage_fs
        .put(
            &physical.join(CRYPTOMATOR_DIR_FILE),
            b"12345678-1234-1234-1234-123456789abc",
        )
        .unwrap();

    assert!(matches!(
        storage.metadata(&logical_path),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData
    ));
}

#[test]
fn metadata_does_not_accept_entries_outside_a_contents_directory() {
    let (_temp_dir, storage) = cryptomator_storage();
    storage
        .storage_fs
        .mkdir(VirtualPath::new("outside"), None)
        .unwrap();
    storage
        .storage_fs
        .put(VirtualPath::new("outside/encoded.c9r"), b"ciphertext")
        .unwrap();

    assert!(
        storage
            .metadata(VirtualPath::new("outside/encoded"))
            .unwrap()
            .file_type
            == FileType::Other
    );
}

#[test]
fn rename_moves_files_across_the_shortening_boundary() {
    let (_temp_dir, storage) = cryptomator_storage();
    let parent_contents = contents_path();
    storage.storage_fs.mkdir_all(&parent_contents).unwrap();
    let short_path = parent_contents.join("short");
    let first_long_path = parent_contents.join("a".repeat(DEFAULT_SHORTENING_THRESHOLD));
    let second_long_path = parent_contents.join("b".repeat(DEFAULT_SHORTENING_THRESHOLD));

    storage
        .create_file(&short_path, b"ciphertext", None)
        .unwrap();
    storage.rename(&short_path, &first_long_path).unwrap();
    assert_eq!(
        storage
            .storage_fs
            .read_all(&storage.entry_paths(&first_long_path).contents_path())
            .unwrap(),
        b"ciphertext"
    );
    storage.rename(&first_long_path, &second_long_path).unwrap();
    storage.rename(&second_long_path, &short_path).unwrap();
    assert_eq!(
        storage
            .storage_fs
            .read_all(&storage.entry_paths(&short_path).contents_path())
            .unwrap(),
        b"ciphertext"
    );
    assert!(storage.metadata(&short_path).is_ok());
}

#[test]
fn custom_threshold_controls_shortening_and_name_validation() {
    const THRESHOLD: usize = 16;
    let (_temp_dir, storage) = cryptomator_storage_with_threshold(THRESHOLD);
    let parent_contents = contents_path();
    storage.storage_fs.mkdir_all(&parent_contents).unwrap();
    let direct_name_len = THRESHOLD - CRYPTOMATOR_REGULAR_SUFFIX.len();
    let direct_path = parent_contents.join("a".repeat(direct_name_len));
    let shortened_path = parent_contents.join("b".repeat(direct_name_len + 1));

    storage.create_file(&direct_path, b"direct", None).unwrap();
    storage
        .create_file(&shortened_path, b"shortened", None)
        .unwrap();

    assert!(!storage.entry_paths(&direct_path).is_shortened());
    assert!(storage.entry_paths(&shortened_path).is_shortened());
    let entries = storage
        .read_dir(parent_contents)
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .any(|entry| entry.file_name == direct_path.file_name().unwrap())
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.file_name == shortened_path.file_name().unwrap())
    );
}
