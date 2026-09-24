use super::*;
use crate::core::{DirectoryContentLayout, FileType, NativeFileSystem, Utf8Path};
use tempfile::tempdir;

struct DetachedTestLayout;

impl DirectoryContentLayout for DetachedTestLayout {
    fn detached_directory_contents_path(
        &self,
        _entry_path: &VirtualPath,
        _token: &[u8],
    ) -> crate::core::Result<VirtualPathBuf> {
        Ok("detached".into())
    }

    fn is_detached_directory_contents_path(&self, path: &VirtualPath) -> bool {
        path == VirtualPath::new("detached")
    }
}

impl DirectoryLayout for DetachedTestLayout {
    fn generate_directory_token(&self) -> Vec<u8> {
        vec![7; 16]
    }

    fn validate_directory_token(&self, token: &[u8], _is_root: bool) -> crate::core::Result<()> {
        anyhow::ensure!(token.len() == 16, "expected a 16-byte test token");
        Ok(())
    }

    fn root_directory_token(&self) -> RootDirectoryToken {
        RootDirectoryToken::Persisted
    }
}

/// Creates a native GoCryptFS storage rooted in a temporary directory.
fn gocryptfs_storage() -> (tempfile::TempDir, GoCryptFsEntryStorage<NativeFileSystem>) {
    let temp_dir = tempdir().unwrap();
    let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
    (
        temp_dir,
        GoCryptFsEntryStorage::with_directory_layout(
            NativeFileSystem::new(root),
            Arc::new(DetachedTestLayout),
        ),
    )
}

/// Creates a native storage that shortens names longer than 62 bytes.
fn short_name_storage() -> (tempfile::TempDir, GoCryptFsEntryStorage<NativeFileSystem>) {
    let temp_dir = tempdir().unwrap();
    let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
    let options = GoCryptFsEntryStorageOptions {
        long_name_max: GOCRYPTFS_MIN_LONG_NAME_MAX,
        raw64: true,
    };
    (
        temp_dir,
        GoCryptFsEntryStorage::with_options_and_directory_layout(
            NativeFileSystem::new(root),
            options,
            Arc::new(DetachedTestLayout),
        )
        .unwrap(),
    )
}

#[test]
fn gocryptfs_storage_materializes_directory_and_native_symlink() {
    let (_temp_dir, storage) = gocryptfs_storage();
    let root = storage.initialize_root_directory().unwrap();
    assert_eq!(root.token, vec![7; 16]);
    let entry_path = VirtualPathBuf::from("docs");
    let token = vec![7; 16];
    let metadata = storage
        .create_directory(entry_path.clone(), token.clone(), None)
        .unwrap();
    assert!(metadata.file_type == FileType::Directory);
    let directory = storage.resolve_directory(&entry_path).unwrap();
    assert_eq!(directory.entry_path, entry_path);
    assert_eq!(directory.contents_path, directory.entry_path);
    assert_eq!(directory.token, token);

    let metadata = storage
        .create_symlink(VirtualPath::new("link"), b"docs")
        .unwrap();
    assert!(metadata.file_type == FileType::SymLink);
    assert_eq!(
        storage.read_symlink(VirtualPath::new("link")).unwrap(),
        b"docs"
    );

    storage
        .storage_fs
        .put(VirtualPath::new("gocryptfs.conf"), b"internal")
        .unwrap();
    let entries = storage
        .read_dir(VirtualPathBuf::default())
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(entries.len(), 2);

    storage.remove_entry(VirtualPath::new("link")).unwrap();
    assert!(storage.storage_fs.metadata("link".into()).is_err());

    storage
        .storage_fs
        .put(VirtualPath::new("file"), b"contents")
        .unwrap();
    storage.remove_entry(VirtualPath::new("file")).unwrap();
    assert!(storage.storage_fs.metadata("file".into()).is_err());

    storage.remove_directory(&directory).unwrap();
    assert!(storage.storage_fs.metadata(&directory.entry_path).is_err());
}

#[test]
fn long_file_name_uses_content_and_sidecar_entries() {
    let (_temp_dir, storage) = short_name_storage();
    let logical_name = "encoded-name".repeat(8);
    let logical_path = VirtualPath::new(&logical_name);
    let paths = storage.entry_paths(logical_path);
    let expected_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(logical_name.as_bytes()));
    let expected_name = format!("{GOCRYPTFS_LONGNAME_PREFIX}{expected_hash}");
    assert_eq!(paths.content.file_name(), Some(expected_name.as_str()));

    storage
        .create_file(logical_path, b"contents", None)
        .unwrap();

    let mut open_options = crate::core::FileOpenOptions::default();
    open_options.read(true);
    storage.open_file_with(logical_path, open_options).unwrap();
    storage
        .set_permissions(logical_path, 0o600_u16.into())
        .unwrap();
    assert!(storage.storage_fs.exists(&paths.content).unwrap());
    let sidecar = paths.sidecar.unwrap();
    assert_eq!(
        storage.storage_fs.read_all(&sidecar).unwrap(),
        logical_name.as_bytes()
    );
    let entries = storage
        .read_dir(VirtualPathBuf::default())
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_name, logical_name);
    assert_eq!(entries[0].path, paths.content);

    storage.remove_entry(logical_path).unwrap();
    assert!(!storage.storage_fs.exists(&paths.content).unwrap());
    assert!(!storage.storage_fs.exists(&sidecar).unwrap());
}

#[test]
fn failed_long_file_recreation_preserves_existing_entry() {
    let (_temp_dir, storage) = short_name_storage();
    let logical_name = "encoded-name".repeat(8);
    let logical_path = VirtualPath::new(&logical_name);
    let paths = storage.entry_paths(logical_path);
    storage
        .create_file(logical_path, b"original", None)
        .unwrap();

    assert!(
        storage
            .create_file(logical_path, b"replacement", None)
            .is_err()
    );

    assert_eq!(
        storage.storage_fs.read_all(&paths.content).unwrap(),
        b"original"
    );
    assert_eq!(
        storage
            .storage_fs
            .read_all(&paths.sidecar.unwrap())
            .unwrap(),
        logical_name.as_bytes()
    );
}

#[test]
fn long_directory_name_resolves_to_its_content_entry() {
    let (_temp_dir, storage) = short_name_storage();
    storage.initialize_root_directory().unwrap();
    let logical_name = "encoded-directory".repeat(6);
    let logical_path = VirtualPath::new(&logical_name);
    let paths = storage.entry_paths(logical_path);
    let token = vec![7; 16];

    storage
        .create_directory(logical_path.to_owned(), token.clone(), None)
        .unwrap();
    let directory = storage.resolve_directory(logical_path).unwrap();

    assert_eq!(directory.entry_path, paths.content);
    assert_eq!(directory.contents_path, paths.content);
    assert_eq!(directory.token, token);
    storage.remove_directory(&directory).unwrap();
    assert!(!storage.storage_fs.exists(&paths.content).unwrap());
    assert!(!storage.storage_fs.exists(&paths.sidecar.unwrap()).unwrap());
}

#[test]
fn directory_removal_preserves_long_entry_when_directory_is_not_empty() {
    let (_temp_dir, storage) = short_name_storage();
    storage.initialize_root_directory().unwrap();
    let logical_name = "encoded-directory".repeat(6);
    let logical_path = VirtualPath::new(&logical_name);
    let paths = storage.entry_paths(logical_path);
    storage
        .create_directory(logical_path.to_owned(), vec![7; 16], None)
        .unwrap();
    let directory = storage.resolve_directory(logical_path).unwrap();
    let marker = paths.content.join(GOCRYPTFS_DIRIV);
    let unexpected = paths.content.join("unexpected");
    let sidecar = paths.sidecar.unwrap();
    storage.storage_fs.put(&unexpected, b"contents").unwrap();

    let error = storage.remove_directory(&directory).unwrap_err();

    assert_eq!(error.raw_os_error(), Some(libc::ENOTEMPTY));
    assert!(storage.storage_fs.exists(&paths.content).unwrap());
    assert!(storage.storage_fs.exists(&marker).unwrap());
    assert!(storage.storage_fs.exists(&sidecar).unwrap());
    assert!(storage.storage_fs.exists(&unexpected).unwrap());
}

#[test]
fn rename_updates_long_name_sidecars_across_name_lengths() {
    let (_temp_dir, storage) = short_name_storage();
    let short_path = VirtualPath::new("short");
    let first_long_name = "first-long-name".repeat(6);
    let first_long_path = VirtualPath::new(&first_long_name);
    let second_long_name = "second-long-name".repeat(6);
    let second_long_path = VirtualPath::new(&second_long_name);
    let final_path = VirtualPath::new("final");

    storage.create_file(short_path, b"contents", None).unwrap();
    storage.rename(short_path, first_long_path).unwrap();
    let first_paths = storage.entry_paths(first_long_path);
    assert!(storage.storage_fs.exists(&first_paths.content).unwrap());
    assert!(
        storage
            .storage_fs
            .exists(&first_paths.sidecar.unwrap())
            .unwrap()
    );

    storage.rename(first_long_path, second_long_path).unwrap();
    let second_paths = storage.entry_paths(second_long_path);
    assert!(!storage.storage_fs.exists(&first_paths.content).unwrap());
    assert!(storage.storage_fs.exists(&second_paths.content).unwrap());
    assert!(
        !storage
            .storage_fs
            .exists(&storage.entry_paths(first_long_path).sidecar.unwrap())
            .unwrap()
    );

    storage.rename(second_long_path, final_path).unwrap();
    assert!(storage.storage_fs.exists(final_path).unwrap());
    assert!(!storage.storage_fs.exists(&second_paths.content).unwrap());
    assert!(
        !storage
            .storage_fs
            .exists(&second_paths.sidecar.unwrap())
            .unwrap()
    );
}

#[test]
fn rename_reuses_an_existing_matching_destination_sidecar() {
    let (_temp_dir, storage) = short_name_storage();
    let source_name = "source-long-name".repeat(6);
    let destination_name = "destination-long-name".repeat(6);
    let source = VirtualPath::new(&source_name);
    let destination = VirtualPath::new(&destination_name);
    let source_paths = storage.entry_paths(source);
    let destination_paths = storage.entry_paths(destination);

    storage.create_file(source, b"source", None).unwrap();
    storage
        .create_file(destination, b"destination", None)
        .unwrap();
    storage.rename(source, destination).unwrap();

    assert!(!storage.storage_fs.exists(&source_paths.content).unwrap());
    assert!(
        !storage
            .storage_fs
            .exists(&source_paths.sidecar.unwrap())
            .unwrap()
    );
    assert_eq!(
        storage
            .storage_fs
            .read_all(&destination_paths.content)
            .unwrap(),
        b"source"
    );
    assert_eq!(
        storage
            .storage_fs
            .read_all(&destination_paths.sidecar.unwrap())
            .unwrap(),
        destination_name.as_bytes()
    );
}

#[test]
fn long_symlink_name_maps_all_operations_to_content_entry() {
    let (_temp_dir, storage) = short_name_storage();
    let logical_name = "encoded-link".repeat(8);
    let logical_path = VirtualPath::new(&logical_name);
    let paths = storage.entry_paths(logical_path);

    storage.create_symlink(logical_path, b"target").unwrap();

    assert_eq!(storage.read_symlink(logical_path).unwrap(), b"target");
    assert!(storage.metadata(logical_path).unwrap().file_type == FileType::SymLink);
    storage.remove_entry(logical_path).unwrap();
    assert!(!storage.storage_fs.exists(&paths.content).unwrap());
    assert!(!storage.storage_fs.exists(&paths.sidecar.unwrap()).unwrap());
}

#[test]
fn padded_hashes_and_minimum_name_length_are_configurable() {
    let temp_dir = tempdir().unwrap();
    let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
    let invalid = GoCryptFsEntryStorageOptions {
        long_name_max: GOCRYPTFS_MIN_LONG_NAME_MAX - 1,
        raw64: true,
    };
    assert!(
        GoCryptFsEntryStorage::with_options(NativeFileSystem::new(root.clone()), invalid).is_err()
    );

    let padded = GoCryptFsEntryStorageOptions {
        long_name_max: GOCRYPTFS_MIN_LONG_NAME_MAX,
        raw64: false,
    };
    let storage = GoCryptFsEntryStorage::with_options(NativeFileSystem::new(root), padded).unwrap();
    let logical_name = "long-name".repeat(8);
    let paths = storage.entry_paths(VirtualPath::new(&logical_name));

    assert!(paths.content.file_name().unwrap().ends_with('='));
}
