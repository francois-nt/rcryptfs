use super::CryptoMator;
use crate::core::{
    DirectoryContentLayout, DirectoryLayout, EncryptionLayout, EncryptionTranslator, EntryStorage,
    EntryStorageBackend, OrIoError, PathCacheAccess, PathLayout, Result, RootDirectoryToken,
    VirtualPath, VirtualPathBuf, default_remove_cached_plain_path,
};

/// Canonical Cryptomator directory policy derived from the SIV key.
pub(super) struct CryptomatorDirectoryLayout {
    siv_key: [u8; 64],
}

impl CryptomatorDirectoryLayout {
    /// Creates the canonical directory policy from derived key material.
    pub(super) fn new(siv_key: [u8; 64]) -> Self {
        Self { siv_key }
    }
}

/// Returns whether a path has the canonical Cryptomator contents shape.
fn is_canonical_contents_path(path: &VirtualPath) -> bool {
    let mut components = path.components();
    let Some("d") = components.next() else {
        return false;
    };
    let Some(prefix) = components.next() else {
        return false;
    };
    let Some(suffix) = components.next() else {
        return false;
    };
    components.next().is_none()
        && prefix.len() == 2
        && suffix.len() == 30
        && prefix
            .bytes()
            .chain(suffix.bytes())
            .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
}

impl DirectoryContentLayout for CryptomatorDirectoryLayout {
    fn detached_directory_contents_path(
        &self,
        _entry_path: &VirtualPath,
        token: &[u8],
    ) -> Result<VirtualPathBuf> {
        super::inner::dir_id_to_storage_path(&self.siv_key, str::from_utf8(token)?)
    }

    fn is_detached_directory_contents_path(&self, path: &VirtualPath) -> bool {
        is_canonical_contents_path(path)
    }
}

impl DirectoryLayout for CryptomatorDirectoryLayout {
    fn generate_directory_token(&self) -> Vec<u8> {
        uuid::Uuid::new_v4().to_string().into_bytes()
    }

    fn validate_directory_token(&self, token: &[u8], is_root: bool) -> Result<()> {
        if is_root && token.is_empty() {
            return Ok(());
        }
        uuid::Uuid::parse_str(str::from_utf8(token)?)?;
        Ok(())
    }

    fn root_directory_token(&self) -> RootDirectoryToken {
        RootDirectoryToken::Implicit(Vec::new())
    }
}

/// Resolves a plain folder path to its storage directory and dir id.
fn folder_path_to_cipher_and_dirid<S>(
    this: &CryptoMator<EntryStorageBackend<S>>,
    plain_path: &VirtualPath,
) -> Result<(VirtualPathBuf, Vec<u8>)>
where
    S: EntryStorage,
{
    this.backend.with_path_cache(|cache| {
        if let Some((dir_id, cipher_path)) = cache.get(plain_path.as_str()) {
            Ok((cipher_path.to_owned(), dir_id.clone()))
        } else {
            if plain_path.as_str().is_empty() {
                let directory = this
                    .entry_storage()
                    .resolve_directory(VirtualPath::root())?;
                cache.insert(
                    String::default(),
                    (directory.token.clone(), directory.contents_path.clone()),
                );
                return Ok((directory.contents_path, directory.token));
            }

            let mut partial_plain_path = VirtualPathBuf::from("");
            let mut absolute_path = VirtualPathBuf::default();
            for plain_part in plain_path.iter() {
                if let Some((dir_id, cipher_parent)) = cache.get(partial_plain_path.as_str()) {
                    let cipher_part = this.plain_name_to_cipher(dir_id, plain_part)?;
                    absolute_path = cipher_parent.join(cipher_part);
                } else {
                    let directory = this.entry_storage().resolve_directory(&absolute_path)?;
                    absolute_path = directory.contents_path;
                    cache.insert(
                        partial_plain_path.as_str().into(),
                        (directory.token.clone(), absolute_path.clone()),
                    );
                    let cipher_part = this.plain_name_to_cipher(&directory.token, plain_part)?;
                    absolute_path.push(cipher_part);
                }
                partial_plain_path.push(plain_part);
            }

            let directory = this.entry_storage().resolve_directory(&absolute_path)?;
            absolute_path = directory.contents_path;

            cache.insert(
                partial_plain_path.as_str().into(),
                (directory.token.clone(), absolute_path.clone()),
            );

            Ok((absolute_path, directory.token))
        }
    })
}

impl<S> PathLayout for CryptoMator<EntryStorageBackend<S>>
where
    S: EntryStorage,
{
    type EntryStorage = S;

    fn entry_storage(&self) -> &Self::EntryStorage {
        self.backend.entry_storage()
    }
    /// Resolves one logical path to its visible storage entry inside the parent storage directory.
    fn plain_path_to_cipher(&self, plain_path: &VirtualPath) -> Result<VirtualPathBuf> {
        if plain_path.as_str().is_empty() {
            return Ok(folder_path_to_cipher_and_dirid(self, plain_path)?.0);
        }

        let parent = plain_path.parent().unwrap_or_else(VirtualPath::root);
        let name = plain_path.file_name().or_invalid()?;
        let (cipher_parent_path, dir_id) = folder_path_to_cipher_and_dirid(self, parent)?;
        let cipher_name = self.plain_name_to_cipher(&dir_id, name)?;
        Ok(cipher_parent_path.join(cipher_name))
    }
    /// Drops one cached plain path and all cached descendants derived from it.
    fn remove_cached_plain_path(&self, plain_path: &VirtualPath) {
        default_remove_cached_plain_path(&self.backend, plain_path);
    }
}

impl<S: EntryStorage> EncryptionLayout for CryptoMator<EntryStorageBackend<S>> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        EncryptionLayout, FileType, NativeFileSystem, PathLayout, StorageFileSystem, Utf8Path,
    };
    use crate::{CryptomatorBackend, CryptomatorEntryStorage};
    use std::sync::Arc;
    use tempfile::tempdir;

    /// Creates a borrowed plain path for tests.
    fn p(path: &str) -> &VirtualPath {
        VirtualPath::new(path)
    }

    /// Returns the raw filesystem used by a test backend.
    fn raw_storage(backend: &CryptoMator<CryptomatorBackend>) -> &NativeFileSystem {
        backend.entry_storage().storage_fs()
    }

    /// Maps a short opaque name to its physical Cryptomator entry path.
    fn physical_entry_path(path: &VirtualPath) -> VirtualPathBuf {
        let parent = path.parent().unwrap_or_else(VirtualPath::root);
        parent.join(format!("{}.c9r", path.file_name().unwrap()))
    }

    /// Creates a deterministic Cryptomator backend with a materialized root storage directory.
    fn test_backend() -> (tempfile::TempDir, CryptoMator<CryptomatorBackend>) {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap();

        let mut siv_key = [0u8; 64];
        for (i, byte) in siv_key.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let directory_layout = Arc::new(CryptomatorDirectoryLayout::new(siv_key));
        let backend: CryptoMator<CryptomatorBackend> = CryptoMator {
            backend: EntryStorageBackend::new(CryptomatorEntryStorage::new(
                NativeFileSystem::new(root.to_owned()),
                directory_layout,
            )),
            siv_key,
        };

        backend.entry_storage().initialize_root_directory().unwrap();

        (temp_dir, backend)
    }

    #[test]
    fn create_and_read_symlink_roundtrip() {
        let (_temp_dir, backend) = test_backend();

        backend.create_symlink(p("link"), "../target.txt").unwrap();

        let target = backend.read_symlink(p("link")).unwrap();
        let metadata = backend.metadata(p("link")).unwrap();

        assert_eq!(target, "../target.txt");
        assert!(metadata.file_type == FileType::SymLink);
        assert!(u16::from(metadata.permissions) == 0o777);
    }

    #[test]
    fn list_dir_plain_names_returns_symlink_entry() {
        let (_temp_dir, backend) = test_backend();
        backend.create_symlink(p("link"), "../target.txt").unwrap();

        let entries: Vec<_> = Arc::from(backend)
            .list_dir_plain_names(p(""))
            .unwrap()
            .map(|entry| entry.unwrap().0)
            .collect();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name, "link");
        assert!(entries[0].metadata.file_type == FileType::SymLink);
    }

    #[test]
    fn list_dir_plain_names_reads_detached_directory_contents() {
        let (_temp_dir, backend) = test_backend();
        backend.mkdir(p("docs"), Some(0o755_u16.into())).unwrap();
        backend
            .mknode(p("docs/note.txt"), Some(0o644_u16.into()))
            .unwrap();

        let entries: Vec<_> = Arc::from(backend)
            .list_dir_plain_names(p("docs"))
            .unwrap()
            .map(|entry| entry.unwrap().0.file_name)
            .collect();

        assert_eq!(entries, ["note.txt"]);
    }

    #[test]
    fn long_plain_name_roundtrips_through_shortened_storage() {
        let (_temp_dir, backend) = test_backend();
        let plain_name = "long-name-".repeat(20);
        let plain_path = VirtualPath::new(&plain_name);

        backend.mknode(plain_path, None).unwrap();
        let entries = Arc::from(backend)
            .list_dir_plain_names(VirtualPath::root())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.file_name, plain_name);
        assert!(entries[0].0.metadata.file_type == FileType::File);
    }

    #[test]
    fn canonical_layout_recognizes_only_canonical_contents_paths() {
        let layout = CryptomatorDirectoryLayout::new([0; 64]);

        assert!(layout.is_detached_directory_contents_path(VirtualPath::new(
            "d/AB/ABCDEFGHIJKLMNOPQRSTUVWXYZ2345"
        )));
        assert!(
            !layout.is_detached_directory_contents_path(VirtualPath::new(
                "objects/ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            ))
        );
        assert!(
            !layout.is_detached_directory_contents_path(VirtualPath::new(
                "d/AB/ABCDEFGHIJKLMNOPQRSTUVWXYZ2345/entry.c9r"
            ))
        );
        assert!(
            !layout.is_detached_directory_contents_path(VirtualPath::new(
                "d/aB/ABCDEFGHIJKLMNOPQRSTUVWXYZ2345"
            ))
        );
    }

    #[test]
    fn metadata_reports_empty_plain_file_for_header_only_node() {
        let (_temp_dir, backend) = test_backend();

        let created_metadata = backend
            .mknode(p("empty.txt"), Some(0o644_u16.into()))
            .unwrap();

        let cipher_path = backend.plain_path_to_cipher(p("empty.txt")).unwrap();
        let physical_path = physical_entry_path(&cipher_path);
        let raw_metadata = raw_storage(&backend).metadata(&physical_path).unwrap();
        let plain_metadata = backend.metadata(p("empty.txt")).unwrap();
        let duplicate_error = backend.mknode(p("empty.txt"), None).err().unwrap();

        assert_eq!(
            raw_metadata.len,
            CryptoMator::<CryptomatorBackend>::HEADER_LEN as u64
        );
        assert_eq!(plain_metadata.len, 0);
        assert!(plain_metadata.file_type == FileType::File);
        assert_eq!(created_metadata.len, 0);
        assert_eq!(u16::from(created_metadata.permissions), 0o644);
        assert_eq!(duplicate_error.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn mkdir_creates_visible_and_storage_directories() {
        let (_temp_dir, backend) = test_backend();

        backend.mkdir(p("docs"), Some(0o755_u16.into())).unwrap();

        let cipher_path = backend.plain_path_to_cipher(p("docs")).unwrap();
        let physical_path = physical_entry_path(&cipher_path);
        let directory = backend
            .entry_storage()
            .resolve_directory(&cipher_path)
            .unwrap();

        assert!(raw_storage(&backend).exists(&physical_path).unwrap());
        assert!(
            raw_storage(&backend)
                .exists(&physical_path.join("dir.c9r"))
                .unwrap()
        );
        assert!(
            raw_storage(&backend)
                .exists(&directory.contents_path)
                .unwrap()
        );
        assert!(backend.metadata(p("docs")).unwrap().file_type == FileType::Directory);
    }

    #[test]
    fn remove_dir_removes_visible_and_storage_directories() {
        let (_temp_dir, backend) = test_backend();

        backend.mkdir(p("docs"), Some(0o755_u16.into())).unwrap();
        let cipher_path = backend.plain_path_to_cipher(p("docs")).unwrap();
        let physical_path = physical_entry_path(&cipher_path);
        let directory = backend
            .entry_storage()
            .resolve_directory(&cipher_path)
            .unwrap();

        backend.remove_dir(p("docs")).unwrap();

        assert!(!raw_storage(&backend).exists(&physical_path).unwrap());
        assert!(
            !raw_storage(&backend)
                .exists(&directory.contents_path)
                .unwrap()
        );
    }

    #[test]
    fn remove_deletes_file_and_symlink_entries() {
        let (_temp_dir, backend) = test_backend();

        backend
            .mknode(p("file.txt"), Some(0o644_u16.into()))
            .unwrap();
        let file_path = backend.plain_path_to_cipher(p("file.txt")).unwrap();
        let physical_file_path = physical_entry_path(&file_path);
        backend.remove(p("file.txt")).unwrap();
        assert!(!raw_storage(&backend).exists(&physical_file_path).unwrap());

        backend.create_symlink(p("link"), "../target.txt").unwrap();
        let symlink_path = backend.plain_path_to_cipher(p("link")).unwrap();
        let physical_symlink_path = physical_entry_path(&symlink_path);
        backend.remove(p("link")).unwrap();
        assert!(
            !raw_storage(&backend)
                .exists(&physical_symlink_path)
                .unwrap()
        );
    }

    #[test]
    fn list_dir_plain_names_filters_special_entries() {
        let (_temp_dir, backend) = test_backend();
        let root_storage = backend
            .entry_storage()
            .resolve_directory(VirtualPath::root())
            .unwrap()
            .contents_path;

        raw_storage(&backend)
            .put(&root_storage.join("dirid.c9r"), b"internal")
            .unwrap();

        let entries: Vec<_> = Arc::from(backend)
            .list_dir_plain_names(p(""))
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();

        assert!(entries.is_empty());
    }

    #[test]
    fn rename_moves_file_directory_and_symlink_entries() {
        let (_temp_dir, backend) = test_backend();

        backend
            .mknode(p("file.txt"), Some(0o644_u16.into()))
            .unwrap();
        backend.rename(p("file.txt"), p("file2.txt")).unwrap();
        assert!(backend.metadata(p("file.txt")).is_err());
        assert!(backend.metadata(p("file2.txt")).is_ok());
        assert!(backend.metadata(p("file2.txt")).unwrap().file_type == FileType::File);

        backend.mkdir(p("docs"), Some(0o755_u16.into())).unwrap();
        backend.rename(p("docs"), p("docs2")).unwrap();
        assert!(backend.metadata(p("docs")).is_err());
        assert!(backend.metadata(p("docs2")).is_ok());
        assert!(backend.metadata(p("docs2")).unwrap().file_type == FileType::Directory);

        backend.create_symlink(p("link"), "../target.txt").unwrap();
        backend.rename(p("link"), p("link2")).unwrap();
        assert!(backend.metadata(p("link")).is_err());
        assert!(backend.metadata(p("link2")).is_ok());
        assert!(backend.metadata(p("link2")).unwrap().file_type == FileType::SymLink);
        assert_eq!(backend.read_symlink(p("link2")).unwrap(), "../target.txt");
    }

    #[test]
    fn set_permissions_updates_file_directory_and_symlink_metadata() {
        let (_temp_dir, backend) = test_backend();

        backend
            .mknode(p("file.txt"), Some(0o644_u16.into()))
            .unwrap();
        let file_metadata = backend
            .set_permissions(p("file.txt"), 0o600_u16.into())
            .unwrap();
        assert_eq!(u16::from(file_metadata.permissions), 0o600);
        assert_eq!(
            u16::from(backend.metadata(p("file.txt")).unwrap().permissions),
            0o600
        );

        backend.mkdir(p("docs"), Some(0o755_u16.into())).unwrap();
        let dir_metadata = backend
            .set_permissions(p("docs"), 0o700_u16.into())
            .unwrap();
        assert_eq!(u16::from(dir_metadata.permissions), 0o700);
        assert_eq!(
            u16::from(backend.metadata(p("docs")).unwrap().permissions),
            0o700
        );

        backend.create_symlink(p("link"), "../target.txt").unwrap();
        let symlink_after = backend
            .set_permissions(p("link"), 0o600_u16.into())
            .unwrap();

        assert!(symlink_after.file_type == FileType::SymLink);
        assert_eq!(backend.read_symlink(p("link")).unwrap(), "../target.txt");
        assert!(backend.metadata(p("link")).unwrap().file_type == FileType::SymLink);
        assert_eq!(u16::from(symlink_after.permissions), 0o777);
        assert_eq!(
            u16::from(backend.metadata(p("link")).unwrap().permissions),
            0o777
        );
    }

    #[test]
    fn set_time_updates_file_directory_and_symlink_metadata() {
        let (_temp_dir, backend) = test_backend();
        let atime =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let mtime =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_123);

        backend
            .mknode(p("file.txt"), Some(0o644_u16.into()))
            .unwrap();
        let file_before = backend.metadata(p("file.txt")).unwrap();
        backend
            .set_time(p("file.txt"), Some(atime), Some(mtime))
            .unwrap();
        let file_after = backend.metadata(p("file.txt")).unwrap();
        assert_ne!(file_before.accessed, file_after.accessed);
        assert_ne!(file_before.modified, file_after.modified);
        assert_eq!(file_after.accessed, atime);
        assert_eq!(file_after.modified, mtime);

        backend.mkdir(p("docs"), Some(0o755_u16.into())).unwrap();
        let dir_before = backend.metadata(p("docs")).unwrap();
        backend
            .set_time(p("docs"), Some(atime), Some(mtime))
            .unwrap();
        let dir_after = backend.metadata(p("docs")).unwrap();
        assert_ne!(dir_before.accessed, dir_after.accessed);
        assert_ne!(dir_before.modified, dir_after.modified);
        assert_eq!(dir_after.accessed, atime);
        assert_eq!(dir_after.modified, mtime);

        backend.create_symlink(p("link"), "../target.txt").unwrap();
        let symlink_before = backend.metadata(p("link")).unwrap();
        backend
            .set_time(p("link"), Some(atime), Some(mtime))
            .unwrap();
        let symlink_after = backend.metadata(p("link")).unwrap();
        assert!(symlink_after.file_type == FileType::SymLink);
        assert_eq!(backend.read_symlink(p("link")).unwrap(), "../target.txt");
        assert_eq!(symlink_after.accessed, atime);
        assert_eq!(symlink_after.modified, mtime);
        assert_ne!(symlink_before.accessed, symlink_after.accessed);
        assert_ne!(symlink_before.modified, symlink_after.modified);
    }
}
