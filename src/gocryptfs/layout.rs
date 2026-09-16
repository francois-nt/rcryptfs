use super::GoCryptFs;
use crate::core::{
    DirectoryContentLayout, DirectoryLayout, EncryptionLayout, EncryptionTranslator, EntryStorage,
    FsBackend, PathCacheAccess, PathLayout, Result, RootDirectoryToken, VirtualPath,
    VirtualPathBuf, default_remove_cached_plain_path,
};

/// Canonical GoCryptFS directory policy.
pub(super) struct GoCryptFsDirectoryLayout;

impl DirectoryContentLayout for GoCryptFsDirectoryLayout {
    fn detached_directory_contents_path(
        &self,
        entry_path: &VirtualPath,
        _token: &[u8],
    ) -> Result<VirtualPathBuf> {
        Ok(entry_path.to_owned())
    }

    fn is_detached_directory_contents_path(&self, _path: &VirtualPath) -> bool {
        false
    }
}

impl DirectoryLayout for GoCryptFsDirectoryLayout {
    fn generate_directory_token(&self) -> Vec<u8> {
        let mut token = vec![0; 16];
        rand::fill(&mut token[..]);
        token
    }

    fn validate_directory_token(&self, token: &[u8], _is_root: bool) -> Result<()> {
        anyhow::ensure!(
            token.len() == 16,
            "GoCryptFS directory token has length {}, expected 16",
            token.len()
        );
        Ok(())
    }

    fn root_directory_token(&self) -> RootDirectoryToken {
        RootDirectoryToken::Persisted
    }
}

impl<S> PathLayout for GoCryptFs<FsBackend<S>>
where
    S: EntryStorage,
{
    type EntryStorage = S;

    fn entry_storage(&self) -> &Self::EntryStorage {
        self.backend.entry_storage()
    }
    fn remove_cached_plain_path(&self, plain_path: &VirtualPath) {
        default_remove_cached_plain_path(&self.backend, plain_path);
    }

    /// Converts a plain path to its cipher text equivalent.
    fn plain_path_to_cipher(&self, plain_path: &VirtualPath) -> Result<VirtualPathBuf> {
        self.backend.with_path_cache(|cache| {
            if let Some((_, cipher_path)) = cache.get(plain_path.as_str()) {
                Ok(cipher_path.to_owned())
            } else {
                let parent_path = plain_path.parent().map(|p| p.as_str()).unwrap_or_default();
                let name = plain_path.file_name().unwrap_or_default();

                if parent_path.is_empty() && name.is_empty() {
                    return Ok(VirtualPathBuf::default());
                }

                if let Some((dir_iv, cipher_parent_path)) = cache.get(parent_path) {
                    let cipher_part = self.plain_name_to_cipher(dir_iv, name)?;
                    Ok(cipher_parent_path.as_path().join(cipher_part))
                } else {
                    let mut partial_plain_path = VirtualPathBuf::from("");
                    let mut absolute_path = VirtualPathBuf::default();
                    for plain_part in plain_path.iter() {
                        if let Some((dir_iv, cipher_parent)) =
                            cache.get(partial_plain_path.as_str())
                        {
                            let cipher_part = self.plain_name_to_cipher(dir_iv, plain_part)?;
                            absolute_path = cipher_parent.join(cipher_part);
                        } else {
                            let directory =
                                self.entry_storage().resolve_directory(&absolute_path)?;

                            absolute_path = directory.contents_path;
                            cache.insert(
                                partial_plain_path.as_str().into(),
                                (directory.token.clone(), absolute_path.clone()),
                            );
                            let cipher_part =
                                self.plain_name_to_cipher(&directory.token, plain_part)?;
                            absolute_path.push(cipher_part);
                        }

                        partial_plain_path.push(plain_part);
                    }
                    Ok(absolute_path)
                }
            }
        })
    }
}

impl<S: EntryStorage> EncryptionLayout for GoCryptFs<FsBackend<S>> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GoCryptFsBackend;
    use crate::core::{EncryptionLayout, FileType, NativeFileSystem, StorageFileSystem, Utf8Path};
    use std::sync::Arc;
    use tempfile::tempdir;

    /// Creates a borrowed plain path for tests.
    fn p(path: &str) -> &VirtualPath {
        VirtualPath::new(path)
    }

    /// Returns the raw filesystem used by a test backend.
    fn raw_storage(backend: &GoCryptFs<GoCryptFsBackend>) -> &NativeFileSystem {
        backend.entry_storage().storage_fs()
    }

    /// Creates a freshly initialized GoCryptFS backend rooted in a temp directory.
    fn test_backend() -> (tempfile::TempDir, GoCryptFs<GoCryptFsBackend>) {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap();
        GoCryptFs::<GoCryptFsBackend>::init_with_default_params(root, "password").unwrap();
        let backend = GoCryptFs::<GoCryptFsBackend>::try_new(root, "password").unwrap();
        (temp_dir, backend)
    }

    #[test]
    fn plain_path_to_cipher_resolves_root_and_nested_paths() {
        let (_temp_dir, backend) = test_backend();

        let root_cipher = backend.plain_path_to_cipher(p("")).unwrap();
        assert!(root_cipher.is_empty());

        backend.mkdir(p("docs"), Some(0o755_u16.into())).unwrap();
        backend
            .mknode(p("docs/note.txt"), Some(0o644_u16.into()))
            .unwrap();

        let docs_cipher = backend.plain_path_to_cipher(p("docs")).unwrap();
        let note_cipher = backend.plain_path_to_cipher(p("docs/note.txt")).unwrap();

        assert_eq!(docs_cipher.parent(), Some(VirtualPath::root()));
        assert_eq!(note_cipher.parent(), Some(docs_cipher.as_path()));
        assert!(!docs_cipher.is_empty());
        assert_ne!(note_cipher.file_name(), Some("note.txt"));
    }

    #[test]
    fn remove_cached_plain_path_invalidates_nested_cache_entries() {
        let (_temp_dir, backend) = test_backend();

        backend.mkdir(p("docs"), Some(0o755_u16.into())).unwrap();
        backend
            .mknode(p("docs/note.txt"), Some(0o644_u16.into()))
            .unwrap();

        let _ = backend.plain_path_to_cipher(p("docs")).unwrap();
        let before = backend.plain_path_to_cipher(p("docs/note.txt")).unwrap();

        backend.remove_cached_plain_path(p("docs"));

        let after = backend.plain_path_to_cipher(p("docs/note.txt")).unwrap();

        assert_eq!(before, after);
    }

    #[test]
    fn list_dir_plain_names_returns_plain_entries_and_filters_special_files() {
        let (_temp_dir, backend) = test_backend();

        backend.mkdir(p("docs"), Some(0o755_u16.into())).unwrap();
        backend
            .mknode(p("file.txt"), Some(0o644_u16.into()))
            .unwrap();
        backend.create_symlink(p("link"), "../target.txt").unwrap();

        let root_cipher = backend.plain_path_to_cipher(p("")).unwrap();
        raw_storage(&backend)
            .put(&root_cipher.join("gocryptfs.conf"), b"ignored")
            .unwrap();
        raw_storage(&backend)
            .put(&root_cipher.join("temp.junk"), b"ignored")
            .unwrap();

        let entries: Vec<_> = Arc::from(backend)
            .list_dir_plain_names(p(""))
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(entries.len(), 3);
        assert!(entries.iter().any(|(entry, _)| entry.file_name == "docs"));
        assert!(
            entries
                .iter()
                .any(|(entry, _)| entry.file_name == "file.txt")
        );
        assert!(entries.iter().any(|(entry, _)| entry.file_name == "link"));
    }

    #[test]
    fn long_plain_name_roundtrips_through_gocryptfs_storage() {
        let (_temp_dir, backend) = test_backend();
        let long_name = "a".repeat(200);
        backend
            .mknode(VirtualPath::new(&long_name), Some(0o644_u16.into()))
            .unwrap();

        let raw_entries = raw_storage(&backend)
            .read_dir(VirtualPath::root())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert!(raw_entries.iter().any(|entry| {
            entry.file_name.starts_with("gocryptfs.longname.")
                && !entry.file_name.ends_with(".name")
        }));
        assert!(raw_entries.iter().any(|entry| {
            entry.file_name.starts_with("gocryptfs.longname.") && entry.file_name.ends_with(".name")
        }));

        let entries = Arc::new(backend)
            .list_dir_plain_names(VirtualPath::root())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.file_name, long_name);
    }

    #[test]
    fn metadata_reports_plain_file_size() {
        let (_temp_dir, backend) = test_backend();

        let plain = b"hello layout metadata";
        let cipher_path = backend.plain_path_to_cipher(p("file.txt")).unwrap();
        let header = backend.generate_cipher_header().unwrap();
        let cipher = backend.plain_block_to_cipher(&header, 0, plain).unwrap();
        raw_storage(&backend)
            .put(
                &cipher_path,
                &[header.as_slice(), cipher.as_slice()].concat(),
            )
            .unwrap();

        let metadata = backend.metadata(p("file.txt")).unwrap();

        assert!(metadata.file_type == FileType::File);
        assert_eq!(metadata.len, plain.len() as u64);
    }

    #[test]
    fn mknode_creates_cipher_file_and_applies_permissions() {
        let (_temp_dir, backend) = test_backend();

        let metadata = backend
            .mknode(p("file.txt"), Some(0o640_u16.into()))
            .unwrap();
        let cipher_path = backend.plain_path_to_cipher(p("file.txt")).unwrap();

        assert!(raw_storage(&backend).exists(&cipher_path).unwrap());
        assert!(metadata.file_type == FileType::File);
        assert_eq!(u16::from(metadata.permissions), 0o640);
    }

    #[test]
    fn mkdir_creates_cipher_directory_and_diriv() {
        let (_temp_dir, backend) = test_backend();

        let metadata = backend.mkdir(p("docs"), Some(0o750_u16.into())).unwrap();
        let cipher_path = backend.plain_path_to_cipher(p("docs")).unwrap();
        let diriv_path = cipher_path.join("gocryptfs.diriv");

        assert!(raw_storage(&backend).exists(&cipher_path).unwrap());
        assert!(raw_storage(&backend).exists(&diriv_path).unwrap());
        assert!(metadata.file_type == FileType::Directory);
        assert_eq!(u16::from(metadata.permissions), 0o750);
    }

    #[test]
    fn remove_deletes_cipher_file() {
        let (_temp_dir, backend) = test_backend();

        backend
            .mknode(p("file.txt"), Some(0o644_u16.into()))
            .unwrap();
        let cipher_path = backend.plain_path_to_cipher(p("file.txt")).unwrap();

        backend.remove(p("file.txt")).unwrap();

        assert!(!raw_storage(&backend).exists(&cipher_path).unwrap());
    }

    #[test]
    fn remove_dir_deletes_directory_and_diriv() {
        let (_temp_dir, backend) = test_backend();

        backend.mkdir(p("docs"), Some(0o755_u16.into())).unwrap();
        let cipher_path = backend.plain_path_to_cipher(p("docs")).unwrap();
        let diriv_path = cipher_path.join("gocryptfs.diriv");

        backend.remove_dir(p("docs")).unwrap();

        assert!(!raw_storage(&backend).exists(&cipher_path).unwrap());
        assert!(!raw_storage(&backend).exists(&diriv_path).unwrap());
    }

    #[test]
    fn create_and_read_symlink_roundtrip() {
        let (_temp_dir, backend) = test_backend();

        let metadata = backend.create_symlink(p("link"), "../target.txt").unwrap();

        assert!(metadata.file_type == FileType::SymLink);
        assert_eq!(backend.read_symlink(p("link")).unwrap(), "../target.txt");
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

        backend.mkdir(p("docs"), Some(0o755_u16.into())).unwrap();
        backend.rename(p("docs"), p("docs2")).unwrap();
        assert!(backend.metadata(p("docs")).is_err());
        assert!(backend.metadata(p("docs2")).is_ok());

        backend.create_symlink(p("link"), "../target.txt").unwrap();
        backend.rename(p("link"), p("link2")).unwrap();
        assert!(backend.metadata(p("link")).is_err());
        assert!(backend.metadata(p("link2")).is_ok());
        assert_eq!(backend.read_symlink(p("link2")).unwrap(), "../target.txt");
    }

    #[test]
    fn set_permissions_and_time_update_plain_metadata() {
        let (_temp_dir, backend) = test_backend();
        let atime =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let mtime =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_123);

        backend
            .mknode(p("file.txt"), Some(0o644_u16.into()))
            .unwrap();
        let metadata = backend
            .set_permissions(p("file.txt"), 0o600_u16.into())
            .unwrap();
        assert_eq!(u16::from(metadata.permissions), 0o600);

        backend
            .set_time(p("file.txt"), Some(atime), Some(mtime))
            .unwrap();
        let after = backend.metadata(p("file.txt")).unwrap();
        assert_eq!(after.accessed, atime);
        assert_eq!(after.modified, mtime);
    }
}
