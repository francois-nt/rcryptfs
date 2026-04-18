use super::GoCryptFs;
use crate::core::{
    Backend, CacheAccess, CipherPathLayout, EncryptionLayout, EncryptionTranslator, FsBackend,
    FsDirEntry, MinimalFs, OrIoError, Result, Utf8Path, Utf8PathBuf,
    default_remove_cached_plain_path, temp_file_path,
};
use anyhow::{Context, anyhow};

impl CipherPathLayout for GoCryptFs<FsBackend> {
    type LowerFs = <FsBackend as Backend>::LowerFs;
    fn lower_fs(&self) -> &Self::LowerFs {
        self.backend.get_fs()
    }
    fn remove_cached_plain_path(&self, plain_path: &str) {
        default_remove_cached_plain_path(&self.backend, plain_path);
    }

    /// Converts a plain path to its cipher text equivalent.
    fn plain_path_to_cipher(&self, plain_path: &Utf8Path) -> Result<Utf8PathBuf> {
        self.backend.access(|cache| {
            if let Some((_, cipher_path)) = cache.get(plain_path.as_str()) {
                Ok(cipher_path.to_owned())
            } else {
                let parent_path = plain_path.parent().map(|p| p.as_str()).unwrap_or_default();
                let name = plain_path.file_name().unwrap_or_default();

                if parent_path.is_empty() && name.is_empty() {
                    return Ok(self.backend.cipher_root.clone());
                }

                if let Some((dir_iv, cipher_parent_path)) = cache.get(parent_path) {
                    let cipher_part = self.plain_name_to_cipher(dir_iv, name)?;
                    Ok(cipher_parent_path.as_path().join(cipher_part))
                } else {
                    let mut partial_plain_path = Utf8PathBuf::from("");
                    let mut absolute_path = self.backend.cipher_root.clone();
                    for plain_part in plain_path.iter() {
                        if let Some((dir_iv, cipher_parent)) =
                            cache.get(partial_plain_path.as_str())
                        {
                            let cipher_part = self.plain_name_to_cipher(dir_iv, plain_part)?;
                            absolute_path = cipher_parent.join(cipher_part);
                        } else {
                            let dir_iv = read_diriv(&absolute_path)?;

                            cache.insert(
                                partial_plain_path.as_str().into(),
                                (dir_iv.to_vec(), absolute_path.clone()),
                            );
                            let cipher_part = self.plain_name_to_cipher(&dir_iv, plain_part)?;
                            absolute_path.push(cipher_part);
                        }

                        partial_plain_path.push(plain_part);
                    }
                    Ok(absolute_path)
                }
            }
        })
        // let mut absolute_path = self.backend.cipher_root.clone();
        // for plain_part in plain_path.iter() {
        //     let dir_iv = read_diriv(&absolute_path)?;
        //     let cipher_part = self.plain_name_to_cipher(&dir_iv, plain_part)?;

        //     absolute_path.push(cipher_part);
        // }
        // Ok(absolute_path)
    }
    /// Creates a temporary name for a given path.
    fn create_temp_name(&self, path: &str, is_dir_iv: bool) -> Utf8PathBuf {
        // Temporary names are deterministic on purpose. This assumes a single
        // rcryptfs process owns a backend at a time; concurrent multi-process
        // access to the same encrypted root is undefined behavior.
        temp_file_path(&self.backend.cipher_root, path, is_dir_iv)
    }
    fn get_dir_iv_file(&self, cipher_folder_path: &Utf8Path) -> Utf8PathBuf {
        cipher_folder_path.join("gocryptfs.diriv")
    }
}

impl EncryptionLayout for GoCryptFs<FsBackend> {
    /// Lists directory entries with plain names.
    fn list_dir_plain_names(
        &self,
        plain_path: &Utf8Path,
    ) -> std::io::Result<impl Iterator<Item = Result<(FsDirEntry, Utf8PathBuf)>> + '_ + use<'_>>
    {
        let plain_path: Utf8PathBuf = plain_path.into();
        let cipher_path = self.plain_path_to_cipher(&plain_path).or_invalid()?;
        let dir_iv = read_diriv(&cipher_path).or_invalid()?;

        Ok(self
            .lower_fs()
            .list_dir(cipher_path.as_str())?
            .filter_map(
                move |entry| match map_dir_entry(self, &cipher_path, &dir_iv, entry) {
                    Ok(Some((plain_name, cipher_path))) => Some(Ok((plain_name, cipher_path))),
                    Ok(None) => None,
                    Err(e) => Some(Err(e)),
                },
            ))

        // //std::fs::metadata(path)
        // Ok(std::fs::read_dir(&cipher_path)?.filter_map(move |entry| {
        //     match map_dir_entry(self, &cipher_path, &dir_iv, entry) {
        //         Ok(Some((plain_name, cipher_path))) => Some(Ok((plain_name, cipher_path))),
        //         Ok(None) => None,
        //         Err(e) => Some(Err(e)),
        //     }
        // }))
    }
}

/// Reads the directory initialization vector from a cipher directory.
fn read_diriv(cipher_dir: &Utf8Path) -> Result<[u8; 16]> {
    let p = cipher_dir.join("gocryptfs.diriv");
    let data = std::fs::read(&p).context(format!("read {:?}", p))?;
    if data.len() != 16 {
        return Err(anyhow!("diriv has len {}, expected 16", data.len()));
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&data);
    Ok(iv)
}

/// Checks if a directory entry is a special gocryptfs file.
fn is_special_entry(name: &str) -> bool {
    name.starts_with("temp.")
        || name == "gocryptfs.diriv"
        || name == "gocryptfs.conf"
        || (name.starts_with("gocryptfs.longname.") && name.ends_with(".name"))
}

/// Maps a cipher directory entry to its plain equivalent.
fn map_dir_entry(
    this: &impl EncryptionLayout,
    cipher_path: &Utf8Path,
    dir_iv: &[u8],
    entry: Result<FsDirEntry, std::io::Error>,
) -> Result<Option<(FsDirEntry, Utf8PathBuf)>> {
    match entry {
        Ok(entry) => {
            let cipher_name = entry.file_name.clone();
            if is_special_entry(&cipher_name) {
                Ok(None)
            } else {
                let plain_name = this.cipher_name_to_plain(dir_iv, &cipher_name)?;
                Ok(Some((
                    entry.with_name(plain_name),
                    cipher_path.join(Utf8Path::new(&cipher_name)),
                )))
            }
        }
        Err(e) => Err(e)?,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{EncryptionLayout, FileType, FsBackend, MinimalFs};
    use tempfile::tempdir;

    /// Creates a freshly initialized GoCryptFS backend rooted in a temp directory.
    fn test_backend() -> (tempfile::TempDir, GoCryptFs<FsBackend>) {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap();
        GoCryptFs::<FsBackend>::init_with_default_params(root, "password").unwrap();
        let backend = GoCryptFs::<FsBackend>::try_new(root, "password").unwrap();
        (temp_dir, backend)
    }

    #[test]
    fn plain_path_to_cipher_resolves_root_and_nested_paths() {
        let (_temp_dir, backend) = test_backend();

        let root_cipher = backend.plain_path_to_cipher(Utf8Path::new("")).unwrap();
        assert_eq!(root_cipher, backend.backend.cipher_root);

        backend.mkdir("docs", 0o755_u16.into()).unwrap();
        backend.mknode("docs/note.txt", 0o644_u16.into()).unwrap();

        let docs_cipher = backend.plain_path_to_cipher(Utf8Path::new("docs")).unwrap();
        let note_cipher = backend
            .plain_path_to_cipher(Utf8Path::new("docs/note.txt"))
            .unwrap();

        assert!(docs_cipher.starts_with(&backend.backend.cipher_root));
        assert!(note_cipher.starts_with(&docs_cipher));
        assert_ne!(docs_cipher, backend.backend.cipher_root);
        assert_ne!(note_cipher.file_name(), Some("note.txt"));
    }

    #[test]
    fn remove_cached_plain_path_invalidates_nested_cache_entries() {
        let (_temp_dir, backend) = test_backend();

        backend.mkdir("docs", 0o755_u16.into()).unwrap();
        backend.mknode("docs/note.txt", 0o644_u16.into()).unwrap();

        let _ = backend.plain_path_to_cipher(Utf8Path::new("docs")).unwrap();
        let before = backend
            .plain_path_to_cipher(Utf8Path::new("docs/note.txt"))
            .unwrap();

        backend.remove_cached_plain_path("docs");

        let after = backend
            .plain_path_to_cipher(Utf8Path::new("docs/note.txt"))
            .unwrap();

        assert_eq!(before, after);
    }

    #[test]
    fn create_temp_name_and_diriv_file_match_expected_shape() {
        let (_temp_dir, backend) = test_backend();

        let temp_path = backend.create_temp_name("docs", false);
        let temp_diriv_path = backend.create_temp_name("docs", true);
        let diriv_path = backend.get_dir_iv_file(Utf8Path::new("/tmp/cipher-dir"));

        assert!(temp_path.starts_with(&backend.backend.cipher_root));
        assert!(
            temp_path
                .file_name()
                .unwrap_or_default()
                .starts_with("temp.")
        );
        assert!(temp_diriv_path.extension() == Some("diriv"));
        assert_eq!(
            diriv_path,
            Utf8Path::new("/tmp/cipher-dir").join("gocryptfs.diriv")
        );
    }

    #[test]
    fn list_dir_plain_names_returns_plain_entries_and_filters_special_files() {
        let (_temp_dir, backend) = test_backend();

        backend.mkdir("docs", 0o755_u16.into()).unwrap();
        backend.mknode("file.txt", 0o644_u16.into()).unwrap();
        backend.create_symlink("link", "../target.txt").unwrap();

        let root_cipher = backend.plain_path_to_cipher(Utf8Path::new("")).unwrap();
        backend
            .lower_fs()
            .put(&root_cipher.join("gocryptfs.conf"), b"ignored")
            .unwrap();
        backend
            .lower_fs()
            .put(&root_cipher.join("temp.junk"), b"ignored")
            .unwrap();

        let entries: Vec<_> = backend
            .list_dir_plain_names(Utf8Path::new(""))
            .unwrap()
            .collect::<Result<Vec<_>>>()
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
    fn metadata_reports_plain_file_size() {
        let (_temp_dir, backend) = test_backend();

        let plain = b"hello layout metadata";
        let cipher_path = backend
            .plain_path_to_cipher(Utf8Path::new("file.txt"))
            .unwrap();
        let header = backend.generate_cipher_header().unwrap();
        let cipher = backend.plain_block_to_cipher(&header, 0, plain).unwrap();
        backend
            .lower_fs()
            .put(
                &cipher_path,
                &[header.as_slice(), cipher.as_slice()].concat(),
            )
            .unwrap();

        let metadata = backend.metadata("file.txt").unwrap();

        assert!(metadata.file_type == FileType::File);
        assert_eq!(metadata.len, plain.len() as u64);
    }

    #[test]
    fn mknode_creates_cipher_file_and_applies_permissions() {
        let (_temp_dir, backend) = test_backend();

        let metadata = backend.mknode("file.txt", 0o640_u16.into()).unwrap();
        let cipher_path = backend
            .plain_path_to_cipher(Utf8Path::new("file.txt"))
            .unwrap();

        assert!(backend.lower_fs().exists(&cipher_path).unwrap());
        assert!(metadata.file_type == FileType::File);
        assert_eq!(u16::from(metadata.permissions), 0o640);
    }

    #[test]
    fn mkdir_creates_cipher_directory_and_diriv() {
        let (_temp_dir, backend) = test_backend();

        let metadata = backend.mkdir("docs", 0o750_u16.into()).unwrap();
        let cipher_path = backend.plain_path_to_cipher(Utf8Path::new("docs")).unwrap();
        let diriv_path = backend.get_dir_iv_file(&cipher_path);

        assert!(backend.lower_fs().exists(&cipher_path).unwrap());
        assert!(backend.lower_fs().exists(&diriv_path).unwrap());
        assert!(metadata.file_type == FileType::Directory);
        assert_eq!(u16::from(metadata.permissions), 0o750);
    }

    #[test]
    fn remove_deletes_cipher_file() {
        let (_temp_dir, backend) = test_backend();

        backend.mknode("file.txt", 0o644_u16.into()).unwrap();
        let cipher_path = backend
            .plain_path_to_cipher(Utf8Path::new("file.txt"))
            .unwrap();

        backend.remove("file.txt").unwrap();

        assert!(!backend.lower_fs().exists(&cipher_path).unwrap());
    }

    #[test]
    fn remove_dir_deletes_directory_and_diriv() {
        let (_temp_dir, backend) = test_backend();

        backend.mkdir("docs", 0o755_u16.into()).unwrap();
        let cipher_path = backend.plain_path_to_cipher(Utf8Path::new("docs")).unwrap();
        let diriv_path = backend.get_dir_iv_file(&cipher_path);

        backend.remove_dir("docs").unwrap();

        assert!(!backend.lower_fs().exists(&cipher_path).unwrap());
        assert!(!backend.lower_fs().exists(&diriv_path).unwrap());
    }

    #[test]
    fn create_and_read_symlink_roundtrip() {
        let (_temp_dir, backend) = test_backend();

        let metadata = backend.create_symlink("link", "../target.txt").unwrap();

        assert!(metadata.file_type == FileType::SymLink);
        assert_eq!(backend.read_symlink("link").unwrap(), "../target.txt");
    }

    #[test]
    fn rename_moves_file_directory_and_symlink_entries() {
        let (_temp_dir, backend) = test_backend();

        backend.mknode("file.txt", 0o644_u16.into()).unwrap();
        backend.rename("file.txt", "file2.txt").unwrap();
        assert!(backend.metadata("file.txt").is_err());
        assert!(backend.metadata("file2.txt").is_ok());

        backend.mkdir("docs", 0o755_u16.into()).unwrap();
        backend.rename("docs", "docs2").unwrap();
        assert!(backend.metadata("docs").is_err());
        assert!(backend.metadata("docs2").is_ok());

        backend.create_symlink("link", "../target.txt").unwrap();
        backend.rename("link", "link2").unwrap();
        assert!(backend.metadata("link").is_err());
        assert!(backend.metadata("link2").is_ok());
        assert_eq!(backend.read_symlink("link2").unwrap(), "../target.txt");
    }

    #[test]
    fn set_permissions_and_time_update_plain_metadata() {
        let (_temp_dir, backend) = test_backend();
        let atime =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let mtime =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_123);

        backend.mknode("file.txt", 0o644_u16.into()).unwrap();
        let metadata = backend
            .set_permissions("file.txt", 0o600_u16.into())
            .unwrap();
        assert_eq!(u16::from(metadata.permissions), 0o600);

        backend
            .set_time("file.txt", Some(atime), Some(mtime))
            .unwrap();
        let after = backend.metadata("file.txt").unwrap();
        assert_eq!(after.accessed, atime);
        assert_eq!(after.modified, mtime);
    }
}
