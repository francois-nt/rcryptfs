use super::CryptoMator;
use crate::core::{
    Backend, CacheAccess, CipherPathLayout, EncryptionLayout, EncryptionTranslator, FileType,
    FsBackend, FsDirEntry, Metadata, MinimalFs, OrIoError, Permissions, Result, Utf8Path,
    Utf8PathBuf, VirtualPath, VirtualPathBuf, default_remove_cached_plain_path, temp_file_path,
};
use anyhow::{Context, anyhow};

/// Reads the directory id vector from a cipher directory.
fn read_dirid(fs: &impl MinimalFs, cipher_dir: &Utf8Path, is_root: bool) -> Result<String> {
    if is_root {
        return Ok(String::default());
    }
    let p = cipher_dir.join("dir.c9r");
    let data = String::from_utf8(fs.read(&p, 0, 37)?).context(format!("read {:?}", p))?;
    if data.len() != 36 {
        return Err(anyhow!("dirid has len {}, expected 36", data.len()));
    }
    Ok(data)
}

/// Resolves a plain folder path to its storage directory and dir id.
fn folder_path_to_cipher_and_dirid<F: MinimalFs>(
    this: &CryptoMator<FsBackend<F>>,
    plain_path: &VirtualPath,
) -> Result<(Utf8PathBuf, Vec<u8>)> {
    this.backend.access(|cache| {
        if let Some((dir_id, cipher_path)) = cache.get(plain_path.as_str()) {
            Ok((cipher_path.to_owned(), dir_id.clone()))
        } else {
            if plain_path.as_str().is_empty() {
                let cipher_path = this.dir_id_to_storage_path(&String::default())?;
                cache.insert(String::default(), (Vec::default(), cipher_path.clone()));
                return Ok((cipher_path, Vec::default()));
            }

            let mut partial_plain_path = VirtualPathBuf::from("");
            let mut absolute_path = Utf8PathBuf::default();
            let mut is_root = true;
            for plain_part in plain_path.iter() {
                if let Some((dir_id, cipher_parent)) = cache.get(partial_plain_path.as_str()) {
                    let cipher_part = this.plain_name_to_cipher(dir_id, plain_part)?;
                    absolute_path = cipher_parent.join(cipher_part);
                } else {
                    let dir_id = read_dirid(this.lower_fs(), &absolute_path, is_root)?;

                    absolute_path = this.dir_id_to_storage_path(&dir_id)?;
                    cache.insert(
                        partial_plain_path.as_str().into(),
                        (dir_id.as_bytes().into(), absolute_path.clone()),
                    );
                    let cipher_part = this.plain_name_to_cipher(dir_id.as_bytes(), plain_part)?;
                    absolute_path.push(cipher_part);
                }
                partial_plain_path.push(plain_part);
                if is_root {
                    is_root = false
                }
            }

            let dir_id = read_dirid(this.lower_fs(), &absolute_path, is_root)?;
            absolute_path = this.dir_id_to_storage_path(&dir_id)?;

            cache.insert(
                partial_plain_path.as_str().into(),
                (dir_id.as_bytes().into(), absolute_path.clone()),
            );

            Ok((absolute_path, dir_id.as_bytes().into()))
        }
    })
}

impl<F: MinimalFs> CipherPathLayout for CryptoMator<FsBackend<F>> {
    type LowerFs = F;
    fn lower_fs(&self) -> &Self::LowerFs {
        self.backend.get_fs()
    }
    /// Resolves one logical path to its visible storage entry inside the parent storage directory.
    fn plain_path_to_cipher(&self, plain_path: &VirtualPath) -> Result<Utf8PathBuf> {
        if plain_path.as_str().is_empty() {
            return Ok(folder_path_to_cipher_and_dirid(self, plain_path)?.0);
        }

        let parent = plain_path.parent().unwrap_or_else(|| VirtualPath::new(""));
        let name = plain_path.file_name().or_invalid()?;
        let (cipher_parent_path, dir_id) = folder_path_to_cipher_and_dirid(self, parent)?;
        let cipher_name = self.plain_name_to_cipher(&dir_id, name)?;
        Ok(cipher_parent_path.join(cipher_name))
    }
    /// Creates a temporary path inside the cipher root for rename-based updates.
    fn create_temp_name(&self, path: &str, is_dir_iv: bool) -> Utf8PathBuf {
        temp_file_path(&self.backend.cipher_root, path, is_dir_iv)
    }
    /// Drops one cached plain path and all cached descendants derived from it.
    fn remove_cached_plain_path(&self, plain_path: &VirtualPath) {
        default_remove_cached_plain_path(&self.backend, plain_path);
    }
    /// Returns the marker file that makes a visible entry behave like a logical directory.
    fn get_dir_iv_file(&self, cipher_folder_path: &Utf8Path) -> Utf8PathBuf {
        cipher_folder_path.join("dir.c9r")
    }
}

impl<F: MinimalFs> EncryptionLayout for CryptoMator<FsBackend<F>> {
    fn list_dir_plain_names(
        &self,
        plain_path: &VirtualPath,
    ) -> std::io::Result<
        impl Iterator<Item = std::io::Result<(FsDirEntry, Utf8PathBuf)>> + '_ + use<'_, F>,
    > {
        // Directory listings come from the storage directory identified by the folder dir id.
        let (cipher_path, dir_id) =
            folder_path_to_cipher_and_dirid(self, plain_path).or_invalid()?;
        // let plain_path: Utf8PathBuf = plain_path.into();
        // let cipher_path = self.plain_path_to_cipher(&plain_path)?;
        // let dir_id = if plain_path == "" {
        //     "".into()
        // } else {
        //     read_dirid(&cipher_path)?
        // };
        // let cipher_path = self.dir_id_to_storage_path(&dir_id)?;
        log::debug!("read_dir on {}", cipher_path);
        Ok(self
            .lower_fs()
            .list_dir(&cipher_path)?
            .filter_map(move |entry| {
                match &entry {
                    Ok(entry) => log::debug!("> entry Ok {entry}"),
                    Err(e) => log::debug!("> entry Err {e}"),
                };
                match map_dir_entry(self, &cipher_path, &dir_id, entry) {
                    Ok(Some((plain_name, cipher_path))) => Some(Ok((plain_name, cipher_path))),
                    Ok(None) => None,
                    Err(e) => Some(Err(e)),
                }
            }))

        // Ok(std::fs::read_dir(&cipher_path)?.filter_map(move |entry| {
        //     log::debug!("> entry {:?}", entry);
        //     match map_dir_entry(self, &cipher_path, &dir_id, entry) {
        //         Ok(Some((plain_name, cipher_path))) => Some(Ok((plain_name, cipher_path))),
        //         Ok(None) => None,
        //         Err(e) => Some(Err(e)),
        //     }
        // }))
    }

    fn metadata(&self, plain_path: &VirtualPath) -> std::io::Result<Metadata> {
        // Metadata must be rewritten from the raw storage view to the logical Cryptomator view.
        let cipher_path = self.plain_path_to_cipher(plain_path).or_invalid()?;
        log::debug!("metadata on [{plain_path}] : {cipher_path}");
        let mut metadata = self.lower_fs().metadata(&cipher_path)?;
        metadata
            .adjust(self, &cipher_path, plain_path.is_empty())
            .or_io_error(libc::EBADF)?;
        Ok(metadata)
    }

    fn mkdir(
        &self,
        plain_path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        log::debug!("mkdir on {plain_path}");
        // A logical directory is represented twice: once as a visible entry with dir.c9r,
        // and once as its storage directory addressed by the generated dir id.
        let parent = plain_path.parent().unwrap_or_else(|| VirtualPath::new(""));
        let name = plain_path.file_name().or_invalid()?;

        log::debug!("parent {parent} - name {name}");

        let cached = self.backend.access(|cache| {
            if let Some((parent_dir_id, cipher_parent_path)) = cache.get(parent.as_str()) {
                log::debug!("found {parent} in cache! {cipher_parent_path}");
                Some((
                    str::from_utf8(parent_dir_id).unwrap_or_default().into(),
                    cipher_parent_path.clone(),
                ))
            } else {
                None
            }
        });
        let (parent_dir_id, cipher_parent_path) = match cached {
            Some((parent_dir_id, cipher_parent_path)) => (parent_dir_id, cipher_parent_path),
            None => {
                let is_root = parent.as_str().is_empty();
                let cipher_parent_path = self.plain_path_to_cipher(parent).or_invalid()?;
                log::debug!("computed cipher_parent_path for {parent} - {cipher_parent_path}");
                let parent_dir_id =
                    read_dirid(self.lower_fs(), &cipher_parent_path, is_root).or_invalid()?;
                (parent_dir_id, cipher_parent_path)
            }
        };

        log::debug!("cipher parent path is {cipher_parent_path}");

        let cipher_name = self
            .plain_name_to_cipher(parent_dir_id.as_bytes(), name)
            .or_invalid()?;
        log::debug!("cipher_name is {cipher_name}");
        let new_dir_iv = self.generate_diriv();
        let cipher_path = cipher_parent_path.join(cipher_name);
        log::debug!("cipher_path is {cipher_path}");
        self.lower_fs().mkdir(&cipher_path)?;
        let new_dir_iv_file = self.get_dir_iv_file(&cipher_path);
        log::debug!("new_dir_iv_file is {new_dir_iv_file}");
        self.lower_fs()
            .put(&new_dir_iv_file, &new_dir_iv)
            .or_invalid()?;

        self.mkdir_storage_path(str::from_utf8(&new_dir_iv).unwrap_or_default())
            .or_invalid()?;
        self.lower_fs().set_permissions(&cipher_path, permissions)
    }
    fn mknode(
        &self,
        plain_path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        // Empty logical files are materialized with a header immediately.
        let cipher_path = self.plain_path_to_cipher(plain_path).or_invalid()?;
        self.lower_fs()
            .put(&cipher_path, &self.generate_cipher_header().or_invalid()?)
            .or_invalid()?;
        self.lower_fs().set_permissions(&cipher_path, permissions)
    }
    fn remove_dir(&self, plain_path: &VirtualPath) -> std::io::Result<()> {
        // Removing a logical directory must remove both its visible entry and its storage directory.
        let cipher_path = self.plain_path_to_cipher(plain_path).or_invalid()?;
        let is_root = plain_path.is_empty();
        let dir_id = read_dirid(self.lower_fs(), &cipher_path, is_root).or_invalid()?;

        let children_path = self.dir_id_to_storage_path(&dir_id).or_invalid()?;
        self.lower_fs()
            .remove_dir(&children_path, false)
            .inspect_err(|e| log::error!("cant rmdir on {children_path} - {e}"))?;
        self.lower_fs()
            .remove_dir(&cipher_path, true)
            .inspect_err(|e| log::error!("cant rmdir all on {cipher_path} - {e}"))?;
        self.remove_cached_plain_path(plain_path);
        Ok(())
    }
    fn remove(&self, plain_path: &VirtualPath) -> std::io::Result<()> {
        // Logical symlinks are stored as directories, so removal depends on the visible entry type.
        let cipher_path = self.plain_path_to_cipher(plain_path).or_invalid()?;
        let meta = self.lower_fs().metadata(&cipher_path)?;
        match meta.file_type {
            FileType::File => self.lower_fs().remove_file(&cipher_path),
            _ => self.lower_fs().remove_dir(&cipher_path, true),
        }
    }
    fn read_symlink(&self, plain_path: &VirtualPath) -> std::io::Result<String> {
        // Logical symlink targets live in the symlink.c9r payload inside the visible entry.
        let cipher_path = self.plain_path_to_cipher(plain_path).or_invalid()?;
        let symlink_content = cipher_path.join("symlink.c9r");
        let data = self
            .lower_fs()
            .read(&symlink_content, 0, 1024)
            .or_invalid()?;
        let target = self.cipher_metavalue_to_plain(&data).or_invalid()?;
        Ok(str::from_utf8(&target).or_invalid()?.into())
    }
    /// Ignores chmod on logical symlinks so the backing directory stays traversable.
    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        let metadata = self.metadata(path)?;
        if metadata.file_type == FileType::SymLink {
            return Ok(metadata);
        }
        let cipher_path = self.plain_path_to_cipher(path).or_invalid()?;
        self.lower_fs().set_permissions(&cipher_path, permissions)
    }
    /// Creates a logical symlink as a visible directory containing one encrypted target payload.
    fn create_symlink(&self, plain_path: &VirtualPath, target: &str) -> std::io::Result<Metadata> {
        let cipher_path = self.plain_path_to_cipher(plain_path).or_invalid()?;
        let cipher_target = self
            .plain_metavalue_to_cipher(target.as_bytes())
            .or_invalid()?;
        self.lower_fs().mkdir(&cipher_path)?;
        self.lower_fs()
            .put(&cipher_path.join("symlink.c9r"), &cipher_target)?;
        let mut meta = self.lower_fs().metadata(&cipher_path)?;
        meta.adjust(self, &cipher_path, false).or_invalid()?;
        Ok(meta)
    }
}

fn is_special_entry(name: &str) -> bool {
    name == "dirid.c9r"
}

/// Adjusts raw lower-fs metadata to the logical Cryptomator view.
trait AdujstMetadata {
    fn adjust<T: EncryptionLayout>(
        &mut self,
        this: &T,
        path: &Utf8Path,
        is_root: bool,
    ) -> Result<()>;
}

impl AdujstMetadata for Metadata {
    fn adjust<T: EncryptionLayout>(
        &mut self,
        this: &T,
        path: &Utf8Path,
        is_root: bool,
    ) -> Result<()> {
        if self.file_type == FileType::File {
            self.len = this.cipher_size_to_plain(self.len)?;
            self.blocks = 1 + self.len / T::PLAIN_BLOCK_LEN;
        } else if self.file_type == FileType::Directory {
            if !is_root {
                let dir = path.join("dir.c9r");
                if !this.lower_fs().exists(&dir)? {
                    let symlink = path.join("symlink.c9r");
                    if this.lower_fs().exists(&symlink)? {
                        self.file_type = FileType::SymLink;
                        self.permissions = 0o777_u16.into();
                    } else {
                        self.file_type = FileType::Other;
                    }
                }
            }
        } else {
            self.file_type = FileType::Other;
        }
        Ok(())
    }
}

/// Maps one storage entry to its plain directory entry when it should be visible.
fn map_dir_entry(
    this: &impl EncryptionLayout,
    cipher_path: &Utf8Path,
    dir_iv: &[u8],
    entry: std::io::Result<FsDirEntry>,
) -> std::io::Result<Option<(FsDirEntry, Utf8PathBuf)>> {
    match entry {
        Ok(mut entry) => {
            let cipher_name = entry.file_name.clone();

            if is_special_entry(&cipher_name) {
                Ok(None)
            } else {
                if let Some(metadata) = entry.metadata.as_mut() {
                    metadata
                        .adjust(this, &cipher_path.join(&cipher_name), false)
                        .or_invalid()?;
                    if let Some(file_type) = entry.file_type.as_mut() {
                        *file_type = metadata.file_type;
                    }
                }
                let plain_name = this
                    .cipher_name_to_plain(dir_iv, &cipher_name)
                    .or_invalid()?;
                Ok(Some((
                    entry.with_name(plain_name),
                    cipher_path.join(Utf8Path::new(&cipher_name)),
                )))
            }
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{CipherPathLayout, EncryptionLayout, FileType, FsBackend, Utf8Path};
    use tempfile::tempdir;

    /// Creates a borrowed plain path for tests.
    fn p(path: &str) -> &VirtualPath {
        VirtualPath::new(path)
    }

    /// Creates a deterministic Cryptomator backend with a materialized root storage directory.
    fn test_backend() -> (tempfile::TempDir, CryptoMator<FsBackend>) {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap();

        let mut siv_key = [0u8; 64];
        for (i, byte) in siv_key.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let backend = CryptoMator {
            backend: root.into(),
            siv_key,
        };

        backend
            .lower_fs()
            .mkdir_all(&backend.dir_id_to_storage_path("").unwrap())
            .unwrap();

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

        let entries: Vec<_> = backend
            .list_dir_plain_names(p(""))
            .unwrap()
            .map(|entry| entry.unwrap().0)
            .collect();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name, "link");
        assert!(entries[0].file_type == Some(FileType::SymLink));
    }

    #[test]
    fn metadata_reports_empty_plain_file_for_header_only_node() {
        let (_temp_dir, backend) = test_backend();

        backend.mknode(p("empty.txt"), 0o644_u16.into()).unwrap();

        let cipher_path = backend.plain_path_to_cipher(p("empty.txt")).unwrap();
        let raw_metadata = backend.lower_fs().metadata(&cipher_path).unwrap();
        let plain_metadata = backend.metadata(p("empty.txt")).unwrap();

        assert_eq!(
            raw_metadata.len,
            CryptoMator::<FsBackend>::HEADER_LEN as u64
        );
        assert_eq!(plain_metadata.len, 0);
        assert!(plain_metadata.file_type == FileType::File);
    }

    #[test]
    fn mkdir_creates_visible_and_storage_directories() {
        let (_temp_dir, backend) = test_backend();

        backend.mkdir(p("docs"), 0o755_u16.into()).unwrap();

        let cipher_path = backend.plain_path_to_cipher(p("docs")).unwrap();
        let dir_id = read_dirid(backend.lower_fs(), &cipher_path, false).unwrap();
        let storage_path = backend.dir_id_to_storage_path(&dir_id).unwrap();

        assert!(backend.lower_fs().exists(&cipher_path).unwrap());
        assert!(
            backend
                .lower_fs()
                .exists(&cipher_path.join("dir.c9r"))
                .unwrap()
        );
        assert!(backend.lower_fs().exists(&storage_path).unwrap());
        assert!(backend.metadata(p("docs")).unwrap().file_type == FileType::Directory);
    }

    #[test]
    fn remove_dir_removes_visible_and_storage_directories() {
        let (_temp_dir, backend) = test_backend();

        backend.mkdir(p("docs"), 0o755_u16.into()).unwrap();
        let cipher_path = backend.plain_path_to_cipher(p("docs")).unwrap();
        let dir_id = read_dirid(backend.lower_fs(), &cipher_path, false).unwrap();
        let storage_path = backend.dir_id_to_storage_path(&dir_id).unwrap();

        backend.remove_dir(p("docs")).unwrap();

        assert!(!backend.lower_fs().exists(&cipher_path).unwrap());
        assert!(!backend.lower_fs().exists(&storage_path).unwrap());
    }

    #[test]
    fn remove_deletes_file_and_symlink_entries() {
        let (_temp_dir, backend) = test_backend();

        backend.mknode(p("file.txt"), 0o644_u16.into()).unwrap();
        let file_path = backend.plain_path_to_cipher(p("file.txt")).unwrap();
        backend.remove(p("file.txt")).unwrap();
        assert!(!backend.lower_fs().exists(&file_path).unwrap());

        backend.create_symlink(p("link"), "../target.txt").unwrap();
        let symlink_path = backend.plain_path_to_cipher(p("link")).unwrap();
        backend.remove(p("link")).unwrap();
        assert!(!backend.lower_fs().exists(&symlink_path).unwrap());
    }

    #[test]
    fn list_dir_plain_names_filters_special_entries() {
        let (_temp_dir, backend) = test_backend();
        let root_storage = backend.dir_id_to_storage_path("").unwrap();

        backend
            .lower_fs()
            .put(&root_storage.join("dirid.c9r"), b"internal")
            .unwrap();

        let entries: Vec<_> = backend
            .list_dir_plain_names(p(""))
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();

        assert!(entries.is_empty());
    }

    #[test]
    fn rename_moves_file_directory_and_symlink_entries() {
        let (_temp_dir, backend) = test_backend();

        backend.mknode(p("file.txt"), 0o644_u16.into()).unwrap();
        backend.rename(p("file.txt"), p("file2.txt")).unwrap();
        assert!(backend.metadata(p("file.txt")).is_err());
        assert!(backend.metadata(p("file2.txt")).is_ok());
        assert!(backend.metadata(p("file2.txt")).unwrap().file_type == FileType::File);

        backend.mkdir(p("docs"), 0o755_u16.into()).unwrap();
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

        backend.mknode(p("file.txt"), 0o644_u16.into()).unwrap();
        let file_metadata = backend
            .set_permissions(p("file.txt"), 0o600_u16.into())
            .unwrap();
        assert_eq!(u16::from(file_metadata.permissions), 0o600);
        assert_eq!(
            u16::from(backend.metadata(p("file.txt")).unwrap().permissions),
            0o600
        );

        backend.mkdir(p("docs"), 0o755_u16.into()).unwrap();
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

        backend.mknode(p("file.txt"), 0o644_u16.into()).unwrap();
        let file_before = backend.metadata(p("file.txt")).unwrap();
        backend
            .set_time(p("file.txt"), Some(atime), Some(mtime))
            .unwrap();
        let file_after = backend.metadata(p("file.txt")).unwrap();
        assert_ne!(file_before.accessed, file_after.accessed);
        assert_ne!(file_before.modified, file_after.modified);
        assert_eq!(file_after.accessed, atime);
        assert_eq!(file_after.modified, mtime);

        backend.mkdir(p("docs"), 0o755_u16.into()).unwrap();
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
