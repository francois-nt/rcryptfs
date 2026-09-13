use crate::core::{
    DirectoryLayout, EntryStorage, FileType, FsBackend, NativeFileSystem, OrIoError, Permissions,
    RootDirectoryToken, StorageDirEntry, StorageDirectory, StorageEntryKind, StorageFileSystem,
    StorageFileSystemAccess, StorageMetadata, Utf8Path, Utf8PathBuf, VirtualPath, VirtualPathBuf,
    forward_storage_fs_operations, temp_file_path,
};

const GOCRYPTFS_DIRIV: &str = "gocryptfs.diriv";

/// Converts a native filesystem type to its GoCryptFS representation kind.
fn direct_entry_kind(file_type: FileType) -> StorageEntryKind {
    match file_type {
        FileType::File => StorageEntryKind::File,
        FileType::Directory => StorageEntryKind::Directory,
        FileType::SymLink => StorageEntryKind::Symlink,
        FileType::Other => StorageEntryKind::Other,
    }
}

/// Returns whether a raw GoCryptFS entry is internal to the representation.
fn is_direct_internal_entry(name: &str) -> bool {
    name.starts_with("temp.")
        || name == GOCRYPTFS_DIRIV
        || name == "gocryptfs.conf"
        || (name.starts_with("gocryptfs.longname.") && name.ends_with(".name"))
}

/// GoCryptFS entry representation used by GoCryptFS-compatible layouts.
pub struct GoCryptFsEntryStorage<F: StorageFileSystem> {
    storage_fs: F,
}

impl<F: StorageFileSystem> GoCryptFsEntryStorage<F> {
    /// Creates a GoCryptFS representation over a raw storage filesystem.
    pub fn new(storage_fs: F) -> Self {
        Self { storage_fs }
    }

    /// Returns the wrapped raw storage filesystem.
    pub fn into_inner(self) -> F {
        self.storage_fs
    }

    /// Resolves and validates the configured token for one directory.
    fn directory_token<L: DirectoryLayout + ?Sized>(
        &self,
        entry_path: &VirtualPath,
        directory_layout: &L,
    ) -> std::io::Result<Vec<u8>> {
        let token = if entry_path.is_empty() {
            match directory_layout.root_directory_token() {
                RootDirectoryToken::Persisted => self
                    .storage_fs
                    .read_all(&entry_path.join(GOCRYPTFS_DIRIV))?,
                RootDirectoryToken::Implicit(token) => token,
            }
        } else {
            self.storage_fs
                .read_all(&entry_path.join(GOCRYPTFS_DIRIV))?
        };
        directory_layout
            .validate_directory_token(&token, entry_path.is_empty())
            .or_invalid()?;
        Ok(token)
    }

    /// Validates that a GoCryptFS directory stores children in its visible entry.
    fn validate_directory(directory: &StorageDirectory) -> std::io::Result<()> {
        if directory.entry_path != directory.contents_path {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "GoCryptFS directory entry and contents paths must match",
            ));
        }
        Ok(())
    }
}

impl From<Utf8PathBuf> for FsBackend<GoCryptFsEntryStorage<NativeFileSystem>> {
    fn from(root: Utf8PathBuf) -> Self {
        Self::new(GoCryptFsEntryStorage::new(NativeFileSystem::new(root)))
    }
}

impl From<&Utf8Path> for FsBackend<GoCryptFsEntryStorage<NativeFileSystem>> {
    fn from(root: &Utf8Path) -> Self {
        root.to_owned().into()
    }
}

impl<F: StorageFileSystem> StorageFileSystemAccess for GoCryptFsEntryStorage<F> {
    type StorageFs = F;

    fn storage_fs(&self) -> &Self::StorageFs {
        &self.storage_fs
    }
}

impl<F: StorageFileSystem> EntryStorage for GoCryptFsEntryStorage<F> {
    type DirEntries = std::vec::IntoIter<std::io::Result<StorageDirEntry>>;

    forward_storage_fs_operations!(
        F,
        storage_fs;
        open_file_with,
        rename,
        set_permissions,
        set_time,
        chown,
        get_xattr,
        list_xattr,
        remove_xattr,
        set_xattr,
    );

    fn metadata(&self, path: &VirtualPath) -> std::io::Result<StorageMetadata> {
        let raw = self.storage_fs.metadata(path)?;
        let kind = direct_entry_kind(raw.file_type);
        Ok(StorageMetadata { raw, kind })
    }

    fn read_dir(&self, contents_path: &VirtualPath) -> std::io::Result<Self::DirEntries> {
        let mut entries = Vec::new();
        for entry in self.storage_fs.read_dir(contents_path)? {
            match entry {
                Ok(entry) if is_direct_internal_entry(&entry.file_name) => {}
                Ok(entry) => {
                    let path = contents_path.join(&entry.file_name);
                    let kind = direct_entry_kind(entry.metadata.file_type);
                    entries.push(Ok(StorageDirEntry {
                        file_name: entry.file_name,
                        path,
                        metadata: StorageMetadata {
                            raw: entry.metadata,
                            kind,
                        },
                    }));
                }
                Err(error) => entries.push(Err(error)),
            }
        }
        Ok(entries.into_iter())
    }

    fn resolve_directory<L: DirectoryLayout + ?Sized>(
        &self,
        entry_path: &VirtualPath,
        directory_layout: &L,
    ) -> std::io::Result<StorageDirectory> {
        let directory = StorageDirectory {
            entry_path: entry_path.to_owned(),
            contents_path: entry_path.to_owned(),
            token: self.directory_token(entry_path, directory_layout)?,
        };
        Self::validate_directory(&directory)?;
        Ok(directory)
    }

    fn initialize_root_directory<L: DirectoryLayout + ?Sized>(
        &self,
        directory_layout: &L,
    ) -> std::io::Result<StorageDirectory> {
        let token = match directory_layout.root_directory_token() {
            RootDirectoryToken::Persisted => {
                let token = directory_layout.generate_directory_token();
                directory_layout
                    .validate_directory_token(&token, true)
                    .or_invalid()?;
                self.storage_fs
                    .put_new(&VirtualPath::root().join(GOCRYPTFS_DIRIV), &token)?;
                token
            }
            RootDirectoryToken::Implicit(token) => {
                directory_layout
                    .validate_directory_token(&token, true)
                    .or_invalid()?;
                token
            }
        };
        Ok(StorageDirectory {
            entry_path: VirtualPathBuf::default(),
            contents_path: VirtualPathBuf::default(),
            token,
        })
    }

    fn create_file(
        &self,
        path: &VirtualPath,
        initial_contents: &[u8],
        permissions: Option<Permissions>,
    ) -> std::io::Result<StorageMetadata> {
        let raw = if initial_contents.is_empty() {
            self.storage_fs.mknode(path, permissions)?
        } else {
            self.storage_fs.put_new(path, initial_contents)?;
            match permissions {
                Some(permissions) => self.storage_fs.set_permissions(path, permissions)?,
                None => self.storage_fs.metadata(path)?,
            }
        };
        Ok(StorageMetadata {
            raw,
            kind: StorageEntryKind::File,
        })
    }

    fn create_directory<L: DirectoryLayout + ?Sized>(
        &self,
        entry_path: VirtualPathBuf,
        token: Vec<u8>,
        directory_layout: &L,
        permissions: Option<Permissions>,
    ) -> std::io::Result<StorageMetadata> {
        let directory = StorageDirectory {
            contents_path: entry_path.clone(),
            entry_path,
            token,
        };
        Self::validate_directory(&directory)?;
        directory_layout
            .validate_directory_token(&directory.token, false)
            .or_invalid()?;
        let temp_path = temp_file_path(directory.entry_path.as_str(), false);
        if self.storage_fs.exists(&temp_path)? {
            self.storage_fs.remove_dir_all(&temp_path)?;
        }

        self.storage_fs.mkdir(&temp_path, None)?;
        if let Err(error) = self
            .storage_fs
            .put(&temp_path.join(GOCRYPTFS_DIRIV), &directory.token)
        {
            let _ = self.storage_fs.remove_dir_all(&temp_path);
            return Err(error);
        }
        if let Err(error) = self.storage_fs.rename(&temp_path, &directory.entry_path) {
            let _ = self.storage_fs.remove_dir_all(&temp_path);
            return Err(error);
        }

        let raw = match permissions {
            Some(permissions) => self
                .storage_fs
                .set_permissions(&directory.entry_path, permissions)?,
            None => self.storage_fs.metadata(&directory.entry_path)?,
        };
        Ok(StorageMetadata {
            raw,
            kind: StorageEntryKind::Directory,
        })
    }

    fn remove_directory(&self, directory: &StorageDirectory) -> std::io::Result<()> {
        Self::validate_directory(directory)?;
        let marker_path = directory.entry_path.join(GOCRYPTFS_DIRIV);
        let temp_path = temp_file_path(marker_path.as_str(), true);
        if self.storage_fs.exists(&temp_path)? {
            self.storage_fs.remove(&temp_path)?;
        }

        self.storage_fs.rename(&marker_path, &temp_path)?;
        if let Err(error) = self.storage_fs.remove_dir(&directory.entry_path) {
            self.storage_fs.rename(&temp_path, &marker_path)?;
            return Err(error);
        }
        let _ = self.storage_fs.remove(&temp_path);
        Ok(())
    }

    fn remove_file(&self, path: &VirtualPath) -> std::io::Result<()> {
        self.storage_fs.remove(path)
    }

    fn create_symlink(
        &self,
        path: &VirtualPath,
        target: &[u8],
    ) -> std::io::Result<StorageMetadata> {
        let target = std::str::from_utf8(target)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let raw = self.storage_fs.create_symlink(path, target)?;
        Ok(StorageMetadata {
            raw,
            kind: StorageEntryKind::Symlink,
        })
    }

    fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<Vec<u8>> {
        Ok(self.storage_fs.read_symlink(path)?.into_bytes())
    }

    fn remove_symlink(&self, path: &VirtualPath) -> std::io::Result<()> {
        self.storage_fs.remove(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{DirectoryContentLayout, NativeFileSystem, Utf8Path};
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
    }

    impl DirectoryLayout for DetachedTestLayout {
        fn generate_directory_token(&self) -> Vec<u8> {
            vec![7; 16]
        }

        fn validate_directory_token(
            &self,
            token: &[u8],
            _is_root: bool,
        ) -> crate::core::Result<()> {
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
            GoCryptFsEntryStorage::new(NativeFileSystem::new(root)),
        )
    }

    #[test]
    fn gocryptfs_storage_materializes_directory_and_native_symlink() {
        let (_temp_dir, storage) = gocryptfs_storage();
        let root = storage
            .initialize_root_directory(&DetachedTestLayout)
            .unwrap();
        assert_eq!(root.token, vec![7; 16]);
        let entry_path = VirtualPathBuf::from("docs");
        let token = vec![7; 16];
        let metadata = storage
            .create_directory(entry_path.clone(), token.clone(), &DetachedTestLayout, None)
            .unwrap();
        assert_eq!(metadata.kind, StorageEntryKind::Directory);
        let directory = storage
            .resolve_directory(&entry_path, &DetachedTestLayout)
            .unwrap();
        assert_eq!(directory.entry_path, entry_path);
        assert_eq!(directory.contents_path, directory.entry_path);
        assert_eq!(directory.token, token);

        let metadata = storage
            .create_symlink(VirtualPath::new("link"), b"docs")
            .unwrap();
        assert_eq!(metadata.kind, StorageEntryKind::Symlink);
        assert_eq!(
            storage.read_symlink(VirtualPath::new("link")).unwrap(),
            b"docs"
        );

        storage
            .storage_fs
            .put(VirtualPath::new("gocryptfs.conf"), b"internal")
            .unwrap();
        let entries = storage
            .read_dir(VirtualPath::root())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 2);

        storage.remove_symlink(VirtualPath::new("link")).unwrap();
        assert!(storage.storage_fs.metadata("link".into()).is_err());

        storage
            .storage_fs
            .put(VirtualPath::new("file"), b"contents")
            .unwrap();
        storage.remove_file(VirtualPath::new("file")).unwrap();
        assert!(storage.storage_fs.metadata("file".into()).is_err());

        storage.remove_directory(&directory).unwrap();
        assert!(storage.storage_fs.metadata(&directory.entry_path).is_err());
    }
}
