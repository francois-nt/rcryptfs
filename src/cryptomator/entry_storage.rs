use crate::core::{
    DirectoryLayout, EntryStorage, FileType, FsBackend, NativeFileSystem, OrIoError, Permissions,
    RootDirectoryToken, StorageDirEntry, StorageDirectory, StorageEntryKind, StorageFileSystem,
    StorageFileSystemAccess, StorageMetadata, Utf8Path, Utf8PathBuf, VirtualPath, VirtualPathBuf,
    forward_storage_fs_operations,
};

const CRYPTOMATOR_DIR_FILE: &str = "dir.c9r";
const CRYPTOMATOR_SYMLINK_FILE: &str = "symlink.c9r";

/// Returns whether a path addresses a Cryptomator directory contents location.
fn is_c9r_contents_path(path: &VirtualPath) -> bool {
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

/// Cryptomator entry representation used by Cryptomator-compatible layouts.
pub struct CryptomatorEntryStorage<F: StorageFileSystem> {
    storage_fs: F,
}

impl<F: StorageFileSystem> CryptomatorEntryStorage<F> {
    /// Creates a Cryptomator container representation over a raw filesystem.
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
                    .read_all(&entry_path.join(CRYPTOMATOR_DIR_FILE))?,
                RootDirectoryToken::Implicit(token) => token,
            }
        } else {
            self.storage_fs
                .read_all(&entry_path.join(CRYPTOMATOR_DIR_FILE))?
        };
        directory_layout
            .validate_directory_token(&token, entry_path.is_empty())
            .or_invalid()?;
        Ok(token)
    }

    /// Determines the logical kind represented by physical metadata.
    fn classify(
        &self,
        path: &VirtualPath,
        file_type: FileType,
    ) -> std::io::Result<StorageEntryKind> {
        match file_type {
            FileType::File => Ok(StorageEntryKind::File),
            FileType::Directory if is_c9r_contents_path(path) => Ok(StorageEntryKind::Directory),
            FileType::Directory if self.storage_fs.exists(&path.join(CRYPTOMATOR_DIR_FILE))? => {
                Ok(StorageEntryKind::Directory)
            }
            FileType::Directory
                if self
                    .storage_fs
                    .exists(&path.join(CRYPTOMATOR_SYMLINK_FILE))? =>
            {
                Ok(StorageEntryKind::Symlink)
            }
            _ => Ok(StorageEntryKind::Other),
        }
    }

    /// Removes a partially-created visible container without masking its error.
    fn remove_partial_entry(&self, path: &VirtualPath) {
        let _ = self.storage_fs.remove_dir_all(path);
    }
}

impl From<Utf8PathBuf> for FsBackend<CryptomatorEntryStorage<NativeFileSystem>> {
    fn from(root: Utf8PathBuf) -> Self {
        Self::new(CryptomatorEntryStorage::new(NativeFileSystem::new(root)))
    }
}

impl From<&Utf8Path> for FsBackend<CryptomatorEntryStorage<NativeFileSystem>> {
    fn from(root: &Utf8Path) -> Self {
        root.to_owned().into()
    }
}

impl<F: StorageFileSystem> StorageFileSystemAccess for CryptomatorEntryStorage<F> {
    type StorageFs = F;

    fn storage_fs(&self) -> &Self::StorageFs {
        &self.storage_fs
    }
}

impl<F: StorageFileSystem> EntryStorage for CryptomatorEntryStorage<F> {
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
        let kind = self.classify(path, raw.file_type)?;
        Ok(StorageMetadata { raw, kind })
    }

    fn read_dir(&self, contents_path: &VirtualPath) -> std::io::Result<Self::DirEntries> {
        let mut entries = Vec::new();
        for entry in self.storage_fs.read_dir(contents_path)? {
            match entry {
                Ok(entry) if entry.file_name == "dirid.c9r" => {}
                Ok(entry) => {
                    let path = contents_path.join(&entry.file_name);
                    match self.classify(&path, entry.metadata.file_type) {
                        Ok(kind) => entries.push(Ok(StorageDirEntry {
                            file_name: entry.file_name,
                            path,
                            metadata: StorageMetadata {
                                raw: entry.metadata,
                                kind,
                            },
                        })),
                        Err(error) => entries.push(Err(error)),
                    }
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
        let token = self.directory_token(entry_path, directory_layout)?;
        let contents_path = directory_layout
            .detached_directory_contents_path(entry_path, &token)
            .or_invalid()?;
        Ok(StorageDirectory {
            entry_path: entry_path.to_owned(),
            contents_path,
            token,
        })
    }

    fn initialize_root_directory<L: DirectoryLayout + ?Sized>(
        &self,
        directory_layout: &L,
    ) -> std::io::Result<StorageDirectory> {
        let (token, persist_token) = match directory_layout.root_directory_token() {
            RootDirectoryToken::Persisted => (directory_layout.generate_directory_token(), true),
            RootDirectoryToken::Implicit(token) => (token, false),
        };
        directory_layout
            .validate_directory_token(&token, true)
            .or_invalid()?;
        let contents_path = directory_layout
            .detached_directory_contents_path(VirtualPath::root(), &token)
            .or_invalid()?;
        let token_path = VirtualPath::root().join(CRYPTOMATOR_DIR_FILE);
        if persist_token {
            self.storage_fs.put_new(&token_path, &token)?;
        }
        if let Err(error) = self.storage_fs.mkdir_all(&contents_path) {
            if persist_token {
                let _ = self.storage_fs.remove(&token_path);
            }
            return Err(error);
        }
        Ok(StorageDirectory {
            entry_path: VirtualPathBuf::default(),
            contents_path,
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
        directory_layout
            .validate_directory_token(&token, false)
            .or_invalid()?;
        let contents_path = directory_layout
            .detached_directory_contents_path(&entry_path, &token)
            .or_invalid()?;
        let directory = StorageDirectory {
            entry_path,
            contents_path,
            token,
        };
        self.storage_fs.mkdir(&directory.entry_path, None)?;
        if let Err(error) = self.storage_fs.put(
            &directory.entry_path.join(CRYPTOMATOR_DIR_FILE),
            &directory.token,
        ) {
            self.remove_partial_entry(&directory.entry_path);
            return Err(error);
        }

        let contents_parent = directory
            .contents_path
            .parent()
            .unwrap_or_else(VirtualPath::root);
        if let Err(error) = self.storage_fs.mkdir_all(contents_parent) {
            self.remove_partial_entry(&directory.entry_path);
            return Err(error);
        }
        if let Err(error) = self.storage_fs.mkdir(&directory.contents_path, None) {
            self.remove_partial_entry(&directory.entry_path);
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
        self.storage_fs.remove_dir(&directory.contents_path)?;
        self.storage_fs.remove_dir_all(&directory.entry_path)
    }

    fn remove_file(&self, path: &VirtualPath) -> std::io::Result<()> {
        self.storage_fs.remove(path)
    }

    fn create_symlink(
        &self,
        path: &VirtualPath,
        target: &[u8],
    ) -> std::io::Result<StorageMetadata> {
        self.storage_fs.mkdir(path, None)?;
        if let Err(error) = self
            .storage_fs
            .put(&path.join(CRYPTOMATOR_SYMLINK_FILE), target)
        {
            self.remove_partial_entry(path);
            return Err(error);
        }
        let raw = self.storage_fs.metadata(path)?;
        Ok(StorageMetadata {
            raw,
            kind: StorageEntryKind::Symlink,
        })
    }

    fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<Vec<u8>> {
        self.storage_fs
            .read_all(&path.join(CRYPTOMATOR_SYMLINK_FILE))
    }

    fn remove_symlink(&self, path: &VirtualPath) -> std::io::Result<()> {
        self.storage_fs.remove_dir_all(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{DirectoryContentLayout, NativeFileSystem, Utf8Path};
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
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        (
            temp_dir,
            CryptomatorEntryStorage::new(NativeFileSystem::new(root)),
        )
    }

    #[test]
    fn cryptomator_storage_classifies_container_entries() {
        let (_temp_dir, storage) = cryptomator_storage();
        storage
            .storage_fs
            .mkdir(VirtualPath::new("root"), None)
            .unwrap();
        let entry_path = VirtualPathBuf::from("root/encoded-dir.c9r");
        let token = b"12345678-1234-1234-1234-123456789abc".to_vec();
        let content_layout = FixedDirectoryContentLayout {
            contents_path: "d/AB/ABCDEFGHIJKLMNOPQRSTUVWXYZ2345".into(),
        };

        assert!(matches!(
            storage.metadata(&content_layout.contents_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ));

        let metadata = storage
            .create_directory(entry_path.clone(), token.clone(), &content_layout, None)
            .unwrap();
        assert_eq!(metadata.kind, StorageEntryKind::Directory);
        let directory = storage
            .resolve_directory(&entry_path, &content_layout)
            .unwrap();
        assert_eq!(
            storage.metadata(&directory.contents_path).unwrap().kind,
            StorageEntryKind::Directory
        );
        assert_eq!(directory.contents_path, content_layout.contents_path);
        assert_eq!(directory.token, token);
        assert!(
            storage
                .resolve_directory(VirtualPath::root(), &content_layout)
                .unwrap()
                .token
                .is_empty()
        );

        let target = [0xff, 0x00, 0x7f];
        let metadata = storage
            .create_symlink(VirtualPath::new("root/encoded-link.c9r"), &target)
            .unwrap();
        assert_eq!(metadata.kind, StorageEntryKind::Symlink);
        assert!(metadata.raw.file_type == FileType::Directory);
        assert_eq!(
            storage
                .read_symlink(VirtualPath::new("root/encoded-link.c9r"))
                .unwrap(),
            target
        );

        storage
            .storage_fs
            .put(VirtualPath::new("root/dirid.c9r"), b"internal")
            .unwrap();
        let entries = storage
            .read_dir(VirtualPath::new("root"))
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .any(|entry| entry.metadata.kind == StorageEntryKind::Directory)
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.metadata.kind == StorageEntryKind::Symlink)
        );

        let symlink_path = VirtualPath::new("root/encoded-link.c9r");
        storage.remove_symlink(symlink_path).unwrap();
        assert!(storage.storage_fs.metadata(symlink_path).is_err());

        let file_path = VirtualPath::new("root/encoded-file.c9r");
        storage.storage_fs.put(file_path, b"contents").unwrap();
        storage.remove_file(file_path).unwrap();
        assert!(storage.storage_fs.metadata(file_path).is_err());

        storage.remove_directory(&directory).unwrap();
        assert!(storage.storage_fs.metadata(&directory.entry_path).is_err());
        assert!(
            storage
                .storage_fs
                .metadata(&directory.contents_path)
                .is_err()
        );
    }
}
