use super::representation::*;
use super::*;

impl<F: StorageFileSystem> GoCryptFsEntryStorage<F> {
    /// Initializes the represented root while the raw filesystem is still borrowed.
    pub(in crate::gocryptfs) fn initialize_root_storage(
        storage_fs: &F,
        directory_layout: &dyn DirectoryLayout,
    ) -> std::io::Result<StorageDirectory> {
        let token = match directory_layout.root_directory_token() {
            RootDirectoryToken::Persisted => {
                let token = directory_layout.generate_directory_token();
                directory_layout
                    .validate_directory_token(&token, true)
                    .or_invalid()?;
                storage_fs.put_new(&VirtualPath::root().join(GOCRYPTFS_DIRIV), &token)?;
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

    /// Prepares a destination and reports whether it created a sidecar.
    fn prepare_sidecar(
        &self,
        logical_path: &VirtualPath,
        paths: &EntryPaths,
    ) -> std::io::Result<bool> {
        let Some(sidecar) = &paths.sidecar else {
            return Ok(false);
        };
        let name = logical_path.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing entry name")
        })?;
        match self.storage_fs.put_new(sidecar, name.as_bytes()) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.storage_fs.read_all(sidecar)? == name.as_bytes() {
                    Ok(false)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "GoCryptFS long-name sidecar does not match its content path",
                    ))
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Removes a sidecar created before an operation that subsequently failed.
    fn rollback_sidecar(&self, paths: &EntryPaths) {
        if let Some(sidecar) = &paths.sidecar {
            let _ = self.storage_fs.remove(sidecar);
        }
    }

    /// Resolves and validates the logical encoded name stored in a sidecar.
    fn read_long_name(
        &self,
        contents_path: &VirtualPath,
        physical_name: &str,
    ) -> std::io::Result<String> {
        let sidecar = contents_path.join(format!("{physical_name}{GOCRYPTFS_LONGNAME_SUFFIX}"));
        let name = String::from_utf8(self.storage_fs.read_all(&sidecar)?)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        if name.len() <= usize::from(self.options.long_name_max)
            || self.hash_long_name(&name) != physical_name
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid GoCryptFS long-name sidecar",
            ));
        }
        Ok(name)
    }

    /// Resolves and validates the configured token for one directory.
    fn directory_token(&self, entry_path: &VirtualPath) -> std::io::Result<Vec<u8>> {
        let directory_layout = self.directory_layout.as_ref();
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
}

impl From<Utf8PathBuf> for EntryStorageBackend<GoCryptFsEntryStorage<NativeFileSystem>> {
    fn from(root: Utf8PathBuf) -> Self {
        Self::new(GoCryptFsEntryStorage::new(NativeFileSystem::new(root)))
    }
}

impl From<&Utf8Path> for EntryStorageBackend<GoCryptFsEntryStorage<NativeFileSystem>> {
    fn from(root: &Utf8Path) -> Self {
        root.to_owned().into()
    }
}

/// Lazily maps physical GoCryptFS directory entries to represented entries.
pub struct GoCryptFsDirEntries<'a, F: StorageFileSystem> {
    storage: &'a GoCryptFsEntryStorage<F>,
    contents_path: VirtualPathBuf,
    entries: F::DirEntries,
}

impl<F: StorageFileSystem> Iterator for GoCryptFsDirEntries<'_, F> {
    type Item = std::io::Result<StorageDirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.entries.next()? {
                Ok(entry) if is_direct_internal_entry(&entry.file_name) => continue,
                Ok(entry) => {
                    let path = self.contents_path.join(&entry.file_name);
                    let file_name = if is_long_name_content(&entry.file_name) {
                        self.storage
                            .read_long_name(&self.contents_path, &entry.file_name)
                    } else {
                        Ok(entry.file_name)
                    };
                    return Some(file_name.map(|file_name| StorageDirEntry {
                        file_name,
                        path,
                        metadata: entry.metadata,
                    }));
                }
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

impl<F: StorageFileSystem> EntryStorage for GoCryptFsEntryStorage<F> {
    type DirEntries<'a>
        = GoCryptFsDirEntries<'a, F>
    where
        Self: 'a;

    fn generate_directory_token(&self) -> Vec<u8> {
        self.directory_layout.generate_directory_token()
    }

    forward_storage_fs_operations!(
        F,
        storage_fs;
        map_path = |this: &Self, path: &VirtualPath| this.entry_paths(path).content;
        open_file_with,
        get_xattr,
        list_xattr,
        remove_xattr,
        set_xattr,
    );

    fn metadata(&self, path: &VirtualPath) -> std::io::Result<Metadata> {
        self.storage_fs.metadata(&self.entry_paths(path).content)
    }

    fn read_dir<'a>(
        &'a self,
        contents_path: VirtualPathBuf,
    ) -> std::io::Result<Self::DirEntries<'a>> {
        let entries = self.storage_fs.read_dir(&contents_path)?;
        Ok(GoCryptFsDirEntries {
            storage: self,
            contents_path,
            entries,
        })
    }

    fn resolve_directory(&self, entry_path: &VirtualPath) -> std::io::Result<StorageDirectory> {
        let entry_path = self.entry_paths(entry_path).content;
        let directory = StorageDirectory {
            contents_path: entry_path.clone(),
            token: self.directory_token(&entry_path)?,
            entry_path,
        };
        Self::validate_directory(&directory)?;
        Ok(directory)
    }

    fn initialize_root_directory(&self) -> std::io::Result<StorageDirectory> {
        Self::initialize_root_storage(&self.storage_fs, self.directory_layout.as_ref())
    }

    fn create_file(
        &self,
        path: &VirtualPath,
        initial_contents: &[u8],
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        let paths = self.entry_paths(path);
        let temp_path = temp_file_path(&format!("file:{}", paths.content), false);
        if self.storage_fs.exists(&temp_path)? {
            self.storage_fs.remove(&temp_path)?;
        }

        let raw = if initial_contents.is_empty() {
            self.storage_fs.mknode(&temp_path, permissions)?
        } else {
            self.storage_fs.put_new(&temp_path, initial_contents)?;
            match permissions {
                Some(permissions) => self.storage_fs.set_permissions(&temp_path, permissions)?,
                None => self.storage_fs.metadata(&temp_path)?,
            }
        };

        let created_sidecar = match self.prepare_sidecar(path, &paths) {
            Ok(created) => created,
            Err(error) => {
                let _ = self.storage_fs.remove(&temp_path);
                return Err(error);
            }
        };
        if let Err(error) = self
            .storage_fs
            .rename_no_replace(&temp_path, &paths.content)
        {
            let _ = self.storage_fs.remove(&temp_path);
            if created_sidecar {
                self.rollback_sidecar(&paths);
            }
            return Err(error);
        }
        Ok(raw)
    }

    fn create_directory(
        &self,
        entry_path: VirtualPathBuf,
        token: Vec<u8>,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        let directory_layout = self.directory_layout.as_ref();
        let paths = self.entry_paths(&entry_path);
        let directory = StorageDirectory {
            contents_path: paths.content.clone(),
            entry_path: paths.content.clone(),
            token,
        };
        Self::validate_directory(&directory)?;
        directory_layout
            .validate_directory_token(&directory.token, false)
            .or_invalid()?;
        let temp_path = temp_file_path(&format!("directory:{}", directory.entry_path), false);
        if self.storage_fs.exists(&temp_path)? {
            self.storage_fs.remove_dir_all(&temp_path)?;
        }

        let raw = self.storage_fs.mkdir(&temp_path, permissions)?;
        if let Err(error) = self
            .storage_fs
            .put(&temp_path.join(GOCRYPTFS_DIRIV), &directory.token)
        {
            let _ = self.storage_fs.remove_dir_all(&temp_path);
            return Err(error);
        }
        let created_sidecar = match self.prepare_sidecar(&entry_path, &paths) {
            Ok(created) => created,
            Err(error) => {
                let _ = self.storage_fs.remove_dir_all(&temp_path);
                return Err(error);
            }
        };
        if let Err(error) = self
            .storage_fs
            .rename_no_replace(&temp_path, &directory.entry_path)
        {
            let _ = self.storage_fs.remove_dir_all(&temp_path);
            if created_sidecar {
                self.rollback_sidecar(&paths);
            }
            return Err(error);
        }
        Ok(raw)
    }

    fn remove_directory(&self, directory: &StorageDirectory) -> std::io::Result<()> {
        Self::validate_directory(directory)?;
        let mut non_directories = vec![directory.entry_path.join(GOCRYPTFS_DIRIV)];
        if let Some(sidecar) = Self::physical_sidecar_path(&directory.entry_path) {
            non_directories.push(sidecar);
        }
        self.storage_fs.remove_multiple(
            std::slice::from_ref(&directory.entry_path),
            &non_directories,
        )
    }

    fn remove_entry(&self, path: &VirtualPath) -> std::io::Result<()> {
        let paths = self.entry_paths(path);
        if let Some(sidecar) = paths.sidecar {
            self.storage_fs
                .remove_multiple(&[], &[paths.content, sidecar])
        } else {
            self.storage_fs.remove(&paths.content)
        }
    }

    fn create_symlink(&self, path: &VirtualPath, target: &[u8]) -> std::io::Result<Metadata> {
        let paths = self.entry_paths(path);
        let target = std::str::from_utf8(target)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let created_sidecar = self.prepare_sidecar(path, &paths)?;
        let raw = match self.storage_fs.create_symlink(&paths.content, target) {
            Ok(raw) => raw,
            Err(error) => {
                if created_sidecar {
                    self.rollback_sidecar(&paths);
                }
                return Err(error);
            }
        };
        Ok(raw)
    }

    fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<Vec<u8>> {
        Ok(self
            .storage_fs
            .read_symlink(&self.entry_paths(path).content)?
            .into_bytes())
    }

    fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()> {
        let plan = self.rename_plan(old_path, new_path)?;
        let result = (|| {
            if let Some((path, contents)) = &plan.staged_sidecar {
                self.storage_fs.put(path, contents)?;
            }
            self.storage_fs.rename_multiple(&plan.operations)
        })();
        for path in plan.cleanup_paths {
            let _ = self.storage_fs.remove(&path);
        }
        result
    }

    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        self.storage_fs
            .set_permissions(&self.entry_paths(path).content, permissions)
    }

    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> std::io::Result<()> {
        self.storage_fs
            .set_time(&self.entry_paths(path).content, atime, mtime)
    }

    fn chown(&self, path: &VirtualPath, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
        self.storage_fs
            .chown(&self.entry_paths(path).content, uid, gid)
    }
}
