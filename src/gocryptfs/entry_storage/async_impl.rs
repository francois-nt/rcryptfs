use super::representation::*;
use super::*;

impl<F: AsyncStorageFileSystem> GoCryptFsEntryStorage<F> {
    /// Initializes the represented root while the raw filesystem is still borrowed.
    pub(super) async fn initialize_root_storage_async(
        storage_fs: &F,
        directory_layout: &dyn DirectoryLayout,
    ) -> std::io::Result<StorageDirectory> {
        let token = match directory_layout.root_directory_token() {
            RootDirectoryToken::Persisted => {
                let token = directory_layout.generate_directory_token();
                directory_layout
                    .validate_directory_token(&token, true)
                    .or_invalid()?;
                storage_fs
                    .put_new(&VirtualPath::root().join(GOCRYPTFS_DIRIV), &token)
                    .await?;
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
    async fn prepare_sidecar_async(
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
        match self.storage_fs.put_new(sidecar, name.as_bytes()).await {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.storage_fs.read_all(sidecar).await? == name.as_bytes() {
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
    async fn rollback_sidecar_async(&self, paths: &EntryPaths) {
        if let Some(sidecar) = &paths.sidecar {
            let _ = self.storage_fs.remove(sidecar).await;
        }
    }

    /// Resolves and validates the logical encoded name stored in a sidecar.
    async fn read_long_name_async(
        &self,
        contents_path: &VirtualPath,
        physical_name: &str,
    ) -> std::io::Result<String> {
        let sidecar = contents_path.join(format!("{physical_name}{GOCRYPTFS_LONGNAME_SUFFIX}"));
        let name = String::from_utf8(self.storage_fs.read_all(&sidecar).await?)
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
    async fn directory_token_async(&self, entry_path: &VirtualPath) -> std::io::Result<Vec<u8>> {
        let directory_layout = self.directory_layout.as_ref();
        let token = if entry_path.is_empty() {
            match directory_layout.root_directory_token() {
                RootDirectoryToken::Persisted => {
                    self.storage_fs
                        .read_all(&entry_path.join(GOCRYPTFS_DIRIV))
                        .await?
                }
                RootDirectoryToken::Implicit(token) => token,
            }
        } else {
            self.storage_fs
                .read_all(&entry_path.join(GOCRYPTFS_DIRIV))
                .await?
        };
        directory_layout
            .validate_directory_token(&token, entry_path.is_empty())
            .or_invalid()?;
        Ok(token)
    }

    /// Maps one raw directory batch to represented GoCryptFS entries.
    async fn map_directory_batch_async(
        &self,
        contents_path: &VirtualPath,
        entries: Vec<FsDirEntry>,
    ) -> std::io::Result<Vec<StorageDirEntry>> {
        let mut mapped = Vec::with_capacity(entries.len());
        for entry in entries {
            if is_direct_internal_entry(&entry.file_name) {
                continue;
            }
            let path = contents_path.join(&entry.file_name);
            let file_name = if is_long_name_content(&entry.file_name) {
                self.read_long_name_async(contents_path, &entry.file_name)
                    .await?
            } else {
                entry.file_name
            };
            mapped.push(StorageDirEntry {
                file_name,
                path,
                metadata: entry.metadata,
            });
        }
        Ok(mapped)
    }
}

impl<F: AsyncStorageFileSystem> AsyncEntryStorage for GoCryptFsEntryStorage<F> {
    type OpenHandle = F::OpenHandle;

    fn generate_directory_token(&self) -> Vec<u8> {
        self.directory_layout.generate_directory_token()
    }

    async fn open_file_with(
        &self,
        path: &VirtualPath,
        options: FileOpenOptions,
    ) -> std::io::Result<Self::OpenHandle> {
        self.storage_fs
            .open_file_with(&self.entry_paths(path).content, options)
            .await
    }

    async fn metadata(&self, path: &VirtualPath) -> std::io::Result<Metadata> {
        self.storage_fs
            .metadata(&self.entry_paths(path).content)
            .await
    }

    fn read_dir(
        &self,
        contents_path: VirtualPathBuf,
    ) -> impl Stream<Item = std::io::Result<Vec<StorageDirEntry>>> + Send {
        self.storage_fs
            .read_dir(contents_path.clone())
            .then(move |entries| {
                let contents_path = contents_path.clone();
                async move {
                    self.map_directory_batch_async(&contents_path, entries?)
                        .await
                }
            })
    }

    async fn resolve_directory(
        &self,
        entry_path: &VirtualPath,
    ) -> std::io::Result<StorageDirectory> {
        let entry_path = self.entry_paths(entry_path).content;
        let directory = StorageDirectory {
            contents_path: entry_path.clone(),
            token: self.directory_token_async(&entry_path).await?,
            entry_path,
        };
        Self::validate_directory(&directory)?;
        Ok(directory)
    }

    async fn initialize_root_directory(&self) -> std::io::Result<StorageDirectory> {
        Self::initialize_root_storage_async(&self.storage_fs, self.directory_layout.as_ref()).await
    }

    async fn create_file(
        &self,
        path: &VirtualPath,
        initial_contents: &[u8],
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        let paths = self.entry_paths(path);
        let temp_path = temp_file_path(&format!("file:{}", paths.content), false);
        if self.storage_fs.exists(&temp_path).await? {
            self.storage_fs.remove(&temp_path).await?;
        }

        let raw = if initial_contents.is_empty() {
            self.storage_fs.mknode(&temp_path, permissions).await?
        } else {
            self.storage_fs
                .put_new(&temp_path, initial_contents)
                .await?;
            match permissions {
                Some(permissions) => {
                    self.storage_fs
                        .set_permissions(&temp_path, permissions)
                        .await
                }
                None => self.storage_fs.metadata(&temp_path).await,
            }?
        };

        let created_sidecar = match self.prepare_sidecar_async(path, &paths).await {
            Ok(created) => created,
            Err(error) => {
                let _ = self.storage_fs.remove(&temp_path).await;
                return Err(error);
            }
        };
        if let Err(error) = self
            .storage_fs
            .rename_no_replace(&temp_path, &paths.content)
            .await
        {
            let _ = self.storage_fs.remove(&temp_path).await;
            if created_sidecar {
                self.rollback_sidecar_async(&paths).await;
            }
            return Err(error);
        }
        Ok(raw)
    }

    async fn create_directory(
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
        if self.storage_fs.exists(&temp_path).await? {
            self.storage_fs.remove_dir_all(&temp_path).await?;
        }

        let raw = self.storage_fs.mkdir(&temp_path, permissions).await?;
        if let Err(error) = self
            .storage_fs
            .put(&temp_path.join(GOCRYPTFS_DIRIV), &directory.token)
            .await
        {
            let _ = self.storage_fs.remove_dir_all(&temp_path).await;
            return Err(error);
        }
        let created_sidecar = match self.prepare_sidecar_async(&entry_path, &paths).await {
            Ok(created) => created,
            Err(error) => {
                let _ = self.storage_fs.remove_dir_all(&temp_path).await;
                return Err(error);
            }
        };
        if let Err(error) = self
            .storage_fs
            .rename_no_replace(&temp_path, &directory.entry_path)
            .await
        {
            let _ = self.storage_fs.remove_dir_all(&temp_path).await;
            if created_sidecar {
                self.rollback_sidecar_async(&paths).await;
            }
            return Err(error);
        }
        Ok(raw)
    }

    async fn remove_directory(&self, directory: &StorageDirectory) -> std::io::Result<()> {
        Self::validate_directory(directory)?;
        let mut non_directories = vec![directory.entry_path.join(GOCRYPTFS_DIRIV)];
        if let Some(sidecar) = Self::physical_sidecar_path(&directory.entry_path) {
            non_directories.push(sidecar);
        }
        self.storage_fs
            .remove_multiple(
                std::slice::from_ref(&directory.entry_path),
                &non_directories,
            )
            .await
    }

    async fn remove_entry(&self, path: &VirtualPath) -> std::io::Result<()> {
        let paths = self.entry_paths(path);
        if let Some(sidecar) = paths.sidecar {
            self.storage_fs
                .remove_multiple(&[], &[paths.content, sidecar])
                .await
        } else {
            self.storage_fs.remove(&paths.content).await
        }
    }

    async fn create_symlink(&self, path: &VirtualPath, target: &[u8]) -> std::io::Result<Metadata> {
        let paths = self.entry_paths(path);
        let target = std::str::from_utf8(target)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let created_sidecar = self.prepare_sidecar_async(path, &paths).await?;
        let raw = match self.storage_fs.create_symlink(&paths.content, target).await {
            Ok(raw) => raw,
            Err(error) => {
                if created_sidecar {
                    self.rollback_sidecar_async(&paths).await;
                }
                return Err(error);
            }
        };
        Ok(raw)
    }

    async fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<Vec<u8>> {
        Ok(self
            .storage_fs
            .read_symlink(&self.entry_paths(path).content)
            .await?
            .into_bytes())
    }

    async fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()> {
        let plan = self.rename_plan(old_path, new_path)?;
        let result = if let Some((path, contents)) = &plan.staged_sidecar {
            match self.storage_fs.put(path, contents).await {
                Ok(()) => self.storage_fs.rename_multiple(&plan.operations).await,
                Err(error) => Err(error),
            }
        } else {
            self.storage_fs.rename_multiple(&plan.operations).await
        };
        for path in plan.cleanup_paths {
            let _ = self.storage_fs.remove(&path).await;
        }
        result
    }

    async fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        self.storage_fs
            .set_permissions(&self.entry_paths(path).content, permissions)
            .await
    }

    async fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> std::io::Result<()> {
        self.storage_fs
            .set_time(&self.entry_paths(path).content, atime, mtime)
            .await
    }

    async fn chown(
        &self,
        path: &VirtualPath,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> std::io::Result<()> {
        self.storage_fs
            .chown(&self.entry_paths(path).content, uid, gid)
            .await
    }

    async fn get_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<Vec<u8>> {
        self.storage_fs
            .get_xattr(&self.entry_paths(path).content, name)
            .await
    }

    async fn list_xattr(&self, path: &VirtualPath) -> std::io::Result<Vec<String>> {
        self.storage_fs
            .list_xattr(&self.entry_paths(path).content)
            .await
    }

    async fn remove_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<()> {
        self.storage_fs
            .remove_xattr(&self.entry_paths(path).content, name)
            .await
    }

    async fn set_xattr(&self, path: &VirtualPath, name: &str, value: &[u8]) -> std::io::Result<()> {
        self.storage_fs
            .set_xattr(&self.entry_paths(path).content, name, value)
            .await
    }
}
