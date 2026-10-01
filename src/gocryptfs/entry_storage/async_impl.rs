use super::representation::*;
use super::*;

impl<F: AsyncStorageFileSystem, L: DirectoryLayout> GoCryptFsEntryStorage<F, L> {
    /// Initializes the represented root while the raw filesystem is still borrowed.
    pub(super) async fn initialize_root_storage_async(
        storage_fs: &F,
        directory_layout: &L,
        token: Vec<u8>,
        _directory_id_backup: Option<Vec<u8>>,
    ) -> std::io::Result<StorageDirectory> {
        let persist_token = match directory_layout.root_directory_token() {
            RootDirectoryToken::Persisted => true,
            RootDirectoryToken::Implicit(expected) => {
                if token != expected {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "root directory token does not match the implicit token",
                    ));
                }
                false
            }
        };
        directory_layout
            .validate_directory_token(&token, true)
            .or_invalid()?;
        let root_id = storage_fs.get_root_id().await?;
        let root = ResolvedStoragePathBuf::new(VirtualPathBuf::default(), root_id.clone());
        if persist_token {
            let token_path = VirtualPath::root().join(GOCRYPTFS_DIRIV);
            storage_fs
                .put_new(ResolvedStoragePath::new(&token_path, &root_id), &token)
                .await?;
        }
        Ok(StorageDirectory {
            entry_path: root.clone(),
            contents_path: root,
            contents_id: root_id,
            token,
        })
    }

    /// Prepares a destination and reports whether it created a sidecar.
    async fn prepare_sidecar_async(
        &self,
        logical_path: ResolvedStoragePath<'_>,
        paths: &ResolvedEntryPaths,
    ) -> std::io::Result<bool> {
        let Some(sidecar) = &paths.sidecar else {
            return Ok(false);
        };
        let name = logical_path.path().file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing entry name")
        })?;
        match self
            .storage_fs
            .put_new(sidecar.as_resolved_path(), name.as_bytes())
            .await
        {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.storage_fs.read_all(sidecar.as_resolved_path()).await? == name.as_bytes() {
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
    async fn rollback_sidecar_async(&self, paths: &ResolvedEntryPaths) {
        if let Some(sidecar) = &paths.sidecar {
            let _ = self.storage_fs.remove(sidecar.as_resolved_path()).await;
        }
    }

    /// Resolves and validates the logical encoded name stored in a sidecar.
    async fn read_long_name_async(
        &self,
        contents_path: &VirtualPath,
        contents_id: &StorageDirectoryId,
        physical_name: &str,
    ) -> std::io::Result<String> {
        let sidecar = contents_path.join(format!("{physical_name}{GOCRYPTFS_LONGNAME_SUFFIX}"));
        let name = String::from_utf8(
            self.storage_fs
                .read_all(ResolvedStoragePath::new(&sidecar, contents_id))
                .await?,
        )
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
    async fn directory_token_async(
        &self,
        entry_path: ResolvedStoragePath<'_>,
    ) -> std::io::Result<(Vec<u8>, StorageDirectoryId)> {
        let directory_layout = self.directory_layout.as_ref();
        let directory_id = if entry_path.path().is_empty() {
            self.storage_fs.get_root_id().await?
        } else {
            self.storage_fs.get_folder_id(entry_path).await?
        };
        let token = if entry_path.path().is_empty() {
            match directory_layout.root_directory_token() {
                RootDirectoryToken::Persisted => {
                    let token_path = entry_path.path().join(GOCRYPTFS_DIRIV);
                    self.storage_fs
                        .read_all(ResolvedStoragePath::new(&token_path, &directory_id))
                        .await?
                }
                RootDirectoryToken::Implicit(token) => token,
            }
        } else {
            let token_path = entry_path.path().join(GOCRYPTFS_DIRIV);
            self.storage_fs
                .read_all(ResolvedStoragePath::new(&token_path, &directory_id))
                .await?
        };
        directory_layout
            .validate_directory_token(&token, entry_path.path().is_empty())
            .or_invalid()?;
        Ok((token, directory_id))
    }

    /// Maps one raw directory batch to represented GoCryptFS entries.
    async fn map_directory_batch_async(
        &self,
        contents_path: &VirtualPath,
        contents_id: &StorageDirectoryId,
        entries: Vec<FsDirEntry>,
    ) -> std::io::Result<Vec<StorageDirEntry>> {
        let mut mapped = Vec::with_capacity(entries.len());
        for entry in entries {
            if is_direct_internal_entry(&entry.file_name) {
                continue;
            }
            let path = contents_path.join(&entry.file_name);
            let file_name = if is_long_name_content(&entry.file_name) {
                self.read_long_name_async(contents_path, contents_id, &entry.file_name)
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

impl<F: AsyncStorageFileSystem, L: DirectoryLayout + 'static> AsyncEntryStorage
    for GoCryptFsEntryStorage<F, L>
{
    const REQUIRES_DIRECTORY_ID_BACKUP: bool = false;

    type OpenHandle = F::OpenHandle;

    async fn get_root_id(&self) -> std::io::Result<StorageDirectoryId> {
        self.storage_fs.get_root_id().await
    }

    async fn open_file_with(
        &self,
        path: ResolvedStoragePath<'_>,
        options: FileOpenOptions,
    ) -> std::io::Result<Self::OpenHandle> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs
            .open_file_with(path.as_resolved_path(), options)
            .await
    }

    async fn metadata(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Metadata> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs.metadata(path.as_resolved_path()).await
    }

    fn read_dir(
        &self,
        contents_path: ResolvedStoragePathBuf,
        contents_id: StorageDirectoryId,
    ) -> impl Stream<Item = std::io::Result<Vec<StorageDirEntry>>> + Send {
        self.storage_fs
            .read_dir(contents_path.clone(), contents_id.clone())
            .then(move |entries| {
                let contents_path = contents_path.clone();
                let contents_id = contents_id.clone();
                async move {
                    self.map_directory_batch_async(contents_path.path(), &contents_id, entries?)
                        .await
                }
            })
    }

    async fn resolve_directory(
        &self,
        entry_path: ResolvedStoragePath<'_>,
    ) -> std::io::Result<StorageDirectory> {
        let entry_path = self.resolved_entry_paths(entry_path).content;
        let (token, contents_id) = self
            .directory_token_async(entry_path.as_resolved_path())
            .await?;
        let directory = StorageDirectory {
            contents_path: entry_path.clone(),
            contents_id,
            token,
            entry_path,
        };
        Self::validate_directory(&directory)?;
        Ok(directory)
    }

    async fn initialize_root_directory(
        &self,
        token: Vec<u8>,
        directory_id_backup: Option<Vec<u8>>,
    ) -> std::io::Result<StorageDirectory> {
        Self::initialize_root_storage_async(
            &self.storage_fs,
            self.directory_layout.as_ref(),
            token,
            directory_id_backup,
        )
        .await
    }

    async fn create_file(
        &self,
        path: ResolvedStoragePath<'_>,
        initial_contents: &[u8],
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        let paths = self.resolved_entry_paths(path);
        let root_id = self.storage_fs.get_root_id().await?;
        let temp_path = ResolvedStoragePathBuf::new(
            temp_file_path(&format!("file:{}", paths.content.path()), false),
            root_id,
        );
        if self.storage_fs.exists(temp_path.as_resolved_path()).await? {
            self.storage_fs.remove(temp_path.as_resolved_path()).await?;
        }

        let raw = if initial_contents.is_empty() {
            self.storage_fs
                .mknode(temp_path.as_resolved_path(), permissions)
                .await?
        } else {
            self.storage_fs
                .put_new(temp_path.as_resolved_path(), initial_contents)
                .await?;
            match permissions {
                Some(permissions) => {
                    self.storage_fs
                        .set_permissions(temp_path.as_resolved_path(), permissions)
                        .await
                }
                None => self.storage_fs.metadata(temp_path.as_resolved_path()).await,
            }?
        };

        let created_sidecar = match self.prepare_sidecar_async(path, &paths).await {
            Ok(created) => created,
            Err(error) => {
                let _ = self.storage_fs.remove(temp_path.as_resolved_path()).await;
                return Err(error);
            }
        };
        if let Err(error) = self
            .storage_fs
            .rename_no_replace(
                temp_path.as_resolved_path(),
                paths.content.as_resolved_path(),
            )
            .await
        {
            let _ = self.storage_fs.remove(temp_path.as_resolved_path()).await;
            if created_sidecar {
                self.rollback_sidecar_async(&paths).await;
            }
            return Err(error);
        }
        Ok(raw)
    }

    async fn create_directory(
        &self,
        entry_path: ResolvedStoragePathBuf,
        token: Vec<u8>,
        _directory_id_backup: Option<Vec<u8>>,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        let directory_layout = self.directory_layout.as_ref();
        let paths = self.resolved_entry_paths(entry_path.as_resolved_path());
        directory_layout
            .validate_directory_token(&token, false)
            .or_invalid()?;
        let root_id = self.storage_fs.get_root_id().await?;
        let temp_path = ResolvedStoragePathBuf::new(
            temp_file_path(&format!("directory:{}", paths.content.path()), false),
            root_id,
        );
        if self.storage_fs.exists(temp_path.as_resolved_path()).await? {
            self.storage_fs
                .remove_dir_all(temp_path.as_resolved_path())
                .await?;
        }

        let raw = self
            .storage_fs
            .mkdir(temp_path.as_resolved_path(), permissions)
            .await?;
        let temp_id = self
            .storage_fs
            .get_folder_id(temp_path.as_resolved_path())
            .await?;
        let token_path = temp_path.path().join(GOCRYPTFS_DIRIV);
        if let Err(error) = self
            .storage_fs
            .put(ResolvedStoragePath::new(&token_path, &temp_id), &token)
            .await
        {
            let _ = self
                .storage_fs
                .remove_dir_all(temp_path.as_resolved_path())
                .await;
            return Err(error);
        }
        let created_sidecar = match self
            .prepare_sidecar_async(entry_path.as_resolved_path(), &paths)
            .await
        {
            Ok(created) => created,
            Err(error) => {
                let _ = self
                    .storage_fs
                    .remove_dir_all(temp_path.as_resolved_path())
                    .await;
                return Err(error);
            }
        };
        if let Err(error) = self
            .storage_fs
            .rename_no_replace(
                temp_path.as_resolved_path(),
                paths.content.as_resolved_path(),
            )
            .await
        {
            let _ = self
                .storage_fs
                .remove_dir_all(temp_path.as_resolved_path())
                .await;
            if created_sidecar {
                self.rollback_sidecar_async(&paths).await;
            }
            return Err(error);
        }
        Ok(raw)
    }

    async fn remove_directory(&self, directory: &StorageDirectory) -> std::io::Result<()> {
        Self::validate_directory(directory)?;
        let mut non_directories = vec![ResolvedStoragePathBuf::new(
            directory.contents_path.path().join(GOCRYPTFS_DIRIV),
            directory.contents_id.clone(),
        )];
        if let Some(sidecar) = Self::physical_sidecar_path(directory.entry_path.path()) {
            non_directories.push(ResolvedStoragePathBuf::new(
                sidecar,
                directory.entry_path.expected_parent_id().clone(),
            ));
        }
        self.storage_fs
            .remove_multiple(
                std::slice::from_ref(&directory.entry_path),
                &non_directories,
            )
            .await
    }

    async fn remove_entry(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<()> {
        let paths = self.resolved_entry_paths(path);
        if let Some(sidecar) = paths.sidecar {
            self.storage_fs
                .remove_multiple(&[], &[paths.content, sidecar])
                .await
        } else {
            self.storage_fs
                .remove(paths.content.as_resolved_path())
                .await
        }
    }

    async fn create_symlink(
        &self,
        path: ResolvedStoragePath<'_>,
        target: &[u8],
    ) -> std::io::Result<Metadata> {
        let paths = self.resolved_entry_paths(path);
        let target = std::str::from_utf8(target)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let created_sidecar = self.prepare_sidecar_async(path, &paths).await?;
        let raw = match self
            .storage_fs
            .create_symlink(paths.content.as_resolved_path(), target)
            .await
        {
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

    async fn read_symlink(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Vec<u8>> {
        let path = self.resolved_entry_paths(path).content;
        Ok(self
            .storage_fs
            .read_symlink(path.as_resolved_path())
            .await?
            .into_bytes())
    }

    async fn rename(
        &self,
        old_path: ResolvedStoragePath<'_>,
        new_path: ResolvedStoragePath<'_>,
    ) -> std::io::Result<()> {
        let root_id = self.storage_fs.get_root_id().await?;
        let plan = self.rename_plan(old_path, new_path, &root_id)?;
        let result = if let Some((path, contents)) = &plan.staged_sidecar {
            match self.storage_fs.put(path.as_resolved_path(), contents).await {
                Ok(()) => self.storage_fs.rename_multiple(&plan.operations).await,
                Err(error) => Err(error),
            }
        } else {
            self.storage_fs.rename_multiple(&plan.operations).await
        };
        for path in plan.cleanup_paths {
            let _ = self.storage_fs.remove(path.as_resolved_path()).await;
        }
        result
    }

    async fn set_permissions(
        &self,
        path: ResolvedStoragePath<'_>,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs
            .set_permissions(path.as_resolved_path(), permissions)
            .await
    }

    async fn set_time(
        &self,
        path: ResolvedStoragePath<'_>,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> std::io::Result<()> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs
            .set_time(path.as_resolved_path(), atime, mtime)
            .await
    }

    async fn chown(
        &self,
        path: ResolvedStoragePath<'_>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> std::io::Result<()> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs
            .chown(path.as_resolved_path(), uid, gid)
            .await
    }

    async fn get_xattr(
        &self,
        path: ResolvedStoragePath<'_>,
        name: &str,
    ) -> std::io::Result<Vec<u8>> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs
            .get_xattr(path.as_resolved_path(), name)
            .await
    }

    async fn list_xattr(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Vec<String>> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs.list_xattr(path.as_resolved_path()).await
    }

    async fn remove_xattr(&self, path: ResolvedStoragePath<'_>, name: &str) -> std::io::Result<()> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs
            .remove_xattr(path.as_resolved_path(), name)
            .await
    }

    async fn set_xattr(
        &self,
        path: ResolvedStoragePath<'_>,
        name: &str,
        value: &[u8],
    ) -> std::io::Result<()> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs
            .set_xattr(path.as_resolved_path(), name, value)
            .await
    }
}
