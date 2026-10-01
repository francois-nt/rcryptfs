use super::representation::*;
use super::*;

impl<F: StorageFileSystem, L: DirectoryLayout> GoCryptFsEntryStorage<F, L> {
    /// Initializes the represented root while the raw filesystem is still borrowed.
    pub(in crate::gocryptfs) fn initialize_root_storage(
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
        let root_id = storage_fs.get_root_id()?;
        let root = ResolvedStoragePathBuf::new(VirtualPathBuf::default(), root_id.clone());
        if persist_token {
            let token_path = VirtualPath::root().join(GOCRYPTFS_DIRIV);
            storage_fs.put_new(ResolvedStoragePath::new(&token_path, &root_id), &token)?;
        }
        Ok(StorageDirectory {
            entry_path: root.clone(),
            contents_path: root,
            contents_id: root_id,
            token,
        })
    }

    /// Prepares a destination and reports whether it created a sidecar.
    fn prepare_sidecar(
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
        {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.storage_fs.read_all(sidecar.as_resolved_path())? == name.as_bytes() {
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
    fn rollback_sidecar(&self, paths: &ResolvedEntryPaths) {
        if let Some(sidecar) = &paths.sidecar {
            let _ = self.storage_fs.remove(sidecar.as_resolved_path());
        }
    }

    /// Resolves and validates the logical encoded name stored in a sidecar.
    fn read_long_name(
        &self,
        contents_path: &VirtualPath,
        contents_id: &StorageDirectoryId,
        physical_name: &str,
    ) -> std::io::Result<String> {
        let sidecar = contents_path.join(format!("{physical_name}{GOCRYPTFS_LONGNAME_SUFFIX}"));
        let name = String::from_utf8(
            self.storage_fs
                .read_all(ResolvedStoragePath::new(&sidecar, contents_id))?,
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
    fn directory_token(
        &self,
        entry_path: ResolvedStoragePath<'_>,
    ) -> std::io::Result<(Vec<u8>, StorageDirectoryId)> {
        let directory_layout = self.directory_layout.as_ref();
        let directory_id = if entry_path.path().is_empty() {
            self.storage_fs.get_root_id()?
        } else {
            self.storage_fs.get_folder_id(entry_path)?
        };
        let token = if entry_path.path().is_empty() {
            match directory_layout.root_directory_token() {
                RootDirectoryToken::Persisted => {
                    let token_path = entry_path.path().join(GOCRYPTFS_DIRIV);
                    self.storage_fs
                        .read_all(ResolvedStoragePath::new(&token_path, &directory_id))?
                }
                RootDirectoryToken::Implicit(token) => token,
            }
        } else {
            let token_path = entry_path.path().join(GOCRYPTFS_DIRIV);
            self.storage_fs
                .read_all(ResolvedStoragePath::new(&token_path, &directory_id))?
        };
        directory_layout
            .validate_directory_token(&token, entry_path.path().is_empty())
            .or_invalid()?;
        Ok((token, directory_id))
    }
}

impl From<Utf8PathBuf>
    for EntryStorageBackend<
        GoCryptFsEntryStorage<NativeFileSystem, GoCryptFsDirectoryLayout>,
        GoCryptFsDirectoryLayout,
    >
{
    fn from(root: Utf8PathBuf) -> Self {
        let directory_layout = Arc::new(GoCryptFsDirectoryLayout);
        Self::new(
            GoCryptFsEntryStorage::with_directory_layout(
                NativeFileSystem::new(root),
                directory_layout.clone(),
            ),
            directory_layout,
        )
    }
}

impl From<&Utf8Path>
    for EntryStorageBackend<
        GoCryptFsEntryStorage<NativeFileSystem, GoCryptFsDirectoryLayout>,
        GoCryptFsDirectoryLayout,
    >
{
    fn from(root: &Utf8Path) -> Self {
        root.to_owned().into()
    }
}

/// Lazily maps physical GoCryptFS directory entries to represented entries.
pub struct GoCryptFsDirEntries<'a, F: StorageFileSystem, L: DirectoryLayout> {
    storage: &'a GoCryptFsEntryStorage<F, L>,
    contents_path: VirtualPathBuf,
    contents_id: StorageDirectoryId,
    entries: F::DirEntries,
}

impl<F: StorageFileSystem, L: DirectoryLayout> Iterator for GoCryptFsDirEntries<'_, F, L> {
    type Item = std::io::Result<StorageDirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.entries.next()? {
                Ok(entry) if is_direct_internal_entry(&entry.file_name) => continue,
                Ok(entry) => {
                    let path = self.contents_path.join(&entry.file_name);
                    let file_name = if is_long_name_content(&entry.file_name) {
                        self.storage.read_long_name(
                            &self.contents_path,
                            &self.contents_id,
                            &entry.file_name,
                        )
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

impl<F: StorageFileSystem, L: DirectoryLayout + 'static> EntryStorage
    for GoCryptFsEntryStorage<F, L>
{
    const REQUIRES_DIRECTORY_ID_BACKUP: bool = false;

    type DirEntries<'a>
        = GoCryptFsDirEntries<'a, F, L>
    where
        Self: 'a;

    fn get_root_id(&self) -> std::io::Result<StorageDirectoryId> {
        self.storage_fs.get_root_id()
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

    fn metadata(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Metadata> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs.metadata(path.as_resolved_path())
    }

    fn read_dir<'a>(
        &'a self,
        contents_path: ResolvedStoragePathBuf,
        contents_id: StorageDirectoryId,
    ) -> std::io::Result<Self::DirEntries<'a>> {
        let entries = self
            .storage_fs
            .read_dir(contents_path.as_resolved_path(), &contents_id)?;
        Ok(GoCryptFsDirEntries {
            storage: self,
            contents_path: contents_path.path().to_owned(),
            contents_id,
            entries,
        })
    }

    fn resolve_directory(
        &self,
        entry_path: ResolvedStoragePath<'_>,
    ) -> std::io::Result<StorageDirectory> {
        let entry_path = self.resolved_entry_paths(entry_path).content;
        let (token, contents_id) = self.directory_token(entry_path.as_resolved_path())?;
        let directory = StorageDirectory {
            contents_path: entry_path.clone(),
            contents_id,
            token,
            entry_path,
        };
        Self::validate_directory(&directory)?;
        Ok(directory)
    }

    fn initialize_root_directory(
        &self,
        token: Vec<u8>,
        directory_id_backup: Option<Vec<u8>>,
    ) -> std::io::Result<StorageDirectory> {
        Self::initialize_root_storage(
            &self.storage_fs,
            self.directory_layout.as_ref(),
            token,
            directory_id_backup,
        )
    }

    fn create_file(
        &self,
        path: ResolvedStoragePath<'_>,
        initial_contents: &[u8],
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        let paths = self.resolved_entry_paths(path);
        let root_id = self.storage_fs.get_root_id()?;
        let temp_path = ResolvedStoragePathBuf::new(
            temp_file_path(&format!("file:{}", paths.content.path()), false),
            root_id,
        );
        if self.storage_fs.exists(temp_path.as_resolved_path())? {
            self.storage_fs.remove(temp_path.as_resolved_path())?;
        }

        let raw = if initial_contents.is_empty() {
            self.storage_fs
                .mknode(temp_path.as_resolved_path(), permissions)?
        } else {
            self.storage_fs
                .put_new(temp_path.as_resolved_path(), initial_contents)?;
            match permissions {
                Some(permissions) => self
                    .storage_fs
                    .set_permissions(temp_path.as_resolved_path(), permissions)?,
                None => self.storage_fs.metadata(temp_path.as_resolved_path())?,
            }
        };

        let created_sidecar = match self.prepare_sidecar(path, &paths) {
            Ok(created) => created,
            Err(error) => {
                let _ = self.storage_fs.remove(temp_path.as_resolved_path());
                return Err(error);
            }
        };
        if let Err(error) = self.storage_fs.rename_no_replace(
            temp_path.as_resolved_path(),
            paths.content.as_resolved_path(),
        ) {
            let _ = self.storage_fs.remove(temp_path.as_resolved_path());
            if created_sidecar {
                self.rollback_sidecar(&paths);
            }
            return Err(error);
        }
        Ok(raw)
    }

    fn create_directory(
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
        let root_id = self.storage_fs.get_root_id()?;
        let temp_path = ResolvedStoragePathBuf::new(
            temp_file_path(&format!("directory:{}", paths.content.path()), false),
            root_id,
        );
        if self.storage_fs.exists(temp_path.as_resolved_path())? {
            self.storage_fs
                .remove_dir_all(temp_path.as_resolved_path())?;
        }

        let raw = self
            .storage_fs
            .mkdir(temp_path.as_resolved_path(), permissions)?;
        let temp_id = self
            .storage_fs
            .get_folder_id(temp_path.as_resolved_path())?;
        let token_path = temp_path.path().join(GOCRYPTFS_DIRIV);
        if let Err(error) = self
            .storage_fs
            .put(ResolvedStoragePath::new(&token_path, &temp_id), &token)
        {
            let _ = self.storage_fs.remove_dir_all(temp_path.as_resolved_path());
            return Err(error);
        }
        let created_sidecar = match self.prepare_sidecar(entry_path.as_resolved_path(), &paths) {
            Ok(created) => created,
            Err(error) => {
                let _ = self.storage_fs.remove_dir_all(temp_path.as_resolved_path());
                return Err(error);
            }
        };
        if let Err(error) = self.storage_fs.rename_no_replace(
            temp_path.as_resolved_path(),
            paths.content.as_resolved_path(),
        ) {
            let _ = self.storage_fs.remove_dir_all(temp_path.as_resolved_path());
            if created_sidecar {
                self.rollback_sidecar(&paths);
            }
            return Err(error);
        }
        Ok(raw)
    }

    fn remove_directory(&self, directory: &StorageDirectory) -> std::io::Result<()> {
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
        self.storage_fs.remove_multiple(
            std::slice::from_ref(&directory.entry_path),
            &non_directories,
        )
    }

    fn remove_entry(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<()> {
        let paths = self.resolved_entry_paths(path);
        if let Some(sidecar) = paths.sidecar {
            self.storage_fs
                .remove_multiple(&[], &[paths.content, sidecar])
        } else {
            self.storage_fs.remove(paths.content.as_resolved_path())
        }
    }

    fn create_symlink(
        &self,
        path: ResolvedStoragePath<'_>,
        target: &[u8],
    ) -> std::io::Result<Metadata> {
        let paths = self.resolved_entry_paths(path);
        let target = std::str::from_utf8(target)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let created_sidecar = self.prepare_sidecar(path, &paths)?;
        let raw = match self
            .storage_fs
            .create_symlink(paths.content.as_resolved_path(), target)
        {
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

    fn read_symlink(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Vec<u8>> {
        let path = self.resolved_entry_paths(path).content;
        Ok(self
            .storage_fs
            .read_symlink(path.as_resolved_path())?
            .into_bytes())
    }

    fn rename(
        &self,
        old_path: ResolvedStoragePath<'_>,
        new_path: ResolvedStoragePath<'_>,
    ) -> std::io::Result<()> {
        let root_id = self.storage_fs.get_root_id()?;
        let plan = self.rename_plan(old_path, new_path, &root_id)?;
        let result = (|| {
            if let Some((path, contents)) = &plan.staged_sidecar {
                self.storage_fs.put(path.as_resolved_path(), contents)?;
            }
            self.storage_fs.rename_multiple(&plan.operations)
        })();
        for path in plan.cleanup_paths {
            let _ = self.storage_fs.remove(path.as_resolved_path());
        }
        result
    }

    fn set_permissions(
        &self,
        path: ResolvedStoragePath<'_>,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs
            .set_permissions(path.as_resolved_path(), permissions)
    }

    fn set_time(
        &self,
        path: ResolvedStoragePath<'_>,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> std::io::Result<()> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs
            .set_time(path.as_resolved_path(), atime, mtime)
    }

    fn chown(
        &self,
        path: ResolvedStoragePath<'_>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> std::io::Result<()> {
        let path = self.resolved_entry_paths(path).content;
        self.storage_fs.chown(path.as_resolved_path(), uid, gid)
    }
}
