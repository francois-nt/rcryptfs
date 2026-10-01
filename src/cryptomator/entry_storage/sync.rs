use super::*;

/// Lazily maps physical Cryptomator directory entries to represented entries.
pub struct CryptomatorDirEntries<'a, F: StorageFileSystem, L: DirectoryLayout> {
    storage: &'a CryptomatorEntryStorage<F, L>,
    contents_path: VirtualPathBuf,
    contents_id: StorageDirectoryId,
    entries: F::DirEntries,
}

impl<F: StorageFileSystem, L: DirectoryLayout> Iterator for CryptomatorDirEntries<'_, F, L> {
    type Item = std::io::Result<StorageDirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.entries.next()? {
                Ok(entry) if entry.file_name == CRYPTOMATOR_DIR_ID_BACKUP_FILE => continue,
                Ok(entry)
                    if !entry.file_name.ends_with(CRYPTOMATOR_REGULAR_SUFFIX)
                        && !entry.file_name.ends_with(CRYPTOMATOR_SHORT_SUFFIX) =>
                {
                    continue;
                }
                Ok(entry) => {
                    let path = self.contents_path.join(&entry.file_name);
                    let mapped = (|| {
                        let resolved_path = ResolvedStoragePath::new(&path, &self.contents_id);
                        let file_name = self.storage.logical_name(resolved_path)?;
                        let classification = self
                            .storage
                            .classify_physical(resolved_path, entry.metadata.file_type)?;
                        let metadata = match &classification.metadata_path {
                            Some(metadata_path) => self
                                .storage
                                .storage_fs
                                .metadata(metadata_path.as_resolved_path())?,
                            None => entry.metadata,
                        };
                        Ok((
                            file_name,
                            CryptomatorEntryStorage::<F, L>::normalize_metadata(
                                metadata,
                                &classification,
                            ),
                        ))
                    })();
                    return Some(mapped.map(|(file_name, metadata)| StorageDirEntry {
                        file_name,
                        path,
                        metadata,
                    }));
                }
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

impl<F: StorageFileSystem, L: DirectoryLayout + 'static> EntryStorage
    for CryptomatorEntryStorage<F, L>
{
    const REQUIRES_DIRECTORY_ID_BACKUP: bool = true;

    type DirEntries<'a>
        = CryptomatorDirEntries<'a, F, L>
    where
        Self: 'a;
    type OpenHandle = F::OpenHandle;

    fn get_root_id(&self) -> std::io::Result<StorageDirectoryId> {
        self.storage_fs.get_root_id()
    }

    forward_storage_fs_operations!(
        F,
        storage_fs;
        map_path = |this: &Self, path: &VirtualPath| this.entry_paths(path).entry;
        get_xattr,
        list_xattr,
        remove_xattr,
        set_xattr,
    );

    fn open_file_with(
        &self,
        path: ResolvedStoragePath<'_>,
        options: FileOpenOptions,
    ) -> std::io::Result<Self::OpenHandle> {
        let paths = self.resolved_entry_paths(path);
        self.validate_shortened_name(&paths)?;
        let contents_path = paths.contents_path(&self.storage_fs)?;
        self.storage_fs
            .open_file_with(contents_path.as_resolved_path(), options)
    }

    fn metadata(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Metadata> {
        let (outer, _physical_path, classification) = self.classify(path)?;
        let metadata = match &classification.metadata_path {
            Some(metadata_path) => self.storage_fs.metadata(metadata_path.as_resolved_path())?,
            None => outer,
        };
        Ok(Self::normalize_metadata(metadata, &classification))
    }

    fn read_dir<'a>(
        &'a self,
        contents_path: ResolvedStoragePathBuf,
        contents_id: StorageDirectoryId,
    ) -> std::io::Result<Self::DirEntries<'a>> {
        let directory_layout = self.directory_layout.as_ref();
        if !directory_layout.is_detached_directory_contents_path(contents_path.path()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path is not a detached directory contents location",
            ));
        }
        let entries = self
            .storage_fs
            .read_dir(contents_path.as_resolved_path(), &contents_id)?;
        Ok(CryptomatorDirEntries {
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
        let directory_layout = self.directory_layout.as_ref();
        let (physical_entry_path, token) = self.directory_token(entry_path)?;
        let contents_path = directory_layout
            .detached_directory_contents_path(physical_entry_path.path(), &token)
            .or_invalid()?;
        if !directory_layout.is_detached_directory_contents_path(&contents_path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "directory layout returned an invalid detached contents path",
            ));
        }
        let contents_path = resolve_storage_path(&self.storage_fs, &contents_path)?;
        let contents_id = self
            .storage_fs
            .get_folder_id(contents_path.as_resolved_path())?;
        Ok(StorageDirectory {
            entry_path: physical_entry_path,
            contents_path,
            contents_id,
            token,
        })
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
        if paths.is_shortened() {
            self.prepare_container(&paths)?;
        }
        let contents_path = paths.contents_path(&self.storage_fs)?;
        let result = if initial_contents.is_empty() {
            self.storage_fs
                .mknode(contents_path.as_resolved_path(), permissions)
        } else {
            self.storage_fs
                .put_new(contents_path.as_resolved_path(), initial_contents)?;
            match permissions {
                Some(permissions) => self
                    .storage_fs
                    .set_permissions(contents_path.as_resolved_path(), permissions),
                None => self.storage_fs.metadata(contents_path.as_resolved_path()),
            }
        };
        if result.is_err() && paths.is_shortened() {
            self.remove_partial_entry(paths.entry.as_resolved_path());
        }
        result
    }

    fn create_directory(
        &self,
        entry_path: ResolvedStoragePathBuf,
        token: Vec<u8>,
        directory_id_backup: Option<Vec<u8>>,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        let directory_id_backup = Self::require_directory_id_backup(directory_id_backup)?;
        let directory_layout = self.directory_layout.as_ref();
        directory_layout
            .validate_directory_token(&token, false)
            .or_invalid()?;
        let paths = self.resolved_entry_paths(entry_path.as_resolved_path());
        let contents_path = directory_layout
            .detached_directory_contents_path(paths.entry.path(), &token)
            .or_invalid()?;
        if !directory_layout.is_detached_directory_contents_path(&contents_path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "directory layout returned an invalid detached contents path",
            ));
        }
        self.prepare_container(&paths)?;
        let container_id = self
            .storage_fs
            .get_folder_id(paths.entry.as_resolved_path())?;
        let token_path = paths.entry.path().join(CRYPTOMATOR_DIR_FILE);
        if let Err(error) = self
            .storage_fs
            .put_new(ResolvedStoragePath::new(&token_path, &container_id), &token)
        {
            self.remove_partial_entry(paths.entry.as_resolved_path());
            return Err(error);
        }

        let contents_parent = contents_path.parent().unwrap_or_else(VirtualPath::root);
        if let Err(error) = self.storage_fs.mkdir_all(contents_parent) {
            self.remove_partial_entry(paths.entry.as_resolved_path());
            return Err(error);
        }
        let contents_path = resolve_storage_path(&self.storage_fs, &contents_path)?;
        if let Err(error) = self
            .storage_fs
            .mkdir(contents_path.as_resolved_path(), None)
        {
            self.remove_partial_entry(paths.entry.as_resolved_path());
            return Err(error);
        }
        let contents_id = self
            .storage_fs
            .get_folder_id(contents_path.as_resolved_path())?;
        let backup_path = contents_path.path().join(CRYPTOMATOR_DIR_ID_BACKUP_FILE);
        if let Err(error) = self.storage_fs.put_new(
            ResolvedStoragePath::new(&backup_path, &contents_id),
            &directory_id_backup,
        ) {
            let _ = self
                .storage_fs
                .remove_dir_all(contents_path.as_resolved_path());
            self.remove_partial_entry(paths.entry.as_resolved_path());
            return Err(error);
        }
        let mut metadata = match permissions {
            Some(permissions) => self
                .storage_fs
                .set_permissions(contents_path.as_resolved_path(), permissions)?,
            None => self.storage_fs.metadata(contents_path.as_resolved_path())?,
        };
        metadata.file_type = FileType::Directory;
        Ok(metadata)
    }

    fn remove_directory(&self, directory: &StorageDirectory) -> std::io::Result<()> {
        let entry_id = self
            .storage_fs
            .get_folder_id(directory.entry_path.as_resolved_path())?;
        let mut non_directories = vec![ResolvedStoragePathBuf::new(
            directory.entry_path.path().join(CRYPTOMATOR_DIR_FILE),
            entry_id.clone(),
        )];
        if directory
            .entry_path
            .path()
            .file_name()
            .is_some_and(|name| name.ends_with(CRYPTOMATOR_SHORT_SUFFIX))
        {
            non_directories.push(ResolvedStoragePathBuf::new(
                directory.entry_path.path().join(CRYPTOMATOR_NAME_FILE),
                entry_id,
            ));
        }
        let token_backup = ResolvedStoragePathBuf::new(
            directory
                .contents_path
                .path()
                .join(CRYPTOMATOR_DIR_ID_BACKUP_FILE),
            directory.contents_id.clone(),
        );
        if self.storage_fs.exists(token_backup.as_resolved_path())? {
            non_directories.push(token_backup);
        }
        self.storage_fs.remove_multiple(
            &[
                directory.contents_path.clone(),
                directory.entry_path.clone(),
            ],
            &non_directories,
        )
    }

    fn remove_entry(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<()> {
        let (_, physical_path, classification) = self.classify(path)?;
        let is_shortened = physical_path
            .path()
            .file_name()
            .is_some_and(|name| name.ends_with(CRYPTOMATOR_SHORT_SUFFIX));
        let contents_file = match classification.file_type {
            FileType::File if is_shortened => Some(CRYPTOMATOR_CONTENTS_FILE),
            FileType::SymLink => Some(CRYPTOMATOR_SYMLINK_FILE),
            _ => None,
        };
        let Some(contents_file) = contents_file else {
            return self.storage_fs.remove(physical_path.as_resolved_path());
        };

        let container_id = self
            .storage_fs
            .get_folder_id(physical_path.as_resolved_path())?;
        let mut non_directories = vec![ResolvedStoragePathBuf::new(
            physical_path.path().join(contents_file),
            container_id.clone(),
        )];
        if is_shortened {
            non_directories.push(ResolvedStoragePathBuf::new(
                physical_path.path().join(CRYPTOMATOR_NAME_FILE),
                container_id,
            ));
        }
        self.storage_fs
            .remove_multiple(std::slice::from_ref(&physical_path), &non_directories)
    }

    fn create_symlink(
        &self,
        path: ResolvedStoragePath<'_>,
        target: &[u8],
    ) -> std::io::Result<Metadata> {
        let paths = self.resolved_entry_paths(path);
        self.prepare_container(&paths)?;
        let container_id = self
            .storage_fs
            .get_folder_id(paths.entry.as_resolved_path())?;
        let symlink_path = ResolvedStoragePathBuf::new(
            paths.entry.path().join(CRYPTOMATOR_SYMLINK_FILE),
            container_id,
        );
        if let Err(error) = self
            .storage_fs
            .put_new(symlink_path.as_resolved_path(), target)
        {
            self.remove_partial_entry(paths.entry.as_resolved_path());
            return Err(error);
        }
        let mut metadata = self.storage_fs.metadata(symlink_path.as_resolved_path())?;
        metadata.file_type = FileType::SymLink;
        Ok(metadata)
    }

    fn read_symlink(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Vec<u8>> {
        let paths = self.resolved_entry_paths(path);
        self.validate_shortened_name(&paths)?;
        let container_id = self
            .storage_fs
            .get_folder_id(paths.entry.as_resolved_path())?;
        let symlink_path = paths.entry.path().join(CRYPTOMATOR_SYMLINK_FILE);
        self.storage_fs
            .read_all(ResolvedStoragePath::new(&symlink_path, &container_id))
    }

    fn rename(
        &self,
        old_path: ResolvedStoragePath<'_>,
        new_path: ResolvedStoragePath<'_>,
    ) -> std::io::Result<()> {
        let old = self.resolved_entry_paths(old_path);
        let new = self.resolved_entry_paths(new_path);
        self.validate_shortened_name(&old)?;
        if old.entry == new.entry {
            return Ok(());
        }

        let root_id = self.storage_fs.get_root_id()?;
        let mut cleanup_files = Vec::new();
        let mut cleanup_directories = Vec::new();
        let result = (|| match (old.is_shortened(), new.is_shortened()) {
            (false, false) => self.storage_fs.rename_multiple(&[RenameOperation::replace(
                old.entry.clone(),
                new.entry.clone(),
            )]),
            (false, true)
                if self
                    .storage_fs
                    .metadata(old.entry.as_resolved_path())?
                    .file_type
                    == FileType::File =>
            {
                let staged_container = self.stage_container(&new, &root_id)?;
                let staged_id = self
                    .storage_fs
                    .get_folder_id(staged_container.as_resolved_path())?;
                cleanup_directories.push(staged_container.clone());
                self.storage_fs.rename_multiple(&[
                    RenameOperation::replace(staged_container, new.entry.clone()),
                    RenameOperation::replace(
                        old.entry.clone(),
                        ResolvedStoragePathBuf::new(
                            new.entry.path().join(CRYPTOMATOR_CONTENTS_FILE),
                            staged_id,
                        ),
                    ),
                ])
            }
            (_, true) => {
                let staged_name = self.stage_name_file(&new, &root_id)?;
                let old_id = self
                    .storage_fs
                    .get_folder_id(old.entry.as_resolved_path())?;
                cleanup_files.push(staged_name.clone());
                self.storage_fs.rename_multiple(&[
                    RenameOperation::replace(old.entry.clone(), new.entry.clone()),
                    RenameOperation::replace(
                        staged_name,
                        ResolvedStoragePathBuf::new(
                            new.entry.path().join(CRYPTOMATOR_NAME_FILE),
                            old_id,
                        ),
                    ),
                ])
            }
            (true, false) => {
                if self.container_is_file(old.entry.as_resolved_path())? {
                    let retired = ResolvedStoragePathBuf::new(
                        temp_file_path(&format!("retired-container:{}", old.entry.path()), false),
                        root_id.clone(),
                    );
                    cleanup_directories.push(retired.clone());
                    self.storage_fs.rename_multiple(&[
                        RenameOperation::replace(
                            old.contents_path(&self.storage_fs)?,
                            new.entry.clone(),
                        ),
                        RenameOperation::replace(old.entry.clone(), retired),
                    ])
                } else {
                    let old_id = self
                        .storage_fs
                        .get_folder_id(old.entry.as_resolved_path())?;
                    let old_name_path = ResolvedStoragePathBuf::new(
                        old.entry.path().join(CRYPTOMATOR_NAME_FILE),
                        old_id,
                    );
                    let retired = ResolvedStoragePathBuf::new(
                        temp_file_path(&format!("retired-name:{}", old_name_path.path()), false),
                        root_id.clone(),
                    );
                    cleanup_files.push(retired.clone());
                    self.storage_fs.rename_multiple(&[
                        RenameOperation::replace(old.entry.clone(), new.entry.clone()),
                        RenameOperation::replace(old_name_path, retired),
                    ])
                }
            }
        })();
        for path in cleanup_files {
            let _ = self.storage_fs.remove(path.as_resolved_path());
        }
        for path in cleanup_directories {
            let _ = self.storage_fs.remove_dir_all(path.as_resolved_path());
        }
        result
    }

    fn set_permissions(
        &self,
        path: ResolvedStoragePath<'_>,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        let (outer, physical_path, classification) = self.classify(path)?;
        let metadata = if classification.file_type == FileType::SymLink {
            match &classification.metadata_path {
                Some(metadata_path) => {
                    self.storage_fs.metadata(metadata_path.as_resolved_path())?
                }
                None => outer,
            }
        } else {
            self.storage_fs.set_permissions(
                classification.metadata_path_or(physical_path.as_resolved_path()),
                permissions,
            )?
        };
        Ok(Self::normalize_metadata(metadata, &classification))
    }

    fn set_time(
        &self,
        path: ResolvedStoragePath<'_>,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> std::io::Result<()> {
        let (_, physical_path, classification) = self.classify(path)?;
        self.storage_fs.set_time(
            classification.metadata_path_or(physical_path.as_resolved_path()),
            atime,
            mtime,
        )
    }

    fn chown(
        &self,
        path: ResolvedStoragePath<'_>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> std::io::Result<()> {
        let (_, physical_path, classification) = self.classify(path)?;
        self.storage_fs.chown(
            classification.metadata_path_or(physical_path.as_resolved_path()),
            uid,
            gid,
        )
    }
}
