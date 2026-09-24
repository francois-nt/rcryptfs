use super::*;

/// Lazily maps physical Cryptomator directory entries to represented entries.
pub struct CryptomatorDirEntries<'a, F: StorageFileSystem> {
    storage: &'a CryptomatorEntryStorage<F>,
    contents_path: VirtualPathBuf,
    entries: F::DirEntries,
}

impl<F: StorageFileSystem> Iterator for CryptomatorDirEntries<'_, F> {
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
                    return Some((|| {
                        let file_name = self.storage.logical_name(&path)?;
                        let classification = self
                            .storage
                            .classify_physical(&path, entry.metadata.file_type)?;
                        let metadata = match &classification.metadata_path {
                            Some(metadata_path) => {
                                self.storage.storage_fs.metadata(metadata_path)?
                            }
                            None => entry.metadata,
                        };
                        Ok(StorageDirEntry {
                            file_name,
                            path,
                            metadata: CryptomatorEntryStorage::<F>::normalize_metadata(
                                metadata,
                                &classification,
                            ),
                        })
                    })());
                }
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

impl<F: StorageFileSystem> EntryStorage for CryptomatorEntryStorage<F> {
    type DirEntries<'a>
        = CryptomatorDirEntries<'a, F>
    where
        Self: 'a;
    type OpenHandle = F::OpenHandle;

    fn generate_directory_token(&self) -> Vec<u8> {
        self.directory_layout.generate_directory_token()
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
        path: &VirtualPath,
        options: FileOpenOptions,
    ) -> std::io::Result<Self::OpenHandle> {
        let paths = self.entry_paths(path);
        self.validate_shortened_name(&paths)?;
        self.storage_fs
            .open_file_with(&paths.contents_path(), options)
    }

    fn metadata(&self, path: &VirtualPath) -> std::io::Result<Metadata> {
        let (outer, _physical_path, classification) = self.classify(path)?;
        let metadata = match &classification.metadata_path {
            Some(metadata_path) => self.storage_fs.metadata(metadata_path)?,
            None => outer,
        };
        Ok(Self::normalize_metadata(metadata, &classification))
    }

    fn read_dir<'a>(
        &'a self,
        contents_path: VirtualPathBuf,
    ) -> std::io::Result<Self::DirEntries<'a>> {
        let directory_layout = self.directory_layout.as_ref();
        if !directory_layout.is_detached_directory_contents_path(&contents_path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path is not a detached directory contents location",
            ));
        }
        let entries = self.storage_fs.read_dir(&contents_path)?;
        Ok(CryptomatorDirEntries {
            storage: self,
            contents_path,
            entries,
        })
    }

    fn resolve_directory(&self, entry_path: &VirtualPath) -> std::io::Result<StorageDirectory> {
        let directory_layout = self.directory_layout.as_ref();
        let (physical_entry_path, token) = self.directory_token(entry_path)?;
        let contents_path = directory_layout
            .detached_directory_contents_path(&physical_entry_path, &token)
            .or_invalid()?;
        if !directory_layout.is_detached_directory_contents_path(&contents_path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "directory layout returned an invalid detached contents path",
            ));
        }
        Ok(StorageDirectory {
            entry_path: physical_entry_path,
            contents_path,
            token,
        })
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
        if paths.is_shortened() {
            self.prepare_container(&paths)?;
        }
        let contents_path = paths.contents_path();
        let result = if initial_contents.is_empty() {
            self.storage_fs.mknode(&contents_path, permissions)
        } else {
            self.storage_fs.put_new(&contents_path, initial_contents)?;
            match permissions {
                Some(permissions) => self.storage_fs.set_permissions(&contents_path, permissions),
                None => self.storage_fs.metadata(&contents_path),
            }
        };
        if result.is_err() && paths.is_shortened() {
            self.remove_partial_entry(&paths.entry);
        }
        result
    }

    fn create_directory(
        &self,
        entry_path: VirtualPathBuf,
        token: Vec<u8>,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        let directory_layout = self.directory_layout.as_ref();
        directory_layout
            .validate_directory_token(&token, false)
            .or_invalid()?;
        let paths = self.entry_paths(&entry_path);
        let contents_path = directory_layout
            .detached_directory_contents_path(&paths.entry, &token)
            .or_invalid()?;
        if !directory_layout.is_detached_directory_contents_path(&contents_path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "directory layout returned an invalid detached contents path",
            ));
        }
        self.prepare_container(&paths)?;
        if let Err(error) = self
            .storage_fs
            .put_new(&paths.entry.join(CRYPTOMATOR_DIR_FILE), &token)
        {
            self.remove_partial_entry(&paths.entry);
            return Err(error);
        }

        let contents_parent = contents_path.parent().unwrap_or_else(VirtualPath::root);
        if let Err(error) = self.storage_fs.mkdir_all(contents_parent) {
            self.remove_partial_entry(&paths.entry);
            return Err(error);
        }
        if let Err(error) = self.storage_fs.mkdir(&contents_path, None) {
            self.remove_partial_entry(&paths.entry);
            return Err(error);
        }
        let mut metadata = match permissions {
            Some(permissions) => self
                .storage_fs
                .set_permissions(&contents_path, permissions)?,
            None => self.storage_fs.metadata(&contents_path)?,
        };
        metadata.file_type = FileType::Directory;
        Ok(metadata)
    }

    fn remove_directory(&self, directory: &StorageDirectory) -> std::io::Result<()> {
        let mut non_directories = vec![directory.entry_path.join(CRYPTOMATOR_DIR_FILE)];
        if directory
            .entry_path
            .file_name()
            .is_some_and(|name| name.ends_with(CRYPTOMATOR_SHORT_SUFFIX))
        {
            non_directories.push(directory.entry_path.join(CRYPTOMATOR_NAME_FILE));
        }
        let token_backup = directory.contents_path.join(CRYPTOMATOR_DIR_ID_BACKUP_FILE);
        if self.storage_fs.exists(&token_backup)? {
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

    fn remove_entry(&self, path: &VirtualPath) -> std::io::Result<()> {
        let (_, physical_path, classification) = self.classify(path)?;
        let is_shortened = physical_path
            .file_name()
            .is_some_and(|name| name.ends_with(CRYPTOMATOR_SHORT_SUFFIX));
        let contents_file = match classification.file_type {
            FileType::File if is_shortened => Some(CRYPTOMATOR_CONTENTS_FILE),
            FileType::SymLink => Some(CRYPTOMATOR_SYMLINK_FILE),
            _ => None,
        };
        let Some(contents_file) = contents_file else {
            return self.storage_fs.remove(&physical_path);
        };

        let mut non_directories = vec![physical_path.join(contents_file)];
        if is_shortened {
            non_directories.push(physical_path.join(CRYPTOMATOR_NAME_FILE));
        }
        self.storage_fs
            .remove_multiple(std::slice::from_ref(&physical_path), &non_directories)
    }

    fn create_symlink(&self, path: &VirtualPath, target: &[u8]) -> std::io::Result<Metadata> {
        let paths = self.entry_paths(path);
        self.prepare_container(&paths)?;
        let symlink_path = paths.entry.join(CRYPTOMATOR_SYMLINK_FILE);
        if let Err(error) = self.storage_fs.put_new(&symlink_path, target) {
            self.remove_partial_entry(&paths.entry);
            return Err(error);
        }
        let mut metadata = self.storage_fs.metadata(&symlink_path)?;
        metadata.file_type = FileType::SymLink;
        Ok(metadata)
    }

    fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<Vec<u8>> {
        let paths = self.entry_paths(path);
        self.validate_shortened_name(&paths)?;
        self.storage_fs
            .read_all(&paths.entry.join(CRYPTOMATOR_SYMLINK_FILE))
    }

    fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()> {
        let old = self.entry_paths(old_path);
        let new = self.entry_paths(new_path);
        self.validate_shortened_name(&old)?;
        if old.entry == new.entry {
            return Ok(());
        }

        let mut cleanup_files = Vec::new();
        let mut cleanup_directories = Vec::new();
        let result = (|| match (old.is_shortened(), new.is_shortened()) {
            (false, false) => self
                .storage_fs
                .rename_multiple(&[RenameOperation::replace(old.entry, new.entry)]),
            (false, true) if self.storage_fs.metadata(&old.entry)?.file_type == FileType::File => {
                let staged_container = self.stage_container(&new)?;
                cleanup_directories.push(staged_container.clone());
                self.storage_fs.rename_multiple(&[
                    RenameOperation::replace(staged_container, new.entry.clone()),
                    RenameOperation::replace(old.entry, new.contents_path()),
                ])
            }
            (_, true) => {
                let staged_name = self.stage_name_file(&new)?;
                cleanup_files.push(staged_name.clone());
                self.storage_fs.rename_multiple(&[
                    RenameOperation::replace(old.entry, new.entry.clone()),
                    RenameOperation::replace(staged_name, new.entry.join(CRYPTOMATOR_NAME_FILE)),
                ])
            }
            (true, false) => {
                if self.container_is_file(&old.entry)? {
                    let retired =
                        temp_file_path(&format!("retired-container:{}", old.entry), false);
                    cleanup_directories.push(retired.clone());
                    self.storage_fs.rename_multiple(&[
                        RenameOperation::replace(old.contents_path(), new.entry),
                        RenameOperation::replace(old.entry, retired),
                    ])
                } else {
                    let old_name_path = old.entry.join(CRYPTOMATOR_NAME_FILE);
                    let retired = temp_file_path(&format!("retired-name:{old_name_path}"), false);
                    cleanup_files.push(retired.clone());
                    self.storage_fs.rename_multiple(&[
                        RenameOperation::replace(old.entry, new.entry),
                        RenameOperation::replace(old_name_path, retired),
                    ])
                }
            }
        })();
        for path in cleanup_files {
            let _ = self.storage_fs.remove(&path);
        }
        for path in cleanup_directories {
            let _ = self.storage_fs.remove_dir_all(&path);
        }
        result
    }

    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        let (outer, physical_path, classification) = self.classify(path)?;
        let metadata = if classification.file_type == FileType::SymLink {
            match &classification.metadata_path {
                Some(metadata_path) => self.storage_fs.metadata(metadata_path)?,
                None => outer,
            }
        } else {
            self.storage_fs
                .set_permissions(classification.metadata_path_or(&physical_path), permissions)?
        };
        Ok(Self::normalize_metadata(metadata, &classification))
    }

    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> std::io::Result<()> {
        let (_, physical_path, classification) = self.classify(path)?;
        self.storage_fs.set_time(
            classification.metadata_path_or(&physical_path),
            atime,
            mtime,
        )
    }

    fn chown(&self, path: &VirtualPath, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
        let (_, physical_path, classification) = self.classify(path)?;
        self.storage_fs
            .chown(classification.metadata_path_or(&physical_path), uid, gid)
    }
}
