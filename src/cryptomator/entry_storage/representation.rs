use super::*;

/// Physical paths and reverse mapping for one opaque encoded entry name.
pub(super) struct EntryPaths {
    pub(super) entry: VirtualPathBuf,
    pub(super) inflated_name: Option<String>,
}

impl EntryPaths {
    /// Returns whether this entry uses a shortened container.
    pub(super) fn is_shortened(&self) -> bool {
        self.inflated_name.is_some()
    }

    /// Returns the physical file carrying regular-file contents.
    pub(super) fn contents_path(&self) -> VirtualPathBuf {
        if self.is_shortened() {
            self.entry.join(CRYPTOMATOR_CONTENTS_FILE)
        } else {
            self.entry.clone()
        }
    }
}

/// Logical type and alternate metadata location of a represented entry.
pub(super) struct ClassifiedEntry {
    pub(super) file_type: FileType,
    pub(super) metadata_path: Option<VirtualPathBuf>,
}

impl ClassifiedEntry {
    /// Returns the physical path carrying the represented metadata.
    pub(super) fn metadata_path_or<'a>(&'a self, entry_path: &'a VirtualPath) -> &'a VirtualPath {
        self.metadata_path.as_deref().unwrap_or(entry_path)
    }
}

/// Returns an InvalidData error for a malformed Cryptomator representation.
fn invalid_representation(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

impl<F> CryptomatorEntryStorage<F> {
    /// Maps an opaque encoded final component to its Cryptomator representation.
    pub(super) fn entry_paths(&self, path: &VirtualPath) -> EntryPaths {
        let Some(logical_name) = path.file_name() else {
            return EntryPaths {
                entry: path.to_owned(),
                inflated_name: None,
            };
        };
        let inflated_name = if logical_name.ends_with(CRYPTOMATOR_REGULAR_SUFFIX) {
            logical_name.to_owned()
        } else {
            format!("{logical_name}{CRYPTOMATOR_REGULAR_SUFFIX}")
        };
        let parent = path.parent().unwrap_or_else(VirtualPath::root);
        if inflated_name.len() <= self.options.shortening_threshold {
            return EntryPaths {
                entry: parent.join(inflated_name),
                inflated_name: None,
            };
        }

        let hash = URL_SAFE.encode(Sha1::digest(inflated_name.as_bytes()));
        EntryPaths {
            entry: parent.join(format!("{hash}{CRYPTOMATOR_SHORT_SUFFIX}")),
            inflated_name: Some(inflated_name),
        }
    }

    /// Replaces the physical type with the represented logical type.
    pub(super) fn normalize_metadata(
        mut metadata: Metadata,
        classification: &ClassifiedEntry,
    ) -> Metadata {
        metadata.file_type = classification.file_type;
        metadata
    }
}
impl<F: StorageFileSystem> CryptomatorEntryStorage<F> {
    /// Initializes the represented root while the raw filesystem is still borrowed.
    pub(in crate::cryptomator) fn initialize_root_storage(
        storage_fs: &F,
        directory_layout: &dyn DirectoryLayout,
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
        if !directory_layout.is_detached_directory_contents_path(&contents_path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "directory layout returned an invalid detached contents path",
            ));
        }
        let token_path = VirtualPath::root().join(CRYPTOMATOR_DIR_FILE);
        if persist_token {
            storage_fs.put_new(&token_path, &token)?;
        }
        if let Err(error) = storage_fs.mkdir_all(&contents_path) {
            if persist_token {
                let _ = storage_fs.remove(&token_path);
            }
            return Err(error);
        }
        Ok(StorageDirectory {
            entry_path: VirtualPathBuf::default(),
            contents_path,
            token,
        })
    }

    /// Writes the reverse mapping required by a shortened entry.
    fn write_name_file(&self, paths: &EntryPaths, create_new: bool) -> std::io::Result<()> {
        let Some(inflated_name) = &paths.inflated_name else {
            return Ok(());
        };
        let name_path = paths.entry.join(CRYPTOMATOR_NAME_FILE);
        if create_new {
            self.storage_fs
                .put_new(&name_path, inflated_name.as_bytes())
        } else {
            self.storage_fs.put(&name_path, inflated_name.as_bytes())
        }
    }

    /// Creates a represented directory and its optional reverse mapping.
    pub(super) fn prepare_container(&self, paths: &EntryPaths) -> std::io::Result<()> {
        self.storage_fs.mkdir(&paths.entry, None)?;
        if let Err(error) = self.write_name_file(paths, true) {
            self.remove_partial_entry(&paths.entry);
            return Err(error);
        }
        Ok(())
    }

    /// Reads and validates the reverse mapping of a physical shortened entry.
    fn read_shortened_name(&self, entry_path: &VirtualPath) -> std::io::Result<String> {
        let physical_name = entry_path
            .file_name()
            .ok_or_else(|| invalid_representation("shortened entry has no file name"))?;
        let inflated = self
            .storage_fs
            .read_all(&entry_path.join(CRYPTOMATOR_NAME_FILE))?;
        let inflated = String::from_utf8(inflated)
            .map_err(|error| invalid_representation(format!("invalid name.c9s: {error}")))?;
        if inflated.len() <= self.options.shortening_threshold
            || !inflated.ends_with(CRYPTOMATOR_REGULAR_SUFFIX)
            || inflated.contains('/')
        {
            return Err(invalid_representation("invalid inflated name in name.c9s"));
        }
        let expected = format!(
            "{}{CRYPTOMATOR_SHORT_SUFFIX}",
            URL_SAFE.encode(Sha1::digest(inflated.as_bytes()))
        );
        if physical_name != expected {
            return Err(invalid_representation(
                "name.c9s does not match its shortened entry name",
            ));
        }
        Ok(inflated)
    }

    /// Validates that a logical long name resolves to the stored reverse mapping.
    pub(super) fn validate_shortened_name(&self, paths: &EntryPaths) -> std::io::Result<()> {
        let Some(expected) = &paths.inflated_name else {
            return Ok(());
        };
        if self.read_shortened_name(&paths.entry)? != *expected {
            return Err(invalid_representation(
                "name.c9s contains a different encrypted name",
            ));
        }
        Ok(())
    }

    /// Restores the opaque encoded name represented by a physical entry.
    pub(super) fn logical_name(&self, entry_path: &VirtualPath) -> std::io::Result<String> {
        let physical_name = entry_path
            .file_name()
            .ok_or_else(|| invalid_representation("entry has no file name"))?;
        let inflated = if physical_name.ends_with(CRYPTOMATOR_SHORT_SUFFIX) {
            self.read_shortened_name(entry_path)?
        } else if physical_name.ends_with(CRYPTOMATOR_REGULAR_SUFFIX) {
            physical_name.to_owned()
        } else {
            return Err(invalid_representation(
                "Cryptomator entry must end with .c9r or .c9s",
            ));
        };
        inflated
            .strip_suffix(CRYPTOMATOR_REGULAR_SUFFIX)
            .map(str::to_owned)
            .ok_or_else(|| invalid_representation("inflated name has no .c9r suffix"))
    }

    /// Reads and validates the token stored by one physical directory entry.
    fn read_directory_token(&self, physical_entry_path: &VirtualPath) -> std::io::Result<Vec<u8>> {
        let token = self
            .storage_fs
            .read_all(&physical_entry_path.join(CRYPTOMATOR_DIR_FILE))?;
        self.directory_layout
            .validate_directory_token(&token, false)
            .or_invalid()?;
        Ok(token)
    }

    /// Resolves and validates the configured token for one logical directory.
    pub(super) fn directory_token(
        &self,
        entry_path: &VirtualPath,
    ) -> std::io::Result<(VirtualPathBuf, Vec<u8>)> {
        let directory_layout = self.directory_layout.as_ref();
        if entry_path.is_empty() {
            let token = match directory_layout.root_directory_token() {
                RootDirectoryToken::Persisted => self
                    .storage_fs
                    .read_all(&entry_path.join(CRYPTOMATOR_DIR_FILE))?,
                RootDirectoryToken::Implicit(token) => token,
            };
            directory_layout
                .validate_directory_token(&token, true)
                .or_invalid()?;
            return Ok((entry_path.to_owned(), token));
        }

        let paths = self.entry_paths(entry_path);
        self.validate_shortened_name(&paths)?;
        let token = self.read_directory_token(&paths.entry)?;
        Ok((paths.entry, token))
    }

    /// Classifies a physical entry and locates the metadata it represents.
    pub(super) fn classify_physical(
        &self,
        path: &VirtualPath,
        file_type: FileType,
    ) -> std::io::Result<ClassifiedEntry> {
        let directory_layout = self.directory_layout.as_ref();
        if directory_layout.is_detached_directory_contents_path(path) {
            return Ok(ClassifiedEntry {
                file_type: if file_type == FileType::Directory {
                    FileType::Directory
                } else {
                    FileType::Other
                },
                metadata_path: None,
            });
        }

        if !path
            .parent()
            .is_some_and(|parent| directory_layout.is_detached_directory_contents_path(parent))
        {
            return Ok(ClassifiedEntry {
                file_type: FileType::Other,
                metadata_path: None,
            });
        }

        let name = path.file_name().unwrap_or_default();
        let is_regular_name = name.ends_with(CRYPTOMATOR_REGULAR_SUFFIX);
        let is_shortened_name = name.ends_with(CRYPTOMATOR_SHORT_SUFFIX);
        if !is_regular_name && !is_shortened_name {
            return Ok(ClassifiedEntry {
                file_type: FileType::Other,
                metadata_path: None,
            });
        }
        if file_type == FileType::File {
            return Ok(ClassifiedEntry {
                file_type: if is_regular_name {
                    FileType::File
                } else {
                    FileType::Other
                },
                metadata_path: None,
            });
        }
        if file_type != FileType::Directory {
            return Ok(ClassifiedEntry {
                file_type: FileType::Other,
                metadata_path: None,
            });
        }

        let contents_path = path.join(CRYPTOMATOR_CONTENTS_FILE);
        let directory_marker = path.join(CRYPTOMATOR_DIR_FILE);
        let symlink_path = path.join(CRYPTOMATOR_SYMLINK_FILE);
        let has_contents = is_shortened_name && self.storage_fs.exists(&contents_path)?;
        let has_directory = self.storage_fs.exists(&directory_marker)?;
        let has_symlink = self.storage_fs.exists(&symlink_path)?;
        if usize::from(has_contents) + usize::from(has_directory) + usize::from(has_symlink) != 1 {
            return Err(invalid_representation(
                "Cryptomator container must contain exactly one type marker",
            ));
        }

        if has_contents {
            return Ok(ClassifiedEntry {
                file_type: FileType::File,
                metadata_path: Some(contents_path),
            });
        }
        if has_symlink {
            return Ok(ClassifiedEntry {
                file_type: FileType::SymLink,
                metadata_path: Some(symlink_path),
            });
        }

        let token = self.read_directory_token(path)?;
        let metadata_path = directory_layout
            .detached_directory_contents_path(path, &token)
            .or_invalid()?;
        Ok(ClassifiedEntry {
            file_type: FileType::Directory,
            metadata_path: (metadata_path.as_path() != path).then_some(metadata_path),
        })
    }

    /// Resolves a logical entry before classifying its physical representation.
    pub(super) fn classify(
        &self,
        path: &VirtualPath,
    ) -> std::io::Result<(Metadata, VirtualPathBuf, ClassifiedEntry)> {
        if self
            .directory_layout
            .is_detached_directory_contents_path(path)
        {
            let outer = self.storage_fs.metadata(path)?;
            let classification = self.classify_physical(path, outer.file_type)?;
            return Ok((outer, path.to_owned(), classification));
        }

        let paths = self.entry_paths(path);
        self.validate_shortened_name(&paths)?;
        let outer = self.storage_fs.metadata(&paths.entry)?;
        let classification = self.classify_physical(&paths.entry, outer.file_type)?;
        Ok((outer, paths.entry, classification))
    }

    /// Removes a partially-created visible container without masking its error.
    pub(super) fn remove_partial_entry(&self, path: &VirtualPath) {
        let _ = self.storage_fs.remove_dir_all(path);
    }

    /// Returns whether a physical container represents a regular file.
    pub(super) fn container_is_file(&self, path: &VirtualPath) -> std::io::Result<bool> {
        self.storage_fs
            .exists(&path.join(CRYPTOMATOR_CONTENTS_FILE))
    }

    /// Stages the reverse mapping used by a renamed shortened entry.
    pub(super) fn stage_name_file(&self, paths: &EntryPaths) -> std::io::Result<VirtualPathBuf> {
        let inflated_name = paths
            .inflated_name
            .as_ref()
            .ok_or_else(|| invalid_representation("shortened entry has no inflated name"))?;
        let staging = temp_file_path(&format!("rename-name:{}", paths.entry), false);
        self.storage_fs.put(&staging, inflated_name.as_bytes())?;
        Ok(staging)
    }

    /// Stages an empty shortened container carrying its reverse mapping.
    pub(super) fn stage_container(&self, paths: &EntryPaths) -> std::io::Result<VirtualPathBuf> {
        let staging = temp_file_path(&format!("rename-container:{}", paths.entry), false);
        if self.storage_fs.exists(&staging)? {
            self.storage_fs.remove_dir_all(&staging)?;
        }
        let staged_paths = EntryPaths {
            entry: staging.clone(),
            inflated_name: paths.inflated_name.clone(),
        };
        self.prepare_container(&staged_paths)?;
        Ok(staging)
    }
}
