use crate::core::{
    DirectoryLayout, EntryStorage, FileOpenOptions, FileType, Metadata, OrIoError, Permissions,
    RootDirectoryToken, StorageDirEntry, StorageDirectory, StorageFileSystem, VirtualPath,
    VirtualPathBuf, forward_storage_fs_operations,
};
use base64::{Engine, engine::general_purpose::URL_SAFE};
use sha1::{Digest, Sha1};
use std::sync::Arc;

const CRYPTOMATOR_CONTENTS_FILE: &str = "contents.c9r";
const CRYPTOMATOR_DIR_ID_BACKUP_FILE: &str = "dirid.c9r";
const CRYPTOMATOR_DIR_FILE: &str = "dir.c9r";
const CRYPTOMATOR_NAME_FILE: &str = "name.c9s";
const CRYPTOMATOR_REGULAR_SUFFIX: &str = ".c9r";
const CRYPTOMATOR_SHORT_SUFFIX: &str = ".c9s";
const CRYPTOMATOR_SYMLINK_FILE: &str = "symlink.c9r";
const CRYPTOMATOR_NAME_MAX: usize = 220;

/// Physical paths and reverse mapping for one opaque encoded entry name.
struct EntryPaths {
    entry: VirtualPathBuf,
    inflated_name: Option<String>,
}

impl EntryPaths {
    /// Returns whether this entry uses a shortened container.
    fn is_shortened(&self) -> bool {
        self.inflated_name.is_some()
    }

    /// Returns the physical file carrying regular-file contents.
    fn contents_path(&self) -> VirtualPathBuf {
        if self.is_shortened() {
            self.entry.join(CRYPTOMATOR_CONTENTS_FILE)
        } else {
            self.entry.clone()
        }
    }
}

/// Logical type and alternate metadata location of a represented entry.
struct ClassifiedEntry {
    file_type: FileType,
    metadata_path: Option<VirtualPathBuf>,
}

impl ClassifiedEntry {
    /// Returns the physical path carrying the represented metadata.
    fn metadata_path_or<'a>(&'a self, entry_path: &'a VirtualPath) -> &'a VirtualPath {
        self.metadata_path.as_deref().unwrap_or(entry_path)
    }
}

/// Returns an InvalidData error for a malformed Cryptomator representation.
fn invalid_representation(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

/// Cryptomator entry representation used by Cryptomator-compatible layouts.
pub struct CryptomatorEntryStorage<F: StorageFileSystem> {
    storage_fs: F,
    directory_layout: Arc<dyn DirectoryLayout>,
}

impl<F: StorageFileSystem> CryptomatorEntryStorage<F> {
    /// Creates a Cryptomator container representation with its directory policy.
    pub fn new(storage_fs: F, directory_layout: Arc<dyn DirectoryLayout>) -> Self {
        Self {
            storage_fs,
            directory_layout,
        }
    }

    /// Initializes the represented root while the raw filesystem is still borrowed.
    pub(super) fn initialize_root_storage(
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

    /// Returns the raw filesystem for representation-level tests.
    #[cfg(test)]
    pub(crate) fn storage_fs(&self) -> &F {
        &self.storage_fs
    }

    /// Maps an opaque encoded final component to its Cryptomator representation.
    fn entry_paths(&self, path: &VirtualPath) -> EntryPaths {
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
        if inflated_name.len() <= CRYPTOMATOR_NAME_MAX {
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
    fn prepare_container(&self, paths: &EntryPaths) -> std::io::Result<()> {
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
        if inflated.len() <= CRYPTOMATOR_NAME_MAX
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
    fn validate_shortened_name(&self, paths: &EntryPaths) -> std::io::Result<()> {
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
    fn logical_name(&self, entry_path: &VirtualPath) -> std::io::Result<String> {
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
    fn directory_token(
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
    fn classify_physical(
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
    fn classify(
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

    /// Replaces the physical type with the represented logical type.
    fn normalize_metadata(mut metadata: Metadata, classification: &ClassifiedEntry) -> Metadata {
        metadata.file_type = classification.file_type;
        metadata
    }

    /// Removes a partially-created visible container without masking its error.
    fn remove_partial_entry(&self, path: &VirtualPath) {
        let _ = self.storage_fs.remove_dir_all(path);
    }

    /// Returns whether a physical container represents a regular file.
    fn container_is_file(&self, path: &VirtualPath) -> std::io::Result<bool> {
        self.storage_fs
            .exists(&path.join(CRYPTOMATOR_CONTENTS_FILE))
    }
}

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
        self.storage_fs.remove_dir(&directory.contents_path)?;
        self.storage_fs.remove_dir_all(&directory.entry_path)
    }

    fn remove_entry(&self, path: &VirtualPath) -> std::io::Result<()> {
        let (_, physical_path, classification) = self.classify(path)?;
        if classification.file_type == FileType::SymLink
            || (classification.file_type == FileType::File
                && physical_path
                    .file_name()
                    .is_some_and(|name| name.ends_with(CRYPTOMATOR_SHORT_SUFFIX)))
        {
            self.storage_fs.remove_dir_all(&physical_path)
        } else {
            self.storage_fs.remove(&physical_path)
        }
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
        match (old.is_shortened(), new.is_shortened()) {
            (false, false) => self.storage_fs.rename(&old.entry, &new.entry),
            (true, true) => {
                self.storage_fs.rename(&old.entry, &new.entry)?;
                if let Err(error) = self.write_name_file(&new, false) {
                    let _ = self.storage_fs.rename(&new.entry, &old.entry);
                    return Err(error);
                }
                Ok(())
            }
            (false, true) => {
                let old_metadata = self.storage_fs.metadata(&old.entry)?;
                if old_metadata.file_type == FileType::File {
                    self.prepare_container(&new)?;
                    if let Err(error) = self.storage_fs.rename(&old.entry, &new.contents_path()) {
                        self.remove_partial_entry(&new.entry);
                        return Err(error);
                    }
                    Ok(())
                } else {
                    self.storage_fs.rename(&old.entry, &new.entry)?;
                    if let Err(error) = self.write_name_file(&new, true) {
                        let _ = self.storage_fs.rename(&new.entry, &old.entry);
                        return Err(error);
                    }
                    Ok(())
                }
            }
            (true, false) => {
                if self.container_is_file(&old.entry)? {
                    self.storage_fs.rename(&old.contents_path(), &new.entry)?;
                    self.storage_fs.remove_dir_all(&old.entry)
                } else {
                    let old_name_path = old.entry.join(CRYPTOMATOR_NAME_FILE);
                    self.storage_fs.remove(&old_name_path)?;
                    if let Err(error) = self.storage_fs.rename(&old.entry, &new.entry) {
                        let _ = self.write_name_file(&old, true);
                        return Err(error);
                    }
                    Ok(())
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{DirectoryContentLayout, NativeFileSystem, ReadAt, Utf8Path};
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

        fn is_detached_directory_contents_path(&self, path: &VirtualPath) -> bool {
            let mut components = path.components();
            matches!(components.next(), Some("d"))
                && components.next().is_some_and(|part| part.len() == 2)
                && components.next().is_some_and(|part| part.len() == 30)
                && components.next().is_none()
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
            CryptomatorEntryStorage::new(
                NativeFileSystem::new(root),
                Arc::new(FixedDirectoryContentLayout {
                    contents_path: child_contents_path(),
                }),
            ),
        )
    }

    /// Returns a canonical-looking detached contents path for storage tests.
    fn contents_path() -> VirtualPathBuf {
        "d/AB/ABCDEFGHIJKLMNOPQRSTUVWXYZ2345".into()
    }

    /// Returns a distinct contents location for a represented child directory.
    fn child_contents_path() -> VirtualPathBuf {
        "d/CD/2345ABCDEFGHIJKLMNOPQRSTUVWXYZ".into()
    }

    #[test]
    fn short_entries_are_classified_from_their_physical_representation() {
        let (_temp_dir, storage) = cryptomator_storage();
        let parent_contents = contents_path();
        storage.storage_fs.mkdir_all(&parent_contents).unwrap();
        let directory_path = parent_contents.join("encoded-directory");
        let symlink_path = parent_contents.join("encoded-link");

        let directory = storage
            .create_directory(
                directory_path.clone(),
                storage.generate_directory_token(),
                None,
            )
            .unwrap();
        assert!(directory.file_type == FileType::Directory);
        let symlink = storage.create_symlink(&symlink_path, b"target").unwrap();
        assert!(symlink.file_type == FileType::SymLink);

        let entries = storage
            .read_dir(parent_contents)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert!(entries.iter().any(|entry| {
            entry.file_name == "encoded-directory"
                && entry.metadata.file_type == FileType::Directory
        }));
        assert!(entries.iter().any(|entry| {
            entry.file_name == "encoded-link" && entry.metadata.file_type == FileType::SymLink
        }));
    }

    #[test]
    fn long_file_uses_and_validates_name_c9s() {
        let (_temp_dir, storage) = cryptomator_storage();
        let parent_contents = contents_path();
        storage.storage_fs.mkdir_all(&parent_contents).unwrap();
        let long_name = "a".repeat(CRYPTOMATOR_NAME_MAX);
        let logical_path = parent_contents.join(&long_name);
        storage
            .create_file(&logical_path, b"ciphertext", None)
            .unwrap();

        let paths = storage.entry_paths(&logical_path);
        assert!(paths.is_shortened());
        assert!(storage.storage_fs.exists(&paths.entry).unwrap());
        assert_eq!(
            storage
                .storage_fs
                .read_all(&paths.entry.join(CRYPTOMATOR_NAME_FILE))
                .unwrap(),
            format!("{long_name}{CRYPTOMATOR_REGULAR_SUFFIX}").as_bytes()
        );

        let entries = storage
            .read_dir(parent_contents)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name, long_name);
        assert!(entries[0].metadata.file_type == FileType::File);

        let mut options = FileOpenOptions::default();
        options.read(true);
        let handle = storage.open_file_with(&logical_path, options).unwrap();
        let mut data = [0; 10];
        assert_eq!(handle.read_all_at(0, &mut data).unwrap(), data.len());
        assert_eq!(&data, b"ciphertext");

        storage
            .storage_fs
            .put(&paths.entry.join(CRYPTOMATOR_NAME_FILE), b"wrong.c9r")
            .unwrap();
        assert!(matches!(
            storage.metadata(&logical_path),
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn read_dir_ignores_foreign_names_but_reports_malformed_entries() {
        let (_temp_dir, storage) = cryptomator_storage();
        let parent_contents = contents_path();
        storage.storage_fs.mkdir_all(&parent_contents).unwrap();
        storage
            .storage_fs
            .put(&parent_contents.join("sync-conflict"), b"foreign")
            .unwrap();

        let entries = storage
            .read_dir(parent_contents.clone())
            .unwrap()
            .collect::<Vec<_>>();
        assert!(entries.is_empty());

        storage
            .storage_fs
            .mkdir(&parent_contents.join("broken.c9s"), None)
            .unwrap();
        let entries = storage
            .read_dir(parent_contents)
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_err());
    }

    #[test]
    fn long_directory_and_symlink_use_name_c9s() {
        let (_temp_dir, storage) = cryptomator_storage();
        let parent_contents = contents_path();
        storage.storage_fs.mkdir_all(&parent_contents).unwrap();
        let directory_path = parent_contents.join("d".repeat(CRYPTOMATOR_NAME_MAX));
        let symlink_path = parent_contents.join("s".repeat(CRYPTOMATOR_NAME_MAX));

        storage
            .create_directory(
                directory_path.clone(),
                storage.generate_directory_token(),
                None,
            )
            .unwrap();
        storage.create_symlink(&symlink_path, b"target").unwrap();

        for logical_path in [&directory_path, &symlink_path] {
            let paths = storage.entry_paths(logical_path);
            assert!(paths.is_shortened());
            assert!(
                storage
                    .storage_fs
                    .exists(&paths.entry.join(CRYPTOMATOR_NAME_FILE))
                    .unwrap()
            );
        }
        assert!(storage.metadata(&directory_path).unwrap().file_type == FileType::Directory);
        assert!(storage.metadata(&symlink_path).unwrap().file_type == FileType::SymLink);
    }

    #[test]
    fn metadata_rejects_conflicting_container_markers() {
        let (_temp_dir, storage) = cryptomator_storage();
        let parent_contents = contents_path();
        storage.storage_fs.mkdir_all(&parent_contents).unwrap();
        let logical_path = parent_contents.join("encoded");
        storage.create_symlink(&logical_path, b"target").unwrap();
        let physical = storage.entry_paths(&logical_path).entry;
        storage
            .storage_fs
            .put(
                &physical.join(CRYPTOMATOR_DIR_FILE),
                b"12345678-1234-1234-1234-123456789abc",
            )
            .unwrap();

        assert!(matches!(
            storage.metadata(&logical_path),
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn metadata_does_not_accept_entries_outside_a_contents_directory() {
        let (_temp_dir, storage) = cryptomator_storage();
        storage
            .storage_fs
            .mkdir(VirtualPath::new("outside"), None)
            .unwrap();
        storage
            .storage_fs
            .put(VirtualPath::new("outside/encoded.c9r"), b"ciphertext")
            .unwrap();

        assert!(
            storage
                .metadata(VirtualPath::new("outside/encoded"))
                .unwrap()
                .file_type
                == FileType::Other
        );
    }

    #[test]
    fn rename_moves_files_across_the_shortening_boundary() {
        let (_temp_dir, storage) = cryptomator_storage();
        let parent_contents = contents_path();
        storage.storage_fs.mkdir_all(&parent_contents).unwrap();
        let short_path = parent_contents.join("short");
        let first_long_path = parent_contents.join("a".repeat(CRYPTOMATOR_NAME_MAX));
        let second_long_path = parent_contents.join("b".repeat(CRYPTOMATOR_NAME_MAX));

        storage
            .create_file(&short_path, b"ciphertext", None)
            .unwrap();
        storage.rename(&short_path, &first_long_path).unwrap();
        assert_eq!(
            storage
                .storage_fs
                .read_all(&storage.entry_paths(&first_long_path).contents_path())
                .unwrap(),
            b"ciphertext"
        );
        storage.rename(&first_long_path, &second_long_path).unwrap();
        storage.rename(&second_long_path, &short_path).unwrap();
        assert_eq!(
            storage
                .storage_fs
                .read_all(&storage.entry_paths(&short_path).contents_path())
                .unwrap(),
            b"ciphertext"
        );
        assert!(storage.metadata(&short_path).is_ok());
    }
}
