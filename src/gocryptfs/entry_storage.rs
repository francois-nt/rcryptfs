use crate::core::{
    DirectoryLayout, EntryStorage, EntryStorageBackend, Metadata, NativeFileSystem, OrIoError,
    Permissions, RootDirectoryToken, StorageDirEntry, StorageDirectory, StorageFileSystem,
    Utf8Path, Utf8PathBuf, VirtualPath, VirtualPathBuf, forward_storage_fs_operations,
    temp_file_path,
};
use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::layout::GoCryptFsDirectoryLayout;

const GOCRYPTFS_DIRIV: &str = "gocryptfs.diriv";
const GOCRYPTFS_LONGNAME_PREFIX: &str = "gocryptfs.longname.";
const GOCRYPTFS_LONGNAME_SUFFIX: &str = ".name";
const GOCRYPTFS_MIN_LONG_NAME_MAX: u8 = 62;

/// Configures how long encoded names are represented by GoCryptFS storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoCryptFsEntryStorageOptions {
    /// Maximum encoded name length stored directly in a directory.
    pub long_name_max: u8,
    /// Uses unpadded URL-safe Base64 for long-name hashes.
    pub raw64: bool,
}

impl Default for GoCryptFsEntryStorageOptions {
    fn default() -> Self {
        Self {
            long_name_max: u8::MAX,
            raw64: true,
        }
    }
}

/// Physical paths used to represent one opaque encoded entry.
struct EntryPaths {
    content: VirtualPathBuf,
    sidecar: Option<VirtualPathBuf>,
}

/// Returns whether a raw GoCryptFS entry is internal to the representation.
fn is_direct_internal_entry(name: &str) -> bool {
    name.starts_with("temp.")
        || name == GOCRYPTFS_DIRIV
        || name == "gocryptfs.conf"
        || (name.starts_with(GOCRYPTFS_LONGNAME_PREFIX)
            && name.ends_with(GOCRYPTFS_LONGNAME_SUFFIX))
}

/// Returns whether a raw entry stores content for a shortened name.
fn is_long_name_content(name: &str) -> bool {
    name.starts_with(GOCRYPTFS_LONGNAME_PREFIX) && !name.ends_with(GOCRYPTFS_LONGNAME_SUFFIX)
}

/// GoCryptFS entry representation used by GoCryptFS-compatible layouts.
pub struct GoCryptFsEntryStorage<F: StorageFileSystem> {
    storage_fs: F,
    options: GoCryptFsEntryStorageOptions,
    directory_layout: Arc<dyn DirectoryLayout>,
}

impl<F: StorageFileSystem> GoCryptFsEntryStorage<F> {
    /// Creates a GoCryptFS representation over a raw storage filesystem.
    pub fn new(storage_fs: F) -> Self {
        Self {
            storage_fs,
            options: GoCryptFsEntryStorageOptions::default(),
            directory_layout: Arc::new(GoCryptFsDirectoryLayout),
        }
    }

    /// Creates a GoCryptFS representation with an explicit directory policy.
    pub fn with_directory_layout(
        storage_fs: F,
        directory_layout: Arc<dyn DirectoryLayout>,
    ) -> Self {
        Self {
            storage_fs,
            options: GoCryptFsEntryStorageOptions::default(),
            directory_layout,
        }
    }

    /// Creates a GoCryptFS representation with explicit long-name settings.
    pub fn with_options(
        storage_fs: F,
        options: GoCryptFsEntryStorageOptions,
    ) -> std::io::Result<Self> {
        Self::with_options_and_directory_layout(
            storage_fs,
            options,
            Arc::new(GoCryptFsDirectoryLayout),
        )
    }

    /// Creates a GoCryptFS representation with explicit name and directory policies.
    pub fn with_options_and_directory_layout(
        storage_fs: F,
        options: GoCryptFsEntryStorageOptions,
        directory_layout: Arc<dyn DirectoryLayout>,
    ) -> std::io::Result<Self> {
        if options.long_name_max < GOCRYPTFS_MIN_LONG_NAME_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "GoCryptFS long-name maximum must be at least {GOCRYPTFS_MIN_LONG_NAME_MAX}"
                ),
            ));
        }
        Ok(Self {
            storage_fs,
            options,
            directory_layout,
        })
    }

    /// Initializes the represented root while the raw filesystem is still borrowed.
    pub(super) fn initialize_root_storage(
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

    /// Returns the raw filesystem for representation-level tests.
    #[cfg(test)]
    pub(crate) fn storage_fs(&self) -> &F {
        &self.storage_fs
    }

    /// Hashes an opaque encoded name using the configured GoCryptFS alphabet.
    fn hash_long_name(&self, name: &str) -> String {
        let digest = Sha256::digest(name.as_bytes());
        let hash = if self.options.raw64 {
            URL_SAFE_NO_PAD.encode(digest)
        } else {
            URL_SAFE.encode(digest)
        };
        format!("{GOCRYPTFS_LONGNAME_PREFIX}{hash}")
    }

    /// Maps the final logical encoded component to its physical representation.
    fn entry_paths(&self, path: &VirtualPath) -> EntryPaths {
        let Some(name) = path.file_name() else {
            return EntryPaths {
                content: path.to_owned(),
                sidecar: None,
            };
        };
        if name.len() <= usize::from(self.options.long_name_max) {
            return EntryPaths {
                content: path.to_owned(),
                sidecar: None,
            };
        }

        let stored_name = self.hash_long_name(name);
        let parent = path.parent().unwrap_or_else(VirtualPath::root);
        EntryPaths {
            content: parent.join(&stored_name),
            sidecar: Some(parent.join(format!("{stored_name}{GOCRYPTFS_LONGNAME_SUFFIX}"))),
        }
    }

    /// Returns the sidecar associated with an already-physical content path.
    fn physical_sidecar_path(path: &VirtualPath) -> Option<VirtualPathBuf> {
        let name = path.file_name()?;
        is_long_name_content(name).then(|| {
            path.parent()
                .unwrap_or_else(VirtualPath::root)
                .join(format!("{name}{GOCRYPTFS_LONGNAME_SUFFIX}"))
        })
    }

    /// Creates the sidecar required by a new long-name entry.
    fn create_sidecar(
        &self,
        logical_path: &VirtualPath,
        paths: &EntryPaths,
    ) -> std::io::Result<()> {
        if let Some(sidecar) = &paths.sidecar {
            let name = logical_path.file_name().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing entry name")
            })?;
            self.storage_fs.put_new(sidecar, name.as_bytes())?;
        }
        Ok(())
    }

    /// Prepares a rename destination and reports whether it created a sidecar.
    fn prepare_rename_sidecar(
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
        self.create_sidecar(path, &paths)?;
        let raw = if initial_contents.is_empty() {
            match self.storage_fs.mknode(&paths.content, permissions) {
                Ok(raw) => raw,
                Err(error) => {
                    self.rollback_sidecar(&paths);
                    return Err(error);
                }
            }
        } else {
            if let Err(error) = self.storage_fs.put_new(&paths.content, initial_contents) {
                self.rollback_sidecar(&paths);
                return Err(error);
            }
            let metadata = match permissions {
                Some(permissions) => self.storage_fs.set_permissions(&paths.content, permissions),
                None => self.storage_fs.metadata(&paths.content),
            };
            match metadata {
                Ok(raw) => raw,
                Err(error) => {
                    let _ = self.storage_fs.remove(&paths.content);
                    self.rollback_sidecar(&paths);
                    return Err(error);
                }
            }
        };
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
        if let Err(error) = self.create_sidecar(&entry_path, &paths) {
            let _ = self.storage_fs.remove_dir_all(&temp_path);
            return Err(error);
        }
        if let Err(error) = self.storage_fs.rename(&temp_path, &directory.entry_path) {
            let _ = self.storage_fs.remove_dir_all(&temp_path);
            self.rollback_sidecar(&paths);
            return Err(error);
        }

        let raw = match permissions {
            Some(permissions) => self
                .storage_fs
                .set_permissions(&directory.entry_path, permissions)?,
            None => self.storage_fs.metadata(&directory.entry_path)?,
        };
        Ok(raw)
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
        match Self::physical_sidecar_path(&directory.entry_path) {
            Some(sidecar) => self.storage_fs.remove(&sidecar),
            None => Ok(()),
        }
    }

    fn remove_entry(&self, path: &VirtualPath) -> std::io::Result<()> {
        let paths = self.entry_paths(path);
        self.storage_fs.remove(&paths.content)?;
        match paths.sidecar {
            Some(sidecar) => self.storage_fs.remove(&sidecar),
            None => Ok(()),
        }
    }

    fn create_symlink(&self, path: &VirtualPath, target: &[u8]) -> std::io::Result<Metadata> {
        let paths = self.entry_paths(path);
        let target = std::str::from_utf8(target)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        self.create_sidecar(path, &paths)?;
        let raw = match self.storage_fs.create_symlink(&paths.content, target) {
            Ok(raw) => raw,
            Err(error) => {
                self.rollback_sidecar(&paths);
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
        let old_paths = self.entry_paths(old_path);
        let new_paths = self.entry_paths(new_path);
        let created_sidecar = self.prepare_rename_sidecar(new_path, &new_paths)?;
        if let Err(error) = self
            .storage_fs
            .rename(&old_paths.content, &new_paths.content)
        {
            if created_sidecar {
                self.rollback_sidecar(&new_paths);
            }
            return Err(error);
        }
        if old_paths.sidecar != new_paths.sidecar
            && let Some(sidecar) = old_paths.sidecar
        {
            self.storage_fs.remove(&sidecar)?;
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{DirectoryContentLayout, FileType, NativeFileSystem, Utf8Path};
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

        fn is_detached_directory_contents_path(&self, path: &VirtualPath) -> bool {
            path == VirtualPath::new("detached")
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
            GoCryptFsEntryStorage::with_directory_layout(
                NativeFileSystem::new(root),
                Arc::new(DetachedTestLayout),
            ),
        )
    }

    /// Creates a native storage that shortens names longer than 62 bytes.
    fn short_name_storage() -> (tempfile::TempDir, GoCryptFsEntryStorage<NativeFileSystem>) {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let options = GoCryptFsEntryStorageOptions {
            long_name_max: GOCRYPTFS_MIN_LONG_NAME_MAX,
            raw64: true,
        };
        (
            temp_dir,
            GoCryptFsEntryStorage::with_options_and_directory_layout(
                NativeFileSystem::new(root),
                options,
                Arc::new(DetachedTestLayout),
            )
            .unwrap(),
        )
    }

    #[test]
    fn gocryptfs_storage_materializes_directory_and_native_symlink() {
        let (_temp_dir, storage) = gocryptfs_storage();
        let root = storage.initialize_root_directory().unwrap();
        assert_eq!(root.token, vec![7; 16]);
        let entry_path = VirtualPathBuf::from("docs");
        let token = vec![7; 16];
        let metadata = storage
            .create_directory(entry_path.clone(), token.clone(), None)
            .unwrap();
        assert!(metadata.file_type == FileType::Directory);
        let directory = storage.resolve_directory(&entry_path).unwrap();
        assert_eq!(directory.entry_path, entry_path);
        assert_eq!(directory.contents_path, directory.entry_path);
        assert_eq!(directory.token, token);

        let metadata = storage
            .create_symlink(VirtualPath::new("link"), b"docs")
            .unwrap();
        assert!(metadata.file_type == FileType::SymLink);
        assert_eq!(
            storage.read_symlink(VirtualPath::new("link")).unwrap(),
            b"docs"
        );

        storage
            .storage_fs
            .put(VirtualPath::new("gocryptfs.conf"), b"internal")
            .unwrap();
        let entries = storage
            .read_dir(VirtualPathBuf::default())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 2);

        storage.remove_entry(VirtualPath::new("link")).unwrap();
        assert!(storage.storage_fs.metadata("link".into()).is_err());

        storage
            .storage_fs
            .put(VirtualPath::new("file"), b"contents")
            .unwrap();
        storage.remove_entry(VirtualPath::new("file")).unwrap();
        assert!(storage.storage_fs.metadata("file".into()).is_err());

        storage.remove_directory(&directory).unwrap();
        assert!(storage.storage_fs.metadata(&directory.entry_path).is_err());
    }

    #[test]
    fn long_file_name_uses_content_and_sidecar_entries() {
        let (_temp_dir, storage) = short_name_storage();
        let logical_name = "encoded-name".repeat(8);
        let logical_path = VirtualPath::new(&logical_name);
        let paths = storage.entry_paths(logical_path);
        let expected_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(logical_name.as_bytes()));
        let expected_name = format!("{GOCRYPTFS_LONGNAME_PREFIX}{expected_hash}");
        assert_eq!(paths.content.file_name(), Some(expected_name.as_str()));

        storage
            .create_file(logical_path, b"contents", None)
            .unwrap();

        let mut open_options = crate::core::FileOpenOptions::default();
        open_options.read(true);
        storage.open_file_with(logical_path, open_options).unwrap();
        storage
            .set_permissions(logical_path, 0o600_u16.into())
            .unwrap();
        assert!(storage.storage_fs.exists(&paths.content).unwrap());
        let sidecar = paths.sidecar.unwrap();
        assert_eq!(
            storage.storage_fs.read_all(&sidecar).unwrap(),
            logical_name.as_bytes()
        );
        let entries = storage
            .read_dir(VirtualPathBuf::default())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name, logical_name);
        assert_eq!(entries[0].path, paths.content);

        storage.remove_entry(logical_path).unwrap();
        assert!(!storage.storage_fs.exists(&paths.content).unwrap());
        assert!(!storage.storage_fs.exists(&sidecar).unwrap());
    }

    #[test]
    fn failed_long_file_recreation_preserves_existing_entry() {
        let (_temp_dir, storage) = short_name_storage();
        let logical_name = "encoded-name".repeat(8);
        let logical_path = VirtualPath::new(&logical_name);
        let paths = storage.entry_paths(logical_path);
        storage
            .create_file(logical_path, b"original", None)
            .unwrap();

        assert!(
            storage
                .create_file(logical_path, b"replacement", None)
                .is_err()
        );

        assert_eq!(
            storage.storage_fs.read_all(&paths.content).unwrap(),
            b"original"
        );
        assert_eq!(
            storage
                .storage_fs
                .read_all(&paths.sidecar.unwrap())
                .unwrap(),
            logical_name.as_bytes()
        );
    }

    #[test]
    fn long_directory_name_resolves_to_its_content_entry() {
        let (_temp_dir, storage) = short_name_storage();
        storage.initialize_root_directory().unwrap();
        let logical_name = "encoded-directory".repeat(6);
        let logical_path = VirtualPath::new(&logical_name);
        let paths = storage.entry_paths(logical_path);
        let token = vec![7; 16];

        storage
            .create_directory(logical_path.to_owned(), token.clone(), None)
            .unwrap();
        let directory = storage.resolve_directory(logical_path).unwrap();

        assert_eq!(directory.entry_path, paths.content);
        assert_eq!(directory.contents_path, paths.content);
        assert_eq!(directory.token, token);
        storage.remove_directory(&directory).unwrap();
        assert!(!storage.storage_fs.exists(&paths.content).unwrap());
        assert!(!storage.storage_fs.exists(&paths.sidecar.unwrap()).unwrap());
    }

    #[test]
    fn rename_updates_long_name_sidecars_across_name_lengths() {
        let (_temp_dir, storage) = short_name_storage();
        let short_path = VirtualPath::new("short");
        let first_long_name = "first-long-name".repeat(6);
        let first_long_path = VirtualPath::new(&first_long_name);
        let second_long_name = "second-long-name".repeat(6);
        let second_long_path = VirtualPath::new(&second_long_name);
        let final_path = VirtualPath::new("final");

        storage.create_file(short_path, b"contents", None).unwrap();
        storage.rename(short_path, first_long_path).unwrap();
        let first_paths = storage.entry_paths(first_long_path);
        assert!(storage.storage_fs.exists(&first_paths.content).unwrap());
        assert!(
            storage
                .storage_fs
                .exists(&first_paths.sidecar.unwrap())
                .unwrap()
        );

        storage.rename(first_long_path, second_long_path).unwrap();
        let second_paths = storage.entry_paths(second_long_path);
        assert!(!storage.storage_fs.exists(&first_paths.content).unwrap());
        assert!(storage.storage_fs.exists(&second_paths.content).unwrap());
        assert!(
            !storage
                .storage_fs
                .exists(&storage.entry_paths(first_long_path).sidecar.unwrap())
                .unwrap()
        );

        storage.rename(second_long_path, final_path).unwrap();
        assert!(storage.storage_fs.exists(final_path).unwrap());
        assert!(!storage.storage_fs.exists(&second_paths.content).unwrap());
        assert!(
            !storage
                .storage_fs
                .exists(&second_paths.sidecar.unwrap())
                .unwrap()
        );
    }

    #[test]
    fn long_symlink_name_maps_all_operations_to_content_entry() {
        let (_temp_dir, storage) = short_name_storage();
        let logical_name = "encoded-link".repeat(8);
        let logical_path = VirtualPath::new(&logical_name);
        let paths = storage.entry_paths(logical_path);

        storage.create_symlink(logical_path, b"target").unwrap();

        assert_eq!(storage.read_symlink(logical_path).unwrap(), b"target");
        assert!(storage.metadata(logical_path).unwrap().file_type == FileType::SymLink);
        storage.remove_entry(logical_path).unwrap();
        assert!(!storage.storage_fs.exists(&paths.content).unwrap());
        assert!(!storage.storage_fs.exists(&paths.sidecar.unwrap()).unwrap());
    }

    #[test]
    fn padded_hashes_and_minimum_name_length_are_configurable() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let invalid = GoCryptFsEntryStorageOptions {
            long_name_max: GOCRYPTFS_MIN_LONG_NAME_MAX - 1,
            raw64: true,
        };
        assert!(
            GoCryptFsEntryStorage::with_options(NativeFileSystem::new(root.clone()), invalid)
                .is_err()
        );

        let padded = GoCryptFsEntryStorageOptions {
            long_name_max: GOCRYPTFS_MIN_LONG_NAME_MAX,
            raw64: false,
        };
        let storage =
            GoCryptFsEntryStorage::with_options(NativeFileSystem::new(root), padded).unwrap();
        let logical_name = "long-name".repeat(8);
        let paths = storage.entry_paths(VirtualPath::new(&logical_name));

        assert!(paths.content.file_name().unwrap().ends_with('='));
    }
}
