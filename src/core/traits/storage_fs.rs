use super::{
    AsyncFileHandle, AsyncReadAt, AsyncSetLen, AsyncSize, AsyncWriteAt, FileHandle,
    FileOpenOptions, FileType, FsDirEntry, Metadata, Permissions, ReadAt, SetLen, Size,
    VirtualPath, VirtualPathBuf, WriteAt,
};
use futures_core::Stream;
use std::{future::Future, ops::Deref, time::SystemTime};

/// Opaque identifier assigned by a storage backend to one directory.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StorageDirectoryId(Vec<u8>);

impl StorageDirectoryId {
    /// Creates an identifier from its backend-specific representation.
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    /// Returns the backend-specific representation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the identifier and returns its representation.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Borrowed storage path carrying the expected identity of its parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedStoragePath<'a> {
    path: &'a VirtualPath,
    expected_parent_id: &'a StorageDirectoryId,
}

impl<'a> ResolvedStoragePath<'a> {
    /// Creates a resolved path from its physical path and expected parent.
    pub fn new(path: &'a VirtualPath, expected_parent_id: &'a StorageDirectoryId) -> Self {
        Self {
            path,
            expected_parent_id,
        }
    }

    /// Returns the physical storage path.
    pub fn path(self) -> &'a VirtualPath {
        self.path
    }

    /// Returns the expected identity of the physical parent directory.
    pub fn expected_parent_id(self) -> &'a StorageDirectoryId {
        self.expected_parent_id
    }

    /// Copies this resolved path into owned storage.
    pub fn to_owned(self) -> ResolvedStoragePathBuf {
        ResolvedStoragePathBuf::new(self.path.to_owned(), self.expected_parent_id.clone())
    }
}

/// Owned storage path carrying the expected identity of its parent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedStoragePathBuf {
    path: VirtualPathBuf,
    expected_parent_id: StorageDirectoryId,
}

impl ResolvedStoragePathBuf {
    /// Creates an owned resolved storage path.
    pub fn new(path: VirtualPathBuf, expected_parent_id: StorageDirectoryId) -> Self {
        Self {
            path,
            expected_parent_id,
        }
    }

    /// Returns a borrowed resolved storage path.
    pub fn as_resolved_path(&self) -> ResolvedStoragePath<'_> {
        ResolvedStoragePath::new(&self.path, &self.expected_parent_id)
    }

    /// Returns the physical storage path.
    pub fn path(&self) -> &VirtualPath {
        &self.path
    }

    /// Returns the expected identity of the physical parent directory.
    pub fn expected_parent_id(&self) -> &StorageDirectoryId {
        &self.expected_parent_id
    }
}

impl Deref for ResolvedStoragePathBuf {
    type Target = VirtualPath;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

/// Defines how a grouped rename handles an existing destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExistingDestinationPolicy {
    /// Replaces a compatible destination.
    Replace,
    /// Fails before any namespace change.
    Reject,
    /// Keeps a compatible destination and consumes the source.
    Ignore,
}

/// One source-to-destination move in a grouped rename operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenameOperation {
    /// Existing entry moved by the operation.
    pub source: ResolvedStoragePathBuf,
    /// Final path assigned to the entry.
    pub destination: ResolvedStoragePathBuf,
    /// Policy applied when the destination exists after sources are detached.
    pub existing_destination: ExistingDestinationPolicy,
}

impl RenameOperation {
    /// Creates an operation that replaces a compatible destination.
    pub fn replace(source: ResolvedStoragePathBuf, destination: ResolvedStoragePathBuf) -> Self {
        Self {
            source,
            destination,
            existing_destination: ExistingDestinationPolicy::Replace,
        }
    }

    /// Creates an operation that requires the destination to be absent.
    pub fn no_replace(source: ResolvedStoragePathBuf, destination: ResolvedStoragePathBuf) -> Self {
        Self {
            source,
            destination,
            existing_destination: ExistingDestinationPolicy::Reject,
        }
    }

    /// Creates an operation that keeps a compatible existing destination.
    pub fn ignore_existing(
        source: ResolvedStoragePathBuf,
        destination: ResolvedStoragePathBuf,
    ) -> Self {
        Self {
            source,
            destination,
            existing_destination: ExistingDestinationPolicy::Ignore,
        }
    }
}

/// Provides the filesystem operations required by encrypted storage layouts.
///
/// Identity mismatches must return [`std::io::ErrorKind::StaleNetworkFileHandle`]
/// before any requested mutation is applied, so callers may safely retry once.
pub trait StorageFileSystem: Send + Sync + 'static {
    /// Handle returned when opening a file.
    type OpenHandle: FileHandle;

    /// Iterator returned when listing a directory.
    type DirEntries: Iterator<Item = std::io::Result<FsDirEntry>>;

    /// Returns the identity of the storage root.
    fn get_root_id(&self) -> std::io::Result<StorageDirectoryId>;

    /// Returns a directory identity after optionally validating its parent.
    fn get_folder_id(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<StorageDirectoryId>;

    /// Opens a file with the requested capabilities.
    fn open_file_with(
        &self,
        path: ResolvedStoragePath<'_>,
        options: FileOpenOptions,
    ) -> std::io::Result<Self::OpenHandle>;

    /// Updates access and modification times.
    fn set_time(
        &self,
        path: ResolvedStoragePath<'_>,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()>;

    /// Changes ownership of an entry.
    fn chown(
        &self,
        path: ResolvedStoragePath<'_>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> std::io::Result<()>;

    /// Returns metadata for an entry.
    fn metadata(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Metadata>;

    /// Returns whether an entry exists.
    fn exists(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<bool> {
        match self.metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Truncates a file to a new size.
    fn truncate(&self, path: ResolvedStoragePath<'_>, new_size: u64) -> std::io::Result<()> {
        let mut options = FileOpenOptions::default();
        options.read(true).write(true);
        let file = self.open_file_with(path, options)?;
        file.set_len(new_size)?;
        file.flush()
    }

    /// Creates a new directory with optional permissions.
    fn mkdir(
        &self,
        path: ResolvedStoragePath<'_>,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata>;

    /// Creates a new node with optional permissions.
    fn mknode(
        &self,
        path: ResolvedStoragePath<'_>,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata>;

    /// Renames an entry.
    fn rename(
        &self,
        old_path: ResolvedStoragePath<'_>,
        new_path: ResolvedStoragePath<'_>,
    ) -> std::io::Result<()>;

    /// Atomically renames an entry and fails if the destination already exists.
    fn rename_no_replace(
        &self,
        old_path: ResolvedStoragePath<'_>,
        new_path: ResolvedStoragePath<'_>,
    ) -> std::io::Result<()>;

    /// Renames a group of entries using each destination policy.
    ///
    /// Paths must be non-root and unique within their source or destination set.
    /// Paths may nest within a set, but the two sets must not overlap. Sources
    /// are detached child-first and destinations published parent-first.
    /// Replaced destination subtrees and ignored sources are consumed in their
    /// entirety. Overlapping namespace mutations must not interfere with rollback.
    /// Concurrent reads may observe intermediate states.
    fn rename_multiple(&self, operations: &[RenameOperation]) -> std::io::Result<()>;

    /// Removes a non-directory entry.
    fn remove(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<()>;

    /// Removes an empty directory.
    fn remove_dir(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<()>;

    /// Removes an exact set of entries while preserving unlisted directory contents.
    ///
    /// Non-directory entries are staged before directories. If a staged directory
    /// still contains an unlisted entry, the operation restores every staged entry
    /// and returns an error equivalent to ENOTEMPTY.
    /// Every supplied path must exist, be unique, and match its declared kind.
    /// Implementation-owned staging entries must remain hidden and inaccessible.
    fn remove_multiple(
        &self,
        directories: &[ResolvedStoragePathBuf],
        non_directories: &[ResolvedStoragePathBuf],
    ) -> std::io::Result<()>;

    /// Recursively removes a directory and its contents.
    fn remove_dir_all(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<()> {
        if path.path().is_empty() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY));
        }

        let directory_id = self.get_folder_id(path)?;
        let entries = self
            .read_dir(path, &directory_id)?
            .collect::<std::io::Result<Vec<_>>>()?;
        for entry in entries {
            let child_path = path.path().join(entry.file_name);
            let child = ResolvedStoragePath::new(&child_path, &directory_id);
            if entry.metadata.file_type == FileType::Directory {
                self.remove_dir_all(child)?;
            } else {
                self.remove(child)?;
            }
        }
        self.remove_dir(path)
    }

    /// Writes a complete file, replacing existing contents.
    fn put(&self, path: ResolvedStoragePath<'_>, data: &[u8]) -> std::io::Result<()> {
        let mut options = FileOpenOptions::default();
        options.write(true).truncate(true).create(true);
        self.open_file_with(path, options)?.write_all_at(0, data)
    }

    /// Writes a complete new file and fails if it already exists.
    fn put_new(&self, path: ResolvedStoragePath<'_>, data: &[u8]) -> std::io::Result<()> {
        let mut options = FileOpenOptions::default();
        options.write(true).create_new(true);
        self.open_file_with(path, options)?.write_all_at(0, data)
    }

    /// Reads the complete contents of a file.
    fn read_all(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Vec<u8>> {
        let mut options = FileOpenOptions::default();
        options.read(true);
        let file = self.open_file_with(path, options)?;
        let size = file.size()?;
        let size =
            usize::try_from(size).map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let mut buffer = vec![0; size];
        file.read_exact_at(0, &mut buffer)?;
        Ok(buffer)
    }

    /// Returns whether a directory contains no entries.
    fn is_dir_empty(
        &self,
        path: ResolvedStoragePath<'_>,
        expected_directory_id: &StorageDirectoryId,
    ) -> std::io::Result<bool> {
        self.read_dir(path, expected_directory_id)?
            .next()
            .transpose()
            .map(|entry| entry.is_none())
    }

    /// Creates a directory and any missing parents.
    fn mkdir_all(&self, path: &VirtualPath) -> std::io::Result<()> {
        let mut parent_id = self.get_root_id()?;
        let mut current = VirtualPathBuf::default();
        for component in path.components() {
            current.push(component);
            let current_path = ResolvedStoragePath::new(&current, &parent_id);
            match self.get_folder_id(current_path) {
                Ok(id) => parent_id = id,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.mkdir(current_path, None)?;
                    parent_id = self.get_folder_id(current_path)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Updates permissions and returns the resulting metadata.
    fn set_permissions(
        &self,
        path: ResolvedStoragePath<'_>,
        permissions: Permissions,
    ) -> std::io::Result<Metadata>;

    /// Reads an extended attribute.
    fn get_xattr(&self, path: ResolvedStoragePath<'_>, name: &str) -> std::io::Result<Vec<u8>>;

    /// Lists extended attribute names.
    fn list_xattr(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Vec<String>>;

    /// Removes an extended attribute.
    fn remove_xattr(&self, path: ResolvedStoragePath<'_>, name: &str) -> std::io::Result<()>;

    /// Writes an extended attribute.
    fn set_xattr(
        &self,
        path: ResolvedStoragePath<'_>,
        name: &str,
        value: &[u8],
    ) -> std::io::Result<()>;

    /// Reads a symbolic-link target.
    fn read_symlink(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<String>;

    /// Creates a symbolic link.
    fn create_symlink(
        &self,
        path: ResolvedStoragePath<'_>,
        target: &str,
    ) -> std::io::Result<Metadata>;

    /// Iterates over directory entries after validating the directory identity.
    fn read_dir(
        &self,
        path: ResolvedStoragePath<'_>,
        expected_directory_id: &StorageDirectoryId,
    ) -> std::io::Result<Self::DirEntries>;
}

/// Provides asynchronous filesystem operations required by encrypted storage layouts.
///
/// Identity mismatches must return [`std::io::ErrorKind::StaleNetworkFileHandle`]
/// before any requested mutation is applied, so callers may safely retry once.
/// A directory listing must report such a mismatch before yielding its first batch.
pub trait AsyncStorageFileSystem: Send + Sync + 'static {
    /// Handle returned when opening a file.
    type OpenHandle: AsyncFileHandle;

    /// Returns the identity of the storage root.
    fn get_root_id(&self) -> impl Future<Output = std::io::Result<StorageDirectoryId>> + Send;

    /// Returns a directory identity after optionally validating its parent.
    fn get_folder_id(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<StorageDirectoryId>> + Send;

    /// Opens a file with the requested capabilities.
    fn open_file_with(
        &self,
        path: ResolvedStoragePath<'_>,
        options: FileOpenOptions,
    ) -> impl Future<Output = std::io::Result<Self::OpenHandle>> + Send;

    /// Updates access and modification times.
    fn set_time(
        &self,
        path: ResolvedStoragePath<'_>,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Changes ownership of an entry.
    fn chown(
        &self,
        path: ResolvedStoragePath<'_>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Returns metadata for an entry.
    fn metadata(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Returns whether an entry exists.
    fn exists(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<bool>> + Send {
        async move {
            match self.metadata(path).await {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error),
            }
        }
    }

    /// Truncates a file to a new size.
    fn truncate(
        &self,
        path: ResolvedStoragePath<'_>,
        new_size: u64,
    ) -> impl Future<Output = std::io::Result<()>> + Send {
        async move {
            let mut options = FileOpenOptions::default();
            options.read(true).write(true);
            let file = self.open_file_with(path, options).await?;
            file.set_len(new_size).await?;
            file.flush().await
        }
    }

    /// Creates a new directory with optional permissions.
    fn mkdir(
        &self,
        path: ResolvedStoragePath<'_>,
        permissions: Option<Permissions>,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Creates a new node with optional permissions.
    fn mknode(
        &self,
        path: ResolvedStoragePath<'_>,
        permissions: Option<Permissions>,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Renames an entry.
    fn rename(
        &self,
        old_path: ResolvedStoragePath<'_>,
        new_path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Atomically renames an entry and fails if the destination already exists.
    fn rename_no_replace(
        &self,
        old_path: ResolvedStoragePath<'_>,
        new_path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Renames a group of entries using each destination policy.
    ///
    /// Paths must be non-root and unique within their source or destination set.
    /// Paths may nest within a set, but the two sets must not overlap. Sources
    /// are detached child-first and destinations published parent-first.
    /// Replaced destination subtrees and ignored sources are consumed in their
    /// entirety. Overlapping namespace mutations must not interfere with rollback.
    /// Concurrent reads may observe intermediate states. Once accepted by a
    /// remote implementation, dropping the future need not cancel the operation.
    fn rename_multiple(
        &self,
        operations: &[RenameOperation],
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Removes a non-directory entry.
    fn remove(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Removes an empty directory.
    fn remove_dir(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Removes an exact set of entries while preserving unlisted directory contents.
    ///
    /// Non-directory entries are staged before directories. If a staged directory
    /// still contains an unlisted entry, the operation restores every staged entry
    /// and returns an error equivalent to ENOTEMPTY.
    /// Every supplied path must exist, be unique, and match its declared kind.
    /// Implementation-owned staging entries must remain hidden and inaccessible.
    fn remove_multiple(
        &self,
        directories: &[ResolvedStoragePathBuf],
        non_directories: &[ResolvedStoragePathBuf],
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Recursively removes a directory and its contents.
    fn remove_dir_all(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Writes a complete file, replacing existing contents.
    fn put(
        &self,
        path: ResolvedStoragePath<'_>,
        data: &[u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send {
        async move {
            let mut options = FileOpenOptions::default();
            options.write(true).truncate(true).create(true);
            self.open_file_with(path, options)
                .await?
                .write_all_at(0, data)
                .await
        }
    }

    /// Writes a complete new file and fails if it already exists.
    fn put_new(
        &self,
        path: ResolvedStoragePath<'_>,
        data: &[u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send {
        async move {
            let mut options = FileOpenOptions::default();
            options.write(true).create_new(true);
            self.open_file_with(path, options)
                .await?
                .write_all_at(0, data)
                .await
        }
    }

    /// Reads the complete contents of a file.
    fn read_all(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<Vec<u8>>> + Send {
        async move {
            let mut options = FileOpenOptions::default();
            options.read(true);
            let file = self.open_file_with(path, options).await?;
            let size = file.size().await?;
            let size = usize::try_from(size)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
            let mut buffer = vec![0; size];
            file.read_exact_at(0, &mut buffer).await?;
            Ok(buffer)
        }
    }

    /// Returns whether a directory contains no entries.
    fn is_dir_empty(
        &self,
        path: ResolvedStoragePathBuf,
        expected_directory_id: StorageDirectoryId,
    ) -> impl Future<Output = std::io::Result<bool>> + Send {
        async move {
            let entries = self.read_dir(path, expected_directory_id);
            let mut entries = std::pin::pin!(entries);
            while let Some(batch) =
                std::future::poll_fn(|context| entries.as_mut().poll_next(context)).await
            {
                if !batch?.is_empty() {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }

    /// Creates a directory and any missing parents.
    fn mkdir_all(&self, path: &VirtualPath) -> impl Future<Output = std::io::Result<()>> + Send {
        async move {
            let mut parent_id = self.get_root_id().await?;
            let mut current = VirtualPathBuf::default();
            for component in path.components() {
                current.push(component);
                let current_path = ResolvedStoragePath::new(&current, &parent_id);
                match self.get_folder_id(current_path).await {
                    Ok(id) => parent_id = id,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        self.mkdir(current_path, None).await?;
                        parent_id = self.get_folder_id(current_path).await?;
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        }
    }

    /// Updates permissions and returns the resulting metadata.
    fn set_permissions(
        &self,
        path: ResolvedStoragePath<'_>,
        permissions: Permissions,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Reads an extended attribute.
    fn get_xattr(
        &self,
        path: ResolvedStoragePath<'_>,
        name: &str,
    ) -> impl Future<Output = std::io::Result<Vec<u8>>> + Send;

    /// Lists extended attribute names.
    fn list_xattr(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<Vec<String>>> + Send;

    /// Removes an extended attribute.
    fn remove_xattr(
        &self,
        path: ResolvedStoragePath<'_>,
        name: &str,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Writes an extended attribute.
    fn set_xattr(
        &self,
        path: ResolvedStoragePath<'_>,
        name: &str,
        value: &[u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Reads a symbolic-link target.
    fn read_symlink(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<String>> + Send;

    /// Creates a symbolic link.
    fn create_symlink(
        &self,
        path: ResolvedStoragePath<'_>,
        target: &str,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Streams directory entries after validating the directory identity.
    fn read_dir(
        &self,
        path: ResolvedStoragePathBuf,
        expected_directory_id: StorageDirectoryId,
    ) -> impl Stream<Item = std::io::Result<Vec<FsDirEntry>>> + Send;
}
