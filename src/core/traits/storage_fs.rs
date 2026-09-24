use super::{
    AsyncFileHandle, AsyncReadAt, AsyncSetLen, AsyncSize, AsyncWriteAt, FileHandle,
    FileOpenOptions, FileType, FsDirEntry, Metadata, Permissions, ReadAt, SetLen, Size,
    VirtualPath, VirtualPathBuf, WriteAt,
};
use futures_core::Stream;
use std::{future::Future, time::SystemTime};

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
    pub source: VirtualPathBuf,
    /// Final path assigned to the entry.
    pub destination: VirtualPathBuf,
    /// Policy applied when the destination exists after sources are detached.
    pub existing_destination: ExistingDestinationPolicy,
}

impl RenameOperation {
    /// Creates an operation that replaces a compatible destination.
    pub fn replace(source: VirtualPathBuf, destination: VirtualPathBuf) -> Self {
        Self {
            source,
            destination,
            existing_destination: ExistingDestinationPolicy::Replace,
        }
    }

    /// Creates an operation that requires the destination to be absent.
    pub fn no_replace(source: VirtualPathBuf, destination: VirtualPathBuf) -> Self {
        Self {
            source,
            destination,
            existing_destination: ExistingDestinationPolicy::Reject,
        }
    }

    /// Creates an operation that keeps a compatible existing destination.
    pub fn ignore_existing(source: VirtualPathBuf, destination: VirtualPathBuf) -> Self {
        Self {
            source,
            destination,
            existing_destination: ExistingDestinationPolicy::Ignore,
        }
    }
}

/// Provides the filesystem operations required by encrypted storage layouts.
pub trait StorageFileSystem: Send + Sync + 'static {
    /// Handle returned when opening a file.
    type OpenHandle: FileHandle;

    /// Iterator returned when listing a directory.
    type DirEntries: Iterator<Item = std::io::Result<FsDirEntry>>;

    /// Opens a file with the requested capabilities.
    fn open_file_with(
        &self,
        path: &VirtualPath,
        options: FileOpenOptions,
    ) -> std::io::Result<Self::OpenHandle>;

    /// Updates access and modification times.
    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()>;

    /// Changes ownership of an entry.
    fn chown(&self, path: &VirtualPath, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()>;

    /// Returns metadata for an entry.
    fn metadata(&self, path: &VirtualPath) -> std::io::Result<Metadata>;

    /// Returns whether an entry exists.
    fn exists(&self, path: &VirtualPath) -> std::io::Result<bool> {
        match self.metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Truncates a file to a new size.
    fn truncate(&self, path: &VirtualPath, new_size: u64) -> std::io::Result<()> {
        let mut options = FileOpenOptions::default();
        options.read(true).write(true);
        let file = self.open_file_with(path, options)?;
        file.set_len(new_size)?;
        file.flush()
    }

    /// Creates a new directory with optional permissions.
    fn mkdir(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata>;

    /// Creates a new node with optional permissions.
    fn mknode(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata>;

    /// Renames an entry.
    fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()>;

    /// Atomically renames an entry and fails if the destination already exists.
    fn rename_no_replace(
        &self,
        old_path: &VirtualPath,
        new_path: &VirtualPath,
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
    fn remove(&self, path: &VirtualPath) -> std::io::Result<()>;

    /// Removes an empty directory.
    fn remove_dir(&self, path: &VirtualPath) -> std::io::Result<()>;

    /// Removes an exact set of entries while preserving unlisted directory contents.
    ///
    /// Non-directory entries are staged before directories. If a staged directory
    /// still contains an unlisted entry, the operation restores every staged entry
    /// and returns an error equivalent to ENOTEMPTY.
    /// Every supplied path must exist, be unique, and match its declared kind.
    /// Implementation-owned staging entries must remain hidden and inaccessible.
    fn remove_multiple(
        &self,
        directories: &[VirtualPathBuf],
        non_directories: &[VirtualPathBuf],
    ) -> std::io::Result<()>;

    /// Recursively removes a directory and its contents.
    fn remove_dir_all(&self, path: &VirtualPath) -> std::io::Result<()> {
        if path.is_empty() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY));
        }

        let entries = self.read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        for entry in entries {
            let child_path = path.join(entry.file_name);
            if entry.metadata.file_type == FileType::Directory {
                self.remove_dir_all(&child_path)?;
            } else {
                self.remove(&child_path)?;
            }
        }
        self.remove_dir(path)
    }

    /// Writes a complete file, replacing existing contents.
    fn put(&self, path: &VirtualPath, data: &[u8]) -> std::io::Result<()> {
        let mut options = FileOpenOptions::default();
        options.write(true).truncate(true).create(true);
        self.open_file_with(path, options)?.write_all_at(0, data)
    }

    /// Writes a complete new file and fails if it already exists.
    fn put_new(&self, path: &VirtualPath, data: &[u8]) -> std::io::Result<()> {
        let mut options = FileOpenOptions::default();
        options.write(true).create_new(true);
        self.open_file_with(path, options)?.write_all_at(0, data)
    }

    /// Reads the complete contents of a file.
    fn read_all(&self, path: &VirtualPath) -> std::io::Result<Vec<u8>> {
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
    fn is_dir_empty(&self, path: &VirtualPath) -> std::io::Result<bool> {
        self.read_dir(path)?
            .next()
            .transpose()
            .map(|entry| entry.is_none())
    }

    /// Creates a directory and any missing parents.
    fn mkdir_all(&self, path: &VirtualPath) -> std::io::Result<()> {
        if self.exists(path)? {
            return Ok(());
        }
        if let Some(parent) = path.parent()
            && !parent.as_str().is_empty()
        {
            self.mkdir_all(parent)?;
        }
        match self.mkdir(path, None) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Updates permissions and returns the resulting metadata.
    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata>;

    /// Reads an extended attribute.
    fn get_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<Vec<u8>>;

    /// Lists extended attribute names.
    fn list_xattr(&self, path: &VirtualPath) -> std::io::Result<Vec<String>>;

    /// Removes an extended attribute.
    fn remove_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<()>;

    /// Writes an extended attribute.
    fn set_xattr(&self, path: &VirtualPath, name: &str, value: &[u8]) -> std::io::Result<()>;

    /// Reads a symbolic-link target.
    fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<String>;

    /// Creates a symbolic link.
    fn create_symlink(&self, path: &VirtualPath, target: &str) -> std::io::Result<Metadata>;

    /// Iterates over directory entries.
    fn read_dir(&self, path: &VirtualPath) -> std::io::Result<Self::DirEntries>;
}

/// Provides asynchronous filesystem operations required by encrypted storage layouts.
pub trait AsyncStorageFileSystem: Send + Sync + 'static {
    /// Handle returned when opening a file.
    type OpenHandle: AsyncFileHandle;

    /// Opens a file with the requested capabilities.
    fn open_file_with(
        &self,
        path: &VirtualPath,
        options: FileOpenOptions,
    ) -> impl Future<Output = std::io::Result<Self::OpenHandle>> + Send;

    /// Updates access and modification times.
    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Changes ownership of an entry.
    fn chown(
        &self,
        path: &VirtualPath,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Returns metadata for an entry.
    fn metadata(
        &self,
        path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Returns whether an entry exists.
    fn exists(&self, path: &VirtualPath) -> impl Future<Output = std::io::Result<bool>> + Send {
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
        path: &VirtualPath,
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
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Creates a new node with optional permissions.
    fn mknode(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Renames an entry.
    fn rename(
        &self,
        old_path: &VirtualPath,
        new_path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Atomically renames an entry and fails if the destination already exists.
    fn rename_no_replace(
        &self,
        old_path: &VirtualPath,
        new_path: &VirtualPath,
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
    fn remove(&self, path: &VirtualPath) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Removes an empty directory.
    fn remove_dir(&self, path: &VirtualPath) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Removes an exact set of entries while preserving unlisted directory contents.
    ///
    /// Non-directory entries are staged before directories. If a staged directory
    /// still contains an unlisted entry, the operation restores every staged entry
    /// and returns an error equivalent to ENOTEMPTY.
    /// Every supplied path must exist, be unique, and match its declared kind.
    /// Implementation-owned staging entries must remain hidden and inaccessible.
    fn remove_multiple(
        &self,
        directories: &[VirtualPathBuf],
        non_directories: &[VirtualPathBuf],
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Recursively removes a directory and its contents.
    fn remove_dir_all(
        &self,
        path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Writes a complete file, replacing existing contents.
    fn put(
        &self,
        path: &VirtualPath,
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
        path: &VirtualPath,
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
        path: &VirtualPath,
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
        path: VirtualPathBuf,
    ) -> impl Future<Output = std::io::Result<bool>> + Send {
        async move {
            let entries = self.read_dir(path);
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
    fn mkdir_all(&self, path: &VirtualPath) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Updates permissions and returns the resulting metadata.
    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Reads an extended attribute.
    fn get_xattr(
        &self,
        path: &VirtualPath,
        name: &str,
    ) -> impl Future<Output = std::io::Result<Vec<u8>>> + Send;

    /// Lists extended attribute names.
    fn list_xattr(
        &self,
        path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<Vec<String>>> + Send;

    /// Removes an extended attribute.
    fn remove_xattr(
        &self,
        path: &VirtualPath,
        name: &str,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Writes an extended attribute.
    fn set_xattr(
        &self,
        path: &VirtualPath,
        name: &str,
        value: &[u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Reads a symbolic-link target.
    fn read_symlink(
        &self,
        path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<String>> + Send;

    /// Creates a symbolic link.
    fn create_symlink(
        &self,
        path: &VirtualPath,
        target: &str,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Streams directory entries in implementation-defined batches.
    fn read_dir(
        &self,
        path: VirtualPathBuf,
    ) -> impl Stream<Item = std::io::Result<Vec<FsDirEntry>>> + Send;
}
