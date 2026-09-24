use super::super::{
    FileOpenOptions, FileType, FsDirEntry, Metadata, Permissions, Result, UnsafeOpenFileTable,
    VirtualPath,
};
pub use camino::{Utf8Path, Utf8PathBuf};
use log::error;
use std::{fmt::Display, future::Future, pin::Pin, time::SystemTime};

/// Boxed future returned by asynchronous I/O traits.
pub type IoFuture<'a, T> = Pin<Box<dyn Future<Output = std::io::Result<T>> + Send + 'a>>;

/// Provides positioned reads without changing a shared file cursor.
pub trait ReadAt {
    /// Performs one positioned read and returns the number of bytes read.
    ///
    /// A successful read may return fewer bytes than the buffer can hold.
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Repeats positioned reads until the buffer is full, EOF is reached, or an error occurs.
    fn read_all_at(&self, mut pos: u64, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let requested = buf.len();
        while !buf.is_empty() {
            match self.read_at(pos, buf) {
                Ok(0) => break,
                Ok(n) => {
                    buf = &mut buf[n..];
                    if !buf.is_empty() {
                        pos = pos
                            .checked_add(n as u64)
                            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EOVERFLOW))?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(requested - buf.len())
    }

    /// Fills the entire buffer or returns an error, including unexpected EOF.
    fn read_exact_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let expected = buf.len();
        let actual = self.read_all_at(pos, buf)?;

        if actual == expected {
            Ok(())
        } else {
            Err(std::io::ErrorKind::UnexpectedEof.into())
        }
    }
}

/// Provides asynchronous positioned reads without changing a shared file cursor.
pub trait AsyncReadAt: Send + Sync {
    /// Performs one positioned read and returns the number of bytes read.
    ///
    /// A successful read may return fewer bytes than the buffer can hold.
    fn read_at<'a>(&'a self, pos: u64, buf: &'a mut [u8]) -> IoFuture<'a, usize>;

    /// Repeats positioned reads until the buffer is full, EOF is reached, or an error occurs.
    fn read_all_at<'a>(&'a self, mut pos: u64, mut buf: &'a mut [u8]) -> IoFuture<'a, usize> {
        Box::pin(async move {
            let requested = buf.len();
            while !buf.is_empty() {
                match self.read_at(pos, buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf = &mut buf[n..];
                        if !buf.is_empty() {
                            pos = pos.checked_add(n as u64).ok_or_else(|| {
                                std::io::Error::from_raw_os_error(libc::EOVERFLOW)
                            })?;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(requested - buf.len())
        })
    }

    /// Fills the entire buffer or returns an error, including unexpected EOF.
    fn read_exact_at<'a>(&'a self, pos: u64, buf: &'a mut [u8]) -> IoFuture<'a, ()> {
        Box::pin(async move {
            let expected = buf.len();
            let actual = self.read_all_at(pos, buf).await?;

            if actual == expected {
                Ok(())
            } else {
                Err(std::io::ErrorKind::UnexpectedEof.into())
            }
        })
    }
}

/// Returns the logical size of a file-like object.
pub trait Size {
    fn size(&self) -> std::io::Result<u64>;
}

/// Returns the logical size of a file-like object asynchronously.
pub trait AsyncSize: Send + Sync {
    /// Returns the logical size.
    fn size(&self) -> IoFuture<'_, u64>;
}

/// Provides access to a file's modification time.
pub trait ModifiedTime {
    fn get_modified(&self) -> std::io::Result<SystemTime>;
    fn set_modified_time(&self, modified_time: SystemTime) -> std::io::Result<()>;
}

/// Provides asynchronous access to a file's modification time.
pub trait AsyncModifiedTime: Send + Sync {
    /// Returns the modification time.
    fn get_modified(&self) -> IoFuture<'_, SystemTime>;

    /// Updates the modification time.
    fn set_modified_time(&self, modified_time: SystemTime) -> IoFuture<'_, ()>;
}

/// Provides positioned writes without changing a shared file cursor.
pub trait WriteAt {
    fn write_at(&self, pos: u64, buf: &[u8]) -> std::io::Result<usize>;

    /// Writes the full buffer unless an error occurs.
    fn write_all_at(&self, mut pos: u64, mut buf: &[u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            match self.write_at(pos, buf) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ));
                }
                Ok(n) => {
                    buf = &buf[n..];
                    pos += n as u64;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    /// Flushes buffered state when the implementation uses staging.
    fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Provides asynchronous positioned writes without changing a shared file cursor.
pub trait AsyncWriteAt: Send + Sync {
    /// Performs one positioned write and returns the number of bytes written.
    fn write_at<'a>(&'a self, pos: u64, buf: &'a [u8]) -> IoFuture<'a, usize>;

    /// Writes the full buffer unless an error occurs.
    fn write_all_at<'a>(&'a self, mut pos: u64, mut buf: &'a [u8]) -> IoFuture<'a, ()> {
        Box::pin(async move {
            while !buf.is_empty() {
                match self.write_at(pos, buf).await {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "failed to write whole buffer",
                        ));
                    }
                    Ok(n) => {
                        buf = &buf[n..];
                        pos += n as u64;
                    }
                    Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })
    }

    /// Flushes buffered state when the implementation uses staging.
    fn flush(&self) -> IoFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

/// Trait for synchronization operations.
pub trait SetSync {
    /// Synchronizes data to disk.
    fn sync(&self, datasync: bool) -> std::io::Result<()>;
}

/// Provides asynchronous synchronization operations.
pub trait AsyncSetSync: Send + Sync {
    /// Synchronizes data to storage.
    fn sync(&self, datasync: bool) -> IoFuture<'_, ()>;
}

/// Trait for setting file length.
pub trait SetLen {
    /// Sets the length of the file.
    fn set_len(&self, new_size: u64) -> std::io::Result<()>;
}

/// Provides asynchronous file length updates.
pub trait AsyncSetLen: Send + Sync {
    /// Sets the file length.
    fn set_len(&self, new_size: u64) -> IoFuture<'_, ()>;
}

/// Marker trait for read operations.
pub trait ReadHandle: ReadAt + Send + Sync {}
/// Provides the complete set of operations supported by an open file.
pub trait FileHandle:
    ReadHandle + WriteAt + SetLen + SetSync + Size + ModifiedTime + 'static
{
}

/// Provides the complete asynchronous operation set supported by an open file.
pub trait AsyncFileHandle:
    AsyncReadAt + AsyncWriteAt + AsyncSetLen + AsyncSetSync + AsyncSize + AsyncModifiedTime + 'static
{
}

trait _AsyncDynFileHandle {
    fn read_all_at<'a>(&'a self, pos: u64, buf: &'a mut [u8]) -> IoFuture<'a, usize>;
    fn read_exact_at<'a>(&'a self, pos: u64, buf: &'a mut [u8]) -> IoFuture<'a, ()>;
    fn size(&self) -> IoFuture<'_, u64>;
    fn get_modified(&self) -> IoFuture<'_, SystemTime>;
    fn set_modified_time(&self, modified_time: SystemTime) -> IoFuture<'_, ()>;
    fn write_all_at<'a>(&'a self, pos: u64, buf: &'a [u8]) -> IoFuture<'a, ()>;
    fn flush(&self) -> IoFuture<'_, ()>;
    fn sync(&self, datasync: bool) -> IoFuture<'_, ()>;
    fn set_len(&self, new_size: u64) -> IoFuture<'_, ()>;
}

/// Access capabilities required from a physical file handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileCapabilities {
    /// The handle only needs to support reads.
    ReadOnly,
    /// The handle must support both reads and writes.
    ReadWrite,
}

impl FileCapabilities {
    /// Returns whether these capabilities cover another open request.
    pub fn contains(self, required: Self) -> bool {
        matches!(self, Self::ReadWrite) || self == required
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Box<T> {
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        (**self).read_at(pos, buf)
    }

    fn read_all_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        (**self).read_all_at(pos, buf)
    }

    fn read_exact_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<()> {
        (**self).read_exact_at(pos, buf)
    }
}

impl<T: AsyncReadAt + ?Sized> AsyncReadAt for Box<T> {
    fn read_at<'a>(&'a self, pos: u64, buf: &'a mut [u8]) -> IoFuture<'a, usize> {
        (**self).read_at(pos, buf)
    }

    fn read_all_at<'a>(&'a self, pos: u64, buf: &'a mut [u8]) -> IoFuture<'a, usize> {
        (**self).read_all_at(pos, buf)
    }

    fn read_exact_at<'a>(&'a self, pos: u64, buf: &'a mut [u8]) -> IoFuture<'a, ()> {
        (**self).read_exact_at(pos, buf)
    }
}

impl<T: WriteAt + ?Sized> WriteAt for Box<T> {
    fn write_at(&self, pos: u64, buf: &[u8]) -> std::io::Result<usize> {
        (**self).write_at(pos, buf)
    }

    fn flush(&self) -> std::io::Result<()> {
        (**self).flush()
    }
}

impl<T: AsyncWriteAt + ?Sized> AsyncWriteAt for Box<T> {
    fn write_at<'a>(&'a self, pos: u64, buf: &'a [u8]) -> IoFuture<'a, usize> {
        (**self).write_at(pos, buf)
    }

    fn flush(&self) -> IoFuture<'_, ()> {
        (**self).flush()
    }
}

impl<T: SetLen + ?Sized> SetLen for Box<T> {
    fn set_len(&self, new_size: u64) -> std::io::Result<()> {
        (**self).set_len(new_size)
    }
}

impl<T: AsyncSetLen + ?Sized> AsyncSetLen for Box<T> {
    fn set_len(&self, new_size: u64) -> IoFuture<'_, ()> {
        (**self).set_len(new_size)
    }
}

impl<T: SetSync + ?Sized> SetSync for Box<T> {
    fn sync(&self, datasync: bool) -> std::io::Result<()> {
        (**self).sync(datasync)
    }
}

impl<T: AsyncSetSync + ?Sized> AsyncSetSync for Box<T> {
    fn sync(&self, datasync: bool) -> IoFuture<'_, ()> {
        (**self).sync(datasync)
    }
}

impl<T: Size + ?Sized> Size for Box<T> {
    fn size(&self) -> std::io::Result<u64> {
        (**self).size()
    }
}

impl<T: AsyncSize + ?Sized> AsyncSize for Box<T> {
    fn size(&self) -> IoFuture<'_, u64> {
        (**self).size()
    }
}

impl<T: ModifiedTime + ?Sized> ModifiedTime for Box<T> {
    fn get_modified(&self) -> std::io::Result<SystemTime> {
        (**self).get_modified()
    }

    fn set_modified_time(&self, modified_time: SystemTime) -> std::io::Result<()> {
        (**self).set_modified_time(modified_time)
    }
}

impl<T: AsyncModifiedTime + ?Sized> AsyncModifiedTime for Box<T> {
    fn get_modified(&self) -> IoFuture<'_, SystemTime> {
        (**self).get_modified()
    }

    fn set_modified_time(&self, modified_time: SystemTime) -> IoFuture<'_, ()> {
        (**self).set_modified_time(modified_time)
    }
}

impl<T> ReadHandle for T where T: ReadAt + Send + Sync {}

impl<T> FileHandle for T where
    T: ReadHandle + WriteAt + SetLen + SetSync + Size + ModifiedTime + 'static
{
}

impl<T> AsyncFileHandle for T where
    T: AsyncReadAt
        + AsyncWriteAt
        + AsyncSetLen
        + AsyncSetSync
        + AsyncSize
        + AsyncModifiedTime
        + 'static
{
}

/// Maps stable identifiers to open file handles.
pub trait OpenFileTable: Default {
    /// Opens an inode and returns a unique identifier for this open reference.
    ///
    /// Implementations may share one physical handle between references to the
    /// same inode. `replace_existing` requests a fresh shared handle after an
    /// operation such as truncation has reset the underlying file.
    fn open<F>(
        &self,
        inode: u64,
        capabilities: FileCapabilities,
        replace_existing: bool,
        opener: F,
    ) -> std::io::Result<u64>
    where
        F: FnOnce() -> std::io::Result<Box<dyn FileHandle>>;

    /// Releases an open file handle.
    fn release(&self, id: u64) -> std::io::Result<()>;

    /// Accesses an open file handle.
    fn access<U, F: FnOnce(&dyn FileHandle) -> std::io::Result<U>>(
        &self,
        id: u64,
        handler: F,
    ) -> std::io::Result<U>;

    /// Accesses a shared inode handle when it provides the required capabilities.
    fn access_inode<U, F: FnOnce(&dyn FileHandle) -> std::io::Result<U>>(
        &self,
        _inode: u64,
        _capabilities: FileCapabilities,
        _handler: F,
    ) -> std::io::Result<Option<U>> {
        Ok(None)
    }
}

/// Trait for read-only filesystem operations.
pub trait ReadOnlyFileSystem: Send + Sync + 'static {
    /// Opens a file in read-only mode.
    fn open_readonly(&self, path: &VirtualPath) -> std::io::Result<Box<dyn FileHandle>>;
    /// Lists directory entries.
    fn read_dir(
        &self,
        path: &VirtualPath,
    ) -> std::io::Result<Box<dyn Iterator<Item = std::io::Result<FsDirEntry>> + '_>>;
    /// Retrieves metadata for a path.
    fn metadata(&self, path: &VirtualPath) -> std::io::Result<Metadata>;
    /// Checks if a path exists.
    fn exists(&self, path: &VirtualPath) -> std::io::Result<bool> {
        match self.metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
    /// Reads the target of a symbolic link.
    fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<String>;
    /// Lists extended attribute names.
    fn list_xattr(&self, path: &VirtualPath) -> std::io::Result<Vec<String>>;
    /// Gets an extended attribute value.
    fn get_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<Vec<u8>>;
}

//pub trait GenericFileSystem: FileSystem<File = Box<dyn ReadWrite>> {}
//impl<T: FileSystem<File = Box<dyn ReadWrite>>> GenericFileSystem for T {}

/// Trait for full filesystem operations.
pub trait FileSystem: ReadOnlyFileSystem {
    /// Opens a file with specified options.
    fn open_file_with(
        &self,
        path: &VirtualPath,
        options: FileOpenOptions,
    ) -> std::io::Result<Box<dyn FileHandle>>;
    /// Truncates a file to a new size.
    fn truncate(&self, path: &VirtualPath, new_size: u64) -> std::io::Result<()> {
        let mut options = FileOpenOptions::default();
        options.read(true).write(true);
        let file = self.open_file_with(path, options)?;
        file.set_len(new_size)?;
        file.flush()
    }
    /// Renames a file or directory.
    fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()>;
    /// Removes a non-directory entry.
    fn remove(&self, path: &VirtualPath) -> std::io::Result<()>;
    /// Removes an empty directory.
    fn remove_dir(&self, path: &VirtualPath) -> std::io::Result<()>;
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
    /// Creates a new directory with optional permissions.
    fn mkdir(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata>;
    /// Creates a new node (file) with optional permissions.
    fn mknode(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata>;
    /// Sets permissions on a path.
    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata>;
    /// Sets access and modification times.
    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()>;
    /// Creates a symbolic link.
    fn create_symlink(&self, path: &VirtualPath, target_path: &str) -> std::io::Result<Metadata>;
    /// Changes ownership of a path.
    fn chown(&self, path: &VirtualPath, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()>;

    /// Sets an extended attribute.
    fn set_xattr(&self, path: &VirtualPath, name: &str, value: &[u8]) -> std::io::Result<()>;
    /// Removes an extended attribute.
    fn remove_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<()>;
}

/// Hosts a filesystem together with its open file table.
pub struct FileSystemSession<C: OpenFileTable = UnsafeOpenFileTable> {
    fs: Box<dyn FileSystem>,
    open_files: C,
    is_background_child: bool,
}

impl<C: OpenFileTable> FileSystemSession<C> {
    pub fn open_files(&self) -> &C {
        &self.open_files
    }
    pub fn set_as_background_child(&mut self) {
        self.is_background_child = true;
    }
    pub fn is_background_child(&self) -> bool {
        self.is_background_child
    }
}

impl<T: FileSystem, C: OpenFileTable> From<T> for FileSystemSession<C> {
    fn from(value: T) -> Self {
        Self {
            fs: Box::new(value),
            open_files: C::default(),
            is_background_child: false,
        }
    }
}

impl<C: OpenFileTable> From<Box<dyn FileSystem>> for FileSystemSession<C> {
    fn from(value: Box<dyn FileSystem>) -> Self {
        Self {
            fs: value,
            open_files: C::default(),
            is_background_child: false,
        }
    }
}

impl<C: OpenFileTable> AsRef<dyn FileSystem> for FileSystemSession<C> {
    fn as_ref(&self) -> &dyn FileSystem {
        self.fs.as_ref()
    }
}

/// Converts results to IO errors.
pub trait OrIoError<T> {
    /// Converts to an invalid IO error.
    fn or_invalid(self) -> std::io::Result<T>;
    /// Converts to a specified IO error.
    fn or_io_error(self, error: i32) -> std::io::Result<T>;
}

impl<T> OrIoError<T> for Option<T> {
    fn or_invalid(self) -> std::io::Result<T> {
        self.ok_or_else(|| {
            //error!("invalid error [None]");
            std::io::Error::from_raw_os_error(libc::EINVAL)
        })
    }
    fn or_io_error(self, error: i32) -> std::io::Result<T> {
        self.ok_or_else(|| {
            //error!("io error [None]");
            std::io::Error::from_raw_os_error(error)
        })
    }
}

impl<T, E: Display> OrIoError<T> for Result<T, E> {
    fn or_invalid(self) -> std::io::Result<T> {
        self.map_err(|e| {
            error!("invalid error {e}");
            //std::io::ErrorKind::InvalidData.into()
            std::io::Error::from_raw_os_error(libc::EINVAL)
        })
    }
    fn or_io_error(self, error: i32) -> std::io::Result<T> {
        self.map_err(|e| {
            error!("io error {e}");
            //std::io::ErrorKind::InvalidData.into()
            std::io::Error::from_raw_os_error(error)
        })
    }
}

/// Converts results to libc errors.
pub trait ErrorMapper<T> {
    /// Converts to an invalid libc error.
    fn or_libc_invalid(self) -> Result<T, i32>;
    /// Converts to a specified libc error.
    fn or_libc_error(self, error: i32) -> Result<T, i32>;
}

/// Converts IO errors to libc errors.
pub trait IoErrorToLib<T> {
    /// Converts an IO error to a libc error.
    fn libc_err(self) -> Result<T, i32>;
}

impl<T> IoErrorToLib<T> for std::io::Result<T> {
    fn libc_err(self) -> Result<T, i32> {
        self.map_err(|e| match e.raw_os_error().unwrap_or(libc::EINVAL) {
            2 => 2,
            libc::ENODATA => libc::ENODATA,
            value => {
                log::error!("os error {e} {value}");
                value
            }
        })
    }
}

impl<T, E: Display> ErrorMapper<T> for Result<T, E> {
    fn or_libc_invalid(self) -> Result<T, i32> {
        self.map_err(|e| {
            log::error!("or invalid error {e}");
            libc::EINVAL
        })
    }
    fn or_libc_error(self, error: i32) -> Result<T, i32> {
        self.map_err(|e| {
            log::error!("or libc error {e}");
            error
        })
    }
}

impl<T> ErrorMapper<T> for Option<T> {
    fn or_libc_invalid(self) -> Result<T, i32> {
        self.ok_or(libc::EINVAL)
    }
    fn or_libc_error(self, error: i32) -> Result<T, i32> {
        self.ok_or(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{AsyncFileHandle, ReadAt};

    struct ShortReader(&'static [u8]);

    impl ReadAt for ShortReader {
        fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let Ok(pos) = usize::try_from(pos) else {
                return Ok(0);
            };
            let Some(source) = self.0.get(pos..) else {
                return Ok(0);
            };
            let len = source.len().min(buf.len()).min(2);
            buf[..len].copy_from_slice(&source[..len]);
            Ok(len)
        }
    }

    #[test]
    fn async_file_handle_is_dyn_compatible() {
        fn accept_dyn_handle(_: Option<&dyn AsyncFileHandle>) {}

        accept_dyn_handle(None);
    }

    #[test]
    fn read_all_at_retries_short_reads() {
        let reader = ShortReader(b"abcdef");
        let mut buffer = [0; 5];

        let bytes_read = reader.read_all_at(1, &mut buffer).unwrap();

        assert_eq!(bytes_read, buffer.len());
        assert_eq!(&buffer, b"bcdef");
    }

    #[test]
    fn read_exact_at_reports_unexpected_eof_after_short_reads() {
        let reader = ShortReader(b"abc");
        let mut buffer = [0; 4];

        let error = reader.read_exact_at(0, &mut buffer).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
