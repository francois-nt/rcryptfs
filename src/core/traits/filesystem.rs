use super::super::{
    FileOpenOptions, FileType, FsDirEntry, Metadata, Permissions, Result, UnsafeOpenFileTable,
    VirtualPath,
};
pub use camino::{Utf8Path, Utf8PathBuf};
use log::error;
use std::{fmt::Display, time::SystemTime};

/// Provides positioned reads without changing a shared file cursor.
pub trait ReadAt {
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Reads exactly `buf.len()` bytes unless EOF is reached first.
    fn read_exact_at(&self, mut pos: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            match self.read_at(pos, buf) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    pos += n as u64;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if !buf.is_empty() {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ))
        } else {
            Ok(())
        }
    }
}

/// Returns the logical size of a file-like object.
pub trait Size {
    fn size(&self) -> std::io::Result<u64>;
}

/// Provides access to a file's modification time.
pub trait ModifiedTime {
    fn get_modified(&self) -> std::io::Result<SystemTime>;
    fn set_modified_time(&self, modified_time: SystemTime) -> std::io::Result<()>;
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

/// Trait for synchronization operations.
pub trait SetSync {
    /// Synchronizes data to disk.
    fn sync(&self, datasync: bool) -> std::io::Result<()>;
}
/// Trait for setting file length.
pub trait SetLen {
    /// Sets the length of the file.
    fn set_len(&self, new_size: u64) -> std::io::Result<()>;
}

/// Marker trait for read operations.
pub trait ReadHandle: ReadAt + Send + Sync {}
/// Provides the complete set of operations supported by an open file.
pub trait FileHandle:
    ReadHandle + WriteAt + SetLen + SetSync + Size + ModifiedTime + 'static
{
}

impl<T> ReadHandle for T where T: ReadAt + Send + Sync {}

impl<T> FileHandle for T where
    T: ReadHandle + WriteAt + SetLen + SetSync + Size + ModifiedTime + 'static
{
}

/// Maps stable identifiers to open file handles.
pub trait OpenFileTable: Default {
    /// Inserts a file and returns its unique handle identifier.
    fn insert(&self, file: Box<dyn FileHandle>) -> u64;

    /// Releases an open file handle.
    fn release(&self, id: u64) -> std::io::Result<()>;

    /// Accesses an open file handle.
    fn access<U, F: FnOnce(&dyn FileHandle) -> std::io::Result<U>>(
        &self,
        id: u64,
        handler: F,
    ) -> std::io::Result<U>;
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
        self.metadata(path).map(|_| true)
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
    fn truncate(&self, path: &VirtualPath, new_size: u64) -> std::io::Result<()>;
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
            let file_type = match entry.file_type {
                Some(file_type) => file_type,
                None => self.metadata(&child_path)?.file_type,
            };
            if file_type == FileType::Directory {
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
pub struct FileSystemHandler<C: OpenFileTable = UnsafeOpenFileTable> {
    fs: Box<dyn FileSystem>,
    open_files: C,
    is_background_child: bool,
}

impl<C: OpenFileTable> FileSystemHandler<C> {
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

impl<T: FileSystem, C: OpenFileTable> From<T> for FileSystemHandler<C> {
    fn from(value: T) -> Self {
        Self {
            fs: Box::new(value),
            open_files: C::default(),
            is_background_child: false,
        }
    }
}

impl<C: OpenFileTable> From<Box<dyn FileSystem>> for FileSystemHandler<C> {
    fn from(value: Box<dyn FileSystem>) -> Self {
        Self {
            fs: value,
            open_files: C::default(),
            is_background_child: false,
        }
    }
}

impl<C: OpenFileTable> AsRef<dyn FileSystem> for FileSystemHandler<C> {
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
