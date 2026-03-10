use crate::{FsDirEntry, GenericOpenOptions, Metadata, Permissions, Result, UnsafeCache};
pub use camino::{Utf8Path, Utf8PathBuf};
use log::error;
use std::{fmt::Display, time::SystemTime};

/// Marker trait for backend implementations.
pub trait Backend {}

/// Trait for encryption and decryption operations.
pub trait EncryptionTranslator {
    const CIPHER_BLOCK_LEN: u64;
    const PLAIN_BLOCK_LEN: u64;
    const HEADER_LEN: usize;
    /// Decrypts a cipher filename to plain text.
    fn cipher_name_to_plain(&self, parent_iv: &[u8], cipher_name: &str) -> Result<String>;
    /// Encrypts a plain filename to cipher text.
    fn plain_name_to_cipher(&self, parent_iv: &[u8], plain_name: &str) -> Result<String>;

    /// Converts plain file size to cipher file size.
    fn plain_size_to_cipher(&self, plain_size: u64) -> u64;
    /// Converts cipher file size to plain file size.
    fn cipher_size_to_plain(&self, cipher_size: u64) -> Result<u64>;

    /// Generates a cipher header for the file.
    fn generate_cipher_header(&self) -> Vec<u8>;
    /// Generates a random initialization vector for directories.
    fn generate_diriv(&self) -> [u8; 16];

    /// Decrypts a cipher block to plain data.
    fn cipher_block_to_plain(
        &self,
        header: &[u8],
        block_no: u64,
        cipher_data: &[u8],
    ) -> Result<Vec<u8>>;
    /// Encrypts a plain block to cipher data.
    fn plain_block_to_cipher(
        &self,
        header: &[u8],
        block_no: u64,
        plain_data: &[u8],
    ) -> Result<Vec<u8>>;

    /// Encrypts a plain metavalue (e.g., symlink target) to cipher string.
    fn plain_metavalue_to_cipher(&self, plain_metavalue: &[u8]) -> Result<String>;
    /// Decrypts a cipher metavalue to plain bytes.
    fn cipher_metavalue_to_plain(&self, cipher_metavalue: &str) -> Result<Vec<u8>>;
}

/// Trait for extended attribute name and value translation.
pub trait XattrTranslator: EncryptionTranslator {
    /// Converts a plain extended attribute name to cipher text.
    fn plain_xattr_name_to_cipher(&self, plain_xattr_name: &str) -> Result<String>;
    /// Converts a cipher extended attribute name to plain text.
    fn cipher_xattr_name_to_plain(&self, cipher_xattr_name: &str) -> Result<String>;
    /// Encrypts a plain extended attribute value.
    fn plain_xattr_value_to_cipher(&self, plain_xattr_value: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts a cipher extended attribute value.
    fn cipher_xattr_value_to_plain(&self, cipher_xattr_value: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for path translation between plain and cipher.
pub trait PathTranslator: EncryptionTranslator {
    /// Creates a temporary name for a given path.
    fn create_temp_name(&self, path: &str, is_dir_iv: bool) -> Utf8PathBuf;
    /// Converts a cipher path to its plain text equivalent.
    fn cipher_path_to_plain(&self, cipher_path: &Utf8Path) -> Result<Utf8PathBuf>;
    /// Converts a plain path to its cipher text equivalent.
    fn plain_path_to_cipher(&self, plain_path: &Utf8Path) -> Result<Utf8PathBuf>;
    /// Lists directory entries with plain names.
    fn list_dir_plain_names(
        &self,
        plain_path: &Utf8Path,
    ) -> Result<impl Iterator<Item = Result<(FsDirEntry, Utf8PathBuf)>> + '_>;

    /// Invalidates one cached plain path and its cached descendants.
    fn remove_cached_plain_path(&self, plain_path: &str);

    /// Returns the path of the per-directory IV file for a cipher directory.
    fn get_dir_iv_file(&self, cipher_folder_path: &Utf8Path) -> Utf8PathBuf;
}

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

/// Returns the logical size of a file-like object when available.
pub trait Size {
    fn size(&self) -> std::io::Result<Option<u64>>;
}

impl Size for std::fs::File {
    fn size(&self) -> std::io::Result<Option<u64>> {
        let md = self.metadata()?;
        if md.is_file() {
            Ok(Some(md.len()))
        } else {
            Ok(None)
        }
    }
}

impl ReadAt for std::fs::File {
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        return std::os::unix::fs::FileExt::read_at(self, buf, pos);
        #[cfg(windows)]
        return std::os::windows::fs::FileExt::seek_read(self, buf, pos);
    }
}

impl WriteAt for std::fs::File {
    fn write_at(&self, pos: u64, buf: &[u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        return std::os::unix::fs::FileExt::write_at(self, buf, pos);
        #[cfg(windows)]
        return std::os::windows::fs::FileExt::seek_write(self, buf, pos);
    }
}

impl SetLen for std::fs::File {
    fn set_len(&self, new_size: u64) -> std::io::Result<()> {
        std::fs::File::set_len(self, new_size)
    }
}
impl SetSync for std::fs::File {
    fn sync(&self, datasync: bool) -> std::io::Result<()> {
        if datasync {
            std::fs::File::sync_data(self)
        } else {
            std::fs::File::sync_all(self)
        }
    }
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
pub trait Read: ReadAt + Send + Sync {}
/// Marker trait for read-write operations.
pub trait ReadWrite: Read + WriteAt + SetLen + SetSync {}

impl<T> Read for T where T: ReadAt + Send + Sync {}

impl<T> ReadWrite for T where T: ReadAt + WriteAt + SetLen + SetSync + Send + Sync {}

/// Trait for caching open files.
pub trait OpenCache: Default {
    /// Inserts a file into the cache and returns an unique fileId.
    fn insert(&self, file: Box<dyn ReadWrite>) -> u64;

    /// Releases a file from the cache.
    fn release(&self, id: u64) -> std::io::Result<()>;

    /// Accesses a file in the cache.
    fn access<U, F: FnOnce(&dyn ReadWrite) -> std::io::Result<U>>(
        &self,
        id: u64,
        handler: F,
    ) -> std::io::Result<U>;
}

/// Trait for read-only filesystem operations.
pub trait ReadOnlyFileSystem: Send + Sync + 'static {
    /// Opens a file in read-only mode.
    fn open_readonly(&self, path: &str) -> std::io::Result<Box<dyn ReadWrite>>;
    /// Lists directory entries.
    fn read_dir(&self, path: &str) -> std::io::Result<Box<dyn Iterator<Item = FsDirEntry> + '_>>;
    /// Retrieves metadata for a path.
    fn metadata(&self, path: &str) -> std::io::Result<Metadata>;
    /// Checks if a path exists.
    fn exists(&self, path: &str) -> std::io::Result<bool> {
        self.metadata(path).map(|_| true)
    }
    /// Reads the target of a symbolic link.
    fn read_symlink(&self, path: &str) -> std::io::Result<String>;
    /// Lists extended attribute names.
    fn list_xattr(&self, path: &str) -> std::io::Result<Box<dyn Iterator<Item = String> + '_>>;
    /// Gets an extended attribute value.
    fn get_xattr(&self, path: &str, name: &str) -> std::io::Result<Vec<u8>>;
}

//pub trait GenericFileSystem: FileSystem<File = Box<dyn ReadWrite>> {}
//impl<T: FileSystem<File = Box<dyn ReadWrite>>> GenericFileSystem for T {}

/// Trait for full filesystem operations.
pub trait FileSystem: ReadOnlyFileSystem {
    /// Opens a file with specified options.
    fn open_file_with(
        &self,
        path: &str,
        options: GenericOpenOptions,
    ) -> std::io::Result<Box<dyn ReadWrite>>;
    /// Truncates a file to a new size.
    fn truncate(&self, path: &str, new_size: u64) -> std::io::Result<()>;
    /// Renames a file or directory.
    fn rename(&self, old_path: &str, new_path: &str) -> std::io::Result<()>;
    /// Removes a file.
    fn remove(&self, path: &str) -> std::io::Result<()>;
    /// Removes a directory.
    fn remove_dir(&self, path: &str) -> std::io::Result<()>;
    /// Creates a new directory with permissions.
    fn mkdir(&self, path: &str, permissions: Permissions) -> std::io::Result<Metadata>;
    /// Creates a new node (file) with permissions.
    fn mknode(&self, path: &str, permissions: Permissions) -> std::io::Result<Metadata>;
    /// Sets permissions on a path.
    fn set_permissions(&self, path: &str, permissions: Permissions) -> std::io::Result<Metadata>;
    /// Sets access and modification times.
    fn set_time(
        &self,
        path: &str,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()>;
    /// Creates a symbolic link.
    fn create_symlink(&self, path: &str, target_path: &str) -> std::io::Result<Metadata>;
    /// Changes ownership of a path.
    fn chown(&self, path: &str, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()>;

    /// Sets an extended attribute.
    fn set_xattr(&self, path: &str, name: &str, value: &[u8]) -> std::io::Result<()>;
    /// Removes an extended attribute.
    fn remove_xattr(&self, path: &str, name: &str) -> std::io::Result<()>;
}

/// Wrapper for filesystem with caching.
pub struct FileSystemHandler<C: OpenCache = UnsafeCache>(Box<dyn FileSystem>, C);

impl<C: OpenCache> FileSystemHandler<C> {
    pub fn as_cache(&self) -> &C {
        &self.1
    }
}

impl<T: FileSystem, C: OpenCache> From<T> for FileSystemHandler<C> {
    fn from(value: T) -> Self {
        Self(Box::new(value), C::default())
    }
}

impl<C: OpenCache> From<Box<dyn FileSystem>> for FileSystemHandler<C> {
    fn from(value: Box<dyn FileSystem>) -> Self {
        Self(value, C::default())
    }
}

impl<C: OpenCache> AsRef<dyn FileSystem> for FileSystemHandler<C> {
    fn as_ref(&self) -> &dyn FileSystem {
        self.0.as_ref()
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
