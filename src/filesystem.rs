use crate::{
    BufferedFile, CryptFsFile, EncryptionLayout, EncryptionTranslator, FileSystem, FsDirEntry,
    GenericOpenOptions, Metadata, OrIoError, Permissions, ReadOnlyFileSystem, ReadWrite, Utf8Path,
    XattrTranslator,
};

use std::sync::Arc;

pub trait FileCachePolicy: Send + Sync + 'static {
    fn cache_write(&self) -> bool;
    fn cache_read(&self) -> bool;
}

#[derive(Clone, Copy, Default)]
pub struct FileCache {
    cache_write: bool,
    cache_read: bool,
}

impl FileCache {
    pub fn with_cache_write(self) -> Self {
        Self {
            cache_write: true,
            cache_read: self.cache_read,
        }
    }
    pub fn with_cache_read(self) -> Self {
        Self {
            cache_write: self.cache_write,
            cache_read: true,
        }
    }
}

impl FileCachePolicy for FileCache {
    fn cache_write(&self) -> bool {
        self.cache_write
    }
    fn cache_read(&self) -> bool {
        self.cache_read
    }
}

#[derive(Clone, Copy, Default)]
pub struct NoCache;
impl FileCachePolicy for NoCache {
    fn cache_write(&self) -> bool {
        false
    }
    fn cache_read(&self) -> bool {
        false
    }
}

#[derive(Clone)]
pub struct EncryptedFileTranslator<T> {
    fs: Arc<T>,
    cache_policy: Arc<dyn FileCachePolicy>,
}

impl<T> From<(T, Box<dyn FileCachePolicy>)> for EncryptedFileTranslator<T> {
    fn from(value: (T, Box<dyn FileCachePolicy>)) -> Self {
        Self {
            fs: Arc::from(value.0),
            cache_policy: Arc::from(value.1),
        }
    }
}

/// Opens an encrypted file and wraps it with the requested cache policy.
fn try_open_crypt_file<T>(
    path: &Utf8Path,
    backend: Arc<T>,
    options: GenericOpenOptions,
    cache_policy: &dyn FileCachePolicy,
) -> std::io::Result<Box<dyn ReadWrite>>
where
    T: EncryptionTranslator + Send + Sync + 'static,
{
    if cache_policy.cache_write() {
        Ok(Box::new(BufferedFile::from(CryptFsFile::<T>::try_open(
            path, backend, options,
        )?)))
    } else {
        Ok(Box::new(CryptFsFile::<T>::try_open(
            path, backend, options,
        )?))
    }
}

impl<T> ReadOnlyFileSystem for EncryptedFileTranslator<T>
where
    T: EncryptionTranslator + EncryptionLayout + XattrTranslator + Send + Sync + 'static,
{
    fn open_readonly(&self, path: &str) -> std::io::Result<Box<dyn ReadWrite>> {
        let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        let mut options = GenericOpenOptions::default();
        options.read(true);
        try_open_crypt_file(
            &cipher_path,
            self.fs.clone(),
            options,
            self.cache_policy.as_ref(),
        )
    }
    fn metadata(&self, path: &str) -> std::io::Result<Metadata> {
        self.fs.metadata(path)
    }
    fn read_dir(&self, path: &str) -> std::io::Result<Box<dyn Iterator<Item = FsDirEntry> + '_>> {
        let it = self
            .fs
            .list_dir_plain_names(path.into())
            .or_invalid()?
            .filter_map(|it| Some(it.ok()?.0));
        Ok(Box::new(it))
    }
    fn read_symlink(&self, path: &str) -> std::io::Result<String> {
        self.fs.read_symlink(path)
    }
    fn get_xattr(&self, path: &str, name: &str) -> std::io::Result<Vec<u8>> {
        #[cfg(not(unix))]
        {
            let _ = (path, name);
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        #[cfg(unix)]
        {
            let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
            let cipher_name = self.fs.plain_xattr_name_to_cipher(name).or_invalid()?;

            let cipher_xattr_value =
                xattr::get(cipher_path, cipher_name)?.or_io_error(libc::ENODATA)?;
            self.fs
                .cipher_xattr_value_to_plain(&cipher_xattr_value)
                .or_invalid()
        }
    }
    fn list_xattr(&self, path: &str) -> std::io::Result<Box<dyn Iterator<Item = String> + '_>> {
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        #[cfg(unix)]
        {
            let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
            Ok(Box::new(xattr::list(cipher_path)?.flat_map(move |s| {
                s.to_str()
                    .and_then(|s| self.fs.cipher_xattr_name_to_plain(s).ok())
            })))
        }
    }
}

impl<T> FileSystem for EncryptedFileTranslator<T>
where
    T: EncryptionTranslator + EncryptionLayout + XattrTranslator + Send + Sync + 'static,
{
    /// Opens a file with the specified options.
    fn open_file_with(
        &self,
        path: &str,
        options: GenericOpenOptions,
    ) -> std::io::Result<Box<dyn ReadWrite>> {
        let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        try_open_crypt_file(
            &cipher_path,
            self.fs.clone(),
            options,
            self.cache_policy.as_ref(),
        )
    }
    /// Creates a new directory with given permissions.
    fn mkdir(&self, path: &str, permissions: Permissions) -> std::io::Result<Metadata> {
        self.fs.mkdir(path, permissions)
    }
    fn mknode(&self, path: &str, permissions: Permissions) -> std::io::Result<Metadata> {
        self.fs.mknode(path, permissions)
    }
    fn remove(&self, path: &str) -> std::io::Result<()> {
        self.fs.remove(path)
    }
    fn remove_dir(&self, path: &str) -> std::io::Result<()> {
        if path.is_empty() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY));
        }
        self.fs.remove_dir(path)
    }
    fn rename(&self, old_path: &str, new_path: &str) -> std::io::Result<()> {
        self.fs.rename(old_path, new_path)
    }
    fn set_permissions(&self, path: &str, permissions: Permissions) -> std::io::Result<Metadata> {
        self.fs.set_permissions(path, permissions)
    }
    fn set_time(
        &self,
        path: &str,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> std::io::Result<()> {
        self.fs.set_time(path, atime, mtime)
    }
    fn truncate(&self, path: &str, new_size: u64) -> std::io::Result<()> {
        let mut options = GenericOpenOptions::default();
        options.read(true).write(true).append(false);
        let file = self.open_file_with(path, options)?;
        file.set_len(new_size)?;
        file.flush()?;

        Ok(())
    }
    fn chown(&self, path: &str, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
            std::os::unix::fs::chown(cipher_path, uid, gid)
        }
        #[cfg(not(unix))]
        {
            let _ = (path, uid, gid);
            Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
        }
    }
    fn create_symlink(&self, path: &str, target_path: &str) -> std::io::Result<Metadata> {
        self.fs.create_symlink(path, target_path)
    }

    fn remove_xattr(&self, path: &str, name: &str) -> std::io::Result<()> {
        #[cfg(not(unix))]
        {
            let _ = (path, name);
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        #[cfg(unix)]
        {
            let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
            let cipher_name = self.fs.plain_xattr_name_to_cipher(name).or_invalid()?;

            xattr::remove(cipher_path, cipher_name)
        }
    }
    fn set_xattr(&self, path: &str, name: &str, value: &[u8]) -> std::io::Result<()> {
        #[cfg(not(unix))]
        {
            let _ = (path, name, value);
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        #[cfg(unix)]
        {
            let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
            let cipher_name = self.fs.plain_xattr_name_to_cipher(name).or_invalid()?;
            let cipher_xattr_value = self.fs.plain_xattr_value_to_cipher(value).or_invalid()?;
            xattr::set(cipher_path, cipher_name, &cipher_xattr_value)
        }
    }
}
