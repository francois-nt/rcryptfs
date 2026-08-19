use crate::core::XattrLayout;

use super::{
    BufferedFile, CryptFsFile, EncryptionLayout, EncryptionTranslator, FileSystem, FsDirEntry,
    GenericOpenOptions, Metadata, MinimalFs, OrIoError, Permissions, ReadOnlyFileSystem, ReadWrite,
    Utf8Path,
};

use std::sync::Arc;

/// Describes how opened cipher files should be wrapped with read or write caching.
pub trait FileCachePolicy: Send + Sync + 'static {
    fn cache_write(&self) -> bool;
    fn cache_read(&self) -> bool;
}

/// Enables buffering for selected file access patterns.
#[derive(Clone, Copy, Default)]
pub struct FileCache {
    cache_write: bool,
    cache_read: bool,
}

impl FileCache {
    /// Returns a policy that buffers writes.
    pub fn with_cache_write(self) -> Self {
        Self {
            cache_write: true,
            cache_read: self.cache_read,
        }
    }
    /// Returns a policy that buffers reads.
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

/// Disables all extra buffering around opened encrypted files.
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

/// Adapts a backend layout and translator into the FileSystem traits.
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
    mut options: GenericOpenOptions,
    cache_policy: &dyn FileCachePolicy,
) -> std::io::Result<Box<dyn ReadWrite>>
where
    T: EncryptionTranslator + EncryptionLayout + Send + Sync + 'static,
{
    if options.append {
        options.write = true;
    }
    let readonly = options.is_readonly();
    options.read(true).append(false);
    let cipher_file = backend.lower_fs().open_file_with(path, options)?;
    let crypt_file = CryptFsFile::try_from_file(cipher_file, backend, readonly)?;

    if cache_policy.cache_write() {
        Ok(Box::new(BufferedFile::new(
            crypt_file,
            T::PLAIN_BLOCK_LEN as usize,
        )))
    } else {
        Ok(Box::new(crypt_file))
    }
}

impl<T> ReadOnlyFileSystem for EncryptedFileTranslator<T>
where
    T: EncryptionTranslator + EncryptionLayout + XattrLayout + Send + Sync + 'static,
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
        self.fs.get_xattr(path, name)
    }
    fn list_xattr(&self, path: &str) -> std::io::Result<Vec<String>> {
        self.fs.list_xattr(path)
    }
}

impl<T> FileSystem for EncryptedFileTranslator<T>
where
    T: EncryptionTranslator + EncryptionLayout + XattrLayout + Send + Sync + 'static,
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
        let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        self.fs.lower_fs().chown(&cipher_path, uid, gid)
    }
    fn create_symlink(&self, path: &str, target_path: &str) -> std::io::Result<Metadata> {
        self.fs.create_symlink(path, target_path)
    }

    fn remove_xattr(&self, path: &str, name: &str) -> std::io::Result<()> {
        self.fs.remove_xattr(path, name)
    }
    fn set_xattr(&self, path: &str, name: &str, value: &[u8]) -> std::io::Result<()> {
        self.fs.set_xattr(path, name, value)
    }
}
