use crate::{core::XattrLayout, impl_dyn_handler_target};

use super::{
    CleartextFile, CryptFsFile, EncryptionLayout, EntryStorage, FileHandle, FileOpenOptions,
    FileSystem, FsDirEntry, Handler, HandlerTarget, Metadata, Permissions, ReadOnlyFileSystem,
    VirtualPath,
};

use std::sync::Arc;

/// Describes how opened cipher files should be wrapped with read or write caching.
pub trait FileBufferingPolicy: Send + Sync + 'static {
    fn cache_write(&self) -> bool;
    fn cache_read(&self) -> bool;
}

impl_dyn_handler_target!(FileBufferingPolicy);

/// Enables buffering for selected file access patterns.
#[derive(Clone, Copy, Default)]
pub struct FileBuffering {
    cache_write: bool,
    cache_read: bool,
}

impl FileBuffering {
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

impl FileBufferingPolicy for FileBuffering {
    fn cache_write(&self) -> bool {
        self.cache_write
    }
    fn cache_read(&self) -> bool {
        self.cache_read
    }
}

/// Disables all extra buffering around opened encrypted files.
#[derive(Clone, Copy, Default)]
pub struct NoBuffering;
impl FileBufferingPolicy for NoBuffering {
    fn cache_write(&self) -> bool {
        false
    }
    fn cache_read(&self) -> bool {
        false
    }
}

/// Exposes an encrypted layout through the public filesystem traits.
#[derive(Clone)]
pub struct CleartextFileSystem<T> {
    fs: Arc<T>,
    cache_policy: Arc<dyn FileBufferingPolicy>,
}

impl<T> From<(T, Handler<dyn FileBufferingPolicy>)> for CleartextFileSystem<T> {
    fn from(value: (T, Handler<dyn FileBufferingPolicy>)) -> Self {
        Self {
            fs: Arc::from(value.0),
            cache_policy: Arc::from(value.1.into_repr()),
        }
    }
}

impl<T, U: FileBufferingPolicy> From<(T, U)> for CleartextFileSystem<T> {
    fn from(value: (T, U)) -> Self {
        Self {
            fs: Arc::from(value.0),
            cache_policy: Arc::from(value.1),
        }
    }
}

/// Concrete cleartext file produced by an encryption layout.
type OpenCleartextFile<T> = CleartextFile<
    CryptFsFile<T, <<T as EncryptionLayout>::EntryStorage as EntryStorage>::OpenHandle>,
>;

/// Opens an encrypted file and wraps it with the requested cache policy.
fn try_open_crypt_file<T>(
    path: &VirtualPath,
    backend: Arc<T>,
    options: FileOpenOptions,
    cache_policy: &dyn FileBufferingPolicy,
) -> std::io::Result<OpenCleartextFile<T>>
where
    T: EncryptionLayout + Send + Sync + 'static,
{
    let readonly = options.is_readonly();
    let cipher_file = backend.open_file_with(path, options)?;
    let crypt_file = CryptFsFile::try_from_file(cipher_file, backend, readonly)?;

    Ok(CleartextFile::new(
        crypt_file,
        T::PLAIN_BLOCK_LEN as usize,
        cache_policy.cache_write(),
    ))
}

impl<T, F> ReadOnlyFileSystem<F> for CleartextFileSystem<T>
where
    T: EncryptionLayout + XattrLayout + Send + Sync + 'static,
    F: FileHandle + HandlerTarget + ?Sized,
    Handler<F>: From<Handler<OpenCleartextFile<T>>>,
{
    fn open_readonly(&self, path: &VirtualPath) -> std::io::Result<Handler<F>> {
        let mut options = FileOpenOptions::default();
        options.read(true);
        try_open_crypt_file(path, self.fs.clone(), options, self.cache_policy.as_ref())
            .map(|file| Handler::new(file).into())
    }
    fn metadata(&self, path: &VirtualPath) -> std::io::Result<Metadata> {
        self.fs.metadata(path)
    }
    fn read_dir(
        &self,
        path: &VirtualPath,
    ) -> std::io::Result<Handler<dyn Iterator<Item = std::io::Result<FsDirEntry>> + '_>> {
        let it = self
            .fs
            .list_dir_plain_names(path)?
            .map(|it| it.map(|r| r.0));
        Ok(Handler::new(it).into())
    }
    fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<String> {
        self.fs.read_symlink(path)
    }
    fn get_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<Vec<u8>> {
        self.fs.get_xattr(path, name)
    }
    fn list_xattr(&self, path: &VirtualPath) -> std::io::Result<Vec<String>> {
        self.fs.list_xattr(path)
    }
}

impl<T, F> FileSystem<F> for CleartextFileSystem<T>
where
    T: EncryptionLayout + XattrLayout + Send + Sync + 'static,
    F: FileHandle + HandlerTarget + ?Sized,
    Handler<F>: From<Handler<OpenCleartextFile<T>>>,
{
    /// Opens a file with the specified options.
    fn open_file_with(
        &self,
        path: &VirtualPath,
        options: FileOpenOptions,
    ) -> std::io::Result<Handler<F>> {
        try_open_crypt_file(path, self.fs.clone(), options, self.cache_policy.as_ref())
            .map(|file| Handler::new(file).into())
    }
    /// Creates a new directory with given permissions.
    fn mkdir(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        self.fs.mkdir(path, permissions)
    }
    fn mknode(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        self.fs.mknode(path, permissions)
    }
    fn remove(&self, path: &VirtualPath) -> std::io::Result<()> {
        self.fs.remove(path)
    }
    fn remove_dir(&self, path: &VirtualPath) -> std::io::Result<()> {
        if path.is_empty() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY));
        }
        self.fs.remove_dir(path)
    }
    fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()> {
        self.fs.rename(old_path, new_path)
    }
    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        self.fs.set_permissions(path, permissions)
    }
    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> std::io::Result<()> {
        self.fs.set_time(path, atime, mtime)
    }
    fn chown(&self, path: &VirtualPath, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
        self.fs.chown(path, uid, gid)
    }
    fn create_symlink(&self, path: &VirtualPath, target_path: &str) -> std::io::Result<Metadata> {
        self.fs.create_symlink(path, target_path)
    }

    fn remove_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<()> {
        self.fs.remove_xattr(path, name)
    }
    fn set_xattr(&self, path: &VirtualPath, name: &str, value: &[u8]) -> std::io::Result<()> {
        self.fs.set_xattr(path, name, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CryptoMator, CryptomatorBackend,
        core::{DynamicFileSystem, EncryptionTranslator, ReadAt, Size, Utf8Path, WriteAt},
    };

    #[test]
    fn concrete_and_dynamic_handles_preserve_buffering_modes() {
        type Backend = CryptoMator<CryptomatorBackend>;

        let root = tempfile::tempdir().unwrap();
        let root_path = Utf8Path::from_path(root.path()).unwrap();
        Backend::init_with_default_params(root_path, "password").unwrap();

        for cache_write in [false, true] {
            let backend = Backend::try_new(root_path, "password").unwrap();
            let policy = if cache_write {
                FileBuffering::default().with_cache_write()
            } else {
                FileBuffering::default()
            };
            let fs: CleartextFileSystem<Backend> = (backend, policy).into();
            let path = VirtualPath::new(if cache_write { "buffered" } else { "direct" });
            let mut options = FileOpenOptions::default();
            options.read(true).write(true).create(true);

            let file: Handler<OpenCleartextFile<Backend>> =
                fs.open_file_with(path, options.clone()).unwrap();
            file.write_all_at(0, b"abcdef").unwrap();
            assert_eq!(file.size().unwrap(), 6);
            let mut data = [0; 6];
            file.read_exact_at(0, &mut data).unwrap();
            assert_eq!(&data, b"abcdef");

            let mut readonly = FileOpenOptions::default();
            readonly.read(true);
            let cipher_file = fs.fs.open_file_with(path, readonly).unwrap();
            assert_eq!(
                cipher_file.size().unwrap() == Backend::HEADER_LEN as u64,
                cache_write
            );
            file.flush().unwrap();

            let file: Handler<OpenCleartextFile<Backend>> = fs.open_readonly(path).unwrap();
            file.read_exact_at(0, &mut data).unwrap();
            assert_eq!(&data, b"abcdef");

            let fs: Box<DynamicFileSystem> = Box::new(fs);
            let file = fs.open_file_with(path, options).unwrap();
            file.write_all_at(2, b"XY").unwrap();
            file.set_len(5).unwrap();
            file.sync(false).unwrap();
            assert_eq!(file.size().unwrap(), 5);
            let mut data = [0; 5];
            fs.open_readonly(path)
                .unwrap()
                .read_exact_at(0, &mut data)
                .unwrap();
            assert_eq!(&data, b"abXYe");
            assert_eq!(fs.metadata(path).unwrap().len, 5);
        }
    }
}
