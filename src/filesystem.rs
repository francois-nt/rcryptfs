use crate::{
    BufferedFile, CryptFsFile, EncryptionTranslator, FileSystem, FileType, FsBackend, FsDirEntry,
    GenericOpenOptions, GoCryptFs, Metadata, OrIoError, PathTranslator, Permissions,
    ReadOnlyFileSystem, ReadWrite, Result, Utf8Path, WriteAt, XattrTranslator,
};
use filetime::set_symlink_file_times;
use log::{debug, error};
use std::sync::Arc;

pub trait FileCachePolicy: Send + Sync + 'static + Copy {
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

pub struct EncryptedFileTranslator<T, C: FileCachePolicy> {
    fs: Arc<T>,
    cache_policy: C,
}

impl<T, C: FileCachePolicy> From<(T, C)> for EncryptedFileTranslator<T, C> {
    fn from(value: (T, C)) -> Self {
        Self {
            fs: Arc::from(value.0),
            cache_policy: value.1,
        }
    }
}

impl<T, C: FileCachePolicy> Clone for EncryptedFileTranslator<T, C> {
    fn clone(&self) -> Self {
        Self {
            fs: self.fs.clone(),
            cache_policy: self.cache_policy,
        }
    }
}

/// Opens an encrypted file and wraps it with the requested cache policy.
fn try_open_crypt_file<T, C: FileCachePolicy>(
    path: &Utf8Path,
    backend: Arc<T>,
    options: GenericOpenOptions,
    cache_policy: C,
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

impl<T, C: FileCachePolicy> ReadOnlyFileSystem for EncryptedFileTranslator<T, C>
where
    T: EncryptionTranslator + PathTranslator + XattrTranslator + Send + Sync + 'static,
{
    fn open_readonly(&self, path: &str) -> std::io::Result<Box<dyn ReadWrite>> {
        let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        let mut options = GenericOpenOptions::default();
        options.read(true);
        try_open_crypt_file(&cipher_path, self.fs.clone(), options, self.cache_policy)
    }
    fn metadata(&self, path: &str) -> std::io::Result<Metadata> {
        let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        let mut res: Metadata = std::fs::symlink_metadata(cipher_path)?.into();
        if res.file_type == FileType::File {
            res.len = self.fs.cipher_size_to_plain(res.len).or_invalid()?;
        }
        Ok(res)
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
        let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        let cipher_target = std::fs::read_link(cipher_path)?;
        let cipher_target = cipher_target.to_str().or_invalid()?;
        let plain_value = self
            .fs
            .cipher_metavalue_to_plain(cipher_target)
            .or_invalid()?;

        String::from_utf8(plain_value).or_invalid()
    }
    fn get_xattr(&self, path: &str, name: &str) -> std::io::Result<Vec<u8>> {
        #[cfg(windows)]
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
        #[cfg(windows)]
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

/// Creates a directory with an initialization vector file.
fn create_diriv(
    path: impl AsRef<Utf8Path>,
    diriv_path: impl AsRef<Utf8Path>,
    iv: &[u8],
) -> std::io::Result<()> {
    // Temporary paths are owned exclusively by the current process. Reusing the
    // same backend concurrently from multiple rcryptfs processes is undefined behavior.
    if std::fs::exists(path.as_ref())? {
        std::fs::remove_dir_all(path.as_ref())?;
    }
    std::fs::create_dir(path.as_ref())?;

    let file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(diriv_path.as_ref())?;

    file.write_all_at(0, iv)
}

impl<T, C: FileCachePolicy> FileSystem for EncryptedFileTranslator<T, C>
where
    T: EncryptionTranslator + PathTranslator + XattrTranslator + Send + Sync + 'static,
{
    /// Opens a file with the specified options.
    fn open_file_with(
        &self,
        path: &str,
        options: GenericOpenOptions,
    ) -> std::io::Result<Box<dyn ReadWrite>> {
        let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        try_open_crypt_file(&cipher_path, self.fs.clone(), options, self.cache_policy)
    }
    /// Creates a new directory with given permissions.
    fn mkdir(&self, path: &str, permissions: Permissions) -> std::io::Result<Metadata> {
        let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        let temp_path = self.fs.create_temp_name(cipher_path.as_str(), false);
        let dir_iv_path = self.fs.get_dir_iv_file(&temp_path);

        let iv = self.fs.generate_diriv();

        // Create into a temporary location first so the directory and diriv appear atomically.
        create_diriv(&temp_path, &dir_iv_path, &iv)?;
        std::fs::rename(&temp_path, &cipher_path)?;
        self.set_permissions(path, permissions)
    }
    fn mknode(&self, path: &str, permissions: Permissions) -> std::io::Result<Metadata> {
        let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        std::fs::File::create_new(&cipher_path)?;
        self.set_permissions(path, permissions)
    }
    fn remove(&self, path: &str) -> std::io::Result<()> {
        let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        std::fs::remove_file(cipher_path)
    }
    fn remove_dir(&self, path: &str) -> std::io::Result<()> {
        let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        let iv_path = self.fs.get_dir_iv_file(&cipher_path);
        let temp_path = self.fs.create_temp_name(iv_path.as_str(), true);

        // Move the diriv out of the way first so a failed rmdir can be rolled back cleanly.
        std::fs::rename(&iv_path, &temp_path)
            .inspect_err(|e| error!("cant rename {iv_path} to {temp_path} - {e}"))?;
        if let Err(e) = std::fs::remove_dir(&cipher_path) {
            debug!("rmdir error {e} {:?}", e.raw_os_error());
            std::fs::rename(&temp_path, &iv_path)
                .inspect_err(|e| error!("cant rename back {temp_path} to {iv_path} - {e}"))?;
            Err(e)
        } else {
            let _ = std::fs::remove_file(&temp_path);
            self.fs.remove_cached_plain_path(path);
            Ok(())
        }
    }
    fn rename(&self, old_path: &str, new_path: &str) -> std::io::Result<()> {
        let old_cipher_path = self.fs.plain_path_to_cipher(old_path.into()).or_invalid()?;
        let new_cipher_path = self.fs.plain_path_to_cipher(new_path.into()).or_invalid()?;
        std::fs::rename(&old_cipher_path, &new_cipher_path)?;
        self.fs.remove_cached_plain_path(old_path);
        self.fs.remove_cached_plain_path(new_path);
        Ok(())
    }
    fn set_permissions(&self, path: &str, permissions: Permissions) -> std::io::Result<Metadata> {
        debug!("set permissions on {path} {permissions}");
        let path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        debug!("cipher_path is {path}");
        let metadata = std::fs::symlink_metadata(&path)?;
        debug!("metadata {:?}", metadata);
        let mut file_permissions = metadata.permissions();
        let new_mode: u16 = permissions.into();

        #[cfg(not(unix))]
        file_permissions.set_readonly(file_permissions.readonly());
        #[cfg(unix)]
        std::os::unix::fs::PermissionsExt::set_mode(&mut file_permissions, new_mode as u32);

        debug!("setting permissions {:?}", file_permissions);
        std::fs::set_permissions(&path, file_permissions)?;
        debug!("trying to convert metadata");
        let mut metadata: Metadata = metadata.into();
        metadata.permissions = new_mode.into();
        debug!("metadata are {metadata}");
        Ok(metadata)
    }
    fn set_time(
        &self,
        path: &str,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> std::io::Result<()> {
        let path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        if atime.is_none() && mtime.is_none() {
            return Ok(());
        }
        if let Some((atime, mtime)) = atime.zip(mtime) {
            set_symlink_file_times(path, atime.into(), mtime.into())
        } else {
            let meta = std::fs::symlink_metadata(&path)?;
            let atime = atime.unwrap_or_else(|| meta.accessed().unwrap_or(std::time::UNIX_EPOCH));
            let mtime = mtime.unwrap_or_else(|| meta.modified().unwrap_or(std::time::UNIX_EPOCH));
            set_symlink_file_times(path, atime.into(), mtime.into())
        }
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
        #[cfg(windows)]
        {
            let _ = (path, uid, gid);
            Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
        }
    }
    fn create_symlink(&self, path: &str, target_path: &str) -> std::io::Result<Metadata> {
        let cipher_path = self.fs.plain_path_to_cipher(path.into()).or_invalid()?;
        let cipher_target = self
            .fs
            .plain_metavalue_to_cipher(target_path.as_bytes())
            .or_invalid()?;

        #[cfg(unix)]
        std::os::unix::fs::symlink(cipher_target, &cipher_path)?;
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(cipher_target, &cipher_path)?;

        let metadata: Metadata = std::fs::symlink_metadata(cipher_path)?.into();
        Ok(metadata)
    }

    fn remove_xattr(&self, path: &str, name: &str) -> std::io::Result<()> {
        #[cfg(windows)]
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
        #[cfg(windows)]
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

pub trait FileSystemBuilder {
    fn build<Cache: FileCachePolicy>(
        root_path: &Utf8Path,
        password: &str,
        cache_policy: Cache,
    ) -> Result<Box<dyn FileSystem>>;
}

pub struct FileSystemFactory;

impl FileSystemBuilder for FileSystemFactory {
    fn build<Cache: FileCachePolicy>(
        root_path: &Utf8Path,
        password: &str,
        cache_policy: Cache,
    ) -> Result<Box<dyn FileSystem>> {
        let cryptfs: EncryptedFileTranslator<GoCryptFs<FsBackend>, _> = (
            GoCryptFs::<FsBackend>::try_new(root_path, password)?,
            cache_policy,
        )
            .into();
        Ok(Box::new(cryptfs))
    }
}
