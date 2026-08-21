use super::super::FsCacheEntry;
use super::{
    FileHandle, FileType, FsDirEntry, GenericOpenOptions, Metadata, ModifiedTime, Permissions,
    ReadAt, Result, Size, VirtualPath, VirtualPathBuf, WriteAt,
};
use super::{
    default_create_symlink, default_metadata, default_mkdir, default_mknode, default_read_symlink,
    default_remove, default_remove_dir, default_rename, default_set_permissions, default_set_time,
};
use std::sync::Arc;
use std::{collections::BTreeMap, time::SystemTime};
/// Marker trait for backend implementations.
pub trait Backend {
    type LowerFs: MinimalFs;
    fn get_fs(&self) -> &Self::LowerFs;
}

pub trait CacheAccess {
    fn access<Res, F: FnOnce(&mut BTreeMap<String, FsCacheEntry>) -> Res>(&self, f: F) -> Res;
}
/// Trait for encryption and decryption operations.
pub trait EncryptionTranslator {
    const CIPHER_BLOCK_LEN: u64;
    const PLAIN_BLOCK_LEN: u64;
    const HEADER_LEN: usize;
    const ENCRYPT_SPARSE_PARTS: bool;
    const EMPTY_FILE_HAS_HEADER: bool;
    /// Decrypts a cipher filename to plain text.
    fn cipher_name_to_plain(&self, parent_iv: &[u8], cipher_name: &str) -> Result<String>;
    /// Encrypts a plain filename to cipher text.
    fn plain_name_to_cipher(&self, parent_iv: &[u8], plain_name: &str) -> Result<String>;

    /// Converts plain file size to cipher file size.
    fn plain_size_to_cipher(&self, plain_size: u64) -> u64;
    /// Converts cipher file size to plain file size.
    fn cipher_size_to_plain(&self, cipher_size: u64) -> Result<u64>;

    /// Generates a cipher header for the file.
    fn generate_cipher_header(&self) -> Result<Vec<u8>>;
    /// Generates a random initialization vector for directories.
    fn generate_diriv(&self) -> Vec<u8>;

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
    fn plain_metavalue_to_cipher(&self, plain_metavalue: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts a cipher metavalue to plain bytes.
    fn cipher_metavalue_to_plain(&self, cipher_metavalue: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for extended attribute name and value translation.
pub trait XattrLayout: EncryptionTranslator {
    fn get_xattr(&self, _path: &VirtualPath, _name: &str) -> std::io::Result<Vec<u8>> {
        #[cfg(not(unix))]
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        #[cfg(unix)]
        return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
    }
    fn list_xattr(&self, _path: &VirtualPath) -> std::io::Result<Vec<String>> {
        #[cfg(not(unix))]
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        #[cfg(unix)]
        return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
    }
    fn remove_xattr(&self, _path: &VirtualPath, _name: &str) -> std::io::Result<()> {
        #[cfg(not(unix))]
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        #[cfg(unix)]
        return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
    }
    fn set_xattr(&self, _path: &VirtualPath, _name: &str, _value: &[u8]) -> std::io::Result<()> {
        #[cfg(not(unix))]
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        #[cfg(unix)]
        return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
    }
}

pub(crate) fn default_remove_cached_plain_path<T: CacheAccess>(
    backend: &T,
    plain_path: &VirtualPath,
) {
    backend.access(|cache| {
        cache.remove(plain_path.as_str());
        // Remove cached descendants in one range operation.
        let prefix = format!("{plain_path}/");
        let end = format!("{plain_path}0"); // b'0' == b'/' + 1
        let mut tail = cache.split_off(&prefix); // >= prefix
        let mut after = tail.split_off(&end); // >= end, so tail contains [prefix, end[

        cache.append(&mut after); // [prefix, end[ was removed.
    });
}

/// Trait for path translation between plain and cipher.
pub trait CipherPathLayout: EncryptionTranslator {
    type LowerFs: MinimalFs;
    fn lower_fs(&self) -> &Self::LowerFs;
    /// Creates a temporary name for a given path.
    fn create_temp_name(&self, path: &str, is_dir_iv: bool) -> VirtualPathBuf;
    /// Converts a plain path to its cipher text equivalent.
    fn plain_path_to_cipher(&self, plain_path: &VirtualPath) -> Result<VirtualPathBuf>;

    /// Invalidates one cached plain path and its cached descendants.
    fn remove_cached_plain_path(&self, plain_path: &VirtualPath);

    /// Returns the path of the per-directory IV file for a cipher directory.
    fn get_dir_iv_file(&self, cipher_folder_path: &VirtualPath) -> VirtualPathBuf;
}
pub trait EncryptionLayout: CipherPathLayout {
    /// Lists directory entries with plain names.
    fn list_dir_plain_names(
        self: Arc<Self>,
        plain_path: &VirtualPath,
    ) -> std::io::Result<
        impl Iterator<Item = std::io::Result<(FsDirEntry, VirtualPathBuf)>> + 'static,
    >;

    fn metadata(&self, plain_path: &VirtualPath) -> std::io::Result<Metadata> {
        default_metadata(self, plain_path)
    }
    fn mknode(
        &self,
        plain_path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        default_mknode(self, plain_path, permissions)
    }
    fn mkdir(
        &self,
        plain_path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        default_mkdir(self, plain_path, permissions)
    }
    fn remove(&self, plain_path: &VirtualPath) -> std::io::Result<()> {
        default_remove(self, plain_path)
    }
    fn remove_dir(&self, plain_path: &VirtualPath) -> std::io::Result<()> {
        default_remove_dir(self, plain_path)
    }
    fn create_symlink(&self, plain_path: &VirtualPath, target: &str) -> std::io::Result<Metadata> {
        default_create_symlink(self, plain_path, target)
    }
    fn read_symlink(&self, plain_path: &VirtualPath) -> std::io::Result<String> {
        default_read_symlink(self, plain_path)
    }
    fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()> {
        default_rename(self, old_path, new_path)
    }
    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        default_set_permissions(self, path, permissions)
    }
    /// Sets access and modification times.
    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()> {
        default_set_time(self, path, atime, mtime)
    }
}

pub trait StorageFile: FileHandle + Size + ModifiedTime + 'static {}

impl<T> StorageFile for T where T: FileHandle + Size + ModifiedTime + 'static {}

pub trait MinimalFs: Send + Sync + 'static {
    type OpenHandle: StorageFile;
    type DirEntries: Iterator<Item = std::io::Result<FsDirEntry>>;
    fn open_file_with(
        &self,
        path: &VirtualPath,
        options: GenericOpenOptions,
    ) -> std::io::Result<Self::OpenHandle>;

    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()>;

    fn chown(&self, path: &VirtualPath, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()>;
    fn metadata(&self, path: &VirtualPath) -> std::io::Result<Metadata>;
    fn exists(&self, path: &VirtualPath) -> std::io::Result<bool>;
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
    fn put(&self, path: &VirtualPath, data: &[u8]) -> std::io::Result<()> {
        let mut options = GenericOpenOptions::default();
        options.write(true).truncate(true).create(true);
        self.open_file_with(path, options)?.write_all_at(0, data)
    }
    fn put_new(&self, path: &VirtualPath, data: &[u8]) -> std::io::Result<()> {
        let mut options = GenericOpenOptions::default();
        options.write(true).create_new(true);
        self.open_file_with(path, options)?.write_all_at(0, data)
    }
    fn read_at(
        &self,
        path: &VirtualPath,
        offset: u64,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        let mut options = GenericOpenOptions::default();
        options.read(true);
        self.open_file_with(path, options)?.read_at(offset, buffer)
    }
    fn read(&self, path: &VirtualPath, offset: u64, size: usize) -> std::io::Result<Vec<u8>> {
        let mut buffer = vec![0; size];
        let bytes_read = self.read_at(path, offset, &mut buffer)?;
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
    fn read_all(&self, path: &VirtualPath) -> std::io::Result<Vec<u8>> {
        let mut options = GenericOpenOptions::default();
        options.read(true);
        let file = self.open_file_with(path, options)?;
        let size = file.size()?;
        let size =
            usize::try_from(size).map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let mut buffer = vec![0; size];
        file.read_exact_at(0, &mut buffer)?;
        Ok(buffer)
    }
    fn is_dir_empty(&self, path: &VirtualPath) -> std::io::Result<bool> {
        self.read_dir(path)?
            .next()
            .transpose()
            .map(|entry| entry.is_none())
    }
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
    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata>;
    fn get_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<Vec<u8>>;
    fn list_xattr(&self, path: &VirtualPath) -> std::io::Result<Vec<String>>;
    fn remove_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<()>;
    fn set_xattr(&self, path: &VirtualPath, name: &str, value: &[u8]) -> std::io::Result<()>;
    fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<String>;
    fn create_symlink(&self, path: &VirtualPath, target: &str) -> std::io::Result<Metadata>;
    fn read_dir(&self, path: &VirtualPath) -> std::io::Result<Self::DirEntries>;
}
