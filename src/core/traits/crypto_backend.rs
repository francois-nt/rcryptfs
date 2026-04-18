use super::super::FsCacheEntry;
use super::{FsDirEntry, Metadata, Permissions, Result, Utf8Path, Utf8PathBuf};
use super::{
    default_create_symlink, default_metadata, default_mkdir, default_mknode, default_read_symlink,
    default_remove, default_remove_dir, default_rename, default_set_permissions, default_set_time,
};
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
    fn get_xattr(&self, _path: &str, _name: &str) -> std::io::Result<Vec<u8>> {
        #[cfg(not(unix))]
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        #[cfg(unix)]
        return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
    }
    fn list_xattr(&self, _path: &str) -> std::io::Result<Vec<String>> {
        #[cfg(not(unix))]
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        #[cfg(unix)]
        return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
    }
    fn remove_xattr(&self, _path: &str, _name: &str) -> std::io::Result<()> {
        #[cfg(not(unix))]
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        #[cfg(unix)]
        return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
    }
    fn set_xattr(&self, _path: &str, _name: &str, _value: &[u8]) -> std::io::Result<()> {
        #[cfg(not(unix))]
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        #[cfg(unix)]
        return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
    }
}

pub(crate) fn default_remove_cached_plain_path<T: CacheAccess>(backend: &T, plain_path: &str) {
    backend.access(|cache| {
        cache.remove(plain_path);
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
    fn create_temp_name(&self, path: &str, is_dir_iv: bool) -> Utf8PathBuf;
    /// Converts a plain path to its cipher text equivalent.
    fn plain_path_to_cipher(&self, plain_path: &Utf8Path) -> Result<Utf8PathBuf>;

    /// Invalidates one cached plain path and its cached descendants.
    fn remove_cached_plain_path(&self, plain_path: &str);

    /// Returns the path of the per-directory IV file for a cipher directory.
    fn get_dir_iv_file(&self, cipher_folder_path: &Utf8Path) -> Utf8PathBuf;
}
pub trait EncryptionLayout: CipherPathLayout {
    /// Lists directory entries with plain names.
    fn list_dir_plain_names(
        &self,
        plain_path: &Utf8Path,
    ) -> std::io::Result<impl Iterator<Item = Result<(FsDirEntry, Utf8PathBuf)>> + '_ + use<'_, Self>>;

    fn metadata(&self, plain_path: &str) -> std::io::Result<Metadata> {
        default_metadata(self, plain_path)
    }
    fn mknode(&self, plain_path: &str, permissions: Permissions) -> std::io::Result<Metadata> {
        default_mknode(self, plain_path, permissions)
    }
    fn mkdir(&self, plain_path: &str, permissions: Permissions) -> std::io::Result<Metadata> {
        default_mkdir(self, plain_path, permissions)
    }
    fn remove(&self, plain_path: &str) -> std::io::Result<()> {
        default_remove(self, plain_path)
    }
    fn remove_dir(&self, plain_path: &str) -> std::io::Result<()> {
        default_remove_dir(self, plain_path)
    }
    fn create_symlink(&self, plain_path: &str, target: &str) -> std::io::Result<Metadata> {
        default_create_symlink(self, plain_path, target)
    }
    fn read_symlink(&self, plain_path: &str) -> std::io::Result<String> {
        default_read_symlink(self, plain_path)
    }
    fn rename(&self, old_path: &str, new_path: &str) -> std::io::Result<()> {
        default_rename(self, old_path, new_path)
    }
    fn set_permissions(&self, path: &str, permissions: Permissions) -> std::io::Result<Metadata> {
        default_set_permissions(self, path, permissions)
    }
    /// Sets access and modification times.
    fn set_time(
        &self,
        path: &str,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()> {
        default_set_time(self, path, atime, mtime)
    }
}

pub trait MinimalFs {
    fn metadata(&self, path: &Utf8Path) -> std::io::Result<Metadata>;
    fn exists(&self, path: &Utf8Path) -> std::io::Result<bool>;
    fn mkdir(&self, path: &Utf8Path) -> std::io::Result<()>;
    fn mknode(&self, path: &Utf8Path) -> std::io::Result<()>;
    fn rename(&self, old_path: &Utf8Path, new_path: &Utf8Path) -> std::io::Result<()>;
    fn remove_file(&self, path: &Utf8Path) -> std::io::Result<()>;
    fn remove_dir(&self, path: &Utf8Path, all: bool) -> std::io::Result<()>;
    fn put(&self, path: &Utf8Path, data: &[u8]) -> std::io::Result<()>;
    fn read_at(&self, path: &Utf8Path, offset: u64, buffer: &mut [u8]) -> std::io::Result<usize>;
    fn read(&self, path: &Utf8Path, offset: u64, size: usize) -> std::io::Result<Vec<u8>> {
        let mut buffer = vec![0; size];
        let bytes_read = self.read_at(path, offset, &mut buffer)?;
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
    fn set_permissions(
        &self,
        path: &Utf8Path,
        permissions: Permissions,
    ) -> std::io::Result<Metadata>;
    fn get_xattr(&self, path: &str, name: &str) -> std::io::Result<Vec<u8>>;
    fn list_xattr(&self, path: &str) -> std::io::Result<Vec<String>>;
    fn remove_xattr(&self, path: &str, name: &str) -> std::io::Result<()>;
    fn set_xattr(&self, path: &str, name: &str, value: &[u8]) -> std::io::Result<()>;
    fn read_symlink(&self, path: &str) -> std::io::Result<Utf8PathBuf>;
    fn create_symlink(&self, path: &str, target_path: &str) -> std::io::Result<Metadata>;
    fn list_dir(
        &self,
        path: &str,
    ) -> std::io::Result<impl Iterator<Item = std::io::Result<FsDirEntry>> + '_ + use<'_, Self>>;
}
