use super::super::CipherPathCacheEntry;
use super::{
    AsyncEntryStorage, EntryStorage, FsDirEntry, Metadata, Permissions, Result, VirtualPath,
    VirtualPathBuf,
};
use super::{
    default_create_symlink, default_list_dir_plain_names, default_metadata, default_mkdir,
    default_mknode, default_read_symlink, default_remove, default_remove_dir, default_rename,
    default_set_permissions, default_set_time,
};
use futures_core::Stream;
use std::{collections::BTreeMap, future::Future, time::SystemTime};
/// Marker trait for backend implementations.
pub trait Backend {}

/// Provides synchronized access to the plain-to-cipher path cache.
pub trait PathCacheAccess {
    fn with_path_cache<Res, F: FnOnce(&mut BTreeMap<String, CipherPathCacheEntry>) -> Res>(
        &self,
        f: F,
    ) -> Res;
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

/// Resolves the physical location used by detached directory representations.
///
/// Entry storages decide whether this policy is needed. Inline representations
/// can ignore it and use the visible entry path as their contents path.
pub trait DirectoryContentLayout: Send + Sync {
    /// Computes the physical contents path for one detached directory.
    fn detached_directory_contents_path(
        &self,
        entry_path: &VirtualPath,
        token: &[u8],
    ) -> Result<VirtualPathBuf>;

    /// Returns whether a path is a detached directory contents location.
    fn is_detached_directory_contents_path(&self, path: &VirtualPath) -> bool;
}

/// Defines how directory tokens, roots, and detached contents are represented.
pub trait DirectoryLayout: DirectoryContentLayout {
    /// Generates a token for a newly-created non-root directory.
    fn generate_directory_token(&self) -> Vec<u8>;

    /// Validates a directory token before it is consumed or persisted.
    fn validate_directory_token(&self, token: &[u8], is_root: bool) -> Result<()>;

    /// Selects whether the root token is stored or derived implicitly.
    fn root_directory_token(&self) -> RootDirectoryToken;
}

/// Describes how the token of the logical root directory is obtained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootDirectoryToken {
    /// Generate the root token once and persist it through the entry storage.
    Persisted,
    /// Derive the root token from the configured constant bytes.
    Implicit(Vec<u8>),
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

pub(crate) fn default_remove_cached_plain_path<T: PathCacheAccess>(
    backend: &T,
    plain_path: &VirtualPath,
) {
    backend.with_path_cache(|cache| {
        cache.remove(plain_path.as_str());
        // Remove cached descendants in one range operation.
        let prefix = format!("{plain_path}/");
        let end = format!("{plain_path}0"); // b'0' == b'/' + 1
        let mut tail = cache.split_off(&prefix); // >= prefix
        let mut after = tail.split_off(&end); // >= end, so tail contains [prefix, end[

        cache.append(&mut after); // [prefix, end[ was removed.
    });
}

/// Resolves plain paths against an encrypted entry layout.
pub trait PathLayout {
    /// Storage implementing the physical entry representation.
    type EntryStorage: EntryStorage;
    /// Returns the representation-aware entry storage.
    fn entry_storage(&self) -> &Self::EntryStorage;
    /// Converts a plain path to its cipher text equivalent.
    fn plain_path_to_cipher(&self, plain_path: &VirtualPath) -> Result<VirtualPathBuf>;

    /// Invalidates one cached plain path and its cached descendants.
    fn remove_cached_plain_path(&self, plain_path: &VirtualPath);
}

/// Resolves plain paths against an asynchronous encrypted entry layout.
pub trait AsyncPathLayout: Send + Sync + 'static {
    /// Storage implementing the physical entry representation.
    type EntryStorage: AsyncEntryStorage;

    /// Returns the representation-aware asynchronous entry storage.
    fn entry_storage(&self) -> &Self::EntryStorage;

    /// Converts a plain path to its cipher text equivalent asynchronously.
    fn plain_path_to_cipher(
        &self,
        plain_path: &VirtualPath,
    ) -> impl Future<Output = Result<VirtualPathBuf>> + Send;

    /// Invalidates one cached plain path and its cached descendants.
    fn remove_cached_plain_path(&self, plain_path: &VirtualPath);
}

/// Provides asynchronous operations over an encrypted entry layout.
pub trait AsyncEncryptionLayout: AsyncPathLayout + EncryptionTranslator {
    /// Lists plain directory entries in implementation-defined batches.
    fn list_dir_plain_names(
        &self,
        plain_path: &VirtualPath,
    ) -> impl Stream<Item = std::io::Result<Vec<(FsDirEntry, VirtualPathBuf)>>> + Send;

    /// Returns plain metadata for a path.
    fn metadata(
        &self,
        plain_path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Creates a plain regular file.
    fn mknode(
        &self,
        plain_path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Creates a plain directory.
    fn mkdir(
        &self,
        plain_path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Removes a plain non-directory entry.
    fn remove(&self, plain_path: &VirtualPath) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Removes a plain directory.
    fn remove_dir(
        &self,
        plain_path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Creates a plain symbolic link.
    fn create_symlink(
        &self,
        plain_path: &VirtualPath,
        target: &str,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Reads a plain symbolic link target.
    fn read_symlink(
        &self,
        plain_path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<String>> + Send;

    /// Renames a plain entry.
    fn rename(
        &self,
        old_path: &VirtualPath,
        new_path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Updates permissions on a plain entry.
    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Sets access and modification times on a plain entry.
    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;
}

pub trait EncryptionLayout: PathLayout + EncryptionTranslator {
    /// Lists directory entries with plain names.
    fn list_dir_plain_names(
        &self,
        plain_path: &VirtualPath,
    ) -> std::io::Result<impl Iterator<Item = std::io::Result<(FsDirEntry, VirtualPathBuf)>> + '_>
    {
        default_list_dir_plain_names(self, plain_path)
    }

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
