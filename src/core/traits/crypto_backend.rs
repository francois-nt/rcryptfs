use super::super::PathCache;
use super::{
    AsyncEntryStorage, EntryStorage, FileOpenOptions, FsDirEntry, Metadata, Permissions,
    ResolvedStoragePathBuf, Result, VirtualPath, VirtualPathBuf,
};
use super::{
    default_async_chown, default_async_create_symlink, default_async_list_dir_plain_names,
    default_async_metadata, default_async_mkdir, default_async_mknode,
    default_async_open_file_with, default_async_read_symlink, default_async_remove,
    default_async_remove_dir, default_async_rename, default_async_set_permissions,
    default_async_set_time,
};
use super::{
    default_chown, default_create_symlink, default_list_dir_plain_names, default_metadata,
    default_mkdir, default_mknode, default_open_file_with, default_read_symlink, default_remove,
    default_remove_dir, default_rename, default_set_permissions, default_set_time,
};
use futures_core::Stream;
use std::{future::Future, time::SystemTime};
/// Marker trait for backend implementations.
pub trait Backend {}

/// Provides synchronized access to the plain-to-cipher path cache.
pub trait PathCacheAccess {
    /// Returns the shared plain-to-cipher path cache.
    fn path_cache(&self) -> &PathCache;
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
    /// Generates a token when a new directory requires a persisted identifier.
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

/// Returns the platform-specific error used for unsupported extended attributes.
fn unsupported_xattr<T>() -> std::io::Result<T> {
    #[cfg(not(unix))]
    let errno = libc::ENOTSUP;
    #[cfg(unix)]
    let errno = libc::ENOSYS;
    Err(std::io::Error::from_raw_os_error(errno))
}

/// Provides synchronous extended attribute operations on plain paths.
pub trait XattrLayout: EncryptionLayout {
    /// Returns one decrypted extended attribute value.
    fn get_xattr(&self, _path: &VirtualPath, _name: &str) -> std::io::Result<Vec<u8>> {
        unsupported_xattr()
    }

    /// Lists decrypted extended attribute names.
    fn list_xattr(&self, _path: &VirtualPath) -> std::io::Result<Vec<String>> {
        unsupported_xattr()
    }

    /// Removes one extended attribute.
    fn remove_xattr(&self, _path: &VirtualPath, _name: &str) -> std::io::Result<()> {
        unsupported_xattr()
    }

    /// Encrypts and stores one extended attribute value.
    fn set_xattr(&self, _path: &VirtualPath, _name: &str, _value: &[u8]) -> std::io::Result<()> {
        unsupported_xattr()
    }
}

/// Provides asynchronous extended attribute operations on plain paths.
pub trait AsyncXattrLayout: AsyncEncryptionLayout {
    /// Returns one decrypted extended attribute value.
    fn get_xattr(
        &self,
        _path: &VirtualPath,
        _name: &str,
    ) -> impl Future<Output = std::io::Result<Vec<u8>>> + Send {
        std::future::ready(unsupported_xattr())
    }

    /// Lists decrypted extended attribute names.
    fn list_xattr(
        &self,
        _path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<Vec<String>>> + Send {
        std::future::ready(unsupported_xattr())
    }

    /// Removes one extended attribute.
    fn remove_xattr(
        &self,
        _path: &VirtualPath,
        _name: &str,
    ) -> impl Future<Output = std::io::Result<()>> + Send {
        std::future::ready(unsupported_xattr())
    }

    /// Encrypts and stores one extended attribute value.
    fn set_xattr(
        &self,
        _path: &VirtualPath,
        _name: &str,
        _value: &[u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send {
        std::future::ready(unsupported_xattr())
    }
}

pub(crate) fn default_remove_cached_plain_path<T: PathCacheAccess>(
    backend: &T,
    plain_path: &VirtualPath,
) {
    backend.path_cache().invalidate(plain_path);
}

/// Returns whether an operation rejected a stale storage-directory identity.
pub(crate) fn is_stale_identity(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::StaleNetworkFileHandle
}

/// Logs a cryptographic failure and exposes it as invalid input to filesystem callers.
pub(crate) fn crypto_io_result<T>(result: Result<T>) -> std::io::Result<T> {
    result.map_err(|error| {
        log::error!("crypto error: {error}");
        std::io::Error::from_raw_os_error(libc::EINVAL)
    })
}

/// Clears stale resolutions and retries one complete synchronous operation once.
pub(crate) fn retry_stale<T>(
    layout: &(impl PathCacheAccess + ?Sized),
    mut operation: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    match operation() {
        Err(error) if is_stale_identity(&error) => {}
        result => return result,
    }
    layout.path_cache().invalidate(VirtualPath::root());
    let result = operation();
    if result.as_ref().is_err_and(is_stale_identity) {
        layout.path_cache().invalidate(VirtualPath::root());
    }
    result
}

/// Clears stale resolutions and retries one complete asynchronous operation once.
pub(crate) async fn retry_stale_async<T, F, Fut>(
    layout: &(impl PathCacheAccess + ?Sized),
    mut operation: F,
) -> std::io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::io::Result<T>>,
{
    match operation().await {
        Err(error) if is_stale_identity(&error) => {}
        result => return result,
    }
    layout.path_cache().invalidate(VirtualPath::root());
    let result = operation().await;
    if result.as_ref().is_err_and(is_stale_identity) {
        layout.path_cache().invalidate(VirtualPath::root());
    }
    result
}

/// Resolves plain paths against an encrypted entry layout.
pub trait PathLayout: PathCacheAccess {
    /// Converts a plain path to its cipher text equivalent.
    fn plain_path_to_cipher(
        &self,
        plain_path: &VirtualPath,
    ) -> std::io::Result<ResolvedStoragePathBuf>;

    /// Invalidates one cached plain path and its cached descendants.
    fn remove_cached_plain_path(&self, plain_path: &VirtualPath);
}

/// Resolves plain paths against an asynchronous encrypted entry layout.
pub trait AsyncPathLayout: PathCacheAccess + Send + Sync + 'static {
    /// Converts a plain path to its cipher text equivalent asynchronously.
    fn plain_path_to_cipher(
        &self,
        plain_path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<ResolvedStoragePathBuf>> + Send;

    /// Invalidates one cached plain path and its cached descendants.
    fn remove_cached_plain_path(&self, plain_path: &VirtualPath);
}

/// Provides asynchronous operations over an encrypted entry layout.
pub trait AsyncEncryptionLayout: AsyncPathLayout + EncryptionTranslator {
    /// Storage implementing the physical entry representation.
    type EntryStorage: AsyncEntryStorage;
    /// Directory policy used by this composed layout.
    type DirectoryLayout: DirectoryLayout;

    /// Returns the representation-aware asynchronous entry storage.
    fn entry_storage(&self) -> &Self::EntryStorage;

    /// Returns the directory policy used by this composed layout.
    fn directory_layout(&self) -> &Self::DirectoryLayout;

    /// Opens the represented cipher file for one plain path.
    fn open_file_with(
        &self,
        plain_path: &VirtualPath,
        options: FileOpenOptions,
    ) -> impl Future<Output = std::io::Result<<Self::EntryStorage as AsyncEntryStorage>::OpenHandle>>
    + Send {
        retry_stale_async(self, move || {
            default_async_open_file_with(self, plain_path, options.clone())
        })
    }

    /// Lists plain directory entries in implementation-defined batches.
    fn list_dir_plain_names(
        &self,
        plain_path: &VirtualPath,
    ) -> impl Stream<Item = std::io::Result<Vec<(FsDirEntry, VirtualPathBuf)>>> + Send {
        default_async_list_dir_plain_names(self, plain_path)
    }

    /// Returns plain metadata for a path.
    fn metadata(
        &self,
        plain_path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send {
        retry_stale_async(self, move || default_async_metadata(self, plain_path))
    }

    /// Creates a plain regular file.
    fn mknode(
        &self,
        plain_path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send {
        retry_stale_async(self, move || {
            default_async_mknode(self, plain_path, permissions)
        })
    }

    /// Creates a plain directory.
    fn mkdir(
        &self,
        plain_path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send {
        retry_stale_async(self, move || {
            default_async_mkdir(self, plain_path, permissions)
        })
    }

    /// Removes a plain non-directory entry.
    fn remove(&self, plain_path: &VirtualPath) -> impl Future<Output = std::io::Result<()>> + Send {
        retry_stale_async(self, move || default_async_remove(self, plain_path))
    }

    /// Removes a plain directory.
    fn remove_dir(
        &self,
        plain_path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<()>> + Send {
        retry_stale_async(self, move || default_async_remove_dir(self, plain_path))
    }

    /// Creates a plain symbolic link.
    fn create_symlink(
        &self,
        plain_path: &VirtualPath,
        target: &str,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send {
        retry_stale_async(self, move || {
            default_async_create_symlink(self, plain_path, target)
        })
    }

    /// Reads a plain symbolic link target.
    fn read_symlink(
        &self,
        plain_path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<String>> + Send {
        retry_stale_async(self, move || default_async_read_symlink(self, plain_path))
    }

    /// Renames a plain entry.
    fn rename(
        &self,
        old_path: &VirtualPath,
        new_path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<()>> + Send {
        retry_stale_async(self, move || default_async_rename(self, old_path, new_path))
    }

    /// Updates permissions on a plain entry.
    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send {
        retry_stale_async(self, move || {
            default_async_set_permissions(self, path, permissions)
        })
    }

    /// Sets access and modification times on a plain entry.
    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> impl Future<Output = std::io::Result<()>> + Send {
        retry_stale_async(self, move || {
            default_async_set_time(self, path, atime, mtime)
        })
    }

    /// Changes ownership of a plain entry.
    fn chown(
        &self,
        path: &VirtualPath,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> impl Future<Output = std::io::Result<()>> + Send {
        retry_stale_async(self, move || default_async_chown(self, path, uid, gid))
    }
}

pub trait EncryptionLayout: PathLayout + EncryptionTranslator {
    /// Storage implementing the physical entry representation.
    type EntryStorage: EntryStorage;
    /// Directory policy used by this composed layout.
    type DirectoryLayout: DirectoryLayout;

    /// Returns the representation-aware entry storage.
    fn entry_storage(&self) -> &Self::EntryStorage;

    /// Returns the directory policy used by this composed layout.
    fn directory_layout(&self) -> &Self::DirectoryLayout;

    /// Opens the represented cipher file for one plain path.
    fn open_file_with(
        &self,
        plain_path: &VirtualPath,
        options: FileOpenOptions,
    ) -> std::io::Result<<Self::EntryStorage as EntryStorage>::OpenHandle> {
        retry_stale(self, || {
            default_open_file_with(self, plain_path, options.clone())
        })
    }

    /// Lists directory entries with plain names.
    fn list_dir_plain_names(
        &self,
        plain_path: &VirtualPath,
    ) -> std::io::Result<impl Iterator<Item = std::io::Result<(FsDirEntry, VirtualPathBuf)>> + '_>
    {
        default_list_dir_plain_names(self, plain_path)
    }

    fn metadata(&self, plain_path: &VirtualPath) -> std::io::Result<Metadata> {
        retry_stale(self, || default_metadata(self, plain_path))
    }
    fn mknode(
        &self,
        plain_path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        retry_stale(self, || default_mknode(self, plain_path, permissions))
    }
    fn mkdir(
        &self,
        plain_path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        retry_stale(self, || {
            default_mkdir(self, self.directory_layout(), plain_path, permissions)
        })
    }
    fn remove(&self, plain_path: &VirtualPath) -> std::io::Result<()> {
        retry_stale(self, || default_remove(self, plain_path))
    }
    fn remove_dir(&self, plain_path: &VirtualPath) -> std::io::Result<()> {
        retry_stale(self, || default_remove_dir(self, plain_path))
    }
    fn create_symlink(&self, plain_path: &VirtualPath, target: &str) -> std::io::Result<Metadata> {
        retry_stale(self, || default_create_symlink(self, plain_path, target))
    }
    fn read_symlink(&self, plain_path: &VirtualPath) -> std::io::Result<String> {
        retry_stale(self, || default_read_symlink(self, plain_path))
    }
    fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()> {
        retry_stale(self, || default_rename(self, old_path, new_path))
    }
    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        retry_stale(self, || default_set_permissions(self, path, permissions))
    }
    /// Sets access and modification times.
    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()> {
        retry_stale(self, || default_set_time(self, path, atime, mtime))
    }

    /// Changes ownership of a plain entry.
    fn chown(&self, path: &VirtualPath, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
        retry_stale(self, || default_chown(self, path, uid, gid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{CacheLookup, CipherPathCacheEntry};
    use std::cell::Cell;

    struct TestLayout(PathCache);

    impl PathCacheAccess for TestLayout {
        fn path_cache(&self) -> &PathCache {
            &self.0
        }
    }

    #[test]
    fn stale_operation_is_retried_once() {
        let layout = TestLayout(PathCache::default());
        let attempts = Cell::new(0);

        retry_stale(&layout, || {
            let attempt = attempts.get();
            attempts.set(attempt + 1);
            if attempt == 0 {
                let snapshot = layout.0.snapshot_blocking(VirtualPath::root());
                snapshot.commit(vec![(
                    String::new(),
                    CipherPathCacheEntry {
                        token: Vec::new(),
                        contents_path: ResolvedStoragePathBuf::new(
                            VirtualPathBuf::default(),
                            Default::default(),
                        ),
                        contents_id: Default::default(),
                    },
                )]);
                Err(std::io::ErrorKind::StaleNetworkFileHandle.into())
            } else {
                assert!(matches!(
                    layout
                        .0
                        .snapshot_blocking(VirtualPath::root())
                        .lookup(VirtualPath::root()),
                    CacheLookup::Miss
                ));
                Ok(())
            }
        })
        .unwrap();

        assert_eq!(attempts.get(), 2);
    }

    #[test]
    fn crypto_failure_becomes_invalid_input() {
        let error = crypto_io_result::<()>(Err(anyhow::anyhow!("invalid ciphertext"))).unwrap_err();

        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
    }
}
