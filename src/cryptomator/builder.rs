use super::{CryptoMator, CryptomatorBackend};
use crate::core::{
    Backend, BackendProvider, DirectoryLayout, EncryptedFileSystem, EntryStorage, FileCachePolicy,
    FileSystem, FsBackend, MasterKey, Result, StorageFileSystem, StorageFileSystemAccess,
};
use crate::{Utf8Path, register_provider};
use std::sync::Arc;

/// Backend provider for Cryptomator repositories.
pub struct CryptoMatorBuilder;

register_provider!(CryptoMatorBuilder);

impl CryptoMatorBuilder {
    /// Checks whether an entry representation contains a Cryptomator crypto configuration.
    pub fn probe_backend<S>(backend: &FsBackend<S>) -> bool
    where
        S: EntryStorage + StorageFileSystemAccess,
    {
        backend
            .storage_fs()
            .exists("vault.cryptomator".into())
            .unwrap_or(false)
    }

    /// Builds a Cryptomator crypto layer over an arbitrary entry representation.
    pub fn try_build_with_backend<S>(
        backend: FsBackend<S>,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>>
    where
        S: EntryStorage + StorageFileSystemAccess,
    {
        let cryptfs: EncryptedFileSystem<CryptoMator<FsBackend<S>>> = (
            CryptoMator::try_new_with_backend(backend, password)?,
            cache_policy,
        )
            .into();
        Ok(Box::new(cryptfs))
    }

    /// Builds a Cryptomator crypto layer with explicit directory policies.
    pub fn try_build_with_backend_and_directory_layout<S>(
        backend: FsBackend<S>,
        password: &str,
        directory_layout: Arc<dyn DirectoryLayout>,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>>
    where
        S: EntryStorage + StorageFileSystemAccess,
    {
        let cryptfs: EncryptedFileSystem<CryptoMator<FsBackend<S>>> = (
            CryptoMator::try_new_with_backend_and_directory_layout(
                backend,
                password,
                directory_layout,
            )?,
            cache_policy,
        )
            .into();
        Ok(Box::new(cryptfs))
    }

    /// Initializes a Cryptomator crypto configuration over an entry representation.
    pub fn init_with_backend<S>(
        backend: &FsBackend<S>,
        password: &str,
    ) -> Result<Box<dyn MasterKey>>
    where
        S: EntryStorage + StorageFileSystemAccess,
    {
        CryptoMator::init_with_backend(backend, password)
            .map(|keys| -> Box<dyn MasterKey> { Box::new(keys) })
    }

    /// Initializes a Cryptomator crypto configuration with explicit directory policies.
    pub fn init_with_backend_and_directory_layout<S>(
        backend: &FsBackend<S>,
        password: &str,
        directory_layout: &dyn DirectoryLayout,
    ) -> Result<Box<dyn MasterKey>>
    where
        S: EntryStorage + StorageFileSystemAccess,
    {
        CryptoMator::init_with_backend_and_directory_layout(backend, password, directory_layout)
            .map(|keys| -> Box<dyn MasterKey> { Box::new(keys) })
    }
}

impl BackendProvider for CryptoMatorBuilder {
    fn name(&self) -> &'static str {
        "cryptomator"
    }
    fn probe(&self, root: &Utf8Path) -> bool {
        let backend: CryptomatorBackend = root.into();
        Self::probe_backend(&backend)
    }
    fn try_build(
        &self,
        root: &Utf8Path,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>> {
        let backend: CryptomatorBackend = root.into();
        Self::try_build_with_backend(backend, password, cache_policy)
    }
    fn init_with_default_params(
        &self,
        root: &Utf8Path,
        password: &str,
    ) -> Result<Box<dyn MasterKey>> {
        let backend: CryptomatorBackend = root.into();
        Self::init_with_backend(&backend, password)
    }
}
