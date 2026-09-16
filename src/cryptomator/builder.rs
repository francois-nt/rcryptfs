use super::{CryptoMator, entry_storage::UnboundCryptomatorEntryStorage};
use crate::core::{
    BackendProvider, ConfigFileSystemAccess, EncryptedFileSystem, EntryStorage, FileCachePolicy,
    FileSystem, FsBackend, MasterKey, NativeFileSystem, Result,
};
use crate::{Utf8Path, register_provider};

/// Backend provider for Cryptomator repositories.
pub struct CryptoMatorBuilder;

register_provider!(CryptoMatorBuilder);

impl CryptoMatorBuilder {
    /// Checks whether an entry representation contains a Cryptomator crypto configuration.
    pub fn probe_backend<S>(backend: &FsBackend<S>) -> bool
    where
        S: EntryStorage + ConfigFileSystemAccess,
    {
        backend
            .config_fs()
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
        S: EntryStorage + ConfigFileSystemAccess,
    {
        let cryptfs: EncryptedFileSystem<CryptoMator<FsBackend<S>>> = (
            CryptoMator::try_new_with_backend(backend, password)?,
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
        S: EntryStorage + ConfigFileSystemAccess,
    {
        CryptoMator::init_with_backend(backend, password)
            .map(|keys| -> Box<dyn MasterKey> { Box::new(keys) })
    }
}

impl BackendProvider for CryptoMatorBuilder {
    fn name(&self) -> &'static str {
        "cryptomator"
    }
    fn probe(&self, root: &Utf8Path) -> bool {
        let storage = UnboundCryptomatorEntryStorage::new(NativeFileSystem::new(root.to_owned()));
        storage
            .config_fs()
            .exists("vault.cryptomator".into())
            .unwrap_or(false)
    }
    fn try_build(
        &self,
        root: &Utf8Path,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>> {
        let cryptfs: EncryptedFileSystem<CryptoMator> =
            (CryptoMator::try_new(root, password)?, cache_policy).into();
        Ok(Box::new(cryptfs))
    }
    fn init_with_default_params(
        &self,
        root: &Utf8Path,
        password: &str,
    ) -> Result<Box<dyn MasterKey>> {
        CryptoMator::init_with_default_params(root, password)
            .map(|keys| -> Box<dyn MasterKey> { Box::new(keys) })
    }
}
