use super::CryptoMator;
use crate::core::{
    Backend, BackendProvider, EncryptedFileSystem, FileCachePolicy, FileSystem, FsBackend,
    MasterKey, Result, StorageFileSystem,
};
use crate::{Utf8Path, register_provider};

/// Backend provider for Cryptomator repositories.
pub struct CryptoMatorBuilder;

register_provider!(CryptoMatorBuilder);

impl CryptoMatorBuilder {
    /// Checks whether a storage backend contains a Cryptomator repository.
    pub fn probe_backend<F: StorageFileSystem>(backend: &FsBackend<F>) -> bool {
        backend
            .get_fs()
            .exists("vault.cryptomator".into())
            .unwrap_or(false)
    }

    /// Builds a Cryptomator filesystem on an arbitrary storage backend.
    pub fn try_build_with_backend<F: StorageFileSystem>(
        backend: FsBackend<F>,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>> {
        let cryptfs: EncryptedFileSystem<CryptoMator<FsBackend<F>>> = (
            CryptoMator::try_new_with_backend(backend, password)?,
            cache_policy,
        )
            .into();
        Ok(Box::new(cryptfs))
    }

    /// Initializes a Cryptomator repository on an arbitrary storage backend.
    pub fn init_with_backend<F: StorageFileSystem>(
        backend: &FsBackend<F>,
        password: &str,
    ) -> Result<Box<dyn MasterKey>> {
        CryptoMator::init_with_backend(backend, password)
            .map(|keys| -> Box<dyn MasterKey> { Box::new(keys) })
    }
}

impl BackendProvider for CryptoMatorBuilder {
    fn name(&self) -> &'static str {
        "cryptomator"
    }
    fn probe(&self, root: &Utf8Path) -> bool {
        Self::probe_backend(&root.into())
    }
    fn try_build(
        &self,
        root: &Utf8Path,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>> {
        Self::try_build_with_backend(root.into(), password, cache_policy)
    }
    fn init_with_default_params(
        &self,
        root: &Utf8Path,
        password: &str,
    ) -> Result<Box<dyn MasterKey>> {
        Self::init_with_backend(&root.into(), password)
    }
}
