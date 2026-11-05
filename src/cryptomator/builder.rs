use super::CryptoMator;
use crate::core::{
    BackendProvider, CleartextFileSystem, ConfigFileSystem, DirectoryLayout, DynamicFileSystem,
    EntryStorage, EntryStorageBackend, FileBufferingPolicy, Handler, MasterKey, NativeFileSystem,
    Result, StorageConfigFileSystem,
};
use crate::{Utf8Path, register_provider};

/// Concrete filesystem built over the supplied entry and directory layouts.
type BuiltFileSystem<S, L> = CleartextFileSystem<CryptoMator<EntryStorageBackend<S, L>>>;

/// Backend provider for Cryptomator repositories.
pub struct CryptoMatorBuilder;

register_provider!(CryptoMatorBuilder);

impl CryptoMatorBuilder {
    /// Checks whether an entry representation contains a Cryptomator crypto configuration.
    pub fn probe_config<C: ConfigFileSystem + ?Sized>(config_fs: &C) -> bool {
        config_fs
            .exists("vault.cryptomator".into())
            .unwrap_or(false)
    }

    /// Builds a Cryptomator crypto layer over an arbitrary entry representation.
    pub fn try_build_with_backend<S, L, C>(
        backend: EntryStorageBackend<S, L>,
        config_fs: &C,
        password: &str,
        cache_policy: impl FileBufferingPolicy,
    ) -> Result<BuiltFileSystem<S, L>>
    where
        S: EntryStorage,
        L: DirectoryLayout + 'static,
        C: ConfigFileSystem + ?Sized,
    {
        let cryptfs: CleartextFileSystem<CryptoMator<EntryStorageBackend<S, L>>> = (
            CryptoMator::try_new_with_backend(backend, config_fs, password)?,
            cache_policy,
        )
            .into();
        Ok(cryptfs)
    }

    /// Initializes a Cryptomator crypto configuration over an entry representation.
    pub fn init_with_backend<S, L, C>(
        backend: &EntryStorageBackend<S, L>,
        config_fs: &C,
        password: &str,
    ) -> Result<impl MasterKey + 'static + use<S, L, C>>
    where
        S: EntryStorage,
        L: DirectoryLayout,
        C: ConfigFileSystem + ?Sized,
    {
        CryptoMator::init_with_backend(backend, config_fs, password)
    }
}

impl BackendProvider for CryptoMatorBuilder {
    fn name(&self) -> &'static str {
        "cryptomator"
    }
    fn probe(&self, root: &Utf8Path) -> bool {
        let storage_fs = NativeFileSystem::new(root.to_owned());
        Self::probe_config(&StorageConfigFileSystem::new(&storage_fs))
    }
    fn try_build(
        &self,
        root: &Utf8Path,
        password: &str,
        cache_policy: Handler<dyn FileBufferingPolicy>,
    ) -> Result<Handler<DynamicFileSystem>> {
        let cryptfs: CleartextFileSystem<CryptoMator> =
            (CryptoMator::try_new(root, password)?, cache_policy).into();

        Ok(Handler::new(cryptfs).into())
    }
    fn init_with_default_params(
        &self,
        root: &Utf8Path,
        password: &str,
    ) -> Result<Handler<dyn MasterKey>> {
        CryptoMator::init_with_default_params(root, password).map(|keys| Handler::new(keys).into())
    }
}
