use super::CryptoMator;
use crate::core::{
    BackendProvider, EncryptedFileTranslator, FileCachePolicy, FileSystem, FsBackend, MasterKey,
    Result,
};
use crate::{Utf8Path, register_provider};

/// Backend provider for Cryptomator repositories.
pub struct CryptoMatorBuilder;

register_provider!(CryptoMatorBuilder);

impl BackendProvider for CryptoMatorBuilder {
    fn name(&self) -> &'static str {
        "cryptomator"
    }
    fn probe(&self, root: &Utf8Path) -> bool {
        std::fs::exists(root.join("vault.cryptomator")).unwrap_or(false)
    }
    fn try_build(
        &self,
        root: &Utf8Path,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>> {
        let cryptfs: EncryptedFileTranslator<CryptoMator<FsBackend>> = (
            CryptoMator::<FsBackend>::try_new(root, password)?,
            cache_policy,
        )
            .into();
        Ok(Box::new(cryptfs))
    }
    fn init_with_default_params(
        &self,
        root: &Utf8Path,
        password: &str,
    ) -> Result<Box<dyn MasterKey>> {
        CryptoMator::<FsBackend>::init_with_default_params(root, password)
            .map(|keys| -> Box<dyn MasterKey> { Box::new(keys) })
    }
}
