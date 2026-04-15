use super::GoCryptFs;
use crate::core::{
    BackendProvider, EncryptedFileTranslator, FileCachePolicy, FileSystem, FsBackend, MasterKey,
    Result,
};
use crate::{Utf8Path, register_provider};

struct GoCryptFSMasterKey(Vec<u8>);
impl MasterKey for GoCryptFSMasterKey {
    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Backend provider for GoCryptFS repositories.
pub struct GoCryptFsBuilder;
register_provider!(GoCryptFsBuilder);

impl BackendProvider for GoCryptFsBuilder {
    fn name(&self) -> &'static str {
        "gocryptfs"
    }
    fn probe(&self, root: &Utf8Path) -> bool {
        std::fs::exists(root.join("gocryptfs.conf")).unwrap_or(false)
    }
    fn try_build(
        &self,
        root: &Utf8Path,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>> {
        let cryptfs: EncryptedFileTranslator<GoCryptFs<FsBackend>> = (
            GoCryptFs::<FsBackend>::try_new(root, password)?,
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
        GoCryptFs::<FsBackend>::init_with_default_params(root, password)
            .map(|key| -> Box<dyn MasterKey> { Box::new(GoCryptFSMasterKey(key)) })
    }
}
