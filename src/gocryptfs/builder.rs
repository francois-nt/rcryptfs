use super::GoCryptFs;
use crate::core::{
    Backend, BackendProvider, EncryptedFileSystem, FileCachePolicy, FileSystem, FsBackend,
    MasterKey, Result, StorageFileSystem,
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

impl GoCryptFsBuilder {
    /// Checks whether a storage backend contains a GoCryptFS repository.
    pub fn probe_backend<F: StorageFileSystem>(backend: &FsBackend<F>) -> bool {
        backend
            .storage_fs()
            .exists("gocryptfs.conf".into())
            .unwrap_or(false)
    }

    /// Builds a GoCryptFS filesystem on an arbitrary storage backend.
    pub fn try_build_with_backend<F: StorageFileSystem>(
        backend: FsBackend<F>,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>> {
        let cryptfs: EncryptedFileSystem<GoCryptFs<FsBackend<F>>> = (
            GoCryptFs::try_new_with_backend(backend, password)?,
            cache_policy,
        )
            .into();
        Ok(Box::new(cryptfs))
    }

    /// Initializes a GoCryptFS repository on an arbitrary storage backend.
    pub fn init_with_backend<F: StorageFileSystem>(
        backend: &FsBackend<F>,
        password: &str,
    ) -> Result<Box<dyn MasterKey>> {
        GoCryptFs::init_with_backend(backend, password)
            .map(|key| -> Box<dyn MasterKey> { Box::new(GoCryptFSMasterKey(key)) })
    }
}

impl BackendProvider for GoCryptFsBuilder {
    fn name(&self) -> &'static str {
        "gocryptfs"
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
