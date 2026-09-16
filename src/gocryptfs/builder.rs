use super::{GoCryptFs, GoCryptFsBackend};
use crate::core::{
    BackendProvider, ConfigFileSystemAccess, EncryptedFileSystem, EntryStorage, FileCachePolicy,
    FileSystem, FsBackend, MasterKey, Result,
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
    /// Checks whether an entry representation contains a GoCryptFS crypto configuration.
    pub fn probe_backend<S>(backend: &FsBackend<S>) -> bool
    where
        S: EntryStorage + ConfigFileSystemAccess,
    {
        backend
            .config_fs()
            .exists("gocryptfs.conf".into())
            .unwrap_or(false)
    }

    /// Builds a GoCryptFS crypto layer over an arbitrary entry representation.
    pub fn try_build_with_backend<S>(
        backend: FsBackend<S>,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>>
    where
        S: EntryStorage + ConfigFileSystemAccess,
    {
        let cryptfs: EncryptedFileSystem<GoCryptFs<FsBackend<S>>> = (
            GoCryptFs::try_new_with_backend(backend, password)?,
            cache_policy,
        )
            .into();
        Ok(Box::new(cryptfs))
    }

    /// Initializes a GoCryptFS crypto configuration over an entry representation.
    pub fn init_with_backend<S>(
        backend: &FsBackend<S>,
        password: &str,
    ) -> Result<Box<dyn MasterKey>>
    where
        S: EntryStorage + ConfigFileSystemAccess,
    {
        GoCryptFs::init_with_backend(backend, password)
            .map(|key| -> Box<dyn MasterKey> { Box::new(GoCryptFSMasterKey(key)) })
    }
}

impl BackendProvider for GoCryptFsBuilder {
    fn name(&self) -> &'static str {
        "gocryptfs"
    }
    fn probe(&self, root: &Utf8Path) -> bool {
        let backend: GoCryptFsBackend = root.into();
        Self::probe_backend(&backend)
    }
    fn try_build(
        &self,
        root: &Utf8Path,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>> {
        let backend: GoCryptFsBackend = root.into();
        Self::try_build_with_backend(backend, password, cache_policy)
    }
    fn init_with_default_params(
        &self,
        root: &Utf8Path,
        password: &str,
    ) -> Result<Box<dyn MasterKey>> {
        let backend: GoCryptFsBackend = root.into();
        Self::init_with_backend(&backend, password)
    }
}
