use super::GoCryptFs;
use crate::core::{
    BackendProvider, ConfigFileSystem, EncryptedFileSystem, EntryStorage, FileCachePolicy,
    FileSystem, FsBackend, MasterKey, NativeFileSystem, Result, StorageConfigFileSystem,
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
    pub fn probe_config<C: ConfigFileSystem + ?Sized>(config_fs: &C) -> bool {
        config_fs.exists("gocryptfs.conf".into()).unwrap_or(false)
    }

    /// Builds a GoCryptFS crypto layer over an arbitrary entry representation.
    pub fn try_build_with_backend<S, C>(
        backend: FsBackend<S>,
        config_fs: &C,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>>
    where
        S: EntryStorage,
        C: ConfigFileSystem + ?Sized,
    {
        let cryptfs: EncryptedFileSystem<GoCryptFs<FsBackend<S>>> = (
            GoCryptFs::try_new_with_backend(backend, config_fs, password)?,
            cache_policy,
        )
            .into();
        Ok(Box::new(cryptfs))
    }

    /// Initializes a GoCryptFS crypto configuration over an entry representation.
    pub fn init_with_backend<S, C>(
        backend: &FsBackend<S>,
        config_fs: &C,
        password: &str,
    ) -> Result<Box<dyn MasterKey>>
    where
        S: EntryStorage,
        C: ConfigFileSystem + ?Sized,
    {
        GoCryptFs::init_with_backend(backend, config_fs, password)
            .map(|key| -> Box<dyn MasterKey> { Box::new(GoCryptFSMasterKey(key)) })
    }
}

impl BackendProvider for GoCryptFsBuilder {
    fn name(&self) -> &'static str {
        "gocryptfs"
    }
    fn probe(&self, root: &Utf8Path) -> bool {
        let storage_fs = NativeFileSystem::new(root.to_owned());
        Self::probe_config(&StorageConfigFileSystem::new(&storage_fs))
    }
    fn try_build(
        &self,
        root: &Utf8Path,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>> {
        let cryptfs: EncryptedFileSystem<GoCryptFs> =
            (GoCryptFs::try_new(root, password)?, cache_policy).into();
        Ok(Box::new(cryptfs))
    }
    fn init_with_default_params(
        &self,
        root: &Utf8Path,
        password: &str,
    ) -> Result<Box<dyn MasterKey>> {
        GoCryptFs::init_with_default_params(root, password)
            .map(|key| -> Box<dyn MasterKey> { Box::new(GoCryptFSMasterKey(key)) })
    }
}
