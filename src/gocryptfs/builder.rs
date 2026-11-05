use super::GoCryptFs;
use crate::core::{
    BackendProvider, CleartextFileSystem, ConfigFileSystem, DirectoryLayout, DynamicFileSystem,
    EntryStorage, EntryStorageBackend, FileBufferingPolicy, Handler, MasterKey, NativeFileSystem,
    Result, StorageConfigFileSystem,
};
use crate::{Utf8Path, register_provider};

/// Concrete filesystem built over the supplied entry and directory layouts.
type BuiltFileSystem<S, L> = CleartextFileSystem<GoCryptFs<EntryStorageBackend<S, L>>>;

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
        let cryptfs: CleartextFileSystem<GoCryptFs<EntryStorageBackend<S, L>>> = (
            GoCryptFs::try_new_with_backend(backend, config_fs, password)?,
            cache_policy,
        )
            .into();
        Ok(cryptfs)
    }

    /// Initializes a GoCryptFS crypto configuration over an entry representation.
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
        GoCryptFs::init_with_backend(backend, config_fs, password).map(GoCryptFSMasterKey)
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
        cache_policy: Handler<dyn FileBufferingPolicy>,
    ) -> Result<Handler<DynamicFileSystem>> {
        let cryptfs: CleartextFileSystem<GoCryptFs> =
            (GoCryptFs::try_new(root, password)?, cache_policy).into();
        Ok(Handler::new(cryptfs).into())
    }
    fn init_with_default_params(
        &self,
        root: &Utf8Path,
        password: &str,
    ) -> Result<Handler<dyn MasterKey>> {
        GoCryptFs::init_with_default_params(root, password)
            .map(|key| Handler::new(GoCryptFSMasterKey(key)).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GoCryptFsBackend;
    use crate::core::{FileSystemSession, LockedOpenFileTable, NoBuffering, VirtualPath};

    #[test]
    fn concrete_builders_return_owned_handles() {
        let root = tempfile::tempdir().unwrap();
        let root_path = Utf8Path::from_path(root.path()).unwrap();
        let (key, fs) = {
            let storage = NativeFileSystem::new(root_path.to_owned());
            let config = StorageConfigFileSystem::new(&storage);
            let backend = GoCryptFsBackend::from(root_path);
            let key = GoCryptFsBuilder::init_with_backend(&backend, &config, "password").unwrap();
            let fs =
                GoCryptFsBuilder::try_build_with_backend(backend, &config, "password", NoBuffering)
                    .unwrap();
            (key, fs)
        };

        assert_eq!(key.to_vec().len(), 32);
        let session: FileSystemSession<LockedOpenFileTable> = fs.into();
        assert!(session.as_ref().exists(VirtualPath::root()).unwrap());
    }
}
