use crate::core::{Backend, EntryStorage, PathCacheAccess, VirtualPathBuf};
use parking_lot::Mutex;
use std::collections::BTreeMap;

/// Cached directory identifier and resolved cipher path.
pub type CipherPathCacheEntry = (Vec<u8>, VirtualPathBuf);

/// Backend state shared by one encrypted layout.
pub struct FsBackend<S: EntryStorage> {
    entry_storage: S,
    path_cache: Mutex<BTreeMap<String, CipherPathCacheEntry>>,
}

impl<S: EntryStorage> FsBackend<S> {
    /// Creates a backend backed by the provided entry storage.
    pub fn new(entry_storage: S) -> Self {
        Self {
            entry_storage,
            path_cache: Default::default(),
        }
    }

    /// Returns the entry storage owned by this backend.
    pub fn entry_storage(&self) -> &S {
        &self.entry_storage
    }
}

impl<S: EntryStorage> PathCacheAccess for FsBackend<S> {
    /// Gives temporary mutable access to the plain-to-cipher path cache.
    fn with_path_cache<Res, Op: FnOnce(&mut BTreeMap<String, CipherPathCacheEntry>) -> Res>(
        &self,
        f: Op,
    ) -> Res {
        f(&mut self.path_cache.lock())
    }
}

impl<S: EntryStorage> Backend for FsBackend<S> {}

/// In-memory backend for testing.
#[derive(Default)]
pub struct MemoryBackend;

impl Backend for MemoryBackend {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        DirectoryContentLayout, DirectoryLayout, EncryptionLayout, EntryStorage, NativeFileSystem,
        RootDirectoryToken, StorageConfigFileSystem, Utf8Path, VirtualPath, XattrLayout,
    };
    use crate::{CryptoMator, CryptomatorEntryStorage, GoCryptFs, GoCryptFsEntryStorage};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tempfile::tempdir;

    #[derive(Clone, Copy)]
    enum MatrixTokenKind {
        GoCryptFs,
        Cryptomator,
    }

    /// Configurable directory policy used to exercise storage permutations.
    struct MatrixDirectoryLayout {
        token_kind: MatrixTokenKind,
        detached: bool,
    }

    impl DirectoryContentLayout for MatrixDirectoryLayout {
        fn detached_directory_contents_path(
            &self,
            entry_path: &VirtualPath,
            token: &[u8],
        ) -> crate::core::Result<VirtualPathBuf> {
            if !self.detached {
                return Ok(entry_path.to_owned());
            }
            let name = URL_SAFE_NO_PAD.encode(Sha256::digest(token));
            Ok(VirtualPath::new("objects").join(name))
        }

        fn is_detached_directory_contents_path(&self, path: &VirtualPath) -> bool {
            self.detached
                && path
                    .as_str()
                    .strip_prefix("objects/")
                    .is_some_and(|name| !name.is_empty() && !name.contains('/'))
        }
    }

    impl DirectoryLayout for MatrixDirectoryLayout {
        fn generate_directory_token(&self) -> Vec<u8> {
            match self.token_kind {
                MatrixTokenKind::GoCryptFs => {
                    let mut token = vec![0; 16];
                    rand::fill(&mut token[..]);
                    token
                }
                MatrixTokenKind::Cryptomator => uuid::Uuid::new_v4().to_string().into_bytes(),
            }
        }

        fn validate_directory_token(&self, token: &[u8], is_root: bool) -> crate::core::Result<()> {
            match self.token_kind {
                MatrixTokenKind::GoCryptFs => {
                    anyhow::ensure!(token.len() == 16, "expected a 16-byte directory token");
                }
                MatrixTokenKind::Cryptomator if is_root && token.is_empty() => {}
                MatrixTokenKind::Cryptomator => {
                    uuid::Uuid::parse_str(std::str::from_utf8(token)?)?;
                }
            }
            Ok(())
        }

        fn root_directory_token(&self) -> RootDirectoryToken {
            match self.token_kind {
                MatrixTokenKind::GoCryptFs => RootDirectoryToken::Persisted,
                MatrixTokenKind::Cryptomator => RootDirectoryToken::Implicit(Vec::new()),
            }
        }
    }

    /// Creates a policy matching one crypto and one storage topology.
    fn matrix_layout(token_kind: MatrixTokenKind, detached: bool) -> Arc<dyn DirectoryLayout> {
        Arc::new(MatrixDirectoryLayout {
            token_kind,
            detached,
        })
    }

    /// Creates a nested directory tree and checks the selected storage topology.
    fn create_matrix_tree<T: EncryptionLayout>(
        backend: &T,
        detached: bool,
        expected_root_token_len: usize,
    ) {
        let root = backend
            .entry_storage()
            .resolve_directory(VirtualPath::root())
            .unwrap();
        assert_eq!(root.token.len(), expected_root_token_len);

        backend.mkdir(VirtualPath::new("docs"), None).unwrap();
        let entry_path = backend
            .plain_path_to_cipher(VirtualPath::new("docs"))
            .unwrap();
        let directory = backend
            .entry_storage()
            .resolve_directory(&entry_path)
            .unwrap();
        assert_eq!(directory.entry_path != directory.contents_path, detached);

        backend
            .mknode(VirtualPath::new("docs/note.txt"), None)
            .unwrap();
    }

    /// Verifies that a newly-opened composition can read the persisted tree.
    fn assert_matrix_tree<T: EncryptionLayout + 'static>(backend: T) {
        let entries = Arc::new(backend)
            .list_dir_plain_names(VirtualPath::new("docs"))
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.file_name, "note.txt");
    }

    /// Asserts that one composed crypto and storage type exposes the complete runtime layout.
    fn assert_encryption_layout<T: EncryptionLayout + XattrLayout>() {}

    #[test]
    fn crypto_layers_accept_the_opposite_entry_storage_type() {
        type GoCryptoWithC9rStorage =
            GoCryptFs<FsBackend<CryptomatorEntryStorage<NativeFileSystem>>>;
        type CryptomatorCryptoWithDirectStorage =
            CryptoMator<FsBackend<GoCryptFsEntryStorage<NativeFileSystem>>>;

        assert_encryption_layout::<GoCryptoWithC9rStorage>();
        assert_encryption_layout::<CryptomatorCryptoWithDirectStorage>();
    }

    #[test]
    fn go_crypto_with_direct_storage_reopens_directory_tree() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let config_storage = NativeFileSystem::new(root.clone());
        let config_fs = StorageConfigFileSystem::new(&config_storage);
        let directory_layout = matrix_layout(MatrixTokenKind::GoCryptFs, false);
        let backend = FsBackend::new(GoCryptFsEntryStorage::with_directory_layout(
            NativeFileSystem::new(root.clone()),
            directory_layout.clone(),
        ));
        GoCryptFs::init_with_backend(&backend, &config_fs, "password").unwrap();
        let cryptfs = GoCryptFs::try_new_with_backend(backend, &config_fs, "password").unwrap();
        create_matrix_tree(&cryptfs, false, 16);
        drop(cryptfs);

        let backend = FsBackend::new(GoCryptFsEntryStorage::with_directory_layout(
            NativeFileSystem::new(root),
            directory_layout,
        ));
        let reopened = GoCryptFs::try_new_with_backend(backend, &config_fs, "password").unwrap();
        assert_matrix_tree(reopened);
    }

    #[test]
    fn go_crypto_with_c9r_storage_reopens_directory_tree() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let config_storage = NativeFileSystem::new(root.clone());
        let config_fs = StorageConfigFileSystem::new(&config_storage);
        let directory_layout = matrix_layout(MatrixTokenKind::GoCryptFs, true);
        let backend = FsBackend::new(CryptomatorEntryStorage::new(
            NativeFileSystem::new(root.clone()),
            directory_layout.clone(),
        ));
        GoCryptFs::init_with_backend(&backend, &config_fs, "password").unwrap();
        let cryptfs = GoCryptFs::try_new_with_backend(backend, &config_fs, "password").unwrap();
        create_matrix_tree(&cryptfs, true, 16);
        drop(cryptfs);

        let backend = FsBackend::new(CryptomatorEntryStorage::new(
            NativeFileSystem::new(root),
            directory_layout,
        ));
        let reopened = GoCryptFs::try_new_with_backend(backend, &config_fs, "password").unwrap();
        assert_matrix_tree(reopened);
    }

    #[test]
    fn cryptomator_crypto_with_direct_storage_reopens_directory_tree() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let config_storage = NativeFileSystem::new(root.clone());
        let config_fs = StorageConfigFileSystem::new(&config_storage);
        let directory_layout = matrix_layout(MatrixTokenKind::Cryptomator, false);
        let backend = FsBackend::new(GoCryptFsEntryStorage::with_directory_layout(
            NativeFileSystem::new(root.clone()),
            directory_layout.clone(),
        ));
        CryptoMator::init_with_backend(&backend, &config_fs, "password").unwrap();
        let cryptfs = CryptoMator::try_new_with_backend(backend, &config_fs, "password").unwrap();
        create_matrix_tree(&cryptfs, false, 0);
        drop(cryptfs);

        let backend = FsBackend::new(GoCryptFsEntryStorage::with_directory_layout(
            NativeFileSystem::new(root),
            directory_layout,
        ));
        let reopened = CryptoMator::try_new_with_backend(backend, &config_fs, "password").unwrap();
        assert_matrix_tree(reopened);
    }

    #[test]
    fn cryptomator_crypto_with_c9r_storage_reopens_directory_tree() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let config_storage = NativeFileSystem::new(root.clone());
        let config_fs = StorageConfigFileSystem::new(&config_storage);
        let directory_layout = matrix_layout(MatrixTokenKind::Cryptomator, true);
        let backend = FsBackend::new(CryptomatorEntryStorage::new(
            NativeFileSystem::new(root.clone()),
            directory_layout.clone(),
        ));
        CryptoMator::init_with_backend(&backend, &config_fs, "password").unwrap();
        let cryptfs = CryptoMator::try_new_with_backend(backend, &config_fs, "password").unwrap();
        create_matrix_tree(&cryptfs, true, 0);
        drop(cryptfs);

        let backend = FsBackend::new(CryptomatorEntryStorage::new(
            NativeFileSystem::new(root),
            directory_layout,
        ));
        let reopened = CryptoMator::try_new_with_backend(backend, &config_fs, "password").unwrap();
        assert_matrix_tree(reopened);
    }
}
