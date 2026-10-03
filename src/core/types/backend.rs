use crate::core::{
    Backend, DirectoryLayout, PathCacheAccess, StorageDirectoryId, VirtualPath, VirtualPathBuf,
};
use parking_lot::{Condvar, Mutex};
use std::{
    collections::BTreeMap,
    future::poll_fn,
    sync::Arc,
    task::{Poll, Waker},
};

/// Cached cryptographic token, stable contents path, and storage identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CipherPathCacheEntry {
    /// Opaque token used to encode children of this directory.
    pub token: Vec<u8>,
    /// Stable physical directory containing the encoded children.
    pub contents_path: crate::core::ResolvedStoragePathBuf,
    /// Storage identity expected when accessing those children.
    pub contents_id: StorageDirectoryId,
}

#[derive(Default)]
struct PathCacheState {
    next_snapshot: u64,
    snapshots: BTreeMap<u64, ActiveSnapshot>,
    mutations: Vec<VirtualPathBuf>,
    entries: BTreeMap<VirtualPathBuf, CipherPathCacheEntry>,
    waiters: Vec<Waker>,
}

/// Resolution registered while storage I/O runs without the cache lock.
struct ActiveSnapshot {
    path: VirtualPathBuf,
    invalidated: bool,
}

/// Cache of resolved plain directory paths shared by sync and async layouts.
#[derive(Default)]
pub struct PathCache {
    state: Mutex<PathCacheState>,
    stable: Condvar,
}

/// Snapshot used to publish a resolution only if its path stayed stable.
pub struct PathCacheSnapshot<'a> {
    cache: &'a PathCache,
    id: u64,
    active: bool,
}

/// Result of reading an entry through a cache snapshot.
pub enum CacheLookup {
    /// The requested directory was cached by this snapshot.
    Hit(CipherPathCacheEntry),
    /// The requested directory must be resolved from entry storage.
    Miss,
    /// The resolved path changed after this snapshot was acquired.
    Invalidated,
}

/// Result of publishing entries through a cache snapshot.
pub enum CacheCommit {
    /// Every staged resolution was published or already cached identically.
    Committed,
    /// The resolved path changed before the staged entries could be published.
    Invalidated,
    /// Another resolution produced a different entry for this plain path.
    Conflict(VirtualPathBuf),
}

/// Invalidates cached paths around one namespace mutation.
pub struct PathCacheMutation<'a> {
    cache: &'a PathCache,
    paths: Vec<VirtualPathBuf>,
}

impl PathCache {
    /// Waits synchronously until no relevant namespace mutation is running.
    pub fn snapshot_blocking(&self, path: &VirtualPath) -> PathCacheSnapshot<'_> {
        let mut state = self.state.lock();
        while has_relevant_mutation(&state, path) {
            self.stable.wait(&mut state);
        }
        let id = state.register_snapshot(path.to_owned());
        PathCacheSnapshot {
            cache: self,
            id,
            active: true,
        }
    }

    /// Waits asynchronously until no relevant namespace mutation is running.
    pub async fn snapshot_async(&self, path: &VirtualPath) -> PathCacheSnapshot<'_> {
        let path = path.to_owned();
        let id = poll_fn(|context| {
            let mut state = self.state.lock();
            if has_relevant_mutation(&state, &path) {
                if !state
                    .waiters
                    .iter()
                    .any(|waiter| waiter.will_wake(context.waker()))
                {
                    state.waiters.push(context.waker().clone());
                }
                Poll::Pending
            } else {
                Poll::Ready(state.register_snapshot(path.clone()))
            }
        })
        .await;
        PathCacheSnapshot {
            cache: self,
            id,
            active: true,
        }
    }

    /// Invalidates paths before and after a namespace mutation.
    /// Path resolution must complete before this guard is acquired.
    pub fn begin_mutation(&self, paths: &[&VirtualPath]) -> PathCacheMutation<'_> {
        let paths = paths
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<Vec<_>>();
        let mut state = self.state.lock();
        state.mutations.extend(paths.iter().cloned());
        for path in &paths {
            invalidate_snapshots(&mut state.snapshots, path);
            invalidate_subtree(&mut state.entries, path);
        }
        drop(state);
        PathCacheMutation { cache: self, paths }
    }

    /// Invalidates one cached path and every cached descendant.
    pub fn invalidate(&self, path: &VirtualPath) {
        let mut state = self.state.lock();
        invalidate_snapshots(&mut state.snapshots, path);
        invalidate_subtree(&mut state.entries, path);
    }

    fn finish_mutation(&self, paths: &[VirtualPathBuf]) {
        let waiters = {
            let mut state = self.state.lock();
            for path in paths {
                invalidate_subtree(&mut state.entries, path);
                if let Some(index) = state.mutations.iter().position(|active| active == path) {
                    state.mutations.swap_remove(index);
                }
            }
            self.stable.notify_all();
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }
}

impl PathCacheState {
    fn register_snapshot(&mut self, path: VirtualPathBuf) -> u64 {
        let id = self.next_snapshot;
        self.next_snapshot = self.next_snapshot.wrapping_add(1);
        let _ = self.snapshots.insert(
            id,
            ActiveSnapshot {
                path,
                invalidated: false,
            },
        );
        id
    }
}

impl PathCacheSnapshot<'_> {
    /// Reads one entry if this snapshot is still current.
    pub fn lookup(&self, path: &VirtualPath) -> CacheLookup {
        let state = self.cache.state.lock();
        if state
            .snapshots
            .get(&self.id)
            .is_none_or(|snapshot| snapshot.invalidated)
        {
            CacheLookup::Invalidated
        } else {
            state
                .entries
                .get(path)
                .cloned()
                .map_or(CacheLookup::Miss, CacheLookup::Hit)
        }
    }

    /// Publishes completed resolutions if this snapshot is still current.
    pub fn commit(mut self, staged: Vec<(VirtualPathBuf, CipherPathCacheEntry)>) -> CacheCommit {
        let mut state = self.cache.state.lock();
        let conflict = staged.iter().find_map(|(path, candidate)| {
            state
                .entries
                .get(path)
                .filter(|existing| *existing != candidate)
                .map(|_| path.clone())
        });
        let result = if state.snapshots[&self.id].invalidated {
            CacheCommit::Invalidated
        } else if let Some(path) = conflict {
            invalidate_snapshots(&mut state.snapshots, &path);
            invalidate_subtree(&mut state.entries, &path);
            CacheCommit::Conflict(path)
        } else {
            for (path, entry) in staged {
                state.entries.entry(path).or_insert(entry);
            }
            CacheCommit::Committed
        };
        state.snapshots.remove(&self.id);
        drop(state);
        self.active = false;
        result
    }
}

impl Drop for PathCacheSnapshot<'_> {
    fn drop(&mut self) {
        if self.active {
            self.cache.state.lock().snapshots.remove(&self.id);
        }
    }
}

impl Drop for PathCacheMutation<'_> {
    fn drop(&mut self) {
        self.cache.finish_mutation(&self.paths);
    }
}

fn has_relevant_mutation(state: &PathCacheState, path: &VirtualPath) -> bool {
    state
        .mutations
        .iter()
        .any(|mutation| mutation.is_ancestor_or_same(path))
}

fn invalidate_snapshots(snapshots: &mut BTreeMap<u64, ActiveSnapshot>, path: &VirtualPath) {
    for snapshot in snapshots.values_mut() {
        snapshot.invalidated |= path.is_ancestor_or_same(&snapshot.path);
    }
}

fn invalidate_subtree(
    entries: &mut BTreeMap<VirtualPathBuf, CipherPathCacheEntry>,
    path: &VirtualPath,
) {
    let mut tail = entries.split_off(&path.to_owned());
    if let Some(end) = tail
        .keys()
        .find(|candidate| !path.is_ancestor_or_same(candidate))
        .cloned()
    {
        let mut after = tail.split_off(&end);
        entries.append(&mut after);
    }
}

/// Backend state shared by one encrypted layout.
pub struct EntryStorageBackend<S, L: DirectoryLayout> {
    entry_storage: S,
    directory_layout: Arc<L>,
    path_cache: PathCache,
}

impl<S, L: DirectoryLayout> EntryStorageBackend<S, L> {
    /// Creates a backend from an entry storage and its shared directory policy.
    pub fn new(entry_storage: S, directory_layout: Arc<L>) -> Self {
        Self {
            entry_storage,
            directory_layout,
            path_cache: Default::default(),
        }
    }

    /// Returns the entry storage owned by this backend.
    pub fn entry_storage(&self) -> &S {
        &self.entry_storage
    }

    /// Returns the directory policy shared by the composed layout.
    pub fn directory_layout(&self) -> &L {
        self.directory_layout.as_ref()
    }

    /// Returns the shared plain-to-cipher path cache.
    pub fn path_cache(&self) -> &PathCache {
        &self.path_cache
    }
}

impl<S, L: DirectoryLayout> PathCacheAccess for EntryStorageBackend<S, L> {
    fn path_cache(&self) -> &PathCache {
        &self.path_cache
    }
}

impl<S, L: DirectoryLayout> Backend for EntryStorageBackend<S, L> {}

/// In-memory backend for testing.
#[derive(Default)]
pub struct MemoryBackend;

impl Backend for MemoryBackend {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        DirectoryContentLayout, DirectoryLayout, EncryptionLayout, EntryStorage, NativeFileSystem,
        ResolvedStoragePath, ResolvedStoragePathBuf, RootDirectoryToken, StorageConfigFileSystem,
        Utf8Path, VirtualPath, VirtualPathBuf, XattrLayout,
    };
    use crate::{CryptoMator, CryptomatorEntryStorage, GoCryptFs, GoCryptFsEntryStorage};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use futures_util::task::noop_waker;
    use sha2::{Digest, Sha256};
    use std::{future::Future, sync::Arc, task::Context};
    use tempfile::tempdir;

    fn cache_entry(token: u8, path: impl Into<VirtualPathBuf>) -> CipherPathCacheEntry {
        CipherPathCacheEntry {
            token: vec![token],
            contents_path: ResolvedStoragePathBuf::new(path.into(), StorageDirectoryId::default()),
            contents_id: StorageDirectoryId::default(),
        }
    }

    #[test]
    fn path_cache_commits_and_invalidates_directory_subtrees() {
        let cache = PathCache::default();
        let snapshot = cache.snapshot_blocking(VirtualPath::new("docs/nested"));
        assert!(matches!(
            snapshot.lookup(VirtualPath::root()),
            CacheLookup::Miss
        ));
        assert!(matches!(
            snapshot.commit(vec![
                (
                    VirtualPathBuf::default(),
                    cache_entry(0, VirtualPathBuf::default()),
                ),
                ("docs".into(), cache_entry(1, "cipher-docs")),
                (
                    "docs/nested".into(),
                    cache_entry(2, "cipher-docs/cipher-nested"),
                ),
                ("docs!".into(), cache_entry(3, "cipher-docs-sibling")),
            ]),
            CacheCommit::Committed
        ));

        cache.invalidate(VirtualPath::new("docs"));
        let snapshot = cache.snapshot_blocking(VirtualPath::new("docs/nested"));
        assert!(matches!(
            snapshot.lookup(VirtualPath::root()),
            CacheLookup::Hit(_)
        ));
        assert!(matches!(
            snapshot.lookup(VirtualPath::new("docs")),
            CacheLookup::Miss
        ));
        assert!(matches!(
            snapshot.lookup(VirtualPath::new("docs/nested")),
            CacheLookup::Miss
        ));
        assert!(matches!(
            snapshot.lookup(VirtualPath::new("docs!")),
            CacheLookup::Hit(_)
        ));
    }

    #[test]
    fn async_path_cache_snapshot_waits_for_mutations() {
        let cache = PathCache::default();
        let mutation = cache.begin_mutation(&[VirtualPath::new("docs")]);
        let mut affected = Box::pin(cache.snapshot_async(VirtualPath::new("docs/nested")));
        let mut unrelated = Box::pin(cache.snapshot_async(VirtualPath::new("documents")));
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        assert!(affected.as_mut().poll(&mut context).is_pending());
        assert!(unrelated.as_mut().poll(&mut context).is_ready());
        drop(mutation);
        assert!(affected.as_mut().poll(&mut context).is_ready());
    }

    #[test]
    fn path_cache_only_invalidates_affected_snapshots() {
        let cache = PathCache::default();
        let affected = cache.snapshot_blocking(VirtualPath::new("docs/nested"));
        let unrelated = cache.snapshot_blocking(VirtualPath::new("documents"));
        let mutation = cache.begin_mutation(&[VirtualPath::new("docs")]);

        assert!(matches!(
            affected.lookup(VirtualPath::root()),
            CacheLookup::Invalidated
        ));
        assert!(matches!(
            unrelated.lookup(VirtualPath::root()),
            CacheLookup::Miss
        ));
        assert!(matches!(
            unrelated.commit(Vec::new()),
            CacheCommit::Committed
        ));
        assert!(matches!(
            affected.commit(Vec::new()),
            CacheCommit::Invalidated
        ));
        drop(mutation);
        assert!(cache.state.lock().snapshots.is_empty());
    }

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
    fn matrix_layout(token_kind: MatrixTokenKind, detached: bool) -> Arc<MatrixDirectoryLayout> {
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
        let root_id = backend.entry_storage().get_root_id().unwrap();
        let root = backend
            .entry_storage()
            .resolve_directory(ResolvedStoragePath::new(VirtualPath::root(), &root_id))
            .unwrap();
        assert_eq!(root.token.len(), expected_root_token_len);

        backend.mkdir(VirtualPath::new("docs"), None).unwrap();
        let entry_path = backend
            .plain_path_to_cipher(VirtualPath::new("docs"))
            .unwrap();
        let directory = backend
            .entry_storage()
            .resolve_directory(entry_path.as_resolved_path())
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
        type GoCryptoWithC9rStorage = GoCryptFs<
            EntryStorageBackend<
                CryptomatorEntryStorage<NativeFileSystem, MatrixDirectoryLayout>,
                MatrixDirectoryLayout,
            >,
        >;
        type CryptomatorCryptoWithDirectStorage = CryptoMator<
            EntryStorageBackend<
                GoCryptFsEntryStorage<NativeFileSystem, MatrixDirectoryLayout>,
                MatrixDirectoryLayout,
            >,
        >;

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
        let backend = EntryStorageBackend::new(
            GoCryptFsEntryStorage::with_directory_layout(
                NativeFileSystem::new(root.clone()),
                directory_layout.clone(),
            ),
            directory_layout.clone(),
        );
        GoCryptFs::init_with_backend(&backend, &config_fs, "password").unwrap();
        let cryptfs = GoCryptFs::try_new_with_backend(backend, &config_fs, "password").unwrap();
        create_matrix_tree(&cryptfs, false, 16);
        drop(cryptfs);

        let backend = EntryStorageBackend::new(
            GoCryptFsEntryStorage::with_directory_layout(
                NativeFileSystem::new(root),
                directory_layout.clone(),
            ),
            directory_layout,
        );
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
        let backend = EntryStorageBackend::new(
            CryptomatorEntryStorage::new(
                NativeFileSystem::new(root.clone()),
                directory_layout.clone(),
            ),
            directory_layout.clone(),
        );
        GoCryptFs::init_with_backend(&backend, &config_fs, "password").unwrap();
        let cryptfs = GoCryptFs::try_new_with_backend(backend, &config_fs, "password").unwrap();
        create_matrix_tree(&cryptfs, true, 16);
        drop(cryptfs);

        let backend = EntryStorageBackend::new(
            CryptomatorEntryStorage::new(NativeFileSystem::new(root), directory_layout.clone()),
            directory_layout,
        );
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
        let backend = EntryStorageBackend::new(
            GoCryptFsEntryStorage::with_directory_layout(
                NativeFileSystem::new(root.clone()),
                directory_layout.clone(),
            ),
            directory_layout.clone(),
        );
        CryptoMator::init_with_backend(&backend, &config_fs, "password").unwrap();
        let cryptfs = CryptoMator::try_new_with_backend(backend, &config_fs, "password").unwrap();
        create_matrix_tree(&cryptfs, false, 0);
        drop(cryptfs);

        let backend = EntryStorageBackend::new(
            GoCryptFsEntryStorage::with_directory_layout(
                NativeFileSystem::new(root),
                directory_layout.clone(),
            ),
            directory_layout,
        );
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
        let backend = EntryStorageBackend::new(
            CryptomatorEntryStorage::new(
                NativeFileSystem::new(root.clone()),
                directory_layout.clone(),
            ),
            directory_layout.clone(),
        );
        CryptoMator::init_with_backend(&backend, &config_fs, "password").unwrap();
        let cryptfs = CryptoMator::try_new_with_backend(backend, &config_fs, "password").unwrap();
        create_matrix_tree(&cryptfs, true, 0);
        drop(cryptfs);

        let backend = EntryStorageBackend::new(
            CryptomatorEntryStorage::new(NativeFileSystem::new(root), directory_layout.clone()),
            directory_layout,
        );
        let reopened = CryptoMator::try_new_with_backend(backend, &config_fs, "password").unwrap();
        assert_matrix_tree(reopened);
    }
}
