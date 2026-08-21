use super::NativeFileSystem;
use crate::core::{Backend, PathCacheAccess, StorageFileSystem, VirtualPathBuf};
use camino::{Utf8Path, Utf8PathBuf};
use parking_lot::Mutex;
use std::collections::BTreeMap;

/// Cached directory identifier and resolved cipher path.
pub type CipherPathCacheEntry = (Vec<u8>, VirtualPathBuf);

/// Backend state shared by one encrypted layout.
pub struct FsBackend<F: StorageFileSystem = NativeFileSystem> {
    fs: F,
    path_cache: Mutex<BTreeMap<String, CipherPathCacheEntry>>,
}

impl<F: StorageFileSystem> FsBackend<F> {
    /// Creates a backend backed by the provided rooted storage implementation.
    pub fn new(fs: F) -> Self {
        Self {
            fs,
            path_cache: Default::default(),
        }
    }
}

impl<F: StorageFileSystem> PathCacheAccess for FsBackend<F> {
    /// Gives temporary mutable access to the plain-to-cipher path cache.
    fn with_path_cache<Res, Op: FnOnce(&mut BTreeMap<String, CipherPathCacheEntry>) -> Res>(
        &self,
        f: Op,
    ) -> Res {
        f(&mut self.path_cache.lock())
    }
}

impl From<Utf8PathBuf> for FsBackend {
    fn from(value: Utf8PathBuf) -> Self {
        Self::new(NativeFileSystem::new(value))
    }
}

impl From<&Utf8Path> for FsBackend {
    fn from(value: &Utf8Path) -> Self {
        Self::new(NativeFileSystem::new(value.into()))
    }
}

impl<F: StorageFileSystem> Backend for FsBackend<F> {
    type LowerFs = F;

    fn get_fs(&self) -> &F {
        &self.fs
    }
}

/// In-memory backend for testing.
#[derive(Default)]
pub struct MemoryBackend {
    fs: NativeFileSystem,
}

impl Backend for MemoryBackend {
    type LowerFs = NativeFileSystem;

    fn get_fs(&self) -> &NativeFileSystem {
        &self.fs
    }
}
