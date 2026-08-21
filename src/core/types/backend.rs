use super::DefaultFs;
use crate::core::{Backend, CacheAccess, MinimalFs, VirtualPathBuf};
use camino::{Utf8Path, Utf8PathBuf};
use parking_lot::Mutex;
use std::collections::BTreeMap;

pub type FsCacheEntry = (Vec<u8>, VirtualPathBuf);

/// Backend state shared by one encrypted layout.
pub struct FsBackend<F: MinimalFs = DefaultFs> {
    fs: F,
    cache: Mutex<BTreeMap<String, FsCacheEntry>>,
}

impl<F: MinimalFs> FsBackend<F> {
    /// Creates a backend backed by the provided rooted storage implementation.
    pub fn new(fs: F) -> Self {
        Self {
            fs,
            cache: Default::default(),
        }
    }
}

impl<F: MinimalFs> CacheAccess for FsBackend<F> {
    /// Gives temporary mutable access to the plain-to-cipher path cache.
    fn access<Res, Op: FnOnce(&mut BTreeMap<String, FsCacheEntry>) -> Res>(&self, f: Op) -> Res {
        f(&mut self.cache.lock())
    }
}

impl From<Utf8PathBuf> for FsBackend {
    fn from(value: Utf8PathBuf) -> Self {
        Self::new(DefaultFs::new(value))
    }
}

impl From<&Utf8Path> for FsBackend {
    fn from(value: &Utf8Path) -> Self {
        Self::new(DefaultFs::new(value.into()))
    }
}

impl<F: MinimalFs> Backend for FsBackend<F> {
    type LowerFs = F;

    fn get_fs(&self) -> &F {
        &self.fs
    }
}

/// In-memory backend for testing.
#[derive(Default)]
pub struct MemoryBackend {
    fs: DefaultFs,
}

impl Backend for MemoryBackend {
    type LowerFs = DefaultFs;

    fn get_fs(&self) -> &DefaultFs {
        &self.fs
    }
}
