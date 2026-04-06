use crate::{FileCachePolicy, FileSystem, Result, Utf8Path};
use linkme::distributed_slice;

/// Builds a filesystem implementation for a backend that recognizes a cipher root.
pub trait BackendProvider: Send + Sync + 'static {
    fn probe(&self, root: &Utf8Path) -> bool;
    fn try_build(
        &self,
        root: &Utf8Path,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>>;
}

/// Registry of backend providers linked into the current binary.
#[distributed_slice]
pub static PROVIDERS: [&dyn BackendProvider];

/// Registers a backend provider in the global provider registry.
#[macro_export]
macro_rules! register_provider {
    ($provider:ident) => {
        ::paste::paste! {
            #[::linkme::distributed_slice($crate::backend_provider::PROVIDERS)]
            static [<$provider:upper>]: &dyn $crate::BackendProvider = &$provider;
        }
    };
}

/// Builds the first filesystem whose provider recognizes the requested root.
pub fn build_filesystem(
    root_path: &Utf8Path,
    password: &str,
    cache_policy: impl FileCachePolicy,
) -> Result<Box<dyn FileSystem>> {
    for &provider in PROVIDERS {
        if provider.probe(root_path) {
            return provider.try_build(root_path, password, Box::new(cache_policy));
        }
    }
    anyhow::bail!("unknown filesystem!");
}
