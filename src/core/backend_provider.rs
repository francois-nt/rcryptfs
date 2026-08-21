use super::{FileCachePolicy, FileSystem, Result, Utf8Path};
use linkme::distributed_slice;

pub trait MasterKey {
    fn to_vec(&self) -> Vec<u8>;
    fn to_formatted_bytes(&self) -> String {
        let lines = self
            .to_vec()
            .chunks(16)
            .map(|line| {
                line.chunks(4)
                    .map(|chunk| {
                        chunk
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<String>()
                    })
                    .collect::<Vec<_>>()
                    .join("-")
            })
            .collect::<Vec<_>>()
            .join("-\n    ");
        format!("    {lines}\n")
    }
}

/// Builds a filesystem implementation for a backend that recognizes a cipher root.
pub trait BackendProvider: Send + Sync {
    fn init_with_default_params(
        &self,
        root: &Utf8Path,
        password: &str,
    ) -> Result<Box<dyn MasterKey>>;
    fn name(&self) -> &'static str;
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
            #[::linkme::distributed_slice($crate::core::PROVIDERS)]
            static [<$provider:upper>]: &dyn $crate::core::BackendProvider = &$provider;
        }
    };
}

/// Builds the first filesystem whose provider recognizes the requested root.
pub fn build_filesystem(
    root_path: &Utf8Path,
    password: &str,
    cache_policy: impl FileCachePolicy + 'static,
) -> Result<Box<dyn FileSystem>> {
    for &provider in PROVIDERS {
        if provider.probe(root_path) {
            return provider.try_build(root_path, password, Box::new(cache_policy));
        }
    }
    anyhow::bail!("unknown filesystem!");
}

pub fn init_filesystem(
    root_path: &Utf8Path,
    password: &str,
    name: &str,
) -> Result<Box<dyn MasterKey>> {
    for &provider in PROVIDERS {
        if provider.name() == name {
            return provider.init_with_default_params(root_path, password);
        }
    }
    anyhow::bail!("filesystem {name} unknown!");
}

pub fn get_providers_name() -> Vec<&'static str> {
    PROVIDERS.iter().map(|p| p.name()).collect()
}
