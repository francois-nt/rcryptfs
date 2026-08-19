mod backend_provider;
mod buffered_file;
mod cache;
mod file;
mod filesystem;
mod traits;
mod types;
pub use anyhow::Result;
pub use backend_provider::{
    BackendProvider, MasterKey, PROVIDERS, build_filesystem, get_providers_name, init_filesystem,
};
pub use buffered_file::BufferedFile;
pub use cache::{CacheLock, UnsafeCache};
pub use file::CryptFsFile;
pub use filesystem::{EncryptedFileTranslator, FileCache, FileCachePolicy, NoCache};
pub(crate) use traits::temp_file_path;
pub use traits::*;
pub use types::*;

/// Returns whether a directory contains no entries.
pub fn is_dir_empty(path: &Utf8Path) -> std::io::Result<bool> {
    DefaultFs.is_dir_empty(path)
}
