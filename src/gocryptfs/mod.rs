use crate::core::{Backend, DirectoryLayout, FsBackend, NativeFileSystem};
use std::sync::Arc;

mod builder;
mod encryption_translator;
mod entry_storage;
mod inner;
mod layout;
mod xattr_translator;

/// GoCryptFS backend with derived content and filename encryption keys.
pub struct GoCryptFs<T: Backend = GoCryptFsBackend> {
    backend: T,
    directory_layout: Arc<dyn DirectoryLayout>,
    /// AES-256-GCM key for file content (blocks)
    gcm_key: [u8; 32],
    /// AES-256-EME key for filename encryption
    eme_key: [u8; 32],
    /// base64 encoding of file names (Raw64 => no pad)
    raw64: bool,
}
pub use builder::GoCryptFsBuilder;
pub use entry_storage::{GoCryptFsEntryStorage, GoCryptFsEntryStorageOptions};

/// Backend using the GoCryptFS entry representation.
pub type GoCryptFsBackend<F = NativeFileSystem> = FsBackend<GoCryptFsEntryStorage<F>>;
