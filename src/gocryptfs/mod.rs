use crate::core::Backend;

mod builder;
mod encryption_translator;
mod inner;
mod layout;
mod xattr_translator;

/// GoCryptFS backend with derived content and filename encryption keys.
pub struct GoCryptFs<T: Backend> {
    backend: T,
    /// AES-256-GCM key for file content (blocks)
    gcm_key: [u8; 32],
    /// AES-256-EME key for filename encryption
    eme_key: [u8; 32],
    /// base64 encoding of file names (Raw64 => no pad)
    raw64: bool,
}
pub use builder::GoCryptFsBuilder;
