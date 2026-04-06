#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
use anyhow::Result;
mod backend_provider;
mod buffered_file;
mod cache;
mod cryptomator;
mod daemonize;
mod file;
mod filesystem;
mod gocryptfs;
pub mod platform;
mod traits;
mod types;
pub use backend_provider::{BackendProvider, build_filesystem};
pub use buffered_file::BufferedFile;
pub use cache::{CacheLock, UnsafeCache};
pub use cryptomator::{CryptoMator, CryptoMatorBuilder};
pub use daemonize::{
    SetBackgroundChild, is_background_child, respawn_in_background, wait_child_mounted,
};
pub use file::CryptFsFile;
pub use filesystem::{EncryptedFileTranslator, FileCache, FileCachePolicy, NoCache};
pub use gocryptfs::{GoCryptFs, GoCryptFsBuilder};
pub use traits::*;
pub use types::*;

#[cfg(unix)]
mod fuse_impl;

/// Returns whether a directory contains no entries.
pub fn is_dir_empty(path: &Utf8Path) -> std::io::Result<bool> {
    Ok(std::fs::read_dir(path)?.next().is_none())
}
