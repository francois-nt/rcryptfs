#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
use anyhow::Result;
mod buffered_file;
mod cache;
mod daemonize;
mod file;
mod filesystem;
mod gocryptfs;
pub mod platform;
mod traits;
mod types;
pub use buffered_file::BufferedFile;
pub use cache::{CacheLock, UnsafeCache};
pub use daemonize::{
    SetBackgroundChild, is_background_child, respawn_in_background, wait_child_mounted,
};
pub use file::CryptFsFile;
pub use filesystem::{
    EncryptedFileTranslator, FileCache, FileSystemBuilder, FileSystemFactory, NoCache,
};
pub use gocryptfs::GoCryptFs;
pub use traits::*;
pub use types::*;

#[cfg(unix)]
mod fuse_impl;

pub fn is_dir_empty(path: &Utf8Path) -> std::io::Result<bool> {
    Ok(std::fs::read_dir(path)?.next().is_none())
}
