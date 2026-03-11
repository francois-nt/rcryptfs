#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
use anyhow::Result;
mod buffered_file;
mod cache;
mod file;
mod filesystem;
mod gocryptfs;
mod traits;
mod types;
pub use buffered_file::BufferedFile;
pub use cache::{CacheLock, UnsafeCache};
pub use file::CryptFsFile;
pub use filesystem::{
    EncryptedFileTranslator, FileCache, FileSystemBuilder, FileSystemFactory, NoCache,
};
pub use gocryptfs::GoCryptFs;
pub use traits::*;
pub use types::*;

#[cfg(not(windows))]
mod fuse_impl;
