#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
pub mod core;
mod cryptomator;
mod daemonize;
mod gocryptfs;
pub mod platform;
pub use core::{JoinVirtualPath, Utf8Path, Utf8PathBuf, VirtualPath, VirtualPathBuf};
pub use cryptomator::{
    CryptoMator, CryptoMatorBuilder, CryptomatorBackend, CryptomatorEntryStorage,
};
pub use daemonize::{
    SetBackgroundChild, is_background_child, respawn_in_background, wait_child_mounted,
};
pub use gocryptfs::{
    GoCryptFs, GoCryptFsBackend, GoCryptFsBuilder, GoCryptFsEntryStorage,
    GoCryptFsEntryStorageOptions,
};

#[cfg(unix)]
mod fuse_impl;
