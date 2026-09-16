mod builder;
mod encryption_translator;
mod entry_storage;
mod inner;
mod layout;
use crate::core::{Backend, FsBackend, NativeFileSystem};

const HEADER_NONCE_LEN: usize = 12;
const NONCE_LEN: usize = 12;

/// Cryptomator backend state with the derived SIV key material.
pub struct CryptoMator<T: Backend = CryptomatorBackend> {
    backend: T,
    siv_key: [u8; 64],
}

pub use builder::CryptoMatorBuilder;
pub use entry_storage::CryptomatorEntryStorage;

/// Backend using the Cryptomator entry representation.
pub type CryptomatorBackend<F = NativeFileSystem> = FsBackend<CryptomatorEntryStorage<F>>;
