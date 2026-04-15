mod builder;
mod encryption_translator;
mod inner;
mod layout;
use crate::core::Backend;

const HEADER_NONCE_LEN: usize = 12;
const NONCE_LEN: usize = 12;

/// Cryptomator backend state with the derived SIV key material.
pub struct CryptoMator<T: Backend> {
    backend: T,
    siv_key: [u8; 64],
}

pub use builder::CryptoMatorBuilder;
