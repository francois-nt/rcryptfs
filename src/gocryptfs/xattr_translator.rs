use super::GoCryptFs;
use crate::{Backend, EncryptionTranslator, Result, XattrTranslator};

const XATTR_IV: &[u8] = b"xattr_name_iv_xx";
const XATTR_NAME_PREFIX: &str = "user.gocryptfs.";

impl<T: Backend> XattrTranslator for GoCryptFs<T> {
    /// Converts a plain extended attribute name to cipher text.
    fn plain_xattr_name_to_cipher(&self, plain_xattr_name: &str) -> Result<String> {
        if plain_xattr_name.starts_with("user.") {
            Ok(format!(
                "{XATTR_NAME_PREFIX}{}",
                self.plain_name_to_cipher(XATTR_IV, plain_xattr_name)?
            ))
        } else {
            Ok(plain_xattr_name.into())
        }
    }
    /// Converts a cipher extended attribute name to plain text.
    fn cipher_xattr_name_to_plain(&self, cipher_xattr_name: &str) -> Result<String> {
        if let Some(cipher_xattr_name) = cipher_xattr_name.strip_prefix(XATTR_NAME_PREFIX) {
            self.cipher_name_to_plain(XATTR_IV, cipher_xattr_name)
        } else {
            Ok(cipher_xattr_name.into())
        }
    }
    /// Encrypts a plain extended attribute value.
    fn plain_xattr_value_to_cipher(&self, plain_xattr_value: &[u8]) -> Result<Vec<u8>> {
        self.plain_block_to_cipher(&[], 0, plain_xattr_value)
    }
    /// Decrypts a cipher extended attribute value.
    fn cipher_xattr_value_to_plain(&self, cipher_xattr_value: &[u8]) -> Result<Vec<u8>> {
        self.cipher_block_to_plain(&[], 0, cipher_xattr_value)
    }
}
