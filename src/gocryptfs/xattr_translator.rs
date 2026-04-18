use super::GoCryptFs;
use crate::core::{CipherPathLayout, EncryptionTranslator, FsBackend, OrIoError, XattrLayout};

const XATTR_IV: &[u8] = b"xattr_name_iv_xx";
const XATTR_NAME_PREFIX: &str = "user.gocryptfs.";

/// Converts a plain extended attribute name to cipher text.
fn plain_xattr_name_to_cipher(
    this: &impl EncryptionTranslator,
    plain_xattr_name: &str,
) -> std::io::Result<String> {
    if plain_xattr_name.starts_with("user.") {
        Ok(format!(
            "{XATTR_NAME_PREFIX}{}",
            this.plain_name_to_cipher(XATTR_IV, plain_xattr_name)
                .or_invalid()?
        ))
    } else {
        Ok(plain_xattr_name.into())
    }
}
/// Converts a cipher extended attribute name to plain text.
fn cipher_xattr_name_to_plain(
    this: &impl EncryptionTranslator,
    cipher_xattr_name: &str,
) -> std::io::Result<String> {
    if let Some(cipher_xattr_name) = cipher_xattr_name.strip_prefix(XATTR_NAME_PREFIX) {
        this.cipher_name_to_plain(XATTR_IV, cipher_xattr_name)
            .or_invalid()
    } else {
        Ok(cipher_xattr_name.into())
    }
}
/// Encrypts a plain extended attribute value.
fn plain_xattr_value_to_cipher(
    this: &impl EncryptionTranslator,
    plain_xattr_value: &[u8],
) -> std::io::Result<Vec<u8>> {
    this.plain_block_to_cipher(&[], 0, plain_xattr_value)
        .or_invalid()
}
/// Decrypts a cipher extended attribute value.
fn cipher_xattr_value_to_plain(
    this: &impl EncryptionTranslator,
    cipher_xattr_value: &[u8],
) -> std::io::Result<Vec<u8>> {
    this.cipher_block_to_plain(&[], 0, cipher_xattr_value)
        .or_invalid()
}

impl XattrLayout for GoCryptFs<FsBackend> {
    fn get_xattr(&self, path: &str, name: &str) -> std::io::Result<Vec<u8>> {
        let cipher_path = self.plain_path_to_cipher(path.into()).or_invalid()?;
        let cipher_name = plain_xattr_name_to_cipher(self, name).or_invalid()?;

        let cipher_xattr_value =
            xattr::get(cipher_path, cipher_name)?.or_io_error(libc::ENODATA)?;
        cipher_xattr_value_to_plain(self, &cipher_xattr_value).or_invalid()
    }
    fn set_xattr(&self, path: &str, name: &str, value: &[u8]) -> std::io::Result<()> {
        let cipher_path = self.plain_path_to_cipher(path.into()).or_invalid()?;
        let cipher_name = plain_xattr_name_to_cipher(self, name).or_invalid()?;
        let cipher_xattr_value = plain_xattr_value_to_cipher(self, value).or_invalid()?;
        xattr::set(cipher_path, cipher_name, &cipher_xattr_value)
    }
    fn remove_xattr(&self, path: &str, name: &str) -> std::io::Result<()> {
        let cipher_path = self.plain_path_to_cipher(path.into()).or_invalid()?;
        let cipher_name = plain_xattr_name_to_cipher(self, name).or_invalid()?;
        xattr::remove(cipher_path, cipher_name)
    }
    fn list_xattr(&self, path: &str) -> std::io::Result<Vec<String>> {
        let cipher_path = self.plain_path_to_cipher(path.into()).or_invalid()?;
        Ok(xattr::list(cipher_path)?
            .flat_map(move |s| {
                s.to_str()
                    .and_then(|s| cipher_xattr_name_to_plain(self, s).ok())
            })
            .collect())
    }
}
