use crate::{
    Backend, CipherPathLayout, EncryptionTranslator, FsBackend, MinimalFs, Result, Utf8Path,
    Utf8PathBuf, XattrTranslator,
};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, Payload},
};
use aes_kw::KekAes256;
use aes_siv::aead::KeyInit;
use aes_siv::siv::Aes256Siv;
use anyhow::{Context, anyhow, bail};
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use scrypt::{Params as ScryptParams, scrypt};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use unicode_normalization::UnicodeNormalization;

mod encryption_translator;
mod layout;
pub struct CryptoMator<T: Backend> {
    backend: T,
    siv_key: [u8; 64],
}

/// Reads the directory id vector from a cipher directory.
fn read_dirid(cipher_dir: &Utf8Path) -> Result<String> {
    let p = cipher_dir.join("dir.c9r");
    let data = std::fs::read_to_string(&p).context(format!("read {:?}", p))?;
    if data.len() != 36 {
        return Err(anyhow!("dirid has len {}, expected 36", data.len()));
    }
    Ok(data)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CryptoMatorConfig {
    version: u32,
    scrypt_salt: String,
    scrypt_cost_param: u32,
    scrypt_block_size: u32,
    primary_master_key: String,
    hmac_master_key: String,
    version_mac: String,
}

struct MasterKeys {
    primary_master_key: Vec<u8>,
    hmac_master_key: Vec<u8>,
}

fn log2_pow2(n: u32) -> Result<u8> {
    if n < 2 || (n & (n - 1)) != 0 {
        bail!("scryptCostParam (N) must be a power of two >= 2 (got {n})");
    }
    Ok(n.trailing_zeros() as u8)
}

fn derive_keys(password: &str, config: &CryptoMatorConfig) -> Result<MasterKeys> {
    // 1) Cryptomator expects password normalization (NFC)
    let pw_nfc: String = password.nfc().collect();

    // 2) Decode salt
    let salt = base64::engine::general_purpose::STANDARD
        .decode(config.scrypt_salt.as_bytes())
        .context("base64 decode scryptSalt")?;

    // 3) scrypt params
    let log_n = log2_pow2(config.scrypt_cost_param)?;
    let r = config.scrypt_block_size;
    let p: u32 = 1; // Cryptomator uses non-parallel scrypt; no field for p in masterkey.cryptomator

    let params =
        ScryptParams::new(log_n, r, p, 32).map_err(|e| anyhow!("invalid scrypt params: {e}"))?;

    // 4) Derive KEK (32 bytes)
    let mut kek_bytes = [0u8; 32];
    scrypt(pw_nfc.as_bytes(), &salt, &params, &mut kek_bytes)
        .map_err(|e| anyhow!("scrypt failed: {e}"))?;

    // 5) Decode wrapped keys (AES Key Wrap)
    let wrapped_primary = base64::engine::general_purpose::STANDARD
        .decode(config.primary_master_key.as_bytes())
        .context("base64 decode primaryMasterKey")?;
    let wrapped_hmac = base64::engine::general_purpose::STANDARD
        .decode(config.hmac_master_key.as_bytes())
        .context("base64 decode hmacMasterKey")?;

    // 6) Unwrap (wrong password => unwrap error)
    let kek = KekAes256::from(kek_bytes);

    let primary = kek.unwrap_vec(&wrapped_primary).map_err(|e| {
        anyhow!("AES-KW unwrap primaryMasterKey failed (wrong password or corrupted file): {e}")
    })?;

    let hmac = kek.unwrap_vec(&wrapped_hmac).map_err(|e| {
        anyhow!("AES-KW unwrap hmacMasterKey failed (wrong password or corrupted file): {e}")
    })?;

    if primary.len() != 32 || hmac.len() != 32 {
        bail!(
            "unwrapped key lengths unexpected (primary={}, hmac={})",
            primary.len(),
            hmac.len()
        );
    }

    Ok(MasterKeys {
        primary_master_key: primary,
        hmac_master_key: hmac,
    })
}

const HEADER_NONCE_LEN: usize = 12;
const NONCE_LEN: usize = 12;

impl CryptoMator<FsBackend> {
    /// Creates a new GoCryptFs instance from a cipher root path and password.
    pub fn try_new(root_path: &Utf8Path, password: &str) -> Result<Self> {
        let file_path = root_path.join("masterkey.cryptomator");
        let json_str = std::fs::read_to_string(file_path)?;
        let config: CryptoMatorConfig = serde_json::from_str(&json_str)?;

        let keys = derive_keys(password, &config)?;
        let mut siv_key = [0u8; 64];
        siv_key[..32].copy_from_slice(&keys.hmac_master_key);
        siv_key[32..].copy_from_slice(&keys.primary_master_key);
        Ok(CryptoMator {
            backend: root_path.into(),
            siv_key,
        })
    }

    fn mkdir_storage_path(&self, dir_id: &str) -> Result<()> {
        let full_path = self.dir_id_to_storage_path(dir_id)?;
        self.lower_fs()
            .mkdir(full_path.parent().unwrap_or_else(|| "".into()))?;
        self.lower_fs().mkdir(&full_path)?;
        Ok(())
    }

    fn dir_id_to_storage_path(&self, dir_id: &str) -> Result<Utf8PathBuf> {
        // Key material for AES-SIV-512 (RFC 5297): 64 bytes split into two halves.
        // We concatenate mac_master_key || master_key.

        let mut siv = Aes256Siv::new_from_slice(&self.siv_key)?;

        // associated data = null => empty iterator
        let enc_dir_id = siv
            .encrypt(std::iter::empty::<&[u8]>(), dir_id.as_bytes())
            .map_err(|_| anyhow!("AES-SIV encryption should not fail for small inputs"))?;

        // SHA-1 over encrypted dirId
        let digest = Sha1::digest(&enc_dir_id);

        // Base32 without padding, uppercase alphabet (matches Cryptomator doc)
        let b32 = BASE32_NOPAD.encode(digest.as_slice());
        debug_assert_eq!(b32.len(), 32, "base32(sha1(..)) should be 32 chars");

        let (pfx, rest) = b32.split_at(2); // 2 + 30 chars
        let rest = &rest[..30];

        Ok(self.backend.cipher_root.join("d").join(pfx).join(rest))
    }
}

impl<T: Backend> CryptoMator<T> {
    fn master_key(&self) -> &[u8] {
        &self.siv_key[32..]
    }
    fn decrypt_content_key_from_header(&self, header: &[u8]) -> Result<([u8; 32], [u8; 12])> {
        if header.len() < Self::HEADER_LEN {
            bail!(
                "Cryptomator header too short: {} < {}",
                header.len(),
                Self::HEADER_LEN
            );
        }

        let header_nonce: [u8; HEADER_NONCE_LEN] = header[0..HEADER_NONCE_LEN].try_into()?;
        let ct_and_tag = &header[HEADER_NONCE_LEN..Self::HEADER_LEN]; // 40 + 16 = 56 bytes

        let cipher = Aes256Gcm::new_from_slice(self.master_key())
            .map_err(|e| anyhow!("AES-GCM init failed: {e}"))?;

        let nonce = aes_gcm::Nonce::from_slice(&header_nonce);

        // AAD empty for header encryption in Cryptomator spec
        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct_and_tag,
                    aad: &[],
                },
            )
            .map_err(|_| anyhow!("header decrypt failed (bad key or corrupted header)"))?;

        if pt.len() != 8 + 32 {
            bail!("unexpected header payload len: {} (expected 40)", pt.len());
        }

        // 8 bytes filled with 1 (0xFF) in the spec
        if pt[0..8] != [0xFFu8; 8] {
            bail!("header payload marker mismatch (expected 8 bytes 0xFF)");
        }

        let mut content_key = [0u8; 32];
        content_key.copy_from_slice(&pt[8..40]);

        Ok((content_key, header_nonce))
    }
}

impl<T: Backend> XattrTranslator for CryptoMator<T> {
    fn cipher_xattr_name_to_plain(&self, _cipher_xattr_name: &str) -> Result<String> {
        bail!("todo")
    }
    fn cipher_xattr_value_to_plain(&self, _cipher_xattr_value: &[u8]) -> Result<Vec<u8>> {
        bail!("todo")
    }
    fn plain_xattr_name_to_cipher(&self, _plain_xattr_name: &str) -> Result<String> {
        bail!("todo")
    }
    fn plain_xattr_value_to_cipher(&self, _plain_xattr_value: &[u8]) -> Result<Vec<u8>> {
        bail!("todo")
    }
}
