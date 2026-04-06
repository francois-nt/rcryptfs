use crate::core::{
    Backend, BackendProvider, CipherPathLayout, EncryptedFileTranslator, EncryptionTranslator,
    FileCachePolicy, FileSystem, FsBackend, MasterKey, MinimalFs, OrIoError, Result, Utf8Path,
    Utf8PathBuf, XattrTranslator, is_dir_empty,
};
use crate::register_provider;
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, Payload},
};
use aes_kw::KekAes256;
use aes_siv::siv::Aes256Siv;
use anyhow::{Context, anyhow, bail};
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use scrypt::{Params as ScryptParams, scrypt};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::io::Write;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

mod encryption_translator;
mod layout;
/// Cryptomator backend state with the derived SIV key material.
pub struct CryptoMator<T: Backend> {
    backend: T,
    siv_key: [u8; 64],
}

/// Reads the directory id vector from a cipher directory.
fn read_dirid(cipher_dir: &Utf8Path, is_root: bool) -> Result<String> {
    if is_root {
        return Ok(String::default());
    }
    let p = cipher_dir.join("dir.c9r");
    let data = std::fs::read_to_string(&p).context(format!("read {:?}", p))?;
    if data.len() != 36 {
        return Err(anyhow!("dirid has len {}, expected 36", data.len()));
    }
    Ok(data)
}

/// JWT header stored in vault.cryptomator.
#[derive(Serialize)]
struct JwtHeader<'a> {
    kid: &'a str,
    typ: &'a str,
    alg: &'a str,
}

/// JWT payload stored in vault.cryptomator.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JwtPayload<'a> {
    format: u32,
    shortening_threshold: u32,
    jti: String,
    cipher_combo: &'a str,
}

/// Builds the signed vault.cryptomator token for the current master keys.
fn generate_vault_cryptomator(
    master_keys: &CryptomatorMasterKeys,
    cipher_combo: &str,        // "SIV_GCM" ou "SIV_CTRMAC"
    shortening_threshold: u32, // typiquement 220
) -> Result<String> {
    if cipher_combo != "SIV_GCM" && cipher_combo != "SIV_CTRMAC" {
        bail!("unsupported cipherCombo: {cipher_combo}");
    }

    // 1) header + payload
    let header = JwtHeader {
        kid: "masterkeyfile:masterkey.cryptomator",
        typ: "JWT",
        alg: "HS256",
    };
    let payload = JwtPayload {
        format: 8,
        shortening_threshold,
        jti: Uuid::new_v4().to_string(),
        cipher_combo,
    };

    // 2) JSON -> bytes
    let header_json = serde_json::to_vec(&header)?;
    let payload_json = serde_json::to_vec(&payload)?;

    // 3) base64url sans padding
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = b64.encode(header_json);
    let payload_b64 = b64.encode(payload_json);

    // 4) message à signer
    let signing_input = format!("{header_b64}.{payload_b64}");

    // 5) key = encryptionMasterKey || macMasterKey (512-bit raw masterkey)
    let jwt_key = master_keys.jwt_key();

    let mut mac = HmacSha256::new_from_slice(&jwt_key)?;
    mac.update(signing_input.as_bytes());
    let sig = mac.finalize().into_bytes(); // 32 bytes

    let sig_b64 = b64.encode(sig);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Serialized masterkey.cryptomator contents.
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

/// Computes the version authentication tag stored in masterkey.cryptomator.
fn compute_version_mac(version: u32, mac_master_key: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(mac_master_key)?;
    mac.update(&version.to_be_bytes()); // 4 bytes big-endian
    let out = mac.finalize().into_bytes(); // 32 bytes
    let out: [u8; _] = out.into();
    Ok(out.into())
}

impl CryptoMatorConfig {
    /// Creates a fresh Cryptomator config and the matching raw master keys.
    fn try_new(password: &str) -> Result<(Self, CryptomatorMasterKeys)> {
        const DEFAULT_VERSION: u32 = 999;
        const DEFAULT_SCRYPT_COST: u32 = 32768;
        const DEFAULT_SCRYPT_BLOCK_SIZE: u32 = 8;
        let pw_nfc: String = password.nfc().collect();

        let mut salt = [0u8; 8];
        rand::rng().fill_bytes(&mut salt);

        let params = ScryptParams::new(15, DEFAULT_SCRYPT_BLOCK_SIZE, 1, 32)
            .map_err(|e| anyhow!("invalid default scrypt params: {e}"))?;

        let mut kek_bytes = [0u8; 32];
        scrypt(pw_nfc.as_bytes(), &salt, &params, &mut kek_bytes)
            .map_err(|e| anyhow!("scrypt failed: {e}"))?;

        let kek = KekAes256::from(kek_bytes);

        let mut primary_master_key = vec![0u8; 32];
        rand::rng().fill_bytes(&mut primary_master_key);

        let mut hmac_master_key = vec![0u8; 32];
        rand::rng().fill_bytes(&mut hmac_master_key);

        Ok((
            CryptoMatorConfig {
                version: DEFAULT_VERSION,
                scrypt_salt: base64::engine::general_purpose::STANDARD.encode(salt),
                scrypt_cost_param: DEFAULT_SCRYPT_COST,
                scrypt_block_size: DEFAULT_SCRYPT_BLOCK_SIZE,
                primary_master_key: base64::engine::general_purpose::STANDARD.encode(
                    kek.wrap_vec(&primary_master_key)
                        .map_err(|e| anyhow!("AES-KW wrap primaryMasterKey failed: {e}"))?,
                ),
                hmac_master_key: base64::engine::general_purpose::STANDARD.encode(
                    kek.wrap_vec(&hmac_master_key)
                        .map_err(|e| anyhow!("AES-KW wrap hmacMasterKey failed: {e}"))?,
                ),
                version_mac: base64::engine::general_purpose::STANDARD
                    .encode(compute_version_mac(DEFAULT_VERSION, &hmac_master_key)?),
            },
            CryptomatorMasterKeys {
                primary_master_key,
                hmac_master_key,
            },
        ))
    }
}

/// Raw Cryptomator master keys before they are wrapped for storage.
pub struct CryptomatorMasterKeys {
    pub primary_master_key: Vec<u8>,
    pub hmac_master_key: Vec<u8>,
}

impl CryptomatorMasterKeys {
    /// Returns the JWT signing key order used for vault.cryptomator.
    fn jwt_key(&self) -> [u8; 64] {
        let mut arr = [0; 64];
        arr[..32].copy_from_slice(&self.primary_master_key);
        arr[32..].copy_from_slice(&self.hmac_master_key);
        arr
    }
    /// Returns the SIV key order used for filename encryption.
    pub fn siv_key(&self) -> [u8; 64] {
        let mut arr = [0; 64];
        arr[..32].copy_from_slice(&self.hmac_master_key);
        arr[32..].copy_from_slice(&self.primary_master_key);
        arr
    }
}

/// Converts a power-of-two scrypt cost into the log2 value expected by the crate.
fn log2_pow2(n: u32) -> Result<u8> {
    if n < 2 || (n & (n - 1)) != 0 {
        bail!("scryptCostParam (N) must be a power of two >= 2 (got {n})");
    }
    Ok(n.trailing_zeros() as u8)
}

/// Derives and unwraps the Cryptomator master keys from a password and config.
fn derive_keys(password: &str, config: &CryptoMatorConfig) -> Result<CryptomatorMasterKeys> {
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

    Ok(CryptomatorMasterKeys {
        primary_master_key: primary,
        hmac_master_key: hmac,
    })
}

const HEADER_NONCE_LEN: usize = 12;
const NONCE_LEN: usize = 12;

/// Backend provider for Cryptomator repositories.
pub struct CryptoMatorBuilder;

register_provider!(CryptoMatorBuilder);

impl BackendProvider for CryptoMatorBuilder {
    fn name(&self) -> &'static str {
        "cryptomator"
    }
    fn probe(&self, root: &Utf8Path) -> bool {
        std::fs::exists(root.join("vault.cryptomator")).unwrap_or(false)
    }
    fn try_build(
        &self,
        root: &Utf8Path,
        password: &str,
        cache_policy: Box<dyn FileCachePolicy>,
    ) -> Result<Box<dyn FileSystem>> {
        let cryptfs: EncryptedFileTranslator<CryptoMator<FsBackend>> = (
            CryptoMator::<FsBackend>::try_new(root, password)?,
            cache_policy,
        )
            .into();
        Ok(Box::new(cryptfs))
    }
    fn init_with_default_params(
        &self,
        root: &Utf8Path,
        password: &str,
    ) -> Result<Box<dyn MasterKey>> {
        CryptoMator::<FsBackend>::init_with_default_params(root, password)
            .map(|keys| -> Box<dyn MasterKey> { Box::new(keys) })
    }
}

impl MasterKey for CryptomatorMasterKeys {
    fn to_vec(&self) -> Vec<u8> {
        self.siv_key().to_vec()
    }
}

impl CryptoMator<FsBackend> {
    /// Initializes a new Cryptomator-compatible backend with default parameters.
    pub fn init_with_default_params(
        root_path: &Utf8Path,
        password: &str,
    ) -> Result<CryptomatorMasterKeys> {
        if !is_dir_empty(root_path)? {
            bail!("Directory {root_path} must be empty!");
        }

        let rollback = |_: &std::io::Error| {
            let _ = std::fs::remove_file(root_path.join("masterkey.cryptomator"));
            let _ = std::fs::remove_file(root_path.join("vault.cryptomator"));
            let _ = std::fs::remove_dir_all(root_path.join("d"));
        };

        let (config, master_keys) = CryptoMatorConfig::try_new(password)?;

        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(root_path.join("masterkey.cryptomator"))
            .and_then(|mut file| {
                let json_config = serde_json::to_vec_pretty(&config)?;
                file.write_all(&json_config)
            })
            .inspect_err(rollback)?;

        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(root_path.join("vault.cryptomator"))
            .and_then(|mut file| {
                let vault =
                    generate_vault_cryptomator(&master_keys, "SIV_GCM", 220).or_invalid()?;
                file.write_all(vault.as_bytes())
            })
            .inspect_err(rollback)?;

        let siv_key = master_keys.siv_key();
        let backend = CryptoMator {
            backend: root_path.into(),
            siv_key,
        };
        std::fs::create_dir_all(backend.dir_id_to_storage_path("")?).inspect_err(rollback)?;

        Ok(master_keys)
    }

    /// Creates a new GoCryptFs instance from a cipher root path and password.
    pub fn try_new(root_path: &Utf8Path, password: &str) -> Result<Self> {
        let file_path = root_path.join("masterkey.cryptomator");
        let json_str = std::fs::read_to_string(file_path)?;
        let config: CryptoMatorConfig = serde_json::from_str(&json_str)?;

        let keys = derive_keys(password, &config)?;
        let siv_key = keys.siv_key();
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
        use aes_siv::aead::KeyInit;
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
        use aes_siv::aead::KeyInit;
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
