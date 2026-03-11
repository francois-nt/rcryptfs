use super::Utf8Path;
use crate::{Backend, FsBackend, Result};
use aes::{Aes256, cipher::generic_array::GenericArray};
use aes_gcm::{
    Aes256Gcm, AesGcm, KeyInit,
    aead::{self, Aead},
};
use anyhow::{Context, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hkdf::Hkdf;
use scrypt::{Params as ScryptParams, scrypt};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Write;

mod encryption_translator;
mod path_translator;
mod xattr_translator;

/// GoCryptFS backend with derived content and filename encryption keys.
pub struct GoCryptFs<T: Backend> {
    backend: T,
    /// AES-256-GCM key for file content (blocks)
    gcm_key: [u8; 32],
    /// AES-256-EME key for filename encryption
    eme_key: [u8; 32],
    /// base64 encoding of file names (Raw64 => no pad)
    raw64: bool,
}

/// Derives encryption keys from master key and feature flags.
fn derive_keys<T: Backend>(
    backend: T,
    master_key: &[u8; 32],
    feature_flags: &[String],
) -> Result<GoCryptFs<T>> {
    let has = |flag: &str| feature_flags.iter().any(|f| f == flag);

    let has_hkdf = has("HKDF");
    //let gcm_nonce_len = if has("GCMIV128") { 16 } else { 12 };
    if !has("GCMIV128") {
        bail!("Only GCMIV128 is supported");
    }
    let raw64 = has("Raw64");

    let mut gcm_key = [0u8; 32];
    let mut eme_key = [0u8; 32];

    if has_hkdf {
        // gocryptfs info strings
        const INFO_GCM: &[u8] = b"AES-GCM file content encryption";
        const INFO_EME: &[u8] = b"EME filename encryption";

        let hk = Hkdf::<Sha256>::new(None, master_key);

        hk.expand(INFO_GCM, &mut gcm_key)
            .map_err(|_| anyhow!("hkdf expand failed for gcm_key"))?;
        hk.expand(INFO_EME, &mut eme_key)
            .map_err(|_| anyhow!("hkdf expand failed for eme_key"))?;
    } else {
        // Ancien format: une seule clé (master key) utilisée pour contenu + noms
        gcm_key.copy_from_slice(master_key);
        eme_key.copy_from_slice(master_key);
    }
    Ok(GoCryptFs {
        backend,
        gcm_key,
        eme_key,
        raw64,
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
/// Scrypt parameters stored in `gocryptfs.conf`.
struct ScryptObject {
    salt: String,
    n: u32,
    r: u8,
    p: u8,
    key_len: u8,
}

impl Default for ScryptObject {
    /// Builds the default scrypt parameters used when initializing a new backend.
    fn default() -> Self {
        let mut salt = [0u8; 32];
        rand::fill(&mut salt);
        let salt = B64.encode(salt);
        Self {
            salt,
            n: 65536,
            r: 8,
            p: 1,
            key_len: 32,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoCryptfsConfig {
    creator: String,
    encrypted_key: String,
    scrypt_object: ScryptObject,
    version: u64,
    feature_flags: Vec<String>,
}

impl GoCryptfsConfig {
    /// Creates a fresh `gocryptfs.conf` payload and returns the generated master key.
    fn try_new(password: &str) -> Result<(Self, Vec<u8>)> {
        let creator = format!("rcryptfs {}", env!("CARGO_PKG_VERSION"));
        let scrypt_object = ScryptObject::default();
        let version = 2;
        let feature_flags = vec![
            "HKDF",
            "GCMIV128",
            "DirIV",
            "EMENames",
            "LongNames",
            "Raw64",
        ];
        let feature_flags: Vec<String> = feature_flags.into_iter().map(String::from).collect();
        let salt = B64.decode(&scrypt_object.salt)?;
        let log_n = scrypt_object.n.trailing_zeros() as u8;
        let params = ScryptParams::new(log_n, scrypt_object.r.into(), scrypt_object.p.into(), 32)?;
        let mut kek = [0u8; 32];
        scrypt(password.as_bytes(), salt.as_slice(), &params, &mut kek)?;
        let mut gcm_key = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(None, &kek);
        hk.expand(b"AES-GCM file content encryption", &mut gcm_key)
            .map_err(|_| anyhow!("hkdf expand failed"))?;

        let aad = [0u8; 8];
        let mut nonce = [0u8; 16];
        rand::fill(&mut nonce);
        let mut master_key = vec![0u8; 32];
        rand::fill(master_key.as_mut_slice());
        type Aes256GcmIv128 = AesGcm<Aes256, typenum::U16>;
        let cipher = Aes256GcmIv128::new(GenericArray::from_slice(&gcm_key));
        let raw_encrypted_key = cipher
            .encrypt(
                GenericArray::from_slice(&nonce),
                aead::Payload {
                    msg: &master_key,
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow!("can't encrypt master_key {e}"))?;
        // The final EncryptedKey field is 'nonce||ciphertext||tag', encoded in base64.
        let mut encrypted_key = Vec::with_capacity(nonce.len() + raw_encrypted_key.len());
        encrypted_key.extend_from_slice(&nonce);
        encrypted_key.extend_from_slice(&raw_encrypted_key);
        let encrypted_key = B64.encode(encrypted_key);
        Ok((
            Self {
                creator,
                encrypted_key,
                scrypt_object,
                version,
                feature_flags,
            },
            master_key,
        ))
    }
}

/// Derives the master key from password and configuration.
fn get_master_key(input: &str, config: &GoCryptfsConfig) -> Result<Vec<u8>> {
    let has_hkdf = config.feature_flags.iter().any(|f| f.as_str() == "HKDF");

    // --- Parse EncryptedKey (base64) ---
    //let enc_key_b64 = json.get_str("EncryptedKey")?;

    let enc_key = B64
        .decode(&config.encrypted_key)
        .context("EncryptedKey base64 decode failed")?;

    // --- Parse ScryptObject ---
    // let scrypt_obj = json
    //     .get("ScryptObject")
    //     .context("missing or invalid ScryptObject")?;

    let scrypt_obj = &config.scrypt_object;
    let salt = B64.decode(&scrypt_obj.salt)?;

    if scrypt_obj.key_len != 32 {
        bail!("unexpected KeyLen={}, expected 32", scrypt_obj.key_len);
    }

    let n = scrypt_obj.n;
    // N must be a power of two > 1
    if n < 2 || (n & (n - 1)) != 0 {
        bail!("scrypt N must be a power of two > 1, got {n}");
    }
    let log_n = n.trailing_zeros() as u8;

    let params = ScryptParams::new(log_n, scrypt_obj.r.into(), scrypt_obj.p.into(), 32)
        .context("invalid scrypt params")?;

    // --- Derive KEK with scrypt ---
    let mut kek = [0u8; 32];
    scrypt(input.as_bytes(), &salt, &params, &mut kek)?;

    // --- If HKDF enabled: derive the actual AES-GCM key used for wrapping ---
    // gocryptfs uses HKDF-SHA256 with salt=nil, info="AES-GCM file content encryption"
    let mut gcm_key = [0u8; 32];
    if has_hkdf {
        let hk = Hkdf::<Sha256>::new(None, &kek);
        hk.expand(b"AES-GCM file content encryption", &mut gcm_key)
            .map_err(|_| anyhow!("hkdf expand failed"))?;
    } else {
        gcm_key.copy_from_slice(&kek);
    }

    // --- Determine nonce length for EncryptedKey decryption ---
    // In gocryptfs config code: 96-bit for old (no HKDF), 128-bit when HKDF is on.
    let nonce_len = if has_hkdf { 16 } else { 12 };

    if enc_key.len() < nonce_len + 16 {
        bail!(
            "EncryptedKey too short: {} bytes (need at least {})",
            enc_key.len(),
            nonce_len + 16
        );
    }

    let (nonce, ct_and_tag) = enc_key.split_at(nonce_len);

    // AAD for config masterkey decrypt is blockNo=0, fileID=nil => 8 bytes big-endian zero
    let aad = [0u8; 8];

    // --- AES-256-GCM decrypt ---
    let pt_res = if has_hkdf {
        // 128-bit nonce
        type Aes256GcmIv128 = AesGcm<Aes256, typenum::U16>;
        let cipher = Aes256GcmIv128::new(GenericArray::from_slice(&gcm_key));
        cipher.decrypt(
            GenericArray::from_slice(nonce),
            aead::Payload {
                msg: ct_and_tag,
                aad: &aad,
            },
        )
    } else {
        // 96-bit nonce
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&gcm_key));
        cipher.decrypt(
            GenericArray::from_slice(nonce),
            aead::Payload {
                msg: ct_and_tag,
                aad: &aad,
            },
        )
    };

    pt_res.map_err(|_| anyhow!("bad password"))
}

impl<T: Backend> GoCryptFs<T> {
    /// Constants matching the GoCryptFS on-disk file layout.
    const NONCE_LEN: usize = 16;
    const HEADER_LEN: usize = 18;
    const FILEID_LEN: usize = 16;
    const TAG_LEN: usize = 16;
    const PLAIN_BLOCK_LEN: u64 = 4096;
    const CIPHER_BLOCK_LEN: u64 = Self::PLAIN_BLOCK_LEN + (Self::TAG_LEN + Self::NONCE_LEN) as u64;
}

fn dir_is_empty(path: &Utf8Path) -> std::io::Result<bool> {
    Ok(std::fs::read_dir(path)?.next().is_none())
}

impl GoCryptFs<FsBackend> {
    /// Initializes a new GoCryptFS-compatible backend with default parameters.
    pub fn init_with_default_params(root_path: &Utf8Path, password: &str) -> Result<Vec<u8>> {
        if !dir_is_empty(root_path)? {
            bail!("Directory {} must be empty!", root_path);
        }
        let (config, master_key) = GoCryptfsConfig::try_new(password)?;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(root_path.join("gocryptfs.conf"))?;
        let json_config = serde_json::to_vec_pretty(&config)?;
        file.write_all(&json_config)?;

        // The root directory uses its own DirIV file just like any other directory.
        let mut root_dir_iv = [0u8; 16];
        rand::fill(&mut root_dir_iv);
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(root_path.join("gocryptfs.diriv"))?;
        file.write_all(&root_dir_iv)?;

        Ok(master_key)
    }
    /// Creates a new GoCryptFs instance from a cipher root path and password.
    pub fn try_new(root_path: &Utf8Path, password: &str) -> Result<Self> {
        let file_path = root_path.join("gocryptfs.conf");
        let json_str = std::fs::read_to_string(file_path)?;
        let config: GoCryptfsConfig = serde_json::from_str(&json_str)?;

        let master_key = get_master_key(password, &config)?;
        derive_keys(
            root_path.into(),
            master_key.as_slice().try_into()?,
            &config.feature_flags,
        )
    }
}
