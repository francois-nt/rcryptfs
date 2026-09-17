use super::{
    CryptoMator, CryptomatorBackend, CryptomatorEntryStorage, CryptomatorEntryStorageOptions,
    DEFAULT_SHORTENING_THRESHOLD, layout::CryptomatorDirectoryLayout,
};
use crate::core::{
    Backend, ConfigFileSystem, EncryptionTranslator, EntryStorage, FsBackend, MasterKey,
    NativeFileSystem, Result, StorageConfigFileSystem, Utf8Path, VirtualPath, VirtualPathBuf,
    XattrLayout,
};
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
use sha2::{Sha256, Sha384, Sha512};
use std::sync::Arc;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

const MASTERKEY_FILE: &str = "masterkey.cryptomator";
const MASTERKEY_KID: &str = "masterkeyfile:masterkey.cryptomator";
const VAULT_FILE: &str = "vault.cryptomator";

/// JWT header stored in vault.cryptomator.
#[derive(Deserialize, Serialize)]
struct JwtHeader {
    kid: String,
    typ: String,
    alg: String,
}

/// JWT payload stored in vault.cryptomator.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct JwtPayload {
    format: u32,
    #[serde(default = "default_shortening_threshold")]
    shortening_threshold: usize,
    jti: String,
    cipher_combo: String,
}

/// Returns the interoperable filename shortening threshold.
fn default_shortening_threshold() -> usize {
    DEFAULT_SHORTENING_THRESHOLD
}

/// Parsed compact JWT with its original authenticated input.
struct ParsedVault {
    header: JwtHeader,
    payload: JwtPayload,
    signing_input: String,
    signature: Vec<u8>,
}

impl ParsedVault {
    /// Parses the three segments of vault.cryptomator without trusting their contents.
    fn parse(data: &[u8]) -> Result<Self> {
        let token = std::str::from_utf8(data)
            .context("vault.cryptomator is not valid UTF-8")?
            .trim();
        let mut segments = token.split('.');
        let header_segment = segments
            .next()
            .context("vault.cryptomator is missing its header")?;
        let payload_segment = segments
            .next()
            .context("vault.cryptomator is missing its payload")?;
        let signature_segment = segments
            .next()
            .context("vault.cryptomator is missing its signature")?;
        if segments.next().is_some() {
            bail!("vault.cryptomator must contain exactly three segments");
        }

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = serde_json::from_slice(
            &b64.decode(header_segment)
                .context("decode vault.cryptomator header")?,
        )
        .context("parse vault.cryptomator header")?;
        let payload = serde_json::from_slice(
            &b64.decode(payload_segment)
                .context("decode vault.cryptomator payload")?,
        )
        .context("parse vault.cryptomator payload")?;
        let signature = b64
            .decode(signature_segment)
            .context("decode vault.cryptomator signature")?;

        Ok(Self {
            header,
            payload,
            signing_input: format!("{header_segment}.{payload_segment}"),
            signature,
        })
    }

    /// Validates the JWT header and returns the supported masterkey path.
    fn masterkey_path(&self) -> Result<&'static VirtualPath> {
        if self.header.typ != "JWT" {
            bail!("unsupported vault.cryptomator type: {}", self.header.typ);
        }
        if !matches!(self.header.alg.as_str(), "HS256" | "HS384" | "HS512") {
            bail!(
                "unsupported vault.cryptomator algorithm: {}",
                self.header.alg
            );
        }
        if self.header.kid != MASTERKEY_KID {
            bail!("unsupported vault.cryptomator key: {}", self.header.kid);
        }
        Ok(VirtualPath::new(MASTERKEY_FILE))
    }

    /// Authenticates the JWT and returns its supported payload.
    fn verify(self, master_keys: &CryptomatorMasterKeys) -> Result<JwtPayload> {
        let key = master_keys.jwt_key();
        let signing_input = self.signing_input.as_bytes();
        match self.header.alg.as_str() {
            "HS256" => {
                let mut mac = HmacSha256::new_from_slice(&key)?;
                mac.update(signing_input);
                mac.verify_slice(&self.signature)
            }
            "HS384" => {
                let mut mac = HmacSha384::new_from_slice(&key)?;
                mac.update(signing_input);
                mac.verify_slice(&self.signature)
            }
            "HS512" => {
                let mut mac = HmacSha512::new_from_slice(&key)?;
                mac.update(signing_input);
                mac.verify_slice(&self.signature)
            }
            _ => unreachable!("the JWT algorithm was validated before loading the key"),
        }
        .context("invalid vault.cryptomator signature")?;

        if self.payload.format != 8 {
            bail!(
                "unsupported Cryptomator vault format: {}",
                self.payload.format
            );
        }
        match self.payload.cipher_combo.as_str() {
            "SIV_GCM" => {}
            "SIV_CTRMAC" => bail!("Cryptomator cipherCombo SIV_CTRMAC is not supported"),
            cipher_combo => bail!("unsupported Cryptomator cipherCombo: {cipher_combo}"),
        }

        Ok(self.payload)
    }
}

/// Builds the signed vault.cryptomator token for the current master keys.
fn generate_vault_cryptomator(
    master_keys: &CryptomatorMasterKeys,
    cipher_combo: &str,          // "SIV_GCM" ou "SIV_CTRMAC"
    shortening_threshold: usize, // typiquement 220
) -> Result<String> {
    if cipher_combo != "SIV_GCM" && cipher_combo != "SIV_CTRMAC" {
        bail!("unsupported cipherCombo: {cipher_combo}");
    }

    let header = JwtHeader {
        kid: MASTERKEY_KID.to_owned(),
        typ: "JWT".to_owned(),
        alg: "HS256".to_owned(),
    };
    let payload = JwtPayload {
        format: 8,
        shortening_threshold,
        jti: Uuid::new_v4().to_string(),
        cipher_combo: cipher_combo.to_owned(),
    };

    sign_vault(&header, &payload, master_keys)
}

/// Serializes and signs a Cryptomator vault JWT.
fn sign_vault(
    header: &JwtHeader,
    payload: &JwtPayload,
    master_keys: &CryptomatorMasterKeys,
) -> Result<String> {
    let header_json = serde_json::to_vec(&header)?;
    let payload_json = serde_json::to_vec(&payload)?;

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = b64.encode(header_json);
    let payload_b64 = b64.encode(payload_json);

    let signing_input = format!("{header_b64}.{payload_b64}");

    let jwt_key = master_keys.jwt_key();
    let sig = match header.alg.as_str() {
        "HS256" => {
            let mut mac = HmacSha256::new_from_slice(&jwt_key)?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "HS384" => {
            let mut mac = HmacSha384::new_from_slice(&jwt_key)?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "HS512" => {
            let mut mac = HmacSha512::new_from_slice(&jwt_key)?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        algorithm => bail!("unsupported vault.cryptomator algorithm: {algorithm}"),
    };

    let sig_b64 = b64.encode(sig);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Opens and authenticates the Cryptomator configuration files.
fn unlock_vault<C: ConfigFileSystem + ?Sized>(
    config_fs: &C,
    password: &str,
) -> Result<(CryptomatorMasterKeys, JwtPayload)> {
    let vault_data = config_fs.read_all(VAULT_FILE.into())?;
    let vault = ParsedVault::parse(&vault_data)?;
    let masterkey_path = vault.masterkey_path()?;
    let config_data = config_fs.read_all(masterkey_path)?;
    let config: CryptoMatorConfig = serde_json::from_slice(&config_data)?;
    let master_keys = derive_keys(password, &config)?;
    let payload = vault.verify(&master_keys)?;
    Ok((master_keys, payload))
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
    let pw_nfc: String = password.nfc().collect();

    let salt = base64::engine::general_purpose::STANDARD
        .decode(config.scrypt_salt.as_bytes())
        .context("base64 decode scryptSalt")?;

    let log_n = log2_pow2(config.scrypt_cost_param)?;
    let r = config.scrypt_block_size;
    let p: u32 = 1;

    let params =
        ScryptParams::new(log_n, r, p, 32).map_err(|e| anyhow!("invalid scrypt params: {e}"))?;

    let mut kek_bytes = [0u8; 32];
    scrypt(pw_nfc.as_bytes(), &salt, &params, &mut kek_bytes)
        .map_err(|e| anyhow!("scrypt failed: {e}"))?;

    let wrapped_primary = base64::engine::general_purpose::STANDARD
        .decode(config.primary_master_key.as_bytes())
        .context("base64 decode primaryMasterKey")?;
    let wrapped_hmac = base64::engine::general_purpose::STANDARD
        .decode(config.hmac_master_key.as_bytes())
        .context("base64 decode hmacMasterKey")?;

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

    let version_mac = base64::engine::general_purpose::STANDARD
        .decode(config.version_mac.as_bytes())
        .context("base64 decode versionMac")?;
    let mut mac = HmacSha256::new_from_slice(&hmac)?;
    mac.update(&config.version.to_be_bytes());
    mac.verify_slice(&version_mac)
        .context("invalid masterkey.cryptomator versionMac")?;

    Ok(CryptomatorMasterKeys {
        primary_master_key: primary,
        hmac_master_key: hmac,
    })
}

impl MasterKey for CryptomatorMasterKeys {
    fn to_vec(&self) -> Vec<u8> {
        self.siv_key().to_vec()
    }
}

impl CryptoMator<CryptomatorBackend> {
    /// Initializes a new Cryptomator-compatible backend with default parameters.
    pub fn init_with_default_params(
        root_path: &Utf8Path,
        password: &str,
    ) -> Result<CryptomatorMasterKeys> {
        let storage_fs = NativeFileSystem::new(root_path.to_owned());
        let config_fs = StorageConfigFileSystem::new(&storage_fs);
        let (config, master_keys) = CryptoMatorConfig::try_new(password)?;
        let directory_layout = Arc::new(CryptomatorDirectoryLayout::new(master_keys.siv_key()));
        Self::write_config_and_initialize_root(&config_fs, &config, master_keys, || {
            CryptomatorEntryStorage::initialize_root_storage(&storage_fs, directory_layout.as_ref())
        })
    }

    /// Opens a Cryptomator repository from a local cipher root path.
    pub fn try_new(root_path: &Utf8Path, password: &str) -> Result<Self> {
        let storage_fs = NativeFileSystem::new(root_path.to_owned());
        let config_fs = StorageConfigFileSystem::new(&storage_fs);
        let (keys, vault) = unlock_vault(&config_fs, password)?;
        let siv_key = keys.siv_key();
        let directory_layout = Arc::new(CryptomatorDirectoryLayout::new(siv_key));
        let backend = FsBackend::new(CryptomatorEntryStorage::with_options(
            storage_fs,
            directory_layout,
            CryptomatorEntryStorageOptions {
                shortening_threshold: vault.shortening_threshold,
            },
        ));
        Ok(Self { backend, siv_key })
    }
}

impl<S> CryptoMator<FsBackend<S>>
where
    S: EntryStorage,
{
    /// Initializes the Cryptomator crypto configuration over an entry representation.
    pub fn init_with_backend<C: ConfigFileSystem + ?Sized>(
        backend: &FsBackend<S>,
        config_fs: &C,
        password: &str,
    ) -> Result<CryptomatorMasterKeys> {
        let (config, master_keys) = CryptoMatorConfig::try_new(password)?;
        Self::write_config_and_initialize_root(config_fs, &config, master_keys, || {
            backend.entry_storage().initialize_root_directory()
        })
    }

    /// Writes the crypto configuration and initializes its root representation.
    fn write_config_and_initialize_root<C, InitializeRoot>(
        config_fs: &C,
        config: &CryptoMatorConfig,
        master_keys: CryptomatorMasterKeys,
        initialize_root: InitializeRoot,
    ) -> Result<CryptomatorMasterKeys>
    where
        C: ConfigFileSystem + ?Sized,
        InitializeRoot: FnOnce() -> std::io::Result<crate::core::StorageDirectory>,
    {
        let root_path = VirtualPath::root();
        if !config_fs.is_empty()? {
            bail!("Directory {root_path} must be empty!");
        }

        let rollback = |_: &std::io::Error| {
            let _ = config_fs.remove(MASTERKEY_FILE.into());
            let _ = config_fs.remove(VAULT_FILE.into());
        };

        let json_config = serde_json::to_vec_pretty(&config)?;
        config_fs
            .put_new(MASTERKEY_FILE.into(), &json_config)
            .inspect_err(rollback)?;

        let vault = generate_vault_cryptomator(&master_keys, "SIV_GCM", 220)?;
        config_fs
            .put_new(VAULT_FILE.into(), vault.as_bytes())
            .inspect_err(rollback)?;

        initialize_root().inspect_err(rollback)?;

        Ok(master_keys)
    }

    /// Opens a Cryptomator crypto configuration over an entry representation.
    pub fn try_new_with_backend<C: ConfigFileSystem + ?Sized>(
        backend: FsBackend<S>,
        config_fs: &C,
        password: &str,
    ) -> Result<Self> {
        let (keys, _vault) = unlock_vault(config_fs, password)?;
        let siv_key = keys.siv_key();
        Ok(CryptoMator { backend, siv_key })
    }
}

/// Computes the storage directory for a Cryptomator directory identifier.
pub(super) fn dir_id_to_storage_path(siv_key: &[u8; 64], dir_id: &str) -> Result<VirtualPathBuf> {
    use aes_siv::aead::KeyInit;
    let mut siv = Aes256Siv::new_from_slice(siv_key)?;
    let enc_dir_id = siv
        .encrypt(std::iter::empty::<&[u8]>(), dir_id.as_bytes())
        .map_err(|_| anyhow!("AES-SIV encryption should not fail for small inputs"))?;
    let digest = Sha1::digest(&enc_dir_id);
    let b32 = BASE32_NOPAD.encode(digest.as_slice());
    debug_assert_eq!(b32.len(), 32, "base32(sha1(..)) should be 32 chars");
    let (prefix, rest) = b32.split_at(2);
    Ok(VirtualPath::new("d").join(prefix).join(&rest[..30]))
}

const HEADER_NONCE_LEN: usize = 12;
//const NONCE_LEN: usize = 12;

impl<T: Backend> CryptoMator<T> {
    pub(super) fn master_key(&self) -> &[u8] {
        &self.siv_key[32..]
    }
    pub(super) fn decrypt_content_key_from_header(
        &self,
        header: &[u8],
    ) -> Result<([u8; 32], [u8; 12])> {
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

impl<T: Backend> XattrLayout for CryptoMator<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{PathLayout, StorageFileSystem};
    use tempfile::tempdir;

    /// Returns deterministic master keys for vault tests.
    fn test_master_keys() -> CryptomatorMasterKeys {
        CryptomatorMasterKeys {
            primary_master_key: vec![0x11; 32],
            hmac_master_key: vec![0x22; 32],
        }
    }

    /// Returns a supported vault header.
    fn test_header() -> JwtHeader {
        JwtHeader {
            kid: MASTERKEY_KID.to_owned(),
            typ: "JWT".to_owned(),
            alg: "HS256".to_owned(),
        }
    }

    /// Returns a supported vault payload.
    fn test_payload() -> JwtPayload {
        JwtPayload {
            format: 8,
            shortening_threshold: 220,
            jti: Uuid::nil().to_string(),
            cipher_combo: "SIV_GCM".to_owned(),
        }
    }

    #[test]
    fn generated_vault_is_parsed_and_verified() {
        let master_keys = test_master_keys();
        let token = generate_vault_cryptomator(&master_keys, "SIV_GCM", 220).unwrap();
        let vault = ParsedVault::parse(token.as_bytes()).unwrap();

        assert_eq!(
            vault.masterkey_path().unwrap(),
            VirtualPath::new(MASTERKEY_FILE)
        );
        let payload = vault.verify(&master_keys).unwrap();
        assert_eq!(payload.format, 8);
        assert_eq!(payload.shortening_threshold, 220);
        assert_eq!(payload.cipher_combo, "SIV_GCM");
    }

    #[test]
    fn vault_without_shortening_threshold_uses_default() {
        let payload: JwtPayload = serde_json::from_str(
            r#"{"format":8,"jti":"00000000-0000-0000-0000-000000000000","cipherCombo":"SIV_GCM"}"#,
        )
        .unwrap();

        assert_eq!(payload.shortening_threshold, DEFAULT_SHORTENING_THRESHOLD);
    }

    #[test]
    fn canonical_backend_uses_authenticated_shortening_threshold() {
        const THRESHOLD: usize = 80;
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap();
        let master_keys = CryptoMator::init_with_default_params(root, "password").unwrap();
        let vault = generate_vault_cryptomator(&master_keys, "SIV_GCM", THRESHOLD).unwrap();
        NativeFileSystem::new(root.to_owned())
            .put(VirtualPath::new(VAULT_FILE), vault.as_bytes())
            .unwrap();

        let cryptfs = CryptoMator::try_new(root, "password").unwrap();

        assert_eq!(
            cryptfs.entry_storage().options().shortening_threshold,
            THRESHOLD
        );
    }

    #[test]
    fn vault_rejects_a_tampered_signature() {
        let master_keys = test_master_keys();
        let token = generate_vault_cryptomator(&master_keys, "SIV_GCM", 220).unwrap();
        let (signing_input, signature) = token.rsplit_once('.').unwrap();
        let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
        let token = format!("{signing_input}.{replacement}{}", &signature[1..]);
        let vault = ParsedVault::parse(token.as_bytes()).unwrap();

        assert!(vault.verify(&master_keys).is_err());
    }

    #[test]
    fn vault_rejects_unsupported_header_fields() {
        let headers = [
            JwtHeader {
                typ: "JWS".to_owned(),
                ..test_header()
            },
            JwtHeader {
                alg: "none".to_owned(),
                ..test_header()
            },
            JwtHeader {
                kid: "masterkeyfile:other.key".to_owned(),
                ..test_header()
            },
        ];

        for header in headers {
            let vault = ParsedVault {
                header,
                payload: test_payload(),
                signing_input: String::new(),
                signature: Vec::new(),
            };
            assert!(vault.masterkey_path().is_err());
        }
    }

    #[test]
    fn vault_accepts_supported_hmac_algorithms() {
        let master_keys = test_master_keys();
        for algorithm in ["HS256", "HS384", "HS512"] {
            let header = JwtHeader {
                alg: algorithm.to_owned(),
                ..test_header()
            };
            let token = sign_vault(&header, &test_payload(), &master_keys).unwrap();
            let vault = ParsedVault::parse(token.as_bytes()).unwrap();

            vault.masterkey_path().unwrap();
            vault.verify(&master_keys).unwrap();
        }
    }

    #[test]
    fn vault_rejects_unsupported_payload_fields() {
        let master_keys = test_master_keys();
        let payloads = [
            JwtPayload {
                format: 9,
                ..test_payload()
            },
            JwtPayload {
                cipher_combo: "SIV_CTRMAC".to_owned(),
                ..test_payload()
            },
            JwtPayload {
                cipher_combo: "unknown".to_owned(),
                ..test_payload()
            },
        ];

        for payload in payloads {
            let token = sign_vault(&test_header(), &payload, &master_keys).unwrap();
            let vault = ParsedVault::parse(token.as_bytes()).unwrap();
            assert!(vault.verify(&master_keys).is_err());
        }
    }

    #[test]
    fn vault_rejects_an_invalid_segment_count() {
        assert!(ParsedVault::parse(b"header.payload").is_err());
        assert!(ParsedVault::parse(b"header.payload.signature.extra").is_err());
    }

    #[test]
    fn masterkey_rejects_an_invalid_version_mac() {
        let (mut config, _) = CryptoMatorConfig::try_new("password").unwrap();
        config.version_mac = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);

        assert!(derive_keys("password", &config).is_err());
    }
}
