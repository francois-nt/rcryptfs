use std::fs::DirEntry;

use crate::{
    Backend, CacheAccess, CipherPathLayout, DefaultFs, EncryptionLayout, EncryptionTranslator,
    FileType, FsBackend, FsDirEntry, Metadata, MinimalFs, OrIoError, Result, Utf8Path, Utf8PathBuf,
    XattrTranslator, temp_file_path,
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
use rand::RngCore;
use scrypt::{Params as ScryptParams, scrypt};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use unicode_normalization::UnicodeNormalization;

pub struct CryptoMator<T: Backend> {
    backend: T,
    siv_key: [u8; 64],
}

//struct CryptoMatorBackend;
/*impl MinimalFs for CryptoMatorBackend {
    fn exists(&self, path: &Utf8Path) -> std::io::Result<bool> {
        DefaultFs.exists(path)
    }
    fn set_permissions(
        &self,
        path: &Utf8Path,
        permissions: crate::Permissions,
    ) -> std::io::Result<crate::Metadata> {
        DefaultFs.set_permissions(path, permissions)
    }
    fn metadata(&self, path: &Utf8Path) -> std::io::Result<Metadata> {
        let mut metadata = DefaultFs.metadata(path)?;
        if metadata.file_type == FileType::Directory {
            let dir = path.join("dir.c9r");
            if !DefaultFs.exists(&dir)? {
                let symlink = path.join("symlink.c9r");
                if DefaultFs.exists(&symlink)? {
                    metadata.file_type = FileType::SymLink;
                } else {
                    metadata.file_type = FileType::Other;
                }
            }
        } else if metadata.file_type != FileType::File {
            metadata.file_type = FileType::Other;
        };
        Ok(metadata)
    }
}*/

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

const HEADER_NONCE_LEN: usize = 12;
const NONCE_LEN: usize = 12;

impl<T: Backend> CryptoMator<T> {
    //const HEADER_NONCE_LEN: usize = 12;
    //const GCM_TAG_LEN: usize = 16;
    //const HEADER_CT_LEN: usize = 40;
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

        let header_nonce: [u8; 12] = header[0..12].try_into()?;
        let ct_and_tag = &header[12..Self::HEADER_LEN]; // 40 + 16 = 56 bytes

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

impl<T: Backend> EncryptionTranslator for CryptoMator<T> {
    const CIPHER_BLOCK_LEN: u64 = Self::PLAIN_BLOCK_LEN + 28;
    const HEADER_LEN: usize = 68;
    const PLAIN_BLOCK_LEN: u64 = 32768;
    const ENCRYPT_SPARSE_PARTS: bool = true;
    const EMPTY_FILE_HAS_HEADER: bool = true;
    fn cipher_name_to_plain(&self, parent_dir_id: &[u8], cipher_name: &str) -> Result<String> {
        log::debug!(
            "cipher name to plain on {cipher_name} with parent_dir_id_len {}",
            parent_dir_id.len()
        );
        if cipher_name == "." || cipher_name == ".." {
            return Ok(cipher_name.into());
        }
        let cipher_name = cipher_name.strip_suffix(".c9r").unwrap_or(cipher_name);
        let bin = base64::engine::general_purpose::URL_SAFE.decode(cipher_name)?;

        let mut siv = Aes256Siv::new_from_slice(&self.siv_key)
            .map_err(|e| anyhow!("invalid AES-SIV key length: {e}"))?;

        let plain_bytes = siv
            .decrypt(std::iter::once(parent_dir_id), &bin)
            .map_err(|_| anyhow!("AES-SIV decryption failed"))?;

        let s = str::from_utf8(&plain_bytes)?;
        Ok(s.to_string())
    }
    fn plain_name_to_cipher(&self, parent_dir_id: &[u8], plain_name: &str) -> Result<String> {
        if plain_name == "." || plain_name == ".." {
            return Ok(plain_name.to_string());
        }
        // 1) Unicode NFC + UTF-8 (Cryptomator spec)
        let nfc_name: String = plain_name.nfc().collect();
        let pt = nfc_name.as_bytes();

        // 2) AES-SIV with AD = parent_dir_id
        // Key material: 64 bytes = mac_master_key || master_key

        let mut siv = Aes256Siv::new_from_slice(&self.siv_key)
            .map_err(|e| anyhow!("invalid AES-SIV key length: {e}"))?;

        let ct = siv
            .encrypt(std::iter::once(parent_dir_id), pt)
            .map_err(|_| anyhow!("AES-SIV encryption failed"))?;

        // 3) base64url + ".c9r"
        // Cryptomator format 7+ uses base64url and the .c9r extension.
        // (Padding '=' is allowed/used in examples.)
        let b64 = base64::engine::general_purpose::URL_SAFE.encode(ct);
        Ok(format!("{b64}.c9r"))
    }
    fn cipher_block_to_plain(
        &self,
        header: &[u8],
        block_no: u64,
        cipher_data: &[u8],
    ) -> Result<Vec<u8>> {
        // if data is empty, then return empty vec
        if cipher_data.is_empty() {
            return Ok(Vec::default());
        }

        // 1) parse header -> contentKey + headerNonce
        let (content_key, header_nonce) = self.decrypt_content_key_from_header(header)?;

        // 2) parse chunk
        if cipher_data.len() < (Self::CIPHER_BLOCK_LEN - Self::PLAIN_BLOCK_LEN) as usize {
            bail!(
                "cipher chunk too short: {} < {}",
                cipher_data.len(),
                Self::CIPHER_BLOCK_LEN - Self::PLAIN_BLOCK_LEN
            );
        }
        let (chunk_nonce_bytes, ct_and_tag) = cipher_data.split_at(HEADER_NONCE_LEN);

        // 3) build AAD = be64(block_no) || headerNonce
        let mut aad = [0u8; 8 + 12];
        aad[0..8].copy_from_slice(&block_no.to_be_bytes());
        aad[8..20].copy_from_slice(&header_nonce);

        // 4) decrypt
        let cipher = Aes256Gcm::new_from_slice(&content_key)
            .map_err(|e| anyhow!("AES-GCM init failed: {e}"))?;

        let nonce = aes_gcm::Nonce::from_slice(chunk_nonce_bytes);

        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct_and_tag,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow!("chunk decrypt failed (auth failed / wrong key / corrupted data)")
            })?;
        Ok(pt)
    }
    fn cipher_metavalue_to_plain(&self, cipher_metavalue: &[u8]) -> Result<Vec<u8>> {
        if cipher_metavalue.len() < Self::HEADER_LEN {
            bail!(
                "target link too short! {} < {}",
                cipher_metavalue.len(),
                Self::HEADER_LEN
            );
        }
        self.cipher_block_to_plain(
            &cipher_metavalue[..Self::HEADER_LEN],
            0,
            &cipher_metavalue[Self::HEADER_LEN..],
        )
    }
    fn generate_cipher_header(&self) -> Result<Vec<u8>> {
        const MARKER_LEN: usize = 8;
        const CONTENT_KEY_LEN: usize = 32;

        // 1) headerNonce aléatoire
        let mut header_nonce = [0u8; HEADER_NONCE_LEN];
        rand::rng().fill_bytes(&mut header_nonce);

        // 2) contentKey aléatoire (clé par fichier)
        let mut content_key = [0u8; CONTENT_KEY_LEN];
        rand::rng().fill_bytes(&mut content_key);

        // 3) plaintext header payload = 8 * 0xFF || contentKey
        let mut payload_pt = [0u8; MARKER_LEN + CONTENT_KEY_LEN];
        payload_pt[..MARKER_LEN].fill(0xFF);
        payload_pt[MARKER_LEN..].copy_from_slice(&content_key);

        // 4) AES-256-GCM encrypt avec master_key, AAD vide
        let cipher =
            Aes256Gcm::new_from_slice(self.master_key()).context("master_key must be 32 bytes")?;
        let nonce = aes_gcm::Nonce::from_slice(&header_nonce);

        // encrypt() renvoie ciphertext||tag (tag=16)
        let ct_and_tag = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &payload_pt,
                    aad: &[],
                },
            )
            .map_err(|e| anyhow!("{e} - header encryption failed"))?;

        // 5) header final: nonce || ct || tag
        let mut out = Vec::with_capacity(HEADER_NONCE_LEN + ct_and_tag.len());
        out.extend_from_slice(&header_nonce);
        out.extend_from_slice(&ct_and_tag);

        debug_assert_eq!(
            out.len(),
            Self::HEADER_LEN,
            "Cryptomator header must be {} bytes",
            Self::HEADER_LEN
        );
        Ok(out)
    }
    fn generate_diriv(&self) -> Vec<u8> {
        uuid::Uuid::new_v4().to_string().into()
    }
    fn plain_block_to_cipher(
        &self,
        header: &[u8],
        block_no: u64,
        plain_data: &[u8],
    ) -> Result<Vec<u8>> {
        let (content_key, header_nonce) = self.decrypt_content_key_from_header(header)?;

        let mut aad = [0u8; 8 + 12];
        aad[0..8].copy_from_slice(&block_no.to_be_bytes());
        aad[8..20].copy_from_slice(&header_nonce);

        let mut chunk_nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut chunk_nonce);

        let cipher = Aes256Gcm::new_from_slice(&content_key)
            .map_err(|e| anyhow!("AES-GCM init failed: {e}"))?;

        let ct_and_tag = cipher
            .encrypt(
                aes_gcm::Nonce::from_slice(&chunk_nonce),
                Payload {
                    msg: plain_data,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("chunk encrypt failed"))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ct_and_tag.len());
        out.extend_from_slice(&chunk_nonce);
        out.extend_from_slice(&ct_and_tag);
        Ok(out)
    }
    fn plain_metavalue_to_cipher(&self, plain_metavalue: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(
            Self::HEADER_LEN
                + (Self::CIPHER_BLOCK_LEN - Self::PLAIN_BLOCK_LEN) as usize
                + plain_metavalue.len(),
        );
        let mut header = self.generate_cipher_header()?;
        let mut data = self.plain_block_to_cipher(&header, 0, plain_metavalue)?;
        result.append(&mut header);
        result.append(&mut data);

        Ok(result)
    }
    fn cipher_size_to_plain(&self, cipher_size: u64) -> Result<u64> {
        if cipher_size == 0 {
            return Ok(0);
        }
        let size = cipher_size
            .checked_sub(Self::HEADER_LEN as u64)
            .ok_or_else(|| anyhow!("size < HEADER_LEN"))?;
        let overhead = Self::CIPHER_BLOCK_LEN - Self::PLAIN_BLOCK_LEN;
        let (div, mut remain) = (size / Self::CIPHER_BLOCK_LEN, size % Self::CIPHER_BLOCK_LEN);
        if remain > 0 {
            remain = remain
                .checked_sub(overhead)
                .ok_or_else(|| anyhow!("remaining size < TAG_LEN + NONCE_LEN"))?;
        }
        Ok(div * Self::PLAIN_BLOCK_LEN + remain)
    }

    /// Converts plain file size to cipher file size.
    fn plain_size_to_cipher(&self, plain_size: u64) -> u64 {
        if plain_size == 0 {
            return Self::HEADER_LEN as u64;
        }
        let (div, mut remain) = (
            plain_size / Self::PLAIN_BLOCK_LEN,
            plain_size % Self::PLAIN_BLOCK_LEN,
        );
        if remain > 0 {
            remain += Self::CIPHER_BLOCK_LEN - Self::PLAIN_BLOCK_LEN;
        }
        Self::HEADER_LEN as u64 + div * Self::CIPHER_BLOCK_LEN + remain
    }
}

fn folder_path_to_cipher_and_dirid(
    this: &CryptoMator<FsBackend>,
    plain_path: &Utf8Path,
) -> Result<(Utf8PathBuf, Vec<u8>)> {
    this.backend.access(|cache| {
        if let Some((dir_id, cipher_path)) = cache.get(plain_path.as_str()) {
            Ok((cipher_path.to_owned(), dir_id.clone()))
        } else {
            if plain_path.as_str().is_empty() {
                let cipher_path = this.dir_id_to_storage_path(&String::default())?;
                cache.insert(String::default(), (Vec::default(), cipher_path.clone()));
                return Ok((cipher_path, Vec::default()));
            }

            let mut partial_plain_path = Utf8PathBuf::from("");
            let mut absolute_path = Utf8PathBuf::default();
            let mut is_root = true;
            for plain_part in plain_path.iter() {
                if let Some((dir_id, cipher_parent)) = cache.get(partial_plain_path.as_str()) {
                    let cipher_part = this.plain_name_to_cipher(dir_id, plain_part)?;
                    absolute_path = cipher_parent.join(cipher_part);
                } else {
                    let dir_id = if is_root {
                        String::default()
                    } else {
                        read_dirid(&absolute_path)?
                    };

                    absolute_path = this.dir_id_to_storage_path(&dir_id)?;
                    cache.insert(
                        partial_plain_path.as_str().into(),
                        (dir_id.as_bytes().into(), absolute_path.clone()),
                    );
                    let cipher_part = this.plain_name_to_cipher(dir_id.as_bytes(), plain_part)?;
                    absolute_path.push(cipher_part);
                }
                partial_plain_path.push(plain_part);
                if is_root {
                    is_root = false
                }
            }

            let dir_id = read_dirid(&absolute_path)?;
            absolute_path = this.dir_id_to_storage_path(&dir_id)?;

            cache.insert(
                partial_plain_path.as_str().into(),
                (dir_id.as_bytes().into(), absolute_path.clone()),
            );

            Ok((absolute_path, dir_id.as_bytes().into()))
        }
    })
}

impl CipherPathLayout for CryptoMator<FsBackend> {
    type LowerFs = DefaultFs;
    fn lower_fs(&self) -> &Self::LowerFs {
        &DefaultFs
    }
    fn plain_path_to_cipher(&self, plain_path: &Utf8Path) -> Result<Utf8PathBuf> {
        if plain_path.as_str().is_empty() {
            return Ok(folder_path_to_cipher_and_dirid(self, plain_path)?.0);
        }

        let parent = plain_path.parent().unwrap_or_else(|| "".into());
        let name = plain_path.file_name().or_invalid()?;
        let (cipher_parent_path, dir_id) = folder_path_to_cipher_and_dirid(self, parent)?;
        let cipher_name = self.plain_name_to_cipher(&dir_id, name)?;
        Ok(cipher_parent_path.join(cipher_name))
    }
    fn create_temp_name(&self, path: &str, is_dir_iv: bool) -> Utf8PathBuf {
        temp_file_path(&self.backend.cipher_root, path, is_dir_iv)
    }
    fn remove_cached_plain_path(&self, plain_path: &str) {
        crate::default_remove_cached_plain_path(&self.backend, plain_path);
    }
    fn get_dir_iv_file(&self, cipher_folder_path: &Utf8Path) -> Utf8PathBuf {
        cipher_folder_path.join("dir.c9r")
    }
}

impl EncryptionLayout for CryptoMator<FsBackend> {
    fn list_dir_plain_names(
        &self,
        plain_path: &Utf8Path,
    ) -> Result<impl Iterator<Item = Result<(crate::FsDirEntry, Utf8PathBuf)>> + '_> {
        let (cipher_path, dir_id) = folder_path_to_cipher_and_dirid(self, plain_path)?;
        // let plain_path: Utf8PathBuf = plain_path.into();
        // let cipher_path = self.plain_path_to_cipher(&plain_path)?;
        // let dir_id = if plain_path == "" {
        //     "".into()
        // } else {
        //     read_dirid(&cipher_path)?
        // };
        // let cipher_path = self.dir_id_to_storage_path(&dir_id)?;
        log::debug!("read_dir on {}", &cipher_path);
        Ok(std::fs::read_dir(&cipher_path)?.filter_map(move |entry| {
            match map_dir_entry(self, &cipher_path, &dir_id, entry) {
                Ok(Some((plain_name, cipher_path))) => Some(Ok((plain_name, cipher_path))),
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            }
        }))
    }

    fn metadata(&self, plain_path: &str) -> std::io::Result<crate::Metadata> {
        let cipher_path = self.plain_path_to_cipher(plain_path.into()).or_invalid()?;
        log::debug!("metadata on [{plain_path}] : {cipher_path}");
        let mut metadata = self.lower_fs().metadata(&cipher_path)?;
        metadata
            .adjust(self, &cipher_path, plain_path.is_empty())
            .or_invalid()?;
        Ok(metadata)
    }

    fn mkdir(
        &self,
        plain_path: &str,
        permissions: crate::Permissions,
    ) -> std::io::Result<Metadata> {
        log::debug!("mkdir on {plain_path}");
        let plain_path: &Utf8Path = plain_path.into();
        let parent = plain_path.parent().unwrap_or_else(|| "".into());
        let name = plain_path.file_name().or_invalid()?;

        log::debug!("parent {parent} - name {name}");

        let (parent_dir_id, cipher_parent_path) = self.backend.access(|cache| {
            if let Some((parent_dir_id, cipher_parent_path)) = cache.get(parent.as_str()) {
                log::debug!("found {parent} in cache! {cipher_parent_path}");
                Ok::<_, std::io::Error>((
                    str::from_utf8(parent_dir_id).unwrap_or_default().into(),
                    cipher_parent_path.clone(),
                ))
            } else {
                let cipher_parent_path = self.plain_path_to_cipher(parent).or_invalid()?;
                log::debug!("computed cipher_parent_path for {parent} - {cipher_parent_path}");
                let parent_dir_id = read_dirid(&cipher_parent_path).or_invalid()?;
                Ok((parent_dir_id, cipher_parent_path))
            }
        })?;
        log::debug!("cipher parent path is {cipher_parent_path}");
        //let cipher_parent_path = self.plain_path_to_cipher(parent).or_invalid()?;
        //let parent_dir_id = read_dirid(&cipher_parent_path).or_invalid()?;
        let cipher_name = self
            .plain_name_to_cipher(parent_dir_id.as_bytes(), name)
            .or_invalid()?;
        log::debug!("cipher_name is {cipher_name}");
        let new_dir_iv = self.generate_diriv();
        let cipher_path = cipher_parent_path.join(cipher_name);
        log::debug!("cipher_path is {cipher_path}");
        self.lower_fs().mkdir(&cipher_path)?;
        let new_dir_iv_file = self.get_dir_iv_file(&cipher_path);
        log::debug!("new_dir_iv_file is {new_dir_iv_file}");
        self.lower_fs()
            .put(&new_dir_iv_file, &new_dir_iv)
            .or_invalid()?;

        self.mkdir_storage_path(str::from_utf8(&new_dir_iv).unwrap_or_default())
            .or_invalid()?;
        self.lower_fs().set_permissions(&cipher_path, permissions)
    }
    fn mknode(
        &self,
        plain_path: &str,
        permissions: crate::Permissions,
    ) -> std::io::Result<Metadata> {
        let cipher_path = self.plain_path_to_cipher(plain_path.into()).or_invalid()?;
        self.lower_fs()
            .put(&cipher_path, &self.generate_cipher_header().or_invalid()?)
            .or_invalid()?;
        self.lower_fs().set_permissions(&cipher_path, permissions)
    }
    fn remove_dir(&self, plain_path: &str) -> std::io::Result<()> {
        let cipher_path = self.plain_path_to_cipher(plain_path.into()).or_invalid()?;
        let dir_id = read_dirid(&cipher_path).or_invalid()?;

        let children_path = self.dir_id_to_storage_path(&dir_id).or_invalid()?;
        self.lower_fs()
            .remove_dir(&children_path, false)
            .inspect_err(|e| log::error!("cant rmdir on {children_path} - {e}"))?;
        self.lower_fs()
            .remove_dir(&cipher_path, true)
            .inspect_err(|e| log::error!("cant rmdir all on {cipher_path} - {e}"))?;
        self.remove_cached_plain_path(plain_path);
        Ok(())
    }
    fn remove(&self, plain_path: &str) -> std::io::Result<()> {
        let cipher_path = self.plain_path_to_cipher(plain_path.into()).or_invalid()?;
        let meta = self.lower_fs().metadata(&cipher_path)?;
        match meta.file_type {
            FileType::File => self.lower_fs().remove_file(&cipher_path),
            _ => self.lower_fs().remove_dir(&cipher_path, true),
        }
    }
    fn read_symlink(&self, plain_path: &str) -> std::io::Result<String> {
        let cipher_path = self.plain_path_to_cipher(plain_path.into()).or_invalid()?;
        let symlink_content = cipher_path.join("symlink.c9r");
        let data = self
            .lower_fs()
            .read(&symlink_content, 0, 1024)
            .or_invalid()?;
        let target = self.cipher_metavalue_to_plain(&data).or_invalid()?;
        Ok(str::from_utf8(&target).or_invalid()?.into())
    }
    fn create_symlink(&self, plain_path: &str, target: &str) -> std::io::Result<Metadata> {
        let cipher_path = self.plain_path_to_cipher(plain_path.into()).or_invalid()?;
        let cipher_target = self
            .plain_metavalue_to_cipher(target.as_bytes())
            .or_invalid()?;
        self.lower_fs().mkdir(&cipher_path)?;
        self.lower_fs()
            .put(&cipher_path.join("symlink.c9r"), &cipher_target)?;
        let mut meta = self.lower_fs().metadata(&cipher_path)?;
        meta.adjust(self, &cipher_path, false).or_invalid()?;
        Ok(meta)
    }
}

fn is_special_entry(name: &str) -> bool {
    name == "dirid.c9r"
}

trait AdujstMetadata {
    fn adjust<T: EncryptionTranslator>(
        &mut self,
        this: &T,
        path: &Utf8Path,
        is_root: bool,
    ) -> Result<()>;
}

impl AdujstMetadata for Metadata {
    fn adjust<T: EncryptionTranslator>(
        &mut self,
        this: &T,
        path: &Utf8Path,
        is_root: bool,
    ) -> Result<()> {
        if self.file_type == FileType::File {
            self.len = this.cipher_size_to_plain(self.len).or_invalid()?;
            self.blocks = 1 + self.len / T::PLAIN_BLOCK_LEN;
        } else if self.file_type == FileType::Directory {
            if !is_root {
                let dir = path.join("dir.c9r");
                if !std::fs::exists(&dir)? {
                    let symlink = path.join("symlink.c9r");
                    if std::fs::exists(&symlink)? {
                        self.file_type = FileType::SymLink;
                        self.permissions = 0o777_u16.into();
                    } else {
                        self.file_type = FileType::Other;
                    }
                }
            }
        } else {
            self.file_type = FileType::Other;
        }
        Ok(())
    }
}

fn map_dir_entry(
    this: &impl EncryptionLayout,
    cipher_path: &Utf8Path,
    dir_iv: &[u8],
    entry: Result<DirEntry, std::io::Error>,
) -> Result<Option<(FsDirEntry, Utf8PathBuf)>> {
    match entry {
        Ok(entry) => {
            let cipher_name = &entry.file_name();
            let cipher_name: String = cipher_name.to_string_lossy().into();
            let mut fs_dir_entry: FsDirEntry = entry.into();

            if let Some(metadata) = fs_dir_entry.metadata.as_mut() {
                metadata.adjust(this, &cipher_path.join(&cipher_name), false)?;
                if let Some(file_type) = fs_dir_entry.file_type.as_mut() {
                    *file_type = metadata.file_type;
                }
            }

            if is_special_entry(&cipher_name) {
                Ok(None)
            } else {
                let plain_name = this.cipher_name_to_plain(dir_iv, &cipher_name)?;
                Ok(Some((
                    fs_dir_entry.with_name(plain_name),
                    cipher_path.join(Utf8Path::new(&cipher_name)),
                )))
            }
        }
        Err(e) => Err(e)?,
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
