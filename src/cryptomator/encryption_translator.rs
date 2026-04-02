use super::{CryptoMator, HEADER_NONCE_LEN, NONCE_LEN};
use crate::{Backend, EncryptionTranslator, Result};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, Payload},
};
use aes_siv::aead::KeyInit;
use aes_siv::siv::Aes256Siv;
use anyhow::{Context, anyhow, bail};
use base64::Engine;
use rand::RngCore;
use unicode_normalization::UnicodeNormalization;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryBackend;

    /// Creates a deterministic backend instance for pure crypto tests.
    fn test_backend() -> CryptoMator<MemoryBackend> {
        let mut siv_key = [0u8; 64];
        for (i, byte) in siv_key.iter_mut().enumerate() {
            *byte = i as u8;
        }

        CryptoMator {
            backend: MemoryBackend,
            siv_key,
        }
    }

    #[test]
    fn filename_roundtrip_preserves_plain_name() {
        let backend = test_backend();
        let parent_dir_id = b"directory-id";
        let plain_name = "hello-e\u{301}_file.txt";

        let cipher_name = backend
            .plain_name_to_cipher(parent_dir_id, plain_name)
            .unwrap();
        let decrypted_name = backend
            .cipher_name_to_plain(parent_dir_id, &cipher_name)
            .unwrap();

        assert_eq!(decrypted_name, "hello-\u{e9}_file.txt");
    }

    #[test]
    fn block_roundtrip_preserves_plain_data() {
        let backend = test_backend();
        let header = backend.generate_cipher_header().unwrap();
        let plain_data = b"hello encrypted world";

        let cipher_data = backend
            .plain_block_to_cipher(&header, 0, plain_data)
            .unwrap();
        let decrypted_data = backend
            .cipher_block_to_plain(&header, 0, &cipher_data)
            .unwrap();

        assert_eq!(decrypted_data, plain_data);
    }

    #[test]
    fn metavalue_roundtrip_preserves_plain_data() {
        let backend = test_backend();
        let plain_value = b"/some/symlink/target";

        let cipher_value = backend.plain_metavalue_to_cipher(plain_value).unwrap();
        let decrypted_value = backend.cipher_metavalue_to_plain(&cipher_value).unwrap();

        assert_eq!(decrypted_value, plain_value);
    }

    #[test]
    fn plain_and_cipher_sizes_roundtrip() {
        let backend = test_backend();

        for plain_size in [
            0,
            1,
            15,
            128,
            4095,
            4096,
            4097,
            32767,
            32768,
            32769,
            65536 + 123,
        ] {
            let cipher_size = backend.plain_size_to_cipher(plain_size);
            let recovered_plain_size = backend.cipher_size_to_plain(cipher_size).unwrap();
            assert_eq!(recovered_plain_size, plain_size);
        }
    }

    #[test]
    fn corrupted_header_is_rejected() {
        let backend = test_backend();
        let mut header = backend.generate_cipher_header().unwrap();
        let plain_data = b"integrity matters";
        let cipher_data = backend
            .plain_block_to_cipher(&header, 0, plain_data)
            .unwrap();

        header[0] ^= 0x01;

        assert!(
            backend
                .cipher_block_to_plain(&header, 0, &cipher_data)
                .is_err()
        );
    }

    #[test]
    fn filename_decryption_rejects_wrong_parent_dir_id() {
        let backend = test_backend();
        let cipher_name = backend
            .plain_name_to_cipher(b"directory-id", "hello.txt")
            .unwrap();

        assert!(
            backend
                .cipher_name_to_plain(b"other-directory-id", &cipher_name)
                .is_err()
        );
    }

    #[test]
    fn block_decryption_rejects_wrong_block_number() {
        let backend = test_backend();
        let header = backend.generate_cipher_header().unwrap();
        let cipher_data = backend
            .plain_block_to_cipher(&header, 7, b"hello encrypted world")
            .unwrap();

        assert!(
            backend
                .cipher_block_to_plain(&header, 8, &cipher_data)
                .is_err()
        );
    }

    #[test]
    fn cipher_size_to_plain_rejects_truncated_header() {
        let backend = test_backend();

        assert!(
            backend
                .cipher_size_to_plain((CryptoMator::<MemoryBackend>::HEADER_LEN - 1) as u64)
                .is_err()
        );
    }

    #[test]
    fn empty_block_roundtrip_preserves_plain_data() {
        let backend = test_backend();
        let header = backend.generate_cipher_header().unwrap();
        let cipher_data = backend.plain_block_to_cipher(&header, 0, b"").unwrap();
        let decrypted_data = backend
            .cipher_block_to_plain(&header, 0, &cipher_data)
            .unwrap();

        assert_eq!(decrypted_data, b"");
    }

    #[test]
    fn empty_metavalue_roundtrip_preserves_plain_data() {
        let backend = test_backend();
        let cipher_value = backend.plain_metavalue_to_cipher(b"").unwrap();
        let decrypted_value = backend.cipher_metavalue_to_plain(&cipher_value).unwrap();

        assert_eq!(decrypted_value, b"");
    }
}
