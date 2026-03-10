use super::GoCryptFs;
use crate::{Backend, EncryptionTranslator, Result};
use aes::{Aes256, cipher::KeyIvInit};
use aes_gcm::{
    AeadCore, AesGcm, KeyInit,
    aead::{Aead, OsRng, Payload},
};
use anyhow::{Context, anyhow, bail};
use base64::{Engine, engine::GeneralPurpose};
use eme_mode::DynamicEme;
use generic_array::{ArrayLength, GenericArray};
use rand::RngCore;
use typenum::{U8, U16};

/// Removes PKCS7 padding from a 16-byte aligned buffer.
fn pkcs7_unpad16(mut buf: Vec<u8>) -> Result<Vec<u8>> {
    if buf.is_empty() || !buf.len().is_multiple_of(16) {
        bail!("bad padded length");
    }
    let pad = *buf.last().unwrap() as usize;
    if pad == 0 || pad > 16 || pad > buf.len() {
        bail!("bad pkcs7 pad len");
    }
    // all padding bytes must be identical
    if !buf[buf.len() - pad..].iter().all(|&b| b as usize == pad) {
        bail!("bad pkcs7 padding bytes");
    }
    buf.truncate(buf.len() - pad);
    if buf.is_empty() {
        bail!("unpadded name is empty");
    }
    Ok(buf)
}

/// Adds PKCS7 padding to make the input 16-byte aligned.
fn pkcs7_pad16(input: &[u8]) -> Result<Vec<u8>> {
    if input.is_empty() {
        bail!("empty filename component is invalid");
    }
    let pad_len = 16 - (input.len() % 16);
    let pad_len = if pad_len == 0 { 16 } else { pad_len };
    let mut out = Vec::with_capacity(input.len() + pad_len);
    out.extend_from_slice(input);
    out.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    Ok(out)
}
/// File identifier size embedded in GoCryptFS file headers.
const FILEID_LEN: usize = 16;
/// Creates additional authenticated data for GCM encryption with 16-byte file ID.
fn make_aad_16(block_no: u64, file_id: &[u8; FILEID_LEN]) -> [u8; 8 + FILEID_LEN] {
    let mut aad = [0u8; 8 + FILEID_LEN];
    aad[..8].copy_from_slice(&(block_no).to_be_bytes());
    aad[8..].copy_from_slice(file_id);
    aad
}

/// Creates additional authenticated data for GCM encryption with generic file ID length.
fn _make_aad<N>(block_no: u64, file_id: &GenericArray<u8, N>) -> GenericArray<u8, N::Output>
where
    N: ArrayLength + core::ops::Add<U8>,
    N::Output: ArrayLength,
{
    let mut aad: GenericArray<u8, N::Output> = GenericArray::default();
    aad[..8].copy_from_slice(&(block_no).to_be_bytes());
    aad[8..].copy_from_slice(file_id);
    aad
}

impl<T: Backend> EncryptionTranslator for GoCryptFs<T> {
    const HEADER_LEN: usize = GoCryptFs::<T>::HEADER_LEN;
    const CIPHER_BLOCK_LEN: u64 = GoCryptFs::<T>::CIPHER_BLOCK_LEN;
    const PLAIN_BLOCK_LEN: u64 = GoCryptFs::<T>::PLAIN_BLOCK_LEN;

    /// Decrypts a cipher filename to plain text.
    fn cipher_name_to_plain(&self, parent_iv: &[u8], cipher_name: &str) -> Result<String> {
        if cipher_name == "." || cipher_name == ".." {
            return Ok(cipher_name.into());
        }

        let engine = if self.raw64 {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
        } else {
            base64::engine::general_purpose::URL_SAFE
        };

        let mut bin = engine.decode(cipher_name.as_bytes())?;

        if !bin.len().is_multiple_of(16) {
            bail!("decoded len {} not multiple of 16", bin.len());
        }

        // EME decrypt in-place
        let mut eme = DynamicEme::<Aes256>::new_from_slices(self.eme_key.as_slice(), parent_iv)
            .context("EME init")?;
        eme.decrypt_block_mut(&mut bin);

        let plain_bytes = pkcs7_unpad16(bin)?;
        let s = str::from_utf8(&plain_bytes)?;
        Ok(s.to_string())
    }
    /// Encrypts a plain filename to cipher text.
    fn plain_name_to_cipher(&self, parent_iv: &[u8], plain_name: &str) -> Result<String> {
        if plain_name == "." || plain_name == ".." {
            return Ok(plain_name.to_string());
        }

        let mut buf = pkcs7_pad16(plain_name.as_bytes())?;

        let mut eme = DynamicEme::<Aes256>::new_from_slices(&self.eme_key, parent_iv)
            .map_err(|e| anyhow!("EME init: {e:?}"))?;
        eme.encrypt_block_mut(&mut buf);

        let b64 = if self.raw64 {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
        } else {
            base64::engine::general_purpose::URL_SAFE
        };

        Ok(b64.encode(buf))
    }
    /// Decrypts a cipher block to plain data.
    fn cipher_block_to_plain(&self, header: &[u8], block_no: u64, data: &[u8]) -> Result<Vec<u8>> {
        // if data is empty, then return empty vec
        if data.is_empty() {
            return Ok(Vec::default());
        }

        let overhead = Self::NONCE_LEN + Self::TAG_LEN;
        let data_len = data.len();
        if data_len < overhead {
            bail!("ciphertext block too short: {data_len}");
        }
        // A fully zeroed block is treated as implicit plaintext zeros after sparse growth.
        if data.iter().all(|&v| v == 0) {
            return Ok(vec![0u8; data_len - overhead]);
        }

        let (nonce, msg) = data.split_at(Self::NONCE_LEN);
        let aad: &[u8] = if header.is_empty() {
            &[0; 8]
        } else {
            let file_id = &header[Self::HEADER_LEN - Self::FILEID_LEN..];
            &make_aad_16(block_no, file_id.try_into()?)
        };
        //let aad = make_aad_16(block_no, file_id.try_into()?);
        type Aes256GcmIv128 = AesGcm<Aes256, U16>;
        let cipher = Aes256GcmIv128::new_from_slice(&self.gcm_key).map_err(|e| anyhow!("{e}"))?;
        cipher
            .decrypt(nonce.into(), Payload { msg, aad })
            .map_err(|_| anyhow!("GCM auth failed (bad key/nonce/aad or corrupted data)"))
    }
    /// Encrypts a plain block to cipher data.
    fn plain_block_to_cipher(&self, header: &[u8], block_no: u64, data: &[u8]) -> Result<Vec<u8>> {
        let aad: &[u8] = if header.is_empty() {
            &[0; 8]
        } else {
            let file_id = &header[Self::HEADER_LEN - Self::FILEID_LEN..];
            &make_aad_16(block_no, file_id.try_into()?)
        };
        type Aes256GcmIv128 = AesGcm<Aes256, U16>;
        let nonce = Aes256GcmIv128::generate_nonce(&mut OsRng);
        let cipher = Aes256GcmIv128::new_from_slice(&self.gcm_key).map_err(|e| anyhow!("{e}"))?;

        let cipher_data = cipher
            .encrypt(nonce.as_slice().into(), Payload { msg: data, aad })
            .map_err(|_| anyhow!("GCM encrypt failed"))?;
        let mut full_result = Vec::with_capacity(nonce.len() + cipher_data.len());
        full_result.extend_from_slice(nonce.as_slice());
        full_result.extend_from_slice(&cipher_data);
        Ok(full_result)
    }

    /// Converts cipher file size to plain file size.
    fn cipher_size_to_plain(&self, cipher_size: u64) -> Result<u64> {
        if cipher_size == 0 {
            return Ok(0);
        }
        let size = cipher_size
            .checked_sub(Self::HEADER_LEN as u64)
            .ok_or_else(|| anyhow!("size < HEADER_LEN"))?;
        let overhead = (Self::TAG_LEN + Self::NONCE_LEN) as u64;
        let (div, mut remain) = (size / Self::CIPHER_BLOCK_LEN, size % Self::CIPHER_BLOCK_LEN);
        if remain > 0 {
            remain = remain
                .checked_sub(overhead)
                .ok_or_else(|| anyhow!("remaining size < TAG_LEN + NONCE_LEN"))?;
        }
        Ok(div * Self::PLAIN_BLOCK_LEN + remain)
    }
    /// Generates a cipher header for the file.
    fn generate_cipher_header(&self) -> Vec<u8> {
        // Header layout: reserved byte, version, then random file ID.
        let mut header = vec![0u8; Self::HEADER_LEN];
        header[0] = 0; // reserved
        header[1] = 2; // version
        rand::rng().fill_bytes(&mut header[Self::HEADER_LEN - Self::FILEID_LEN..Self::HEADER_LEN]);

        header
    }
    /// Generates a random initialization vector for directories.
    fn generate_diriv(&self) -> [u8; 16] {
        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut iv);
        iv
    }

    /// Converts plain file size to cipher file size.
    fn plain_size_to_cipher(&self, plain_size: u64) -> u64 {
        if plain_size == 0 {
            return 0;
        }
        let (div, mut remain) = (
            plain_size / Self::PLAIN_BLOCK_LEN,
            plain_size % Self::PLAIN_BLOCK_LEN,
        );
        if remain > 0 {
            remain += (Self::TAG_LEN + Self::NONCE_LEN) as u64;
        }
        Self::HEADER_LEN as u64 + div * Self::CIPHER_BLOCK_LEN + remain
    }

    /// Encrypts a plain metavalue (e.g., symlink target) to cipher string.
    fn plain_metavalue_to_cipher(&self, plain_metavalue: &[u8]) -> Result<String> {
        let data = self.plain_block_to_cipher(&[], 0, plain_metavalue)?;
        Ok(b64_engine(self.raw64).encode(data))
    }
    /// Decrypts a cipher metavalue to plain bytes.
    fn cipher_metavalue_to_plain(&self, cipher_metavalue: &str) -> Result<Vec<u8>> {
        let data = b64_engine(self.raw64).decode(cipher_metavalue)?;
        self.cipher_block_to_plain(&[], 0, &data)
    }
}

/// Returns the appropriate base64 engine based on raw64 flag.
fn b64_engine(raw64: bool) -> GeneralPurpose {
    if raw64 {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
    } else {
        base64::engine::general_purpose::URL_SAFE
    }
}
