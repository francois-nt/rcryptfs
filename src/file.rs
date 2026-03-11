use crate::{
    EncryptionTranslator, GenericOpenOptions, OrIoError, ReadAt, SetLen, SetSync, Size, Utf8Path,
    WriteAt,
};
use log::{debug, error};
use parking_lot::RwLock;
use std::{fs::OpenOptions, sync::Arc};

/// Wraps a cipher file and exposes plain-text block I/O.
pub struct CryptFsFile<T: EncryptionTranslator> {
    backend: Arc<T>,
    cipher_file: std::fs::File,
    header: RwLock<Vec<u8>>,
}

impl<T: EncryptionTranslator> CryptFsFile<T> {
    /// Opens the backing cipher file and eagerly loads the file header when present.
    pub fn try_open(
        cipher_path: &Utf8Path,
        backend: Arc<T>,
        mut options: GenericOpenOptions,
    ) -> std::io::Result<Self> {
        if options.append {
            options.write = true;
        }
        let mut options: OpenOptions = options.into();
        let cipher_file = options
            .read(true)
            .append(false)
            .open(cipher_path)
            .or_invalid()?;

        let cipher_file_size = cipher_file
            .size()?
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;

        let header = if cipher_file_size == 0 {
            Vec::default()
        } else {
            Self::read_header(&cipher_file)?
        };

        Ok(Self {
            cipher_file,
            backend,
            header: header.into(),
        })
    }
    /// Reads the fixed-size file header from the beginning of the cipher file.
    fn read_header(cipher_file: &std::fs::File) -> std::io::Result<Vec<u8>> {
        let mut buffer: Vec<u8> = vec![0; T::HEADER_LEN];
        cipher_file.read_exact_at(0, &mut buffer)?;
        Ok(buffer)
    }
    /// Creates and persists a fresh header for a newly materialized cipher file.
    fn create_header(&self) -> std::io::Result<()> {
        let header = self.backend.generate_cipher_header();
        self.cipher_file.write_all_at(0, &header)?;
        *self.header.write() = header;
        Ok(())
    }
    /// Returns the current on-disk cipher file size.
    fn get_physical_size(&self) -> std::io::Result<u64> {
        self.cipher_file
            .size()
            .inspect_err(|e| error!("catastrophic error while reading size len {e}"))?
            .ok_or_else(|| {
                error!("catastrophic error while reading size (null value)");
                std::io::Error::from_raw_os_error(libc::EINVAL)
            })
    }
    /// Reads and decrypts one cipher block into the caller-provided plain buffer.
    fn read_block(
        &self,
        block_no: u64,
        header: &[u8],
        plain_buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        let mut cipher_buffer = vec![0; T::CIPHER_BLOCK_LEN as usize];
        let buffer_len = plain_buffer.len();

        let bytes_read = self.cipher_file.read_at(
            T::HEADER_LEN as u64 + block_no * T::CIPHER_BLOCK_LEN,
            &mut cipher_buffer,
        )?;
        let plain_data = self
            .backend
            .cipher_block_to_plain(header, block_no, &cipher_buffer[0..bytes_read])
            .or_invalid()
            .inspect_err(|_| {
                error!(
                    "error in reading block {block_no} with len {} header is {:?}!",
                    plain_buffer.len(),
                    header
                )
            })?;

        let bytes_read = plain_data.len();
        if bytes_read > buffer_len {
            plain_buffer.copy_from_slice(&plain_data[..buffer_len]);
        }
        // bytes_read <= buffer.len()
        else {
            plain_buffer[..bytes_read].copy_from_slice(&plain_data);
        }
        Ok(bytes_read.min(buffer_len))
    }
    /// Encrypts one plain block and writes it back at the matching cipher offset.
    fn write_block(
        &self,
        block_no: u64,
        header: &[u8],
        plain_data: &[u8],
    ) -> std::io::Result<usize> {
        debug!(
            "writing plain data block {} bytes at offset {}",
            plain_data.len(),
            block_no * T::PLAIN_BLOCK_LEN
        );
        let cipher_data = self
            .backend
            .plain_block_to_cipher(header, block_no, plain_data)
            .or_invalid()?;
        self.cipher_file.write_all_at(
            block_no * T::CIPHER_BLOCK_LEN + T::HEADER_LEN as u64,
            &cipher_data,
        )?;
        Ok(plain_data.len())
    }

    /// Re-encodes the boundary block when a resize changes authenticated block contents.
    fn re_encode_last_block(
        &self,
        current_plain_len: u64,
        target_plain_len: u64,
        header: &[u8],
        set_len: bool,
    ) -> std::io::Result<()> {
        // When extending the file:
        // - Pad the current last plaintext block with zeros and re-encrypt it.
        // - Extend beyond with zero blocks (no encryption needed: OS sparse set_len).
        //
        // When truncating:
        // - Truncate the new last plaintext block and re-encrypt it (updates the auth tag).
        // - If new length is exact block multiple (new_offset % BLOCK_LEN == 0), no re-encrypt: just truncate cipher file.
        if target_plain_len == 0 || current_plain_len == 0 || current_plain_len == target_plain_len
        {
            // no re-encoding needed.
            return Ok(());
        };

        let mut target_end_offset = (target_plain_len % T::PLAIN_BLOCK_LEN) as usize;
        let current_end_offset = (current_plain_len % T::PLAIN_BLOCK_LEN) as usize;
        if (current_end_offset == 0 && target_plain_len > current_plain_len)
            || (target_end_offset == 0 && target_plain_len < current_plain_len)
        {
            // no re-encoding needed.
            return Ok(());
        }
        if target_end_offset == 0 {
            target_end_offset = T::PLAIN_BLOCK_LEN as usize;
        }

        let last_block = (current_plain_len.min(target_plain_len) - 1) / T::PLAIN_BLOCK_LEN;
        let target_block = (target_plain_len - 1) / T::PLAIN_BLOCK_LEN;

        if !set_len && last_block == target_block {
            return Ok(());
        }

        let mut read_buffer = vec![0; T::PLAIN_BLOCK_LEN as usize];

        let bytes_read = self.read_block(last_block, header, &mut read_buffer)?;

        log::debug!(
            "re-encoding last block {last_block} bytes_read {bytes_read} current_len {current_plain_len} target_len {target_plain_len}"
        );

        if target_block > last_block {
            read_buffer[bytes_read..].fill(0);
            self.write_block(last_block, header, &read_buffer)?;
        } else {
            // target_block == last_block
            if target_end_offset > bytes_read {
                read_buffer[bytes_read..target_end_offset].fill(0);
            }
            self.write_block(last_block, header, &read_buffer[..target_end_offset])?;
        }
        Ok(())
    }
}

impl<T: EncryptionTranslator> ReadAt for CryptFsFile<T> {
    /// Reads plain bytes across encrypted block boundaries.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        debug!("trying to read at offset {} for len {}", offset, buf.len());
        let physical_size = self.get_physical_size()?;
        if buf.is_empty() || physical_size < T::HEADER_LEN as u64 {
            error!(
                "error reading with buf {} and physical size {physical_size}",
                buf.len()
            );
            return Ok(0);
        }

        let buf_len = buf.len();

        let header = self.header.read();

        let plain_start = offset;
        let plain_end = plain_start + buf.len() as u64;

        debug!("plain_start {plain_start} plain_end {plain_end}");

        let (block_no, first_block_offset) = (
            plain_start / T::PLAIN_BLOCK_LEN,
            plain_start % T::PLAIN_BLOCK_LEN,
        );
        let end_block_no = (plain_end - 1) / T::PLAIN_BLOCK_LEN;
        let mut total_bytes_read;

        if first_block_offset == 0 {
            let bytes_read = self
                .read_block(block_no, &header, buf)
                .inspect_err(|e| error!("read error in block_no {block_no} ! {e}"))?;

            total_bytes_read = bytes_read;
            if bytes_read < T::PLAIN_BLOCK_LEN as usize || total_bytes_read >= buf_len {
                return Ok(total_bytes_read);
            }
        } else {
            // Read the first block into a temporary buffer so the intra-block offset
            // can be skipped before copying into the caller buffer.
            let mut owned_buf =
                vec![
                    0;
                    first_block_offset as usize
                        + buf_len.min((T::PLAIN_BLOCK_LEN - first_block_offset) as usize)
                ];
            let bytes_read = self
                .read_block(block_no, &header, owned_buf.as_mut_slice())
                .inspect_err(|e| error!("read error in block_no {block_no} ! {e}"))?;
            if bytes_read <= first_block_offset as usize {
                return Ok(0);
            }
            total_bytes_read = bytes_read - first_block_offset as usize;
            buf[..total_bytes_read]
                .copy_from_slice(&owned_buf[first_block_offset as usize..bytes_read]);

            if bytes_read < T::PLAIN_BLOCK_LEN as usize || total_bytes_read >= buf_len {
                return Ok(total_bytes_read);
            }
        }

        for current_block in block_no + 1..=end_block_no {
            let bytes_read = self
                .read_block(current_block, &header, &mut buf[total_bytes_read..])
                .inspect_err(|e| error!("read error in block_no {current_block} ! {e}"))?;

            total_bytes_read += bytes_read;
            if bytes_read < T::PLAIN_BLOCK_LEN as usize || total_bytes_read >= buf_len {
                break;
            }
        }
        Ok(total_bytes_read)
    }
}

impl<T: EncryptionTranslator> WriteAt for CryptFsFile<T> {
    /// Writes plain bytes across encrypted block boundaries.
    fn write_at(&self, offset: u64, data: &[u8]) -> std::io::Result<usize> {
        // debug!(
        //     "trying to write at offset {} for len {}",
        //     offset,
        //     data.len()
        // );

        if data.is_empty() {
            return Ok(0);
        }

        let mut current_cipher_len = self.get_physical_size()?;
        if current_cipher_len < T::HEADER_LEN as u64 {
            current_cipher_len = T::HEADER_LEN as u64;
            self.create_header()?;
        }
        let header = self.header.read();
        let current_plain_len = self
            .backend
            .cipher_size_to_plain(current_cipher_len)
            .or_invalid()?;
        if current_plain_len < offset {
            self.re_encode_last_block(current_plain_len, offset, &header, false)?;
        }

        let plain_start = offset;
        let plain_end = plain_start + data.len() as u64;

        //debug!("plain_start {plain_start} plain_end {plain_end}");

        let block_no = plain_start / T::PLAIN_BLOCK_LEN;
        let end_block_no = (plain_end - 1) / T::PLAIN_BLOCK_LEN;

        let mut read_buffer = vec![0; T::PLAIN_BLOCK_LEN as usize];

        for current_block in block_no..=end_block_no {
            let block_start = current_block * T::PLAIN_BLOCK_LEN;
            let block_end = block_start + T::PLAIN_BLOCK_LEN;
            //debug!("in block {current_block} start {block_start} end {block_end}");
            if plain_start <= block_start && plain_end >= block_end {
                self.write_block(
                    current_block,
                    &header,
                    &data[(block_start - plain_start) as usize..(block_end - plain_start) as usize],
                )?;
            } else {
                // Partial block writes must preserve untouched bytes, so the current
                // plaintext block is read, patched in memory, then re-encrypted.
                let bytes_read = self
                    .read_block(current_block, &header, &mut read_buffer)
                    .inspect_err(|e| debug!("read block error! {e}"))?;

                let first = plain_start.max(block_start);
                let last = plain_end.min(block_end);
                //debug!("bytes_read {bytes_read} first {first} last {last}");

                if bytes_read < (last - block_start) as usize {
                    read_buffer[bytes_read..(last - block_start) as usize].fill(0);
                }

                read_buffer[(first - block_start) as usize..(last - block_start) as usize]
                    .copy_from_slice(
                        &data[(first - plain_start) as usize..(last - plain_start) as usize],
                    );
                let last = last.max(block_start + bytes_read as u64);
                self.write_block(
                    current_block,
                    &header,
                    &read_buffer[..(last - block_start) as usize],
                )
                .inspect_err(|e| debug!("write block error! {e}"))?;
            }
        }
        Ok(data.len())
    }
}

/// Preserves modification time while buffered writes are staged.
pub trait ModifiedTime {
    /// Returns the current modification time of the backing file.
    fn get_modified(&self) -> std::io::Result<std::time::SystemTime>;
    /// Restores or updates the modification time of the backing file.
    fn set_modified_time(&self, modified_time: std::time::SystemTime) -> std::io::Result<()>;
}

impl<T: EncryptionTranslator> ModifiedTime for CryptFsFile<T> {
    /// Returns the modification time of the underlying cipher file.
    fn get_modified(&self) -> std::io::Result<std::time::SystemTime> {
        self.cipher_file.metadata()?.modified()
    }
    /// Sets the modification time of the underlying cipher file.
    fn set_modified_time(&self, modified_time: std::time::SystemTime) -> std::io::Result<()> {
        self.cipher_file
            .set_times(std::fs::FileTimes::default().set_modified(modified_time))
    }
}

impl<T: EncryptionTranslator> SetSync for CryptFsFile<T> {
    /// Flushes the underlying cipher file with the requested durability level.
    fn sync(&self, datasync: bool) -> std::io::Result<()> {
        if datasync {
            self.cipher_file.sync_data()
        } else {
            self.cipher_file.sync_all()
        }
    }
}

impl<T: EncryptionTranslator> SetLen for CryptFsFile<T> {
    /// Resizes the plain file while keeping the final encrypted block consistent.
    fn set_len(&self, target_plain_len: u64) -> std::io::Result<()> {
        if target_plain_len > 0 {
            let current_cipher_len = self.get_physical_size()?;
            let current_plain_len = self
                .backend
                .cipher_size_to_plain(current_cipher_len)
                .or_invalid()?;

            if current_plain_len == 0 {
                self.create_header()?;
            }
            let header = self.header.read();
            self.re_encode_last_block(current_plain_len, target_plain_len, &header, true)?;
        }
        self.cipher_file
            .set_len(self.backend.plain_size_to_cipher(target_plain_len))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FsBackend, GoCryptFs};
    use std::sync::Arc;
    use tempfile::tempdir;

    /// Creates a test file backed by a freshly initialized GoCryptFS repository.
    fn open_test_file() -> (tempfile::TempDir, CryptFsFile<GoCryptFs<FsBackend>>) {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap();
        GoCryptFs::<FsBackend>::init_with_default_params(root, "password").unwrap();
        let backend = Arc::new(GoCryptFs::<FsBackend>::try_new(root, "password").unwrap());

        let mut options = GenericOpenOptions::default();
        options.read(true).write(true).create(true);
        let file = CryptFsFile::try_open(&root.join("cipher.bin"), backend, options).unwrap();

        (temp_dir, file)
    }

    /// Builds deterministic test data of the requested size.
    fn sample_data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn write_then_read_aligned_block() {
        let (_temp_dir, file) = open_test_file();
        let plain = sample_data(4096);

        file.write_all_at(0, &plain).unwrap();

        let mut read_back = vec![0u8; plain.len()];
        let bytes_read = file.read_at(0, &mut read_back).unwrap();

        assert_eq!(bytes_read, plain.len());
        assert_eq!(read_back, plain);
    }

    #[test]
    fn write_then_read_unaligned_range() {
        let (_temp_dir, file) = open_test_file();
        let offset = 37;
        let plain = sample_data(900);

        file.write_all_at(offset, &plain).unwrap();

        let mut read_back = vec![0u8; plain.len()];
        let bytes_read = file.read_at(offset, &mut read_back).unwrap();

        assert_eq!(bytes_read, plain.len());
        assert_eq!(read_back, plain);
    }

    #[test]
    fn read_unaligned_range_across_blocks() {
        let (_temp_dir, file) = open_test_file();
        let full = sample_data(9000);
        let offset = 123;
        let expected = &full[offset..offset + 5000];

        file.write_all_at(0, &full).unwrap();

        let mut read_back = vec![0u8; expected.len()];
        let bytes_read = file.read_at(offset as u64, &mut read_back).unwrap();

        assert_eq!(bytes_read, expected.len());
        assert_eq!(read_back, expected);
    }

    #[test]
    fn write_and_read_handle_boundary_offsets_and_gaps() {
        for offset in [1u64, 4095, 4096, 4097] {
            let (_temp_dir, file) = open_test_file();
            let plain = sample_data(128);

            file.write_all_at(offset, &plain).unwrap();

            let mut gap_and_data = vec![0u8; offset as usize + plain.len()];
            let bytes_read = file.read_at(0, &mut gap_and_data).unwrap();

            assert_eq!(bytes_read, gap_and_data.len(), "offset {offset}");
            assert!(
                gap_and_data[..offset as usize].iter().all(|&b| b == 0),
                "offset {offset}"
            );
            assert_eq!(
                &gap_and_data[offset as usize..],
                plain.as_slice(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn truncate_preserves_prefix() {
        let (_temp_dir, file) = open_test_file();
        let full = sample_data(6000);
        let truncated_len = 3000;

        file.write_all_at(0, &full).unwrap();
        file.set_len(truncated_len as u64).unwrap();

        let mut read_back = vec![0u8; 4000];
        let bytes_read = file.read_at(0, &mut read_back).unwrap();

        assert_eq!(bytes_read, truncated_len);
        assert_eq!(&read_back[..truncated_len], &full[..truncated_len]);
    }
}
