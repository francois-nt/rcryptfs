use super::{
    EncryptionTranslator, FileHandle, ModifiedTime, OrIoError, ReadAt, SetLen, SetSync, Size,
    WriteAt,
};
use log::{debug, error};
use parking_lot::RwLock;
use std::sync::Arc;

enum LenChange {
    BeforeWrite,
    Resize,
}

struct PlainEnd {
    block_no: u64,
    offset: usize,
}

/// Wraps a cipher file and exposes plain-text block I/O.
pub struct CryptFsFile<T: EncryptionTranslator, F: FileHandle> {
    backend: Arc<T>,
    cipher_file: F,
    header: RwLock<Vec<u8>>,
}

impl<T: EncryptionTranslator, F: FileHandle> CryptFsFile<T, F> {
    /// Wraps an opened cipher file and eagerly loads its header when present.
    pub fn try_from_file(cipher_file: F, backend: Arc<T>, readonly: bool) -> std::io::Result<Self> {
        let mut cipher_file_size = cipher_file.size()?;
        if T::EMPTY_FILE_HAS_HEADER && !readonly && cipher_file_size == 0 {
            cipher_file.write_all_at(0, &backend.generate_cipher_header().or_invalid()?)?;
            cipher_file_size = cipher_file.size()?;
        }

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
    fn read_header(cipher_file: &F) -> std::io::Result<Vec<u8>> {
        let mut buffer: Vec<u8> = vec![0; T::HEADER_LEN];
        cipher_file.read_exact_at(0, &mut buffer)?;
        Ok(buffer)
    }
    /// Creates and persists a fresh header for a newly materialized cipher file.
    fn create_header(&self) -> std::io::Result<()> {
        let header = self
            .backend
            .generate_cipher_header()
            .or_io_error(libc::EIO)?;
        self.cipher_file.write_all_at(0, &header)?;
        *self.header.write() = header;
        Ok(())
    }
    /// Returns the current on-disk cipher file size.
    fn get_physical_size(&self) -> std::io::Result<u64> {
        self.cipher_file
            .size()
            .inspect_err(|e| error!("catastrophic error while reading size len {e}"))
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
            .inspect_err(|e| {
                error!(
                    "error {e} : in reading block {block_no} with len {} header is {:?}!",
                    plain_buffer.len(),
                    header
                )
            })
            .or_invalid()?;

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

    fn plain_end(len: u64) -> Option<PlainEnd> {
        if len == 0 {
            return None;
        }

        let mut offset = (len % T::PLAIN_BLOCK_LEN) as usize;
        if offset == 0 {
            offset = T::PLAIN_BLOCK_LEN as usize;
        }

        Some(PlainEnd {
            block_no: (len - 1) / T::PLAIN_BLOCK_LEN,
            offset,
        })
    }

    fn write_zero_blocks(
        &self,
        header: &[u8],
        start_block: u64,
        end: PlainEnd,
    ) -> std::io::Result<()> {
        let zero_block = vec![0; T::PLAIN_BLOCK_LEN as usize];
        for block_no in start_block..end.block_no {
            self.write_block(block_no, header, &zero_block)?;
        }

        if end.offset == T::PLAIN_BLOCK_LEN as usize {
            self.write_block(end.block_no, header, &zero_block)?;
        } else {
            self.write_block(end.block_no, header, &zero_block[..end.offset])?;
        }

        Ok(())
    }

    fn zero_fill_block(
        &self,
        block_no: u64,
        header: &[u8],
        target_len: usize,
    ) -> std::io::Result<()> {
        let mut read_buffer = vec![0; T::PLAIN_BLOCK_LEN as usize];
        let bytes_read = self.read_block(block_no, header, &mut read_buffer)?;
        if target_len > bytes_read {
            read_buffer[bytes_read..target_len].fill(0);
        }
        self.write_block(block_no, header, &read_buffer[..target_len])?;
        Ok(())
    }

    fn prepare_extension(
        &self,
        current_plain_len: u64,
        target_plain_len: u64,
        header: &[u8],
        change: LenChange,
    ) -> std::io::Result<()> {
        let target_end = Self::plain_end(target_plain_len).or_io_error(libc::EINVAL)?;

        if let Some(current_end) = Self::plain_end(current_plain_len) {
            if matches!(change, LenChange::BeforeWrite)
                && current_end.block_no == target_end.block_no
                && target_end.offset != T::PLAIN_BLOCK_LEN as usize
            {
                return Ok(());
            }

            if current_end.offset != T::PLAIN_BLOCK_LEN as usize {
                self.zero_fill_block(current_end.block_no, header, T::PLAIN_BLOCK_LEN as usize)?;
            }

            if T::ENCRYPT_SPARSE_PARTS && target_end.block_no > current_end.block_no {
                self.write_zero_blocks(header, current_end.block_no + 1, target_end)?;
            }

            return Ok(());
        }

        if T::ENCRYPT_SPARSE_PARTS {
            self.write_zero_blocks(header, 0, target_end)?;
        }
        Ok(())
    }

    fn prepare_truncation(&self, target_plain_len: u64, header: &[u8]) -> std::io::Result<()> {
        let target_end = Self::plain_end(target_plain_len).or_io_error(libc::EINVAL)?;
        if target_end.offset != T::PLAIN_BLOCK_LEN as usize {
            self.zero_fill_block(target_end.block_no, header, target_end.offset)?;
        }
        Ok(())
    }

    /// Re-encodes boundary blocks when a logical length transition changes block contents.
    fn prepare_len_change(
        &self,
        current_plain_len: u64,
        target_plain_len: u64,
        header: &[u8],
        change: LenChange,
    ) -> std::io::Result<()> {
        match target_plain_len.cmp(&current_plain_len) {
            std::cmp::Ordering::Equal => Ok(()),
            std::cmp::Ordering::Greater => {
                self.prepare_extension(current_plain_len, target_plain_len, header, change)
            }
            std::cmp::Ordering::Less => self.prepare_truncation(target_plain_len, header),
        }
    }
}

impl<T: EncryptionTranslator, F: FileHandle> ReadAt for CryptFsFile<T, F> {
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

impl<T: EncryptionTranslator, F: FileHandle> WriteAt for CryptFsFile<T, F> {
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
            self.prepare_len_change(current_plain_len, offset, &header, LenChange::BeforeWrite)?;
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

impl<T: EncryptionTranslator, F: FileHandle> Size for CryptFsFile<T, F> {
    /// Returns the logical plain-text file size.
    fn size(&self) -> std::io::Result<u64> {
        self.backend
            .cipher_size_to_plain(self.get_physical_size()?)
            .or_invalid()
    }
}

impl<T: EncryptionTranslator, F: FileHandle> ModifiedTime for CryptFsFile<T, F> {
    /// Returns the modification time of the underlying cipher file.
    fn get_modified(&self) -> std::io::Result<std::time::SystemTime> {
        self.cipher_file.get_modified()
    }
    /// Sets the modification time of the underlying cipher file.
    fn set_modified_time(&self, modified_time: std::time::SystemTime) -> std::io::Result<()> {
        self.cipher_file.set_modified_time(modified_time)
    }
}

impl<T: EncryptionTranslator, F: FileHandle> SetSync for CryptFsFile<T, F> {
    /// Flushes the underlying cipher file with the requested durability level.
    fn sync(&self, datasync: bool) -> std::io::Result<()> {
        self.cipher_file.sync(datasync)
    }
}

impl<T: EncryptionTranslator, F: FileHandle> SetLen for CryptFsFile<T, F> {
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
            self.prepare_len_change(
                current_plain_len,
                target_plain_len,
                &header,
                LenChange::Resize,
            )?;
        }
        self.cipher_file
            .set_len(self.backend.plain_size_to_cipher(target_plain_len))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::core::*;
    use crate::{CryptoMator, GoCryptFs};
    use std::sync::Arc;
    use tempfile::tempdir;

    /// Creates a test file backed by a freshly initialized GoCryptFS repository.
    fn open_gocryptfs_test_file() -> (
        tempfile::TempDir,
        CryptFsFile<GoCryptFs<FsBackend>, std::fs::File>,
    ) {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap();
        GoCryptFs::<FsBackend>::init_with_default_params(root, "password").unwrap();
        let backend = Arc::new(GoCryptFs::<FsBackend>::try_new(root, "password").unwrap());

        let mut options = FileOpenOptions::default();
        options.read(true).write(true).create(true);
        let cipher_file = backend
            .lower_fs()
            .open_file_with("cipher.bin".into(), options)
            .unwrap();
        let file = CryptFsFile::try_from_file(cipher_file, backend, false).unwrap();

        (temp_dir, file)
    }

    /// Creates a test file backed by a freshly initialized Cryptomator repository.
    fn open_cryptomator_test_file() -> (
        tempfile::TempDir,
        CryptFsFile<CryptoMator<FsBackend>, std::fs::File>,
    ) {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap();
        CryptoMator::<FsBackend>::init_with_default_params(root, "password").unwrap();
        let backend = Arc::new(CryptoMator::<FsBackend>::try_new(root, "password").unwrap());

        let mut options = FileOpenOptions::default();
        options.read(true).write(true).create(true);
        let cipher_file = backend
            .lower_fs()
            .open_file_with("cipher.bin".into(), options)
            .unwrap();
        let file = CryptFsFile::try_from_file(cipher_file, backend, false).unwrap();

        (temp_dir, file)
    }

    /// Builds deterministic test data of the requested size.
    fn sample_data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn gocryptfs_write_then_read_aligned_block() {
        let (_temp_dir, file) = open_gocryptfs_test_file();
        let plain = sample_data(4096);

        file.write_all_at(0, &plain).unwrap();

        assert_eq!(file.size().unwrap(), plain.len() as u64);

        let mut read_back = vec![0u8; plain.len()];
        let bytes_read = file.read_at(0, &mut read_back).unwrap();

        assert_eq!(bytes_read, plain.len());
        assert_eq!(read_back, plain);
    }

    #[test]
    fn gocryptfs_write_then_read_unaligned_range() {
        let (_temp_dir, file) = open_gocryptfs_test_file();
        let offset = 37;
        let plain = sample_data(900);

        file.write_all_at(offset, &plain).unwrap();

        let mut read_back = vec![0u8; plain.len()];
        let bytes_read = file.read_at(offset, &mut read_back).unwrap();

        assert_eq!(bytes_read, plain.len());
        assert_eq!(read_back, plain);
    }

    #[test]
    fn gocryptfs_read_unaligned_range_across_blocks() {
        let (_temp_dir, file) = open_gocryptfs_test_file();
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
    fn gocryptfs_write_and_read_handle_boundary_offsets_and_gaps() {
        for offset in [1u64, 4095, 4096, 4097] {
            let (_temp_dir, file) = open_gocryptfs_test_file();
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
    fn gocryptfs_aligned_extension_to_next_block_reencodes_previous_last_block() {
        let (_temp_dir, file) = open_gocryptfs_test_file();
        let block_len = <GoCryptFs<FsBackend> as EncryptionTranslator>::PLAIN_BLOCK_LEN as usize;
        let offset_in_block = 64usize;
        let first = sample_data(728);
        let tail = b"tail";

        file.write_all_at(offset_in_block as u64, &first).unwrap();
        file.write_all_at(block_len as u64, tail).unwrap();

        let mut first_block = vec![0u8; block_len];
        let bytes_read = file.read_at(0, &mut first_block).unwrap();

        assert_eq!(bytes_read, block_len);
        assert!(first_block[..offset_in_block].iter().all(|&b| b == 0));
        assert_eq!(
            &first_block[offset_in_block..offset_in_block + first.len()],
            first.as_slice()
        );
        assert!(
            first_block[offset_in_block + first.len()..]
                .iter()
                .all(|&b| b == 0)
        );
    }

    #[test]
    fn gocryptfs_aligned_gap_extension_reencodes_previous_last_block() {
        let (_temp_dir, file) = open_gocryptfs_test_file();
        let block_len = <GoCryptFs<FsBackend> as EncryptionTranslator>::PLAIN_BLOCK_LEN as usize;
        let offset_in_block = 64usize;
        let first = sample_data(728);
        let tail = b"tail";

        file.write_all_at(offset_in_block as u64, &first).unwrap();
        file.write_all_at((2 * block_len) as u64, tail).unwrap();

        let mut first_block = vec![0u8; block_len];
        let bytes_read = file.read_at(0, &mut first_block).unwrap();

        assert_eq!(bytes_read, block_len);
        assert!(first_block[..offset_in_block].iter().all(|&b| b == 0));
        assert_eq!(
            &first_block[offset_in_block..offset_in_block + first.len()],
            first.as_slice()
        );
        assert!(
            first_block[offset_in_block + first.len()..]
                .iter()
                .all(|&b| b == 0)
        );
    }

    #[test]
    fn truncate_preserves_prefix() {
        let (_temp_dir, file) = open_gocryptfs_test_file();
        let full = sample_data(6000);
        let truncated_len = 3000;

        file.write_all_at(0, &full).unwrap();
        file.set_len(truncated_len as u64).unwrap();

        let mut read_back = vec![0u8; 4000];
        let bytes_read = file.read_at(0, &mut read_back).unwrap();

        assert_eq!(bytes_read, truncated_len);
        assert_eq!(&read_back[..truncated_len], &full[..truncated_len]);
    }

    #[test]
    fn truncate_from_exact_block_boundary_reencodes_new_partial_last_block() {
        let (_temp_dir, file) = open_gocryptfs_test_file();
        let block_len = <GoCryptFs<FsBackend> as EncryptionTranslator>::PLAIN_BLOCK_LEN as usize;
        let full = sample_data(2 * block_len);
        let truncated_len = block_len + 100;

        file.write_all_at(0, &full).unwrap();
        file.set_len(truncated_len as u64).unwrap();

        let mut read_back = vec![0u8; truncated_len];
        let bytes_read = file.read_at(0, &mut read_back).unwrap();

        assert_eq!(bytes_read, truncated_len);
        assert_eq!(read_back, full[..truncated_len]);
    }

    #[test]
    fn cryptomator_open_materializes_header_for_empty_file() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap();
        CryptoMator::<FsBackend>::init_with_default_params(root, "password").unwrap();
        let backend = Arc::new(CryptoMator::<FsBackend>::try_new(root, "password").unwrap());

        let mut options = FileOpenOptions::default();
        options.read(true).write(true).create(true);
        let cipher_file = backend
            .lower_fs()
            .open_file_with("cipher.bin".into(), options)
            .unwrap();
        let _file = CryptFsFile::try_from_file(cipher_file, backend, false).unwrap();

        let raw_len = std::fs::metadata(root.join("cipher.bin")).unwrap().len();
        assert_eq!(raw_len, CryptoMator::<FsBackend>::HEADER_LEN as u64);
    }

    #[test]
    fn cryptomator_write_then_read_aligned_block() {
        let (_temp_dir, file) = open_cryptomator_test_file();
        let plain = sample_data(4096);

        file.write_all_at(0, &plain).unwrap();

        assert_eq!(file.size().unwrap(), plain.len() as u64);

        let mut read_back = vec![0u8; plain.len()];
        let bytes_read = file.read_at(0, &mut read_back).unwrap();

        assert_eq!(bytes_read, plain.len());
        assert_eq!(read_back, plain);
    }

    #[test]
    fn cryptomator_write_then_read_unaligned_range() {
        let (_temp_dir, file) = open_cryptomator_test_file();
        let offset = 37;
        let plain = sample_data(900);

        file.write_all_at(offset, &plain).unwrap();

        let mut read_back = vec![0u8; plain.len()];
        let bytes_read = file.read_at(offset, &mut read_back).unwrap();

        assert_eq!(bytes_read, plain.len());
        assert_eq!(read_back, plain);
    }
    #[test]
    fn cryptomator_write_and_read_handle_boundary_offsets_and_gaps() {
        for offset in [1u64, 32767, 32768, 32769, 65535, 65536, 65537] {
            let (_temp_dir, file) = open_cryptomator_test_file();
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
    fn cryptomator_truncate_preserves_prefix() {
        let (_temp_dir, file) = open_cryptomator_test_file();
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
