use super::{FileHandle, ModifiedTime, OrIoError, ReadAt, SetLen, SetSync, Size, WriteAt};
use parking_lot::Mutex;

struct State {
    // next expected position if sequential writing
    sequential_end: Option<u64>,

    buffer_offset: u64,
    buffer_len: usize,
    buffer: Vec<u8>,
}

/// Buffers sequential plain-text writes so full encryption blocks can be flushed together.
pub struct BufferedFile<W> {
    inner: W,
    state: Mutex<State>,
    block_len: usize,
}

impl<W> BufferedFile<W> {
    pub fn new(inner: W, block_len: usize) -> Self {
        Self {
            inner,
            state: State {
                sequential_end: None,
                buffer_offset: 0,
                buffer_len: 0,
                buffer: vec![0; block_len],
            }
            .into(),
            block_len,
        }
    }
}

impl<W: FileHandle> BufferedFile<W> {
    /// Flushes staged data before operations that must observe durable file contents.
    fn flush_staging(&self) -> std::io::Result<()> {
        let mut state = self.state.lock();
        self.flush_staging_locked(&mut state)?;
        drop(state);
        Ok(())
    }
    /// Writes the current staged block and restores the backing file modification time.
    fn flush_staging_locked(&self, state: &mut State) -> std::io::Result<()> {
        if state.buffer_len == 0 {
            return Ok(());
        }
        let modified = self.inner.get_modified()?;
        self.inner
            .write_all_at(state.buffer_offset, &state.buffer[..state.buffer_len])?;
        self.inner.set_modified_time(modified)?;
        state.buffer_len = 0;
        Ok(())
    }

    #[inline]
    fn block_end(&self, pos: u64) -> u64 {
        let base = (pos / self.block_len as u64) * self.block_len as u64;
        base + self.block_len as u64
    }
}

impl<W: FileHandle> ReadAt for BufferedFile<W> {
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let state = self.state.lock();
        if state.buffer_len == 0 {
            return self.inner.read_at(pos, buf);
        }

        let read_end = pos.saturating_add(buf.len() as u64);
        let staged_start = state.buffer_offset;
        let staged_end = staged_start + state.buffer_len as u64;

        // If the requested range does not touch staged data, read directly from the inner file.
        if read_end <= staged_start || staged_end <= pos {
            return self.inner.read_at(pos, buf);
        }

        let bytes_read = self.inner.read_at(pos, buf)?;

        // Overlay the staged bytes on top of the physical read result.
        let overlap_start = pos.max(staged_start);
        let overlap_end = read_end.min(staged_end);
        let dst_start = (overlap_start - pos) as usize;
        let dst_end = (overlap_end - pos) as usize;
        let src_start = (overlap_start - staged_start) as usize;
        let src_end = src_start + (dst_end - dst_start);

        // Fill any sparse gap between the physical EOF and the staged range.
        if bytes_read < dst_start {
            buf[bytes_read..dst_start].fill(0);
        }
        buf[dst_start..dst_end].copy_from_slice(&state.buffer[src_start..src_end]);
        Ok(bytes_read.max(dst_end))
    }
}

impl<W: FileHandle> Size for BufferedFile<W> {
    /// Returns the logical size, including data that has not been flushed yet.
    fn size(&self) -> std::io::Result<u64> {
        let state = self.state.lock();
        let inner_size = self.inner.size()?;
        if state.buffer_len == 0 {
            return Ok(inner_size);
        }
        let staged_end = state
            .buffer_offset
            .checked_add(state.buffer_len as u64)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        Ok(inner_size.max(staged_end))
    }
}

impl<W: FileHandle> ModifiedTime for BufferedFile<W> {
    /// Returns the backing file modification time.
    fn get_modified(&self) -> std::io::Result<std::time::SystemTime> {
        let _state = self.state.lock();
        self.inner.get_modified()
    }

    /// Updates the backing file modification time without racing a flush.
    fn set_modified_time(&self, modified_time: std::time::SystemTime) -> std::io::Result<()> {
        let _state = self.state.lock();
        self.inner.set_modified_time(modified_time)
    }
}

impl<W: FileHandle> SetLen for BufferedFile<W> {
    fn set_len(&self, new_size: u64) -> std::io::Result<()> {
        self.flush_staging()?;
        self.inner.set_len(new_size)
    }
}

impl<W: FileHandle> SetSync for BufferedFile<W> {
    fn sync(&self, datasync: bool) -> std::io::Result<()> {
        self.flush()?;
        self.inner.sync(datasync)
    }
}

impl<W: FileHandle> WriteAt for BufferedFile<W> {
    fn write_at(&self, pos: u64, mut data: &[u8]) -> std::io::Result<usize> {
        let mut state = self.state.lock();
        let mut has_written = false;
        match state.sequential_end {
            None => state.sequential_end = Some(pos),
            Some(end) if end != pos => {
                self.flush_staging_locked(&mut state)?;
                state.sequential_end = Some(pos);
            }
            _ => {}
        };
        // post_condition: state.sequential_end == Some(pos)

        let mut done = 0usize;

        while !data.is_empty() {
            let cursor = state.sequential_end.or_invalid()?;

            if state.buffer_len == 0
                && cursor.is_multiple_of(self.block_len as u64)
                && data.len() >= self.block_len
            {
                // Forward aligned full blocks directly to the inner file to avoid extra copies.
                let full = (data.len() / self.block_len) * self.block_len;
                let mut off = cursor;

                for chunk in data[..full].chunks_exact(self.block_len) {
                    if let Err(e) = self.inner.write_all_at(off, chunk) {
                        return if done > 0 { Ok(done) } else { Err(e) };
                    }
                    has_written = true;
                    off += self.block_len as u64;
                }

                data = &data[full..];
                done += full;
                state.sequential_end = Some(off);
                continue;
            }

            if state.buffer_len == 0 {
                state.buffer_offset = cursor;
            }

            assert_eq!(state.buffer_offset + state.buffer_len as u64, cursor);

            let end_block = self.block_end(cursor);
            let max_in_this_block = (end_block - cursor) as usize;
            let take = data
                .len()
                .min(max_in_this_block)
                .min(self.block_len - state.buffer_len);

            let prev_len = state.buffer_len;
            state.buffer[prev_len..prev_len + take].copy_from_slice(&data[..take]);
            state.buffer_len += take;

            data = &data[take..];
            done += take;
            state.sequential_end = Some(cursor + take as u64);

            if state.sequential_end.or_invalid()? == end_block {
                // Flush a completed staging block as soon as it becomes full.
                if let Err(e) = self
                    .inner
                    .write_all_at(state.buffer_offset, &state.buffer[..state.buffer_len])
                {
                    state.buffer_len = prev_len;
                    state.sequential_end = Some(state.buffer_offset + state.buffer_len as u64);
                    done -= take;
                    return if done > 0 { Ok(done) } else { Err(e) };
                }
                has_written = true;
                state.buffer_len = 0;
            }
        }
        if !has_written {
            // no physical writing, but we change the modification time as if there had been one.
            let _ = self.inner.set_modified_time(std::time::SystemTime::now());
        }

        Ok(done)
    }

    fn flush(&self) -> std::io::Result<()> {
        self.flush_staging()?;
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_includes_staged_data() {
        let file = tempfile::tempfile().unwrap();
        let buffered = BufferedFile::new(file, 16);

        buffered.write_all_at(100, b"abc").unwrap();

        assert_eq!(buffered.size().unwrap(), 103);
        assert_file_handle(&buffered);
    }

    fn assert_file_handle(_file: &impl FileHandle) {}
}
