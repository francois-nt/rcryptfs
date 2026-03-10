use crate::{ReadAt, ReadWrite, SetLen, SetSync, WriteAt, file::ModifiedTime};
use parking_lot::Mutex;

const BLOCK_LEN: usize = 4096;

struct State {
    // next expected position if sequential writing
    sequential_end: Option<u64>,

    buffer_offset: u64,
    buffer_len: usize,
    buffer: [u8; BLOCK_LEN],
}

impl Default for State {
    fn default() -> Self {
        Self {
            sequential_end: None,
            buffer_offset: 0,
            buffer_len: 0,
            buffer: [0; BLOCK_LEN],
        }
    }
}

/// Buffers sequential plain-text writes so full encryption blocks can be flushed together.
pub struct BufferedFile<W> {
    inner: W,
    state: Mutex<State>,
}

impl<W> BufferedFile<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            state: Default::default(),
        }
    }
}

impl<W: ReadWrite> From<W> for BufferedFile<W> {
    fn from(value: W) -> Self {
        Self::new(value)
    }
}

impl<W: WriteAt + ModifiedTime> BufferedFile<W> {
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
    fn block_end(pos: u64) -> u64 {
        let base = (pos / BLOCK_LEN as u64) * BLOCK_LEN as u64;
        base + BLOCK_LEN as u64
    }
}

impl<W: ReadWrite + ModifiedTime> ReadAt for BufferedFile<W> {
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.flush_staging()?;
        self.inner.read_at(pos, buf)
    }
}

impl<W: ReadWrite + ModifiedTime> SetLen for BufferedFile<W> {
    fn set_len(&self, new_size: u64) -> std::io::Result<()> {
        self.flush_staging()?;
        self.inner.set_len(new_size)
    }
}

impl<W: ReadWrite + ModifiedTime> SetSync for BufferedFile<W> {
    fn sync(&self, datasync: bool) -> std::io::Result<()> {
        self.flush()?;
        self.inner.sync(datasync)
    }
}

impl<W: WriteAt + ModifiedTime> WriteAt for BufferedFile<W> {
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
            let cursor = state.sequential_end.unwrap();

            if state.buffer_len == 0
                && cursor.is_multiple_of(BLOCK_LEN as u64)
                && data.len() >= BLOCK_LEN
            {
                // Forward aligned full blocks directly to the inner file to avoid extra copies.
                let full = (data.len() / BLOCK_LEN) * BLOCK_LEN;
                let mut off = cursor;

                for chunk in data[..full].chunks_exact(BLOCK_LEN) {
                    if let Err(e) = self.inner.write_all_at(off, chunk) {
                        return if done > 0 { Ok(done) } else { Err(e) };
                    }
                    has_written = true;
                    off += BLOCK_LEN as u64;
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

            let end_block = Self::block_end(cursor);
            let max_in_this_block = (end_block - cursor) as usize;
            let take = data
                .len()
                .min(max_in_this_block)
                .min(BLOCK_LEN - state.buffer_len);

            let prev_len = state.buffer_len;
            state.buffer[prev_len..prev_len + take].copy_from_slice(&data[..take]);
            state.buffer_len += take;

            data = &data[take..];
            done += take;
            state.sequential_end = Some(cursor + take as u64);

            if state.sequential_end.unwrap() == end_block {
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
