use super::{
    BufferedFile, FileHandle, Handler, ModifiedTime, ReadAt, SetLen, SetSync, Size, WriteAt,
};
use std::{io, time::SystemTime};

/// Holds the buffering mode selected when a cleartext file is opened.
enum FileBuffer<F> {
    Direct(F),
    Buffered(BufferedFile<F>),
}

/// An open cleartext file with optional write buffering.
pub struct CleartextFile<F>(FileBuffer<F>);

impl<F> CleartextFile<F> {
    /// Selects whether the opened file buffers writes.
    pub(crate) fn new(file: F, block_len: usize, cache_write: bool) -> Self {
        Self(if cache_write {
            FileBuffer::Buffered(BufferedFile::new(file, block_len))
        } else {
            FileBuffer::Direct(file)
        })
    }
}

impl<F: FileHandle> From<CleartextFile<F>> for Handler<dyn FileHandle> {
    fn from(file: CleartextFile<F>) -> Self {
        Handler::new(file).into()
    }
}

/// Forwards file operations to the selected concrete buffering variant.
macro_rules! forward_file_operations {
    ($($tr:ident { $(fn $method:ident(&self $(, $arg:ident: $ty:ty)*) -> $result:ty;)* })*) => {
        $(impl<F: FileHandle> $tr for CleartextFile<F> {
            $(fn $method(&self $(, $arg: $ty)*) -> $result {
                match &self.0 {
                    FileBuffer::Direct(file) => file.$method($($arg),*),
                    FileBuffer::Buffered(file) => file.$method($($arg),*),
                }
            })*
        })*
    };
}

forward_file_operations! {
    ReadAt {
        fn read_at(&self, pos: u64, buf: &mut [u8]) -> io::Result<usize>;
        fn read_all_at(&self, pos: u64, buf: &mut [u8]) -> io::Result<usize>;
        fn read_exact_at(&self, pos: u64, buf: &mut [u8]) -> io::Result<()>;
    }
    WriteAt {
        fn write_at(&self, pos: u64, buf: &[u8]) -> io::Result<usize>;
        fn write_all_at(&self, pos: u64, buf: &[u8]) -> io::Result<()>;
        fn flush(&self) -> io::Result<()>;
    }
    Size {
        fn size(&self) -> io::Result<u64>;
    }
    ModifiedTime {
        fn get_modified(&self) -> io::Result<SystemTime>;
        fn set_modified_time(&self, modified_time: SystemTime) -> io::Result<()>;
    }
    SetSync {
        fn sync(&self, datasync: bool) -> io::Result<()>;
    }
    SetLen {
        fn set_len(&self, new_size: u64) -> io::Result<()>;
    }
}
