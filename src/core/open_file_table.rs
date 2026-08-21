use super::{FileHandle, OpenFileTable, OrIoError};
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

/// Stores open handles directly in pointer-derived identifiers.
#[derive(Default)]
pub struct UnsafeOpenFileTable;

impl OpenFileTable for UnsafeOpenFileTable {
    fn insert(&self, file: Box<dyn FileHandle>) -> u64 {
        let file = Box::new(file);
        Box::into_raw(file) as usize as u64
    }
    fn release(&self, id: u64) -> std::io::Result<()> {
        let file = unsafe { Box::from_raw(id as usize as *mut Box<dyn FileHandle>) };
        drop(file);
        Ok(())
    }
    fn access<U, F: FnOnce(&dyn FileHandle) -> std::io::Result<U>>(
        &self,
        id: u64,
        handler: F,
    ) -> std::io::Result<U> {
        let file = unsafe { &*(id as usize as *const Box<dyn FileHandle>) };
        handler(file.as_ref())
    }
}

type FileDictionary<T> = HashMap<u64, Arc<T>>;
/// Stores open handles in a synchronized identifier table.
pub struct LockedOpenFileTable {
    id: AtomicU64,
    open_files: RwLock<FileDictionary<dyn FileHandle>>,
}

impl Default for LockedOpenFileTable {
    fn default() -> Self {
        Self {
            id: 1.into(),
            open_files: RwLock::default(),
        }
    }
}

impl OpenFileTable for LockedOpenFileTable {
    fn insert(&self, file: Box<dyn FileHandle>) -> u64 {
        let id = self.id.fetch_add(1, Ordering::Relaxed);
        self.open_files.write().insert(id, file.into());
        id
    }
    fn access<U, F: FnOnce(&dyn FileHandle) -> std::io::Result<U>>(
        &self,
        id: u64,
        handler: F,
    ) -> std::io::Result<U> {
        let value = self
            .open_files
            .read()
            .get(&id)
            .or_io_error(libc::EBADF)?
            .clone();

        handler(value.as_ref())
    }
    fn release(&self, id: u64) -> std::io::Result<()> {
        self.open_files
            .write()
            .remove(&id)
            .or_io_error(libc::EBADF)?;
        Ok(())
    }
}
