use crate::{OpenCache, OrIoError, ReadWrite};
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Default)]
pub struct UnsafeCache;

impl OpenCache for UnsafeCache {
    fn insert(&self, file: Box<dyn ReadWrite>) -> u64 {
        let file = Box::new(file);
        Box::into_raw(file) as usize as u64
    }
    fn release(&self, id: u64) -> std::io::Result<()> {
        let file = unsafe { Box::from_raw(id as usize as *mut Box<dyn ReadWrite>) };
        drop(file);
        Ok(())
    }
    fn access<U, F: FnOnce(&dyn ReadWrite) -> std::io::Result<U>>(
        &self,
        id: u64,
        handler: F,
    ) -> std::io::Result<U> {
        let file = unsafe { Box::from_raw(id as usize as *mut Box<dyn ReadWrite>) };
        let res = handler(file.as_ref().as_ref());
        let _ = Box::into_raw(file);
        res
    }
}

type FileDictionary<T> = HashMap<u64, Arc<T>>;
pub struct CacheLock {
    id: AtomicU64,
    open_files: RwLock<FileDictionary<dyn ReadWrite>>,
}

impl Default for CacheLock {
    fn default() -> Self {
        Self {
            id: 1.into(),
            open_files: RwLock::default(),
        }
    }
}

impl OpenCache for CacheLock {
    fn insert(&self, file: Box<dyn ReadWrite>) -> u64 {
        let id = self.id.fetch_add(1, Ordering::Relaxed);
        self.open_files.write().insert(id, file.into());
        id
    }
    fn access<U, F: FnOnce(&dyn ReadWrite) -> std::io::Result<U>>(
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
