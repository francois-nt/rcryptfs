use super::{FileCapabilities, FileHandle, OpenFileTable, OrIoError};
use parking_lot::{Condvar, Mutex, RwLock};
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
    fn open<F>(
        &self,
        _inode: u64,
        _capabilities: FileCapabilities,
        _replace_existing: bool,
        opener: F,
    ) -> std::io::Result<u64>
    where
        F: FnOnce() -> std::io::Result<Box<dyn FileHandle>>,
    {
        let file = opener()?;
        let file = Box::new(file);
        Ok(Box::into_raw(file) as usize as u64)
    }
    fn release(&self, id: u64) -> std::io::Result<()> {
        let file = unsafe { Box::from_raw(id as usize as *mut Box<dyn FileHandle>) };
        let result = file.flush();
        drop(file);
        result
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

struct SharedHandle {
    file: Box<dyn FileHandle>,
    capabilities: FileCapabilities,
}

/// Owns the replaceable physical handle shared by all opens of one inode.
struct SharedFile {
    handle: RwLock<Option<SharedHandle>>,
    open_gate: Mutex<()>,
}

impl SharedFile {
    fn new() -> Self {
        Self {
            handle: RwLock::new(None),
            open_gate: Mutex::new(()),
        }
    }

    /// Validates one open and upgrades or replaces the shared handle when needed.
    fn open<F>(
        &self,
        capabilities: FileCapabilities,
        replace_existing: bool,
        opener: F,
    ) -> std::io::Result<()>
    where
        F: FnOnce() -> std::io::Result<Box<dyn FileHandle>>,
    {
        let _open_guard = self.open_gate.lock();
        let needs_replacement =
            self.handle.read().as_ref().is_none_or(|handle| {
                replace_existing || !handle.capabilities.contains(capabilities)
            });

        if needs_replacement {
            // Keep all accesses out while opening a truncating or upgraded handle.
            let mut handle = self.handle.write();
            let file = opener()?;
            *handle = Some(SharedHandle { file, capabilities });
        } else {
            // Preserve the normal permission and existence checks of every open.
            drop(opener()?);
        }
        Ok(())
    }

    /// Runs an operation while preventing replacement of the physical handle.
    fn access<U, F>(&self, handler: F) -> std::io::Result<U>
    where
        F: FnOnce(&dyn FileHandle) -> std::io::Result<U>,
    {
        let handle = self.handle.read();
        let handle = handle.as_ref().or_io_error(libc::EBADF)?;
        handler(handle.file.as_ref())
    }

    /// Flushes the physical handle before the final open reference is removed.
    fn flush(&self) -> std::io::Result<()> {
        let handle = self.handle.write();
        match handle.as_ref() {
            Some(handle) => handle.file.flush(),
            None => Ok(()),
        }
    }
}

struct InodeFile {
    shared: Arc<SharedFile>,
    references: usize,
    closing: bool,
}

struct OpenFileReference {
    inode: u64,
    shared: Arc<SharedFile>,
}

#[derive(Default)]
struct FileTableState {
    by_inode: HashMap<u64, InodeFile>,
    by_handle: HashMap<u64, OpenFileReference>,
}

/// Stores open handles in a synchronized identifier table.
pub struct LockedOpenFileTable {
    id: AtomicU64,
    state: Mutex<FileTableState>,
    close_finished: Condvar,
}

impl Default for LockedOpenFileTable {
    fn default() -> Self {
        Self {
            id: 1.into(),
            state: Mutex::default(),
            close_finished: Condvar::new(),
        }
    }
}

impl LockedOpenFileTable {
    /// Reserves one reference and waits for a preceding final close to finish.
    fn reserve_inode(&self, inode: u64) -> Arc<SharedFile> {
        let mut state = self.state.lock();
        loop {
            match state.by_inode.get_mut(&inode) {
                Some(entry) if entry.closing => self.close_finished.wait(&mut state),
                Some(entry) => {
                    entry.references += 1;
                    return entry.shared.clone();
                }
                None => {
                    let shared = Arc::new(SharedFile::new());
                    state.by_inode.insert(
                        inode,
                        InodeFile {
                            shared: shared.clone(),
                            references: 1,
                            closing: false,
                        },
                    );
                    return shared;
                }
            }
        }
    }

    /// Removes one reservation and returns the file when it became the last one.
    fn remove_reference(&self, inode: u64) -> std::io::Result<Option<Arc<SharedFile>>> {
        let mut state = self.state.lock();
        let entry = state.by_inode.get_mut(&inode).or_io_error(libc::EBADF)?;
        entry.references = entry.references.checked_sub(1).or_io_error(libc::EBADF)?;
        if entry.references == 0 {
            entry.closing = true;
            Ok(Some(entry.shared.clone()))
        } else {
            Ok(None)
        }
    }

    /// Completes the last close and wakes opens waiting on the same inode.
    fn finish_close(&self, inode: u64, shared: &Arc<SharedFile>) {
        let mut state = self.state.lock();
        if state
            .by_inode
            .get(&inode)
            .is_some_and(|entry| entry.closing && Arc::ptr_eq(&entry.shared, shared))
        {
            state.by_inode.remove(&inode);
        }
        self.close_finished.notify_all();
    }

    /// Flushes and removes a shared file after its last reservation disappears.
    fn close_last(&self, inode: u64, shared: Arc<SharedFile>) -> std::io::Result<()> {
        let result = shared.flush();
        self.finish_close(inode, &shared);
        result
    }
}

impl OpenFileTable for LockedOpenFileTable {
    fn open<F>(
        &self,
        inode: u64,
        capabilities: FileCapabilities,
        replace_existing: bool,
        opener: F,
    ) -> std::io::Result<u64>
    where
        F: FnOnce() -> std::io::Result<Box<dyn FileHandle>>,
    {
        let shared = self.reserve_inode(inode);
        if let Err(error) = shared.open(capabilities, replace_existing, opener) {
            if let Some(last) = self.remove_reference(inode)? {
                let _ = self.close_last(inode, last);
            }
            return Err(error);
        }

        let id = self.id.fetch_add(1, Ordering::Relaxed);
        self.state
            .lock()
            .by_handle
            .insert(id, OpenFileReference { inode, shared });
        Ok(id)
    }
    fn access<U, F: FnOnce(&dyn FileHandle) -> std::io::Result<U>>(
        &self,
        id: u64,
        handler: F,
    ) -> std::io::Result<U> {
        let shared = self
            .state
            .lock()
            .by_handle
            .get(&id)
            .or_io_error(libc::EBADF)?
            .shared
            .clone();

        shared.access(handler)
    }
    fn access_inode<U, F: FnOnce(&dyn FileHandle) -> std::io::Result<U>>(
        &self,
        inode: u64,
        capabilities: FileCapabilities,
        handler: F,
    ) -> std::io::Result<Option<U>> {
        let shared = self
            .state
            .lock()
            .by_inode
            .get(&inode)
            .map(|entry| entry.shared.clone());
        let Some(shared) = shared else {
            return Ok(None);
        };
        let handle = shared.handle.read();
        match handle.as_ref() {
            Some(handle) if handle.capabilities.contains(capabilities) => {
                handler(handle.file.as_ref()).map(Some)
            }
            _ => Ok(None),
        }
    }
    fn release(&self, id: u64) -> std::io::Result<()> {
        let reference = self
            .state
            .lock()
            .by_handle
            .remove(&id)
            .or_io_error(libc::EBADF)?;
        match self.remove_reference(reference.inode)? {
            Some(last) => self.close_last(reference.inode, last),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{ModifiedTime, ReadAt, SetLen, SetSync, Size, WriteAt};
    use std::{
        io,
        sync::atomic::{AtomicUsize, Ordering},
        time::SystemTime,
    };

    /// Observable handle used to verify sharing, replacement, and final flushing.
    struct TestFile {
        identity: u64,
        flushes: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl ReadAt for TestFile {
        fn read_at(&self, _pos: u64, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl WriteAt for TestFile {
        fn write_at(&self, _pos: u64, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&self) -> io::Result<()> {
            self.flushes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    impl SetLen for TestFile {
        fn set_len(&self, _new_size: u64) -> io::Result<()> {
            Ok(())
        }
    }

    impl SetSync for TestFile {
        fn sync(&self, _datasync: bool) -> io::Result<()> {
            Ok(())
        }
    }

    impl Size for TestFile {
        fn size(&self) -> io::Result<u64> {
            Ok(self.identity)
        }
    }

    impl ModifiedTime for TestFile {
        fn get_modified(&self) -> io::Result<SystemTime> {
            Ok(SystemTime::UNIX_EPOCH)
        }

        fn set_modified_time(&self, _modified_time: SystemTime) -> io::Result<()> {
            Ok(())
        }
    }

    /// Creates a boxed test handle with shared lifecycle counters.
    fn test_file(
        identity: u64,
        flushes: &Arc<AtomicUsize>,
        drops: &Arc<AtomicUsize>,
    ) -> Box<dyn FileHandle> {
        Box::new(TestFile {
            identity,
            flushes: flushes.clone(),
            drops: drops.clone(),
        })
    }

    #[test]
    fn shares_and_upgrades_one_handle_per_inode() {
        let table = LockedOpenFileTable::default();
        let flushes = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));

        let first = table
            .open(7, FileCapabilities::ReadOnly, false, || {
                Ok(test_file(1, &flushes, &drops))
            })
            .unwrap();
        let second = table
            .open(7, FileCapabilities::ReadOnly, false, || {
                Ok(test_file(2, &flushes, &drops))
            })
            .unwrap();

        assert_ne!(first, second);
        assert_eq!(table.access(first, Size::size).unwrap(), 1);
        assert_eq!(table.access(second, Size::size).unwrap(), 1);
        assert_eq!(
            table
                .access_inode(7, FileCapabilities::ReadOnly, Size::size)
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            table
                .access_inode(7, FileCapabilities::ReadWrite, Size::size)
                .unwrap(),
            None
        );
        assert_eq!(
            table
                .access_inode(8, FileCapabilities::ReadOnly, Size::size)
                .unwrap(),
            None
        );
        assert_eq!(drops.load(Ordering::Relaxed), 1);

        let writer = table
            .open(7, FileCapabilities::ReadWrite, false, || {
                Ok(test_file(3, &flushes, &drops))
            })
            .unwrap();

        assert_eq!(table.access(first, Size::size).unwrap(), 3);
        assert_eq!(table.access(second, Size::size).unwrap(), 3);
        assert_eq!(table.access(writer, Size::size).unwrap(), 3);
        assert_eq!(
            table
                .access_inode(7, FileCapabilities::ReadWrite, Size::size)
                .unwrap(),
            Some(3)
        );
        assert_eq!(drops.load(Ordering::Relaxed), 2);

        table.release(first).unwrap();
        table.release(second).unwrap();
        assert_eq!(flushes.load(Ordering::Relaxed), 0);

        table.release(writer).unwrap();
        assert_eq!(
            table
                .access_inode(7, FileCapabilities::ReadOnly, Size::size)
                .unwrap(),
            None
        );
        assert_eq!(flushes.load(Ordering::Relaxed), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn replaces_shared_handle_after_resetting_open() {
        let table = LockedOpenFileTable::default();
        let flushes = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let first = table
            .open(9, FileCapabilities::ReadWrite, false, || {
                Ok(test_file(1, &flushes, &drops))
            })
            .unwrap();
        let truncated = table
            .open(9, FileCapabilities::ReadWrite, true, || {
                Ok(test_file(2, &flushes, &drops))
            })
            .unwrap();

        assert_eq!(table.access(first, Size::size).unwrap(), 2);
        assert_eq!(table.access(truncated, Size::size).unwrap(), 2);

        table.release(first).unwrap();
        table.release(truncated).unwrap();
        assert_eq!(flushes.load(Ordering::Relaxed), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn failed_upgrade_keeps_the_existing_handle() {
        let table = LockedOpenFileTable::default();
        let flushes = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let reader = table
            .open(11, FileCapabilities::ReadOnly, false, || {
                Ok(test_file(1, &flushes, &drops))
            })
            .unwrap();

        let error = table
            .open(11, FileCapabilities::ReadWrite, false, || {
                Err(io::Error::from_raw_os_error(libc::EACCES))
            })
            .unwrap_err();

        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
        assert_eq!(table.access(reader, Size::size).unwrap(), 1);
        table.release(reader).unwrap();
        assert_eq!(flushes.load(Ordering::Relaxed), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
