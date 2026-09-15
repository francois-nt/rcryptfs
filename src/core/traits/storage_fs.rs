use super::{
    FileHandle, FileOpenOptions, FileType, FsDirEntry, Metadata, Permissions, ReadAt, SetLen, Size,
    VirtualPath, WriteAt,
};
use std::time::SystemTime;

/// Provides the filesystem operations required by encrypted storage layouts.
pub trait StorageFileSystem: Send + Sync + 'static {
    type OpenHandle: FileHandle;
    type DirEntries: Iterator<Item = std::io::Result<FsDirEntry>>;
    fn open_file_with(
        &self,
        path: &VirtualPath,
        options: FileOpenOptions,
    ) -> std::io::Result<Self::OpenHandle>;

    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()>;

    fn chown(&self, path: &VirtualPath, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()>;
    fn metadata(&self, path: &VirtualPath) -> std::io::Result<Metadata>;
    fn exists(&self, path: &VirtualPath) -> std::io::Result<bool> {
        match self.metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
    /// Truncates a file to a new size.
    fn truncate(&self, path: &VirtualPath, new_size: u64) -> std::io::Result<()> {
        let mut options = FileOpenOptions::default();
        options.read(true).write(true);
        let file = self.open_file_with(path, options)?;
        file.set_len(new_size)?;
        file.flush()
    }
    /// Creates a new directory with optional permissions.
    fn mkdir(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata>;
    /// Creates a new node with optional permissions.
    fn mknode(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata>;
    fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()>;
    /// Atomically renames an entry and fails if the destination already exists.
    fn rename_no_replace(
        &self,
        old_path: &VirtualPath,
        new_path: &VirtualPath,
    ) -> std::io::Result<()> {
        let _ = (old_path, new_path);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "atomic no-replace rename is not supported",
        ))
    }
    /// Removes a non-directory entry.
    fn remove(&self, path: &VirtualPath) -> std::io::Result<()>;
    /// Removes an empty directory.
    fn remove_dir(&self, path: &VirtualPath) -> std::io::Result<()>;
    /// Recursively removes a directory and its contents.
    fn remove_dir_all(&self, path: &VirtualPath) -> std::io::Result<()> {
        if path.is_empty() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY));
        }

        let entries = self.read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        for entry in entries {
            let child_path = path.join(entry.file_name);
            if entry.metadata.file_type == FileType::Directory {
                self.remove_dir_all(&child_path)?;
            } else {
                self.remove(&child_path)?;
            }
        }
        self.remove_dir(path)
    }
    fn put(&self, path: &VirtualPath, data: &[u8]) -> std::io::Result<()> {
        let mut options = FileOpenOptions::default();
        options.write(true).truncate(true).create(true);
        self.open_file_with(path, options)?.write_all_at(0, data)
    }
    fn put_new(&self, path: &VirtualPath, data: &[u8]) -> std::io::Result<()> {
        let mut options = FileOpenOptions::default();
        options.write(true).create_new(true);
        self.open_file_with(path, options)?.write_all_at(0, data)
    }
    fn read_at(
        &self,
        path: &VirtualPath,
        offset: u64,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        let mut options = FileOpenOptions::default();
        options.read(true);
        self.open_file_with(path, options)?.read_at(offset, buffer)
    }
    /// Repeats positioned reads until the buffer is full, EOF is reached, or an error occurs.
    fn read_all_at(
        &self,
        path: &VirtualPath,
        offset: u64,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        let mut options = FileOpenOptions::default();
        options.read(true);
        self.open_file_with(path, options)?
            .read_all_at(offset, buffer)
    }
    fn read(&self, path: &VirtualPath, offset: u64, size: usize) -> std::io::Result<Vec<u8>> {
        let mut buffer = vec![0; size];
        let bytes_read = self.read_all_at(path, offset, &mut buffer)?;
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
    fn read_all(&self, path: &VirtualPath) -> std::io::Result<Vec<u8>> {
        let mut options = FileOpenOptions::default();
        options.read(true);
        let file = self.open_file_with(path, options)?;
        let size = file.size()?;
        let size =
            usize::try_from(size).map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let mut buffer = vec![0; size];
        file.read_exact_at(0, &mut buffer)?;
        Ok(buffer)
    }
    fn is_dir_empty(&self, path: &VirtualPath) -> std::io::Result<bool> {
        self.read_dir(path)?
            .next()
            .transpose()
            .map(|entry| entry.is_none())
    }
    fn mkdir_all(&self, path: &VirtualPath) -> std::io::Result<()> {
        if self.exists(path)? {
            return Ok(());
        }
        if let Some(parent) = path.parent()
            && !parent.as_str().is_empty()
        {
            self.mkdir_all(parent)?;
        }
        match self.mkdir(path, None) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(error),
        }
    }
    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata>;
    fn get_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<Vec<u8>>;
    fn list_xattr(&self, path: &VirtualPath) -> std::io::Result<Vec<String>>;
    fn remove_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<()>;
    fn set_xattr(&self, path: &VirtualPath, name: &str, value: &[u8]) -> std::io::Result<()>;
    fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<String>;
    fn create_symlink(&self, path: &VirtualPath, target: &str) -> std::io::Result<Metadata>;
    fn read_dir(&self, path: &VirtualPath) -> std::io::Result<Self::DirEntries>;
}
