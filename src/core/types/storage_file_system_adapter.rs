use crate::core::{
    FileHandle, FileOpenOptions, FileSystem, FsDirEntry, Metadata, Permissions, StorageFileSystem,
    VirtualPath,
};
use std::time::SystemTime;

/// Adapts a dynamic user-facing filesystem for use as an encrypted storage filesystem.
pub struct StorageFileSystemAdapter {
    filesystem: Box<dyn FileSystem>,
}

impl StorageFileSystemAdapter {
    /// Creates an adapter around a dynamic filesystem.
    pub fn new(filesystem: Box<dyn FileSystem>) -> Self {
        Self { filesystem }
    }

    /// Returns the wrapped filesystem.
    pub fn into_inner(self) -> Box<dyn FileSystem> {
        self.filesystem
    }
}

impl<T: FileSystem> From<T> for StorageFileSystemAdapter {
    fn from(filesystem: T) -> Self {
        Self::new(Box::new(filesystem))
    }
}

impl From<Box<dyn FileSystem>> for StorageFileSystemAdapter {
    fn from(filesystem: Box<dyn FileSystem>) -> Self {
        Self::new(filesystem)
    }
}

impl StorageFileSystem for StorageFileSystemAdapter {
    type OpenHandle = Box<dyn FileHandle>;
    type DirEntries = Box<dyn Iterator<Item = std::io::Result<FsDirEntry>> + 'static>;

    fn open_file_with(
        &self,
        path: &VirtualPath,
        options: FileOpenOptions,
    ) -> std::io::Result<Self::OpenHandle> {
        self.filesystem.open_file_with(path, options)
    }

    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()> {
        self.filesystem.set_time(path, atime, mtime)
    }

    fn chown(&self, path: &VirtualPath, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
        self.filesystem.chown(path, uid, gid)
    }

    fn metadata(&self, path: &VirtualPath) -> std::io::Result<Metadata> {
        self.filesystem.metadata(path)
    }

    fn exists(&self, path: &VirtualPath) -> std::io::Result<bool> {
        self.filesystem.exists(path)
    }

    fn truncate(&self, path: &VirtualPath, new_size: u64) -> std::io::Result<()> {
        self.filesystem.truncate(path, new_size)
    }

    fn mkdir(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        self.filesystem.mkdir(path, permissions)
    }

    fn mknode(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        self.filesystem.mknode(path, permissions)
    }

    fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()> {
        self.filesystem.rename(old_path, new_path)
    }

    fn remove(&self, path: &VirtualPath) -> std::io::Result<()> {
        self.filesystem.remove(path)
    }

    fn remove_dir(&self, path: &VirtualPath) -> std::io::Result<()> {
        self.filesystem.remove_dir(path)
    }

    fn remove_dir_all(&self, path: &VirtualPath) -> std::io::Result<()> {
        self.filesystem.remove_dir_all(path)
    }

    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        self.filesystem.set_permissions(path, permissions)
    }

    fn get_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<Vec<u8>> {
        self.filesystem.get_xattr(path, name)
    }

    fn list_xattr(&self, path: &VirtualPath) -> std::io::Result<Vec<String>> {
        self.filesystem.list_xattr(path)
    }

    fn remove_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<()> {
        self.filesystem.remove_xattr(path, name)
    }

    fn set_xattr(&self, path: &VirtualPath, name: &str, value: &[u8]) -> std::io::Result<()> {
        self.filesystem.set_xattr(path, name, value)
    }

    fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<String> {
        self.filesystem.read_symlink(path)
    }

    fn create_symlink(&self, path: &VirtualPath, target: &str) -> std::io::Result<Metadata> {
        self.filesystem.create_symlink(path, target)
    }

    fn read_dir(&self, path: &VirtualPath) -> std::io::Result<Self::DirEntries> {
        self.filesystem.read_dir(path)
    }
}
