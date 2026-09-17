use super::{StorageFileSystem, VirtualPath};

/// Restricted filesystem view used for repository configuration files.
pub trait ConfigFileSystem: Send + Sync {
    /// Returns whether the configuration namespace contains no entries.
    fn is_empty(&self) -> std::io::Result<bool>;

    /// Returns whether a configuration path exists.
    fn exists(&self, path: &VirtualPath) -> std::io::Result<bool>;

    /// Reads a complete configuration file.
    fn read_all(&self, path: &VirtualPath) -> std::io::Result<Vec<u8>>;

    /// Creates a new configuration file without replacing an existing one.
    fn put_new(&self, path: &VirtualPath, data: &[u8]) -> std::io::Result<()>;

    /// Removes a configuration file.
    fn remove(&self, path: &VirtualPath) -> std::io::Result<()>;
}

/// Restricted configuration view borrowing a raw storage filesystem.
pub struct StorageConfigFileSystem<'a, F: StorageFileSystem + ?Sized> {
    storage_fs: &'a F,
}

impl<'a, F: StorageFileSystem + ?Sized> StorageConfigFileSystem<'a, F> {
    /// Creates a configuration view over a raw storage filesystem.
    pub fn new(storage_fs: &'a F) -> Self {
        Self { storage_fs }
    }
}

impl<F: StorageFileSystem + ?Sized> ConfigFileSystem for StorageConfigFileSystem<'_, F> {
    fn is_empty(&self) -> std::io::Result<bool> {
        self.storage_fs.is_dir_empty(VirtualPath::root())
    }

    fn exists(&self, path: &VirtualPath) -> std::io::Result<bool> {
        self.storage_fs.exists(path)
    }

    fn read_all(&self, path: &VirtualPath) -> std::io::Result<Vec<u8>> {
        self.storage_fs.read_all(path)
    }

    fn put_new(&self, path: &VirtualPath, data: &[u8]) -> std::io::Result<()> {
        self.storage_fs.put_new(path, data)
    }

    fn remove(&self, path: &VirtualPath) -> std::io::Result<()> {
        self.storage_fs.remove(path)
    }
}
