use super::VirtualPath;

/// Restricted filesystem view used for repository configuration files.
pub trait ConfigFileSystem: Send + Sync + 'static {
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

/// Provides the restricted configuration filesystem selected by a backend.
pub trait ConfigFileSystemAccess: Send + Sync + 'static {
    /// Returns the configuration filesystem without exposing its concrete type.
    fn config_fs(&self) -> &dyn ConfigFileSystem;
}
