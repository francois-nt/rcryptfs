use crate::Backend;
pub use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Utc};
use derive_more::derive::{From, Into};
use parking_lot::Mutex;
use std::{collections::BTreeMap, fmt::Display, fs::OpenOptions, time::SystemTime};
use strum_macros::Display;

type FsCacheEntry = (Vec<u8>, Utf8PathBuf);
/// Backend configuration with cipher root path.
pub struct FsBackend {
    pub cipher_root: Utf8PathBuf,
    cache: Mutex<BTreeMap<String, FsCacheEntry>>,
}

impl FsBackend {
    /// Gives temporary mutable access to the plain-to-cipher path cache.
    pub fn access<Res, F: FnOnce(&mut BTreeMap<String, FsCacheEntry>) -> Res>(&self, f: F) -> Res {
        f(&mut self.cache.lock())
    }
}

impl From<Utf8PathBuf> for FsBackend {
    fn from(value: Utf8PathBuf) -> Self {
        Self {
            cipher_root: value,
            cache: Default::default(),
        }
    }
}

impl From<&Utf8Path> for FsBackend {
    fn from(value: &Utf8Path) -> Self {
        Self {
            cipher_root: value.into(),
            cache: Default::default(),
        }
    }
}

/// In-memory backend for testing.
pub struct MemoryBackend;
impl Backend for FsBackend {}
impl Backend for MemoryBackend {}

/// File type enumeration.
#[derive(Display, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
    SymLink,
    Other,
}

impl From<std::fs::FileType> for FileType {
    fn from(value: std::fs::FileType) -> Self {
        if value.is_file() {
            return FileType::File;
        } else if value.is_dir() {
            return FileType::Directory;
        } else if value.is_symlink() {
            return FileType::SymLink;
        }
        FileType::Other
    }
}

/// Timestamp with seconds and nanoseconds.
#[derive(From, Into)]
pub struct FsTime(i64, u32);

impl FsTime {
    /// Converts to UTC string representation.
    pub fn to_utc_string(&self) -> Option<String> {
        let secs: i64 = self.0;

        let nanos_u64 = self.1 as u64;
        let secs = secs.checked_add((nanos_u64 / 1_000_000_000) as i64)?;
        let nanos = (nanos_u64 % 1_000_000_000) as u32;

        let utc: DateTime<Utc> = DateTime::<Utc>::from_timestamp(secs, nanos)?;
        let local = utc.with_timezone(&chrono::Local);

        Some(local.format("%Y-%m-%d %H:%M:%S%.9f %Z").to_string())
    }
}

impl Display for FsTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.to_utc_string().as_ref().map_or("bad_time", |v| v)
        )
    }
}

/// Directory entry with name, type, and metadata.
pub struct FsDirEntry {
    pub file_name: String,
    pub file_type: Option<FileType>,
    pub metadata: Option<Metadata>,
}

impl FsDirEntry {
    /// Creates a new entry with a different name.
    pub fn with_name(self, new_name: String) -> Self {
        Self {
            file_name: new_name,
            file_type: self.file_type,
            metadata: self.metadata,
        }
    }
}

impl Display for FsDirEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.file_name)?;
        if let Some(file_type) = &self.file_type {
            write!(f, "\t{}", file_type)?;
        } else {
            write!(f, "\t<no_filetype>")?;
        }
        if let Some(metadata) = &self.metadata {
            write!(f, "\t{}", metadata)?;
        }
        Ok(())
    }
}

/// Options for opening files.
#[derive(Default, Debug)]
pub struct GenericOpenOptions {
    // generic
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub truncate: bool,
    pub create: bool,
    pub create_new: bool,
    pub permissions: Option<Permissions>,
}

impl GenericOpenOptions {
    /// Checks if options are read-only.
    pub fn is_readonly(&self) -> bool {
        self.read
            && !self.write
            && !self.append
            && !self.truncate
            && !self.create
            && !self.create_new
    }
    /// Sets read option.
    pub fn read(&mut self, read: bool) -> &mut Self {
        self.read = read;
        self
    }
    /// Sets write option.
    pub fn write(&mut self, write: bool) -> &mut Self {
        self.write = write;
        self
    }
    /// Sets append option.
    pub fn append(&mut self, append: bool) -> &mut Self {
        self.append = append;
        self
    }
    /// Sets truncate option.
    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.truncate = truncate;
        self
    }
    /// Sets create option.
    pub fn create(&mut self, create: bool) -> &mut Self {
        self.create = create;
        self
    }
    /// Sets create_new option.
    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.create_new = create_new;
        self
    }
    /// Sets permissions.
    pub fn permissions(&mut self, permissions: Permissions) -> &mut Self {
        self.permissions = Some(permissions);
        self
    }
    /// Gets the mode from permissions.
    pub fn mode(&self) -> u16 {
        self.permissions.unwrap_or_default().into()
    }
}

impl From<GenericOpenOptions> for OpenOptions {
    fn from(value: GenericOpenOptions) -> Self {
        let mut this = Self::new();
        this.read(value.read)
            .write(value.write)
            .append(value.append)
            .truncate(value.truncate)
            .create(value.create)
            .create_new(value.create_new);
        #[cfg(unix)]
        {
            if let Some(permissions) = value.permissions {
                use std::os::unix::fs::OpenOptionsExt;
                this.mode(permissions.into());
            }
        }
        this
    }
}

/// File permissions.
#[derive(Clone, Copy, Debug)]
pub struct Permissions(u16);

impl Default for Permissions {
    fn default() -> Self {
        Self(0o666)
    }
}
impl Permissions {
    /// Checks if permissions are read-only.
    pub fn readonly(&self) -> bool {
        #[cfg(unix)]
        return <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(
            self.0 as u32,
        )
        .readonly();
        #[cfg(not(unix))]
        return self.0 == 1;
    }
}

impl Display for Permissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04o}", self.0)
    }
}

impl From<Permissions> for u16 {
    fn from(value: Permissions) -> Self {
        value.0
    }
}

impl From<Permissions> for u32 {
    fn from(value: Permissions) -> Self {
        value.0 as u32
    }
}

impl From<u16> for Permissions {
    fn from(value: u16) -> Self {
        #[cfg(unix)]
        return Self(value);
        #[cfg(not(unix))]
        return Self(value & 1);
    }
}

impl From<u32> for Permissions {
    fn from(value: u32) -> Self {
        Permissions::from(value as u16)
    }
}

impl From<std::fs::Permissions> for Permissions {
    fn from(value: std::fs::Permissions) -> Self {
        #[cfg(unix)]
        return std::os::unix::fs::PermissionsExt::mode(&value).into();
        #[cfg(not(unix))]
        return Self(value.readonly() as u16);
    }
}

impl From<std::fs::DirEntry> for FsDirEntry {
    fn from(value: std::fs::DirEntry) -> Self {
        Self {
            file_name: value.file_name().to_string_lossy().into_owned(),
            file_type: value.file_type().ok().map(|v| v.into()),
            metadata: value.metadata().ok().map(|v| v.into()),
        }
    }
}

impl From<SystemTime> for FsTime {
    /// Converts system time to a display-friendly timestamp and clamps pre-epoch values.
    fn from(value: SystemTime) -> Self {
        let duration = value
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        Self(duration.as_secs() as i64, duration.subsec_nanos())
    }
}

impl From<std::fs::Metadata> for Metadata {
    /// Builds portable metadata and falls back when some timestamps are unavailable.
    fn from(value: std::fs::Metadata) -> Self {
        let modified = value.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let accessed = value.accessed().unwrap_or(modified);
        let created = value.created().unwrap_or(modified);

        let uid: Option<u32>;
        let gid: Option<u32>;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            uid = Some(value.uid());
            gid = Some(value.gid())
        }
        #[cfg(not(unix))]
        {
            uid = None;
            gid = None;
        }

        Self {
            len: value.len(),
            file_type: value.file_type().into(),
            created,
            modified,
            accessed,
            permissions: value.permissions().into(),
            uid,
            gid,
        }
    }
}

/// File metadata.
pub struct Metadata {
    pub len: u64,
    pub file_type: FileType,
    pub created: SystemTime,
    pub modified: SystemTime,
    pub accessed: SystemTime,
    pub permissions: Permissions,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

/// Displays system time for metadata.
fn display_system_time(
    f: &mut std::fmt::Formatter<'_>,
    label: &str,
    fs_time: SystemTime,
) -> std::fmt::Result {
    let fs_time: FsTime = fs_time.into();
    write!(f, "{} {}", label, fs_time)?;

    Ok(())
}

impl Display for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\tsize: {}", self.len)?;
        display_system_time(f, "\tcreation_time:", self.created)?;
        display_system_time(f, "\taccess_time:", self.accessed)?;
        display_system_time(f, "\tmodification_time:", self.modified)?;
        write!(f, "\tmode: {}", self.permissions)?;
        Ok(())
    }
}
