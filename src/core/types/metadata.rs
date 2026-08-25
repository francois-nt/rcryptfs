use chrono::{DateTime, Utc};
use derive_more::derive::{From, Into};
use std::{fmt::Display, time::SystemTime};
use strum_macros::Display;

/// File type enumeration.
#[derive(Display, PartialEq, Eq, Clone, Copy)]
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
    pub metadata: Metadata,
}

impl FsDirEntry {
    /// Creates a new entry with a different name.
    pub fn with_name(self, new_name: String) -> Self {
        Self {
            file_name: new_name,
            metadata: self.metadata,
        }
    }
}

impl TryFrom<std::fs::DirEntry> for FsDirEntry {
    type Error = std::io::Error;
    fn try_from(value: std::fs::DirEntry) -> std::io::Result<Self> {
        Ok(Self {
            file_name: value.file_name().to_string_lossy().into_owned(),
            metadata: value.metadata()?.into(),
        })
    }
}

impl Display for FsDirEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.file_name)?;
        write!(f, "\t{}", self.metadata)?;
        Ok(())
    }
}

/// File permissions.
#[derive(Clone, Copy, Debug)]
pub struct Permissions(u16);

impl Default for Permissions {
    #[cfg(unix)]
    fn default() -> Self {
        Self(0o666)
    }

    #[cfg(not(unix))]
    fn default() -> Self {
        Self(0)
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
        return (std::os::unix::fs::PermissionsExt::mode(&value) & 0o777).into();
        #[cfg(not(unix))]
        return Self(value.readonly() as u16);
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
            blocks: num_blocks(value.len()),
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

fn num_blocks(file_len: u64) -> u64 {
    if file_len == 0 {
        0
    } else {
        (file_len - 1) / 4096 + 1
    }
}
/// File metadata.
pub struct Metadata {
    pub len: u64,
    pub blocks: u64,
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
        write!(f, "\t{}", self.file_type)?;
        display_system_time(f, "\tcreation_time:", self.created)?;
        display_system_time(f, "\taccess_time:", self.accessed)?;
        display_system_time(f, "\tmodification_time:", self.modified)?;
        write!(f, "\tmode: {}", self.permissions)?;
        Ok(())
    }
}
