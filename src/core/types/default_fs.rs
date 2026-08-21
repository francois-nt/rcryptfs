use super::{FsDirEntry, GenericOpenOptions, Metadata, Permissions};
use crate::core::{
    JoinVirtualPath, MinimalFs, ModifiedTime, OrIoError, ReadAt, SetLen, SetSync, Size,
    VirtualPath, WriteAt,
};
use camino::{Utf8Path, Utf8PathBuf};
#[cfg(unix)]
use std::ffi::CString;
use std::{fs::OpenOptions, time::SystemTime};

/// Local filesystem implementation rooted at one native UTF-8 directory.
#[derive(Default)]
pub struct DefaultFs {
    root: Utf8PathBuf,
}

impl DefaultFs {
    /// Creates a local filesystem rooted at the provided native directory.
    pub fn new(root: Utf8PathBuf) -> Self {
        Self { root }
    }

    /// Resolves a virtual storage path below the configured native root.
    fn resolve(&self, path: &VirtualPath) -> std::io::Result<Utf8PathBuf> {
        self.root.join_virtual_path(path)
    }
}

/// Updates selected timestamps without following the final symbolic link.
#[cfg(unix)]
fn set_times_nofollow(
    path: &Utf8Path,
    atime: Option<SystemTime>,
    mtime: Option<SystemTime>,
) -> std::io::Result<()> {
    const NANOS_PER_SECOND: i128 = 1_000_000_000;

    fn to_timespec(time: SystemTime) -> std::io::Result<libc::timespec> {
        let nanos = match time.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => {
                i128::from(duration.as_secs()) * NANOS_PER_SECOND
                    + i128::from(duration.subsec_nanos())
            }
            Err(error) => {
                let duration = error.duration();
                -(i128::from(duration.as_secs()) * NANOS_PER_SECOND
                    + i128::from(duration.subsec_nanos()))
            }
        };
        let tv_sec = nanos
            .div_euclid(NANOS_PER_SECOND)
            .try_into()
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let tv_nsec = nanos
            .rem_euclid(NANOS_PER_SECOND)
            .try_into()
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        Ok(libc::timespec { tv_sec, tv_nsec })
    }

    fn to_optional_timespec(time: Option<SystemTime>) -> std::io::Result<libc::timespec> {
        match time {
            Some(time) => to_timespec(time),
            None => Ok(libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT as _,
            }),
        }
    }

    let path = CString::new(path.as_str())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let times = [to_optional_timespec(atime)?, to_optional_timespec(mtime)?];
    // SAFETY: path is NUL-terminated and times contains two initialized timespec values.
    let result = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Updates selected timestamps without following the final symbolic link.
#[cfg(windows)]
fn set_times_nofollow(
    path: &Utf8Path,
    atime: Option<SystemTime>,
    mtime: Option<SystemTime>,
) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
    };

    let file = OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let mut times = std::fs::FileTimes::new();
    if let Some(atime) = atime {
        times = times.set_accessed(atime);
    }
    if let Some(mtime) = mtime {
        times = times.set_modified(mtime);
    }
    file.set_times(times)
}

/// Iterates over entries returned by the local filesystem.
pub struct FsDirentryIterator(std::fs::ReadDir);

impl Iterator for FsDirentryIterator {
    type Item = std::io::Result<FsDirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|entry| entry.map(|v| v.into()))
    }
}

impl ModifiedTime for std::fs::File {
    fn get_modified(&self) -> std::io::Result<SystemTime> {
        self.metadata()?.modified()
    }

    fn set_modified_time(&self, modified_time: SystemTime) -> std::io::Result<()> {
        self.set_times(std::fs::FileTimes::default().set_modified(modified_time))
    }
}

impl Size for std::fs::File {
    fn size(&self) -> std::io::Result<u64> {
        let metadata = self.metadata()?;
        if metadata.is_file() {
            Ok(metadata.len())
        } else {
            Err(std::io::Error::from_raw_os_error(libc::EISDIR))
        }
    }
}

impl ReadAt for std::fs::File {
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        return std::os::unix::fs::FileExt::read_at(self, buf, pos);
        #[cfg(windows)]
        return std::os::windows::fs::FileExt::seek_read(self, buf, pos);
    }
}

impl WriteAt for std::fs::File {
    fn write_at(&self, pos: u64, buf: &[u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        return std::os::unix::fs::FileExt::write_at(self, buf, pos);
        #[cfg(windows)]
        return std::os::windows::fs::FileExt::seek_write(self, buf, pos);
    }
}

impl SetLen for std::fs::File {
    fn set_len(&self, new_size: u64) -> std::io::Result<()> {
        std::fs::File::set_len(self, new_size)
    }
}

impl SetSync for std::fs::File {
    fn sync(&self, datasync: bool) -> std::io::Result<()> {
        if datasync {
            std::fs::File::sync_data(self)
        } else {
            std::fs::File::sync_all(self)
        }
    }
}

impl MinimalFs for DefaultFs {
    type DirEntries = FsDirentryIterator;
    type OpenHandle = std::fs::File;

    fn open_file_with(
        &self,
        path: &VirtualPath,
        options: GenericOpenOptions,
    ) -> std::io::Result<Self::OpenHandle> {
        let options: OpenOptions = options.into();
        options.open(self.resolve(path)?)
    }

    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()> {
        if atime.is_none() && mtime.is_none() {
            return Ok(());
        }

        let path = self.resolve(path)?;
        set_times_nofollow(&path, atime, mtime)
    }

    fn chown(&self, path: &VirtualPath, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
        let path = self.resolve(path)?;
        #[cfg(unix)]
        {
            std::os::unix::fs::chown(&path, uid, gid)
        }
        #[cfg(not(unix))]
        {
            let _ = (path, uid, gid);
            Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
        }
    }

    fn read_dir(
        &self,
        path: &VirtualPath,
        // impl Iterator<Item = std::io::Result<FsDirEntry>> + '_ + use<'_>
    ) -> std::io::Result<Self::DirEntries> {
        Ok(FsDirentryIterator(std::fs::read_dir(self.resolve(path)?)?))
    }

    fn metadata(&self, path: &VirtualPath) -> std::io::Result<Metadata> {
        Ok(std::fs::symlink_metadata(self.resolve(path)?)?.into())
    }

    fn exists(&self, path: &VirtualPath) -> std::io::Result<bool> {
        std::fs::exists(self.resolve(path)?)
    }

    fn mkdir(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        std::fs::create_dir(self.resolve(path)?)?;
        match permissions {
            Some(permissions) => self.set_permissions(path, permissions),
            None => self.metadata(path),
        }
    }

    fn mknode(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        std::fs::File::create_new(self.resolve(path)?)?;
        match permissions {
            Some(permissions) => self.set_permissions(path, permissions),
            None => self.metadata(path),
        }
    }

    fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()> {
        std::fs::rename(self.resolve(old_path)?, self.resolve(new_path)?)
    }

    fn remove(&self, path: &VirtualPath) -> std::io::Result<()> {
        std::fs::remove_file(self.resolve(path)?)
    }

    fn remove_dir(&self, path: &VirtualPath) -> std::io::Result<()> {
        std::fs::remove_dir(self.resolve(path)?)
    }

    fn remove_dir_all(&self, path: &VirtualPath) -> std::io::Result<()> {
        if path.is_empty() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY));
        }
        std::fs::remove_dir_all(self.resolve(path)?)
    }

    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> std::io::Result<Metadata> {
        let path = self.resolve(path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        log::debug!("metadata {:?}", metadata);
        let mut file_permissions = metadata.permissions();
        let new_mode: u16 = permissions.into();

        #[cfg(not(unix))]
        file_permissions.set_readonly(permissions.readonly());
        #[cfg(unix)]
        std::os::unix::fs::PermissionsExt::set_mode(&mut file_permissions, new_mode as u32);

        log::debug!("setting permissions {:?}", file_permissions);
        std::fs::set_permissions(&path, file_permissions)?;
        let mut metadata: Metadata = metadata.into();
        metadata.permissions = new_mode.into();
        log::debug!("metadata are {metadata}");
        Ok(metadata)
    }

    fn get_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<Vec<u8>> {
        let path = self.resolve(path)?;
        #[cfg(not(unix))]
        {
            let _ = (path, name);
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        #[cfg(unix)]
        {
            xattr::get(&path, name)?.or_io_error(libc::ENODATA)
        }
    }

    fn list_xattr(&self, path: &VirtualPath) -> std::io::Result<Vec<String>> {
        let path = self.resolve(path)?;
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        #[cfg(unix)]
        {
            Ok(xattr::list(&path)?
                .flat_map(move |s| s.to_str().map(|s| s.to_string()))
                .collect())
        }
    }

    fn remove_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<()> {
        let path = self.resolve(path)?;
        #[cfg(not(unix))]
        {
            let _ = (path, name);
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        #[cfg(unix)]
        {
            xattr::remove(&path, name)
        }
    }

    fn set_xattr(&self, path: &VirtualPath, name: &str, value: &[u8]) -> std::io::Result<()> {
        let path = self.resolve(path)?;
        #[cfg(not(unix))]
        {
            let _ = (path, name, value);
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        #[cfg(unix)]
        {
            xattr::set(&path, name, value)
        }
    }

    fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<String> {
        let target: Utf8PathBuf = std::fs::read_link(self.resolve(path)?)?
            .try_into()
            .or_invalid()?;
        Ok(target.into_string())
    }

    fn create_symlink(&self, path: &VirtualPath, target: &str) -> std::io::Result<Metadata> {
        let path = self.resolve(path)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &path)?;
        #[cfg(not(unix))]
        std::os::windows::fs::symlink_file(target, &path)?;

        let metadata: Metadata = std::fs::symlink_metadata(&path)?.into();
        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};
    use tempfile::tempdir;

    #[test]
    fn default_fs_set_time_preserves_omitted_timestamp() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = DefaultFs::new(root);
        let path = VirtualPath::new("file");
        let initial_atime = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        let initial_mtime = UNIX_EPOCH + Duration::from_secs(1_600_000_100);
        let updated_atime = UNIX_EPOCH + Duration::from_secs(1_600_000_200);
        let updated_mtime = UNIX_EPOCH + Duration::from_secs(1_600_000_300);

        fs.mknode(path, None).unwrap();
        fs.set_time(path, Some(initial_atime), Some(initial_mtime))
            .unwrap();
        fs.set_time(path, None, Some(updated_mtime)).unwrap();

        let metadata = fs.metadata(path).unwrap();
        assert_eq!(metadata.accessed, initial_atime);
        assert_eq!(metadata.modified, updated_mtime);

        fs.set_time(path, Some(updated_atime), None).unwrap();

        let metadata = fs.metadata(path).unwrap();
        assert_eq!(metadata.accessed, updated_atime);
        assert_eq!(metadata.modified, updated_mtime);
    }

    #[cfg(unix)]
    #[test]
    fn default_fs_set_time_does_not_follow_symlinks() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = DefaultFs::new(root);
        let target = VirtualPath::new("target");
        let link = VirtualPath::new("link");
        let target_atime = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        let target_mtime = UNIX_EPOCH + Duration::from_secs(1_600_000_100);
        let link_atime = UNIX_EPOCH + Duration::from_secs(1_600_000_200);
        let link_mtime = UNIX_EPOCH + Duration::from_secs(1_600_000_300);

        fs.mknode(target, None).unwrap();
        fs.set_time(target, Some(target_atime), Some(target_mtime))
            .unwrap();
        fs.create_symlink(link, target.as_str()).unwrap();
        fs.set_time(link, Some(link_atime), Some(link_mtime))
            .unwrap();

        let target_metadata = fs.metadata(target).unwrap();
        assert_eq!(target_metadata.accessed, target_atime);
        assert_eq!(target_metadata.modified, target_mtime);
        let link_metadata = fs.metadata(link).unwrap();
        assert_eq!(link_metadata.accessed, link_atime);
        assert_eq!(link_metadata.modified, link_mtime);
    }

    #[cfg(unix)]
    #[test]
    fn default_fs_keeps_symlink_targets_opaque() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = DefaultFs::new(root);
        let target = "/opaque/../target";

        fs.create_symlink(VirtualPath::new("link"), target).unwrap();

        assert_eq!(fs.read_symlink(VirtualPath::new("link")).unwrap(), target);
    }
}
