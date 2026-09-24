use super::{
    FileOpenOptions, FsDirEntry, Metadata, Permissions,
    namespace_lock_manager::NamespaceLockManager,
};
use crate::core::{
    ExistingDestinationPolicy, JoinVirtualPath, ModifiedTime, OrIoError, ReadAt, RenameOperation,
    SetLen, SetSync, Size, StorageFileSystem, VirtualPath, VirtualPathBuf, WriteAt,
};
use camino::{Utf8Path, Utf8PathBuf};
#[cfg(unix)]
use std::ffi::CString;
use std::{cmp::Reverse, collections::HashSet, fs::OpenOptions, time::SystemTime};

const INTERNAL_TEMP_PREFIX: &str = ".#internal.storagefs#.";

fn generate_internal_path(prefix: &str) -> String {
    format!(
        "{INTERNAL_TEMP_PREFIX}{prefix}.{}",
        uuid::Uuid::new_v4().simple()
    )
}
/// One entry moved out of the visible namespace during a grouped removal.
struct StagedRemoval {
    original: Utf8PathBuf,
    temporary: Utf8PathBuf,
    is_directory: bool,
}

/// Tracks one validated entry throughout a grouped rename operation.
struct RenameEntry {
    source: Utf8PathBuf,
    destination: Utf8PathBuf,
    source_is_directory: bool,
    replacement: Option<Utf8PathBuf>,
    replacement_is_directory: bool,
    temporary_source: Option<Utf8PathBuf>,
    temporary_replacement: Option<Utf8PathBuf>,
    ignored: bool,
    published: bool,
}

/// Returns whether a path addresses the private internal namespace.
fn is_internal_temp_path(path: &VirtualPath) -> bool {
    path.components()
        .next()
        .is_some_and(|component| component.starts_with(INTERNAL_TEMP_PREFIX))
}

/// Restores staged entries in reverse order so parents precede their children.
fn rollback_removals(staged: &[StagedRemoval]) -> std::io::Result<()> {
    let mut first_error = None;
    for entry in staged.iter().rev() {
        if let Err(error) = rename_noreplace(&entry.temporary, &entry.original) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Preserves the original failure unless restoring the staged namespace also fails.
fn rollback_removal_error(
    error: std::io::Error,
    staged: &[StagedRemoval],
    temp_root: &Utf8Path,
) -> std::io::Error {
    let rollback = rollback_removals(staged);
    let _ = std::fs::remove_dir(temp_root);
    match rollback {
        Ok(()) => error,
        Err(rollback_error) => std::io::Error::new(
            rollback_error.kind(),
            format!("{error}; removal rollback failed: {rollback_error}"),
        ),
    }
}

/// Restores a partially published grouped rename in dependency order.
fn rollback_renames(entries: &[RenameEntry]) -> std::io::Result<()> {
    let mut first_error = None;

    let mut published = entries
        .iter()
        .filter(|entry| entry.published)
        .collect::<Vec<_>>();
    published.sort_by_key(|entry| Reverse(entry.destination.components().count()));
    for entry in published {
        if let Some(temporary) = &entry.temporary_source
            && let Err(error) = rename_noreplace(&entry.destination, temporary)
        {
            first_error.get_or_insert(error);
        }
    }

    let mut restore = entries
        .iter()
        .flat_map(|entry| {
            [
                entry
                    .temporary_source
                    .as_ref()
                    .map(|temporary| (temporary, &entry.source)),
                entry
                    .temporary_replacement
                    .as_ref()
                    .zip(entry.replacement.as_ref()),
            ]
        })
        .flatten()
        .collect::<Vec<_>>();
    restore.sort_by_key(|(_, original)| original.components().count());
    for (temporary, original) in restore {
        if let Err(error) = rename_noreplace(temporary, original) {
            first_error.get_or_insert(error);
        }
    }

    first_error.map_or(Ok(()), Err)
}

/// Preserves the operation failure unless restoring the namespace also fails.
fn rollback_rename_error(
    error: std::io::Error,
    entries: &[RenameEntry],
    temp_root: &Utf8Path,
) -> std::io::Error {
    let rollback = rollback_renames(entries);
    let _ = std::fs::remove_dir(temp_root);
    match rollback {
        Ok(()) => error,
        Err(rollback_error) => std::io::Error::new(
            rollback_error.kind(),
            format!("{error}; rename rollback failed: {rollback_error}"),
        ),
    }
}

/// Removes an entry retained only for grouped rename cleanup.
fn remove_rename_staging(path: &Utf8Path, is_directory: bool) -> std::io::Result<()> {
    if is_directory {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// Local filesystem implementation rooted at one native UTF-8 directory.
#[derive(Default)]
pub struct NativeFileSystem {
    root: Utf8PathBuf,
    namespace_locks: NamespaceLockManager,
}

impl NativeFileSystem {
    /// Creates a local filesystem rooted at the provided native directory.
    pub fn new(root: Utf8PathBuf) -> Self {
        Self {
            root,
            namespace_locks: NamespaceLockManager::default(),
        }
    }

    /// Resolves a virtual storage path below the configured native root.
    fn resolve(&self, path: &VirtualPath) -> std::io::Result<Utf8PathBuf> {
        if is_internal_temp_path(path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "path is reserved",
            ));
        }
        self.root.join_virtual_path(path)
    }

    /// Validates a grouped rename without changing the namespace.
    fn resolve_rename_operations(
        &self,
        operations: &[RenameOperation],
    ) -> std::io::Result<Vec<RenameEntry>> {
        let mut sources = HashSet::with_capacity(operations.len());
        let mut destinations = HashSet::with_capacity(operations.len());
        let mut entries = Vec::with_capacity(operations.len());

        for operation in operations {
            if operation.source.is_empty() || operation.destination.is_empty() {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
            let source = self.resolve(&operation.source)?;
            let destination = self.resolve(&operation.destination)?;
            if !sources.insert(source.clone()) || !destinations.insert(destination.clone()) {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }

            let source_metadata = std::fs::symlink_metadata(&source)?;
            entries.push(RenameEntry {
                source,
                destination,
                source_is_directory: source_metadata.is_dir(),
                replacement: None,
                replacement_is_directory: false,
                temporary_source: None,
                temporary_replacement: None,
                ignored: false,
                published: false,
            });
        }

        if entries.iter().any(|source| {
            entries.iter().any(|destination| {
                source.source.starts_with(&destination.destination)
                    || destination.destination.starts_with(&source.source)
            })
        }) {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        for index in 0..entries.len() {
            let destination_parent = entries
                .iter()
                .enumerate()
                .filter(|(_, candidate)| {
                    candidate.destination != entries[index].destination
                        && entries[index]
                            .destination
                            .starts_with(&candidate.destination)
                })
                .max_by_key(|(_, candidate)| candidate.destination.components().count())
                .map(|(index, _)| index);

            let replacement = if let Some(parent_index) = destination_parent {
                if !entries[parent_index].source_is_directory {
                    return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR));
                }
                let relative = entries[index]
                    .destination
                    .strip_prefix(&entries[parent_index].destination)
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                entries[parent_index].source.join(relative)
            } else {
                entries[index].destination.clone()
            };
            let parent = replacement
                .parent()
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
            if !std::fs::metadata(parent)?.is_dir() {
                return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR));
            }

            let replacement_is_detached = destination_parent.is_some_and(|parent_index| {
                entries
                    .iter()
                    .enumerate()
                    .any(|(candidate_index, candidate)| {
                        candidate_index != parent_index
                            && candidate.source.starts_with(&entries[parent_index].source)
                            && replacement.starts_with(&candidate.source)
                    })
            });
            let destination_metadata = match std::fs::symlink_metadata(&replacement) {
                Ok(_) if replacement_is_detached => continue,
                Ok(_)
                    if operations[index].existing_destination
                        == ExistingDestinationPolicy::Reject =>
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "rename destination already exists",
                    ));
                }
                Ok(metadata) => Some(metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
            if let Some(destination_metadata) = destination_metadata {
                if entries[index].source_is_directory && !destination_metadata.is_dir() {
                    return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR));
                }
                if !entries[index].source_is_directory && destination_metadata.is_dir() {
                    return Err(std::io::Error::from_raw_os_error(libc::EISDIR));
                }
                if operations[index].existing_destination == ExistingDestinationPolicy::Ignore {
                    entries[index].ignored = true;
                } else {
                    entries[index].replacement_is_directory = destination_metadata.is_dir();
                    entries[index].replacement = Some(replacement);
                }
            }
        }
        Ok(entries)
    }

    /// Performs a grouped rename while its namespace scope is held exclusively.
    fn rename_multiple_impl(&self, operations: &[RenameOperation]) -> std::io::Result<()> {
        if operations.is_empty() {
            return Ok(());
        }
        let _scope = self.namespace_locks.acquire_exclusive(
            operations
                .iter()
                .flat_map(|operation| [&operation.source, &operation.destination]),
        )?;
        let mut entries = self.resolve_rename_operations(operations)?;
        let temp_root = loop {
            let path = self.root.join(generate_internal_path("rename"));
            match std::fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        };

        let mut staging_order = Vec::with_capacity(entries.len() * 2);
        for (index, entry) in entries.iter().enumerate() {
            staging_order.push((entry.source.components().count(), index, false));
            if let Some(replacement) = &entry.replacement {
                staging_order.push((replacement.components().count(), index, true));
            }
        }
        staging_order.sort_by_key(|(depth, _, _)| Reverse(*depth));

        for (_, index, is_replacement) in staging_order {
            let temporary = temp_root.join(if is_replacement {
                format!("destination.{index}")
            } else {
                format!("source.{index}")
            });
            let original = match (is_replacement, &entries[index].replacement) {
                (true, Some(replacement)) => replacement,
                (false, _) => &entries[index].source,
                (true, None) => continue,
            };
            if let Err(error) = rename_noreplace(original, &temporary) {
                return Err(rollback_rename_error(error, &entries, &temp_root));
            }
            if is_replacement {
                entries[index].temporary_replacement = Some(temporary);
            } else {
                entries[index].temporary_source = Some(temporary);
            }
        }

        let mut publication_order = (0..entries.len()).collect::<Vec<_>>();
        publication_order.sort_by_key(|index| entries[*index].destination.components().count());
        for index in publication_order {
            if entries[index].ignored {
                continue;
            }
            let Some(temporary) = &entries[index].temporary_source else {
                continue;
            };
            if let Err(error) = rename_noreplace(temporary, &entries[index].destination) {
                return Err(rollback_rename_error(error, &entries, &temp_root));
            }
            entries[index].published = true;
        }

        for entry in &entries {
            if let Some(temporary) = &entry.temporary_replacement
                && let Err(error) = remove_rename_staging(temporary, entry.replacement_is_directory)
            {
                log::warn!("failed to clean grouped rename backup: {error}");
            }
            if entry.ignored
                && let Some(temporary) = &entry.temporary_source
                && let Err(error) = remove_rename_staging(temporary, entry.source_is_directory)
            {
                log::warn!("failed to clean ignored grouped rename source: {error}");
            }
        }
        if let Err(error) = std::fs::remove_dir(&temp_root) {
            log::warn!("failed to clean grouped rename staging directory: {error}");
        }
        Ok(())
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

/// Atomically renames an entry without replacing an existing destination.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn rename_noreplace(old_path: &Utf8Path, new_path: &Utf8Path) -> std::io::Result<()> {
    let old_path = CString::new(old_path.as_str())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let new_path = CString::new(new_path.as_str())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    // SAFETY: both paths are valid NUL-terminated strings for the duration of the call.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            old_path.as_ptr(),
            libc::AT_FDCWD,
            new_path.as_ptr(),
            libc::RENAME_NOREPLACE as _,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Atomically renames an entry without replacing an existing destination.
#[cfg(target_vendor = "apple")]
fn rename_noreplace(old_path: &Utf8Path, new_path: &Utf8Path) -> std::io::Result<()> {
    let old_path = CString::new(old_path.as_str())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let new_path = CString::new(new_path.as_str())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    // SAFETY: both paths are valid NUL-terminated strings for the duration of the call.
    let result =
        unsafe { libc::renamex_np(old_path.as_ptr(), new_path.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Reports the lack of an atomic no-replace rename primitive on this platform.
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android")),
    not(target_vendor = "apple")
))]
fn rename_noreplace(_old_path: &Utf8Path, _new_path: &Utf8Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace rename is not supported on this Unix platform",
    ))
}

/// Atomically renames an entry without replacing an existing destination.
#[cfg(windows)]
fn rename_noreplace(old_path: &Utf8Path, new_path: &Utf8Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

    let old_path: Vec<u16> = old_path
        .as_std_path()
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let new_path: Vec<u16> = new_path
        .as_std_path()
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both vectors are NUL-terminated and remain alive during the call.
    let result = unsafe { MoveFileExW(old_path.as_ptr(), new_path.as_ptr(), 0) };
    if result != 0 {
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
pub struct NativeDirEntries {
    entries: std::fs::ReadDir,
    hide_internal_temps: bool,
}

impl Iterator for NativeDirEntries {
    type Item = std::io::Result<FsDirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            if self.hide_internal_temps
                && entry.as_ref().is_ok_and(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(INTERNAL_TEMP_PREFIX))
                })
            {
                continue;
            }
            return Some(entry.and_then(TryInto::try_into));
        }
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

impl StorageFileSystem for NativeFileSystem {
    type DirEntries = NativeDirEntries;
    type OpenHandle = std::fs::File;

    fn open_file_with(
        &self,
        path: &VirtualPath,
        options: FileOpenOptions,
    ) -> std::io::Result<Self::OpenHandle> {
        let _scope = if options.create || options.create_new {
            Some(self.namespace_locks.acquire_shared([path])?)
        } else {
            None
        };
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
        Ok(NativeDirEntries {
            entries: std::fs::read_dir(self.resolve(path)?)?,
            hide_internal_temps: path.is_empty(),
        })
    }

    fn metadata(&self, path: &VirtualPath) -> std::io::Result<Metadata> {
        Ok(std::fs::symlink_metadata(self.resolve(path)?)?.into())
    }

    fn mkdir(
        &self,
        path: &VirtualPath,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata> {
        let _scope = self.namespace_locks.acquire_shared([path])?;
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
        let _scope = self.namespace_locks.acquire_shared([path])?;
        std::fs::File::create_new(self.resolve(path)?)?;
        match permissions {
            Some(permissions) => self.set_permissions(path, permissions),
            None => self.metadata(path),
        }
    }

    fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()> {
        let _scope = self.namespace_locks.acquire_shared([old_path, new_path])?;
        std::fs::rename(self.resolve(old_path)?, self.resolve(new_path)?)
    }

    fn rename_no_replace(
        &self,
        old_path: &VirtualPath,
        new_path: &VirtualPath,
    ) -> std::io::Result<()> {
        let _scope = self.namespace_locks.acquire_shared([old_path, new_path])?;
        rename_noreplace(&self.resolve(old_path)?, &self.resolve(new_path)?)
    }

    fn rename_multiple(&self, operations: &[RenameOperation]) -> std::io::Result<()> {
        self.rename_multiple_impl(operations)
    }

    fn remove(&self, path: &VirtualPath) -> std::io::Result<()> {
        let _scope = self.namespace_locks.acquire_shared([path])?;
        std::fs::remove_file(self.resolve(path)?)
    }

    fn remove_dir(&self, path: &VirtualPath) -> std::io::Result<()> {
        let _scope = self.namespace_locks.acquire_shared([path])?;
        std::fs::remove_dir(self.resolve(path)?)
    }

    fn remove_multiple(
        &self,
        directories: &[VirtualPathBuf],
        non_directories: &[VirtualPathBuf],
    ) -> std::io::Result<()> {
        if directories.is_empty() && non_directories.is_empty() {
            return Ok(());
        }
        let _scope = self.namespace_locks.acquire_exclusive(
            directories
                .iter()
                .chain(non_directories)
                .map(VirtualPathBuf::as_path),
        )?;

        let mut seen = HashSet::with_capacity(directories.len() + non_directories.len());
        let mut resolved_files = Vec::with_capacity(non_directories.len());
        for path in non_directories {
            if path.is_empty() {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
            let path = self.resolve(path)?;
            if !seen.insert(path.clone()) || std::fs::symlink_metadata(&path)?.is_dir() {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
            resolved_files.push(path);
        }

        let mut resolved_directories = Vec::with_capacity(directories.len());
        for path in directories {
            if path.is_empty() {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
            let path = self.resolve(path)?;
            if !seen.insert(path.clone()) || !std::fs::symlink_metadata(&path)?.is_dir() {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
            resolved_directories.push(path);
        }
        resolved_directories.sort_by_key(|path| Reverse(path.components().count()));

        let temp_root = loop {
            let path = self.root.join(generate_internal_path("remove"));
            match std::fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        };

        let mut staged = Vec::with_capacity(seen.len());
        for (index, original) in resolved_files.into_iter().enumerate() {
            let temporary = temp_root.join(format!("file.{index}"));
            if let Err(error) = rename_noreplace(&original, &temporary) {
                return Err(rollback_removal_error(error, &staged, &temp_root));
            }
            staged.push(StagedRemoval {
                original,
                temporary,
                is_directory: false,
            });
        }
        for (index, original) in resolved_directories.into_iter().enumerate() {
            let temporary = temp_root.join(format!("directory.{index}"));
            if let Err(error) = rename_noreplace(&original, &temporary) {
                return Err(rollback_removal_error(error, &staged, &temp_root));
            }
            staged.push(StagedRemoval {
                original,
                temporary,
                is_directory: true,
            });
        }

        for entry in staged.iter().filter(|entry| entry.is_directory) {
            let result = std::fs::read_dir(&entry.temporary).and_then(|mut entries| {
                entries.next().transpose().and_then(|entry| match entry {
                    None => Ok(()),
                    Some(_) => Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY)),
                })
            });
            if let Err(error) = result {
                return Err(rollback_removal_error(error, &staged, &temp_root));
            }
        }

        let mut cleanup_error = None;
        for entry in &staged {
            let result = if entry.is_directory {
                std::fs::remove_dir(&entry.temporary)
            } else {
                std::fs::remove_file(&entry.temporary)
            };
            if let Err(error) = result {
                cleanup_error.get_or_insert(error);
            }
        }
        if cleanup_error.is_none()
            && let Err(error) = std::fs::remove_dir(&temp_root)
        {
            cleanup_error = Some(error);
        }
        cleanup_error.map_or(Ok(()), Err)
    }

    fn remove_dir_all(&self, path: &VirtualPath) -> std::io::Result<()> {
        if path.is_empty() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY));
        }
        let _scope = self.namespace_locks.acquire_shared([path])?;
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
        let _scope = self.namespace_locks.acquire_shared([path])?;
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
    fn native_fs_set_time_preserves_omitted_timestamp() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
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

    #[test]
    fn native_fs_default_exists_and_truncate() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
        let path = VirtualPath::new("file");

        assert!(!fs.exists(path).unwrap());
        fs.put(path, b"abcdef").unwrap();
        assert!(fs.exists(path).unwrap());

        fs.truncate(path, 3).unwrap();

        assert_eq!(fs.read_all(path).unwrap(), b"abc");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ))]
    #[test]
    fn native_fs_rename_no_replace_preserves_existing_directory() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
        let source = VirtualPath::new("source");
        let destination = VirtualPath::new("destination");

        fs.mkdir(source, None).unwrap();
        fs.put(&source.join("child"), b"source").unwrap();
        fs.mkdir(destination, None).unwrap();
        fs.put(&destination.join("child"), b"destination").unwrap();

        let error = fs.rename_no_replace(source, destination).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs.read_all(&source.join("child")).unwrap(), b"source");
        assert_eq!(
            fs.read_all(&destination.join("child")).unwrap(),
            b"destination"
        );

        fs.remove_dir_all(destination).unwrap();
        fs.rename_no_replace(source, destination).unwrap();
        assert!(!fs.exists(source).unwrap());
        assert_eq!(fs.read_all(&destination.join("child")).unwrap(), b"source");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ))]
    #[test]
    fn native_fs_rename_multiple_replaces_all_destinations() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
        let first_source = VirtualPathBuf::from("first-source");
        let second_source = VirtualPathBuf::from("second-source");
        let first_destination = VirtualPathBuf::from("first-destination");
        let second_destination = VirtualPathBuf::from("second-destination");

        fs.put(&first_source, b"first").unwrap();
        fs.put(&second_source, b"second").unwrap();
        fs.put(&first_destination, b"old-first").unwrap();
        fs.put(&second_destination, b"old-second").unwrap();

        fs.rename_multiple(&[
            RenameOperation::replace(first_source.clone(), first_destination.clone()),
            RenameOperation::replace(second_source.clone(), second_destination.clone()),
        ])
        .unwrap();

        assert!(!fs.exists(&first_source).unwrap());
        assert!(!fs.exists(&second_source).unwrap());
        assert_eq!(fs.read_all(&first_destination).unwrap(), b"first");
        assert_eq!(fs.read_all(&second_destination).unwrap(), b"second");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ))]
    #[test]
    fn native_fs_rename_multiple_honors_each_destination_policy() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
        let first_source = VirtualPathBuf::from("first-source");
        let second_source = VirtualPathBuf::from("second-source");
        let first_destination = VirtualPathBuf::from("first-destination");
        let second_destination = VirtualPathBuf::from("second-destination");
        let third_source = VirtualPathBuf::from("third-source");
        let third_destination = VirtualPathBuf::from("third-destination");

        fs.put(&first_source, b"first").unwrap();
        fs.put(&second_source, b"second").unwrap();
        fs.put(&third_source, b"third").unwrap();
        fs.put(&second_destination, b"existing").unwrap();

        let error = fs
            .rename_multiple(&[
                RenameOperation::no_replace(first_source.clone(), first_destination.clone()),
                RenameOperation::no_replace(second_source.clone(), second_destination.clone()),
            ])
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs.read_all(&first_source).unwrap(), b"first");
        assert_eq!(fs.read_all(&second_source).unwrap(), b"second");
        assert!(!fs.exists(&first_destination).unwrap());
        assert_eq!(fs.read_all(&second_destination).unwrap(), b"existing");

        fs.rename_multiple(&[
            RenameOperation::replace(first_source, first_destination.clone()),
            RenameOperation::ignore_existing(second_source.clone(), second_destination.clone()),
            RenameOperation::ignore_existing(third_source.clone(), third_destination.clone()),
        ])
        .unwrap();

        assert_eq!(fs.read_all(&first_destination).unwrap(), b"first");
        assert!(!fs.exists(&second_source).unwrap());
        assert_eq!(fs.read_all(&second_destination).unwrap(), b"existing");
        assert!(!fs.exists(&third_source).unwrap());
        assert_eq!(fs.read_all(&third_destination).unwrap(), b"third");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ))]
    #[test]
    fn native_fs_rename_multiple_replaces_nonempty_destination_directory() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
        let source = VirtualPathBuf::from("source");
        let destination = VirtualPathBuf::from("destination");

        fs.mkdir(&source, None).unwrap();
        fs.put(&source.join("child"), b"source").unwrap();
        fs.mkdir(&destination, None).unwrap();
        fs.put(&destination.join("child"), b"existing").unwrap();

        fs.rename_multiple(&[RenameOperation::replace(
            source.clone(),
            destination.clone(),
        )])
        .unwrap();

        assert!(!fs.exists(&source).unwrap());
        assert_eq!(fs.read_all(&destination.join("child")).unwrap(), b"source");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ))]
    #[test]
    fn native_fs_rename_multiple_supports_nested_sources_and_destinations() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
        let old = VirtualPathBuf::from("old");
        let new = VirtualPathBuf::from("new");
        let detached_name = VirtualPathBuf::from("detached-name");
        let replacement_name = VirtualPathBuf::from("replacement-name");

        fs.mkdir(&old, None).unwrap();
        fs.put(&old.join("name"), b"old-name").unwrap();
        fs.put(&old.join("contents"), b"contents").unwrap();
        fs.put(&replacement_name, b"new-name").unwrap();

        fs.rename_multiple(&[
            RenameOperation::replace(old.join("name"), detached_name.clone()),
            RenameOperation::replace(old.clone(), new.clone()),
            RenameOperation::replace(replacement_name.clone(), new.join("name")),
        ])
        .unwrap();

        assert!(!fs.exists(&old).unwrap());
        assert!(!fs.exists(&replacement_name).unwrap());
        assert_eq!(fs.read_all(&detached_name).unwrap(), b"old-name");
        assert_eq!(fs.read_all(&new.join("name")).unwrap(), b"new-name");
        assert_eq!(fs.read_all(&new.join("contents")).unwrap(), b"contents");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ))]
    #[test]
    fn native_fs_rename_multiple_handles_a_nested_destination() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
        let old = VirtualPathBuf::from("old");
        let new = VirtualPathBuf::from("new");
        let replacement_name = VirtualPathBuf::from("replacement-name");

        fs.mkdir(&old, None).unwrap();
        fs.put(&old.join("name"), b"old-name").unwrap();
        fs.put(&replacement_name, b"new-name").unwrap();

        let error = fs
            .rename_multiple(&[
                RenameOperation::no_replace(old.clone(), new.clone()),
                RenameOperation::no_replace(replacement_name.clone(), new.join("name")),
            ])
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs.read_all(&old.join("name")).unwrap(), b"old-name");
        assert_eq!(fs.read_all(&replacement_name).unwrap(), b"new-name");
        assert!(!fs.exists(&new).unwrap());

        fs.rename_multiple(&[
            RenameOperation::replace(old.clone(), new.clone()),
            RenameOperation::replace(replacement_name, new.join("name")),
        ])
        .unwrap();

        assert!(!fs.exists(&old).unwrap());
        assert_eq!(fs.read_all(&new.join("name")).unwrap(), b"new-name");

        let ignored_old = VirtualPathBuf::from("ignored-old");
        let ignored_new = VirtualPathBuf::from("ignored-new");
        let ignored_name = VirtualPathBuf::from("ignored-name");
        fs.mkdir(&ignored_old, None).unwrap();
        fs.put(&ignored_old.join("name"), b"kept-name").unwrap();
        fs.put(&ignored_name, b"discarded-name").unwrap();

        fs.rename_multiple(&[
            RenameOperation::replace(ignored_old, ignored_new.clone()),
            RenameOperation::ignore_existing(ignored_name.clone(), ignored_new.join("name")),
        ])
        .unwrap();

        assert!(!fs.exists(&ignored_name).unwrap());
        assert_eq!(
            fs.read_all(&ignored_new.join("name")).unwrap(),
            b"kept-name"
        );
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ))]
    #[test]
    fn native_fs_remove_multiple_removes_the_exact_entry_set() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
        let directory = VirtualPathBuf::from("directory");
        let marker = directory.join("marker");
        let sidecar = VirtualPathBuf::from("sidecar");

        fs.mkdir(&directory, None).unwrap();
        fs.put(&marker, b"marker").unwrap();
        fs.put(&sidecar, b"sidecar").unwrap();

        fs.remove_multiple(
            std::slice::from_ref(&directory),
            &[marker.clone(), sidecar.clone()],
        )
        .unwrap();

        assert!(!fs.exists(&directory).unwrap());
        assert!(!fs.exists(&sidecar).unwrap());
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ))]
    #[test]
    fn native_fs_remove_multiple_restores_entries_when_a_directory_is_not_empty() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
        let directory = VirtualPathBuf::from("directory");
        let marker = directory.join("marker");
        let unexpected = directory.join("unexpected");
        let sidecar = VirtualPathBuf::from("sidecar");

        fs.mkdir(&directory, None).unwrap();
        fs.put(&marker, b"marker").unwrap();
        fs.put(&unexpected, b"unexpected").unwrap();
        fs.put(&sidecar, b"sidecar").unwrap();

        let error = fs
            .remove_multiple(
                std::slice::from_ref(&directory),
                &[marker.clone(), sidecar.clone()],
            )
            .unwrap_err();

        assert_eq!(error.raw_os_error(), Some(libc::ENOTEMPTY));
        assert_eq!(fs.read_all(&marker).unwrap(), b"marker");
        assert_eq!(fs.read_all(&unexpected).unwrap(), b"unexpected");
        assert_eq!(fs.read_all(&sidecar).unwrap(), b"sidecar");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ))]
    #[test]
    fn native_fs_remove_multiple_rejects_missing_entries_before_staging() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
        let existing = VirtualPathBuf::from("existing");
        let missing = VirtualPathBuf::from("missing");

        fs.put(&existing, b"contents").unwrap();

        let error = fs
            .remove_multiple(&[], &[existing.clone(), missing])
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(fs.read_all(&existing).unwrap(), b"contents");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ))]
    #[test]
    fn native_fs_remove_multiple_orders_nested_directories() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
        let parent = VirtualPathBuf::from("parent");
        let child = parent.join("child");
        let marker = child.join("marker");

        fs.mkdir(&parent, None).unwrap();
        fs.mkdir(&child, None).unwrap();
        fs.put(&marker, b"marker").unwrap();

        fs.remove_multiple(&[parent.clone(), child], &[marker])
            .unwrap();

        assert!(!fs.exists(&parent).unwrap());
    }

    #[test]
    fn native_fs_hides_and_rejects_internal_temporary_paths() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let temp_name = format!("{INTERNAL_TEMP_PREFIX}test");
        std::fs::create_dir(root.join(&temp_name)).unwrap();
        let fs = NativeFileSystem::new(root);

        let entries = fs
            .read_dir(VirtualPath::root())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        let error = match fs.metadata(VirtualPath::new(&temp_name)) {
            Ok(_) => panic!("internal temporary path was accessible"),
            Err(error) => error,
        };

        assert!(entries.is_empty());
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn native_fs_set_time_does_not_follow_symlinks() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
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
    fn native_fs_keeps_symlink_targets_opaque() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();
        let fs = NativeFileSystem::new(root);
        let target = "/opaque/../target";

        fs.create_symlink(VirtualPath::new("link"), target).unwrap();

        assert_eq!(fs.read_symlink(VirtualPath::new("link")).unwrap(), target);
    }
}
