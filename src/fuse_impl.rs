use super::{FileType, Metadata, ReadOnlyFileSystem};
use crate::{
    ErrorMapper, FileSystem, FileSystemHandler, GenericOpenOptions, IoErrorToLib, OpenCache,
};
use fuse_mt::{FileAttr, FilesystemMT};
use log::debug;
use std::{ffi::OsString, path::Path, time::Duration};

impl TryFrom<FileType> for fuse_mt::FileType {
    type Error = i32;
    fn try_from(value: FileType) -> Result<Self, i32> {
        match value {
            FileType::File => Ok(fuse_mt::FileType::RegularFile),
            FileType::Directory => Ok(fuse_mt::FileType::Directory),
            FileType::SymLink => Ok(fuse_mt::FileType::Symlink),
            _ => Err(libc::ENOENT),
        }
    }
}

impl TryFrom<Metadata> for fuse_mt::FileAttr {
    type Error = i32;
    fn try_from(value: Metadata) -> Result<Self, i32> {
        Ok(Self {
            size: value.len,
            // Report allocation with the crypto block granularity used internally.
            blocks: 1 + value.len / 4096,
            atime: value.accessed,
            mtime: value.modified,
            ctime: value.created,
            crtime: value.created,
            kind: value.file_type.try_into()?,
            perm: value.permissions.into(),
            nlink: 1,
            uid: value.uid.unwrap_or_default(),
            gid: value.gid.unwrap_or_default(),
            rdev: 0,
            flags: 0,
        })
    }
}

const TTL: Duration = Duration::from_secs(10);

/// Decodes POSIX open flags into higher-level access checks.
trait HasFlag {
    fn is_ro(&self) -> bool;
    fn is_rw(&self) -> bool;
    fn is_wo(&self) -> bool;
    fn has_read(&self) -> bool;
    fn has_write(&self) -> bool;
    fn has(&self, flag: libc::c_int) -> bool;
}

impl HasFlag for u32 {
    fn is_ro(&self) -> bool {
        self & 0b11 == libc::O_RDONLY as u32
    }
    fn is_rw(&self) -> bool {
        self & 0b11 == libc::O_RDWR as u32
    }
    fn is_wo(&self) -> bool {
        self & 0b11 == libc::O_WRONLY as u32
    }
    fn has_read(&self) -> bool {
        self.is_ro() || self.is_rw()
    }
    fn has_write(&self) -> bool {
        self.is_wo() || self.is_rw()
    }
    fn has(&self, flag: libc::c_int) -> bool {
        if flag == 0 {
            return *self == 0;
        }
        let flag_u32 = match u32::try_from(flag) {
            Ok(v) => v,
            Err(_) => return false,
        };
        self & flag_u32 == flag_u32
    }
}

/// Opens a file through the filesystem backend and stores it in the open-file cache.
fn open<T: FileSystem + ?Sized, C: OpenCache>(
    backend: &T,
    cache: &C,
    path: &Path,
    flags: u32,
    mode: Option<u32>,
) -> Result<u64, libc::c_int> {
    let path = path.sanitize()?;

    let create_new = flags.has(libc::O_EXCL);
    let create = flags.has(libc::O_CREAT);
    let truncate = flags.has(libc::O_TRUNC);
    let append = flags.has(libc::O_APPEND);
    let read = flags.has_read();
    let write = flags.has_write();

    let mut options = GenericOpenOptions::default();
    options
        .read(read)
        .write(write)
        .create(create)
        .create_new(create_new)
        .truncate(truncate)
        .append(append);
    if let Some(mode) = mode {
        options.permissions(mode.into());
    }

    debug!("open options are {:?}", &options);

    let file = if options.is_readonly() {
        backend.open_readonly(path).libc_err()?
    } else {
        backend.open_file_with(path, options).libc_err()?
    };
    Ok(cache.insert(file))
}

impl<C: OpenCache + 'static> FilesystemMT for FileSystemHandler<C> {
    fn init(
        &self,
        req: fuse_mt::RequestInfo,
        //config: &mut fuse_mt::KernelConfig,
    ) -> fuse_mt::ResultEmpty {
        debug!(
            "trying to init! unique {} uid {} gid {} pid {}",
            req.unique, req.uid, req.gid, req.pid
        );
        // let _ = config.add_capabilities(fuse_mt::consts::FUSE_WRITEBACK_CACHE);

        Ok(())
    }
    fn opendir(&self, _req: fuse_mt::RequestInfo, path: &Path, flags: u32) -> fuse_mt::ResultOpen {
        debug!("opendir on path {:?} with flags {flags}", path);
        Ok((0, 0))
    }
    fn releasedir(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        fh: u64,
        flags: u32,
    ) -> fuse_mt::ResultEmpty {
        debug!(
            "releasedir on path {:?} with fh {fh} and flags {flags}",
            path
        );
        Ok(())
    }
    fn mknod(
        &self,
        _req: fuse_mt::RequestInfo,
        parent: &Path,
        name: &std::ffi::OsStr,
        mode: u32,
        _rdev: u32,
    ) -> fuse_mt::ResultEntry {
        let path = parent.join(name);
        debug!("mknod on {:?}", path);
        let path = path.sanitize()?;
        Ok((
            TTL,
            self.as_ref()
                .mknode(path, mode.into())
                .libc_err()?
                .try_into()?,
        ))
    }
    fn mkdir(
        &self,
        _req: fuse_mt::RequestInfo,
        parent: &Path,
        name: &std::ffi::OsStr,
        mode: u32,
    ) -> fuse_mt::ResultEntry {
        let path = parent.join(name);
        debug!("mkdir on {:?}", path);
        let path = path.sanitize()?;
        Ok((
            TTL,
            self.as_ref()
                .mkdir(path, mode.into())
                .libc_err()?
                .try_into()?,
        ))
    }
    fn rename(
        &self,
        _req: fuse_mt::RequestInfo,
        parent: &Path,
        name: &std::ffi::OsStr,
        newparent: &Path,
        newname: &std::ffi::OsStr,
    ) -> fuse_mt::ResultEmpty {
        debug!(
            "rename on path {:?} {:?} {:?} {:?}",
            parent, name, newparent, newname
        );
        let path = parent.join(name);
        let path = path.sanitize()?;
        let new_path = newparent.join(newname);
        let new_path = new_path.sanitize()?;
        self.as_ref().rename(path, new_path).libc_err()
    }
    fn create(
        &self,
        req: fuse_mt::RequestInfo,
        parent: &Path,
        name: &std::ffi::OsStr,
        mode: u32,
        flags: u32,
    ) -> fuse_mt::ResultCreate {
        let path = parent.join(name);
        debug!("create on path {:?} with flags {flags}", path);
        let fh = open(self.as_ref(), self.as_cache(), &path, flags, Some(mode))?;
        debug!("got fh {fh}");
        let attr = self.getattr(req, &path, None)?.1;

        debug!("got create attr {:?}", attr);

        Ok(fuse_mt::CreatedEntry {
            ttl: TTL,
            attr,
            fh,
            flags: 0,
        })
    }
    fn chmod(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        _fh: Option<u64>,
        mode: u32,
    ) -> fuse_mt::ResultEmpty {
        debug!("chmod on {:?} {:0o}", path, mode);
        let path = path.sanitize()?;
        self.as_ref()
            .set_permissions(path, mode.into())
            .libc_err()
            .map(|_| {})
    }
    fn symlink(
        &self,
        req: fuse_mt::RequestInfo,
        parent: &Path,
        name: &std::ffi::OsStr,
        target: &Path,
    ) -> fuse_mt::ResultEntry {
        let path = parent.join(name);
        debug!("symlink on path {:?} with target {:?}", path, target);
        let path = path.sanitize()?;
        let mut attr: FileAttr = self
            .as_ref()
            .create_symlink(path, target.to_str().or_libc_invalid()?)
            .libc_err()?
            .try_into()?;
        attr.gid = req.gid;
        attr.uid = req.uid;
        Ok((TTL, attr))
    }
    fn readlink(&self, _req: fuse_mt::RequestInfo, path: &Path) -> fuse_mt::ResultData {
        debug!("readlink on path {:?}", path);
        let path = path.sanitize()?;
        self.as_ref()
            .read_symlink(path)
            .map(|s| s.into())
            .libc_err()
    }
    fn chown(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        fh: Option<u64>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> fuse_mt::ResultEmpty {
        debug!("chown on {:?} {:?} {:?} {:?}", path, fh, uid, gid);
        let path = path.sanitize()?;
        self.as_ref().chown(path, uid, gid).libc_err()?;
        Ok(())
    }
    fn utimens(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        fh: Option<u64>,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> fuse_mt::ResultEmpty {
        log::debug!("utimens on {:?} {:?} {:?} {:?}", path, fh, atime, mtime);
        let path = path.sanitize()?;
        if atime.is_none() && mtime.is_none() {
            log::error!("error in utimens on {:?} {:?} {:?}", path, atime, mtime);
            Err(libc::EINVAL)?
        }
        //if let Some(fh) = fh {
        //log::error!("flushing file {fh} before utimens");
        //self.as_cache().access(fh, |file| file.flush()).libc_err()?;
        //}
        self.as_ref().set_time(path, atime, mtime).libc_err()
    }

    fn open(&self, _req: fuse_mt::RequestInfo, path: &Path, flags: u32) -> fuse_mt::ResultOpen {
        debug!("open on path {:?} with flags {flags}", path);
        if flags.has(libc::O_DIRECT) {
            log::error!("open on path {:?} with flags {flags}", path);
        }
        let fh = open(self.as_ref(), self.as_cache(), path, flags, None)?;
        Ok((fh, 0))
    }
    fn read(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        fh: u64,
        offset: u64,
        size: u32,
        callback: impl FnOnce(fuse_mt::ResultSlice<'_>) -> fuse_mt::CallbackResult,
    ) -> fuse_mt::CallbackResult {
        read(self.as_cache(), path, fh, offset, size, callback)
    }
    fn write(
        &self,
        _req: fuse_mt::RequestInfo,
        _path: &Path,
        fh: u64,
        offset: u64,
        data: Vec<u8>,
        _flags: u32,
    ) -> fuse_mt::ResultWrite {
        //log::error!("writing to {:?} at {offset} len {}", _path, data.len());
        self.as_cache()
            .access(fh, |file| {
                file.write_all_at(offset, &data).map(|_| data.len() as u32)
            })
            .libc_err()
    }
    fn rmdir(
        &self,
        _req: fuse_mt::RequestInfo,
        parent: &Path,
        name: &std::ffi::OsStr,
    ) -> fuse_mt::ResultEmpty {
        let path = parent.join(name);
        debug!("rmdir on {:?}", path);
        let path = path.sanitize()?;
        self.as_ref().remove_dir(path).libc_err()
    }
    fn unlink(
        &self,
        _req: fuse_mt::RequestInfo,
        parent: &Path,
        name: &std::ffi::OsStr,
    ) -> fuse_mt::ResultEmpty {
        let path = parent.join(name);
        debug!("unlink on {:?}", path);
        let path = path.sanitize()?;
        self.as_ref().remove(path).libc_err()
    }
    fn release(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        fh: u64,
        flags: u32,
        lock_owner: u64,
        flush: bool,
    ) -> fuse_mt::ResultEmpty {
        log::debug!(
            "release on path {:?} with fh {fh} flags {flags} lock_owner {lock_owner} flush {flush}",
            path
        );
        if flush {
            let _ = self.as_cache().access(fh, |f| f.flush());
        }

        self.as_cache().release(fh).libc_err()?;

        Ok(())
    }
    fn fsync(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        fh: u64,
        datasync: bool,
    ) -> fuse_mt::ResultEmpty {
        log::debug!("sync on path {:?} with fh {fh} datasync {datasync}", path);

        self.as_cache()
            .access(fh, |file| file.sync(datasync))
            .libc_err()
    }
    fn flush(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        fh: u64,
        _lock_owner: u64,
    ) -> fuse_mt::ResultEmpty {
        log::debug!("flush on path {:?} with fh {fh}", path);
        let _ = self.as_cache().access(fh, |file| file.flush());
        Ok(())
    }
    fn truncate(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        fh: Option<u64>,
        size: u64,
    ) -> fuse_mt::ResultEmpty {
        log::debug!("truncate on path {:?} with fh {:?} size {size}", path, fh);
        if let Some(fh) = fh {
            self.as_cache()
                .access(fh, |file| file.set_len(size))
                .libc_err()
        } else {
            self.as_ref().truncate(path.sanitize()?, size).libc_err()
        }
    }
    fn getxattr(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        name: &std::ffi::OsStr,
        size: u32,
    ) -> fuse_mt::ResultXattr {
        debug!("getxattr on path {:?} name: {:?} size: {size}", path, name);
        let path = path.sanitize()?;
        let value = self
            .as_ref()
            .get_xattr(path, name.to_str().or_libc_invalid()?)
            .libc_err();
        if size == 0 {
            value.map(|s| fuse_mt::Xattr::Size(s.len() as u32))
        } else {
            value.map(fuse_mt::Xattr::Data)
        }
    }
    fn listxattr(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        size: u32,
    ) -> fuse_mt::ResultXattr {
        debug!("listxattr on path {:?} size: {size}", path);
        let path = path.sanitize()?;
        let mut names = vec![];
        for name in self.as_ref().list_xattr(path).or_libc_invalid()? {
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
        if size == 0 {
            Ok(fuse_mt::Xattr::Size(names.len() as u32))
        } else {
            Ok(fuse_mt::Xattr::Data(names))
        }
    }
    fn removexattr(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        name: &std::ffi::OsStr,
    ) -> fuse_mt::ResultEmpty {
        debug!("remove xattr on path {:?} name: {:?}", path, name);
        let path = path.sanitize()?;
        self.as_ref()
            .remove_xattr(path, name.to_str().or_libc_invalid()?)
            .libc_err()
    }
    fn setxattr(
        &self,
        _req: fuse_mt::RequestInfo,
        path: &Path,
        name: &std::ffi::OsStr,
        value: &[u8],
        _flags: u32,
        _position: u32,
    ) -> fuse_mt::ResultEmpty {
        debug!(
            "setxattr on path {:?} name: {:?} value: {}",
            path,
            name,
            String::from_utf8_lossy(value)
        );
        let path = path.sanitize()?;
        self.as_ref()
            .set_xattr(path, name.to_str().or_libc_invalid()?, value)
            .libc_err()
    }

    fn readdir(&self, _req: fuse_mt::RequestInfo, path: &Path, _fh: u64) -> fuse_mt::ResultReaddir {
        readdir(self, path)
    }
    fn getattr(
        &self,
        req: fuse_mt::RequestInfo,
        path: &Path,
        _fh: Option<u64>,
    ) -> fuse_mt::ResultEntry {
        getattr(self, req, path)
    }
    fn access(&self, _req: fuse_mt::RequestInfo, path: &Path, mask: u32) -> fuse_mt::ResultEmpty {
        access(self, path, mask)
    }
}

fn readdir<T: ReadOnlyFileSystem + ?Sized>(
    fs: impl AsRef<T>,
    path: &Path,
) -> fuse_mt::ResultReaddir {
    debug!("readdir on path {:?}", path);
    let path = path.sanitize()?;

    let common_paths = [
        fuse_mt::DirectoryEntry {
            name: ".".into(),
            kind: fuse_mt::FileType::Directory,
        },
        fuse_mt::DirectoryEntry {
            name: "..".into(),
            kind: fuse_mt::FileType::Directory,
        },
    ];

    let result = common_paths
        .into_iter()
        .chain(fs.as_ref().read_dir(path).libc_err()?.filter_map(|entry| {
            let name: OsString = entry.file_name.into();
            let kind = match entry.file_type? {
                FileType::File => Some(fuse_mt::FileType::RegularFile),
                FileType::Directory => Some(fuse_mt::FileType::Directory),
                FileType::SymLink => Some(fuse_mt::FileType::Symlink),
                _ => None, // ignore anything that isnt a regular file or a directory
            };
            Some(fuse_mt::DirectoryEntry { name, kind: kind? })
        }))
        .collect();
    debug!("readdir ok for path {:?}", path);
    Ok(result)
}

fn getattr<T: ReadOnlyFileSystem + ?Sized>(
    fs: impl AsRef<T>,
    _req: fuse_mt::RequestInfo,
    path: &Path,
) -> fuse_mt::ResultEntry {
    debug!("gettatr on path {:?}", path);
    let path = path.sanitize()?;
    let attr: (_, FileAttr) = fs
        .as_ref()
        .metadata(path)
        .libc_err()
        .inspect(|m| {
            debug!("metadata ok for path {:?} {m}", path);
        })
        .inspect_err(|e| {
            debug!("get attr not found! {e}");
        })
        .and_then(|data| Ok((TTL, data.try_into()?)))?;
    Ok(attr)
}

fn access<T: ReadOnlyFileSystem + ?Sized>(
    fs: impl AsRef<T>,
    path: &Path,
    mask: u32,
) -> fuse_mt::ResultEmpty {
    debug!("access on {:?} with mask {mask}", path);
    let path = path.sanitize()?;
    let _ = fs.as_ref().metadata(path).libc_err()?;
    debug!("access ok for path {:?}", path);
    Ok(())
}

fn read<C: OpenCache + 'static>(
    cache: &C,
    path: &Path,
    fh: u64,
    offset: u64,
    size: u32,
    callback: impl FnOnce(fuse_mt::ResultSlice<'_>) -> fuse_mt::CallbackResult,
) -> fuse_mt::CallbackResult {
    debug!(
        "read on path {:?} with fh {fh} at offset {offset} for size {size}",
        path
    );

    let mut buffer = vec![0; size as usize];

    if let Ok(bytes_read) = cache.access(fh, |file| file.read_at(offset, &mut buffer)) {
        debug!("read ok with len {bytes_read}");
        callback(Ok(&buffer[0..bytes_read]))
    } else {
        debug!("read ko!");
        callback(Err(libc::EBADFD))
    }
}

trait Sanitize {
    fn sanitize(&self) -> Result<&str, i32>;
}

impl Sanitize for Path {
    fn sanitize(&self) -> Result<&str, i32> {
        self.strip_prefix("/")
            .or_libc_invalid()?
            .to_str()
            .or_libc_invalid()
    }
}
