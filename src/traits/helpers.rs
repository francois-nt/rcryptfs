use std::time::SystemTime;

use filetime::set_symlink_file_times;

use super::{EncryptionLayout, MinimalFs, OrIoError};
use crate::{FileType, Metadata, Permissions, Utf8Path};

pub(super) fn default_metadata<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &str,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path.into()).or_invalid()?;
    let mut res: Metadata = this.lower_fs().metadata(&cipher_path)?;
    if res.file_type == FileType::File {
        res.len = this.cipher_size_to_plain(res.len).or_invalid()?;
    }
    Ok(res)
}

pub(super) fn default_mknode<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &str,
    permissions: Permissions,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path.into()).or_invalid()?;
    this.lower_fs().mknode(&cipher_path)?;
    this.lower_fs().set_permissions(&cipher_path, permissions)
}

pub(super) fn default_mkdir<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &str,
    permissions: Permissions,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path.into()).or_invalid()?;
    let temp_path = this.create_temp_name(cipher_path.as_str(), false);
    let dir_iv_path = this.get_dir_iv_file(&temp_path);

    let iv = this.generate_diriv();

    // Create into a temporary location first so the directory and diriv appear atomically.
    create_diriv(this.lower_fs(), &temp_path, &dir_iv_path, &iv)?;
    this.lower_fs().rename(&temp_path, &cipher_path)?;
    this.lower_fs().set_permissions(&cipher_path, permissions)
}

/// Creates a directory with an initialization vector file.
fn create_diriv(
    sub_fs: &impl MinimalFs,
    path: impl AsRef<Utf8Path>,
    diriv_path: impl AsRef<Utf8Path>,
    iv: &[u8],
) -> std::io::Result<()> {
    // Temporary paths are owned exclusively by the current process. Reusing the
    // same backend concurrently from multiple rcryptfs processes is undefined behavior.
    if sub_fs.exists(path.as_ref())? {
        sub_fs.remove_dir(path.as_ref(), true)?;
    }
    sub_fs.mkdir(path.as_ref())?;
    sub_fs.put(diriv_path.as_ref(), iv)
}

pub(super) fn default_remove<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &str,
) -> std::io::Result<()> {
    let cipher_path = this.plain_path_to_cipher(plain_path.into()).or_invalid()?;
    this.lower_fs().remove_file(&cipher_path)
}

pub(super) fn default_remove_dir<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &str,
) -> std::io::Result<()> {
    let cipher_path = this.plain_path_to_cipher(plain_path.into()).or_invalid()?;
    let iv_path = this.get_dir_iv_file(&cipher_path);
    let temp_path = this.create_temp_name(iv_path.as_str(), true);

    // Move the diriv out of the way first so a failed rmdir can be rolled back cleanly.
    this.lower_fs()
        .rename(&iv_path, &temp_path)
        .inspect_err(|e| log::error!("cant rename {iv_path} to {temp_path} - {e}"))?;
    if let Err(e) = this.lower_fs().remove_dir(&cipher_path, false) {
        log::debug!("rmdir error {e} {:?}", e.raw_os_error());
        this.lower_fs()
            .rename(&temp_path, &iv_path)
            .inspect_err(|e| log::error!("cant rename back {temp_path} to {iv_path} - {e}"))?;
        Err(e)
    } else {
        let _ = this.lower_fs().remove_file(&temp_path);
        this.remove_cached_plain_path(plain_path);
        Ok(())
    }
}
pub(super) fn default_create_symlink<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &str,
    target: &str,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path.into()).or_invalid()?;
    let cipher_target = this
        .plain_metavalue_to_cipher(target.as_bytes())
        .or_invalid()?;

    this.lower_fs()
        .create_symlink(cipher_path.as_str(), &cipher_target)
}
pub(super) fn default_read_symlink<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &str,
) -> std::io::Result<String> {
    let cipher_path = this.plain_path_to_cipher(plain_path.into()).or_invalid()?;
    let cipher_target = this.lower_fs().read_symlink(cipher_path.as_str())?;
    let plain_value = this
        .cipher_metavalue_to_plain(cipher_target.as_str())
        .or_invalid()?;

    String::from_utf8(plain_value).or_invalid()
}

pub(super) fn default_rename<T: EncryptionLayout + ?Sized>(
    this: &T,
    old_path: &str,
    new_path: &str,
) -> std::io::Result<()> {
    let old_cipher_path = this.plain_path_to_cipher(old_path.into()).or_invalid()?;
    let new_cipher_path = this.plain_path_to_cipher(new_path.into()).or_invalid()?;
    this.lower_fs().rename(&old_cipher_path, &new_cipher_path)?;
    this.remove_cached_plain_path(old_path);
    this.remove_cached_plain_path(new_path);
    Ok(())
}

pub(super) fn default_set_permissions<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &str,
    permissions: Permissions,
) -> std::io::Result<Metadata> {
    let path = this.plain_path_to_cipher(plain_path.into()).or_invalid()?;
    let metadata = this.lower_fs().set_permissions(&path, permissions)?;

    Ok(metadata)
}
/// Sets access and modification times.
pub(super) fn default_set_time<T: EncryptionLayout + ?Sized>(
    this: &T,
    path: &str,
    atime: Option<SystemTime>,
    mtime: Option<SystemTime>,
) -> std::io::Result<()> {
    let path = this.plain_path_to_cipher(path.into()).or_invalid()?;
    if atime.is_none() && mtime.is_none() {
        return Ok(());
    }
    if let Some((atime, mtime)) = atime.zip(mtime) {
        set_symlink_file_times(path, atime.into(), mtime.into())
    } else {
        let meta = this.lower_fs().metadata(&path)?;
        let atime = atime.unwrap_or(meta.accessed);
        let mtime = mtime.unwrap_or(meta.modified);
        set_symlink_file_times(path, atime.into(), mtime.into())
    }
}
