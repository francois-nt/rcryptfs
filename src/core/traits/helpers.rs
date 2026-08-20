use super::super::FileType;
use super::{EncryptionLayout, MinimalFs, OrIoError};
use super::{Metadata, Permissions, VirtualPath, Utf8Path, Utf8PathBuf};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::Digest;
use std::time::SystemTime;

pub(super) fn default_metadata<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
    let mut res: Metadata = this.lower_fs().metadata(&cipher_path)?;
    if res.file_type == FileType::File {
        res.len = this.cipher_size_to_plain(res.len).or_invalid()?;
    }
    Ok(res)
}

pub(super) fn default_mknode<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    permissions: Permissions,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
    this.lower_fs().mknode(&cipher_path)?;
    this.lower_fs().set_permissions(&cipher_path, permissions)
}

pub(super) fn default_mkdir<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    permissions: Permissions,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
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
    plain_path: &VirtualPath,
) -> std::io::Result<()> {
    let cipher_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
    this.lower_fs().remove_file(&cipher_path)
}

pub(super) fn default_remove_dir<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<()> {
    let cipher_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
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
    plain_path: &VirtualPath,
    target: &str,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
    let cipher_target = this
        .plain_metavalue_to_cipher(target.as_bytes())
        .or_invalid()?;
    let cipher_target = str::from_utf8(&cipher_target).or_invalid()?;

    this.lower_fs()
        .create_symlink(cipher_path.as_str(), cipher_target)
}
pub(super) fn default_read_symlink<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<String> {
    let cipher_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
    let cipher_target = this.lower_fs().read_symlink(cipher_path.as_str())?;
    let plain_value = this
        .cipher_metavalue_to_plain(cipher_target.as_str().as_bytes())
        .or_invalid()?;

    String::from_utf8(plain_value).or_invalid()
}

pub(super) fn default_rename<T: EncryptionLayout + ?Sized>(
    this: &T,
    old_path: &VirtualPath,
    new_path: &VirtualPath,
) -> std::io::Result<()> {
    let old_cipher_path = this.plain_path_to_cipher(old_path).or_invalid()?;
    let new_cipher_path = this.plain_path_to_cipher(new_path).or_invalid()?;
    this.lower_fs().rename(&old_cipher_path, &new_cipher_path)?;
    this.remove_cached_plain_path(old_path);
    this.remove_cached_plain_path(new_path);
    Ok(())
}

pub(super) fn default_set_permissions<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    permissions: Permissions,
) -> std::io::Result<Metadata> {
    let path = this.plain_path_to_cipher(plain_path).or_invalid()?;
    let metadata = this.lower_fs().set_permissions(&path, permissions)?;

    Ok(metadata)
}
/// Sets access and modification times.
pub(super) fn default_set_time<T: EncryptionLayout + ?Sized>(
    this: &T,
    path: &VirtualPath,
    atime: Option<SystemTime>,
    mtime: Option<SystemTime>,
) -> std::io::Result<()> {
    let path = this.plain_path_to_cipher(path).or_invalid()?;
    this.lower_fs().set_time(&path, atime, mtime)
}

pub(crate) fn temp_file_path(root: &Utf8Path, path: &str, is_dir_iv: bool) -> Utf8PathBuf {
    // Temporary names are deterministic on purpose. This assumes a single
    // rcryptfs process owns a backend at a time; concurrent multi-process
    // access to the same encrypted root is undefined behavior.
    let path_digest = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(path.as_bytes()).as_slice());
    let mut new_name = String::from("temp.");
    new_name.push_str(&path_digest);

    let mut result = root.join(new_name);
    if is_dir_iv {
        result.add_extension("diriv");
    }
    result
}
