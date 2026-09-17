use super::{
    EncryptionLayout, EncryptionTranslator, EntryStorage, FileType, FsDirEntry, Metadata,
    OrIoError, Permissions, StorageDirEntry, VirtualPath, VirtualPathBuf,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::Digest;
use std::time::SystemTime;

pub(super) fn default_metadata<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
    let metadata = this.entry_storage().metadata(&cipher_path)?;
    storage_metadata_to_plain(this, metadata)
}

/// Converts represented metadata to the logical encrypted-filesystem view.
pub(crate) fn storage_metadata_to_plain<T: EncryptionTranslator + ?Sized>(
    this: &T,
    mut metadata: Metadata,
) -> std::io::Result<Metadata> {
    if metadata.file_type == FileType::File {
        metadata.len = this.cipher_size_to_plain(metadata.len).or_invalid()?;
        metadata.blocks = 1 + metadata.len / T::PLAIN_BLOCK_LEN;
    } else if metadata.file_type == FileType::SymLink {
        metadata.permissions = 0o777_u16.into();
    }
    Ok(metadata)
}

/// Decrypts one represented directory entry and converts its metadata.
fn storage_dir_entry_to_plain<T: EncryptionTranslator + ?Sized>(
    this: &T,
    parent_token: &[u8],
    entry: StorageDirEntry,
) -> std::io::Result<(FsDirEntry, VirtualPathBuf)> {
    let plain_name = this
        .cipher_name_to_plain(parent_token, &entry.file_name)
        .or_invalid()?;
    let metadata = storage_metadata_to_plain(this, entry.metadata)?;
    Ok((
        FsDirEntry {
            file_name: plain_name,
            metadata,
        },
        entry.path,
    ))
}

/// Lists and decrypts the children of one logical directory.
pub(super) fn default_list_dir_plain_names<'a, T: EncryptionLayout + ?Sized>(
    this: &'a T,
    plain_path: &VirtualPath,
) -> std::io::Result<impl Iterator<Item = std::io::Result<(FsDirEntry, VirtualPathBuf)>> + 'a> {
    let entry_path = if plain_path.is_empty() {
        VirtualPathBuf::default()
    } else {
        this.plain_path_to_cipher(plain_path).or_invalid()?
    };
    let directory = this.entry_storage().resolve_directory(&entry_path)?;
    let token = directory.token;

    Ok(this
        .entry_storage()
        .read_dir(directory.contents_path)?
        .map(move |entry| storage_dir_entry_to_plain(this, &token, entry?)))
}

pub(super) fn default_mknode<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    permissions: Option<Permissions>,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
    let initial_contents = if T::EMPTY_FILE_HAS_HEADER {
        this.generate_cipher_header().or_invalid()?
    } else {
        Vec::new()
    };
    let metadata =
        this.entry_storage()
            .create_file(&cipher_path, &initial_contents, permissions)?;
    storage_metadata_to_plain(this, metadata)
}

pub(super) fn default_mkdir<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    permissions: Option<Permissions>,
) -> std::io::Result<Metadata> {
    let entry_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
    let token = this.entry_storage().generate_directory_token();
    let metadata = this
        .entry_storage()
        .create_directory(entry_path, token, permissions)?;
    storage_metadata_to_plain(this, metadata)
}

pub(super) fn default_remove<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<()> {
    let cipher_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
    this.entry_storage().remove_entry(&cipher_path)
}

pub(super) fn default_remove_dir<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<()> {
    let entry_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
    let directory = this.entry_storage().resolve_directory(&entry_path)?;
    this.entry_storage().remove_directory(&directory)?;
    this.remove_cached_plain_path(plain_path);
    Ok(())
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
    let metadata = this
        .entry_storage()
        .create_symlink(&cipher_path, &cipher_target)?;
    storage_metadata_to_plain(this, metadata)
}
pub(super) fn default_read_symlink<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<String> {
    let cipher_path = this.plain_path_to_cipher(plain_path).or_invalid()?;
    let cipher_target = this.entry_storage().read_symlink(&cipher_path)?;
    let plain_value = this
        .cipher_metavalue_to_plain(&cipher_target)
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
    this.entry_storage()
        .rename(&old_cipher_path, &new_cipher_path)?;
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
    let metadata = this.entry_storage().set_permissions(&path, permissions)?;
    storage_metadata_to_plain(this, metadata)
}
/// Sets access and modification times.
pub(super) fn default_set_time<T: EncryptionLayout + ?Sized>(
    this: &T,
    path: &VirtualPath,
    atime: Option<SystemTime>,
    mtime: Option<SystemTime>,
) -> std::io::Result<()> {
    let path = this.plain_path_to_cipher(path).or_invalid()?;
    this.entry_storage().set_time(&path, atime, mtime)
}

pub(crate) fn temp_file_path(path: &str, is_dir_iv: bool) -> VirtualPathBuf {
    // Temporary names are deterministic on purpose. This assumes a single
    // rcryptfs process owns a backend at a time; concurrent multi-process
    // access to the same encrypted root is undefined behavior.
    let path_digest = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(path.as_bytes()).as_slice());
    let mut new_name = String::from("temp.");
    new_name.push_str(&path_digest);

    if is_dir_iv {
        new_name.push_str(".diriv");
    }
    new_name.into()
}
