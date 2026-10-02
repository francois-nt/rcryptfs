use super::{
    DirectoryLayout, EncryptionLayout, EncryptionTranslator, EntryStorage, FileOpenOptions,
    FileType, FsDirEntry, Metadata, OrIoError, Permissions, ResolvedStoragePathBuf,
    RootDirectoryToken, StorageDirEntry, StorageFileSystem, VirtualPath, VirtualPathBuf,
    is_stale_identity,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::Digest;
use std::time::SystemTime;

/// Resolves a raw storage path by validating every existing ancestor from the root.
pub(crate) fn resolve_storage_path<F: StorageFileSystem + ?Sized>(
    storage: &F,
    path: &VirtualPath,
) -> std::io::Result<ResolvedStoragePathBuf> {
    let mut parent_id = storage.get_root_id()?;
    let mut current = VirtualPathBuf::default();
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        current.push(component);
        let folder = ResolvedStoragePathBuf::new(current.clone(), parent_id);
        parent_id = storage.get_folder_id(folder.as_resolved_path())?;
    }
    Ok(ResolvedStoragePathBuf::new(path.to_owned(), parent_id))
}

pub(super) fn default_metadata<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path)?;
    let metadata = this
        .entry_storage()
        .metadata(cipher_path.as_resolved_path())?;
    storage_metadata_to_plain(this, metadata)
}

/// Opens the represented cipher file for one plain path.
pub(super) fn default_open_file_with<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    mut options: FileOpenOptions,
) -> std::io::Result<<T::EntryStorage as EntryStorage>::OpenHandle> {
    if options.append {
        options.write = true;
    }
    options.read(true).append(false);
    let cipher_path = this.plain_path_to_cipher(plain_path)?;
    this.entry_storage()
        .open_file_with(cipher_path.as_resolved_path(), options)
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
pub(super) fn storage_dir_entry_to_plain<T: EncryptionTranslator + ?Sized>(
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
    let plain_path = plain_path.to_owned();
    let mut retried = false;
    let mut entries = match list_dir_plain_names_once(this, &plain_path) {
        Err(error) if is_stale_identity(&error) => {
            this.path_cache().invalidate(VirtualPath::root());
            retried = true;
            match list_dir_plain_names_once(this, &plain_path) {
                Err(error) if is_stale_identity(&error) => {
                    this.path_cache().invalidate(VirtualPath::root());
                    return Err(error);
                }
                result => result?,
            }
        }
        result => result?,
    };
    let mut emitted = false;
    let mut stopped = false;
    Ok(std::iter::from_fn(move || {
        if stopped {
            return None;
        }
        loop {
            match entries.next() {
                Some(Err(error)) if is_stale_identity(&error) => {
                    this.path_cache().invalidate(VirtualPath::root());
                    if retried || emitted {
                        stopped = true;
                        return Some(Err(error));
                    }
                    retried = true;
                    match list_dir_plain_names_once(this, &plain_path) {
                        Ok(retry) => entries = retry,
                        Err(error) => {
                            if is_stale_identity(&error) {
                                this.path_cache().invalidate(VirtualPath::root());
                            }
                            stopped = true;
                            return Some(Err(error));
                        }
                    }
                }
                item => {
                    emitted |= item.is_some();
                    return item;
                }
            }
        }
    }))
}

/// Builds one synchronous directory-listing attempt.
fn list_dir_plain_names_once<'a, T: EncryptionLayout + ?Sized>(
    this: &'a T,
    plain_path: &VirtualPath,
) -> std::io::Result<
    impl Iterator<Item = std::io::Result<(FsDirEntry, VirtualPathBuf)>> + 'a + use<'a, T>,
> {
    let entry_path = if plain_path.is_empty() {
        ResolvedStoragePathBuf::new(
            VirtualPathBuf::default(),
            this.entry_storage().get_root_id()?,
        )
    } else {
        this.plain_path_to_cipher(plain_path)?
    };
    let directory = this
        .entry_storage()
        .resolve_directory(entry_path.as_resolved_path())?;
    let token = directory.token;

    Ok(this
        .entry_storage()
        .read_dir(directory.contents_path, directory.contents_id)?
        .map(move |entry| storage_dir_entry_to_plain(this, &token, entry?)))
}

pub(super) fn default_mknode<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    permissions: Option<Permissions>,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path)?;
    let initial_contents = if T::EMPTY_FILE_HAS_HEADER {
        this.generate_cipher_header().or_invalid()?
    } else {
        Vec::new()
    };
    let metadata = this.entry_storage().create_file(
        cipher_path.as_resolved_path(),
        &initial_contents,
        permissions,
    )?;
    storage_metadata_to_plain(this, metadata)
}

pub(super) fn default_mkdir<T: EncryptionLayout + ?Sized, L: DirectoryLayout + ?Sized>(
    this: &T,
    directory_layout: &L,
    plain_path: &VirtualPath,
    permissions: Option<Permissions>,
) -> std::io::Result<Metadata> {
    let entry_path = this.plain_path_to_cipher(plain_path)?;
    let token = directory_layout.generate_directory_token();
    directory_layout
        .validate_directory_token(&token, false)
        .or_invalid()?;
    let directory_id_backup = encrypted_directory_id_backup(
        this,
        &token,
        <T::EntryStorage as EntryStorage>::REQUIRES_DIRECTORY_ID_BACKUP,
    )?;
    let _mutation = this.path_cache().begin_mutation(&[plain_path]);
    let metadata = this.entry_storage().create_directory(
        entry_path,
        token,
        directory_id_backup,
        permissions,
    )?;
    storage_metadata_to_plain(this, metadata)
}

/// Encrypts a directory identifier as a complete single-block file when required.
pub(crate) fn encrypted_directory_id_backup<T>(
    translator: &T,
    token: &[u8],
    requires_backup: bool,
) -> std::io::Result<Option<Vec<u8>>>
where
    T: EncryptionTranslator + ?Sized,
{
    if !requires_backup {
        return Ok(None);
    }

    let mut contents = if T::EMPTY_FILE_HAS_HEADER || !token.is_empty() {
        translator.generate_cipher_header().or_invalid()?
    } else {
        Vec::new()
    };
    if !token.is_empty() {
        let block = translator
            .plain_block_to_cipher(&contents, 0, token)
            .or_invalid()?;
        contents.extend(block);
    }
    Ok(Some(contents))
}

/// Selects and validates the token used to materialize a new root directory.
pub(crate) fn select_root_directory_token<L: DirectoryLayout + ?Sized>(
    directory_layout: &L,
) -> std::io::Result<Vec<u8>> {
    let token = match directory_layout.root_directory_token() {
        RootDirectoryToken::Persisted => directory_layout.generate_directory_token(),
        RootDirectoryToken::Implicit(token) => token,
    };
    directory_layout
        .validate_directory_token(&token, true)
        .or_invalid()?;
    Ok(token)
}

pub(super) fn default_remove<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<()> {
    let cipher_path = this.plain_path_to_cipher(plain_path)?;
    this.entry_storage()
        .remove_entry(cipher_path.as_resolved_path())
}

pub(super) fn default_remove_dir<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<()> {
    let entry_path = this.plain_path_to_cipher(plain_path)?;
    let directory = this
        .entry_storage()
        .resolve_directory(entry_path.as_resolved_path())?;
    let _mutation = this.path_cache().begin_mutation(&[plain_path]);
    this.entry_storage().remove_directory(&directory)?;
    Ok(())
}
pub(super) fn default_create_symlink<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    target: &str,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path)?;
    let cipher_target = this
        .plain_metavalue_to_cipher(target.as_bytes())
        .or_invalid()?;
    let metadata = this
        .entry_storage()
        .create_symlink(cipher_path.as_resolved_path(), &cipher_target)?;
    storage_metadata_to_plain(this, metadata)
}
pub(super) fn default_read_symlink<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<String> {
    let cipher_path = this.plain_path_to_cipher(plain_path)?;
    let cipher_target = this
        .entry_storage()
        .read_symlink(cipher_path.as_resolved_path())?;
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
    let old_cipher_path = this.plain_path_to_cipher(old_path)?;
    let new_cipher_path = this.plain_path_to_cipher(new_path)?;
    let _mutation = this.path_cache().begin_mutation(&[old_path, new_path]);
    this.entry_storage().rename(
        old_cipher_path.as_resolved_path(),
        new_cipher_path.as_resolved_path(),
    )?;
    Ok(())
}

pub(super) fn default_set_permissions<T: EncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    permissions: Permissions,
) -> std::io::Result<Metadata> {
    let path = this.plain_path_to_cipher(plain_path)?;
    let metadata = this
        .entry_storage()
        .set_permissions(path.as_resolved_path(), permissions)?;
    storage_metadata_to_plain(this, metadata)
}
/// Sets access and modification times.
pub(super) fn default_set_time<T: EncryptionLayout + ?Sized>(
    this: &T,
    path: &VirtualPath,
    atime: Option<SystemTime>,
    mtime: Option<SystemTime>,
) -> std::io::Result<()> {
    let path = this.plain_path_to_cipher(path)?;
    this.entry_storage()
        .set_time(path.as_resolved_path(), atime, mtime)
}

/// Changes ownership of one represented entry.
pub(super) fn default_chown<T: EncryptionLayout + ?Sized>(
    this: &T,
    path: &VirtualPath,
    uid: Option<u32>,
    gid: Option<u32>,
) -> std::io::Result<()> {
    let path = this.plain_path_to_cipher(path)?;
    this.entry_storage()
        .chown(path.as_resolved_path(), uid, gid)
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
