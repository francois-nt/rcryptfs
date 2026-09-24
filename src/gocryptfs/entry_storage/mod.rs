use crate::core::{
    AsyncEntryStorage, AsyncStorageFileSystem, DirectoryLayout, EntryStorage, EntryStorageBackend,
    FileOpenOptions, FsDirEntry, Metadata, NativeFileSystem, OrIoError, Permissions,
    RenameOperation, RootDirectoryToken, StorageDirEntry, StorageDirectory, StorageFileSystem,
    Utf8Path, Utf8PathBuf, VirtualPath, VirtualPathBuf, forward_storage_fs_operations,
    temp_file_path,
};
use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use futures_core::Stream;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::layout::GoCryptFsDirectoryLayout;

const GOCRYPTFS_DIRIV: &str = "gocryptfs.diriv";
const GOCRYPTFS_LONGNAME_PREFIX: &str = "gocryptfs.longname.";
const GOCRYPTFS_LONGNAME_SUFFIX: &str = ".name";
const GOCRYPTFS_MIN_LONG_NAME_MAX: u8 = 62;

/// Configures how long encoded names are represented by GoCryptFS storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoCryptFsEntryStorageOptions {
    /// Maximum encoded name length stored directly in a directory.
    pub long_name_max: u8,
    /// Uses unpadded URL-safe Base64 for long-name hashes.
    pub raw64: bool,
}

impl Default for GoCryptFsEntryStorageOptions {
    fn default() -> Self {
        Self {
            long_name_max: u8::MAX,
            raw64: true,
        }
    }
}
/// GoCryptFS entry representation used by GoCryptFS-compatible layouts.
pub struct GoCryptFsEntryStorage<F> {
    storage_fs: F,
    options: GoCryptFsEntryStorageOptions,
    directory_layout: Arc<dyn DirectoryLayout>,
}

impl<F> GoCryptFsEntryStorage<F> {
    /// Creates a GoCryptFS representation over a raw storage filesystem.
    pub fn new(storage_fs: F) -> Self {
        Self {
            storage_fs,
            options: GoCryptFsEntryStorageOptions::default(),
            directory_layout: Arc::new(GoCryptFsDirectoryLayout),
        }
    }

    /// Creates a GoCryptFS representation with an explicit directory policy.
    pub fn with_directory_layout(
        storage_fs: F,
        directory_layout: Arc<dyn DirectoryLayout>,
    ) -> Self {
        Self {
            storage_fs,
            options: GoCryptFsEntryStorageOptions::default(),
            directory_layout,
        }
    }

    /// Creates a GoCryptFS representation with explicit long-name settings.
    pub fn with_options(
        storage_fs: F,
        options: GoCryptFsEntryStorageOptions,
    ) -> std::io::Result<Self> {
        Self::with_options_and_directory_layout(
            storage_fs,
            options,
            Arc::new(GoCryptFsDirectoryLayout),
        )
    }

    /// Creates a GoCryptFS representation with explicit name and directory policies.
    pub fn with_options_and_directory_layout(
        storage_fs: F,
        options: GoCryptFsEntryStorageOptions,
        directory_layout: Arc<dyn DirectoryLayout>,
    ) -> std::io::Result<Self> {
        if options.long_name_max < GOCRYPTFS_MIN_LONG_NAME_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "GoCryptFS long-name maximum must be at least {GOCRYPTFS_MIN_LONG_NAME_MAX}"
                ),
            ));
        }
        Ok(Self {
            storage_fs,
            options,
            directory_layout,
        })
    }

    /// Returns the raw filesystem for representation-level tests.
    #[cfg(test)]
    pub(crate) fn storage_fs(&self) -> &F {
        &self.storage_fs
    }
}

mod async_impl;
mod representation;
mod sync;
#[cfg(test)]
mod tests;
