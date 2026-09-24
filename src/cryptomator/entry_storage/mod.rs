use crate::core::{
    DirectoryLayout, EntryStorage, FileOpenOptions, FileType, Metadata, OrIoError, Permissions,
    RenameOperation, RootDirectoryToken, StorageDirEntry, StorageDirectory, StorageFileSystem,
    VirtualPath, VirtualPathBuf, forward_storage_fs_operations, temp_file_path,
};
use base64::{Engine, engine::general_purpose::URL_SAFE};
use sha1::{Digest, Sha1};
use std::sync::Arc;

use super::DEFAULT_SHORTENING_THRESHOLD;

const CRYPTOMATOR_CONTENTS_FILE: &str = "contents.c9r";
const CRYPTOMATOR_DIR_ID_BACKUP_FILE: &str = "dirid.c9r";
const CRYPTOMATOR_DIR_FILE: &str = "dir.c9r";
const CRYPTOMATOR_NAME_FILE: &str = "name.c9s";
const CRYPTOMATOR_REGULAR_SUFFIX: &str = ".c9r";
const CRYPTOMATOR_SHORT_SUFFIX: &str = ".c9s";
const CRYPTOMATOR_SYMLINK_FILE: &str = "symlink.c9r";

/// Configures how long encoded names are represented by Cryptomator storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptomatorEntryStorageOptions {
    /// Maximum encoded name length stored directly in a directory.
    pub shortening_threshold: usize,
}

impl Default for CryptomatorEntryStorageOptions {
    fn default() -> Self {
        Self {
            shortening_threshold: DEFAULT_SHORTENING_THRESHOLD,
        }
    }
}

/// Cryptomator entry representation used by Cryptomator-compatible layouts.
pub struct CryptomatorEntryStorage<F> {
    storage_fs: F,
    options: CryptomatorEntryStorageOptions,
    directory_layout: Arc<dyn DirectoryLayout>,
}

impl<F> CryptomatorEntryStorage<F> {
    /// Creates a Cryptomator container representation with its directory policy.
    pub fn new(storage_fs: F, directory_layout: Arc<dyn DirectoryLayout>) -> Self {
        Self::with_options(
            storage_fs,
            directory_layout,
            CryptomatorEntryStorageOptions::default(),
        )
    }

    /// Creates a Cryptomator representation with explicit name settings.
    pub fn with_options(
        storage_fs: F,
        directory_layout: Arc<dyn DirectoryLayout>,
        options: CryptomatorEntryStorageOptions,
    ) -> Self {
        Self {
            storage_fs,
            options,
            directory_layout,
        }
    }

    /// Returns the raw filesystem for representation-level tests.
    #[cfg(test)]
    pub(crate) fn storage_fs(&self) -> &F {
        &self.storage_fs
    }

    /// Returns the configured representation options for tests.
    #[cfg(test)]
    pub(crate) fn options(&self) -> CryptomatorEntryStorageOptions {
        self.options
    }
}

mod representation;
mod sync;
#[cfg(test)]
mod tests;
