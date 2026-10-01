use super::{
    AsyncFileHandle, FileHandle, FileOpenOptions, Metadata, Permissions, ResolvedStoragePath,
    ResolvedStoragePathBuf, StorageDirectoryId, VirtualPathBuf,
};
use futures_core::Stream;
use std::{future::Future, time::SystemTime};

/// One visible entry returned from a represented storage directory.
pub struct StorageDirEntry {
    /// Encoded name stored in the containing directory.
    pub file_name: String,
    /// Physical path of the represented entry.
    pub path: VirtualPathBuf,
    /// Metadata normalized to the represented logical entry.
    pub metadata: Metadata,
}

/// Paths and opaque token required to materialize a logical directory.
pub struct StorageDirectory {
    /// Physical path of the visible directory entry.
    pub entry_path: ResolvedStoragePathBuf,
    /// Physical path of the directory containing its encoded children.
    pub contents_path: ResolvedStoragePathBuf,
    /// Identity of the directory containing its encoded children.
    pub contents_id: StorageDirectoryId,
    /// Opaque directory identifier or initialization vector.
    pub token: Vec<u8>,
}

/// Generates selected trivial forwards from an entry storage to its raw filesystem field.
macro_rules! forward_storage_fs_operations {
    ($storage_fs_ty:ty, $field:ident;) => {};
    ($storage_fs_ty:ty, $field:ident; map_path = $map_path:expr;) => {};
    (
        $storage_fs_ty:ty,
        $field:ident;
        map_path = $map_path:expr;
        $operation:ident $(, $remaining:ident)* $(,)?
    ) => {
        $crate::core::forward_storage_fs_operations!(
            @one $storage_fs_ty, $field, $operation, $map_path
        );
        $crate::core::forward_storage_fs_operations!(
            $storage_fs_ty, $field;
            map_path = $map_path;
            $($remaining),*
        );
    };
    (
        $storage_fs_ty:ty,
        $field:ident;
        $operation:ident $(, $remaining:ident)* $(,)?
    ) => {
        $crate::core::forward_storage_fs_operations!(
            @one $storage_fs_ty, $field, $operation
        );
        $crate::core::forward_storage_fs_operations!(
            $storage_fs_ty, $field; $($remaining),*
        );
    };
    (@bind_path $self:ident, $path:ident => $mapped_path:ident) => {
        let $mapped_path = $path;
    };
    (@bind_path $self:ident, $path:ident => $mapped_path:ident, $map_path:expr) => {
        let mapped_path_owned = ($map_path)($self, $path.path());
        let $mapped_path = $crate::core::ResolvedStoragePath::new(
            &mapped_path_owned,
            $path.expected_parent_id(),
        );
    };
    (@one $storage_fs_ty:ty, $field:ident, open_file_with $(, $map_path:expr)?) => {
        type OpenHandle =
            <$storage_fs_ty as $crate::core::StorageFileSystem>::OpenHandle;

        fn open_file_with(
            &self,
            path: $crate::core::ResolvedStoragePath<'_>,
            options: $crate::core::FileOpenOptions,
        ) -> std::io::Result<Self::OpenHandle> {
            $crate::core::forward_storage_fs_operations!(
                @bind_path self, path => mapped_path $(, $map_path)?
            );
            <$storage_fs_ty as $crate::core::StorageFileSystem>::open_file_with(
                &self.$field,
                mapped_path,
                options,
            )
        }
    };
    (@one $storage_fs_ty:ty, $field:ident, rename $(, $map_path:expr)?) => {
        fn rename(
            &self,
            old_path: $crate::core::ResolvedStoragePath<'_>,
            new_path: $crate::core::ResolvedStoragePath<'_>,
        ) -> std::io::Result<()> {
            $crate::core::forward_storage_fs_operations!(
                @bind_path self, old_path => mapped_old_path $(, $map_path)?
            );
            $crate::core::forward_storage_fs_operations!(
                @bind_path self, new_path => mapped_new_path $(, $map_path)?
            );
            <$storage_fs_ty as $crate::core::StorageFileSystem>::rename(
                &self.$field,
                mapped_old_path,
                mapped_new_path,
            )
        }
    };
    (@one $storage_fs_ty:ty, $field:ident, set_permissions $(, $map_path:expr)?) => {
        fn set_permissions(
            &self,
            path: $crate::core::ResolvedStoragePath<'_>,
            permissions: $crate::core::Permissions,
        ) -> std::io::Result<()> {
            $crate::core::forward_storage_fs_operations!(
                @bind_path self, path => mapped_path $(, $map_path)?
            );
            <$storage_fs_ty as $crate::core::StorageFileSystem>::set_permissions(
                &self.$field,
                mapped_path,
                permissions,
            )
            .map(|_| ())
        }
    };
    (@one $storage_fs_ty:ty, $field:ident, set_time $(, $map_path:expr)?) => {
        fn set_time(
            &self,
            path: $crate::core::ResolvedStoragePath<'_>,
            atime: Option<std::time::SystemTime>,
            mtime: Option<std::time::SystemTime>,
        ) -> std::io::Result<()> {
            $crate::core::forward_storage_fs_operations!(
                @bind_path self, path => mapped_path $(, $map_path)?
            );
            <$storage_fs_ty as $crate::core::StorageFileSystem>::set_time(
                &self.$field,
                mapped_path,
                atime,
                mtime,
            )
        }
    };
    (@one $storage_fs_ty:ty, $field:ident, chown $(, $map_path:expr)?) => {
        fn chown(
            &self,
            path: $crate::core::ResolvedStoragePath<'_>,
            uid: Option<u32>,
            gid: Option<u32>,
        ) -> std::io::Result<()> {
            $crate::core::forward_storage_fs_operations!(
                @bind_path self, path => mapped_path $(, $map_path)?
            );
            <$storage_fs_ty as $crate::core::StorageFileSystem>::chown(
                &self.$field,
                mapped_path,
                uid,
                gid,
            )
        }
    };
    (@one $storage_fs_ty:ty, $field:ident, get_xattr $(, $map_path:expr)?) => {
        fn get_xattr(
            &self,
            path: $crate::core::ResolvedStoragePath<'_>,
            name: &str,
        ) -> std::io::Result<Vec<u8>> {
            $crate::core::forward_storage_fs_operations!(
                @bind_path self, path => mapped_path $(, $map_path)?
            );
            <$storage_fs_ty as $crate::core::StorageFileSystem>::get_xattr(
                &self.$field,
                mapped_path,
                name,
            )
        }
    };
    (@one $storage_fs_ty:ty, $field:ident, list_xattr $(, $map_path:expr)?) => {
        fn list_xattr(
            &self,
            path: $crate::core::ResolvedStoragePath<'_>,
        ) -> std::io::Result<Vec<String>> {
            $crate::core::forward_storage_fs_operations!(
                @bind_path self, path => mapped_path $(, $map_path)?
            );
            <$storage_fs_ty as $crate::core::StorageFileSystem>::list_xattr(
                &self.$field,
                mapped_path,
            )
        }
    };
    (@one $storage_fs_ty:ty, $field:ident, remove_xattr $(, $map_path:expr)?) => {
        fn remove_xattr(
            &self,
            path: $crate::core::ResolvedStoragePath<'_>,
            name: &str,
        ) -> std::io::Result<()> {
            $crate::core::forward_storage_fs_operations!(
                @bind_path self, path => mapped_path $(, $map_path)?
            );
            <$storage_fs_ty as $crate::core::StorageFileSystem>::remove_xattr(
                &self.$field,
                mapped_path,
                name,
            )
        }
    };
    (@one $storage_fs_ty:ty, $field:ident, set_xattr $(, $map_path:expr)?) => {
        fn set_xattr(
            &self,
            path: $crate::core::ResolvedStoragePath<'_>,
            name: &str,
            value: &[u8],
        ) -> std::io::Result<()> {
            $crate::core::forward_storage_fs_operations!(
                @bind_path self, path => mapped_path $(, $map_path)?
            );
            <$storage_fs_ty as $crate::core::StorageFileSystem>::set_xattr(
                &self.$field,
                mapped_path,
                name,
                value,
            )
        }
    };
}
pub(crate) use forward_storage_fs_operations;

/// Maps logical encoded entries to their physical filesystem representation.
///
/// Paths, directory tokens, and symlink payloads are opaque. Implementations
/// know the on-disk representation but do not encrypt or decrypt their values.
/// Entry-operation paths have an already-resolved physical parent and an
/// encoded logical final component. Paths returned by this trait are physical.
pub trait EntryStorage: Send + Sync + 'static {
    /// Whether this representation persists an encrypted directory identifier backup.
    const REQUIRES_DIRECTORY_ID_BACKUP: bool;

    /// Handle returned when opening a represented regular file.
    type OpenHandle: FileHandle;

    /// Iterator borrowing the entry storage while a directory is being listed.
    type DirEntries<'a>: Iterator<Item = std::io::Result<StorageDirEntry>> + 'a
    where
        Self: 'a;

    /// Returns the identity of the physical storage root.
    fn get_root_id(&self) -> std::io::Result<StorageDirectoryId>;

    /// Opens a represented regular file using opaque physical options.
    fn open_file_with(
        &self,
        path: ResolvedStoragePath<'_>,
        options: FileOpenOptions,
    ) -> std::io::Result<Self::OpenHandle>;

    /// Returns metadata normalized to the represented logical entry.
    fn metadata(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Metadata>;

    /// Lists visible encoded entries from a directory contents location.
    fn read_dir<'a>(
        &'a self,
        contents_path: ResolvedStoragePathBuf,
        contents_id: StorageDirectoryId,
    ) -> std::io::Result<Self::DirEntries<'a>>;

    /// Resolves a stored directory to its complete physical description.
    fn resolve_directory(
        &self,
        entry_path: ResolvedStoragePath<'_>,
    ) -> std::io::Result<StorageDirectory>;

    /// Initializes the logical root with its token and optional encrypted identifier backup.
    fn initialize_root_directory(
        &self,
        token: Vec<u8>,
        directory_id_backup: Option<Vec<u8>>,
    ) -> std::io::Result<StorageDirectory>;

    /// Materializes a regular file with opaque initial contents.
    fn create_file(
        &self,
        path: ResolvedStoragePath<'_>,
        initial_contents: &[u8],
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata>;

    /// Materializes a directory with its token and optional encrypted identifier backup.
    fn create_directory(
        &self,
        entry_path: ResolvedStoragePathBuf,
        token: Vec<u8>,
        directory_id_backup: Option<Vec<u8>>,
        permissions: Option<Permissions>,
    ) -> std::io::Result<Metadata>;

    /// Removes a logical directory and its representation-specific contents.
    fn remove_directory(&self, directory: &StorageDirectory) -> std::io::Result<()>;

    /// Removes a represented non-directory entry.
    fn remove_entry(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<()>;

    /// Materializes a logical symlink containing an opaque target payload.
    fn create_symlink(
        &self,
        path: ResolvedStoragePath<'_>,
        target: &[u8],
    ) -> std::io::Result<Metadata>;

    /// Reads the opaque target payload represented by a logical symlink.
    fn read_symlink(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Vec<u8>>;

    /// Renames one represented entry without interpreting its encoded name.
    fn rename(
        &self,
        old_path: ResolvedStoragePath<'_>,
        new_path: ResolvedStoragePath<'_>,
    ) -> std::io::Result<()>;

    /// Sets permissions and returns normalized metadata for a represented entry.
    fn set_permissions(
        &self,
        path: ResolvedStoragePath<'_>,
        permissions: Permissions,
    ) -> std::io::Result<Metadata>;

    /// Sets access and modification times on a represented entry.
    fn set_time(
        &self,
        path: ResolvedStoragePath<'_>,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()>;

    /// Changes ownership of a represented entry.
    fn chown(
        &self,
        path: ResolvedStoragePath<'_>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> std::io::Result<()>;

    /// Reads one opaque extended-attribute value.
    fn get_xattr(&self, path: ResolvedStoragePath<'_>, name: &str) -> std::io::Result<Vec<u8>>;

    /// Lists opaque extended-attribute names.
    fn list_xattr(&self, path: ResolvedStoragePath<'_>) -> std::io::Result<Vec<String>>;

    /// Removes one opaque extended attribute.
    fn remove_xattr(&self, path: ResolvedStoragePath<'_>, name: &str) -> std::io::Result<()>;

    /// Stores one opaque extended-attribute value.
    fn set_xattr(
        &self,
        path: ResolvedStoragePath<'_>,
        name: &str,
        value: &[u8],
    ) -> std::io::Result<()>;
}

/// Asynchronously maps logical encoded entries to their physical representation.
///
/// This trait shares the value types and representation rules of
/// [EntryStorage], while allowing every storage access to complete
/// asynchronously.
pub trait AsyncEntryStorage: Send + Sync + 'static {
    /// Whether this representation persists an encrypted directory identifier backup.
    const REQUIRES_DIRECTORY_ID_BACKUP: bool;

    /// Handle returned when opening a represented regular file.
    type OpenHandle: AsyncFileHandle;

    /// Returns the identity of the physical storage root.
    fn get_root_id(&self) -> impl Future<Output = std::io::Result<StorageDirectoryId>> + Send;

    /// Opens a represented regular file using opaque physical options.
    fn open_file_with(
        &self,
        path: ResolvedStoragePath<'_>,
        options: FileOpenOptions,
    ) -> impl Future<Output = std::io::Result<Self::OpenHandle>> + Send;

    /// Returns metadata normalized to the represented logical entry.
    fn metadata(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Lists visible encoded entries from a directory contents location.
    fn read_dir(
        &self,
        contents_path: ResolvedStoragePathBuf,
        contents_id: StorageDirectoryId,
    ) -> impl Stream<Item = std::io::Result<Vec<StorageDirEntry>>> + Send;

    /// Resolves a stored directory to its complete physical description.
    fn resolve_directory(
        &self,
        entry_path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<StorageDirectory>> + Send;

    /// Initializes the logical root with its token and optional encrypted identifier backup.
    fn initialize_root_directory(
        &self,
        token: Vec<u8>,
        directory_id_backup: Option<Vec<u8>>,
    ) -> impl Future<Output = std::io::Result<StorageDirectory>> + Send;

    /// Materializes a regular file with opaque initial contents.
    fn create_file(
        &self,
        path: ResolvedStoragePath<'_>,
        initial_contents: &[u8],
        permissions: Option<Permissions>,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Materializes a directory with its token and optional encrypted identifier backup.
    fn create_directory(
        &self,
        entry_path: ResolvedStoragePathBuf,
        token: Vec<u8>,
        directory_id_backup: Option<Vec<u8>>,
        permissions: Option<Permissions>,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Removes a logical directory and its representation-specific contents.
    fn remove_directory(
        &self,
        directory: &StorageDirectory,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Removes a represented non-directory entry.
    fn remove_entry(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Materializes a logical symlink containing an opaque target payload.
    fn create_symlink(
        &self,
        path: ResolvedStoragePath<'_>,
        target: &[u8],
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Reads the opaque target payload represented by a logical symlink.
    fn read_symlink(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<Vec<u8>>> + Send;

    /// Renames one represented entry without interpreting its encoded name.
    fn rename(
        &self,
        old_path: ResolvedStoragePath<'_>,
        new_path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Sets permissions on a represented entry.
    fn set_permissions(
        &self,
        path: ResolvedStoragePath<'_>,
        permissions: Permissions,
    ) -> impl Future<Output = std::io::Result<Metadata>> + Send;

    /// Sets access and modification times on a represented entry.
    fn set_time(
        &self,
        path: ResolvedStoragePath<'_>,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Changes ownership of a represented entry.
    fn chown(
        &self,
        path: ResolvedStoragePath<'_>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Reads one opaque extended-attribute value.
    fn get_xattr(
        &self,
        path: ResolvedStoragePath<'_>,
        name: &str,
    ) -> impl Future<Output = std::io::Result<Vec<u8>>> + Send;

    /// Lists opaque extended-attribute names.
    fn list_xattr(
        &self,
        path: ResolvedStoragePath<'_>,
    ) -> impl Future<Output = std::io::Result<Vec<String>>> + Send;

    /// Removes one opaque extended attribute.
    fn remove_xattr(
        &self,
        path: ResolvedStoragePath<'_>,
        name: &str,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Stores one opaque extended-attribute value.
    fn set_xattr(
        &self,
        path: ResolvedStoragePath<'_>,
        name: &str,
        value: &[u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send;
}
