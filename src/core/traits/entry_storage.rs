use super::{
    DirectoryLayout, FileHandle, FileOpenOptions, Metadata, Permissions, VirtualPath,
    VirtualPathBuf,
};
use std::{future::Future, time::SystemTime};

/// Logical kind exposed by an on-disk entry representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageEntryKind {
    /// A regular file representation.
    File,
    /// A directory representation.
    Directory,
    /// A symbolic-link representation.
    Symlink,
    /// An unsupported or unrecognized representation.
    Other,
}

/// Physical metadata together with the logical kind represented by the entry.
pub struct StorageMetadata {
    /// Metadata reported by the underlying filesystem.
    pub raw: Metadata,
    /// Logical kind inferred from the on-disk representation.
    pub kind: StorageEntryKind,
}

/// One visible entry returned from a represented storage directory.
pub struct StorageDirEntry {
    /// Encoded name stored in the containing directory.
    pub file_name: String,
    /// Physical path of the represented entry.
    pub path: VirtualPathBuf,
    /// Physical metadata and inferred logical kind.
    pub metadata: StorageMetadata,
}

/// Paths and opaque token required to materialize a logical directory.
pub struct StorageDirectory {
    /// Physical path of the visible directory entry.
    pub entry_path: VirtualPathBuf,
    /// Physical path of the directory containing its encoded children.
    pub contents_path: VirtualPathBuf,
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
        let mapped_path_owned = ($map_path)($self, $path);
        let $mapped_path = mapped_path_owned.as_path();
    };
    (@one $storage_fs_ty:ty, $field:ident, open_file_with $(, $map_path:expr)?) => {
        type OpenHandle =
            <$storage_fs_ty as $crate::core::StorageFileSystem>::OpenHandle;

        fn open_file_with(
            &self,
            path: &$crate::core::VirtualPath,
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
            old_path: &$crate::core::VirtualPath,
            new_path: &$crate::core::VirtualPath,
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
            path: &$crate::core::VirtualPath,
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
            path: &$crate::core::VirtualPath,
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
            path: &$crate::core::VirtualPath,
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
            path: &$crate::core::VirtualPath,
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
            path: &$crate::core::VirtualPath,
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
            path: &$crate::core::VirtualPath,
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
            path: &$crate::core::VirtualPath,
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
    /// Handle returned when opening a represented regular file.
    type OpenHandle: FileHandle;

    /// Iterator returned when listing represented directory entries.
    type DirEntries: Iterator<Item = std::io::Result<StorageDirEntry>> + 'static;

    /// Opens a represented regular file using opaque physical options.
    fn open_file_with(
        &self,
        path: &VirtualPath,
        options: FileOpenOptions,
    ) -> std::io::Result<Self::OpenHandle>;

    /// Returns physical metadata and the logical kind represented by an entry.
    fn metadata(&self, path: &VirtualPath) -> std::io::Result<StorageMetadata>;

    /// Lists visible encoded entries from a directory contents location.
    fn read_dir(&self, contents_path: &VirtualPath) -> std::io::Result<Self::DirEntries>;

    /// Resolves a stored directory to its complete physical description.
    fn resolve_directory<L: DirectoryLayout + ?Sized>(
        &self,
        entry_path: &VirtualPath,
        directory_layout: &L,
    ) -> std::io::Result<StorageDirectory>;

    /// Initializes the physical representation of the logical root directory.
    fn initialize_root_directory<L: DirectoryLayout + ?Sized>(
        &self,
        directory_layout: &L,
    ) -> std::io::Result<StorageDirectory>;

    /// Materializes a regular file with opaque initial contents.
    fn create_file(
        &self,
        path: &VirtualPath,
        initial_contents: &[u8],
        permissions: Option<Permissions>,
    ) -> std::io::Result<StorageMetadata>;

    /// Materializes a logical directory according to the storage representation.
    fn create_directory<L: DirectoryLayout + ?Sized>(
        &self,
        entry_path: VirtualPathBuf,
        token: Vec<u8>,
        directory_layout: &L,
        permissions: Option<Permissions>,
    ) -> std::io::Result<StorageMetadata>;

    /// Removes a logical directory and its representation-specific contents.
    fn remove_directory(&self, directory: &StorageDirectory) -> std::io::Result<()>;

    /// Removes a regular file representation.
    fn remove_file(&self, path: &VirtualPath) -> std::io::Result<()>;

    /// Materializes a logical symlink containing an opaque target payload.
    fn create_symlink(&self, path: &VirtualPath, target: &[u8])
    -> std::io::Result<StorageMetadata>;

    /// Reads the opaque target payload represented by a logical symlink.
    fn read_symlink(&self, path: &VirtualPath) -> std::io::Result<Vec<u8>>;

    /// Removes a logical symlink representation.
    fn remove_symlink(&self, path: &VirtualPath) -> std::io::Result<()>;

    /// Renames one represented entry without interpreting its encoded name.
    fn rename(&self, old_path: &VirtualPath, new_path: &VirtualPath) -> std::io::Result<()>;

    /// Sets permissions on a represented entry.
    fn set_permissions(&self, path: &VirtualPath, permissions: Permissions) -> std::io::Result<()>;

    /// Sets access and modification times on a represented entry.
    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> std::io::Result<()>;

    /// Changes ownership of a represented entry.
    fn chown(&self, path: &VirtualPath, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()>;

    /// Reads one opaque extended-attribute value.
    fn get_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<Vec<u8>>;

    /// Lists opaque extended-attribute names.
    fn list_xattr(&self, path: &VirtualPath) -> std::io::Result<Vec<String>>;

    /// Removes one opaque extended attribute.
    fn remove_xattr(&self, path: &VirtualPath, name: &str) -> std::io::Result<()>;

    /// Stores one opaque extended-attribute value.
    fn set_xattr(&self, path: &VirtualPath, name: &str, value: &[u8]) -> std::io::Result<()>;
}

/// Asynchronously maps logical encoded entries to their physical representation.
///
/// This trait shares the value types and representation rules of
/// [EntryStorage], while allowing every storage access to complete
/// asynchronously.
pub trait AsyncEntryStorage: Send + Sync + 'static {
    /// Iterator returned after an asynchronous directory lookup.
    ///
    /// Iterating over the returned entries must not perform blocking I/O.
    type DirEntries: Iterator<Item = std::io::Result<StorageDirEntry>> + Send + 'static;

    /// Returns physical metadata and the logical kind represented by an entry.
    fn metadata(
        &self,
        path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<StorageMetadata>> + Send;

    /// Lists visible encoded entries from a directory contents location.
    fn read_dir(
        &self,
        contents_path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<Self::DirEntries>> + Send;

    /// Resolves a stored directory to its complete physical description.
    fn resolve_directory<L: DirectoryLayout + ?Sized>(
        &self,
        entry_path: &VirtualPath,
        directory_layout: &L,
    ) -> impl Future<Output = std::io::Result<StorageDirectory>> + Send;

    /// Initializes the physical representation of the logical root directory.
    fn initialize_root_directory<L: DirectoryLayout + ?Sized>(
        &self,
        directory_layout: &L,
    ) -> impl Future<Output = std::io::Result<StorageDirectory>> + Send;

    /// Materializes a regular file with opaque initial contents.
    fn create_file(
        &self,
        path: &VirtualPath,
        initial_contents: &[u8],
        permissions: Option<Permissions>,
    ) -> impl Future<Output = std::io::Result<StorageMetadata>> + Send;

    /// Materializes a logical directory according to the storage representation.
    fn create_directory<L: DirectoryLayout + ?Sized>(
        &self,
        entry_path: VirtualPathBuf,
        token: Vec<u8>,
        directory_layout: &L,
        permissions: Option<Permissions>,
    ) -> impl Future<Output = std::io::Result<StorageMetadata>> + Send;

    /// Removes a logical directory and its representation-specific contents.
    fn remove_directory(
        &self,
        directory: &StorageDirectory,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Removes a regular file representation.
    fn remove_file(&self, path: &VirtualPath) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Materializes a logical symlink containing an opaque target payload.
    fn create_symlink(
        &self,
        path: &VirtualPath,
        target: &[u8],
    ) -> impl Future<Output = std::io::Result<StorageMetadata>> + Send;

    /// Reads the opaque target payload represented by a logical symlink.
    fn read_symlink(
        &self,
        path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<Vec<u8>>> + Send;

    /// Removes a logical symlink representation.
    fn remove_symlink(
        &self,
        path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Renames one represented entry without interpreting its encoded name.
    fn rename(
        &self,
        old_path: &VirtualPath,
        new_path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Sets permissions on a represented entry.
    fn set_permissions(
        &self,
        path: &VirtualPath,
        permissions: Permissions,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Sets access and modification times on a represented entry.
    fn set_time(
        &self,
        path: &VirtualPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Changes ownership of a represented entry.
    fn chown(
        &self,
        path: &VirtualPath,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Reads one opaque extended-attribute value.
    fn get_xattr(
        &self,
        path: &VirtualPath,
        name: &str,
    ) -> impl Future<Output = std::io::Result<Vec<u8>>> + Send;

    /// Lists opaque extended-attribute names.
    fn list_xattr(
        &self,
        path: &VirtualPath,
    ) -> impl Future<Output = std::io::Result<Vec<String>>> + Send;

    /// Removes one opaque extended attribute.
    fn remove_xattr(
        &self,
        path: &VirtualPath,
        name: &str,
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Stores one opaque extended-attribute value.
    fn set_xattr(
        &self,
        path: &VirtualPath,
        name: &str,
        value: &[u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send;
}
