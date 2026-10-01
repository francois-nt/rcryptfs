use super::helpers::{
    encrypted_directory_id_backup, storage_dir_entry_to_plain, storage_metadata_to_plain,
};
use super::{
    AsyncEncryptionLayout, AsyncEntryStorage, DirectoryLayout, FsDirEntry, Metadata, OrIoError,
    Permissions, ResolvedStoragePathBuf, VirtualPath, VirtualPathBuf,
};
use futures_core::Stream;
use futures_util::{StreamExt, TryStreamExt, stream};
use std::time::SystemTime;

pub(super) fn default_async_list_dir_plain_names<T: AsyncEncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> impl Stream<Item = std::io::Result<Vec<(FsDirEntry, VirtualPathBuf)>>> + Send {
    stream::once(async move {
        let entry_path = if plain_path.is_empty() {
            ResolvedStoragePathBuf::new(
                VirtualPathBuf::default(),
                this.entry_storage().get_root_id().await?,
            )
        } else {
            this.plain_path_to_cipher(plain_path).await.or_invalid()?
        };
        let directory = this
            .entry_storage()
            .resolve_directory(entry_path.as_resolved_path())
            .await?;
        let token = directory.token;
        Ok::<_, std::io::Error>(
            this.entry_storage()
                .read_dir(directory.contents_path, directory.contents_id)
                .map(move |entries| {
                    entries?
                        .into_iter()
                        .map(|entry| storage_dir_entry_to_plain(this, &token, entry))
                        .collect()
                }),
        )
    })
    .try_flatten()
}

pub(super) async fn default_async_metadata<T: AsyncEncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path).await.or_invalid()?;
    let metadata = this
        .entry_storage()
        .metadata(cipher_path.as_resolved_path())
        .await?;
    storage_metadata_to_plain(this, metadata)
}

pub(super) async fn default_async_mknode<T: AsyncEncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    permissions: Option<Permissions>,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path).await.or_invalid()?;
    let initial_contents = if T::EMPTY_FILE_HAS_HEADER {
        this.generate_cipher_header().or_invalid()?
    } else {
        Vec::new()
    };
    let metadata = this
        .entry_storage()
        .create_file(
            cipher_path.as_resolved_path(),
            &initial_contents,
            permissions,
        )
        .await?;
    storage_metadata_to_plain(this, metadata)
}

pub(super) async fn default_async_mkdir<T: AsyncEncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    permissions: Option<Permissions>,
) -> std::io::Result<Metadata> {
    let entry_path = this.plain_path_to_cipher(plain_path).await.or_invalid()?;
    let token = this.directory_layout().generate_directory_token();
    this.directory_layout()
        .validate_directory_token(&token, false)
        .or_invalid()?;
    let directory_id_backup = encrypted_directory_id_backup(
        this,
        &token,
        <T::EntryStorage as AsyncEntryStorage>::REQUIRES_DIRECTORY_ID_BACKUP,
    )?;
    let _mutation = this.path_cache().begin_mutation(&[plain_path]);
    let metadata = this
        .entry_storage()
        .create_directory(entry_path, token, directory_id_backup, permissions)
        .await?;
    storage_metadata_to_plain(this, metadata)
}

pub(super) async fn default_async_remove<T: AsyncEncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<()> {
    let cipher_path = this.plain_path_to_cipher(plain_path).await.or_invalid()?;
    this.entry_storage()
        .remove_entry(cipher_path.as_resolved_path())
        .await
}

pub(super) async fn default_async_remove_dir<T: AsyncEncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<()> {
    let entry_path = this.plain_path_to_cipher(plain_path).await.or_invalid()?;
    let directory = this
        .entry_storage()
        .resolve_directory(entry_path.as_resolved_path())
        .await?;
    let _mutation = this.path_cache().begin_mutation(&[plain_path]);
    this.entry_storage().remove_directory(&directory).await
}

pub(super) async fn default_async_create_symlink<T: AsyncEncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    target: &str,
) -> std::io::Result<Metadata> {
    let cipher_path = this.plain_path_to_cipher(plain_path).await.or_invalid()?;
    let cipher_target = this
        .plain_metavalue_to_cipher(target.as_bytes())
        .or_invalid()?;
    let metadata = this
        .entry_storage()
        .create_symlink(cipher_path.as_resolved_path(), &cipher_target)
        .await?;
    storage_metadata_to_plain(this, metadata)
}

pub(super) async fn default_async_read_symlink<T: AsyncEncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
) -> std::io::Result<String> {
    let cipher_path = this.plain_path_to_cipher(plain_path).await.or_invalid()?;
    let cipher_target = this
        .entry_storage()
        .read_symlink(cipher_path.as_resolved_path())
        .await?;
    let plain_value = this
        .cipher_metavalue_to_plain(&cipher_target)
        .or_invalid()?;
    String::from_utf8(plain_value).or_invalid()
}

pub(super) async fn default_async_rename<T: AsyncEncryptionLayout + ?Sized>(
    this: &T,
    old_path: &VirtualPath,
    new_path: &VirtualPath,
) -> std::io::Result<()> {
    let old_cipher_path = this.plain_path_to_cipher(old_path).await.or_invalid()?;
    let new_cipher_path = this.plain_path_to_cipher(new_path).await.or_invalid()?;
    let _mutation = this.path_cache().begin_mutation(&[old_path, new_path]);
    this.entry_storage()
        .rename(
            old_cipher_path.as_resolved_path(),
            new_cipher_path.as_resolved_path(),
        )
        .await
}

pub(super) async fn default_async_set_permissions<T: AsyncEncryptionLayout + ?Sized>(
    this: &T,
    plain_path: &VirtualPath,
    permissions: Permissions,
) -> std::io::Result<Metadata> {
    let path = this.plain_path_to_cipher(plain_path).await.or_invalid()?;
    let metadata = this
        .entry_storage()
        .set_permissions(path.as_resolved_path(), permissions)
        .await?;
    storage_metadata_to_plain(this, metadata)
}

pub(super) async fn default_async_set_time<T: AsyncEncryptionLayout + ?Sized>(
    this: &T,
    path: &VirtualPath,
    atime: Option<SystemTime>,
    mtime: Option<SystemTime>,
) -> std::io::Result<()> {
    let path = this.plain_path_to_cipher(path).await.or_invalid()?;
    this.entry_storage()
        .set_time(path.as_resolved_path(), atime, mtime)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        AsyncFileHandle, AsyncPathLayout, DirectoryContentLayout, DirectoryLayout,
        EncryptionTranslator, FileOpenOptions, FileType, PathCache, PathCacheAccess,
        ResolvedStoragePath, ResolvedStoragePathBuf, Result, RootDirectoryToken, StorageDirEntry,
        StorageDirectory, StorageDirectoryId,
    };
    use futures_util::{StreamExt, task::noop_waker};
    use std::{future::Future, task::Context};

    fn metadata(file_type: FileType) -> Metadata {
        Metadata {
            len: 5,
            blocks: 1,
            file_type,
            created: SystemTime::UNIX_EPOCH,
            modified: SystemTime::UNIX_EPOCH,
            accessed: SystemTime::UNIX_EPOCH,
            permissions: 0o644_u16.into(),
            uid: None,
            gid: None,
        }
    }

    fn unsupported<T>() -> std::io::Result<T> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        loop {
            if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
            std::thread::yield_now();
        }
    }

    struct TestStorage;

    impl AsyncEntryStorage for TestStorage {
        const REQUIRES_DIRECTORY_ID_BACKUP: bool = false;
        type OpenHandle = Box<dyn AsyncFileHandle>;

        async fn open_file_with(
            &self,
            _path: ResolvedStoragePath<'_>,
            _options: FileOpenOptions,
        ) -> std::io::Result<Self::OpenHandle> {
            unsupported()
        }

        async fn metadata(&self, _path: ResolvedStoragePath<'_>) -> std::io::Result<Metadata> {
            Ok(metadata(FileType::File))
        }

        fn read_dir(
            &self,
            contents_path: ResolvedStoragePathBuf,
            _contents_id: StorageDirectoryId,
        ) -> impl Stream<Item = std::io::Result<Vec<StorageDirEntry>>> + Send {
            futures_util::stream::iter([Ok(vec![StorageDirEntry {
                file_name: "child".into(),
                path: contents_path.path().join("child"),
                metadata: metadata(FileType::File),
            }])])
        }

        async fn resolve_directory(
            &self,
            entry_path: ResolvedStoragePath<'_>,
        ) -> std::io::Result<StorageDirectory> {
            Ok(StorageDirectory {
                entry_path: entry_path.to_owned(),
                contents_path: entry_path.to_owned(),
                contents_id: StorageDirectoryId::default(),
                token: vec![1],
            })
        }

        async fn initialize_root_directory(
            &self,
            token: Vec<u8>,
            _directory_id_backup: Option<Vec<u8>>,
        ) -> std::io::Result<StorageDirectory> {
            Ok(StorageDirectory {
                entry_path: ResolvedStoragePathBuf::new(
                    VirtualPathBuf::default(),
                    StorageDirectoryId::default(),
                ),
                contents_path: ResolvedStoragePathBuf::new(
                    VirtualPathBuf::default(),
                    StorageDirectoryId::default(),
                ),
                contents_id: StorageDirectoryId::default(),
                token,
            })
        }

        async fn get_root_id(&self) -> std::io::Result<StorageDirectoryId> {
            Ok(StorageDirectoryId::default())
        }

        async fn create_file(
            &self,
            _path: ResolvedStoragePath<'_>,
            _initial_contents: &[u8],
            _permissions: Option<Permissions>,
        ) -> std::io::Result<Metadata> {
            Ok(metadata(FileType::File))
        }

        async fn create_directory(
            &self,
            _entry_path: ResolvedStoragePathBuf,
            _token: Vec<u8>,
            _directory_id_backup: Option<Vec<u8>>,
            _permissions: Option<Permissions>,
        ) -> std::io::Result<Metadata> {
            Ok(metadata(FileType::Directory))
        }

        async fn remove_directory(&self, _directory: &StorageDirectory) -> std::io::Result<()> {
            Ok(())
        }

        async fn remove_entry(&self, _path: ResolvedStoragePath<'_>) -> std::io::Result<()> {
            Ok(())
        }

        async fn create_symlink(
            &self,
            _path: ResolvedStoragePath<'_>,
            _target: &[u8],
        ) -> std::io::Result<Metadata> {
            Ok(metadata(FileType::SymLink))
        }

        async fn read_symlink(&self, _path: ResolvedStoragePath<'_>) -> std::io::Result<Vec<u8>> {
            Ok(b"target".to_vec())
        }

        async fn rename(
            &self,
            _old_path: ResolvedStoragePath<'_>,
            _new_path: ResolvedStoragePath<'_>,
        ) -> std::io::Result<()> {
            Ok(())
        }

        async fn set_permissions(
            &self,
            _path: ResolvedStoragePath<'_>,
            permissions: Permissions,
        ) -> std::io::Result<Metadata> {
            let mut result = metadata(FileType::File);
            result.permissions = permissions;
            Ok(result)
        }

        async fn set_time(
            &self,
            _path: ResolvedStoragePath<'_>,
            _atime: Option<SystemTime>,
            _mtime: Option<SystemTime>,
        ) -> std::io::Result<()> {
            Ok(())
        }

        async fn chown(
            &self,
            _path: ResolvedStoragePath<'_>,
            _uid: Option<u32>,
            _gid: Option<u32>,
        ) -> std::io::Result<()> {
            Ok(())
        }

        async fn get_xattr(
            &self,
            _path: ResolvedStoragePath<'_>,
            _name: &str,
        ) -> std::io::Result<Vec<u8>> {
            unsupported()
        }

        async fn list_xattr(&self, _path: ResolvedStoragePath<'_>) -> std::io::Result<Vec<String>> {
            unsupported()
        }

        async fn remove_xattr(
            &self,
            _path: ResolvedStoragePath<'_>,
            _name: &str,
        ) -> std::io::Result<()> {
            unsupported()
        }

        async fn set_xattr(
            &self,
            _path: ResolvedStoragePath<'_>,
            _name: &str,
            _value: &[u8],
        ) -> std::io::Result<()> {
            unsupported()
        }
    }

    struct TestDirectoryLayout;

    impl DirectoryContentLayout for TestDirectoryLayout {
        fn detached_directory_contents_path(
            &self,
            entry_path: &VirtualPath,
            _token: &[u8],
        ) -> Result<VirtualPathBuf> {
            Ok(entry_path.into())
        }

        fn is_detached_directory_contents_path(&self, _path: &VirtualPath) -> bool {
            false
        }
    }

    impl DirectoryLayout for TestDirectoryLayout {
        fn generate_directory_token(&self) -> Vec<u8> {
            vec![1]
        }

        fn validate_directory_token(&self, _token: &[u8], _is_root: bool) -> Result<()> {
            Ok(())
        }

        fn root_directory_token(&self) -> RootDirectoryToken {
            RootDirectoryToken::Implicit(vec![1])
        }
    }

    struct TestLayout {
        cache: PathCache,
        storage: TestStorage,
        directory_layout: TestDirectoryLayout,
    }

    impl Default for TestLayout {
        fn default() -> Self {
            Self {
                cache: PathCache::default(),
                storage: TestStorage,
                directory_layout: TestDirectoryLayout,
            }
        }
    }

    impl PathCacheAccess for TestLayout {
        fn path_cache(&self) -> &PathCache {
            &self.cache
        }
    }

    impl AsyncPathLayout for TestLayout {
        type EntryStorage = TestStorage;
        type DirectoryLayout = TestDirectoryLayout;

        fn entry_storage(&self) -> &Self::EntryStorage {
            &self.storage
        }

        fn directory_layout(&self) -> &Self::DirectoryLayout {
            &self.directory_layout
        }

        async fn plain_path_to_cipher(
            &self,
            plain_path: &VirtualPath,
        ) -> Result<ResolvedStoragePathBuf> {
            Ok(ResolvedStoragePathBuf::new(
                plain_path.into(),
                StorageDirectoryId::default(),
            ))
        }

        fn remove_cached_plain_path(&self, plain_path: &VirtualPath) {
            self.cache.invalidate(plain_path);
        }
    }

    impl EncryptionTranslator for TestLayout {
        const CIPHER_BLOCK_LEN: u64 = 16;
        const PLAIN_BLOCK_LEN: u64 = 16;
        const HEADER_LEN: usize = 0;
        const ENCRYPT_SPARSE_PARTS: bool = false;
        const EMPTY_FILE_HAS_HEADER: bool = false;

        fn cipher_name_to_plain(&self, _parent_iv: &[u8], cipher_name: &str) -> Result<String> {
            Ok(cipher_name.into())
        }

        fn plain_name_to_cipher(&self, _parent_iv: &[u8], plain_name: &str) -> Result<String> {
            Ok(plain_name.into())
        }

        fn plain_size_to_cipher(&self, plain_size: u64) -> u64 {
            plain_size
        }

        fn cipher_size_to_plain(&self, cipher_size: u64) -> Result<u64> {
            Ok(cipher_size)
        }

        fn generate_cipher_header(&self) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }

        fn cipher_block_to_plain(
            &self,
            _header: &[u8],
            _block_no: u64,
            cipher_data: &[u8],
        ) -> Result<Vec<u8>> {
            Ok(cipher_data.into())
        }

        fn plain_block_to_cipher(
            &self,
            _header: &[u8],
            _block_no: u64,
            plain_data: &[u8],
        ) -> Result<Vec<u8>> {
            Ok(plain_data.into())
        }

        fn plain_metavalue_to_cipher(&self, plain_metavalue: &[u8]) -> Result<Vec<u8>> {
            Ok(plain_metavalue.into())
        }

        fn cipher_metavalue_to_plain(&self, cipher_metavalue: &[u8]) -> Result<Vec<u8>> {
            Ok(cipher_metavalue.into())
        }
    }

    impl AsyncEncryptionLayout for TestLayout {}

    #[test]
    fn async_defaults_cover_layout_operations_and_directory_batches() {
        let layout = TestLayout::default();
        let file = VirtualPath::new("docs/file");
        let directory = VirtualPath::new("docs");

        assert_eq!(block_on(layout.metadata(file)).unwrap().len, 5);
        assert!(block_on(layout.mknode(file, None)).unwrap().file_type == FileType::File);
        assert!(block_on(layout.mkdir(directory, None)).unwrap().file_type == FileType::Directory);
        block_on(layout.remove(file)).unwrap();
        block_on(layout.remove_dir(directory)).unwrap();
        assert!(
            block_on(layout.create_symlink(file, "target"))
                .unwrap()
                .file_type
                == FileType::SymLink
        );
        assert_eq!(block_on(layout.read_symlink(file)).unwrap(), "target");
        block_on(layout.rename(file, VirtualPath::new("docs/new"))).unwrap();
        block_on(layout.set_permissions(file, 0o600_u16.into())).unwrap();
        block_on(layout.set_time(file, None, None)).unwrap();

        let batches = block_on(layout.list_dir_plain_names(directory).collect::<Vec<_>>());
        assert_eq!(batches.len(), 1);
        let entries = batches.into_iter().next().unwrap().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.file_name, "child");
    }
}
