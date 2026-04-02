use super::{CryptoMator, read_dirid};
use crate::{
    CacheAccess, CipherPathLayout, DefaultFs, EncryptionLayout, EncryptionTranslator, FileType,
    FsBackend, FsDirEntry, Metadata, MinimalFs, OrIoError, Result, Utf8Path, Utf8PathBuf,
    temp_file_path,
};
use std::fs::DirEntry;

fn folder_path_to_cipher_and_dirid(
    this: &CryptoMator<FsBackend>,
    plain_path: &Utf8Path,
) -> Result<(Utf8PathBuf, Vec<u8>)> {
    this.backend.access(|cache| {
        if let Some((dir_id, cipher_path)) = cache.get(plain_path.as_str()) {
            Ok((cipher_path.to_owned(), dir_id.clone()))
        } else {
            if plain_path.as_str().is_empty() {
                let cipher_path = this.dir_id_to_storage_path(&String::default())?;
                cache.insert(String::default(), (Vec::default(), cipher_path.clone()));
                return Ok((cipher_path, Vec::default()));
            }

            let mut partial_plain_path = Utf8PathBuf::from("");
            let mut absolute_path = Utf8PathBuf::default();
            let mut is_root = true;
            for plain_part in plain_path.iter() {
                if let Some((dir_id, cipher_parent)) = cache.get(partial_plain_path.as_str()) {
                    let cipher_part = this.plain_name_to_cipher(dir_id, plain_part)?;
                    absolute_path = cipher_parent.join(cipher_part);
                } else {
                    let dir_id = if is_root {
                        String::default()
                    } else {
                        read_dirid(&absolute_path)?
                    };

                    absolute_path = this.dir_id_to_storage_path(&dir_id)?;
                    cache.insert(
                        partial_plain_path.as_str().into(),
                        (dir_id.as_bytes().into(), absolute_path.clone()),
                    );
                    let cipher_part = this.plain_name_to_cipher(dir_id.as_bytes(), plain_part)?;
                    absolute_path.push(cipher_part);
                }
                partial_plain_path.push(plain_part);
                if is_root {
                    is_root = false
                }
            }

            let dir_id = read_dirid(&absolute_path)?;
            absolute_path = this.dir_id_to_storage_path(&dir_id)?;

            cache.insert(
                partial_plain_path.as_str().into(),
                (dir_id.as_bytes().into(), absolute_path.clone()),
            );

            Ok((absolute_path, dir_id.as_bytes().into()))
        }
    })
}

impl CipherPathLayout for CryptoMator<FsBackend> {
    type LowerFs = DefaultFs;
    fn lower_fs(&self) -> &Self::LowerFs {
        &DefaultFs
    }
    fn plain_path_to_cipher(&self, plain_path: &Utf8Path) -> Result<Utf8PathBuf> {
        if plain_path.as_str().is_empty() {
            return Ok(folder_path_to_cipher_and_dirid(self, plain_path)?.0);
        }

        let parent = plain_path.parent().unwrap_or_else(|| "".into());
        let name = plain_path.file_name().or_invalid()?;
        let (cipher_parent_path, dir_id) = folder_path_to_cipher_and_dirid(self, parent)?;
        let cipher_name = self.plain_name_to_cipher(&dir_id, name)?;
        Ok(cipher_parent_path.join(cipher_name))
    }
    fn create_temp_name(&self, path: &str, is_dir_iv: bool) -> Utf8PathBuf {
        temp_file_path(&self.backend.cipher_root, path, is_dir_iv)
    }
    fn remove_cached_plain_path(&self, plain_path: &str) {
        crate::default_remove_cached_plain_path(&self.backend, plain_path);
    }
    fn get_dir_iv_file(&self, cipher_folder_path: &Utf8Path) -> Utf8PathBuf {
        cipher_folder_path.join("dir.c9r")
    }
}

impl EncryptionLayout for CryptoMator<FsBackend> {
    fn list_dir_plain_names(
        &self,
        plain_path: &Utf8Path,
    ) -> Result<impl Iterator<Item = Result<(crate::FsDirEntry, Utf8PathBuf)>> + '_> {
        let (cipher_path, dir_id) = folder_path_to_cipher_and_dirid(self, plain_path)?;
        // let plain_path: Utf8PathBuf = plain_path.into();
        // let cipher_path = self.plain_path_to_cipher(&plain_path)?;
        // let dir_id = if plain_path == "" {
        //     "".into()
        // } else {
        //     read_dirid(&cipher_path)?
        // };
        // let cipher_path = self.dir_id_to_storage_path(&dir_id)?;
        log::debug!("read_dir on {}", &cipher_path);
        Ok(std::fs::read_dir(&cipher_path)?.filter_map(move |entry| {
            match map_dir_entry(self, &cipher_path, &dir_id, entry) {
                Ok(Some((plain_name, cipher_path))) => Some(Ok((plain_name, cipher_path))),
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            }
        }))
    }

    fn metadata(&self, plain_path: &str) -> std::io::Result<crate::Metadata> {
        let cipher_path = self.plain_path_to_cipher(plain_path.into()).or_invalid()?;
        log::debug!("metadata on [{plain_path}] : {cipher_path}");
        let mut metadata = self.lower_fs().metadata(&cipher_path)?;
        metadata
            .adjust(self, &cipher_path, plain_path.is_empty())
            .or_invalid()?;
        Ok(metadata)
    }

    fn mkdir(
        &self,
        plain_path: &str,
        permissions: crate::Permissions,
    ) -> std::io::Result<Metadata> {
        log::debug!("mkdir on {plain_path}");
        let plain_path: &Utf8Path = plain_path.into();
        let parent = plain_path.parent().unwrap_or_else(|| "".into());
        let name = plain_path.file_name().or_invalid()?;

        log::debug!("parent {parent} - name {name}");

        let (parent_dir_id, cipher_parent_path) = self.backend.access(|cache| {
            if let Some((parent_dir_id, cipher_parent_path)) = cache.get(parent.as_str()) {
                log::debug!("found {parent} in cache! {cipher_parent_path}");
                Ok::<_, std::io::Error>((
                    str::from_utf8(parent_dir_id).unwrap_or_default().into(),
                    cipher_parent_path.clone(),
                ))
            } else {
                let cipher_parent_path = self.plain_path_to_cipher(parent).or_invalid()?;
                log::debug!("computed cipher_parent_path for {parent} - {cipher_parent_path}");
                let parent_dir_id = read_dirid(&cipher_parent_path).or_invalid()?;
                Ok((parent_dir_id, cipher_parent_path))
            }
        })?;
        log::debug!("cipher parent path is {cipher_parent_path}");
        //let cipher_parent_path = self.plain_path_to_cipher(parent).or_invalid()?;
        //let parent_dir_id = read_dirid(&cipher_parent_path).or_invalid()?;
        let cipher_name = self
            .plain_name_to_cipher(parent_dir_id.as_bytes(), name)
            .or_invalid()?;
        log::debug!("cipher_name is {cipher_name}");
        let new_dir_iv = self.generate_diriv();
        let cipher_path = cipher_parent_path.join(cipher_name);
        log::debug!("cipher_path is {cipher_path}");
        self.lower_fs().mkdir(&cipher_path)?;
        let new_dir_iv_file = self.get_dir_iv_file(&cipher_path);
        log::debug!("new_dir_iv_file is {new_dir_iv_file}");
        self.lower_fs()
            .put(&new_dir_iv_file, &new_dir_iv)
            .or_invalid()?;

        self.mkdir_storage_path(str::from_utf8(&new_dir_iv).unwrap_or_default())
            .or_invalid()?;
        self.lower_fs().set_permissions(&cipher_path, permissions)
    }
    fn mknode(
        &self,
        plain_path: &str,
        permissions: crate::Permissions,
    ) -> std::io::Result<Metadata> {
        let cipher_path = self.plain_path_to_cipher(plain_path.into()).or_invalid()?;
        self.lower_fs()
            .put(&cipher_path, &self.generate_cipher_header().or_invalid()?)
            .or_invalid()?;
        self.lower_fs().set_permissions(&cipher_path, permissions)
    }
    fn remove_dir(&self, plain_path: &str) -> std::io::Result<()> {
        let cipher_path = self.plain_path_to_cipher(plain_path.into()).or_invalid()?;
        let dir_id = read_dirid(&cipher_path).or_invalid()?;

        let children_path = self.dir_id_to_storage_path(&dir_id).or_invalid()?;
        self.lower_fs()
            .remove_dir(&children_path, false)
            .inspect_err(|e| log::error!("cant rmdir on {children_path} - {e}"))?;
        self.lower_fs()
            .remove_dir(&cipher_path, true)
            .inspect_err(|e| log::error!("cant rmdir all on {cipher_path} - {e}"))?;
        self.remove_cached_plain_path(plain_path);
        Ok(())
    }
    fn remove(&self, plain_path: &str) -> std::io::Result<()> {
        let cipher_path = self.plain_path_to_cipher(plain_path.into()).or_invalid()?;
        let meta = self.lower_fs().metadata(&cipher_path)?;
        match meta.file_type {
            FileType::File => self.lower_fs().remove_file(&cipher_path),
            _ => self.lower_fs().remove_dir(&cipher_path, true),
        }
    }
    fn read_symlink(&self, plain_path: &str) -> std::io::Result<String> {
        let cipher_path = self.plain_path_to_cipher(plain_path.into()).or_invalid()?;
        let symlink_content = cipher_path.join("symlink.c9r");
        let data = self
            .lower_fs()
            .read(&symlink_content, 0, 1024)
            .or_invalid()?;
        let target = self.cipher_metavalue_to_plain(&data).or_invalid()?;
        Ok(str::from_utf8(&target).or_invalid()?.into())
    }
    fn create_symlink(&self, plain_path: &str, target: &str) -> std::io::Result<Metadata> {
        let cipher_path = self.plain_path_to_cipher(plain_path.into()).or_invalid()?;
        let cipher_target = self
            .plain_metavalue_to_cipher(target.as_bytes())
            .or_invalid()?;
        self.lower_fs().mkdir(&cipher_path)?;
        self.lower_fs()
            .put(&cipher_path.join("symlink.c9r"), &cipher_target)?;
        let mut meta = self.lower_fs().metadata(&cipher_path)?;
        meta.adjust(self, &cipher_path, false).or_invalid()?;
        Ok(meta)
    }
}

fn is_special_entry(name: &str) -> bool {
    name == "dirid.c9r"
}

trait AdujstMetadata {
    fn adjust<T: EncryptionTranslator>(
        &mut self,
        this: &T,
        path: &Utf8Path,
        is_root: bool,
    ) -> Result<()>;
}

impl AdujstMetadata for Metadata {
    fn adjust<T: EncryptionTranslator>(
        &mut self,
        this: &T,
        path: &Utf8Path,
        is_root: bool,
    ) -> Result<()> {
        if self.file_type == FileType::File {
            self.len = this.cipher_size_to_plain(self.len).or_invalid()?;
            self.blocks = 1 + self.len / T::PLAIN_BLOCK_LEN;
        } else if self.file_type == FileType::Directory {
            if !is_root {
                let dir = path.join("dir.c9r");
                if !std::fs::exists(&dir)? {
                    let symlink = path.join("symlink.c9r");
                    if std::fs::exists(&symlink)? {
                        self.file_type = FileType::SymLink;
                        self.permissions = 0o777_u16.into();
                    } else {
                        self.file_type = FileType::Other;
                    }
                }
            }
        } else {
            self.file_type = FileType::Other;
        }
        Ok(())
    }
}

fn map_dir_entry(
    this: &impl EncryptionLayout,
    cipher_path: &Utf8Path,
    dir_iv: &[u8],
    entry: Result<DirEntry, std::io::Error>,
) -> Result<Option<(FsDirEntry, Utf8PathBuf)>> {
    match entry {
        Ok(entry) => {
            let cipher_name = &entry.file_name();
            let cipher_name: String = cipher_name.to_string_lossy().into();
            let mut fs_dir_entry: FsDirEntry = entry.into();

            if let Some(metadata) = fs_dir_entry.metadata.as_mut() {
                metadata.adjust(this, &cipher_path.join(&cipher_name), false)?;
                if let Some(file_type) = fs_dir_entry.file_type.as_mut() {
                    *file_type = metadata.file_type;
                }
            }

            if is_special_entry(&cipher_name) {
                Ok(None)
            } else {
                let plain_name = this.cipher_name_to_plain(dir_iv, &cipher_name)?;
                Ok(Some((
                    fs_dir_entry.with_name(plain_name),
                    cipher_path.join(Utf8Path::new(&cipher_name)),
                )))
            }
        }
        Err(e) => Err(e)?,
    }
}
