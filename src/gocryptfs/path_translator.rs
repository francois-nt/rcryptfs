use super::GoCryptFs;
use crate::{
    EncryptionTranslator, FsBackend, FsDirEntry, PathTranslator, Result, Utf8Path, Utf8PathBuf,
};
use anyhow::{Context, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::Digest;
use std::fs::DirEntry;

impl PathTranslator for GoCryptFs<FsBackend> {
    /// Converts a cipher path to its plain text equivalent.
    fn cipher_path_to_plain(&self, cipher_path: &Utf8Path) -> Result<Utf8PathBuf> {
        let relative_path = cipher_path.strip_prefix(&self.backend.cipher_root)?;
        let mut absolute_path = self.backend.cipher_root.clone();
        let mut result = Utf8PathBuf::default();
        for cipher_part in relative_path.iter() {
            let dir_iv = read_diriv(&absolute_path)?;
            let plain_part = self.cipher_name_to_plain(&dir_iv, cipher_part)?;
            result.push(plain_part);

            absolute_path.push(cipher_part);
        }
        Ok(result)
    }

    fn remove_cached_plain_path(&self, plain_path: &str) {
        self.backend.access(|cache| {
            cache.remove(plain_path);
            // Remove cached descendants in one range operation.
            let prefix = format!("{plain_path}/");
            let end = format!("{plain_path}0"); // b'0' == b'/' + 1
            let mut tail = cache.split_off(&prefix); // >= prefix
            let mut after = tail.split_off(&end); // >= end, so tail contains [prefix, end[

            cache.append(&mut after); // [prefix, end[ was removed.
        });
    }

    /// Converts a plain path to its cipher text equivalent.
    fn plain_path_to_cipher(&self, plain_path: &Utf8Path) -> Result<Utf8PathBuf> {
        self.backend.access(|cache| {
            if let Some((_, cipher_path)) = cache.get(plain_path.as_str()) {
                Ok(cipher_path.to_owned())
            } else {
                let parent_path = plain_path.parent().map(|p| p.as_str()).unwrap_or_default();
                let name = plain_path.file_name().unwrap_or_default();

                if parent_path.is_empty() && name.is_empty() {
                    return Ok(self.backend.cipher_root.clone());
                }

                if let Some((dir_iv, cipher_parent_path)) = cache.get(parent_path) {
                    let cipher_part = self.plain_name_to_cipher(dir_iv, name)?;
                    Ok(cipher_parent_path.as_path().join(cipher_part))
                } else {
                    let mut partial_plain_path = Utf8PathBuf::from("");
                    let mut absolute_path = self.backend.cipher_root.clone();
                    for plain_part in plain_path.iter() {
                        if let Some((dir_iv, cipher_parent)) =
                            cache.get(partial_plain_path.as_str())
                        {
                            let cipher_part = self.plain_name_to_cipher(dir_iv, plain_part)?;
                            absolute_path = cipher_parent.join(cipher_part);
                        } else {
                            let dir_iv = read_diriv(&absolute_path)?;

                            cache.insert(
                                partial_plain_path.as_str().into(),
                                (dir_iv.to_vec(), absolute_path.clone()),
                            );
                            let cipher_part = self.plain_name_to_cipher(&dir_iv, plain_part)?;
                            absolute_path.push(cipher_part);
                        }

                        partial_plain_path.push(plain_part);
                    }
                    Ok(absolute_path)
                }
            }
        })
        // let mut absolute_path = self.backend.cipher_root.clone();
        // for plain_part in plain_path.iter() {
        //     let dir_iv = read_diriv(&absolute_path)?;
        //     let cipher_part = self.plain_name_to_cipher(&dir_iv, plain_part)?;

        //     absolute_path.push(cipher_part);
        // }
        // Ok(absolute_path)
    }
    /// Creates a temporary name for a given path.
    fn create_temp_name(&self, path: &str, is_dir_iv: bool) -> Utf8PathBuf {
        // Temporary names are deterministic on purpose. This assumes a single
        // rcryptfs process owns a backend at a time; concurrent multi-process
        // access to the same encrypted root is undefined behavior.
        let path_digest = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(path.as_bytes()).as_slice());
        let mut new_name = String::from("temp.");
        new_name.push_str(&path_digest);

        let mut result = self.backend.cipher_root.join(new_name);
        if is_dir_iv {
            result.add_extension("diriv");
        }
        result
    }

    /// Lists directory entries with plain names.
    fn list_dir_plain_names(
        &self,
        plain_path: &Utf8Path,
    ) -> Result<impl Iterator<Item = Result<(FsDirEntry, Utf8PathBuf)>> + '_> {
        let plain_path: Utf8PathBuf = plain_path.into();
        let cipher_path = self.plain_path_to_cipher(&plain_path)?;
        let dir_iv = read_diriv(&cipher_path)?;
        //std::fs::metadata(path)
        Ok(std::fs::read_dir(&cipher_path)?.filter_map(move |entry| {
            match map_dir_entry(self, &cipher_path, &dir_iv, entry) {
                Ok(Some((plain_name, cipher_path))) => Some(Ok((plain_name, cipher_path))),
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            }
        }))
    }

    fn get_dir_iv_file(&self, cipher_folder_path: &Utf8Path) -> Utf8PathBuf {
        cipher_folder_path.join("gocryptfs.diriv")
    }
}

/// Reads the directory initialization vector from a cipher directory.
fn read_diriv(cipher_dir: &Utf8Path) -> Result<[u8; 16]> {
    let p = cipher_dir.join("gocryptfs.diriv");
    let data = std::fs::read(&p).context(format!("read {:?}", p))?;
    if data.len() != 16 {
        return Err(anyhow!("diriv has len {}, expected 16", data.len()));
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&data);
    Ok(iv)
}

/// Checks if a directory entry is a special gocryptfs file.
fn is_special_entry(name: &str) -> bool {
    name.starts_with("temp.")
        || name == "gocryptfs.diriv"
        || name == "gocryptfs.conf"
        || (name.starts_with("gocryptfs.longname.") && name.ends_with(".name"))
}

/// Maps a cipher directory entry to its plain equivalent.
fn map_dir_entry(
    this: &impl PathTranslator,
    cipher_path: &Utf8Path,
    dir_iv: &[u8],
    entry: Result<DirEntry, std::io::Error>,
) -> Result<Option<(FsDirEntry, Utf8PathBuf)>> {
    match entry {
        Ok(entry) => {
            let cipher_name = &entry.file_name();
            let cipher_name = cipher_name.to_string_lossy();
            let fs_dir_entry: FsDirEntry = entry.into();
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
