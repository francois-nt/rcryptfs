use super::*;

/// Physical paths used to represent one opaque encoded entry.
pub(super) struct EntryPaths {
    pub(super) content: VirtualPathBuf,
    pub(super) sidecar: Option<VirtualPathBuf>,
}

/// Physical changes required to rename one GoCryptFS entry.
pub(super) struct RenamePlan {
    pub(super) operations: Vec<RenameOperation>,
    pub(super) staged_sidecar: Option<(VirtualPathBuf, Vec<u8>)>,
    pub(super) cleanup_paths: Vec<VirtualPathBuf>,
}

/// Returns whether a raw GoCryptFS entry is internal to the representation.
pub(super) fn is_direct_internal_entry(name: &str) -> bool {
    name.starts_with("temp.")
        || name == GOCRYPTFS_DIRIV
        || name == "gocryptfs.conf"
        || (name.starts_with(GOCRYPTFS_LONGNAME_PREFIX)
            && name.ends_with(GOCRYPTFS_LONGNAME_SUFFIX))
}

/// Returns whether a raw entry stores content for a shortened name.
pub(super) fn is_long_name_content(name: &str) -> bool {
    name.starts_with(GOCRYPTFS_LONGNAME_PREFIX) && !name.ends_with(GOCRYPTFS_LONGNAME_SUFFIX)
}

impl<F> GoCryptFsEntryStorage<F> {
    /// Hashes an opaque encoded name using the configured GoCryptFS alphabet.
    pub(super) fn hash_long_name(&self, name: &str) -> String {
        let digest = Sha256::digest(name.as_bytes());
        let hash = if self.options.raw64 {
            URL_SAFE_NO_PAD.encode(digest)
        } else {
            URL_SAFE.encode(digest)
        };
        format!("{GOCRYPTFS_LONGNAME_PREFIX}{hash}")
    }

    /// Maps the final logical encoded component to its physical representation.
    pub(super) fn entry_paths(&self, path: &VirtualPath) -> EntryPaths {
        let Some(name) = path.file_name() else {
            return EntryPaths {
                content: path.to_owned(),
                sidecar: None,
            };
        };
        if name.len() <= usize::from(self.options.long_name_max) {
            return EntryPaths {
                content: path.to_owned(),
                sidecar: None,
            };
        }

        let stored_name = self.hash_long_name(name);
        let parent = path.parent().unwrap_or_else(VirtualPath::root);
        EntryPaths {
            content: parent.join(&stored_name),
            sidecar: Some(parent.join(format!("{stored_name}{GOCRYPTFS_LONGNAME_SUFFIX}"))),
        }
    }

    /// Returns the sidecar associated with an already-physical content path.
    pub(super) fn physical_sidecar_path(path: &VirtualPath) -> Option<VirtualPathBuf> {
        let name = path.file_name()?;
        is_long_name_content(name).then(|| {
            path.parent()
                .unwrap_or_else(VirtualPath::root)
                .join(format!("{name}{GOCRYPTFS_LONGNAME_SUFFIX}"))
        })
    }

    /// Validates that a GoCryptFS directory stores children in its visible entry.
    pub(super) fn validate_directory(directory: &StorageDirectory) -> std::io::Result<()> {
        if directory.entry_path != directory.contents_path {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "GoCryptFS directory entry and contents paths must match",
            ));
        }
        Ok(())
    }

    /// Plans an atomic representation rename and its temporary cleanup.
    pub(super) fn rename_plan(
        &self,
        old_path: &VirtualPath,
        new_path: &VirtualPath,
    ) -> std::io::Result<RenamePlan> {
        let old = self.entry_paths(old_path);
        let new = self.entry_paths(new_path);
        let mut operations = if old.content == new.content {
            Vec::new()
        } else {
            vec![RenameOperation::replace(old.content, new.content)]
        };
        let mut cleanup_paths = Vec::new();

        let staged_sidecar = if old.sidecar != new.sidecar {
            let staged = if let Some(new_sidecar) = new.sidecar {
                let name = new_path.file_name().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing entry name")
                })?;
                let staging = temp_file_path(&format!("rename-sidecar:{new_sidecar}"), false);
                operations.push(RenameOperation::ignore_existing(
                    staging.clone(),
                    new_sidecar,
                ));
                cleanup_paths.push(staging.clone());
                Some((staging, name.as_bytes().to_vec()))
            } else {
                None
            };

            if let Some(old_sidecar) = old.sidecar {
                let retired = temp_file_path(&format!("retired-sidecar:{old_sidecar}"), false);
                operations.push(RenameOperation::replace(old_sidecar, retired.clone()));
                cleanup_paths.push(retired);
            }
            staged
        } else {
            None
        };

        Ok(RenamePlan {
            operations,
            staged_sidecar,
            cleanup_paths,
        })
    }
}
