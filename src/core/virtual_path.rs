use camino::{Utf8Path, Utf8PathBuf};
use std::{borrow::Borrow, fmt, ops::Deref, str::FromStr};

/// Borrowed UTF-8 path whose only separator is the Unix slash.
#[repr(transparent)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtualPath(str);

impl VirtualPath {
    /// Returns the virtual filesystem root.
    pub fn root<'a>() -> &'a Self {
        Self::new("")
    }

    /// Reinterprets a UTF-8 string as a Unix path without platform-dependent parsing.
    pub fn new<S: AsRef<str> + ?Sized>(path: &S) -> &Self {
        // SAFETY: VirtualPath has the same representation as str.
        unsafe { &*(path.as_ref() as *const str as *const Self) }
    }

    /// Returns the underlying UTF-8 representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether this path represents the virtual root.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over non-empty components separated exclusively by slash.
    pub fn components(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.0.split('/').filter(|component| !component.is_empty())
    }

    /// Iterates over this path's Unix components.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.components()
    }

    /// Returns the parent path, using an empty path for a root-level entry.
    pub fn parent(&self) -> Option<&Self> {
        let path = self.0.trim_end_matches('/');
        if path.is_empty() {
            return None;
        }
        Some(Self::new(
            path.rsplit_once('/').map_or("", |(parent, _)| parent),
        ))
    }

    /// Returns the final non-empty component.
    pub fn file_name(&self) -> Option<&str> {
        self.iter().next_back()
    }

    /// Appends one path using a Unix slash separator.
    pub fn join(&self, path: impl AsRef<str>) -> VirtualPathBuf {
        let mut result = self.to_owned();
        result.push(path);
        result
    }
}

/// Joins virtual paths below native UTF-8 roots.
pub trait JoinVirtualPath {
    /// Converts a virtual path into a native path below this root.
    ///
    /// Leading slashes refer to the virtual root. Parent components are
    /// normalized, and paths escaping above the root are rejected. This
    /// operation is lexical and does not resolve native symlinks.
    fn join_virtual_path(&self, path: &VirtualPath) -> std::io::Result<Utf8PathBuf>;
}

impl JoinVirtualPath for Utf8Path {
    fn join_virtual_path(&self, path: &VirtualPath) -> std::io::Result<Utf8PathBuf> {
        let mut result = self.to_owned();
        let mut depth = 0usize;
        for component in path.components() {
            if component == "." {
                continue;
            }
            if component == ".." {
                if depth == 0 {
                    return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                }
                result.pop();
                depth -= 1;
                continue;
            }
            if component.contains('\0') {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
            let native_component = Utf8Path::new(component);
            if native_component.file_name() != Some(component) {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
            result.push(native_component);
            depth += 1;
        }
        Ok(result)
    }
}

impl AsRef<VirtualPath> for VirtualPath {
    fn as_ref(&self) -> &VirtualPath {
        self
    }
}

impl<'a> From<&'a str> for &'a VirtualPath {
    fn from(s: &'a str) -> &'a VirtualPath {
        VirtualPath::new(s)
    }
}

impl fmt::Debug for VirtualPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, formatter)
    }
}

impl fmt::Display for VirtualPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl ToOwned for VirtualPath {
    type Owned = VirtualPathBuf;

    fn to_owned(&self) -> Self::Owned {
        VirtualPathBuf(self.0.to_owned())
    }
}

/// Owned UTF-8 path whose only separator is the Unix slash.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtualPathBuf(String);

impl VirtualPathBuf {
    /// Returns this owned path as a borrowed Unix path.
    pub fn as_path(&self) -> &VirtualPath {
        VirtualPath::new(&self.0)
    }

    /// Returns the underlying UTF-8 representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Appends one path using a Unix slash separator.
    pub fn push(&mut self, path: impl AsRef<str>) {
        let path = path.as_ref();
        if path.is_empty() {
            return;
        }
        if !self.0.is_empty() && !self.0.ends_with('/') {
            self.0.push('/');
        }
        self.0.push_str(path.trim_start_matches('/'));
    }
}

impl Deref for VirtualPathBuf {
    type Target = VirtualPath;

    fn deref(&self) -> &Self::Target {
        self.as_path()
    }
}

impl Borrow<VirtualPath> for VirtualPathBuf {
    fn borrow(&self) -> &VirtualPath {
        self.as_path()
    }
}

impl AsRef<VirtualPath> for VirtualPathBuf {
    fn as_ref(&self) -> &VirtualPath {
        self.as_path()
    }
}

impl From<String> for VirtualPathBuf {
    fn from(path: String) -> Self {
        Self(path)
    }
}

impl FromStr for VirtualPathBuf {
    type Err = core::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(VirtualPathBuf::from(s))
    }
}

impl From<&str> for VirtualPathBuf {
    fn from(path: &str) -> Self {
        Self(path.to_owned())
    }
}

impl From<&VirtualPath> for VirtualPathBuf {
    fn from(path: &VirtualPath) -> Self {
        path.to_owned()
    }
}

impl fmt::Debug for VirtualPathBuf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_path(), formatter)
    }
}

impl fmt::Display for VirtualPathBuf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_path(), formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn backslash_is_not_a_separator() {
        let components = VirtualPath::new(r"parent\child/file")
            .components()
            .collect::<Vec<_>>();

        assert_eq!(components, vec![r"parent\child", "file"]);
    }

    #[test]
    fn parent_and_file_name_use_unix_separators() {
        let path = VirtualPath::new(r"parent\child/file");

        assert_eq!(path.parent(), Some(VirtualPath::new(r"parent\child")));
        assert_eq!(path.file_name(), Some("file"));
    }

    #[test]
    fn join_uses_a_slash() {
        let path = VirtualPath::new("parent").join("child");

        assert_eq!(path.as_str(), "parent/child");
    }

    #[test]
    fn root_is_empty() {
        assert!(VirtualPath::root().is_empty());
    }

    #[test]
    fn join_virtual_path_normalizes_root_and_parent_components() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();

        assert_eq!(
            root.join_virtual_path(VirtualPath::new("/hello")).unwrap(),
            root.join("hello")
        );
        assert_eq!(
            root.join_virtual_path(VirtualPath::new("a/b/../hello"))
                .unwrap(),
            root.join("a/hello")
        );
    }

    #[test]
    fn join_virtual_path_rejects_parent_components_above_root() {
        let temp_dir = tempdir().unwrap();
        let root = Utf8Path::from_path(temp_dir.path()).unwrap().to_owned();

        assert!(
            root.join_virtual_path(VirtualPath::new("../hello"))
                .is_err()
        );
        assert!(
            root.join_virtual_path(VirtualPath::new("a/../../hello"))
                .is_err()
        );
    }
}
