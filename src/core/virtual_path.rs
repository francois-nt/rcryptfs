use std::{borrow::Borrow, fmt, ops::Deref};

/// Borrowed UTF-8 path whose only separator is the Unix slash.
#[repr(transparent)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtualPath(str);

impl VirtualPath {
    /// Reinterprets a UTF-8 string as a Unix path without platform-dependent parsing.
    pub fn new(path: &str) -> &Self {
        // SAFETY: VirtualPath has the same representation as str.
        unsafe { &*(path as *const str as *const Self) }
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

impl AsRef<VirtualPath> for VirtualPath {
    fn as_ref(&self) -> &VirtualPath {
        self
    }
}

impl From<String> for VirtualPathBuf {
    fn from(path: String) -> Self {
        Self(path)
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
}
