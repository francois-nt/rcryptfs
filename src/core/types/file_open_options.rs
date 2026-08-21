use super::Permissions;
use std::fs::OpenOptions;

/// Options for opening files.
#[derive(Default, Debug)]
pub struct FileOpenOptions {
    // generic
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub truncate: bool,
    pub create: bool,
    pub create_new: bool,
    pub permissions: Option<Permissions>,
}

impl FileOpenOptions {
    /// Checks if options are read-only.
    pub fn is_readonly(&self) -> bool {
        self.read
            && !self.write
            && !self.append
            && !self.truncate
            && !self.create
            && !self.create_new
    }

    /// Sets read option.
    pub fn read(&mut self, read: bool) -> &mut Self {
        self.read = read;
        self
    }

    /// Sets write option.
    pub fn write(&mut self, write: bool) -> &mut Self {
        self.write = write;
        self
    }

    /// Sets append option.
    pub fn append(&mut self, append: bool) -> &mut Self {
        self.append = append;
        self
    }

    /// Sets truncate option.
    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.truncate = truncate;
        self
    }

    /// Sets create option.
    pub fn create(&mut self, create: bool) -> &mut Self {
        self.create = create;
        self
    }

    /// Sets create_new option.
    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.create_new = create_new;
        self
    }

    /// Sets permissions.
    pub fn permissions(&mut self, permissions: Permissions) -> &mut Self {
        self.permissions = Some(permissions);
        self
    }

    /// Gets the mode from permissions.
    pub fn mode(&self) -> u16 {
        self.permissions.unwrap_or_default().into()
    }
}

impl From<FileOpenOptions> for OpenOptions {
    fn from(value: FileOpenOptions) -> Self {
        let mut this = Self::new();
        this.read(value.read)
            .write(value.write)
            .append(value.append)
            .truncate(value.truncate)
            .create(value.create)
            .create_new(value.create_new);
        #[cfg(unix)]
        {
            if let Some(permissions) = value.permissions {
                use std::os::unix::fs::OpenOptionsExt;
                this.mode(permissions.into());
            }
        }
        this
    }
}
