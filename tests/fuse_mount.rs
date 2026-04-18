#![cfg(unix)]

use anyhow::Result;
use filetime::{FileTime, set_file_times};
use rcryptfs::core::{FsBackend, Utf8Path, is_dir_empty};
use rcryptfs::{CryptoMator, GoCryptFs, SetBackgroundChild, wait_child_mounted};
use std::fmt::Debug;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use tempfile::tempdir;
extern crate log;

// Logger used by FUSE mode to print runtime errors to stdout.
impl log::Log for ConsoleLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        eprintln!("{}: {}: {}", record.target(), record.level(), record.args());
    }

    fn flush(&self) {}
}

// Minimal stdout logger implementation.
struct ConsoleLogger;
static LOGGER: ConsoleLogger = ConsoleLogger;

#[derive(Clone, Copy, Debug)]
enum BackendKind {
    GoCryptFs,
    CryptoMator,
}

impl BackendKind {
    const ALL: [Self; 2] = [Self::GoCryptFs, Self::CryptoMator];

    fn name(self) -> &'static str {
        match self {
            Self::GoCryptFs => "gocryptfs",
            Self::CryptoMator => "cryptomator",
        }
    }

    fn init(self, cipher_root: &Utf8Path, password: &str) {
        match self {
            Self::GoCryptFs => {
                GoCryptFs::<FsBackend>::init_with_default_params(cipher_root, password).unwrap();
            }
            Self::CryptoMator => {
                CryptoMator::<FsBackend>::init_with_default_params(cipher_root, password).unwrap();
            }
        }
    }

    fn unsupported_xattr_errnos(self) -> &'static [i32] {
        match self {
            Self::GoCryptFs => &[],
            // Tighten this to ENOSYS once Cryptomator xattrs are mapped explicitly in FUSE.
            Self::CryptoMator => &[libc::ENOTSUP],
        }
    }
}

/// Owns a mounted test filesystem and tears it down on drop.
struct MountedFs {
    mount_point: PathBuf,
    child: Child,
}

impl MountedFs {
    fn mount_point(&self) -> &Path {
        &self.mount_point
    }
}

impl Drop for MountedFs {
    fn drop(&mut self) {
        let _ = try_unmount(&self.mount_point).or_else(|_| self.child.kill());
        let _ = self.child.wait();
    }
}

/// Tries to unmount a FUSE mountpoint with the available fusermount helper.
fn try_unmount(mount_point: &Path) -> std::io::Result<()> {
    for tool in ["fusermount3", "fusermount"] {
        let status = Command::new(tool).arg("-u").arg(mount_point).status();
        if let Ok(status) = status
            && status.success()
        {
            println!("unmounted {:?}", mount_point);
            return Ok(());
        }
    }
    Err(std::io::Error::other(
        "failed to unmount with fusermount3/fusermount",
    ))
}

fn mount_backend(
    backend: BackendKind,
    password: &str,
) -> Result<(tempfile::TempDir, tempfile::TempDir, MountedFs)> {
    let cipher_dir = tempdir().unwrap();
    let mount_dir = tempdir().unwrap();

    backend.init(Utf8Path::from_path(cipher_dir.path()).unwrap(), password);
    let mounted = mount_test_fs(cipher_dir.path(), mount_dir.path(), password)?;

    Ok((cipher_dir, mount_dir, mounted))
}

fn read_dir_names(path: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn assert_errnos<T: Debug>(result: std::io::Result<T>, expected: &[i32], context: &str) {
    let err = result.unwrap_err();
    let errno = err.raw_os_error().unwrap_or_default();
    assert!(
        expected.contains(&errno),
        "{context}: got errno {errno}, expected one of {expected:?}: {err}"
    );
}

/// Spawns rcryptfs mount and waits for the READY handshake.
fn mount_test_fs(cipher_root: &Path, mount_point: &Path, password: &str) -> Result<MountedFs> {
    let exe = env!("CARGO_BIN_EXE_rcryptfs");
    //.map(PathBuf::from)
    //.unwrap_or_else(|_| PathBuf::from("./target/debug/rcryptfs"));

    let mut child = Command::new(exe)
        .set_as_background_child()
        //.env("TEST_VERBOSE", "1")
        .arg("mount")
        .arg(cipher_root)
        .arg(mount_point)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{password}")?;

    let stdout = child.stdout.take().unwrap();
    wait_child_mounted(stdout)?;

    Ok(MountedFs {
        mount_point: mount_point.to_path_buf(),
        child,
    })
}

/// Verifies a basic file roundtrip through the mounted FUSE filesystem on both backends.
#[test]
fn mount_allows_basic_file_roundtrip_for_all_backends() {
    let password = "test-password";

    for backend in BackendKind::ALL {
        let (_cipher_dir, mount_dir, mounted) = mount_backend(backend, password).unwrap();

        let file_path = mounted.mount_point().join("hello.txt");
        let payload = b"hello through fuse";

        std::fs::write(&file_path, payload).unwrap();
        let read_back = std::fs::read(&file_path).unwrap();

        drop(mounted);

        assert_eq!(read_back, payload, "backend={}", backend.name());
        assert!(
            is_dir_empty(mount_dir.path().try_into().unwrap()).unwrap(),
            "backend={}",
            backend.name()
        );
    }
}

#[test]
fn mount_respects_create_new_for_all_backends() {
    let password = "test-password";

    for backend in BackendKind::ALL {
        let (_cipher_dir, mount_dir, mounted) = mount_backend(backend, password).unwrap();
        let file_path = mounted.mount_point().join("exclusive.txt");

        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path)
            .unwrap();

        let err = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path)
            .unwrap_err();

        drop(mounted);

        assert_eq!(
            err.kind(),
            std::io::ErrorKind::AlreadyExists,
            "backend={}",
            backend.name()
        );
        assert!(
            is_dir_empty(mount_dir.path().try_into().unwrap()).unwrap(),
            "backend={}",
            backend.name()
        );
    }
}

#[ignore]
#[test]
fn mount_supports_directory_listing_rename_and_removal_for_all_backends() {
    let password = "test-password";
    log::set_logger(&LOGGER)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .unwrap();
    log::set_max_level(log::LevelFilter::Debug);
    for backend in BackendKind::ALL {
        let (_cipher_dir, mount_dir, mounted) = mount_backend(backend, password).unwrap();
        let dir_path = mounted.mount_point().join("docs");
        let nested_file = dir_path.join("note.txt");
        let renamed_dir = mounted.mount_point().join("archive");
        let renamed_nested_file = renamed_dir.join("note.txt");

        std::fs::create_dir(&dir_path).unwrap();
        std::fs::write(&nested_file, b"nested through fuse").unwrap();

        assert_eq!(
            read_dir_names(mounted.mount_point()),
            vec!["docs".to_string()]
        );

        std::fs::rename(&dir_path, &renamed_dir).unwrap();
        eprintln!("backend is {}", backend.name());
        assert!(!dir_path.exists(), "backend={}", backend.name());
        assert_eq!(
            std::fs::read(&renamed_nested_file).unwrap(),
            b"nested through fuse",
            "backend={}",
            backend.name()
        );
        assert_eq!(
            read_dir_names(mounted.mount_point()),
            vec!["archive".to_string()],
            "backend={}",
            backend.name()
        );

        std::fs::remove_file(&renamed_nested_file).unwrap();
        std::fs::remove_dir(&renamed_dir).unwrap();
        assert!(
            read_dir_names(mounted.mount_point()).is_empty(),
            "backend={}",
            backend.name()
        );

        drop(mounted);
        assert!(
            is_dir_empty(mount_dir.path().try_into().unwrap()).unwrap(),
            "backend={}",
            backend.name()
        );
    }
}

#[test]
fn mount_supports_symlink_roundtrip_and_rename_for_all_backends() {
    let password = "test-password";

    for backend in BackendKind::ALL {
        let (_cipher_dir, mount_dir, mounted) = mount_backend(backend, password).unwrap();
        let target_path = mounted.mount_point().join("target.txt");
        let link_path = mounted.mount_point().join("link.txt");
        let renamed_link_path = mounted.mount_point().join("renamed-link.txt");

        std::fs::write(&target_path, b"symlink target").unwrap();
        symlink("target.txt", &link_path).unwrap();

        assert_eq!(
            std::fs::read_link(&link_path).unwrap(),
            PathBuf::from("target.txt"),
            "backend={}",
            backend.name()
        );
        assert_eq!(
            std::fs::read(&link_path).unwrap(),
            b"symlink target",
            "backend={}",
            backend.name()
        );

        std::fs::rename(&link_path, &renamed_link_path).unwrap();

        assert_eq!(
            std::fs::read_link(&renamed_link_path).unwrap(),
            PathBuf::from("target.txt"),
            "backend={}",
            backend.name()
        );
        assert_eq!(
            std::fs::read(&renamed_link_path).unwrap(),
            b"symlink target",
            "backend={}",
            backend.name()
        );

        std::fs::remove_file(&renamed_link_path).unwrap();
        assert!(target_path.exists(), "backend={}", backend.name());

        drop(mounted);
        assert!(
            is_dir_empty(mount_dir.path().try_into().unwrap()).unwrap(),
            "backend={}",
            backend.name()
        );
    }
}

#[test]
fn mount_supports_truncate_chmod_and_utimens_for_all_backends() {
    let password = "test-password";

    for backend in BackendKind::ALL {
        let (_cipher_dir, mount_dir, mounted) = mount_backend(backend, password).unwrap();
        let file_path = mounted.mount_point().join("mutable.txt");

        std::fs::write(&file_path, b"abcdefghijklmnopqrstuvwxyz").unwrap();

        let file = OpenOptions::new().write(true).open(&file_path).unwrap();
        file.set_len(5).unwrap();
        drop(file);

        assert_eq!(
            std::fs::read(&file_path).unwrap(),
            b"abcde",
            "backend={}",
            backend.name()
        );

        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let mode = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "backend={}", backend.name());

        let atime = FileTime::from_unix_time(1_700_000_000, 0);
        let mtime = FileTime::from_unix_time(1_700_000_123, 0);
        set_file_times(&file_path, atime, mtime).unwrap();

        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            FileTime::from_last_access_time(&metadata).unix_seconds(),
            atime.unix_seconds(),
            "backend={}",
            backend.name()
        );
        assert_eq!(
            FileTime::from_last_modification_time(&metadata).unix_seconds(),
            mtime.unix_seconds(),
            "backend={}",
            backend.name()
        );

        drop(mounted);
        assert!(
            is_dir_empty(mount_dir.path().try_into().unwrap()).unwrap(),
            "backend={}",
            backend.name()
        );
    }
}

#[test]
fn mount_supports_backend_specific_xattr_behavior_for_all_backends() {
    let password = "test-password";

    for backend in BackendKind::ALL {
        let (_cipher_dir, mount_dir, mounted) = mount_backend(backend, password).unwrap();
        let file_path = mounted.mount_point().join("attrs.txt");

        std::fs::write(&file_path, b"attrs").unwrap();

        match backend {
            BackendKind::GoCryptFs => {
                xattr::set(&file_path, "user.demo", b"value").unwrap();
                assert_eq!(
                    xattr::get(&file_path, "user.demo").unwrap(),
                    Some(b"value".to_vec())
                );

                let names: Vec<_> = xattr::list(&file_path)
                    .unwrap()
                    .map(|name| name.to_string_lossy().into_owned())
                    .collect();
                assert!(
                    names.iter().any(|name| name == "user.demo"),
                    "backend={}",
                    backend.name()
                );

                xattr::remove(&file_path, "user.demo").unwrap();
                assert_eq!(xattr::get(&file_path, "user.demo").unwrap(), None);
            }
            BackendKind::CryptoMator => {
                let expected = backend.unsupported_xattr_errnos();
                assert_errnos(
                    xattr::set(&file_path, "user.demo", b"value"),
                    expected,
                    "setxattr",
                );
                assert_errnos(xattr::get(&file_path, "user.demo"), expected, "getxattr");
                assert_errnos(
                    xattr::list(&file_path).map(|it| it.count()),
                    expected,
                    "listxattr",
                );
                assert_errnos(
                    xattr::remove(&file_path, "user.demo"),
                    expected,
                    "removexattr",
                );
            }
        }

        drop(mounted);
        assert!(
            is_dir_empty(mount_dir.path().try_into().unwrap()).unwrap(),
            "backend={}",
            backend.name()
        );
    }
}
