#![cfg(unix)]

use anyhow::Result;
use rcryptfs::{SetBackgroundChild, is_dir_empty, wait_child_mounted};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use tempfile::tempdir;

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

fn mount_test_fs(cipher_root: &Path, mount_point: &Path, password: &str) -> Result<MountedFs> {
    let exe = std::env::var("CARGO_BIN_EXE_rcryptfs")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./target/debug/rcryptfs"));

    let mut child = Command::new(exe)
        .set_as_background_child()
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

#[test]
fn mount_allows_basic_file_roundtrip() {
    let cipher_dir = tempdir().unwrap();
    let mount_dir = tempdir().unwrap();
    let password = "test-password";

    rcryptfs::GoCryptFs::<rcryptfs::FsBackend>::init_with_default_params(
        camino::Utf8Path::from_path(cipher_dir.path()).unwrap(),
        password,
    )
    .unwrap();

    let mounted = mount_test_fs(cipher_dir.path(), mount_dir.path(), password).unwrap();

    let file_path = mounted.mount_point().join("hello.txt");
    let payload = b"hello through fuse";

    std::fs::write(&file_path, payload).unwrap();
    let read_back = std::fs::read(&file_path).unwrap();

    drop(mounted);

    assert_eq!(read_back, payload);
    assert!(is_dir_empty(mount_dir.path().try_into().unwrap()).unwrap());
}
