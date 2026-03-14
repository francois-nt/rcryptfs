use crate::{OrIoError, platform};
use anyhow::{Result, bail};
use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdout, Stdio};

const BACKGROUND_ENV: &str = "RCRYPTFS_BACKGROUND_CHILD";

/// Returns whether the current process is the respawned background child.
pub fn is_background_child() -> bool {
    std::env::var_os(BACKGROUND_ENV).is_some()
}

/// Marks a command so the spawned process runs as the background child.
pub trait SetBackgroundChild {
    fn set_as_background_child(&mut self) -> &mut Self;
}

impl SetBackgroundChild for std::process::Command {
    fn set_as_background_child(&mut self) -> &mut Self {
        self.env(BACKGROUND_ENV, "1")
    }
}

/// Waits for the child process to report READY or KO on stdout.
pub fn wait_child_mounted(stdout: ChildStdout) -> Result<()> {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let line = line.trim_end();
    if line == "READY" {
        Ok(())
    } else {
        let message = line.strip_prefix("KO ").unwrap_or(line);
        bail!("{message}");
    }
}

/// Restarts the current process in background and sends the password over stdin.
pub fn respawn_in_background(password: &str) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;

    let mut cmd = std::process::Command::new(exe);
    cmd.args(std::env::args_os().skip(1));
    cmd.set_as_background_child();

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    platform::configure_background_command(&mut cmd)?;
    let mut child = cmd.spawn()?;
    let mut stdin = child.stdin.take().or_invalid()?;
    stdin.write_all(password.as_bytes())?;

    if let Some(stdout) = child.stdout.take() {
        match wait_child_mounted(stdout) {
            Ok(_) => {
                println!("Filesystem mounted and ready.");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        std::process::exit(1);
    }
}
