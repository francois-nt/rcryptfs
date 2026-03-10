use anyhow::{Context, Result};
use rustyline::DefaultEditor;
use std::io::Write;
use std::process::Command;

/// Reads password from terminal on Unix.
pub fn prompt_password(prompt: &str) -> Result<String> {
    std::io::stdout().flush()?;
    rpassword::prompt_password(prompt).context("Failed to read password")
}

/// Configures background child process session on Unix.
pub fn configure_background_command(cmd: &mut Command) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;

    // SAFETY: pre_exec is only used to call async-signal-safe libc::setsid before exec.
    unsafe {
        cmd.pre_exec(|| {
            let r = libc::setsid();
            if r == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

/// Reattaches stdin to /dev/tty when stdin was piped.
pub fn prepare_cli_stdin(stdin_is_piped: bool) -> Result<()> {
    if !stdin_is_piped {
        return Ok(());
    }

    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;

    // The password pipe has been consumed already; switch stdin back to the controlling terminal.
    let tty = OpenOptions::new().read(true).open("/dev/tty")?;
    let rc = unsafe { libc::dup2(tty.as_raw_fd(), libc::STDIN_FILENO) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error())
            .context("error while reattaching stdin to console");
    }

    Ok(())
}

/// Creates line editor for CLI mode.
pub fn create_line_editor() -> Result<DefaultEditor> {
    DefaultEditor::new().context("Failed to initialize interactive shell")
}
