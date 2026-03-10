use anyhow::{Context, Result};
use rustyline::{Behavior, Config, DefaultEditor};
use std::io::Write;
use std::process::Command;

/// Temporarily switches Windows console code pages to UTF-8.
struct ConsoleCodePageGuard {
    input_cp: u32,
    output_cp: u32,
}

impl Drop for ConsoleCodePageGuard {
    fn drop(&mut self) {
        // SAFETY: restoring console code pages is a direct WinAPI call with values captured earlier.
        unsafe {
            let _ = windows_sys::Win32::System::Console::SetConsoleCP(self.input_cp);
            let _ = windows_sys::Win32::System::Console::SetConsoleOutputCP(self.output_cp);
        }
    }
}

/// Forces console input/output code page to UTF-8 and restores on drop.
fn set_utf8_console_codepage() -> std::io::Result<ConsoleCodePageGuard> {
    let input_cp = unsafe { windows_sys::Win32::System::Console::GetConsoleCP() };
    let output_cp = unsafe { windows_sys::Win32::System::Console::GetConsoleOutputCP() };

    if input_cp == 0 || output_cp == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { windows_sys::Win32::System::Console::SetConsoleCP(65001) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { windows_sys::Win32::System::Console::SetConsoleOutputCP(65001) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(ConsoleCodePageGuard {
        input_cp,
        output_cp,
    })
}

/// Reads password from terminal on Windows with UTF-8 console guard.
pub fn prompt_password(prompt: &str) -> Result<String> {
    let _cp_guard =
        set_utf8_console_codepage().context("Failed to switch Windows console to UTF-8")?;

    std::io::stdout().flush()?;
    rpassword::prompt_password(prompt).context("Failed to read password")
}

/// No-op on Windows for background command preparation.
pub fn configure_background_command(_cmd: &mut Command) -> std::io::Result<()> {
    Ok(())
}

/// No-op on Windows for stdin reattach in CLI mode.
pub fn prepare_cli_stdin(_stdin_is_piped: bool) -> Result<()> {
    Ok(())
}

/// Creates line editor configured for Windows terminal behavior.
pub fn create_line_editor() -> Result<DefaultEditor> {
    // PreferTerm lets rustyline talk to the console directly instead of relying on stdio.
    let config = Config::builder().behavior(Behavior::PreferTerm).build();
    DefaultEditor::with_config(config).context("Failed to initialize interactive shell")
}
