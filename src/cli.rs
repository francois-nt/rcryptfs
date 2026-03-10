use anyhow::{Context, Result};
use rcryptfs::{FileSystemHandler, FileType, FsDirEntry, FsTime, OpenCache};
use rustyline::error::ReadlineError;

use crate::platform;

// Runs the interactive CLI shell with in-memory history for this session.
pub fn run_cli_shell<C: OpenCache>(handler: &FileSystemHandler<C>) -> Result<()> {
    let mut editor = platform::create_line_editor()?;
    let mut cwd = String::new(); // root = ""

    loop {
        let prompt = format!("rcryptfs:{}> ", display_path(&cwd));
        match editor.readline(&prompt) {
            Ok(line) => {
                let input = line.trim();
                if input.is_empty() {
                    continue;
                }

                let _ = editor.add_history_entry(input);
                if !handle_cli_command(handler, &mut cwd, input) {
                    break;
                }
            }
            Err(ReadlineError::Eof) => {
                println!();
                break; // Ctrl+D
            }
            Err(ReadlineError::Interrupted) => {
                println!();
                continue; // Ctrl+C
            }
            Err(err) => return Err(err).context("CLI input failed"),
        }
    }

    Ok(())
}

// Executes one CLI command and returns false when shell should exit.
fn handle_cli_command<C: OpenCache>(
    handler: &FileSystemHandler<C>,
    cwd: &mut String,
    input: &str,
) -> bool {
    if input == "quit" || input == "exit" {
        return false;
    }

    let mut parts = input.split_whitespace();
    let cmd = parts.next().unwrap_or_default();

    match cmd {
        "ls" => {
            let arg = parts.next();
            if parts.next().is_some() {
                println!("usage: ls [path]");
                return true;
            }

            let target = match arg {
                Some(path) => resolve_path(cwd, path),
                None => cwd.clone(),
            };

            match handler.as_ref().read_dir(&target) {
                Ok(entries) => {
                    for element in entries {
                        println!("{}", format_entry(&element));
                    }
                }
                Err(e) => println!("ls: {}: {}", display_path(&target), e),
            }
        }
        "cd" => {
            let Some(path) = parts.next() else {
                println!("usage: cd <path>");
                return true;
            };
            if parts.next().is_some() {
                println!("usage: cd <path>");
                return true;
            }

            let target = resolve_path(cwd, path);
            match handler.as_ref().read_dir(&target) {
                Ok(_) => *cwd = target,
                Err(e) => println!("cd: {}: {}", display_path(&target), e),
            }
        }
        _ => println!("unknown command: {cmd}"),
    }

    true
}

// Resolves absolute/relative paths and normalizes '.' and '..'.
fn resolve_path(cwd: &str, input: &str) -> String {
    let mut stack: Vec<String> = if input.starts_with('/') {
        Vec::new()
    } else {
        cwd.split('/')
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    };

    for part in input.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                let _ = stack.pop();
            }
            _ => stack.push(part.to_string()),
        }
    }

    stack.join("/")
}

// Formats internal empty path as '/' for display.
fn display_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        format!("/{path}")
    }
}

// Formats one directory entry for CLI output.
fn format_entry(entry: &FsDirEntry) -> String {
    let file_type = match entry.file_type {
        Some(FileType::File) => "F",
        Some(FileType::Directory) => "D",
        Some(FileType::SymLink) => "L",
        _ => "O",
    };
    let rsize = if let Some(metadata) = &entry.metadata {
        let fs_time: FsTime = metadata.modified.into();
        format!("{} [{}]", metadata.len, fs_time)
    } else {
        String::default()
    };
    format!("{} {} {}", &file_type, &entry.file_name, &rsize)
}
