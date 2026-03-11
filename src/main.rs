#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
use anyhow::{Context, Result, bail};
use camino::Utf8Path;
use clap::{Parser, ValueEnum};
use rcryptfs::{
    FileCache, FileSystemBuilder, FileSystemFactory, FileSystemHandler, FsBackend, GoCryptFs,
};
#[cfg(not(windows))]
use std::ffi::OsStr;
use std::io::{IsTerminal, Write};
use std::process::Stdio;

mod cli;
mod platform;

extern crate log;

// Logger used by FUSE mode to print runtime errors to stdout.
impl log::Log for ConsoleLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        println!("{}: {}: {}", record.target(), record.level(), record.args());
    }

    fn flush(&self) {}
}

// Minimal stdout logger implementation.
struct ConsoleLogger;
static LOGGER: ConsoleLogger = ConsoleLogger;

#[derive(Copy, Clone, Debug, ValueEnum)]
/// Supported backend formats for repository initialization.
enum InitMode {
    #[value(name = "gocryptfs")]
    GoCryptFS,
    Other,
}

#[derive(Parser)]
#[command(long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

impl Args {
    fn folder_path(&self) -> &str {
        match &self.command {
            Command::Init(args) => &args.folder_path,
            Command::Cli(args) => &args.folder_path,
            Command::Mount(args) => &args.folder_path,
        }
    }
}

#[derive(clap::Subcommand)]
enum Command {
    Init(InitArgs),
    Mount(MountArgs),
    Cli(CliArgs),
}

#[derive(Parser)]
struct InitArgs {
    /// local encrypted folder
    folder_path: String,

    /// Initialize encrypted directory
    #[arg(value_enum)]
    init_mode: InitMode,
}

#[derive(Parser)]
struct MountArgs {
    /// local encrypted folder
    folder_path: String,

    /// mount point
    mount_point: String,

    /// set the number of background threads - use AUTO for default parallelism
    #[arg(short, long, value_name = "AUTO|number_of_threads")]
    num_threads: Option<String>,

    /// foreground operation
    #[arg(long, short)]
    foreground: bool,

    /// pass options to fuse backend
    #[arg(short = 'o', action = clap::ArgAction::Append)]
    fuse_opts: Vec<String>,
}

#[derive(Parser)]
struct CliArgs {
    /// local encrypted folder
    folder_path: String,
}

#[derive(Parser)]
#[command(long_about = None)]
struct Args0 {
    /// local encrypted folder
    folder_path: String,

    /// set the number of background threads - use AUTO for default parallelism
    #[arg(short, long, value_name = "AUTO|number_of_threads")]
    num_threads: Option<String>,
    /// foreground operation
    #[arg(long, short)]
    foreground: bool,

    /// Initialize encrypted directory
    #[arg(long, conflicts_with = "mount_point", value_name = "CRYPTFS_TYPE")]
    init: Option<InitMode>,

    /// pass options to fuse backend
    #[arg(short = 'o', action = clap::ArgAction::Append)]
    fuse_opts: Vec<String>,

    /// CLI mode (no mount point)
    #[arg(long = "cli", conflicts_with_all = ["mount_point", "init"])]
    cli_mode: bool,

    /// mount point (ex: /mnt/data)
    #[arg(
        value_name = "MOUNT_POINT",
        required_unless_present = "cli_mode",
        required_unless_present = "init"
    )]
    mount_point: Option<String>,
}

fn input_password(prompt: &str) -> Result<String> {
    platform::prompt_password(prompt)
}

#[cfg(not(windows))]
/// Parses thread count from CLI and supports AUTO.
fn parse_number_of_threads(value: &str) -> Option<usize> {
    if value.eq_ignore_ascii_case("auto") {
        Some(
            std::thread::available_parallelism()
                .map(|v| v.into())
                .unwrap_or_default(),
        )
    } else {
        value
            .parse()
            .inspect_err(|e| log::error!("error in num threads {e}"))
            .ok()
    }
}

const BG_ENV: &str = "RCRYPTFS_BACKGROUND_CHILD";

/// Restarts the current process in background and sends the password over stdin.
fn respawn_in_background(password: &str) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;

    let mut cmd = std::process::Command::new(exe);
    cmd.args(std::env::args_os().skip(1));
    cmd.env(BG_ENV, "1");

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    platform::configure_background_command(&mut cmd)?;
    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(password.as_bytes())?;
    }
    std::process::exit(0);
}

/// Reads the background password from stdin once at process startup.
fn read_password_from_stdin() -> Result<String> {
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .context("Failed to read password from stdin")?;
    Ok(password.trim_end_matches(&['\r', '\n'][..]).to_string())
}

/// Formats a 32-byte master key as two grouped hex lines for terminal display.
fn format_32_bytes(data: &[u8]) -> (String, String) {
    assert_eq!(data.len(), 32);

    let first = data[..16]
        .chunks(4)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-");

    let second = data[16..]
        .chunks(4)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-");

    (first, second)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let folder_path = Utf8Path::new(args.folder_path());

    match &args.command {
        Command::Init(init_args) => {
            let password = if stdin_is_piped() {
                read_password_from_stdin()?
            } else {
                let password = platform::prompt_password(
                    "Choose a password for protecting your files.\nPassword: ",
                )?;
                let repeated_password = platform::prompt_password("Repeat: ")?;
                if password != repeated_password {
                    bail!("not the same password!");
                }
                password
            };

            match init_args.init_mode {
                InitMode::GoCryptFS => {
                    // Print the generated master key once so it can be stored offline for recovery.
                    let master_key =
                        GoCryptFs::<FsBackend>::init_with_default_params(folder_path, &password)?;
                    println!("\nYour master key is:\n");
                    let (first, second) = format_32_bytes(&master_key);
                    println!("    {first}-\n    {second}\n");
                    println!(
                        "If the gocryptfs.conf file becomes corrupted or you ever forget your password,"
                    );
                    println!(
                        "there is only one hope for recovery: The master key. Print it to a piece of"
                    );
                    println!("paper and store it in a drawer. This message is only printed once.");
                    println!("The gocryptfs filesystem has been created successfully.");
                    println!(
                        "You can now mount it using: rcryptfs {} MOUNTPOINT",
                        folder_path
                    );
                }
                _ => {
                    // do nothing for the moment
                }
            };
        }

        Command::Mount(mount_args) => {
            let password = if stdin_is_piped() {
                read_password_from_stdin()?
            } else {
                input_password("Enter password: ")?
            };
            let cryptfs = FileSystemFactory::build(folder_path, &password, FileCache::default())?;

            let is_background_child = std::env::var_os(BG_ENV).is_some();
            // Validate the password before respawning so errors are still reported in the foreground process.
            if !mount_args.foreground && !is_background_child {
                respawn_in_background(&password)?;
            }
            let handler: FileSystemHandler<rcryptfs::CacheLock> = cryptfs.into();
            log::set_logger(&LOGGER).map_err(|e| anyhow::anyhow!("{e}"))?;
            log::set_max_level(log::LevelFilter::Error);

            #[cfg(not(windows))]
            {
                let num_threads = mount_args
                    .num_threads
                    .as_ref()
                    .and_then(|v| parse_number_of_threads(v))
                    .unwrap_or_default(); // default is 0

                println!("num threads is {num_threads}");
                let mut fuse_args = Vec::with_capacity(mount_args.fuse_opts.len() * 2 + 2);
                fuse_args.push(OsStr::new("-o"));
                fuse_args.push(OsStr::new("fsname=rcryptfs"));
                for o in &mount_args.fuse_opts {
                    fuse_args.push(OsStr::new("-o"));
                    fuse_args.push(OsStr::new(o));
                }

                fuse_mt::mount(
                    fuse_mt::FuseMT::new(handler, num_threads),
                    &mount_args.mount_point,
                    &fuse_args,
                )?;
            }
        }
        Command::Cli(_) => {
            let password = if stdin_is_piped() {
                #[cfg(windows)]
                anyhow::bail!("stdin cant be piped in cli mode!");
                #[cfg(not(windows))]
                read_password_from_stdin()?
            } else {
                input_password("Enter password: ")?
            };
            let cryptfs = FileSystemFactory::build(folder_path, &password, FileCache::default())?;
            let handler: FileSystemHandler<rcryptfs::CacheLock> = cryptfs.into();
            // CLI mode reuses stdin after password entry, so the platform layer restores an interactive input when needed.
            platform::prepare_cli_stdin(stdin_is_piped())?;
            cli::run_cli_shell(&handler)?;
        }
    };

    Ok(())
}

/// Detects whether stdin comes from a pipe or from an interactive terminal.
fn stdin_is_piped() -> bool {
    !std::io::stdin().is_terminal()
}
