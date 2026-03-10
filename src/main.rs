use anyhow::{Context, Result};
use camino::Utf8Path;
use clap::Parser;
use rcryptfs::{FileCache, FileSystemBuilder, FileSystemFactory, FileSystemHandler};
#[cfg(not(windows))]
use std::ffi::OsStr;
use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

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

#[derive(Parser)]
#[command(long_about = None)]
struct Args {
    /// local encrypted folder
    folder_path: String,

    /// set the number of background threads - use AUTO for default parallelism
    #[arg(short, long, value_name = "AUTO|number_of_threads")]
    num_threads: Option<String>,
    /// foreground operation
    #[arg(long, short)]
    foreground: bool,

    /// pass options to fuse backend
    #[arg(short = 'o', action = clap::ArgAction::Append)]
    fuse_opts: Vec<String>,

    /// CLI mode (no mount point)
    #[arg(long = "cli", conflicts_with = "mount_point")]
    cli_mode: bool,

    /// mount point (ex: /mnt/data)
    #[arg(value_name = "MOUNT_POINT", required_unless_present = "cli_mode")]
    mount_point: Option<String>,
}

fn input_password(prompt: &str) -> Result<String> {
    platform::prompt_password(prompt)
}

#[cfg(not(windows))]
/// Parses thread count from CLI and supports AUTO.
fn parse_number_of_threads(value: String) -> Option<usize> {
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

    let mut cmd = Command::new(exe);
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

fn main() -> Result<()> {
    let args = Args::parse();
    let folder_path = Utf8Path::new(&args.folder_path);
    let is_background_child = std::env::var_os(BG_ENV).is_some();
    if stdin_is_piped() && args.cli_mode {
        // CLI mode needs stdin for interactive commands, so password piping is rejected here.
        anyhow::bail!("stdin cant be piped in cli mode!");
    }
    let password = if stdin_is_piped() {
        read_password_from_stdin()?
    } else {
        input_password("Enter password: ")?
    };
    let cryptfs = FileSystemFactory::build(folder_path, &password, FileCache::default())?;
    // Validate the password before respawning so errors are still reported in the foreground process.
    if !args.foreground && !is_background_child && !args.cli_mode {
        respawn_in_background(&password)?;
    }

    let handler: FileSystemHandler<rcryptfs::CacheLock> = cryptfs.into();

    if let Some(mount_point) = args.mount_point {
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Error);

        #[cfg(windows)]
        {
            let _ = mount_point;
            todo!("mount is unimplemented!");
        }

        #[cfg(not(windows))]
        {
            let num_threads = args
                .num_threads
                .and_then(parse_number_of_threads)
                .unwrap_or_default(); // default is 0

            println!("num threads is {num_threads}");
            let mut fuse_args = Vec::with_capacity(args.fuse_opts.len() * 2 + 2);
            fuse_args.push(OsStr::new("-o"));
            fuse_args.push(OsStr::new("fsname=rcryptfs"));
            for o in &args.fuse_opts {
                fuse_args.push(OsStr::new("-o"));
                fuse_args.push(OsStr::new(o));
            }

            fuse_mt::mount(
                fuse_mt::FuseMT::new(handler, num_threads),
                &mount_point,
                &fuse_args,
            )?;
        }
    } else {
        platform::prepare_cli_stdin(stdin_is_piped())?;
        cli::run_cli_shell(&handler)?;
    }
    Ok(())
}

fn stdin_is_piped() -> bool {
    !std::io::stdin().is_terminal()
}
