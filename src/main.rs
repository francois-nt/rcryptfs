#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
use anyhow::{Context, Result, bail};
use clap::{CommandFactory, FromArgMatches, Parser, builder::PossibleValuesParser};
use rcryptfs::core::{
    CacheLock, FileSystemHandler, NoCache, build_filesystem, get_providers_name, init_filesystem,
    is_native_dir_empty,
};
use rcryptfs::{is_background_child, platform, respawn_in_background};
use std::io::{IsTerminal, Write};

mod cli;

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

#[derive(Parser)]
#[command(long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    Init(InitArgs),
    Mount(MountArgs),
    Cli(CliArgs),
}

#[derive(Parser)]
struct InitArgs {
    /// Initialize encrypted directory
    #[arg(
        long = "type",
        value_name = "CRYPTFS_TYPE",
        default_value = "gocryptfs"
    )]
    init_mode: String,
    /// local encrypted folder
    folder_path: String,
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

fn input_password(prompt: &str) -> Result<String> {
    platform::prompt_password(prompt)
}

#[cfg(unix)]
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

/// Reads the background password from stdin once at process startup.
fn read_password_from_stdin(is_background_child: bool) -> Result<String> {
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .context("Failed to read password from stdin")?;
    if !is_background_child {
        println!("Reading Password from stdin")
    }
    Ok(password.trim_end_matches(&['\r', '\n'][..]).to_string())
}

fn parse_args() -> Result<Args> {
    let provider_names = get_providers_name();

    let cmd = Args::command().mut_subcommand("init", |init_cmd| {
        init_cmd.mut_arg("init_mode", |arg| {
            arg.value_parser(PossibleValuesParser::new(provider_names))
                .default_value("gocryptfs")
        })
    });

    let matches = cmd.get_matches();
    Args::from_arg_matches(&matches).map_err(Into::into)
}

fn main() -> Result<()> {
    let args = parse_args()?;

    match &args.command {
        Command::Init(init_args) => {
            let password = if stdin_is_piped() {
                read_password_from_stdin(false)?
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

            let folder_path = init_args.folder_path.as_str().into();
            let master_key = init_filesystem(folder_path, &password, init_args.init_mode.as_str())?;
            println!("\nYour master key is:\n");
            let formatted = master_key.to_formatted_bytes();
            println!("{formatted}");

            if init_args.init_mode == "gocryptfs" {
                println!(
                    "If the gocryptfs.conf file becomes corrupted or you ever forget your password,\n\
                    there is only one hope for recovery: The master key. Print it to a piece of\n\
                    paper and store it in a drawer. This message is only printed once."
                );
            }

            println!(
                "The {} filesystem has been created successfully.",
                init_args.init_mode
            );
            println!(
                "You can now mount it using: rcryptfs mount {} MOUNTPOINT",
                folder_path
            );
        }

        Command::Mount(mount_args) => {
            let is_background_child = is_background_child();
            run_mount(mount_args, is_background_child).inspect_err(|e| {
                if is_background_child {
                    // background child displays its status
                    println!("KO {e}");
                    let _ = std::io::stdout().flush();
                }
            })?;
        }
        Command::Cli(cli_args) => {
            let password = read_password(true, false)?;
            log::set_logger(&LOGGER).map_err(|e| anyhow::anyhow!("{e}"))?;
            log::set_max_level(log::LevelFilter::Error);
            let cryptfs =
                build_filesystem(cli_args.folder_path.as_str().into(), &password, NoCache)?;
            let handler: FileSystemHandler<CacheLock> = cryptfs.into();
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

/// Reads the repository password from stdin or from an interactive prompt, with CLI-specific piping rules.
fn read_password(cli_mode: bool, is_background_child: bool) -> Result<String> {
    if stdin_is_piped() {
        if cli_mode {
            #[cfg(not(unix))]
            {
                bail!("stdin cant be piped in cli mode!");
            }
            #[cfg(unix)]
            {
                read_password_from_stdin(is_background_child)
            }
        } else {
            read_password_from_stdin(is_background_child)
        }
    } else {
        // password in env is useful for local tests - do not use it in production
        if let Ok(password) = std::env::var("RCRYPTFS_PASSWORD") {
            Ok(password)
        } else {
            input_password("Enter password: ")
        }
    }
}

fn run_mount(mount_args: &MountArgs, is_background_child: bool) -> Result<()> {
    if !is_native_dir_empty(mount_args.mount_point.as_str().into())? {
        bail!(
            "Invalid mountpoint: directory {} not empty",
            mount_args.mount_point
        );
    }
    let password = read_password(false, is_background_child)?;
    let cryptfs = build_filesystem(mount_args.folder_path.as_str().into(), &password, NoCache)?;
    if !is_background_child {
        println!("Decrypting master key");
    }

    // Validate the password before respawning so errors are still reported in the foreground process.
    if !mount_args.foreground && !is_background_child {
        respawn_in_background(&password)?;
    }

    let mut handler: FileSystemHandler<CacheLock> = cryptfs.into();
    if !is_background_child || std::env::var_os("VERBOSE").is_some() {
        log::set_logger(&LOGGER).map_err(|e| anyhow::anyhow!("{e}"))?;
        log::set_max_level(log::LevelFilter::Debug);
    }
    if is_background_child {
        handler.set_as_background_child();
    }

    #[cfg(unix)]
    {
        let num_threads = mount_args
            .num_threads
            .as_ref()
            .and_then(|v| parse_number_of_threads(v))
            .filter(|v| *v > 0)
            .map(fuser_ng::ThreadCount::from)
            .unwrap_or_default();

        log::debug!("num threads is {num_threads:?}");
        let mut fuse_args = Vec::with_capacity(mount_args.fuse_opts.len() + 1);
        fuse_args.push(fuser_ng::MountOption::FSName("rcryptfs".into()));
        fuse_args.extend(
            mount_args
                .fuse_opts
                .iter()
                .cloned()
                .map(fuser_ng::MountOption::CUSTOM),
        );

        fuser_ng::mount(
            fuser_ng::FuserNG::new(handler),
            &mount_args.mount_point,
            &fuse_args,
            num_threads,
        )?;
    }
    Ok(())
}
