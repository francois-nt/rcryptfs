# rcryptfs

[![CI](https://github.com/francois-nt/rcryptfs/actions/workflows/ci.yml/badge.svg)](https://github.com/francois-nt/rcryptfs/actions/workflows/ci.yml)

**A Rust filesystem core and command-line tool for accessing gocryptfs and Cryptomator repositories.**

`rcryptfs` can initialize, read, and write common `gocryptfs` repositories and
the supported `SIV_GCM` subset of `Cryptomator` format 8. Mount a decrypted view
through FUSE or browse its directory structure with the interactive CLI.

For developers, the core keeps cryptography, entry representation, raw storage
I/O, and the mount layer independently replaceable: a common foundation for
encrypted filesystem access, rather than a single encrypted format.

> **Experimental — not audited.** Use disposable test data or independent copies
> of repositories. Do not rely on `rcryptfs` to protect high-value or production
> data. Compatibility is incomplete, and concurrent access by multiple processes
> to the same encrypted backend is unsupported.

## Quick start

### Build from source

Requirements:

- Rust **1.91 or newer** and Cargo.
- Git to clone the repository.
- For the Linux mounting example below: access to `/dev/fuse` and the
  `fusermount3` helper. On Debian/Ubuntu, install the `fuse3` package.

```sh
git clone https://github.com/francois-nt/rcryptfs.git
cd rcryptfs
cargo build --release
```

### Try a disposable repository on Linux

Run these commands from the cloned repository. Initialization and mounting each
prompt for a passphrase; enter the same one both times.

```sh
# Create a fresh workspace for this experiment.
demo_dir=$(mktemp -d)
mkdir "$demo_dir/encrypted" "$demo_dir/mount"

# Initialize a gocryptfs-compatible repository and mount its decrypted view.
./target/release/rcryptfs init "$demo_dir/encrypted"
./target/release/rcryptfs mount "$demo_dir/encrypted" "$demo_dir/mount"

# Write and read a test file through the mount.
printf 'Hello from rcryptfs!\n' > "$demo_dir/mount/hello.txt"
cat "$demo_dir/mount/hello.txt"
ls "$demo_dir/encrypted"

# Unmount when finished. The test repository remains in the temporary directory.
fusermount3 -u "$demo_dir/mount"
```

Mounting runs in the background by default. Use `mount -f` for foreground
operation when troubleshooting.

## Compatibility and status

The project is usable for development, interoperability testing, and
experimentation. It is not a drop-in replacement for every configuration of
gocryptfs or Cryptomator.

| Area | Current support | Limits |
| --- | --- | --- |
| gocryptfs | Initialize, read, and write common repositories, including long-name sidecars | Not every repository option or variant is supported |
| Cryptomator | Initialize, read, and write the `SIV_GCM` subset of format 8; `.c9r`, shortened `.c9s` entries, and detached content directories | `SIV_CTRMAC` is unsupported; directory ID backups and conflict recovery remain incomplete |
| Cryptomator metadata | Authenticated `vault.cryptomator` loading with `HS256`, `HS384`, and `HS512` signatures; masterkey version MAC validation; explicit cipher selection | Scoped to the implemented format 8 subset |
| Cryptomator name shortening | Authenticated `shorteningThreshold` applied to the canonical entry representation | Defaults to `220` when the setting is absent |
| Entry types | Files, directories, and symbolic links in both representations | Broader interoperability still needs testing |
| Repository detection | Automatic detection when mounting or opening the CLI | Limited to supported repository configurations |
| Access layers | FUSE mounting on Unix; a minimal interactive directory browser | Windows support is incomplete; no production-ready Windows mount layer |
| Open files | Buffered writes with one shared physical file handle per open inode | Concurrent multi-process backend access is unsupported |

The checked-in CI runs formatting, Clippy, and tests on Ubuntu. Unix-oriented
code does not imply tested support on every Unix platform.

## Usage

The examples below assume you have built the project and are in its root
directory. When testing an existing repository, use an independent copy and
do not open that copy simultaneously with another client.

### Initialize a repository

gocryptfs is the default:

```sh
./target/release/rcryptfs init /path/to/encrypted
```

To use the supported Cryptomator format:

```sh
./target/release/rcryptfs init --type cryptomator /path/to/encrypted
```

### Mount and unmount

Create an empty mountpoint, then mount the repository. Its type is detected
from its configuration files.

```sh
mkdir -p /path/to/mountpoint
./target/release/rcryptfs mount /path/to/encrypted /path/to/mountpoint
```

For foreground operation:

```sh
./target/release/rcryptfs mount -f /path/to/encrypted /path/to/mountpoint
```

To unmount on Linux:

```sh
fusermount3 -u /path/to/mountpoint
```

### Passphrase input

Use the interactive prompt for normal use. Initialization and mounting also
accept a passphrase through standard input for automation. Avoid placing
literal passphrases in shell commands or scripts, where they may be retained
in history or exposed in logs.

### Browse without mounting

```sh
./target/release/rcryptfs cli /path/to/encrypted
```

The minimal interactive shell supports `ls`, `cd`, and `exit` / `quit`. It
browses the decrypted directory structure; it is not a general-purpose shell.

### Configure threading

Mounting is single-threaded by default. Configure background threads with `-n`:

```sh
# Use auto-detected parallelism.
./target/release/rcryptfs mount -n AUTO /path/to/encrypted /path/to/mountpoint

# Use a specific number of threads.
./target/release/rcryptfs mount -n 4 /path/to/encrypted /path/to/mountpoint
```

Single-thread mode is recommended for workloads with many small files.

### Command help

```sh
./target/release/rcryptfs -h
./target/release/rcryptfs mount -h
```

## Contributing

Help is especially welcome with:

- compatibility testing against gocryptfs and Cryptomator repositories;
- integration and regression tests;
- FUSE behavior and Unix edge cases;
- performance and memory profiling;
- CLI ergonomics and documentation;
- Windows access-layer exploration and platform abstractions.

You do not need to implement a new encryption format to help. Reproducing an
interoperability problem with disposable data is a useful contribution.
For compatibility reports, include the originating tool and version, relevant
repository settings, your platform, reproduction steps, and expected versus
actual behavior. Never publish real passphrases, master keys, or private data.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup, checks, and
contribution guidelines. Please discuss large changes in an issue first.

## Architecture

The core separates encrypted filesystem behavior into replaceable layers:

| Layer | Responsibility |
| --- | --- |
| `EncryptionTranslator` | File names, file contents, and opaque metadata encryption |
| `PathLayout` | Plain-to-cipher path resolution and path caching |
| `EntryStorage` | Physical representation of files, directories, symlinks, and long names |
| `DirectoryLayout` | Directory tokens and detached content locations used by an entry representation |
| `StorageFileSystem` | Raw filesystem I/O without knowledge of encryption or entry formats |
| `ConfigFileSystem` | Restricted access to repository configuration files |
| `CleartextFileSystem` | Public filesystem operations and encrypted file-handle construction |

The gocryptfs and Cryptomator crypto layers can be paired in code with either
entry representation. **Such permutations deliberately define new formats:**
they are not expected to remain compatible with gocryptfs or Cryptomator.

Directory listings are representation-aware and lazy. Open files are shared by
inode so buffered state is flushed by the last released handle rather than by
each independent open operation.

The design aims to keep repository access format-aware but backend-agnostic,
isolate raw I/O from encryption, and keep the core independent from FUSE or any
future access layer. It also leaves room for asynchronous storage backends
without spreading storage I/O throughout the crypto layer.

## Roadmap

- Broader interoperability with gocryptfs and Cryptomator repositories.
- Cryptomator directory ID backups, conflict handling, and `SIV_CTRMAC` support
  when that compatibility work is resumed.
- Storage implementations beyond the native local filesystem.
- Native `rcryptfs` repository initialization with encryption modes not tied
  to gocryptfs, and new formats assembled from independent crypto and entry
  representation layers.
- More testing and hardening.
- Windows support: possible access layers include WebDAV and WinFSP. The
  direction will depend on implementation complexity, reliability, and
  maintenance cost; Windows filesystem semantics and the access layer remain
  incomplete.

Full support for every upstream option, production-grade Windows mounting,
and concurrent multi-process backend access are not current goals.

## License

See [LICENSE](./LICENSE) for the GNU Affero General Public License, version 3.