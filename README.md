# rcryptfs

![CI](https://github.com/francois-nt/rcryptfs/actions/workflows/ci.yml/badge.svg)

`rcryptfs` is an experimental encrypted filesystem core and command-line tool
written in Rust.

It can initialize, read, and write repositories using common `gocryptfs`
settings or the currently supported subset of `Cryptomator` format 8. The core is
designed to keep cryptography, entry representation, raw storage I/O, and the
mount layer independently replaceable.

## Status

The project is already usable for development and experimentation, but it is not finished and should still be considered experimental.

What currently works:

- read and write support for common `gocryptfs` repositories, including long
  encrypted names
- creation and access of `Cryptomator` format 8 repositories using `SIV_GCM`,
  including `.c9r` and shortened `.c9s` entries
- files, directories, and symbolic links for both entry representations
- automatic repository detection when mounting or opening the CLI
- FUSE-based mounting on Unix
- a minimal interactive CLI for browsing the decrypted view
- buffered writes backed by one shared physical file handle per open inode

Current limitations:

- compatibility is not complete for every `gocryptfs` or `Cryptomator` variant
- `Cryptomator` vault metadata validation, `SIV_CTRMAC`, directory ID backups,
  and conflict recovery remain incomplete
- Windows support is incomplete
- multi-process access to the same encrypted backend is unsupported
- the project still needs more testing and hardening

## Project Direction

The long-term direction is:

- improve interoperability with existing `gocryptfs` and `Cryptomator`
  repositories
- allow new formats to be assembled from a crypto layer and an entry storage
  representation without requiring compatibility with an existing tool
- support storage implementations beyond the native local filesystem
- keep the encrypted filesystem core independent from FUSE or any future
  access layer

## Architecture

The main layers are:

| Layer | Responsibility |
| --- | --- |
| `EncryptionTranslator` | File names, file contents, and opaque metadata encryption |
| `PathLayout` | Plain-to-cipher path resolution and path caching |
| `EntryStorage` | Physical representation of files, directories, symlinks, and long names |
| `DirectoryLayout` | Directory tokens and detached content locations used by an entry representation |
| `StorageFileSystem` | Raw filesystem I/O without knowledge of encryption or entry formats |
| `ConfigFileSystem` | Restricted access to repository configuration files |
| `EncryptedFileSystem` | Public filesystem operations and encrypted file-handle construction |

The gocryptfs and Cryptomator crypto layers can be paired in code with either
entry representation. Such permutations deliberately define new formats; they
are not expected to remain compatible with gocryptfs or Cryptomator.

Directory listings are representation-aware and lazy. Open files are shared by
inode so buffered state is flushed by the last released handle rather than by
each independent open operation.

## Platform Strategy

### Unix

On Unix-like systems, the main access layer is currently FUSE.

### Windows

Windows support is a long-term goal, but the target is not limited to a single
approach.

Possible Windows access layers include:

- `WebDAV`, as a pragmatic integration layer
- `WinFSP`, for a more native filesystem mount experience

The exact direction will depend on implementation complexity, reliability, and
maintenance cost. The project can exercise Windows builds, but filesystem
semantics and a production-ready Windows access layer are not complete.

## Compatibility

### Currently supported

- common `gocryptfs` repositories, including the long-name sidecar format
- the implemented `SIV_GCM` subset of `Cryptomator` format 8, with `.c9r`,
  `.c9s`, and detached content directories

### Planned

- broader `gocryptfs` compatibility
- validation of `vault.cryptomator` and its declared settings
- `Cryptomator` directory ID backups, conflict handling, and broader
  interoperability
- `SIV_CTRMAC` support when that compatibility work is resumed
- native `rcryptfs` repository initialization with encryption modes not tied
  to `gocryptfs`

## Design Goals

- keep encrypted repository access format-aware but backend-agnostic
- isolate raw I/O from encryption and entry representation details
- preserve interoperability with existing encrypted repositories where possible
- make room for native formats that better fit `rcryptfs`
- leave room for asynchronous storage backends without spreading storage I/O
  throughout the crypto layer

## Non-goals for now

- full support for every `gocryptfs` or `Cryptomator` option
- production-grade Windows mounting today
- concurrent multi-process access to the same encrypted backend

## Security Notice

`rcryptfs` is experimental software and has not been audited.

It may be suitable for development, interoperability testing, and experimentation,
but it should not yet be relied upon for protecting high-value or production data.

Compatibility remains incomplete, and some repository layouts or options may
be unsupported or only partially tested.

## Contributing

Contributions are welcome, especially in the following areas:

- compatibility testing against real `gocryptfs` and `Cryptomator` repositories
- integration and regression tests
- FUSE behavior and edge-case handling on Unix
- Windows support exploration (`WebDAV`, `WinFSP`, platform abstractions)
- performance and memory profiling
- CLI ergonomics and documentation

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for development setup and
contribution guidelines.

## Getting Started

### Build

```sh
cargo build --release
```

### Initialize a new encrypted repository

Create a gocryptfs-compatible repository, which is the default:

```sh
./target/release/rcryptfs init /path/to/encrypted
```

Create a repository using the supported `Cryptomator` format:

```sh
./target/release/rcryptfs init --type cryptomator /path/to/encrypted
```

You will be prompted for a passphrase, or you can pipe it through standard
input.

### Mount an existing encrypted repository

```sh
./target/release/rcryptfs mount /path/to/encrypted /path/to/mountpoint
```

The repository type is detected from its configuration files.

The passphrase can be entered interactively or piped via stdin:

```sh
echo "mypassphrase" | ./target/release/rcryptfs mount /path/to/encrypted /path/to/mountpoint
```

By default, rcryptfs mounts in background. Use `-f` to run in foreground:

```sh
./target/release/rcryptfs mount -f /path/to/encrypted /path/to/mountpoint
```

### Unmount

```sh
fusermount3 -u /path/to/mountpoint
```

### Browse without mounting

```sh
./target/release/rcryptfs cli /path/to/encrypted
```

### Multi-threading

By default, rcryptfs runs single-threaded. You can configure the number of
background threads:

```sh
# Use default parallelism (auto-detected)
./target/release/rcryptfs mount -n AUTO /path/to/encrypted /path/to/mountpoint

# Use a specific number of threads
./target/release/rcryptfs mount -n 4 /path/to/encrypted /path/to/mountpoint
```

Note: single-thread mode is recommended for workloads with many small files.

### All commands

```sh
./target/release/rcryptfs -h
```
