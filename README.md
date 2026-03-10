# rcryptfs

`rcryptfs` is an experimental encrypted filesystem project written in Rust.

Today, it can read and write encrypted repositories using common `gocryptfs` settings.
The longer-term goal is to turn it into a reusable encrypted filesystem core that can support multiple repository formats and multiple mount or access layers.

## Status

The project is already usable for development and experimentation, but it is not finished and should still be considered experimental.

What currently works:
- read and write support for common `gocryptfs` repositories
- FUSE-based mounting on Unix
- a minimal CLI mode for browsing and interacting with the decrypted view
- direct access to an existing encrypted backend without re-encrypting data

Current limitations:
- compatibility is not complete for every `gocryptfs` feature or configuration
- Windows support is incomplete
- multi-process access to the same encrypted backend is undefined behavior
- the project still needs more testing and hardening

## Project Direction

`rcryptfs` is not intended to remain a `gocryptfs`-only implementation.

The long-term direction is:
- support existing encrypted repository formats such as `gocryptfs`
- add support for other formats such as `Cryptomator`
- allow initialization of new encrypted backends that are not constrained by `gocryptfs` compatibility
- keep the filesystem core reusable independently from the transport or mount layer

## Architecture

The codebase is structured around separable building blocks:
- encryption translators
- path translators
- xattr translators
- filesystem backends
- file and block I/O wrappers

This architecture is meant to make format support and platform integration more modular over time.

## Platform Strategy

### Unix

On Unix-like systems, the main access layer is currently FUSE.

### Windows

Windows support is a long-term goal, but the target is not limited to a single approach.

Possible Windows access layers include:
- `WebDAV`, as a pragmatic integration layer
- `WinFSP`, for a more native filesystem mount experience

The exact direction will depend on implementation complexity, reliability, and maintenance cost.

## Compatibility

### Currently supported
- common `gocryptfs` repositories

### Planned
- broader `gocryptfs` compatibility
- `Cryptomator` support
- native `rcryptfs` repository initialization with encryption modes not tied to `gocryptfs`

## Design Goals

- keep encrypted repository access format-aware but backend-agnostic
- separate filesystem logic from encryption format details
- preserve interoperability with existing encrypted repositories where possible
- make room for native formats that better fit `rcryptfs`

## Non-goals for now

- full support for every `gocryptfs` option
- production-grade Windows mounting today
- concurrent multi-process access to the same encrypted backend

## Security Notice

`rcryptfs` is experimental software and has not been audited.

It may be suitable for development, interoperability testing, and experimentation,
but it should not yet be relied upon for protecting high-value or production data.

Compatibility with `gocryptfs` is still incomplete, and some repository layouts or options
may be unsupported or only partially tested.

## Contributing

Contributions are welcome, especially in the following areas:

- compatibility testing against real `gocryptfs` repositories and options
- integration and regression tests
- FUSE behavior and edge-case handling on Unix
- Windows support exploration (`WebDAV`, `WinFSP`, platform abstractions)
- performance and memory profiling
- CLI ergonomics and documentation

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for development setup and contribution guidelines.

## Getting Started

### Build
```sh
cargo build --release
```
### Mount an existing gocryptfs repository
```sh
./target/release/rcryptfs /path/to/encrypted /path/to/mountpoint
```
### See available arguments
```sh
./target/release/rcryptfs -h
```