# Contributing to rcryptfs

Thank you for your interest in contributing to `rcryptfs`.

`rcryptfs` is an experimental encrypted filesystem project written in Rust.
The project currently focuses on interoperating with common `gocryptfs` repositories,
while evolving toward a more reusable encrypted filesystem core.

Because this is a security-sensitive project, correctness, clarity, and test coverage
matter more than feature count.

## Project status

`rcryptfs` is still experimental.

Contributions are welcome, but please keep in mind:

- the codebase is still evolving
- compatibility with `gocryptfs` is not yet complete
- Windows support is incomplete
- the project has not been audited

If you are looking for a place to help, testing, compatibility work, documentation,
and small correctness fixes are especially valuable.

## Ways to contribute

Useful contributions include:

- interoperability testing with `gocryptfs`
- regression tests for existing behavior
- support for additional repository options or layouts
- documentation improvements
- CLI improvements
- platform-specific investigation and abstraction work
- performance profiling and benchmark coverage
- bug reports with reproduction steps

If you are unsure where to start, look for issues labeled `good first issue`
or `help wanted`.

## Before starting work

Please open an issue before starting large changes.

This is especially helpful for:

- new repository format support
- major refactors
- platform abstraction changes
- mount/access layer changes
- behavior changes that may affect compatibility

For small fixes, documentation changes, or isolated tests, opening a pull request directly is usually fine.

## Development setup

### Requirements

- stable Rust toolchain
- Cargo

### Platform-specific requirements

- a Unix-like environment for current FUSE-based mount development (the current Rust FUSE backend uses `/dev/fuse` directly)
- a native Windows machine for Windows support (although some minimal testing can be done via Wine)

## Build

```sh
cargo build --release
```

## Run tests
To run all tests:
```sh
cargo test
```

To run only unit tests:
```sh
cargo test --lib
```

To run only integration tests in the tests/ directory:
```sh
cargo test --test '*'
```

## Formatting
```sh
cargo fmt --check
```

## Linting
```sh
cargo clippy --all-targets --all-features -- -D warnings
```

Before opening a pull request, please make sure the code builds, is formatted, passes Clippy without warnings,
and passes all tests locally.