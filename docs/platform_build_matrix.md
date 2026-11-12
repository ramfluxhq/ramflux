<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Platform build and CI matrix

This page lists every target the workspace is built or checked for, where each
one runs, and how to build it by hand. The toolchain for every target is the
channel pinned in `rust-toolchain.toml`. A host that cannot install a target
fails; it never skips.

## Matrix

| Target | Triple | Workflow and job | Runner | Kind | Required check |
|---|---|---|---|---|---|
| Linux desktop and node | `x86_64-unknown-linux-gnu` | `ci.yml` (all jobs), `release.yml` `build` | Linux | full tests, release tar | no (see below) |
| macOS desktop | `aarch64-apple-darwin` | `release.yml` `build` | `macos-latest` | release tar | no |
| Windows | `x86_64-pc-windows-msvc` | the `windows-latest` check job that ships with the Windows host module | `windows-latest` | check | no |
| Android | `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android` | `platform-targets.yml` `android` | `ubuntu-latest` + image NDK | `cargo check` | no |
| iOS device | `aarch64-apple-ios` | `platform-targets.yml` `ios` | `macos-latest` | `cargo check` | no |
| iOS simulator | `aarch64-apple-ios-sim` | `platform-targets.yml` `ios` | `macos-latest` | `cargo check` | no |
| Browser | `wasm32-unknown-unknown` | `platform-targets.yml` `wasm` | `ubuntu-latest` | `cargo check` | no |

There is no Intel macOS slice and no `i686` Android slice.

The Windows job is defined once, with the Windows host module. This workflow
does not add a second `windows-latest` job; when that job lands, put its job
name in the Windows row above.

## The platform-targets workflow

`.github/workflows/platform-targets.yml` runs `cargo check` only. It builds no
artifact and runs no test.

- **Path-filtered.** It runs for changes under `crates/`, `vendor/`, the
  workspace manifest and lock file, the toolchain pin, and the workflow itself.
- **Not required.** A path-filtered job reports nothing on a pull request that
  does not touch those paths, so making it a required status check would block
  such pull requests forever. Treat a red job as a finding to fix, not a gate.
- **Not cancelled on `main`.** A newer run cancels an older one on a
  pull-request ref only. Every `main` commit that touches the paths keeps its
  own result.
- **Pinned actions.** Every action is referenced by commit, with the same
  commits the other workflows use.
- **Two steps per native target.** "Check core and transport" covers the
  crates every client links below the SDK (`ramflux-core`, `ramflux-protocol`,
  `ramflux-crypto`, `ramflux-transport`). "Check SDK" covers `ramflux-sdk`. The
  split shows whether a failure is in the neutral core or in a host seam.
- **wasm32.** Only the platform-neutral crates are checked. The browser client
  links neither the native transport nor the SDK daemon; extend the job when
  the web client crate exists.

### Repository settings observed on 2026-11-12

Two facts about the repository, recorded here because they change how a red
run should be read. Neither was changed by this workflow.

1. `main` has no required status checks. No job in any workflow blocks a merge
   by itself; a merge relies on the author and reviewer reading the checks.
2. `ci.yml`, `codeql.yml` and `sec-audit.yml` set `cancel-in-progress: true`
   for every ref, including `main`. A `main` commit that is superseded before
   its run finishes is never fully verified. Only the newest `main` commit is.

## Building each target by hand

All commands run from the workspace root.

### Linux and macOS desktop

```sh
cargo build --locked --release --workspace
```

`release.yml` builds the same with `RAMFLUX_PRODUCTION_BUILD=1` and
`--target <triple>`.

### Windows

On a Windows host with the MSVC build tools:

```sh
rustup target add x86_64-pc-windows-msvc
cargo check --locked -p ramflux-transport -p ramflux-sdk --target x86_64-pc-windows-msvc
```

The HTTP CONNECT proxy feature has no effect on Windows targets.

### Android

Install an Android NDK and point the C toolchain at it. API level 24 is the
level the CI job uses.

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
export CC_aarch64_linux_android="$bin/aarch64-linux-android24-clang"
export AR_aarch64_linux_android="$bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$bin/aarch64-linux-android24-clang"
cargo check --locked -p ramflux-transport -p ramflux-sdk --target aarch64-linux-android
```

For the other ABIs, replace the triple in the three variable names and use
`armv7a-linux-androideabi24-clang` or `x86_64-linux-android24-clang`. On macOS
the prebuilt directory is `darwin-x86_64`.

### iOS

On macOS with Xcode installed:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo check --locked -p ramflux-transport -p ramflux-sdk --target aarch64-apple-ios
cargo check --locked -p ramflux-transport -p ramflux-sdk --target aarch64-apple-ios-sim
```

### wasm32

```sh
rustup target add wasm32-unknown-unknown
cargo check --locked -p ramflux-core -p ramflux-protocol --target wasm32-unknown-unknown
```

## Size budgets

Budgets to confirm by measurement, not yet enforced by a job: each Android ABI
shared library under 20 MB uncompressed, and the gzip-compressed wasm core
under 6 MB.

## What a client build must not contain

Every client target inherits the constraints in
`crates/ramflux-sdk/src/client_constraints.rs`: no compiled-in central
service endpoint, no required vendor push service and no required application
store. `crates/ramflux-sdk/tests/no_central_endpoints.rs` scans the client
sources and manifests and fails when an endpoint or a vendor dependency
appears. The connection rules shared by every native client are in
`docs/transport/connection_policy.md`.
