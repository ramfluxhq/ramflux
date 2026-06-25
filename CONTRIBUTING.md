# Contributing to Ramflux

Thanks for your interest in Ramflux. This document covers how to build, the
quality bar, and how to submit changes.

## Licensing of contributions

- This repository (the **core**) is BSD-3-Clause. By submitting a contribution
  you agree it is licensed under BSD-3-Clause (inbound = outbound).
- All commits must carry a **DCO sign-off**: `git commit -s` (this certifies you
  wrote the change or have the right to submit it; see https://developercertificate.org).
- Client repositories (AGPL-3.0) additionally require signing the `CLA.md`.

## Building and testing

```sh
cargo build --workspace
cargo test  --workspace
```

The toolchain version is pinned in `rust-toolchain.toml`. Real-network
integration tests are feature-gated and require a local container runtime:

```sh
cargo test --features realnet
```

## Quality bar (enforced in CI)

- `cargo fmt --all -- --check` — formatting is enforced.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` —
  **zero warnings**.
- `cargo test --workspace` must pass.
- `cargo deny check` and `cargo audit` must pass (supply chain).

## Code conventions

- **Comments and documentation are written in English.** This is a hard rule —
  do not introduce comments in any other language.
- Every source file starts with an SPDX header:
  `// SPDX-License-Identifier: BSD-3-Clause`.
- **No panics in production code paths.** `unwrap`, `expect`, `panic!`, `dbg!`,
  and `todo!` are for tests only; in library/production code, return a typed
  error.
- **No `std::sync::{Mutex, RwLock, Condvar}` in production** — use
  `parking_lot` or `tokio::sync`.
- Prefer feature-gating heavy or optional code paths.
- Follow Conventional Commits for messages: `feat:`, `fix:`, `perf:`,
  `refactor:`, `test:`, `docs:`, `chore:`.

## Pull requests

- Keep PRs focused; describe what changed and how you tested it.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Do not include internal hostnames, IP addresses, credentials, or private
  infrastructure paths.
- CI must be green before review.

## Security

Do not file security problems as public issues — see `SECURITY.md`.
