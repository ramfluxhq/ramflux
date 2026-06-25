## Summary

## Verification

- [ ] `cargo fmt --check --all`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace`

## Release hygiene

- [ ] Added SPDX headers to new Rust source files.
- [ ] No internal hostnames, private IPs, credentials, or private infrastructure paths.
- [ ] Updated `CHANGELOG.md` under `## [Unreleased]` when user-visible behavior changed.
