# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Newly created group sender-key chains use seed-bound v3 distributions. Upgrade
  every group participant together: older clients cannot import v3 distributions,
  so mixed-version groups can lose delivery after sender-key rotation. Existing
  v1/v2 receive chains remain readable; live outbound checkpoints are retained.

### Added

- Initial public workspace preparation.

## [0.1.0] - TBD

### Added

- Placeholder for the first public release.
- Release binaries for Linux x64 and macOS arm64:
  `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`.

### Notes

- Linux arm64, Intel Mac, and Windows release binaries are deferred until a
  later release.
