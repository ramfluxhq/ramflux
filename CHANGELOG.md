# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Evict expired requester rollback floors oldest first and expose capacity plus
  explicit retired-floor clearing in contact request settings, preserving consent
  fences and pending authority. Duplicate receipts no longer resurrect requester
  caches; overflow roots are deduplicated within each inbox drain.

- Declining a crossed inbound request preserves valid pending outbound consent.
  Failed outbound staging retains the decline fence and rolls back the intent.

- Only local contact unblock restores local request consent; peer unblock controls
  retain local decline and block fences.

- Repeating `contact.accept` for an accepted root and key returns the existing
  contact, including after auto-accept; conflicting cards still fail.

### Changed

- **BREAKING (operators):** Compose inputs use `RF_COMPOSE_*` names listed in
  `deploy/compose-inputs.json`. Migrate existing env files, explicitly provide all
  production security/identity inputs, and run `deploy/scripts/compose-preflight.py`
  with the same `--env-file` arguments before every Compose command. Public default
  admin tokens are rejected; replace them with fresh random secrets. The demo
  generator and integration harness supply their own tokens and run preflight.

- Demo node deployments can opt into the voice UDP overlay with an env setting
  or command-line port, retaining the existing base deployment when unset. Voice
  selection validates the mesh UDP port too; maintenance commands clearly reject
  unapplied voice settings before invoking Compose.

- Public-name warnings allow Highly Restrictive Latin/CJK script combinations and
  compare NFKC, simple case-folded, whitespace-collapsed skeletons without changing
  signed names or identifiers. Complete the pre-1.0 check-glyph policy with U+221A
  and U+237B; acceptance rules are frozen under the v1 profile domain.
- Contact safety status also checks the signed-authority stamp. Actor-bearing
  task journal/metadata rows distinguish authenticated kind from role matching.
  Outstanding public renames survive stale restores by rebasing their epoch;
  intents with confirmation saved locally do not overwrite later sibling renames.
- Legacy v0.1.0 manual contact verifications acquire a signed-authority stamp on
  first read when the active-device hash is unchanged; contacts without signed
  authority can still verify synthetic safety material without authenticating a
  kind. Hash or later stamped-authority changes require explicit re-verification.
- Refine the proposed root-custody design with proxy exporter receipts, bounded
  revocation deltas, pre-recovery time pins and inherited private group restrictions.
  These specifications do not enable custody support.

- Newly created group sender-key chains use seed-bound v3 distributions. Upgrade
  every group participant together: older clients cannot import v3 distributions,
  so mixed-version groups can lose delivery after sender-key rotation. Existing
  v1/v2 receive chains remain readable; live outbound checkpoints are retained.
- Public-name policy rejects invisible names and verification-like checkmarks.
  Directory/contact rows expose warning-only confusable-name and mixed-script facts.
- `device.refresh.kind_asserted` is a kind string or null, and `kind_verified`
  authenticates a public profile. Its former manual-safety signal is now
  `safety_kind_verified`. Upgrade clients with servers before publishing device-set
  v2 profiles; v1-only nodes and clients reject v2 records. This is a coordinated
  pre-1.0 contract change.

### Added

- Reserved identity custody domains and labels for protocol review. This does not
  enable custody accounts or change existing authentication and signing behavior.

- Root-signed public profiles in device-set v2, with verified kind and normalized
  public display names. Legacy v1 remains readable; coordinated client/server
  upgrades are required for v2 publications. Kind verification authenticates a
  root statement and does not attest biological humanity.

- Initial public workspace preparation.

## [0.1.0] - TBD

### Added

- Placeholder for the first public release.
- Release binaries for Linux x64 and macOS arm64:
  `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`.

### Notes

- Linux arm64, Intel Mac, and Windows release binaries are deferred until a
  later release.
