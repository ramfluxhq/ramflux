# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- BREAKING (development identity reset): native v3 creation is enabled by default,
  with an interactive `rf account create --display-name` recovery-phrase ceremony.
  The seed-taking CLI create/login interface and creation opt-in option are removed.
  There is no legacy-to-native identity migration; reset old development identities.
- Remove the temporary custody-only DM API. Native accounts use the ordinary E2EE
  stack; CLI account backup uses attended full-data jobs instead of key-only archives.
- Add explicit local phrase recovery/promotion with higher-range primary replacement,
  exact durable publication ACK checks and master-certified v3 contact cards.

- Keep experimental custody global admission fair across prefixes, isolate custody rows from legacy snapshots.
- Bound authenticated custody sessions per principal, cancel evicted transports immediately, reserve two challenges for fresh prefixes, reject invalid budget configuration.

- Harden experimental custody admission with prefix quotas, bounded listener deadlines, durable new-principal budgets and per-account publication writes. Identical publication is a no-op.
- BREAKING (experimental custody): proofs/challenges commit to the operation hash and receiving node id; signed node metadata binds a separate public listener certificate. Reissue experimental profiles for this pre-default wire revision. Memory-vault builds require an explicit integration-test marker. Native accounts now use ordinary v3 E2EE integration.

- Add experimental born-v3 publication, registration and channel-bound sessions, with durable node pins and one-use challenges. Creation is enabled by default; integration-only memory custody is excluded from production artifacts.


### Added

- Local born-v3 identity setup with a generated recovery phrase,
  one-use backup confirmation, non-synchronizing primary vault custody and
  persisted signed v3 authority. Networking stays pending until exact remote acceptance;
  publication and registration use exact authority ACKs, and legacy-proof fallback is refused.
- Exact v3 authority codecs, certificate/lease verification, durable mode and
  revocation floors, independent recovery/record vectors and revocation-priority
  capacity handling. Native mode refuses legacy account/proof fallback.

### Fixed

- Evict expired requester rollback floors oldest first and expose capacity plus
  explicit retired-floor clearing in contact request settings, preserving consent
  fences and pending authority. Duplicate receipts no longer resurrect requester
  caches; overflow roots are deduplicated within each inbox drain.

- Declining a crossed inbound request retains the decline fence while allowing
  only the peer's Accept for the matching, unexpired outbound request. The fence
  still blocks new requests after that outbound expires. Failed outbound staging
  retains the decline fence and rolls back the intent.

- Repeating `contact.accept` for an accepted root and key upgrades lookup
  provenance from a signed card locally, including after auto-accept. Existing
  card and verified pins never downgrade; conflicting cards still fail.

- Contacts can be blocked again after an unblock, including within one second and
  after a sibling restriction arrives. Consent and object-revocation journal IDs
  identify each decision while preserving immutable event replay and old rows.

- Confirmed contact safety writes its signed-authority stamp in the verification
  transaction. Legacy baselining runs once per account behind a durable marker;
  reads no longer stamp later unstamped records. Legacy card contacts without a
  signed set report the same synthetic safety state across all contact views.

### Security

- Only local contact unblock restores local request consent; peer unblock controls
  retain local decline and block fences.

### Changed

- Deleted-message legacy cleanup no longer runs at unlock or on a background thread.
  Messages deleted before this Unreleased version keep residual
  sender data; reset development data. Older deleted rows open without an upgrade scrub.
- The public federation HTTP listener applies configurable per-source concurrent
  connection, connection-open-rate, and request-rate limits, plus IPv4 `/24` and
  IPv6 `/48` aggregate connection and connection-open-rate caps. Its bounded table
  evicts idle LRU entries; operators can disable source limits for
  non-address-preserving proxies without weakening the global cap. The demo
  defaults them off for rootless, machine, and unknown port-forwarding topologies
  while preserving an explicit operator choice. Proxy forwarding headers remain
  untrusted.

- **BREAKING (operators):** Compose inputs use `RF_COMPOSE_*` names listed in
  `deploy/compose-inputs.json`. Migrate existing env files, explicitly provide all
  production security/identity inputs, and run `deploy/scripts/compose-preflight.py`
  with the same provider arguments before every Compose command. Public default
  admin tokens are rejected; replace them with fresh random secrets. The demo
  generator and integration harness supply their own tokens and run the selected
  provider's config render as preflight. Services also refuse the known public
  admin-token value at startup, including outside Compose.

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
  the first writer unlock after upgrade when the active-device hash is unchanged;
  contacts without signed
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
