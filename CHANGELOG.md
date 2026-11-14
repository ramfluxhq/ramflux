# Changelog

- Activate negotiated ephemeral delivery with volatile same-node routing, bounded queues,
  exclusive signed deadlines and no durable fallback, client journal writes or offline wakes.
  Add real-process CLI push/restart coverage and retry partially applied capability reassertions.

- Task courier rows and group-sync couriers stop on a gateway idempotency conflict instead of
  resubmitting: task rows are retired with a `submit_conflict` record, and a conflicted
  approval decision becomes `failed / submit_conflict` (calling `grant.approve` again re-enqueues
  it once).
- SDK content envelopes now default to seven days of offline retention, configurable
  per account through the SDK and local bus (3600–604800 seconds).

- Unlock, creation confirmation and recovery promotion now open locally before
  background admission; networking outcomes publish immediately. Keyed lifecycle
  work survives client deadlines and disconnects, shares in-flight retries and
  permits lost-holder takeover only for unlock, lock and switch. Other pending
  lifecycle receipts return `OperationReconciliationRequired`.


All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Remove relay HTTP/shared-HMAC object transfers and the obsolete relay-to-retention
  TTL registration route and relay retention fallback settings. Retired relay-key
  options and upload journals carrying them are refused; restart those uploads with
  current gateway-issued QUIC capabilities. Router replay/mailbox tuples and WAL keys,
  registration receipts, foreign authority caches, ownerless notify/relay state,
  unmarked gateway stores and plaintext account/keychain state in retired formats
  now fail closed at load/startup (`UnsupportedPersistedFormat` where applicable).
  Current authority and acknowledged history must be preserved during operator repair.

### Device pairing preview

- Added journaled native head updates and exact-head recipient installation foundations.
  Device pairing remains default-off and preview / CLI only; desktop and mobile
  pairing companions are unavailable. See [device pairing](docs/device_pairing.md).

### Session push

- Keep an offline catch-up in one pass while committed inbox coverage advances.
  The 20-second receive timeout now bounds stalled progress, so slower durable
  stores can drain a finite backlog without cancelling and restarting the pass.
- SDK receive ledger first-activation is default-on for managed push, compatibility
  and standalone receive. Fresh accounts advertise `gateway.session_push.v1` so the
  first handshake can bind the verified node incarnation; already-activated accounts
  keep advertising. Reverting this change leaves already-activated accounts on the
  shared ledger.
- Added `gateway.session_push.v1`: incarnation-bound resume pages, point fetch,
  batched ACKs, compact sender acceptance and registration-owned recipient push.
- Changed stalled-sink close to 15 seconds of actual I/O, ACK backpressure while
  publication is pinned, admission `payload_too_large`, and fail-stop on uncertain
  durability. Whole-population issued probing supplies recovery hints.
- **BREAKING (operators):** in-place rollback to a pre-session-push router on an
  upgraded store is unsupported. Isolate the old store before rollback; restores
  require `--rotate-inbox-incarnations` with serving gateways stopped. Damaged
  segments require `--quarantine-wal-segment`. Router and gateway require external
  supervisor restart policies because fatal durability uncertainty aborts the
  service. Reference compose files do not configure automatic restart.

### Security

- Keep account MAC authority independent of backup encryption keys. Only in-place
  migration with a live account key preserves legacy HKDF bytes. Pre-bundle
  archives receive fresh random authority when opened for restore; their old
  markers remain unmatched, as before schema14. Existing bundles survive copies
  and rekeys unchanged.

- Ed25519 batch wrappers now use per-signature verify_strict, eliminating batch/strict acceptance differences.

### Changed

- Restore attachment references per owner and selector, reject stale aliases behind
  erased selectors or payload fences, and omit unowned legacy placeholders while
  preserving registered revocations. Historical messages can survive without their
  attachments, including messages never deleted on this device. See
  [attachment erasure and restore boundaries](docs/account_backup.md#attachment-erasure-and-restore-boundaries)
  and the existing **BREAKING (downgrade)** schema v13 notice below.

- Keep admitted native group history readable after authority observations expire:
  `group.history` reads stored history, name and roster offline while retaining
  revocation and erasure fences. New authorization keeps fresh-head checks and
  returns typed `NetworkingPending` within five seconds when refresh is unavailable.
  Schedule head refresh on connect, on demand and on a fixed schedule at
  150-second intervals. New demand precedes sweep work; periodic triggers cap
  failed-demand retries at 32 so sweep roots progress. Each trigger handles at
  most 128 roots in paced 32-root batches, with fair continuation and per-root
  failure backoff. Verified background refresh
  immediately redrives matching deferred inbox entries once, preserving unrelated
  retry backoff. Explicit `device.refresh` refreshes the named principal (own by
  default) without redriving inbox retries. Backup restore keeps freshness empty
  until a new network observation. Peer changes use eventual observation, without
  a new node push notification.
- Durable sender retries return their original mailbox sequence. Retry waiters
  forwarded to a new home receive `forward_in_progress`; clients must retry with
  the same sender identity and envelope ID so the remote home deduplicates them.
- **BREAKING (rollback):** Nodes that write `SenderAssigned` WAL records or emit
  the appended native custody refusal variants require a compatible binary.
  Pre-change binaries cannot decode these records or variants; downgrade in place
  is unsupported. Preserve backups from before the upgrade for rollback.

- All pending mutation receipts now return the bus code
  `OperationReconciliationRequired`, preserving the reconciliation message while
  dropping its former `event id conflict:` prefix. The C ABI maps both lifecycle
  and account mutation reconciliation errors to `InvalidArgument` (1).
  Ordinary event ID and changed-intent conflicts retain `ValidationFailed`.

- Native `account.networking.changed` events now include resident session state,
  publishing disconnect/reconnect transitions while preserving custody admission
  state. New connection managers reset persisted session state to connecting.

- Remove revocation placeholders with the last reference of their selector and refuse
  revocations without an authenticated manifest.
- **BREAKING (downgrade):** Account schema v13 uses a writer-floor sentinel;
  older binaries refuse v13 accounts and archives.

- Upgrade Ed25519 to dalek 3 and share curve25519-dalek 5 with X25519 while
  preserving RFC 8032 signatures and node identity record encodings.
- Preserve same-cycle delivery receipts with an eight-second priority admission
  floor and a separate call-signaling allowance, capped by the remaining cycle.
  Document shared receive budgets and deferred background contact discovery.

- Charge complete task courier submissions to the actor cycle budget, service
  receipt and call couriers first, and bound federated task forwarding with
  deadline-aware HTTP workers and typed timeout/capacity results.
- **BREAKING (operators):** Service starts with `--config` now need a writable
  `node-identity/` directory under the configuration directory, unless
  `RAMFLUX_NODE_PRIVACY_KEY_FILE` points to an existing private key. The repository
  Compose files provide the persistent `node-privacy` volume; copied/custom Compose
  files and systemd installs must supply writable storage or the explicit key path.
  Source-IP pseudonym keys persist across services and restarts at mode 0600.
  Existing address-hash buckets age out normally; no quota migration is attempted.
- BREAKING: custody authenticated capacity defaults to unlimited (empty
  `RAMFLUX_CUSTODY_AUTHENTICATED_POOL`); finite values accept 1–1048576. Remove
  authenticated source/principal/stream ceilings and the 4096 active-session cap.
  The removed `RAMFLUX_CUSTODY_AUTHENTICATED_SESSIONS_PER_PRINCIPAL` is ignored
  with one warning; existing finite A=512 remains honored. Add configurable
  `RAMFLUX_CUSTODY_PREAUTH_HANDSHAKES_PER_SOURCE` and router-only
  `RAMFLUX_CUSTODY_CHALLENGES_PER_{IP,PREFIX,NODE}_PER_MINUTE` with strict ordered
  validation. Admission refusals carry typed `retry` scope/time honored by SDK
  retries and read models. Older strict decoders reject a refusal carrying
  `retry`; rebuild clients and node services together. Legacy unhinted and daily
  reset policies remain available. Deadline indexes keep admission work independent
  of authenticated population.

### Fixed

- Keep custody capacity warnings and networking events tied to transitions rather
  than status reads and countdown updates. Expiry publishes a clear event while
  retaining the bounded retry floor. Expiry publication failures warn once and
  leave account commands and background synchronization running.
- Validate the target router admin port before rollback or recovery changes
  managed state. Use `RAMFLUX_ROUTER_ADMIN_ENABLED` / `RAMFLUX_ROUTER_ADMIN_PORT`;
  the demo-only port spelling remains an input alias for one release. Direct
  Compose renames `RAMFLUX_ROUTER_ADMIN_LOOPBACK_PORT` to
  `RAMFLUX_ROUTER_ADMIN_PORT` without an input alias.

- Keep account reads independent of background admission, receive and relay work.
  Add a resident session host with bounded calls and subscriptions, lifecycle
  preemption, admission-based command deadlines, and cancellable transfer slots
  with durable per-chunk checkpoints. Preserve offline receipt replay and cached
  attachment GETs; refuse new network work before reserving its operation.
- Upgrade Web Push P-256 ECDH to p256 0.14 and crypto-bigint 0.7.10, preserving
  RFC encryption bytes and removing the RUSTSEC-2026-0387 audit exceptions.
- Erase proven pre-upgrade attachments after their last message owner is removed;
  preserve only ambiguous legacy payloads. Probe object cleanup through indexes,
  bind legacy receive owners before import, and advance backup privacy generation
  only for actual object/reference erasure. Post-commit notification failures no
  longer report a committed deletion as failed. Pre-enrollment task metadata and
  the sender delivery/owner crash window remain follow-up limitations.
- Clamp loaded and persisted custody retry deadlines after wall-clock rollback,
  retain the unhinted monotonic cooldown across in-process account reloads, and
  use one remaining-time view for status, account lists and networking events.
  Past daily reset hints fall back to the generic 300-second floor.
- Make router loopback administration a separate opt-in, off by default, with
  port validation, occupied-port refusal, and saved overlay recovery. The
  federation administration overlay no longer publishes the router listener.
- Consolidate journal topic lookups into a transactional topic/sequence index.
  Cache missing legacy status coordinates once and keep status snapshots in the
  subscription acknowledgement, with bounded replay pages carrying only events.
- Bound migration forwarding DNS and total socket IO, share forward admission
  across TCP and async ingress, and pin sender signature, restart, and resume
  checkpoint regressions.
- Cap queued DNS resolver work after timeouts and test sender-field binding by
  recomputing canonical bytes from altered envelopes.
- Skip malformed individual contact records during legacy verification migration
  without blocking account unlock. Markerless legacy archive merges baseline only
  imported verifications that still match their observed signed authority; sealed
  local verifications and existing authority stamps remain unchanged.
- Index own-copy expiry and due retries, keep transactional row/byte counters, and
  bound streaming cleanup without scanning parked copies or receipt namespaces.
  Defer live eviction while expired batches remain and avoid reserving an extra
  status slot after a status write.
- Confirm own-device surface context per active sibling set after fanout ACKs,
  park failed targets independently, and preserve exact committed replay handling
  when disposable streaming receipts are evicted. Pending cache rows take priority
  over completed rows within explicit 18,000-row receipt and status budgets.

- Bound custody capacity reset hints to two days, keep node-bound retry deadlines
  without repeated status writes, and expose router budget inspection through
  the operator-only loopback administration overlay.
- Enable daemon diagnostics through `RUST_LOG` with safe invalid-filter handling,
  accept hyphen-leading CLI identifiers and free-text bodies/names, and normalize
  native group selectors to their signed thread. Repair saved group links before
  networking at account unlock while preserving metadata and older history.
- Replicate sent plain-text DMs and group messages to active sibling devices as
  outgoing rows. Copies are best effort, released after confirmed submission and
  deduplicated against original delivery and explicit history import. Native
  copies retain custody scope and freshness checks; deletion erases attribution
  while preserving private replay claims. Sibling history tombstones erase live
  sent-copy rows and prevent late copies from reviving deleted own messages.
- Persist sender revocations before the first attachment import; keep deletion fences through
  late writes and backup restore, hide revoked attachments, and report nonretryable
  `attachment deleted` fetch failures. Add `rf object fetch` for explicit resumable fetches.
  Bind placeholder manifests to authenticated attachment references so last-message erasure
  removes revocation provenance, and restore payload-free legacy fences over live objects.

- Upgrade SHA-2, HMAC, HKDF, and X25519 dependencies without changing stored or wire formats.
- Prepare task courier routes outside the account synchronization loop, isolate
  per-item failures and bounded manifest workers, and retain one actor-owned
  gateway session. Native pending accounts defer courier work until admission;
  queued directory results retain their original current-head freshness age.
- Keep deleted and revoked attachments unavailable during cached completion, discard
  their cached chunks, and finish pending relay ACKs while their grant is valid.
- Erase imported attachment ciphertext and content keys after the final message
  owner is deleted, with shared-reference retention, cache/spool invalidation and
  typed `ObjectErased` outcomes (C ABI 19; account writer contention stays 18,
  object identity conflict is 20 and unverified ownership is 21). Preserve portable
  erasure fences across backup
  merge, native/full restore and rekey; authorize archive publication against the
  current erasure generation. Schema 12 refuses older writers through a versioned
  checksum sentinel. Bounded legacy discovery preserves ambiguous zero-reference
  objects unchanged, including their residual ciphertext/keys; unsafe legacy
  attachment archives are refused explicitly. Pre-delete archives alone, other
  devices, relays, user exports and already-returned bytes remain outside local
  erasure.


- CLI direct-message history preserves the daemon's saved outbound plaintext display after restore instead of overwriting it with encrypted envelope JSON.

- Native group reads include stored plaintext history after restore even when the new device has no pending receive page.

- Keep restored native group history readable after attended recovery revokes the
  source device. Historical roster display does not grant current send routes.

- Keep native group delivery and recovery cursors out of signed-snapshot selection
  during offline backup restore. Strict snapshot validation and full-account merge
  behavior remain unchanged.

- Restore signed native group data offline without requiring a local actor before
  attended recovery. Preserve signed state selection, member data and removal
  floors; report rejected archive authorization as `authorization_rejected`.

- Report missing fresh native restore setup as `restore_setup_required` and refuse
  incomplete CLI imports before archive verification. Successful offline imports
  expose the restored local id, networking state and attended recovery command;
  locked native account status remains readable before recovery and admission.

- Resolve `rf account export-agent-credentials` through the agent's recorded
  human custodian regardless of the active account. Add `--custodian` for explicit
  selection and name missing-custodian and wrong-custodian refusals.

- Complete verified cached DM attachments after upload-grant expiry, and remove
  relay ACK progress atomically with the successful import commit.
- Add `rf dm read --wait SECS` for bounded deferred-fetch polling (default 0);
  retain gateway resume state at simultaneous fetch deadlines and emit one
  warning per attachment failure with debug context for outer callers.

- Resume born-v3 DM attachment downloads and confirmed relay ACKs across bounded
  fetch windows; expose safe fetch diagnostics and daemon readiness in SDK logs.
- CLI compatibility: `rf object list` now returns paginated metadata instead of
  encrypted payloads. Use `rf object get` to export bytes. Oversized legacy SDK
  listings return a bounded error instead of closing the local connection.

- BREAKING (v3 custody capacity hints): refusal frames may carry the optional
  `capacity` field identifying a prefix/global daily new-principal quota and its
  UTC reset time. Clients built before this commit reject refusal frames that
  carry `capacity`; rebuild both sides. The public demo node is upgraded in the
  coordinated deployment follow-up. Other capacity refusals retain the old shape.

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

- Upgraded rustls, rustls-webpki, quinn-proto, h2, tokio, webpki-roots, and webpki-root-certs to patched versions to close RUSTSEC-2026-0258, 0338, 0339, 0340, 0341, 0342, 0285, 0346, 0348, 0349, 0381, 0382, 0383, and 0386. RUSTSEC-2026-0387 (crypto-bigint 0.5, pinned by the P-256 ECDSA stack) remains an accepted, time-limited deny.toml exception until 2026-12-15.

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
- Writable account databases now exclude other writer processes with a local
  advisory lock that expires when the owner closes or exits. Backup readers and
  SQLite automatic rollback preserve managed transaction state without stale
  guards affecting a replacement transaction. CI rejects raw account transaction
  and savepoint bypasses, with explicit private-staging exceptions.
- Writer contention reports retryable `account_busy` on backup and local-bus
  surfaces (bus retry after 1000 ms), with C ABI `RAMFLUX_ERR_ACCOUNT_BUSY = 18`;
  lock/index I/O reports `unreadable` / `storage_unavailable`, and unlock now says
  "wrong passphrase or damaged local key" for local-key verification failures.

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
  contacts without signed authority can still verify synthetic safety material
  without authenticating a kind. Hash or later stamped-authority changes require explicit re-verification.
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
