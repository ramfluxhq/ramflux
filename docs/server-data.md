# Server data and retention

Nodes need delivery metadata. End-to-end encryption protects message content;
it does not conceal who sends to which device. Envelope source principal/device,
target delivery id, creation time, TTL, delivery class and ciphertext size are
plaintext headers visible to gateways, routers and forwarding federation peers.
Sealed sender is a separate future design. Nodes also hold public identity roots,
signed device sets, prekeys, trust pins and necessary revocation fences. They
can observe source network addresses during a connection.

| Service | Durable data and normal deletion policy |
| --- | --- |
| Router | Encrypted envelopes are removed on ACK or at their retention deadline: the earlier of the envelope's own expiry (creation time plus TTL) and seven days after the router accepted it, by the router's clock. Every submission path, including own-device fan-out, judges replay, expiry and clock skew by server time and rejects a `created_at` more than 120 seconds in the future. A 30-second sweep visits only due entries of a deadline index (in memory, in redb and in the WAL) and checkpoints only the mailboxes it changed. Inbox reads hide expired messages without deleting anything. Cursor sequence watermarks remain to prevent replay; envelope-id ACK and NACK diagnostics retain at most 1,024 entries per target. The out-of-order ACK window holds 1,024 sequences. When it is full, the oldest outstanding delivery moves to a dead-letter record instead of refusing the ACK. A delivery NACKed three times is dead-lettered as well. Dead letters keep only sequence, envelope id, reason and deadline (no ciphertext), at most 128 per target, until that deadline. The recipient is not told about a dead-lettered delivery; see Known limitations. Rows written by builds that did not store an acceptance time are treated as accepted at the earlier of their creation time and the upgrade, so they expire at most seven days after the upgrade; that deadline is stored once (in the row, or for old WAL records in a small deadline table) and never recomputed at a later restart. A mailbox checkpoint that fails to save stays due and is retried by the next sweep. Registration-proof receipts expire under the identity replay policy. Identity/public-key and revocation records follow identity lifecycle policy, rather than inbox TTL. |
| Gateway | Live connections retain session metadata. Closed or disconnected sessions, frame queues and resume-token checkpoints are pruned every 30 seconds; disconnected metadata is kept for the configured resume window (`RAMFLUX_GATEWAY_RESUME_WINDOW_SECONDS`, default 300 seconds). Expired challenge and replay state is pruned as well. |
| Notify | Pending wakes retain their delivery-class TTL. Every 30 seconds terminal/expired wakes are removed, including WAL records. Provider diagnostics retain one hour, at most 16 attempts per queue and 1,024 queues after each sweep. Production push routes have a sliding 30-day lifetime set by notify's clock. Each authenticated registration restarts it, and the SDK re-registers on every session (re)connect, on token change and once less than 15 days remain. A device left in the background therefore stays wakeable. Token rotation replaces the device's prior route for that provider. Revocation deletes routes before they expire. The router keeps a revoked device's record marked `revoked`; notify and the gateway treat such a device as no longer current. Every wake rechecks the owner, and a batched sweep checks at most 1,024 owners per 30-second pass (256 per router request). A still-open session of a revoked device cannot register or renew a route. Clearing the route in the SDK sends an explicit deregistration that deletes it at once. Routes without a verified owner, left from before ownership binding, are deleted by the first revocation sweep after startup, outside synthetic test mode. Routes and ownership proofs are encrypted with a separately mounted node key. |
| Federation | The outbound spool retains opaque envelopes until delivery or the earlier of envelope expiry and a seven-day spool cap. The retry loop and authenticated retention GC remove expired spool entries and seen-forward receipts. Public trust/pin and revocation state is separate from delivery retention. The node signing secret lives in a mounted file, never a new redb value. |
| Relay | Attachment chunks are client ciphertext. `RAMFLUX_RELAY_OBJECT_MAX_TTL_SECONDS` defaults to 86,400 seconds and cannot exceed 604,800 seconds, even with a larger environment value. Requested expiry can shorten this cap. Other object/tombstone policies remain independent. |
| Retention | Authenticated router/federation GC requests perform real deletion, including dry-run counts. Owners delete up to the earlier of the requested time and their own clock, so a skewed requester cannot cause early deletion. Incident/evidence, legal-hold and lifecycle policies remain distinct; this does not promise that all server metadata expires after seven days. |

Router WAL files roll at least hourly when writing. A closed segment is deleted once
its last modification is older than the full retention window: seven days plus the
120-second clock-skew allowance plus one roll interval and one sweep. The newest
segment of each shard is the writer's active file and is never deleted, even when a
shard is idle. Recovery takes the highest logged sequence per mailbox from every
record, including expired ones, and checkpoints it before serving, so a sequence is
never reissued after a restart. Logical expiry/checkpoints prevent expired inbox
messages from being restored before the physical cleanup. Redb
deletions retire rows; filesystem snapshots, old backups, SSD remnants and
operator logs need their own deletion policy. These mechanisms are not a secure
erase guarantee against a malicious operator.

Source-IP admission identifiers use HMAC-SHA-256 with a node secret and preserve
IPv6 /64 bucketing (IPv4-mapped addresses normalize to IPv4). They are not
unsalted address hashes. By default each process generates an ephemeral key;
restart changes identifiers. Mount a shared, private base64url-encoded 32-byte
key as `RAMFLUX_NODE_PRIVACY_KEY_FILE` where stable node-local bucketing across
services/restarts is required. Use a distinct key on each node. A server with
that key can still evaluate candidate addresses.

## Mounted secrets and migration

Secret files contain an unpadded base64url encoding of exactly 32 random bytes,
with Unix mode 0640, 0600, 0440 or 0400. Any "other" permission bit, and group
write, is refused. Mount them read-only outside the database volume. Services
refuse missing, malformed or permissively accessible files. Do not check generated
files into source control.

The services drop every Linux capability, so container root cannot bypass file
permissions. The development bootstrap writes secrets with mode 0640 and compose
adds `RAMFLUX_SECRET_GID` as a supplementary group of notify, federation and
retention. `issue-certs.sh` records the group in `deploy/.env` (which compose
reads), unless that file already sets `RAMFLUX_SECRET_GID`:

- The group id is resolved without `getent` where it is unavailable (macOS uses
  `dscl`), the assignment is appended on its own line, and a `deploy/.env` that
  already records a different gid produces a warning naming the correct value.
- By default it is the invoking operator's primary group, so both rootless Podman
  (where the operator's uid is container root) and rootful Docker run by a
  non-root operator work without further setup.
- Recommended for shared hosts: create a dedicated group whose only members are the
  operators, and run `RAMFLUX_SECRET_GROUP=<group> issue-certs.sh`. The script then
  `chgrp`s the secrets to that group and records its id. Without it, everyone in the
  operator's primary group (for example `users` or `staff`) can read the signing
  seed and route key.
- Alternatively, an operator may `chown root:root` the files (mode 0600) on hosts
  where the container runtime does not remap uids.

Each secret has its own directory, so each container mounts only what it needs.

- Notify requires `RAMFLUX_NOTIFY_ROUTE_KEY_FILE`. The development certificate
  bootstrap generates `certs/notify/route.key`, mounted at
  `/etc/ramflux/mesh/route.key`. Back up the key separately from the encrypted
  database: losing it makes saved push routes unreadable. Startup migrates legacy
  plaintext routes into authenticated AES-256-GCM ciphertext and compacts redb.
  Existing synthetic routes without verified owners are unusable in production;
  devices register again through their authenticated session.
- Federation requires `RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE`. Development
  bootstrap generates `certs/node-identity/node-signing.key`, mounted at
  `/etc/ramflux/node-identity/node-signing.key`; an older
  `certs/federation/node-signing.key` is moved there unchanged. If both files exist
and differ, the bootstrap stops with an error and deletes neither; keep the seed
that matches the federation identity pin. For an existing node,
  stop federation and run its binary with the existing `--config` and
  `--export-signing-seed /outside-data-volume/node-signing.key`. The export is
  create-only, private and fsynced. Mount that existing key read-only, then start
  normally. A key different from the legacy identity is refused. Startup removes
  the legacy redb seed and compacts retired pages. A public-key pin prevents an
  accidental identity replacement on subsequent starts. Preserve old identity
  material before upgrading; remove obsolete data-volume backups separately.
  The old seed environment variable is no longer a runtime secret source.
- The retention service uses the same mounted federation identity for signed
  deletion receipts. Compose mounts only `certs/node-identity` into it, read-only.
  Federation's mesh TLS key is not visible to retention.

A live compromised node can read push tokens and signing secrets from memory or
mounted files. Encryption at rest protects a copied data volume without those
keys; it does not protect against the running node or its operator.

## Production push registration

Clients normally use the SDK: set `GatewaySessionConfig::push_route`, call
`GatewaySessionEngine::set_push_route`, or send the local bus request
`device.push_route.set` with `{"registration": {...}}`. `null` clears it and sends
an explicit deregistration, which deletes the node's routes for the device. The
daemon stores the route in the account database and registers it after every
authenticated (re)connect, on token change and before renewal is due.
Registration never blocks the session: it is sent after `connect()` returns,
outside the connect timeout, and its answer is matched by request id whenever it
arrives, so a slow notify or router cannot fail a connect or a heartbeat. On the
gateway, route control runs on one serial worker per session, outside the session
loop: at most one control is in flight, a newer control replaces a queued one (the
replaced one is answered `superseded`), and each exchange is cancelled after 10
seconds. Refusals carry a `code`. `provider_unavailable` (the node has no credential
for that provider) and `rejected` wait 24 hours or until the token changes;
`unavailable` (timeout or backend failure) and unanswered requests back off from 30
seconds, doubling to 6 hours, with up to 20% jitter. A cleared route stays pending
until the node confirms the deregistration and is retried with the same backoff,
also across daemon restarts; a deregistration refused as `rejected` (the device is
not the routes' owner) is dropped instead. Unknown refusal codes from a newer node
are treated like `unavailable`.

Every control carries a strictly increasing client sequence (`ext.push_route_seq`
in the signed request). Notify keeps, per device, the sequence of the last confirmed
deregistration and applies a registration only if its sequence is newer, so a
registration that finishes late (for example behind a slow router lookup) cannot
recreate a cleared route.

The gateway-to-notify route control messages (typed registration answers, refusal
codes and client sequences) changed with this release: upgrade the gateway and
notify together. A mixed pair refuses route control as `unavailable` until both
run the same version; clients back off and retry.

The wire contract: send a `push_route_register` gateway session frame with `request` containing
`signed_request` and `body`. Sign `POST /notify/v1/push-route` with the current
device branch key, canonical body hash, a fresh request id/nonce and expiry,
`device_proof_hash: "already_authed"`, and `ext.session_id` equal to the live
session id. Body fields are `provider` (`apns`, `fcm`, `webpush`), `token`, and
optional `endpoint`, `webpush_p256dh`, `webpush_auth`. Unknown fields are refused:
the caller cannot supply an owner, target delivery id, credentials or expiry.
Success returns `push_route_registered` with server-assigned `expires_at` and the
signed `request_id`. A refused registration returns `push_route_refused` with the
same `request_id`; the session stays open. A `push_route_deregister` frame (body
`provider`, optional; signed for `POST /notify/v1/push-route/delete`) is answered
with `push_route_deregistered`. Only the device bound as the routes' owner may
delete them.

The gateway verifies possession, session binding and fresh root-qualified router
authority. It forwards a short-lived, domain-separated node-signed control over
notify's mTLS QUIC mesh endpoint. Notify independently checks current authority,
stores an encrypted ownership binding, rechecks it before preparing delivery,
and periodically removes revoked routes. Notify's own clock sets the route
lifetime, and the gateway control may be up to 5 seconds ahead of notify's clock. Lookup failures defer delivery; an old
root-signed manifest cannot reactivate a device against the current router head.

Operators provide `RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE`, a JSON array of the
existing tagged `ProviderCredential` records with node-owned secret references.
The first configured credential matching the requested provider is selected.
APNs and FCM endpoints are derived from that server configuration; clients cannot
choose them. APNs tokens are even-length hexadecimal strings of 64 to 400 characters.
An empty `RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE` means "not configured". WebPush requires HTTPS and an exact origin in the comma-separated
`RAMFLUX_NOTIFY_WEBPUSH_ORIGINS` allowlist; credentials and endpoint routing must
be provisioned by the operator before accepting subscriptions. Provider secret
references are stored in redb; provider secrets remain in the referenced files or operator-controlled environment.

Apple/Google receive their device token, a generic alert, wake id, delivery class,
encrypted hint, and a collapse value keyed with the notify route secret
(HMAC-SHA-256). Knowing a delivery id does not let anyone predict it. The raw canonical collapse
key is not forwarded. Provider diagnostics omit raw tokens and application
content. Push providers still learn destination and timing metadata. The
feature-gated `itest-http` registration/credential APIs are synthetic fixtures;
they are not the production registration boundary.

## Known limitations

- Secret-store compaction after a migration is best effort. Federation and notify
  compact redb only on the startup that performs the migration. An interrupted
  startup leaves retired pages until a later compaction, and a single `compact()`
  call may not reclaim everything.
- Source-IP admission buckets use an ephemeral per-process key unless
  `RAMFLUX_NODE_PRIVACY_KEY_FILE` is mounted. Without it, per-IP registration
  budgets reset on every gateway restart and are split across gateway replicas.
- The check that a secret lies outside the database volume is a path heuristic: it
  rejects secrets under the database's parent directory. It does not compare mount
  points, so operators must still mount secrets from a separate location.
- A delivery dead-lettered because the ACK window overflowed is dropped without a
  signal to the recipient: cursor responses do not report dead letters. NACKed
  deliveries are dead-lettered only after the recipient's own repeated NACKs.
