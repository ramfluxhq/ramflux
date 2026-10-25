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
| Router | Encrypted envelopes are removed on ACK or creation time plus TTL, capped at seven days. A 30-second sweep removes expired inbox/replay rows, and inbox reads expire messages before returning them. Cursor sequence watermarks remain to prevent replay; envelope-id ACK and NACK diagnostics retain at most 1,024 entries per target. New out-of-order ACK windows are limited to 1,024 sequences with backpressure, preserving earlier gaps. Oversized legacy sequence windows drain when their outstanding gaps close or expire; they are not truncated into possible redelivery. Registration-proof receipts expire under the identity replay policy. Identity/public-key and revocation records follow identity lifecycle policy, rather than inbox TTL. |
| Gateway | Live connections retain session metadata. Closed or disconnected sessions, frame queues and resume-token checkpoints are pruned every 30 seconds; disconnected metadata has a 300-second resume window. Expired challenge and replay state is pruned as well. |
| Notify | Pending wakes retain their delivery-class TTL. Every 30 seconds terminal/expired wakes are removed, including WAL records. Provider diagnostics retain one hour, at most 16 attempts per queue and 1,024 queues after each sweep. Production push routes expire after one day; token rotation replaces the device's prior route for that provider. Routes and ownership proofs are encrypted with a separately mounted node key. |
| Federation | The outbound spool retains opaque envelopes until delivery or the earlier of envelope expiry and a seven-day spool cap. The retry loop and authenticated retention GC remove expired spool entries and seen-forward receipts. Public trust/pin and revocation state is separate from delivery retention. The node signing secret lives in a mounted file, never a new redb value. |
| Relay | Attachment chunks are client ciphertext. `RAMFLUX_RELAY_OBJECT_MAX_TTL_SECONDS` defaults to 86,400 seconds and cannot exceed 604,800 seconds, even with a larger environment value. Requested expiry can shorten this cap. Other object/tombstone policies remain independent. |
| Retention | Authenticated router/federation GC requests perform real deletion, including dry-run counts. Incident/evidence, legal-hold and lifecycle policies remain distinct; this does not promise that all server metadata expires after seven days. |

Router WAL files roll at least hourly when writing and are deleted once their
last modification is over seven days old. Logical expiry/checkpoints prevent
expired inbox messages from being restored before that physical cleanup. Redb
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
with Unix mode 0600 (0400 is accepted for read-only provisioning). Mount them
read-only outside the database volume. Services refuse missing, malformed or
permissively accessible files. Do not check generated files into source control.

- Notify requires `RAMFLUX_NOTIFY_ROUTE_KEY_FILE`. The development certificate
  bootstrap generates `certs/notify/route.key`, mounted at
  `/etc/ramflux/mesh/route.key`. Back up the key separately from the encrypted
  database: losing it makes saved push routes unreadable. Startup migrates legacy
  plaintext routes into authenticated AES-256-GCM ciphertext and compacts redb.
  Existing synthetic routes without verified owners are unusable in production;
  devices register again through their authenticated session.
- Federation requires `RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE`. Development
  bootstrap generates `certs/federation/node-signing.key`. For an existing node,
  stop federation and run its binary with the existing `--config` and
  `--export-signing-seed /outside-data-volume/node-signing.key`. The export is
  create-only, private and fsynced. Mount that existing key read-only, then start
  normally. A key different from the legacy identity is refused. Startup removes
  the legacy redb seed and compacts retired pages. A public-key pin prevents an
  accidental identity replacement on subsequent starts. Preserve old identity
  material before upgrading; remove obsolete data-volume backups separately.
  The old seed environment variable is no longer a runtime secret source.
- The retention service uses the same mounted federation identity for signed
  deletion receipts. Development compose mounts that key read-only as
  `/etc/ramflux/node-identity/node-signing.key`.

A live compromised node can read push tokens and signing secrets from memory or
mounted files. Encryption at rest protects a copied data volume without those
keys; it does not protect against the running node or its operator.

## Production push registration

Send a `push_route_register` gateway session frame with `request` containing
`signed_request` and `body`. Sign `POST /notify/v1/push-route` with the current
device branch key, canonical body hash, a fresh request id/nonce and expiry,
`device_proof_hash: "already_authed"`, and `ext.session_id` equal to the live
session id. Body fields are `provider` (`apns`, `fcm`, `webpush`), `token`, and
optional `endpoint`, `webpush_p256dh`, `webpush_auth`. Unknown fields are refused:
the caller cannot supply an owner, target delivery id, credentials or expiry.
Success returns `push_route_registered` with server-assigned `expires_at`.

The gateway verifies possession, session binding and fresh root-qualified router
authority. It forwards a short-lived, domain-separated node-signed control over
notify's mTLS QUIC mesh endpoint. Notify independently checks current authority,
stores an encrypted ownership binding, rechecks it before preparing delivery,
and periodically removes revoked routes. Lookup failures defer delivery; an old
root-signed manifest cannot reactivate a device against the current router head.

Operators provide `RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE`, a JSON array of the
existing tagged `ProviderCredential` records with node-owned secret references.
The first configured credential matching the requested provider is selected.
APNs and FCM endpoints are derived from that server configuration; clients cannot
choose them. WebPush requires HTTPS and an exact origin in the comma-separated
`RAMFLUX_NOTIFY_WEBPUSH_ORIGINS` allowlist; credentials and endpoint routing must
be provisioned by the operator before accepting subscriptions. Provider secret
references are stored in redb; provider secrets remain in the referenced files or operator-controlled environment.

Apple/Google receive their device token, a generic alert, wake id, delivery class,
encrypted hint, and a domain-separated collapse hash. The raw canonical collapse
key is not forwarded. Provider diagnostics omit raw tokens and application
content. Push providers still learn destination and timing metadata. The
feature-gated `itest-http` registration/credential APIs are synthetic fixtures;
they are not the production registration boundary.
