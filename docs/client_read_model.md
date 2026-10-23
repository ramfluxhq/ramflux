# Local client read model

All methods use local-bus protocol v1 request frames. Supply `account_id` for account directories.
They use the account's query-only reader connections and one SQLite snapshot per request; they do
not acquire the mutation mailbox or contact a gateway/relay. A locked account has no read pool.

## Startup account restore

`account.unlock` is safe to repeat while startup auto-restore is running or after an account has
opened. Every uncached unlock verifies the supplied `passphrase` against the wrapped database key,
including when the account is already open, and returns the normal account creation/unlock response.
A wrong passphrase still fails. Existing operation-ID receipt replay semantics are unchanged.

Subscribe with `subscription.open` for the account and topic `account.restore.finished` to receive
startup restore completion. The event body is `{"state":"unlocked"}` on success, or
`{"state":"failed","error":{"code":"...","message":"...","retry_after_ms":null}}`
on failure. Success means the local account is open; its gateway session may still be disconnected.
These are live subscription events; a subscriber that connects after completion uses `account.list`
for the current state. Locked accounts are not auto-restored. Failed restores can be retried with
`account.unlock` and the correct passphrase.

## Typed display metadata

`LocalBusAccountCreateRequest` accepts optional `label` and `kind`. Labels contain at most 64
Unicode characters; kind is `human`, `headless_ai`, or `bot`. An absent kind retains the existing
client-mode default. `LocalBusMessageAttachmentInput` accepts optional `name` and `mime`: name is
at most 255 UTF-8 bytes without `/`, `\\`, or control characters; MIME is a concrete type/subtype
with optional parameters, at most 1024 bytes. Invalid metadata is rejected before dispatch.
Absent or null fields are accepted; absent values stay omitted when typed requests are serialized.

## Node socket diagnostics

Local-bus error bodies may include `cause: {kind, raw_os_error}` when an `io::Error` exists in
the source chain. `kind` is the Rust error-kind name (for example `HostUnreachable` or
`ConnectionRefused`), and `raw_os_error` is the native errno or null. Values come from the error,
never message parsing. Clients can use the native platform and errno to explain OS-specific
network permission or routing failures. Discovery HTTP errors omit request URLs, credentials,
query strings and fragments while preserving their source chain.

`node.probe` retains its health response and adds structured errors at `discovery.error`,
`gateway.errors.quic`, `gateway.errors.tcp`, `gateway.errors.session`, `relay.error`, and
`prekey.error` when those stages fail. Each uses the same bus error shape. Not every failure has
an OS cause: protocol rejection, missing authentication, and QUIC timeouts need not provide errno.
These diagnostics do not establish a platform permission denial from a string or invent errno.

## Pagination

`conversation.directory`, `identity.directory`, and `object.directory` accept:

```json
{"limit": 50, "cursor": null}
```

`limit` defaults to 50 and must be 1–100. Responses contain the named array below and
`next_cursor` (string or null). Pass the opaque cursor back to the same account and method.
Cursors are versioned, scoped keyset positions; every page is a fresh snapshot, not a retained
multi-page database transaction. Invalid, oversized, or wrong-scope cursors fail explicitly.
Refresh from the first page to see insertions ordered before a previous cursor.

Pages target a 512 KiB response budget and are checked against the actual 1 MiB framed-response
limit. A single record larger than the budget returns an error rather than silently dropping fields.
A shorter page may still have a next cursor. No directory silently truncates a row.

Existing `group.list`, `mcp.server.list`, and `mcp.approval.list` support the same optional paging.
With neither pagination field supplied they retain complete legacy list semantics, with an explicit
error if the response would exceed the frame limit; use paging for large accounts.

## Conversation directory

Response key: `conversations`. Each row contains:

| Field | Type / meaning |
| --- | --- |
| `id` | Conversation ID |
| `kind` | `direct` or `group`; null for a legacy record with no captured classification |
| `title` | Explicit local title, or null; never an invented display name |
| `participants` | Known principal IDs, excluding unresolved device references |
| `self_principal_id` | Local account principal ID |
| `member_routes` | Group member device IDs, commitments, signing keys, targets and `delivery_target_known`; absent for DMs |
| `group_id` | Explicit group ID, or null |
| `direct_route` | Object below, or null when unresolved/no longer active |
| `unread_count` | Count after the stored reader watermark and clear boundary |
| `is_unread` | Existing local unread projection, including manual unread markers |
| `last_activity` | Last nondeleted message timestamp, or null |
| `muted`, `mute_until` | Current mute flag and optional expiry |
| `disappearing` | `{timer_seconds,countdown_mode,scope}` or null |
| `archived`, `hidden` | Stored list flags |

A known route contains `recipient_principal_commitment`, `recipient_device_ids`,
`target_delivery_id`, and optional `federation`. Its first device is the selected target for that
route. Identity rows supply per-device targets and signing public keys for selecting another device.
Routes are captured from successful submissions and checked against the current verified device set.
An expired/revoked selected device produces a null route; the client must select an active device.

There is no network lookup to invent a route for an unknown contact. Existing conversations with
no captured association keep unknown peer/title fields empty/null. `group.create` may supply an
additional `conversation_id`; `group.send`/`group.receive` already carry it explicitly. Those
operations persist the association. Group IDs are never treated as conversation IDs by the reader.

## Identity directory

Response key: `identities`. Rows contain `id`/`principal_id`, `display_name`, `kind`, `is_self`,
`principal_commitment` (also exposed as `contact_identity_commitment`), `devices`, `safety_state`, `safety_number`, and
`safety_number_available`. The local principal is included after unlock.

Verified device rows contain `id`/`device_id`, `signing_public_key`, `target_delivery_id`, `label`,
`last_seen`, and `verified_at`. The manifest supplies principal/device membership, signing keys,
and delivery targets. `verified_at` is a verification observation, not a fabricated last-seen time.
A new verified manifest replaces the active device set. Cached safety numbers survive unchanged
sets and are cleared on set changes. A previously verified changed set reports `verification_stale`.

Display names, remote principal kinds, device labels and last-seen times are null when not supplied
by an authoritative local source. The current remote manifest does not carry those profile fields.
Self kind is `human`, `headless_ai`, or `bot`, as declared in local account metadata (with existing
client mode as the fallback). Unknown remote kinds remain null rather than assuming Human.

`contact.safety_number` and `contact.verify` persist their computed number for directory reads.
A missing number has `safety_number_available:false`; fetching one remains an explicit contact
operation. Directory lookup itself never performs a network request or changes verification state.

## Object directory

Response key: `objects`. Rows contain `id`, `name`, `size`, `mime`, `direction`, `owner`,
`conversation_id`, `message_id`, `relay_endpoint`, `transfer_state`, `updated_at`, and `transfer`.
`transfer` is null or `{id,state,peer_device_id,updated_at}`. Timestamps are Unix seconds.

Rows select scalar metadata only. No ciphertext, object body, content key, nonce, resume token,
franking data or plaintext payload is returned. Size uses explicit upload metadata or the existing
ChaCha20-Poly1305 object size minus its 16-byte tag. Tombstoned objects are omitted.

Uploads may carry optional `name`/`mime` metadata; streamed uploads retain metadata from begin
through finish. DM attachments record conversation/message references on both sender and receiver.
Direction is `outgoing`/`incoming` when observed. Fields unavailable for older/imported records
remain null. Existing attachment payloads do not transport filename/MIME, so those fields on the
receiving side can remain null. `object.get` accepts a locally available directory object ID.

Received references are persisted in the unlocked account's encrypted database even when
`message.receive` has `auto_fetch_attachments: false`. Such rows have `transfer_state: "not_fetched"`
and include their manifest hash and original conversation/message IDs. Grants, content keys and encrypted
key slots remain private account state and never appear in directory rows.

Call `object.fetch {object_id, operation_id}` to fetch one received reference independently of
message receipt. Both identifiers must contain 1 to 256 bytes. The compact reply contains
`object_id`, `operation_id`, `transfer_state`, `last_error` and `retryable`; it never includes keys,
grants or plaintext. A failed transfer returns `transfer_state: "failed"`, a sanitized error category
and `retryable: true`; the message remains visible. Retry with the same operation ID to resume
verified encrypted chunk checkpoints. Interrupted attempts become retryable failures on daemon
restart. During an attempt the directory reports `fetching` or
`retrying`; success reports `available`, and the normal object read APIs then return the bytes.
Bare `object.get` and `object.get.begin` requests for a completed received attachment use its local
bytes even with a saved node relay profile; explicit relay requests retain their existing behavior.
Successful operation IDs replay their receipt locally, including after daemon restart; reusing
an operation ID for a different object fails. The body operation ID owns this retry policy even
when the frame also carries a generic operation ID.

One attempt permits at most 15 seconds of gateway connection setup and 60 seconds of import,
with at most 16 MiB plaintext, 4096 chunks and 512 KiB per chunk. Access grants still expire and
may be revoked; fetching does not renew or bypass them. Existing auto-fetch callers retain their
receive-time import behavior. A per-object fetch never advances the main message receive cursor.

## Existing list extensions

- `account.list` preserves `accounts` (open IDs) and `active_account_id`, and adds `account_details`
  for every indexed account: `{id,state,label,kind,principal_id}`. State is `locked` or `unlocked`.
  Locked manifests are read without opening account databases. New `account.create` bodies may
  supply `label` and `kind`; both are retained in the private account manifest. This index-wide
  method belongs to the Supervisor and does not require an unlocked account.
- `group.list` adds `id`, `conversation_id`, and `conversation_ids` to its existing group rows.
  A single explicit association gives `conversation_id`; no association or multiple distinct
  associations gives null. Every explicit association remains in `conversation.directory`.
- `mcp.approval.list` includes `conversation_id`/`context_id` when supplied on the originating
  MCP/grant request; lifecycle events carry the same fields. Pending records survive restart.
  Granted/denied records disappear from the pending list. A context is never guessed from tool
  arguments or another account's focused conversation.
- `mcp.server.list` preserves `servers` (IDs) and adds `server_details` rows
  `{id,reachable,last_check,health_source}` from the server registry. The current local dispatcher
  has no transport health probe: unobserved health is `null,null,"not_checked"`. Registration or
  an installed tool is not proof that an external MCP process is reachable.

The directories are additive local projections; node protocol and authorization checks are unchanged.

## Group delivery completeness

Without an explicit single-recipient envelope override, `group.send` resolves routes for every
current member other than the sender. Verified directory entries take precedence over stored
routes. The server validates the entire route set before encrypting, writing a local message or
sending any distribution. Missing targets, commitments or signing keys fail with
`group routes unresolved` and an `unreachable_members` array listing every unresolved device.
No member is silently skipped. Transport failure during an attempted send still returns an error;
preflight cannot make distributed delivery atomic.

`conversation.directory` group rows and `group.list` expose `member_routes` including unresolved
members. `delivery_target_known` describes available routing metadata, not network reachability.
`account.status` now includes `principal_commitment`, matching the self identity directory row.


## Autonomous receive and compatibility reads

The unlocked account's driver owns network receive, decryption and gateway acknowledgement.
A gateway ACK follows a durable projection/ratchet commit and does not consume a client's local
read. `message.receive {conversation_id, limit}` runs a synchronization pass and returns decrypted
Direct deliveries retained in the account's recent delivery cache, including messages the driver
already committed and ACKed before the request. The caller's conversation ID filters authenticated
routing; it never authorizes or invents a legacy binding. Existing Direct conversations still require
explicit sender participation. With an omitted/null conversation ID, the response includes committed Direct deliveries across
conversations, selected from their authenticated routing. The limit applies after filtering.
Unbound legacy or malformed opaque payloads are never guessed into decrypted messages. Attachment
auto-fetch uses the same selected page and its existing shared timeout.
The cache holds at most 64 deliveries, is shared by local clients,
and is not a per-connection read cursor. Repeated compatibility reads can return the same retained
message until explicit `message.ack` removes it from this cache. Across restart or cache eviction,
use durable `message.list` / `message.read`; resumable `bus.subscribe` provides change cursors.

An outgoing envelope signed by a registered device derives `source_principal_id` from that device's
account principal. Passing the account's root commitment in the legacy submit field does not change
wire attribution. Receivers continue to verify device ownership and the envelope signature; they
never accept a caller-supplied unrelated principal as the signing device's owner.

Message identity is `(authenticated source device, envelope_id)`. Returned projection IDs remain
compatible in the ordinary case; cross-sender collisions receive stable sender-qualified opaque
IDs. The `routed:` namespace is reserved and escaped for caller-chosen wire IDs, preventing a peer
from squatting another sender's qualified ID. Treat returned IDs as opaque; do not predict group
fan-out IDs, which are independently randomized for each recipient.

Receipts require participation in the authenticated conversation and have sender-scoped receipt IDs.
A2I events also have sender-scoped identity. An ambiguous event ID cannot acknowledge a different
sender's event; use the `acknowledge_id` returned by `a2i.list` / `a2i.list_pending` as the acknowledge request's `event_id`. Acknowledgements are durable across
restart. Legacy A2I commits its event and ratchet atomically before ACK, like the v2 path.

## Inbox ordering and recovery

A malformed signature, authenticated ciphertext/commitment failure, or unsupported schema is
terminal: encrypted dead-letter storage precedes ACK and a metadata-only `message.undeliverable`.
Membership ordering, missing/freshness-dependent manifests, clock-dependent branch checks, missing
prekeys, transport/storage availability and ratchet skip limits retry independently with backoff
until the packet's gateway TTL. They do not block later entries or cause an early ACK. A packet
requiring an oversized ratchet skip can recover when intermediate packets arrive; bounded oldest-first
skipped-secret eviction prevents accumulated holes from permanently wedging the session.

The private storage re-drive API can requeue retained dead-letter ciphertext. Membership and
manifest changes automatically re-drive it and wake state-dependent retries. Retry and dead-letter
queues each remain bounded to 64 records / one MiB per entry / seven days; re-drive leaves a dead
letter retained when retry capacity is full. Expired or evicted material cannot be recovered through
this API. Refused v1 downgrades remain quarantined and unacknowledged until quarantine expiry or
explicit compatible handling. They are not dead-lettered merely because a v2 pair became active.

Two simultaneously initiated sessions converge by deterministic ordering only after authenticated
inbound confirmation for the same verified device pair; unverified/package sessions cannot select
the outgoing session. Once a peer confirms a local session, its bootstrap header is erased and the
bidirectional DH ratchet continues. Own-device history transfers approved plaintext content without exporting or importing live DM
ratchets (including legacy snapshots). The legacy response counter `imported_dm_sessions` remains
present and is zero. Existing message IDs, timestamps and group history-floor checks remain. Attachment
references retain content keys and original slots, with no ratchet snapshots; they commit with the
message and are scoped by sender. Object ID collisions receive separate `received:` selectors.
Fetch failures remain object-directory/events state and do not alter message content snapshots.

### Device-pair recovery and bounded inbox work

Each verified device pair has one current sending state and up to eight previous receive
states, newest first. Promotion archives the previous current state. Decrypt checks current
then previous states by authenticated session id; an archive hit advances only that state and
never demotes current. A verified delayed bootstrap can promote safely because traffic on the
other live state remains decryptable. Only eviction erases private state and tombstones the id;
authenticated traffic for an evicted state requests a fresh encrypted reset.

A gap beyond the ratchet skip limit or lost state creates durable reset work. Transport submit
acceptance does not confirm recovery. A persistent pair budget survives confirmation: at most
one reset per minute and ten attempts in any rolling 24-hour window. Refusals produce metadata
in `session.reset`. Backoff starts at one minute and caps at five minutes, with the daily budget
postponing later attempts. Only hearing the peer on current confirms recovery. A known evicted
state superseded by that confirmed current is dropped without starting another reset.

Contact removal/blocking, a verified manifest removing a device, and own-device revocation stop
retry work and erase the pair's private states. Revoking the local device clears all its pairs
and fences pair traffic. Retry ticks recheck eligibility. After seven days
from the first attempt, automatic work stops and private states are erased. `identity.directory`
includes `pair_recovery` metadata with `state: needs_manual_recovery`; `session.reset` carries the
same state. Older pending records recover their original start from retained journal evidence;
missing age evidence fails closed to manual recovery instead of renewing the window.
A subsequent valid peer confirmation clears the marker, but stale packets never
restart automatic work while the marker remains.

Encrypted reset acknowledgements let a passive receiver finish recovery. Concurrent unconfirmed
bootstrap candidates choose the lower session id symmetrically, including a reset racing a plain
bootstrap; both states remain decryptable. An unacknowledged candidate that exceeds its skip
window is replaced before a further attempt. Device identity, envelope signature and AEAD checks
remain mandatory before promotion. Orphan session flags are pruned, and at most eight recent
tombstones per pair are retained (unattributed legacy tombstones share a bounded upgrade bucket).
Very late authenticated bootstraps remain subject to the archive's existing compatibility rules.
No conversation descriptor is exposed outside the encrypted body. Failed attachment-slot decrypts
leave the live message ratchet unchanged.

Group invitations and accepts reject already active members. Generic member-key persistence
cannot overwrite an active member's key; a verified device-manifest refresh is the rotation path.
Inactive members can still rejoin with the key proven by their signed accept and the invited role.

Retained retry and dead-letter ciphertext never evict a different source. A claimed source gets
at most two retained failures before authentication/relationship confirmation, or eight for a
verified related peer; strangers share a 16-entry admission budget. Each queue remains bounded
to 64 entries. Trusted failures expire within ten minutes and eight attempts; stranger failures
expire within thirty seconds and three attempts. Gateway TTL can shorten these windows.
Only live retries wake after matching newer group/manifest changes. Original age, expiry and
attempts remain unchanged, with at most eight wakes per second and one per entry per minute.
Dead letters are terminal diagnostics and are never automatically reinserted or re-ACKed by
membership changes. Idempotent key imports and unrelated device records do not advance scoped
revisions. The legacy unrouted hold retains its separate retention contract.

Account writers enable SQLCipher secure deletion. Upgrade overwrites obsolete imported live
ratchet payloads and signatures, preserving ledger ids and counters as explicitly retired
tombstones so causal references remain valid and counters cannot be reused. Reads and history
exports omit retired payloads; surviving event signatures and history imports remain valid.
Old exported pair history and obsolete slot snapshots are erased too. WAL checkpoints follow
retirement transactions. Filesystem snapshots, backups and previously exported blobs are outside
this local operation; active readers can delay checkpoint progress. Live and persisted ratchet
message-key Debug output is redacted, and legacy routing compares typed device hashes without
copying a full secret snapshot to JSON.
