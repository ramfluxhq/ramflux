# Conversation surfaces

A conversation surface is an authored A2UI v2 snapshot carried through encrypted
DMs or groups. Its identity is `(conversation_id, author_principal_id, surface_id)`;
`surface_ref` is an opaque commitment to that tuple. Equal surface IDs from other
authors or conversations coexist. Only the authenticated author changes or closes
a surface. `ramflux_protocol::surface_snapshot_hash` is authoritative.

## Local bus and CLI

`surface.send` and `surface.action` take `conversation_id`, `message_id`,
`wire_base64` and optional `author_principal_id`. Protocol ingress parses the exact
original bytes using `from_wire_bytes`. Local Rust callers can use the output-only
`SurfaceSendRequest` typed builder. Builder IDs contain 128 random bits; persist
the request before sending and reuse its ID and bytes for retries. `rf surface`
commands read `--wire-file`; `--message` is optional and otherwise generates an ID.

The response reports `accepted`, `renderer_error`, and `delivery_state: "submitted"`.
Surface carriers have `content_type: "surface"` and use the same synchronous
`message.submit` and `group.send` adapters, encryption, routes, pins, sender-key
distribution, gateway submission and message journaling as text. Transport failure
returns an error. The caller owns durable retry, as for text; the agent host
persists requests and a desktop can display a failed send with retry. A completed
identical request returns `replayed: true` without executing an action twice.
The retained authored carrier preserves its original signed event and result hash.
A failed send retains the quoted fallback in one logical timeline row and exposes
`delivery_state: "failed"` on the surface view. Per-device ciphertexts share that
logical ID; retrying does not add another timeline row.
DM delivery attempts every active peer device, even after one fails. `delivery_devices`
reports each root/device result; an aggregate failure retains the failed state and fallback.
Changing bytes under an existing ID is rejected.

Live author-device copies use the existing `OwnDeviceFanout` transport, one encrypted
per-event control with pair-ratchet-wrapped keys for active siblings. They never publish
full-history bundles or upload objects. The immutable inner device signature survives
node fanout rewriting the outer route. A lost ACK retries the same inner ciphertext
under a fresh outer envelope ID; sibling receipts and projection commit atomically.
`own_device_copy_state` is independent of peer `delivery_state`. The account retries
up to 10 attempts within the original 600-second lifetime (2–60 seconds backoff),
with a 256-message / 8 MiB pending budget. Each drain has a soft 250 ms work
budget and stops on its first network failure; one operation is bounded by the
ordinary gateway timeout. Exhaustion is visible as `failed`; an explicit
fresh resync can repair a sibling that missed updates. Manual history export/restore
remains separate from live fanout. Live copies require updated sibling receivers;
transport submission does not claim sibling projection or read acknowledgement.

`surface.get` accepts `surface_ref`, or `surface_id` with optional
`conversation_id` and `author_principal_id`. An ambiguous short ID fails explicitly.
It returns the snapshot, version, hash, closed/out-of-sync state and history.
`history_after` is an exclusive version cursor; `history_next_version` continues
pages of at most 100 hashes. `history_first_version` and `history_truncated` expose
eviction. Select `action_id` for a large action; `action_missing` reports eviction.
A public response is capped at 512 KiB. The CLI supports scoped selectors too.

`surface.list` takes `conversation_id`, optional `cursor`, and `limit` (1–100).
`surface.changed` contains metadata only. A foreign reject emits
`surface.rejected` against its authenticated sender/envelope, without changing
the author's view or emitting a change for it. Clients fetch content explicitly;
notifications never contain snapshots, fallback text or action arguments.

## All-terminal delivery and action decisions

DM events fan out to every active verified peer device. The author's own
siblings receive live authenticated own-device history sync copies. The account
sync driver retries a pending history revision; this uses the existing encrypted
history object/export/import protocol, with no per-surface transport queue. Group publications use the same sender-key ciphertext, distribution
controls and verified member routes as group text. Physical delivery wraps that
ciphertext for each member; it does not encrypt separate peer surface controls.
Group actions use the same group adapter restricted to the author's member
routes, keeping arguments off unrelated recipients. Group members copy accepted
events to their own siblings through history sync. Own forwarding requires the same verified identity root, preserves the
original signed carrier, and never copies DM ratchet state. Existing
blocked/revoked contacts are preserved.

The authenticated own-device history bundle pages validated surfaces in batches of
64, up to 64 pages, with 128 retained actions per surface and 8 MiB total surface
data. It prioritizes own authored state before peer state and emits each selected
window oldest-first. `surface_export_metadata` exposes
`truncated`, an optional older-window `next_before` cursor, and counted `skipped`
reasons; the same metadata is recorded locally. A peer cannot abort the bundle by
omitting a full-state proof or exceeding a count budget. Normal signed proofs are
forwarded when usable. Otherwise the last locally validated checkpoint is copied
as private account state inside the authenticated same-root snapshot, with scope,
version, hash, executor, finality and membership-floor checks on restore. This
checkpoint grants no peer signing authority and is never accepted as a peer
carrier. Pending stubs and unavailable decision attestations are explicitly
omitted. Peers may continue sending valid events without optional full-state
proofs; every accepted state has a checkpoint representation. Historical peer
manifests on signed forwarding controls still require current verification.

Actions fan out to all verified author devices. The surface's creator device is
the sole decision executor, pinned when the surface is created. It consumes a
principal/version/action-name once, validates version/hash/arguments, and signs a
receipt containing the original action and a state proof. Siblings authenticate
that receipt and mirror the consumed decision. Only the creator exposes
`actions[].actionable: true`; replicas expose `false`, with
`is_action_executor: false`. Consumers must check those fields. Single use is
account-wide even when the human retries from another terminal with another ID.

This deliberately favors single execution over failover availability: when the
creator is offline, siblings hold the action for up to the retry window. They do
not elect another executor or execute it independently. A revoked/lost creator
requires a newly authored surface. There is no distributed executor lease or
automatic handoff in this version.

There is no surface-specific outbox, coalescing queue or delivery scheduler.
Delivery guarantees match text. A behind recipient is marked `out_of_sync` and
recovers through an explicit signed full-state resync, preserving finality checks.

The carrier admission cap is `(MAX_GATEWAY_FRAME_BYTES - 64 KiB) / 32`, currently
30 KiB, using the shared 1 MiB transport frame limit. The conservative 32x bound
covers JSON byte arrays, group wrapping, encrypted pair framing and base64; a
100-device cryptographic test measures real envelope sizes. Oversize carriers
return typed `SurfaceDeliveryTooLarge` before group or pair sealing, including
when submitted through the normal text methods. Identifiers and routing have
64 KiB reserved headroom; normal transport framing remains the final bound.

## Ordering, integrity and retention

The signed `ramflux.surface.v2` carrier uses `ramflux.surface.carrier.v2`. Its
signature covers conversation, author, actual sender, logical ID, original payload
bytes and any full-state proof. Sender principals come from authenticated device
records, not carrier claims. No receipt is stored before authentication succeeds.
Rejected deliveries are keyed by authenticated device/envelope; they cannot reserve
a victim's logical ID. All private keys, receipts, decisions and events are scoped
by the full surface identity. Checkpoint/row disagreement is a typed storage error.

Future versions are held durably and replayed in order when the gap fills. The
holdback is capped at 32 entries / 1 MiB per surface, 64 entries / 4 MiB per authenticated author,
and 64 versions of lookahead. TTL is 600 seconds, capped by original envelope
expiry. Aggregate storage scales with the number of authorized authors; expiry
sweeps inspect at most 65 rows per tick with a persisted cursor. Future events do not receive permanent rejection receipts. Expiry or
backpressure marks `out_of_sync`; an author-signed explicit resync can recover
it while preserving known stream-finality commitments. Until that resync arrives,
the last valid snapshot remains visible. The author calls `surface.resync` with
`surface_ref` and an optional durable `message_id`, or `rf surface resync`.
A recipient can call `surface.request_resync` with `surface_ref`, or
`rf surface request-resync --account ... --surface-ref ...`. The surface must be
out of sync. Requests use authenticated pair controls to the author's devices;
only the original author device answers with a full-state control over the pair route
to the requesting device. Group recovery never broadcasts or journals unrelated rows.
This deterministic coordinator prevents amplification across author devices and
must be online to answer. Requesters are limited to one request per surface per
60 seconds; the author maintains one shared window per surface, allowing one response per
requester device and at most 64 devices per 60 seconds. Each requester root/principal
can request at most 32 distinct surfaces in that window. Guard tables retain at most
2,048 live rows each; pending replies retain at most 256 rows and expire in 60 seconds. The admission
window commits before the synchronous send; after a failed reply the requester can
try again next window. No surface delivery outbox or group scheduler is introduced.

Normal authored patches, stream appends and closes contain the original delta
plus the mandatory resulting snapshot hash. A missing hash is rejected; disagreement
marks `out_of_sync` without advancing state or hash history. They carry no full
snapshot or checkpoint.
Full state travels in creates and explicit resyncs; resync carries one create-shaped
wire payload and compact content-free finality metadata. The canonical snapshot
cap and per-block stream accumulation cap are 16,384 bytes. JCS and domain-separated
BLAKE3 hashing remain unchanged. Create-shaped canonical snapshots omit empty
`components`, `dataModel` and `allowedActions` collections. Typed readers restore
an absent collection to its empty default; explicit null is not an empty collection.
`surface.get` exposes that canonical representation, so clients must not insert an
empty array into the bytes used for snapshot hashing. Resync rejects rollback, same-version conflicts,
reopening closed state, executor changes, and changes to known finalized blocks.
Private finality tombstones use BLAKE3 commitments; local checkpoint decoding is
capped at 256 KiB.

A history retains at most 256 events / 4 MiB per surface, evicting oldest versions.
Holdback adds at most 1 MiB to that history budget. Actions retain at most 128 rows /
4 MiB; response pagination never exposes private carrier/proof records. Authored
retry records retain at most 256 rows / 4 MiB. SQL savepoints cover state, history,
receipts and decisions so failures cannot leave partial transitions.

Text clients receive `content_type: "surface"` and a fixed single-line body:
`Surface author="..." fallback_text="..."`. The verified author's label and
untrusted text use the shared protocol `text_safety::quote_fallback_field` adapter:
controls/format characters, line separators, quotes and backslashes are escaped,
while printable Chinese, accents and emoji remain readable. Embedded status lines,
terminal escapes and bidi controls cannot forge terminal output. Protocol ingress
also applies its shared free-text policy. The original accepted text remains in
the structured snapshot and signed hash.

This pre-merge revision changes private checkpoint/storage scoping; use fresh
prototype account roots rather than importing unscoped development databases.
The legacy sync `legacy_a2ui_render_profile_hash` hashes a different v1 recursive
permission/profile object under `A2I_CONTROL`; it is not a conversation hash.


### Serialized history budgets

History pages count the serialized controls, checkpoints, metadata, commas and
outer array against the 8 MiB total. Individual items are omitted with counted
skip reasons and explicit truncation when the remaining budget cannot hold them;
an oversized first page cannot turn into an unmarked empty export. Imports use
page-scoped skip records. Reimporting an equal version validates its hash and
leaves the existing history carrier intact.

Fallback fields retain printable Unicode, including ideographic/nonbreaking spaces,
variation selectors and ordinary combining marks. Leading combining marks are escaped.
Hangul fillers, private-use and unassigned code points, controls, format characters,
line separators, quotes and backslashes are escaped by the shared protocol renderer.

The DM lifetime remains 600 seconds. JSON byte-array ciphertext expansion is a
shared transport framing limitation; changing that versioned envelope is separate
from the surface delivery change. History trimming measures each item once and
accounts incrementally for framing and omission metadata.


### Own-device copies and client metadata

Live own copies use `ramflux.sdk.own_device_message.v2`. The node sees only an
opaque logical ID, nonce, ciphertext, signature and recipient cryptographic slots.
Conversation, group, principal/root, original timestamps and logical message context
are inside authenticated encryption; slots contain no conversation ID. Routing
identity and fresh outer envelope timestamps remain available to the node.
FIFO retry sequencing prevents an older backed-off copy being overtaken. Disposable
copy receipts retain at most 4,096 rows (logical expiry plus 300 seconds), and copy
statuses at most 2,048 rows (900 seconds). The first live copy per conversation/epoch
carries bootstrap context, refreshed after 600 seconds; subsequent copies carry only
the event and necessary signer proof. Explicit history export still carries full
context. Legacy v1 queued copies fail their own-copy status and require a fresh copy
or history sync; peer delivery status is independent.

`surface.get` and content-free `surface.changed` metadata include `streams`, a map
of text-capable component IDs to `open` or `final`. Open means appends are permitted;
final means the protocol finalized that block or closed the surface. This map does
not change the content hash. Created/posted and updated times are author-signed
seconds since the Unix epoch, preserved through resync; old undated carriers expose
null rather than a fabricated author time. These are display metadata, not trusted
clock or transport-order evidence. Removal and close metadata carry `surface_ref`.
Refusals expose stable snake-case `reason_code` values, including `stale_version`,
`stale_hash`, `not_author`, `not_out_of_sync`, `rate_limited` and `too_large`.
