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

The response reports `accepted`, `renderer_error`, and `delivery_state: "queued"`.
Acceptance commits local projection and a durable encrypted outbox atomically;
it does not claim remote delivery. Identical committed requests return
`replayed: true`. The retained authored carrier preserves its original signed
snapshot proof on retry. Changing bytes under an existing ID is rejected.

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

Events fan out to every active verified peer device and the author's own sibling
devices. Group routing preserves membership epochs and join floors; sibling
membership follows the same verified identity root. Own forwarding is permitted
only from the same verified root, preserves the original signed carrier, and
never copies DM ratchet state. Existing blocked/revoked contacts are preserved.
The existing own-device history bundle includes bounded signed surface proofs and
decision attestations, with group-epoch filtering for surface messages. Historical
signer manifests must still pass current verification; unavailable/expired trust
material fails explicitly rather than granting stale authority.

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

Prepared ciphertext envelopes are committed before transport submission and
reused unchanged on retries. The account transport queue holds at most 64 jobs /
32 MiB; fanout backpressure rejects admission before local acceptance. Logical
own-forward/decision jobs hold at most 64 entries / 8 MiB. Retries are bounded by
8 attempts, the original envelope expiry and a 600-second window.

## Ordering, integrity and retention

The signed `ramflux.surface.v2` carrier uses `ramflux.surface.carrier.v2`. Its
signature covers conversation, author, actual sender, logical ID, original payload
bytes and any full-state proof. Sender principals come from authenticated device
records, not carrier claims. No receipt is stored before authentication succeeds.
Rejected deliveries are keyed by authenticated device/envelope; they cannot reserve
a victim's logical ID. All private keys, receipts, decisions and events are scoped
by the full surface identity. Checkpoint/row disagreement is a typed storage error.

Future versions are held durably and replayed in order when the gap fills. The
holdback is capped at 32 entries / 1 MiB per surface, 64 entries / 4 MiB per account,
and 64 versions of lookahead. TTL is 600 seconds, capped by original envelope
expiry. Future events do not receive permanent rejection receipts. Expiry or
backpressure marks `out_of_sync`; the next author-signed full snapshot can recover
it while preserving known stream-finality commitments. Until that snapshot arrives,
the last valid snapshot remains visible. There is no active resync request.

Every normal authored event includes a signed full-state proof, including the
bounded checkpoint and original create-shaped snapshot bytes. This is distinct
from a patch: the original patch still enters through `from_wire_bytes`. Snapshot
recovery rejects rollback, same-version conflicts, reopening closed state, executor
changes, and changes to known finalized stream blocks. Private finality tombstones
use domain-separated BLAKE3 commitments; checkpoint decoding is capped at 256 KiB.

A history retains at most 256 events / 4 MiB per surface, evicting oldest versions.
Holdback adds at most 1 MiB to that history budget. Actions retain at most 128 rows /
4 MiB; response pagination never exposes private carrier/proof records. Authored
retry records retain at most 256 rows / 4 MiB. SQL savepoints cover state, history,
receipts, decisions and outbox writes so failures cannot leave partial transitions.

Text clients receive `content_type: "surface"` and a fixed single-line body:
`Surface author="..." fallback_text="..."`. The verified author's label and
untrusted text are quoted, with controls and non-ASCII escaped. Embedded status
lines, terminal escapes and bidi controls therefore cannot forge terminal output.
The original text remains in the structured snapshot and signed hash. One SDK
adapter is the integration point for the shared protocol sanitizer.

This pre-merge revision changes private checkpoint/storage scoping; use fresh
prototype account roots rather than importing unscoped development databases.
The legacy sync `legacy_a2ui_render_profile_hash` hashes a different v1 recursive
permission/profile object under `A2I_CONTROL`; it is not a conversation hash.
