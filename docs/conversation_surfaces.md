# Conversation surfaces

A conversation surface is an authored, versioned A2UI v2 snapshot carried through
ordinary encrypted direct or group messages. Only its author can change or close
it. The authoritative hash is `ramflux_protocol::surface_snapshot_hash`; actions
bind the current version, surface hash, action name and argument hash.

## Local bus methods

`surface.send` and `surface.action` accept `conversation_id`, `message_id` and
`wire_base64` (base64url of the original protocol event or action bytes). The
conversation must already exist. The response reports `accepted` and
`renderer_error`; an identical committed request returns `replayed: true` without
another transport submission. A rejected request must use a new message ID after
its cause is corrected. Group actions are delivered only to the author's device.

`surface.get` accepts `surface_id`, optional `history_after` (exclusive version)
and optional `action_id`. It returns the current snapshot, version, hash, closed
state, renderer error, bounded hash history and accepted actions. History pages
contain at most 100 entries; `history_next_version` continues the page. For large
action payloads, select one `action_id` from the change notification.

`surface.list` accepts `conversation_id`, optional `cursor` and `limit` (1–100).
It returns metadata under `surfaces` and a `next_cursor`. The `surface.changed`
subscription topic also contains metadata only: clients fetch content explicitly
with `surface.get`. Snapshot text, fallback text and action arguments are absent
from change notifications.

The CLI exposes `rf surface send`, `action`, `get` and `list`. Sending commands
read the untouched JSON bytes from `--wire-file`. Message pages expose surface
content as `content_type: "surface"`, `surface_id` and the current `body_utf8`
fallback, so text clients display the authored fallback without interpreting UI.

## Integrity and persistence

The encrypted plaintext has a `ramflux.surface.v2` discriminator followed by a
signed carrier. Its device signature uses `ramflux.surface.carrier.v2`, covering
the exact payload bytes encoded in `wire_base64` and all conversation, sender,
author, surface and logical message identifiers. Peer signing keys come from
verified device records, and the transport-authenticated sender must match.
Protocol ingress uses only `from_wire_bytes`, retaining I-JSON rejection rules.

The account writer atomically stores the checkpoint (including closed state and
stream-finality tombstones), hash history, receipts and consumed decisions.
Rejected transitions preserve the last valid checkpoint and record a renderer
error. Delivery deduplication uses sender principal plus logical message ID;
reusing that ID with different bytes is rejected. Accepted decisions additionally
consume the sender/surface/version/action-name tuple, even if arguments change.
These records survive account restart. A network failure follows the existing
message transport's retry semantics; logical-message receipts become durable
when local projection commits.

The legacy recursive render-profile digest in `ramflux-sync` is named
`legacy_a2ui_render_profile_hash`. It hashes a different v1 object (recursive
component permissions and snake_case profile fields) under `A2I_CONTROL` and
retains that wire contract. It is not a conversation snapshot hash.
