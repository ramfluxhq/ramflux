# Unified message read model

This is the contract between the SDK and the clients that render messages: the
`rf` command line client and `rf-tui`. It defines the JSON a client reads for a
conversation and the events it follows to stay current.

Status: implemented in the SDK and in `rf` behind the message schema v1 storage
generation. While the generation is zero, `rf` prints its existing output and
refuses the flags defined here. `rf-tui` adopts this contract at activation.

Contract name: `ramflux.message.read_model.v1`. Every response carries it in
`schema`. Fields are only added within this name; a removal or a change of
meaning uses a new name.

## Rules

1. **The durable store is the only source.** Every response is rebuilt from the
   account store. No response depends on an in-memory delivery page, so a daemon
   restart or a long unread backlog cannot hide a committed message.
2. **Events are hints; the cursor is the truth.** A client applies change
   batches by `journal_sequence`. A bus event tells it to ask for the next
   batch. Losing an event never loses a message.
3. **A slow subscriber is told.** When a subscriber's queue overflows, its last
   frame is `stream.lagged` and the subscription ends. The client reads changes
   from its applied cursor and subscribes again.
4. **Deleted means gone.** A tombstone carries the message identity and the
   erasure state only: no text, content, revision, reaction or receipt.
5. **No key material.** Content in the read model has no media key slot, no
   manifest read capability and no revision entropy. Media is opened through
   the object reader.

## Requests

All three shapes use the local bus reader `message.read` (alias
`message.list`), domain `message`. The selectors are mutually exclusive.

| Shape | Body | Response |
|---|---|---|
| Page | `{"conversation_id", "read_model": true, "limit"?, "before_order_key"?}` | `MessageViewPage` |
| Changes | `{"conversation_id", "after_sequence", "limit"?}` | `MessageChanges` |
| Single message | `{"conversation_id", "message_id"}` | `MessageDetail` |

`limit` is 1..=100 and defaults to 100. A response is at most 768 KiB encoded;
a batch that would exceed it is shortened and reports that more remains.

`rf` exposes the same shapes:

```sh
rf dm list --account A --conversation C [--limit N] [--before '<next_before JSON>']
rf dm list --account A --conversation C --after-seq SEQ [--limit N]
rf dm list --account A --conversation C --message ID
rf dm read ...    # same flags; first asks the daemon to pull and commit deliveries
```

`rf dm list` never contacts the network. `rf dm read` syncs first and then
prints the same durable response; the sync response itself is not printed.

## MessageView

```json
{
  "id": "<base64url, 32 bytes>",
  "conversation_id": "…",
  "author": {"account_anchor": "…", "device_id": "…", "device_epoch": 1},
  "device_sequence": 7,
  "hlc": 1731434000000,
  "group_id": null,
  "journal_sequence": 42,
  "is_own": false,
  "state": "content",
  "kind": "message",
  "text": "hello",
  "content": { "…": "generated Content JSON, as in MessageUpdate" },
  "unsupported": null,
  "erasure": null,
  "revision": 0,
  "edited": false,
  "reactions": [{"token": "👍", "count": 1}],
  "receipts": [{"device_id": "…", "principal_commitment": "…", "state": "read",
                "delivered_at": 1731434001, "read_at": 1731434002}]
}
```

| Field | Meaning |
|---|---|
| `id` | Identifier of the original immutable event. Stable across edits and deletion. |
| `author`, `device_sequence`, `hlc`, `group_id` | Original event identity. `hlc` orders display. |
| `journal_sequence` | Durable sequence of the row's last change. This is the change cursor. |
| `is_own` | True when the local account authored the message. |
| `state` | `content`, `unsupported` or `tombstone`. |
| `kind` | For `content`: `message`, `service`, `surface`, `task`, `call`, `control`, `self_sync`. Otherwise equal to `state`. |
| `text` | Text of a `message`; null for every other kind and state. |
| `content` | Typed public content in force (after edits). Null unless `state` is `content`. |
| `unsupported` | `{layer, kind, raw_length, reason}` when `state` is `unsupported`. |
| `erasure` | `{scope, tombstone_id}` when `state` is `tombstone`; `scope` is `local`, `everyone` or `unspecified`. |
| `revision`, `edited` | Highest applied edit revision; `edited` is `revision > 0`. Only the content in force is kept; earlier bodies are erased. |
| `reactions` | Visible reaction tokens with counts, ordered by token. |
| `receipts` | Per-device delivery and read state of an own message. |

Edits, reactions, receipts and deletes are not rows. They change the state of
their target row and advance its `journal_sequence`. Typing is never a row and
never appears in any response of this contract.

### Unsupported kinds

A message of a kind or layer this build cannot render is kept and shown as a
placeholder: `state` = `unsupported`, with `content` and `text` null. A client
renders a neutral line such as "This message needs a newer version" and must
not guess at the body. When a later build can decode it, the row changes to
`content` and its `journal_sequence` advances.

## MessageViewPage

```json
{"schema": "ramflux.message.read_model.v1", "conversation_id": "…",
 "messages": [MessageView], "next_before": {EventIdentity} | null,
 "snapshot_sequence": 42}
```

`messages` is newest first. Pass `next_before` unchanged as `before_order_key`
for the next older page; null means the beginning of history was reached.
`snapshot_sequence` is the journal head the page was read at: a client that
opens a conversation with a page starts following changes from it.

## MessageChanges

```json
{"schema": "ramflux.message.read_model.v1", "conversation_id": "…",
 "changes": [MessageView], "next_after": 42, "more": false,
 "snapshot_sequence": 42}
```

`changes` holds each row changed after `after_sequence`, oldest change first,
in its current state. Apply by replacing the cached row with the same `id`.
Then call again with `after_sequence = next_after` while `more` is true.

`after_sequence = 0` asks for the whole conversation in change order. Any other
cursor must lie inside the retained journal.

## MessageDetail

```json
{"schema": "ramflux.message.read_model.v1", "message": MessageView,
 "snapshot_sequence": 42}
```

## Events

A client subscribes with `bus.subscribe`. Three frames matter here:

| Frame | Meaning | Client action |
|---|---|---|
| `state.changed` (durable) | A row of the account changed. | Read changes from the applied cursor. |
| `message.transient` (`seq` = 0) | Live indicator such as typing. Never stored, never replayed, may be dropped under load. | Update the indicator; let it expire. |
| `stream.lagged` | The subscriber's queue overflowed. This is the final frame of the subscription. | Read changes from the applied cursor, then subscribe again. |

`stream.lagged` has the body
`{"last_delivered_seq": <number or null>, "dropped_frame_id"?, "dropped_topic"?}`.
A null `last_delivered_seq` means the bus did not track the position; the
client's own applied cursor is authoritative in every case.

## Errors

Failures use the shared typed error
`{"code", "name", "message", "details"}`. The codes a reader can meet:

| Code | Name | When | Client action |
|---|---|---|---|
| 1 | `invalid_argument` | Bad limit, malformed id or cursor, exclusive selectors combined. | Fix the request. |
| 5 | `schema_reset_required` | The store predates the active generation. | Run the profile reset. |
| 6 | `resync_required` | The change cursor is pruned or ahead of the journal (`details`: `cursor`, `floor`, `head`). | Drop the cache, read a page, follow from its `snapshot_sequence`. |
| 9 | `target_not_found` | No such message in the conversation. | Remove the row. |
| 11 | `payload_too_large` | One row alone exceeds the response cap. | Read it with the single-message shape. |
| 16 | `internal` | Storage or decoding failure. | Report; do not retry in a loop. |

## Client loop

1. Read a page; render it; remember `snapshot_sequence` as the cursor.
2. Subscribe.
3. On `state.changed` or `stream.lagged`: read changes after the cursor until
   `more` is false, replace rows by `id`, store `next_after` as the cursor. After
   `stream.lagged`, subscribe again.
4. On `resync_required`: discard the cache and start at step 1.
