# Card sessions (`card.session.*`)

A card session renders one published surface (an agent card) for a host UI. The SDK owns
authority, signing and every network call; the embedded card runtime owns the tree. The host
draws the batches it receives and sends events back. `rf` and every SDK build with the
`card-runtime` feature ship the runtime. `rf` enables it by default; C ABI hosts choose
the feature when they build the SDK. Without the feature every method fails with
`card runtime unavailable`.

All methods are local-bus requests with `account_id` set. Bodies reject unknown fields and are
at most 16 KiB (open: 4 KiB). Examples show bodies only.

## Methods

| Method | Body | Success `result` |
|---|---|---|
| `card.session.open` | `{"surface_ref", "locale"?, "dark"?}` | `opened` |
| `card.session.update` | `{"session"}` | `updated` |
| `card.session.present` | `{"session", "locale"?, "dark"?}` | `presented` |
| `card.session.event` | `{"session", "token", "event"}` | `edited`, `validation`, `open_url`, `pending_submit`, `stale_dropped`, `refused`, `superseded` |
| `card.session.slot` | `{"session", "token", "slot_id", "request_id", "outcome"}` | `opened`, `cancelled`, `unavailable`, `approval_decision`, `stale_dropped`, `refused` |
| `card.session.submit` | `{"session"}` | `submitted`, `stale_dropped`, `refused`, `superseded` |
| `card.session.suspend` / `resume` | `{"session"}` | `suspended` / `resumed` |
| `card.session.dispose` | `{"session"}` | `disposed` |

`locale` defaults to `en`, `dark` to `false`. `token` is the event token the host copied from the
node or host slot it acts on: `{session, signed_version, edit_seq, tree_version, key}`.
`event` is one of `{"kind":"input","value":...}`, `{"kind":"activate"}`,
`{"kind":"select_tab","index":n}`, `{"kind":"modal_open"}`, `{"kind":"modal_close"}`.
`outcome` is `confirm`, `deny`, `cancel` or `unavailable`.

## Reply

Every reply carries `result`, `render_allowed` and `fallback_text`. Optional fields:

- `session`: the session id (a process-unique `u64`; ids grow, a reopened card gets a new id).
- `reason`: a `card_session_*` token or a runtime reason (`card_closed`, `card_superseded`).
- `batch`: `{schema, ..., mutations, host_slots}`, the tree change to draw.
- `host_request`: a request only the host can fulfil (`open_url`, `approval_decision`).
- `submit`: `{message_id, surface_version, surface_hash, delivery_state?}`.
- `draft_conflict`: `true` when an update kept a draft the author's new version contradicts.
- `action_outcome`: `{status: accepted|refused|superseded, reason?, replacement_ref?}`.

`render_allowed:false` means draw only `fallback_text`: the card is missing, closed or has no tree.

### Batch invariant

For `card.session.event` and `card.session.slot`, every reply with `render_allowed:true` carries
`batch`. When the call changes nothing (a stale event, a refused slot, an approval hand-off)
the batch is the mounted tree: empty `mutations`, current `host_slots`. A session with no tree
replies `render_allowed:false`, `result:"refused"`, `reason:"card_session_inactive"`.
`update`, `present`, `suspend`, `resume` and `submit` do not make this promise for a bare
`stale_dropped`.

## Slot flows

A batch lists `host_slots`. Each has `id`, `key`, `token`, `kind`, plus kind fields. The host
fulfils the slot, then replies with `card.session.slot` (`request_id` from the slot).

**Link** (`kind:"link_open"`, with `url`). The host shows the full URL and the trusted author,
opens the browser, then replies `confirm`, or `cancel` / `unavailable`. The SDK never opens it.

**Approval** (`kind:"approval"`, `request_ref`, optional `task_binding`, `facts`). The host shows
the verified facts and replies `confirm` or `deny`. The SDK matches the approval against its own
task state (the card's `request_ref` and `task_binding` are hints) and answers
`result:"approval_decision"` with `host_request`:

```json
{"kind":"approval_decision","outcome":"confirm","request_ref":"task_approval_<id>",
 "task_binding":{"task_id":"...","step_id":"..."},
 "task_resolve":{"conversation_id":"...","task_id":"...","step_id":"...","base_revision":7,
   "target":{"kind":"approval","grant_id":"..."},"decision_id":"...","decision":"resume"}}
```

`task_resolve` appears for `confirm` (`decision:"resume"`) and `deny` (`decision:"deny"`) only. It
is a complete `task.resolve` body. The client calls `grant.approve` (or `grant.deny`) with
`{approval_id: request_ref}`, then `task.resolve` with `task_resolve` unchanged. The SDK calls
neither. `base_revision` is the task's current version. A decision is consumed once per slot and
surface revision; a replay is `stale_dropped`. See `docs/conversation_tasks.md`.

**Image** (`kind:"image"`). The SDK resolves the card's `attachment` selector
`{object_id, manifest_digest}` before any batch leaves it. The object must belong to the card's
conversation, match the digest, not be erased or tombstoned, and be at most 8 MiB.

```json
{"retrieval":"object","object_id":"...","manifest_digest":"...",
 "transfer_state":"available","size":1234,"mime":"image/png"}
```

Otherwise `{"retrieval":"unavailable","reason":"card_image_unavailable"}`, with no detail about
which check failed. When `transfer_state` is not `available` the host calls `object.fetch`, then
reads bytes with `object.get` (or `object.get.begin/read/finish`; see
`docs/client_read_model.md`). The SDK does no network work here, and no reply carries a URL,
a path or image bytes. `card.session.slot` on an Image slot is `card_session_refused`.

**Modal** (`kind:"modal"`). The host owns the sheet and replies with `modal_open` /
`modal_close` events. `card.session.slot` on a Modal slot is `card_session_refused`.

## Errors

Refusals are typed: the bus error has `error.code` and `error.reason_code` equal to the token.

| Code | Meaning |
|---|---|
| `card_session_expired` | The session was dropped (see Lifetime). Reopen the card. Body has `session`. |
| `card_session_inactive` | No such session, or the card has no tree. |
| `card_session_limit` | 32 sessions are open for the account, or a body is too large. |
| `card_session_refused` | Bad body, unsupported slot kind or outcome, or missing authority. |
| `card_session_stale` | The token or request id does not match a slot of the mounted tree. |
| `card_session_busy` | The session store was re-entered. Retry. |

C ABI hosts get `InvalidArgument` for all of them. Other failures keep their usual codes
(`AccountNotOpen` while locked, `card runtime unavailable` without the feature).

## Lifetime

Sessions live in memory on the account's actor thread. At most 32 per account; opening a second
session for the same `surface_ref` replaces the first. They are dropped when:

- the account locks (`account.lock`, an app-lock timeout, an import) or signs out;
- the account is removed (`account.remove_local` locks it first);
- the actor stops for any other reason;
- the bus connection that opened them closes (a GUI reload or reconnect without a lock).

Each drop of at least one session logs `card sessions dropped` with `account_id`, `reason`
(`lock`, `sign_out`, `actor_stop`, `connection_closed`) and `sessions`. Every later call with a
dropped id returns `card_session_expired`, including `dispose`; an id above the account's highest
dropped id is `card_session_inactive`. While the account is locked, calls fail with
`AccountNotOpen` before reaching the card code, and after `remove_local` the account no longer
exists. A daemon restart drops everything and forgets the ids: the first call after a restart
returns `card_session_inactive`, so a host treats both codes the same way, by reopening the card.
Drafts and an unsent submit die with the session; a submit already sent is unaffected.
