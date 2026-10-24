<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Conversation tasks

Tasks are declarative conversation messages. They carry the original signed
`TaskEvent` bytes inside authenticated E2EE DM or group traffic. They do not
execute tools, change a tool's arguments, or grant tool capabilities.

## Local methods

All methods select an unlocked local account through the request's account ID.

| Method | Body |
|---|---|
| `task.start` | `conversation_id`, `assignee`, `text`, optional `constraints`, `task_id`, `message_id` |
| `task.propose` | `conversation_id`, `assignee`, `title`, `steps`, optional `task_id`, `message_id` |
| `task.accept` | `conversation_id`, `task_id`, next `version`, optional `message_id` |
| `task.decline` | `conversation_id`, `task_id`, `base_revision`, optional `reason`, `message_id` |
| `task.update` | `conversation_id`, `task_id`, next `version`, `state`, `steps`, optional `result_ref`, `message_id` |
| `task.cancel` | `task_id`, `base_revision` (alias `version`), optional `conversation_id`, `reason`, `message_id` |
| `task.resolve` | `conversation_id`, `task_id`, `base_revision`, `step_id`, `target`, `decision_id`, `decision`, optional `message_id` |
| `task.get` | `task_id`, optional `conversation_id` |
| `task.list` | `conversation_id`, optional `state`, `cursor`, `limit` |

The desktop `task.start` form with `proposal_id` accepts the existing proposal;
it does not create another task. Its assignee and any nonempty text must match
the proposal. New constraints must use a separate task because acceptance
cannot change the proposal. `task.cancel {task_id, version}` uses the observed
revision, not the next revision. Unscoped lookups and cancellation reject
ambiguous IDs across conversations.

Start creates a running task. Proposal creates a proposed task, then acceptance
starts it. An ordinary text request can precede a proposal. A task cannot be
started and subsequently proposed under the same task ID.

Use a stable `message_id` and identical body when retrying a failed send.
Network errors are returned to the caller, as with ordinary text submission.
Task delivery has no separate sealed-message outbox. Projection, accepted event
history, replay receipt, decision consumption and metadata journal commit in
one account DB writer transaction. Reader methods use the account reader pool.

## Authority and decisions

Local start, accept, decline, cancel and resolve require an attended human
account. Proposal requires a headless AI account. Receiving verifies the
original device signature, conversation membership and relations: updates
require the assignee, resolution and cancellation require the requester, and
proposal acceptance or decline requires a member distinct from both proposer
and assignee. The temporary role adapter records `actor_kind_verified=false`;
a peer's self-asserted kind is never trusted.

Approval refers to a single-use, argument-bound decision accepted by the
existing MCP approval flow. The grant signature must belong to a verified
requester device. A task receipt does not consume or execute the MCP tool call.
Choice/input refers to an accepted surface action at the current surface
version/hash with validated arguments and deduplication. That action's values
must contain `decision: "resume"` or `decision: "deny"` matching the resolution.
`decision_id` is the surface action receipt ID returned by `surface.get`.
A read-only replica may verify a creator-signed receipt; task confirmation never
makes that surface action executable on the replica.

A requester sends a resolution intent. Its local result is `pending:true`
until the assignee device that opened the intervention verifies its stored
external decision and commits the resolution. It broadcasts an authenticated
certificate binding the exact intent and resulting task version. Certificates
contain references and hashes; private grant records and form values stay with
the executor. Reserved certificates cannot advance peer projections.
`task.decision.prove` is an optional diagnostic reservation method; normal
`task.resolve` does not require manually transporting proof bytes.

Accepted and pending copies survive restart. Future peer revisions use a fair
holdback with at most 32 events/5 MiB per account, eight per
(source principal, conversation), and 16 per source. A less represented source
can displace held work from an overrepresented signer; displaced or expired work
is marked as requiring resync. Unknown-task events still require current
conversation membership. Peer holds expire after ten minutes.

Local requester resolution intents use a separate durable pool, capped at eight
active intents per executor principal and 512/8 MiB per account. After 60
seconds without confirmation an intent releases its slot and byte budget,
compacting into a pending-status record. Status records retain at most 64 per
executor / 512 per account for 30 days; the conversation fallback stays pending. A later executor acknowledgement can
still commit it. This timeout does not authorize or reject the external decision.
Admission uses receiver time: 64 events per task/sender, 128 per principal and
512 per receiving-account/signer per minute. A requester's Cancel and Resolve
use independent 64/minute signer budgets (8 per task), so an executor cannot
consume recovery headroom. Executor confirmation and own-device forwarding
retry at most eight times within ten minutes; inbound receive and ACK do not
depend on their success.

New active tasks have per-source quotas: 32 across the account, 16 per
conversation. Retained bytes and events are charged to each event's verified
signer, not the task's originator: 8 MiB per signer across the account and in a
conversation, 8,192 events per signer and 4,096 per signer/conversation. A
requester's Resolve has a separate 32-event / 64 KiB per-task budget and
512-event / 1 MiB signer budget; Cancel has its own 16 KiB bound. The ordinary
256-event / 2 MiB task history reserves 33 extra requester control events and
64 KiB for resolutions plus a separate 16 KiB for cancellation and 4 KiB
of container overhead, so resolution traffic cannot consume cancellation space. Starts in which the
local account is neither requester nor assignee are rejected. Proposals can
also involve the local account as an eligible acceptor. Quota failures produce
rejection receipts instead of disabling intake for other sources.
An assignee exceeding its quota is rejected and marks its active tasks
`stalled_by_assignee:true`, with `progress_state:"stalled by assignee"`.
Maintenance can compact those histories while retaining a trusted local
reduction checkpoint and intervention origins. Requester cancellation and
verified resolution still work after restart. Checkpoints never enter peer or
own-device history ingress/export; only original signed histories are synced.
Terminal histories compact after seven days, or beyond the newest 16 per
conversation/originating signer and 32 per originating signer. Compaction retains the projection and certificate
hashes and removes signed history bodies. Older projections are fully pruned
after 90 days or beyond 128 terminal tasks per conversation/originating signer
or per originating signer. Locally requested or accepted tasks and work signed
by the local assignee use the local account's retention budget. Unsolicited
assignments stay in their originating signer's bucket until local participation;
a peer cannot allocate local retention slots just by naming the local assignee.
Consumed external-decision keys are preserved independently. Certificate caches
retain at most 32 per executor principal, 64 per conversation and 256 per
account, expire after seven days, and follow task compaction. Existing histories
acquire lifecycle indexes in bounded upgrade pages.

Own-device task history uses causal pages capped at 30 KiB and original signer
verification. Committed events carry same-root membership witnesses from their
event position (group epoch or direct participant/time context); importing
history does not rejudge those events by today's membership or blocked state.
Locally validated roster snapshots, where retained, override bundle membership
claims at that epoch. The claimed position cannot authorize an actor or
assignee absent from the receiver's validated roster. These snapshots are
captured on local group mutations and verified control events, independently
of snapshot import, and are bounded to 256 records. Bundle witnesses are
trusted only within authenticated same-root history, never
as peer authority. Older direct histories can use their committed participant
context; a group history without an epoch witness is skipped with a reason.
Snapshots cannot reactivate known removed local group membership or inactive
member pins. Task import is best effort per causal page; rejected pages are
recorded and do not abort ordinary history restoration.

Peer holdback is capped at 16 entries per signer across conversations and 8
per signer/conversation. At its 32-entry account bound, admission rebalances
from the signer holding the most entries; equal counts replace that signer's
oldest entry. Rejected no-role Starts leave bounded tombstones (64 per signer,
512 per account, seven days), so unrelated follow-up traffic never enters
holdback while its tombstone is retained.

Offline export scans bounded history pages with a persisted continuation cursor
per target device.
Each snapshot includes at most 100 task pages / 4 MiB and optional
`task_export_metadata` (`truncated`, `skipped_items`, `next_cursor`). Oversized or
unavailable task items are skipped; task capacity does not fail the surrounding
ordinary-message snapshot. Later exports resume at the cursor and cycle after
the final history. Snapshot pages can be incomplete when the budget is reached.

## Read models

`task.get` returns the task, steps, revision, timestamps and unverified-kind
marker; `task.list` returns `tasks` plus `next_cursor`. `message.list` and
`message.read` include task content type, escaped fallback and the same marker.
Clients without task rendering can display the fallback. `task.changed` contains
IDs, version and status metadata, never task text, constraints or form values.

Delivery admits at most 30 KiB including the signed carrier or history page,
using a measured conservative budget for nested JSON and E2EE framing under
the 1 MiB gateway frame. `TaskDeliveryTooLarge` is returned before sealing an
over-cap event. This transport bound is smaller than the protocol parser's
65,536-byte event bound; callers must shorten or split large task updates.
