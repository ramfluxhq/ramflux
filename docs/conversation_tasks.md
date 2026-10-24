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

Accepted and pending copies survive restart. Future revisions use a bounded
holdback and expire after ten minutes with `resync_required`. Admission uses
receiver time: 64 events per task/sender, 128 per principal and 512 per account
per minute. The holdback allows 32 events/5 MiB per account and eight per sender.
Executor confirmation and own-device forwarding retry at most eight times
within ten minutes; inbound receive and ACK do not depend on their success.
Own-device task history uses causal pages capped at 30 KiB, original signer
verification and current group pins. A snapshot cannot reactivate known removed
local group membership. Offline task snapshot export is bounded to 100 histories
and 4 MiB and reports an error when the bound is exceeded.

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
