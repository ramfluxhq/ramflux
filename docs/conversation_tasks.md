<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Conversation tasks

Tasks are declarative conversation messages. They carry the original signed
`TaskEvent` bytes inside authenticated E2EE DM or group traffic. They do not
execute tools, change a tool's arguments, or grant tool capabilities.

## Local methods

All methods select an unlocked local account through the request's account ID.

Each example is a request method and body. Account selection belongs to the bus frame.
Optional `message_id` is an idempotency key for writes. Omit `conversation_id` on
existing-task methods only when the task ID is unambiguous. `task.accept` has one
form: accept the existing proposal by task ID and next version; `proposal_id`
on `task.start` is rejected. Decline uses the next version; Cancel uses the
observed version (converted internally to `base_revision`). Resolve uses the
observed `base_revision`. Reason fields are not accepted.

```json
{"method":"task.start","body":{"conversation_id":"thread","task_id":"task","assignee":"agent","text":"Investigate","constraints":"Use approved tools"}}
```
```json
{"method":"task.propose","body":{"conversation_id":"thread","task_id":"task","assignee":"agent","title":"Investigate","steps":[{"id":"step","title":"Inspect","state":"proposed"}]}}
```
```json
{"method":"task.accept","body":{"task_id":"task","version":2}}
```
```json
{"method":"task.decline","body":{"task_id":"task","version":2}}
```
```json
{"method":"task.update","body":{"task_id":"task","version":3,"state":"done","steps":[{"id":"step","title":"Inspect","state":"done"}],"result_ref":"object:report","result_summary":"Inspection complete"}}
```
```json
{"method":"task.cancel","body":{"task_id":"task","version":3}}
```
```json
{"method":"task.resolve","body":{"task_id":"task","base_revision":4,"step_id":"step","target":{"kind":"approval","grant_id":"grant"},"decision_id":"approval","decision":"resume"}}
```
```json
{"method":"task.get","body":{"task_id":"task"}}
```
```json
{"method":"task.list","body":{"conversation_id":"thread","state":"needs_me","cursor":"","limit":50}}
```

Refusals use typed `error.code`: `invalid_request`, `invalid_event`,
`not_requester`, `not_assignee`, `not_member`, `not_eligible_acceptor`,
`human_required`, `stale_revision`, `terminal`, `task_stalled`, `not_found`,
`already_exists`, `no_local_role`, `quota_exhausted`, `rate_limited`,
`decision_consumed`, or `decision_mismatch`. Transport failures keep their
transport error codes. Clients never need to parse English messages.

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
An assignee's pending MCP approval is sent privately to the requester's active
devices as an assignee-signed, pair-E2EE control inside the conversation.
`grant.list.approvals` and `mcp.approval.list.approvals` contain the remote
approval, a scoped `approval_id`, the original `decision_id`, `grant_id` and
`task_binding` (conversation/task/step/opening revision/requester/assignee/executor).
The requester calls `grant.approve {approval_id}` or `grant.deny {approval_id}`.
Its attended daemon signs the immutable grant body and queues the decision
back to the executor and its own siblings. The response's `decision_id` is the
ID to pass to `task.resolve`; the scoped UI approval ID is not a grant ID.
For existing clients, `task.resolve.decision_id` also accepts that scoped UI
approval ID: the requester daemon checks its task/step binding and canonicalizes
it to the original MCP decision ID before signing. Remote approval rows populate
`details.requested_grant_id`, including requests whose assignee used a generated
grant ID. Notifications use the existing `mcp.approval.request`,
`mcp.approval.granted` and `mcp.approval.denied` topics (metadata only).
The executor revalidates the installed MCP registry and original request before
accepting the grant. The grant signature also binds the task intervention;
a changed task or opening revision cannot reuse it. Pending requests and
decisions are stored in the encrypted account database before acknowledgement.
Private tool arguments are never published to other group members or journals.
Courier attempts are bounded (two per sync tick, eight attempts, capped
exponential backoff), with expiry and bounded encrypted storage. Request and
decision queues have separate budgets; a peer cannot consume the requester's
decision-return headroom. Incoming requests allow 64 rows / 384 KiB overall and
16 rows / 96 KiB per assignee, keeping the new list projection below a bus frame.
Other courier queues allow 64 rows / 2 MiB each and 16 rows / 512 KiB per peer.
Decisions without a matching executor-owned request are rejected before storage.
The executor compares requests using RFC 8785 canonical bytes and applies its own
stored request. A malformed row is rejected independently of other decisions,
cleanup and new-request admission.

Each receiver assigns a local expiry no later than receipt time plus 24 hours
(the MCP grant lifetime), without changing signed bytes or request identity.
The executor also caps the installed grant's effective expiry. Full courier rows
retire on application, transport acknowledgement or intervention closure. Compact
replay/delivery receipts expire at the receiver deadline, with at most 64 per
peer and 512 per account; they contain binding metadata and a decision hash,
not tool arguments. A retired receipt preserves the scoped approval-ID mapping.
Approval display retains hash-bound arguments, immutable grant fields and safe
labels; arbitrary unsigned details are omitted and confirmation mode/risk are
locally derived.

Decision rows in the approval list and `task.get.approval_decisions` expose
`delivery_state` (`pending`, `submitted`, `applied`, `rejected`, `failed`) and
an optional typed `reason_code` (`transport_unavailable`, `retry_exhausted`,
`intervention_closed`, `invalid_decision`). After eight failed transport attempts,
the row becomes `failed`, rather than remaining pending. Calling the same
`grant.approve` or `grant.deny` again retries that signed decision unchanged;
a conflicting choice is refused. Successful transport acknowledgement retires
the outgoing full row. Decisions are sent before new requests; request admission
failure never stops decision delivery. Tool execution still uses the existing
argument-bound single-use MCP gate.

Choice/input refers to an accepted surface action at the current surface
version/hash with validated arguments and deduplication. That action's values
must contain `decision: "resume"` or `decision: "deny"` matching the resolution.
`decision_id` is `surface.get.actions[].action_receipt_id` (also
`surface.get.action_receipt_id` for the latest action). `receipt_verified:true`
on the action means its creator receipt is available at that device.
The referenced `surface_id` belongs to the task's assignee, not the requester.
A task action's signed wire includes `taskBinding: {"task_id":"task","step_id":"step"}`;
the creator receipt embeds that same signed action. `surface.get.actions[].task_binding`
exposes it without interpreting form values. The requester retains its own signed
outgoing action and delivery receipt ID across restart: those read rows are
`receipt_verified:false`, `actionable:false` until a creator attestation is available.
They allow a restarted requester to send a resolution intent before a creator
receipt arrives; the executor still requires its own creator-validated action,
and the requester commits only after the executor's authenticated certificate.
This is the delivery receipt ID, distinct from the action name `action_id`.
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
A per-task limit stalls only that task. An assignee exceeding its own signer quota is rejected and marks its active tasks
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
assignee absent from the receiver's validated roster. These rosters are
recorded only after verified group controls, never on snapshot import, and are
bounded to 256 records. Recording errors are nonfatal. A snapshot mismatch is
logged and the verified roster wins. Legacy unproven roster caches are ignored. Bundle witnesses are
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

Retained regular event history has an aggregate cap of 32 MiB / 32,768 events
across all signers. Admission prefers terminal histories, then eligible histories of the largest
signer, retaining a local checkpoint. It never compacts an active task where the
local account is requester or assignee; admission is refused if no eligible
history can free capacity; requester Cancel/Resolve keep recovery headroom.
No-role tombstones are keyed by conversation/task and record starter, requester
and assignee. Follow-ups from named parties are dropped immediately. Only a fresh
Start from another signer can bypass the tombstone and establish a local role.

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
Both message methods expose `task_id`, authenticated `actor_kind` (null for
unknown or legacy metadata) and the role-aware `actor_kind_verified` boolean.
Reads include `result_ref` and
`result_summary` (at most 4,096 safe text characters, signed, terminal updates
only), per-actor `actors.{requester,assignee,acceptor}.{principal_id,actor_kind_verified}`,
and restart-durable `pending_resolution` metadata (`awaiting_executor` or
`executor_timeout`), including `step_id`. Compaction retains the summary. Clients without task rendering can display the fallback. `task.changed` contains
IDs, version and status metadata, including typed `kind:"compacted"` / `kind:"removed"` lifecycle notices, never task text, constraints or form values.

Delivery admits at most 30 KiB including the signed carrier or history page,
using a measured conservative budget for nested JSON and E2EE framing under
the 1 MiB gateway frame. `TaskDeliveryTooLarge` is returned before sealing an
over-cap event. This transport bound is smaller than the protocol parser's
65,536-byte event bound; callers must shorten or split large task updates.


## Bounded follow-ups

The approval driver currently scans at most 1,000 task histories per tick while
pending approvals exist (L4). An indexed task-to-grant lookup remains a follow-up
for large accounts; this bounded scan can delay discovery of later histories.
Cleanup also verifies task history separately for rows in five courier namespaces
(L-r5-1); a per-view-version cache or indexed intervention lookup is a follow-up.
Peer-capacity refusals skip only that approval and continue the scan; account
capacity and storage failures still abort admission. Pending/failed delivery
receipts remain protected while their outgoing jobs exist, including during
peer/account retention. Transient application failures retain decisions for
retry; only validation failures reject them.
The 4,096-event per-conversation signer limit can still mark that assignee's
other tasks stalled (M-r3-2 conversation edge). Distinguishing this conversation
limit from the account-wide assignee limit remains a follow-up; requester recovery
controls retain their separate admission budgets.

See [Local bus error codes and retries](local_bus_errors.md) for transport refusal and approval retry policy.
