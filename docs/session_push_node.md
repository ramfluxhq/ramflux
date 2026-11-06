<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Session push node contract

This document freezes the node interface for capable clients. Client receive
journaling and ephemeral delivery are separate capabilities and are not enabled
by `gateway.session_push.v1`.

## Negotiation and compatibility

The signed device proof must include `gateway.session_push.v1` in capability_scope.
The gateway intersects this with authenticated router readiness and freezes the
result for that session. SessionEstablished.session echoes capabilities and
inbox_incarnation_id only when capable. Missing echo selects the legacy wire,
including its single self-target Deliver submit reply. A capable sender receives
submit_accepted separately from recipient Deliver, including self-target.

The router readiness endpoint is GET `/mvp1/session-push-capabilities`, returning
`{capabilities:["gateway.session_push.v1"]}`. Discovery has a two-second deadline
and retries every 60 seconds without blocking legacy service. Missing, malformed
or failed discovery selects legacy. A disappearing capable route retires the
session; reconnect negotiates again. Incarnation mismatch retires the bound
registration, including pending pushes and hints. No ephemeral capability is listed.

E is a persisted 128-bit random inbox incarnation, encoded as 32 lowercase hex
digits. Sequences are positive u64; unknown targets have issued=0 and no E. Reads
and ACKs of unknown targets do not create inboxes. Deadline values are Unix
seconds and carry the router's actual retain_until, never a reconstructed TTL.
All mesh endpoints below require an authenticated gateway service identity.

## Frozen client frames

All JSON frames use frame_type. Requests are scoped to the authenticated session
target T and incarnation E; supplied legacy target and token must match the session.
Only one request is in flight. An unexpected or malformed reply retires the session.
Existing public legacy frame types remain unchanged; capable types are additive.

| Frame | Fields beyond frame_type | Meaning |
| --- | --- | --- |
| resume | resume:{target_delivery_id,after_inbox_seq,limit,resume_token}, incarnation_id | Fetch bounded coverage |
| resume_page | target_delivery_id, incarnation_id, after_inbox_seq, covered_through_seq, issued_inbox_seq, settled_through_seq, entries, known_losses, oversize_next, more | Authoritative (after,covered] coverage; unsolicited pushes do not change it |
| fetch_entry | incarnation_id, inbox_seq | Exact point request |
| entry | incarnation_id, record:{entry,retain_until} | Live point entry |
| entry_too_large | incarnation_id, inbox_seq, retain_until | Legacy entry exceeds cap, no content or envelope ID |
| entry_gone | incarnation_id, inbox_seq, observed_issued_inbox_seq, reason | Issued row absent; reason may be unknown |
| ack_batch | incarnation_id, inbox_seqs (request); incarnation_id,cursor,results (reply) | Strictly increasing 1..64 positive sequences; one result per sequence |
| ack / nack | legacy ack / nack plus incarnation_id | Bounded async mesh mutation |
| cursor | incarnation_id,cursor | Bound mutation result |
| submit_accepted | incarnation_id,envelope_id,target_delivery_id,inbox_seq | Compact durable sender result |
| deliver | entry,incarnation_id,retain_until | Separate recipient event |
| resync | incarnation_id,target_delivery_id,after_inbox_seq,reason | queue_full or not_pushed; hint to fetch from client cursor |
| nack | reason,incarnation_id | Typed request refusal |

Entry records are `{entry:InboxEntry,retain_until}`. Known losses are
`{from_seq,to_seq,reason}` with expired, ack_window_overflow, nacked or aborted.
Absent evidence is unknown. ACK outcomes are acked, already_settled, not_found,
invalid_seq or rejected; optional reason is at most 256 UTF-8 bytes.

## Mesh interfaces and bounds

| Endpoint | Request | Response |
| --- | --- | --- |
| POST /s1/session | session plus session_push:true | session,incarnation_id; initializes empty capable inbox |
| POST /mvp0/issued-seqs | {targets:[T]}: 1..1,024 unique nonempty targets | {issued:[{target_delivery_id,incarnation_id,inbox_seq}]} exactly one per target |
| GET /mvp1/inbox/{T}?after=&limit=&session_push=1&incarnation_id= | E and after | resume_page fields without frame_type |
| GET /mvp1/inbox-entry/{T}/{s}?incarnation_id= | E and positive s<=issued | entry,entry_too_large,entry_gone |
| POST /mvp0/ack-bound-batch | {target_delivery_id,incarnation_id,inbox_seqs} | {incarnation_id,cursor,results} |
| POST /mvp0/ack-bound, /mvp0/nack-bound | target, E and bound legacy mutation | E and cursor |

Page limit zero is invalid_limit; positive limits clamp to 256. At most 512 sparse
rows are visited, with 256 entries and 64 loss ranges. Whole encoded pages are bounded to 983,040 bytes;
entry/delivery frames are bounded to 1,048,576 bytes. covered_through_seq advances
unless already at issued or oversize_next names after+1. FetchEntry separates
an oversized live row from a gone row. Cursor above issued yields cursor_ahead.
Sequence zero or above published issued yields invalid_seq without state mutation.
E mismatch takes precedence and yields incarnation_mismatch. Malformed frames,
invalid session tokens and oversized frames are refused before mutation.

Durable sender refusals preserve aborted_retry_safe, capacity_retry_after
(retry_after_ms=1000), idempotency_conflict and payload_too_large. Accepted replies
wait for contiguous durable publication; connection loss during fail-stop is
uncertain and requires an identical-envelope retry.

Mesh forwarding returns delivered plus optional outcome queued, overflowed,
no_session, full, unsupported or expired. Durable overflow is handled=true and
must not wake an offline device. A deficient old-forwarder Deliver to a capable
recipient is discarded and schedules not_pushed; it is still handled=true.

## Queue and probe semantics

Each registration owns its generation token, writer and FIFO. Limits clamp the
Open downstream window to 16..256 frames and cap bytes at 4 MiB, including the
in-flight frame. Overflow records the minimum missed sequence minus one. Resync
waits until both occupancies are at most half, with admission latched through the
hint. Control and queued frames share a frame-atomic sink. Actual I/O has a
15-second deadline after separate bounded sink admission; a stalled registration
closes without blocking the sender's next submit or other recipients.

One process probe runs sequential rounds, two seconds after the preceding round
finishes. A stable index snapshot pages all initial tokens by 1,024 targets, with
at most four requests concurrently and 1.5 seconds per request. Replacement
resets coverage and confirmation. Missing, duplicate, foreign or malformed rows
fail the entire batch; timeout/failure resets confirmation and logs at most once
per minute. Changed E retires the registration.

Coverage is a contiguous offered prefix plus at most 256 offered intervals.
Only completed writes count; a higher push cannot cover a lower hole. Interval
exhaustion conservatively schedules a hint. Two consecutive successful issued
observations beyond coverage schedule Resync. The hint records its observed
watermark internally; coverage advances after the actual hint write. Resume or
push progress suppresses obsolete pending hints. These hints never ACK rows or
move the client's durable cursor.

For stable N, round latency R<=ceil(ceil(N/1024)/4)*1.5 seconds plus local overhead.
Recovery hints take at most 2*(2 seconds+R), plus queue drain/write time, assuming
successful requests and fair scheduling. Excluding those costs, bounds are seven
seconds at N<=4,096 and 34 seconds at 40,960. Outage requires client safety sweeps.

## Operations and durability limits

See [server data](server-data.md#restoring-router-inbox-state) for mandatory offline
restore rotation, quarantine and store upgrade. P is the published durable prefix,
R the committed retirement prefix and S=min(R,P). Startup completes recovered
segment/directory syncs and an immediate redb commit before readiness.
`fatal_durability_uncertain` fences publication then aborts; an external supervisor
must restart router and gateway. Automatic supervisor restart is not tested here.
Opening an upgraded store with a pre-session-push writer is unsupported.
Physical-media correctness after an earlier EIO or a false sync is not promised.
