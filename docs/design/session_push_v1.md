# Session push v1

Design revision 3. Proposal for review; no implementation or runtime acceptance is
claimed. All decisions below supersede the earlier S6 implementation-card recipes.
The implementation must be dispatched from approved dependency SHAs, not from this
proposal's source baseline.

## 1. Source facts and decision basis

### 1.1 Reproducible baseline

Product source baseline: `81e59c3032f69b627e421ced8b137c5e995e0a2c`, fetched
`origin/main` for revision 3. The design branch retains its original parent;
all source citations below were rechecked at this newer immutable baseline.
All product file:line citations throughout this document refer to that immutable
object, except the explicitly pinned dependency references in section 1.2.
Line intervals describe a source region; they are not links to mutable main.

| Fact | Source at the base |
| --- | --- |
| The gateway already pushes a committed durable entry, using the same Deliver as the submit reply; self-target push is suppressed | `apps/ramflux-gateway/src/session.rs:1224-1351` |
| Own-device fan-out pushes separately; a local miss forwards through the gateway mesh and can wake an offline device | `apps/ramflux-gateway/src/session.rs:1444-1468`, `:1570-1651` |
| Same-target submissions can overlap: submission_barrier uses a shared read gate, so durable completion order need not match sequence assignment | `crates/ramflux-node-core/src/router_store/submission_barrier.rs:30-32`, `apps/ramflux-router/src/router_engine.rs:61-88` |
| The recipient sink is locked on the sender's task, with a two-second timeout | `apps/ramflux-gateway/src/state.rs:167-226` |
| ACK and NACK call blocking router helpers; Resume uses an async inbox helper | `apps/ramflux-gateway/src/session.rs:1653-1733` |
| Resume request contains target, after, limit and resume token; establishment has no negotiated push capability | `crates/ramflux-node-core/src/gateway_frames.rs:153-169` |
| The shared serialized-frame cap is 1,048,576 bytes | `crates/ramflux-transport/src/lib.rs:94-95` |
| Live inbox reads filter expired rows without deletion, and apply the requested limit without a clamp here | `apps/ramflux-router/src/handlers.rs:1098-1129`, `crates/ramflux-node-core/src/inbox.rs:303-343` |
| ACK selects target/sequence, compares the envelope ID, and accepts an already settled sequence; each call clears its transient retirement list | `crates/ramflux-node-core/src/inbox.rs:368-425` |
| Window 1,024, NACK retry limit 3, dead-letter cap 128; expiry retires pending rows and later checkpoints affected cursors | `crates/ramflux-node-core/src/inbox.rs:11-15`, `:432-490`, `:591-629` |
| Retention is min(signed creation plus capped TTL, router acceptance plus seven days), not merely creation plus TTL | `crates/ramflux-node-core/src/inbox.rs:73-89` |
| Issued sequences survive independently of live rows; redb row restore preserves even expired rows until a sweep | `crates/ramflux-node-core/src/inbox.rs:633-710` |
| Submit authenticates, refreshes authority, accepts in memory, durably records, then replies; persistence failure after acceptance aborts | `apps/ramflux-router/src/router_engine.rs:13-104` |
| Bound ACK mutates the inbox then persists the cursor and deletions | `apps/ramflux-router/src/router_engine.rs:311-319` |
| WAL-enabled submission bypasses redb incremental inbox submission; redb-only submission uses a redb commit operation | `crates/ramflux-node-core/src/router_store.rs:693-777` |
| ACK writes the cursor and deletes its sequence plus accumulated retired rows in one redb transaction, in both submission modes | `crates/ramflux-node-core/src/router_store.rs:853-904` |
| Recovery loads redb rows/cursors, merges WAL, then observes WAL issued watermarks | `crates/ramflux-node-core/src/router_store.rs:1192-1227` |
| WAL replay filters replay-expired records, skips retention-expired entries, and excludes sequences settled by redb cursor state | `crates/ramflux-node-core/src/router_wal.rs:624-635`, `crates/ramflux-node-core/src/router_store.rs:1252-1310` |
| WAL defaults on; group commit defaults off. A redb store still exists with WAL enabled | `crates/ramflux-node-core/src/router_store.rs:375-395`, `:1592-1604` |
| WAL batch appends complete records then syncs before success; segment rotation syncs the old file | `crates/ramflux-node-core/src/router_wal.rs:904-938` |
| Reference Compose selects async ingress, group commit default 0, WAL batch 256 and queue 4,096; it does not set WAL_ENABLED to false | `deploy/docker-compose.itest.yml:84-96` |
| The SDK buffers Deliver while awaiting other replies; Resume merges these unsolicited frames into its returned entries | `crates/ramflux-sdk/src/gateway/engine.rs:477-511`, `:706-716` |
| Receive processes/project-commits, then ACKs, then cleans retry/unrouted state and advances C; held paths deliberately skip completed-entry cleanup | `crates/ramflux-sdk/src/bus/sync_driver.rs:266-352` |
| Locally retained entries can be appended below the receive cursor | `crates/ramflux-sdk/src/bus/sync_driver.rs:566-590` |
| Receive cursor is a projection checkpoint, separate from the gateway's ACK cursor | `crates/ramflux-sdk/src/client/account.rs:244-279` |
| Existing durable holds are runtime_unrouted, runtime_inbox_retry, runtime_inbox_dead_letter and runtime_inbox_policy | `crates/ramflux-storage/src/account_db/journal/mod.rs:43-56` |
| Retry/dead-letter/hold expiry performs real deletes; a new receive ledger must join these lifecycles | `crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:10-18`, `:35-118` |
| The durable outbox is projected into the journal with unique outbox-derived source keys; journal_outbox also marks publication in its transaction | `crates/ramflux-sdk/src/bus/events.rs:38-72`, `crates/ramflux-storage/src/account_db/journal/mod.rs:120-141` |
| Message footprint registers ciphertext/identifier copies, not just plaintext; erasure removes indexed retry/unrouted copies | `crates/ramflux-storage/src/account_db/message_footprint/schema.rs:14-32`, `:61-63`, `crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:60-65` |
| Backup copies SQLite then strips state; merge has a separate exclusion list | `crates/ramflux-storage/src/account_db/backup.rs:110-133`, `crates/ramflux-storage/src/account_db/backup_merge.rs:33-72` |
| An older writer rejects a newer schema before migration writes | `crates/ramflux-storage/src/schema_object_erasure.rs:8-21` |

“As configured” here means the checked-in reference configuration and constructor
rules above. No deployed environment was inspected. Tests must select WAL-enabled
and redb-only explicitly; group commit is a redb batching choice, not a third
recovery model. A custom WAL directory, especially a volatile mount, changes the
failure domain: process-crash recovery assumes its files survive; host/volume loss
has no extra durability guarantee from this design.

### 1.2 Dependency status and provenance

S2's r1 inspection was of uncommitted files, NOT files in committed
`08c056a5adbfc4a55363da74dd90868c8eba1117`. The only identities of those
inspection snapshots are these SHA-256 fingerprints (SDK-relative paths):

| Uncommitted snapshot | SHA-256 |
| --- | --- |
| bus/connection_manager/account_work.rs | ff09289d44c83f89f79893808eb932e890b81bd7f32ef13de813235701b0be50 |
| bus/connection_manager/receive.rs | f2ccdbc25c12c36aa879f89cd657f625010f7705ca1d9c88f7153aa654135508 |
| bus/connection_manager/mod.rs | 7c3a5f0bbfbf59684ac59158b90886719bfa4de25bf3b40c7b8a093165af1a9e |

Their ReceiveApply bool, scheduled pulls and SessionContext without last_read_at
are historical observations only: **provisional, re-verify on S2 merge**. No
file:line is attributed to that committed head. S6b rechecks the merged S2/S3
interfaces before dispatch. S2 remains sole owner of the stream,
cancellation-safe reader, call queue, generation, connection retry, lifecycle
cancellation and courier/transfer task framework.

Approved S0 r4 input is the published `design/s0-msg-schema` at
`61d96751b550c661d15444a7ddecff116897498d`,
`docs/design/message_schema_v1.md:285-354` (complete Decision 6). Controller
approval of this design SHA satisfies S6c's S0 dependency. Section 8.2 copies its
clock and indicator wording verbatim. Its transient transport and endpoint Unsupported
retention are distinct: S6 has no transient DB write; S10a owns S0's authenticated
unknown-content endpoint policy. S6c consumes this approved complete Decision 6;
any successor requires a new controller pin.

### 1.3 International practice and the local choice

[Telegram update recovery](https://core.telegram.org/api/updates#recovering-gaps)
uses local sequence state, a short reorder wait, and explicit difference fetches.
We adopt the 500 ms gap wait and 15-minute safety trigger, with inbox coverage
instead of server message history. [MTProto
acknowledgements](https://core.telegram.org/mtproto/service_messages_about_messages#acknowledgment-of-receipt)
batch identifiers; our device-scoped sequences replace message identifiers.
These are architectural precedents, not evidence for the crash guarantees below.

[SQLite atomic commit](https://www.sqlite.org/atomiccommit.html) provides a
single-transaction all-or-none boundary. We use that boundary for cursor,
settlement intent and loss publication. Processing currently has several commits,
so this proposal adds durable input staging before processing. It does not assume
that placing a later receipt beside the cursor makes earlier processing atomic.

## 2. Receive invariants, owners and durable state

### 2.1 Definitions and invariants

T is the authenticated device's target_delivery_id; E is its router inbox
incarnation; s is a positive u64 inbox sequence within E; C is (T,E)'s durable
receive coverage cursor. A sequence is never identified without its incarnation. C is
not a cumulative
router ACK. The account actor is the sole SQLite writer. Every write below checks
current account/network generation and erasure state before committing; tasks
pass immutable inputs to the actor and never hold a DB handle across network I/O.

- **I1 Coverage:** for every newly covered sequence since ledger activation,
  exactly one local disposition exists: completed, durably held, explicitly
  rejected/erased, or unavailable with a committed gap event. C never regresses within E; only the
  atomic incarnation transition in section 2.5 resets it.
  Historical state below activation C remains historical; no rewrite claims to
  reconstruct pre-upgrade evidence.
- **I2 Staging:** before the first processing effect, W0 commits the input and
  its sequence receipt. That receipt remains discoverable by (T,s) until W2.
  Router absence alone never implies local content loss. A staged or held input
  inside a missing router interval is recovered before classifying that interval.
- **I3 Settlement:** no router ACK is sent for s>C. A terminal receive step
  creates a sequence-only intent in the same transaction that first covers s;
  retry settlement below C creates the intent with C unchanged. Uncertain replies
  keep the intent. No cumulative ACK may consume a held sequence.
- **I4 Holds:** advancing C over HeldLocal or Quarantined preserves its receipt,
  staged input and appropriate existing retry/policy state, and creates no ACK
  intent. A push duplicate at s<=C cannot schedule arbitrary processing; a
  retained receipt explicitly marked held can be redriven at s<=C.
- **I5 Loss atomicity:** subtract all staged/held/terminal receipts from missing
  page intervals before reporting unavailability. Loss ranges, outbox rows,
  counters and the C movement crossing them commit together. A page never grants
  authority above its covered_through_seq. Live pushes confer contiguous-entry
  authority only, never missing-range authority.
- **I6 Ownership/fences:** generation, expected cursor and expected receipt state
  are checked in each transaction. Lock/stop bumps generation, cancels children
  and prevents late applies. Account erasure invalidates every outstanding apply.
- **I7 Bounded work:** all queues, staging, intent tables, sparse page visits,
  loss operations and network calls have explicit caps. Exhaustion pauses before
  effects rather than deleting recovery evidence. Hold sub-budgets and atomic
  typed eviction reserve admission capacity for routable mail (section 2.6).
- **I8 Protocol isolation:** negotiation controls new frames in both directions;
  sender replies are never interpreted as recipient entries in push mode.
- **I9 Transience:** accepted ephemeral means queued, with one immutable signed
  deadline; it never means durable delivery or application acceptance.

### 2.2 Account DB schema and lifecycle

The following are exact column allowlists, not permission to add opaque JSON to
metadata tables. Sequences use fixed-width big-endian 8-byte BLOBs in SQLite
(indexable unsigned order); timestamps use signed Unix seconds unless suffixed
_ms. Range counts and checked u64 arithmetic are encoded without SQLite signed
integer overflow. Existing string checkpoint C is updated by compare-and-set on (E,C) in
the same transaction as these tables; no second authoritative C is introduced.
Every receipt/work/intent/loss key and due/range index below includes E after T;
the abbreviated (T,s) notation elsewhere means (T,E,s) in the active incarnation.

| Table / state | Columns and key | Owner and lifetime |
| --- | --- | --- |
| gateway_receive_receipt | target_delivery_id, incarnation_id, inbox_seq, disposition, retain_until, first_seen; PK(T,E,s) | Actor W0 creates staged; W1 may set held/quarantined; erasure sets erased. W2 removes terminal receipts after covering them and creating intent; held receipts remain below C until WS. Terminal compat receipts/work remain until proof-checked WA (section 4.3). No message ID, sender or digest |
| gateway_receive_work | target_delivery_id, incarnation_id, inbox_seq, entry_json, admission_key, byte_len; PK(T,E,s), FK to receipt | Actor W0 creates a recoverable encrypted input. This IS a message-linked copy. W2/WS removes only after terminal disposition; held processing keeps it. Indexed footprint, bindings and erase fence are mandatory |
| gateway_ack_intent | target_delivery_id, incarnation_id, inbox_seq, created_at, attempts, next_attempt_at, expires_at; PK(T,E,s), due index(T,E,next_attempt_at,inbox_seq) | W2/WS creates; WA retries or deletes after a terminal router result/verified legacy absence/deadline. Lock preserves it |
| gateway_inbox_loss | target_delivery_id, incarnation_id, from_seq, to_seq, count, reason, recorded_at, classification; PK(T,E,from_seq,to_seq) | W2 creates nonoverlapping ranges plus outbox. Keep at most 1,024 projected ranges per target, prune oldest only after journal projection; counters survive pruning |
| gateway_receive_epoch | target_delivery_id, incarnation_id, incarnation_verified, retired_incarnations, activated_cursor, legacy_uncertain_through; PK(T) | Active E and bounded retired-E fence; migration initializes uncertainty, section 2.5 alone switches E |
| projection_checkpoint | existing receive checkpoint | W2 alone advances C within E; section 2.5 alone resets it on new E; WS/WA never move it |
| runtime_inbox_retry / policy / unrouted / dead_letter | existing schemas and message-linked keys | Existing retry policy remains the scheduler/classifier; the new receipt is the sequence index and staged input is recovery authority. All terminal expiry/removal paths join WS/erasure below |
| runtime_outbox / runtime_journal | existing schemas, including UNIQUE journal source_key | W2 creates outbox keys; journal_outbox projects using the unique outbox sequence. Network delivery is replayable, not an exactly-once socket promise |

New metadata tables carry only the device's own target, sequences, enums,
counters and times. Message erasure leaves these metadata rows; it MUST erase
work.entry_json, its admission key, existing retry/unrouted copies and aliases.
Register work by its composite locator in message_footprint, bind the original
wire copy before decode and bind the logical message when it becomes known.
An erasure-trigger transaction first changes the corresponding receipt to
`erased`, then deletes the indexed work and existing message copies. A late W0
or W1 checks the existing erased-message/replay fence and can produce only erased
metadata; it cannot reinsert content. There must never be a staged receipt with
no work unless its disposition is erased or another terminal state.

No message-keyed column is added to receipt/intent/loss/epoch. Adding such a
column would require footprint registration and a new privacy review; an empty
payload would not exempt it. All five new tables are stripped from backup snapshots
and excluded from merge, including whole-database restore/import sanitization.
Restoring a target never restores its cursor in isolation: clear the associated
receive checkpoint and epoch with these tables, then establish the restored
new device's inbox state. Existing history/seen markers follow their own restore
policy. Account erase deletes the DB and WAL through the existing storage API.

The migration is forward-only. An older writer returns AccountSchemaTooNew
before writes and leaves the DB unchanged; recovery is running this build or
newer. Router persistence now includes incarnation state (section 2.5). In-place
rollback to a pre-S6 router on that store is unsupported; an old binary cannot
be assumed to recognize new metadata. Controller rollback/restore must isolate
the old store, and subsequent capable service rotates E before admission.
S6 loaders refuse unknown future storage versions rather than guessing them.

Loss storage has a hard total cap of 2,048 ranges per T, including unpublished
ranges. If a W2 would exceed it after pruning eligible projected ranges, pause
before that W2 and let journal projection drain; never prune an unpublished
event or split its cursor transaction. Its metadata-only outbox records fit a
bounded 1 MiB pending-loss budget as a second limit. Duplicate staging of an
existing receipt consumes no second slot; receipt+reserved-intent capacity is
tracked transactionally, including erasure/WS release. All per-T caps include inactive-incarnation
local work; resets cannot multiply available disk quotas.

### 2.3 Ordered receive and below-cursor settlement

**W0 Stage:** before processing an entry, reserve both staging capacity and a
potential ACK-intent slot. In ONE transaction create receipt(staged) and work,
register footprint and validate target/sequence/erase fence. Existing same-seq
work must be identical after authenticated normalization. On mismatched bytes,
keep the FIRST staged copy as recovery authority, discard the conflicting copy
and increment a bounded metadata diagnostic (one event per (E,s), at most 64
recent diagnostic rows per T). Redrive the original; do not repeatedly retire
the session or overwrite work on reconnect. Such a conflict never authorizes
an ACK of the second copy or a new processing attempt. Reserve capacity before W1, not
after it. Maximum per T: 1,024 receipts/work and 64 MiB serialized work; 1,024
intents plus reserved terminal slots. Held work retains its reserved slot until
WS or explicit terminal disposal. Held entries are additionally constrained
by section 2.6; exceeding a hold quota settles the oldest held entry with an
explicit held_evicted event. Resource refusal outside that policy pauses before
processing and never silently discards recovery evidence.

**W1 Process:** execute the existing authenticated/idempotent receive stages on
the durable work. Their individual commits may include ratchet/seen marker,
message/control projection, policy, retries and local outbox. W0 survives EVERY
such commit. Processing may prepare network work for S2 couriers but never await
it on the actor. Each content kind must retain its current committed-receipt
recovery, and commit each irreversible local effect with its dedup marker.
Section 3.1 enumerates the bounded stage adaptations owned by S6b; a seen marker
alone cannot skip unfinished projection or reply-outbox creation. Reopening W0 redrives
these stages safely, even if the router row expired, was ACKed, or disappeared.
A Completed result means all local effects are durable, not just decode success.

**W2 Cover:** accept at most 64 receipt/range boundaries per actor turn and yield
between turns. For the next ordered entry, reconcile preceding missing intervals
against receipts, processing staged work first. In ONE expected-C transaction:

1. Write missing ranges that have no local receipt, their gap outbox records and
   counters. Adjacent same-reason ranges merge before insertion, never by per-seq
   loops. Loss classification is described below.
2. Completed/Duplicate/terminal Rejected/Erased: insert intent; delete this work,
   receipt and the appropriate existing retry/unrouted/backpressure rows. For
   Rejected retain only the existing allowed diagnostic metadata, no extra copy.
3. HeldLocal/Quarantined: preserve receipt, work, retry/policy/quarantine and
   backpressure state; omit intent and completed-entry cleanup.
4. Set C to this entry's s, conditional on expected old C. A final range-only W2
   reaches page.covered. Capacity refusal rolls back the whole step; earlier
   steps remain durable and the unprocessed suffix is re-fetched from C.

**WS Settle retained work:** due retry walks receipts using a (T,s) range index,
including s<=C. A network duplicate is ignored below C; this explicit local work
is not. Redrive W1 from durable work, then ONE expected-state transaction creates
an intent and deletes only completed recovery state. C and prior loss rows do
not change. A new held outcome updates scheduling and preserves the work. Router
dead-lettering or expiry does not delete the local copy; its later ACK can return
not_found and settle successfully. When local policy itself expires/rejects the
work, WS records a local receive-failure event and terminal intent before cleanup;
this is a local policy failure, not a newly inferred router content gap. Existing
expire_inbox_holds and every deletion in section 2.6 must join that transition.
If the selected receipt has s>C, use ordered W2 with the same terminal outcome
instead of WS; eviction never grants coverage over an unexamined predecessor.

**WA Settle ACK intent:** acked, already_settled and not_found delete only the
matching requested (E,s) intent. invalid_seq is terminal: delete that intent
with a diagnostic and force incarnation revalidation, never back off and retry
a future sequence. incarnation_mismatch invokes section 2.5 before any retry.
Only an explicitly transient rejection backs off 1,2,4,...60 s. A malformed/missing
per-seq result or lost response retains it; duplicate/foreign results are protocol
errors. At expires_at, delete with a metadata diagnostic, never a content-loss
event: content was already accounted. Timeout after write retires the session.

Actual router retain_until is carried with push/page/FetchEntry metadata. If an
old node cannot supply it, use the conservative fallback
`min(created_at + min(ttl,604800), first_local_seen + 604800 + 120)` with checked
arithmetic. It is an upper bound only under the explicit assumption that the
client clock lags router time by at most 120 s. Larger skew can expire a local
intent before router retirement; status reports fallback_clock_unverified and
normal router TTL eventually retires it. No unconditional clock claim is made. For
EntryTooLarge use its explicit retain_until. The
clock can be past that bound already: W2 still accounts the sequence atomically,
then WA expires the intent without network traffic.

### 2.4 What a gap means, including old history

A modern epoch's `classification=unavailable` means the router's authoritative
coverage contains no live entry and this device has no durable staged/held copy
or terminal receipt for that sequence. Reason is expired, ack_window_overflow,
nacked, aborted, oversize, or unknown. A durable aborted tombstone means an
assigned sequence was abandoned before acceptance; it is sequence accounting,
not proof that an accepted logical message was lost. This is missing delivery
evidence, not proof that
an entire logical message has no copy on any other device. Gap events contain
only T, E, from_seq, to_seq, count, reason and classification.

Migration initializes activated_cursor=C. Existing local retry/unrouted work is
indexed into receipts before enabling loss inference. On the first capable page,
atomically set legacy_uncertain_through to its issued watermark before applying
any coverage. Missing intervals in (activated_cursor,legacy_uncertain_through]
without recoverable work get `classification=legacy_unverified`, not a claim of
content loss: an old client might have ACKed after processing and crashed before
its C write. Report these separately in status. A fresh device initialized with
this ledger has legacy_uncertain_through=0. Incarnation resets instead import
the new router settled prefix as specified in section 2.5; that prefix is
historical coverage and produces no loss event of either class.
New-client compatibility sessions use
the same ledger. Verified same-E transitions add no uncertainty epoch; a
proofless compatibility namespace must bind through section 2.5 before enabling
capable ACKs or using its prior C as modern coverage.
Known local work always suppresses both kinds of gap, including a capacity pause
after W1 and before W2.

### 2.5 Inbox incarnation and counter regression

E is a CSPRNG random 128-bit value, encoded as 32 lowercase hexadecimal digits.
Create it atomically with the first durable inbox counter, including counter=0
when an authenticated session explicitly initializes its own empty inbox. Persist
E in redb cursor state and every WAL submission/checkpoint; restore validates
equality before replay. An inbox is never recreated by ACK or a read probe.
An unknown target probe reports no incarnation and issued=0. Capable session
establishment initializes its own inbox durably before its reply, so its E is
always present; first binding with C=0 and no prior E emits no reset warning.
Existing stores migrate every recovered counter to one E before advertising
readiness, retaining that E across ordinary process restarts. Restore rotation,
not ordinary restart, changes E.

Every storage-loss or restore path that can lower the counter MUST create a new
E before serving requests. A whole-volume snapshot restore is an explicit
operator recovery operation: rotate all restored inbox incarnations in one
recovery pass before traffic, rewrite/checkpoint their WAL association, and
invalidate old gateway registrations. No software can detect a byte-identical
whole-volume rollback from that volume alone. Unannounced rollback that preserves
E while lowering counters violates the storage/recovery prerequisite; it is not
silently accepted. A same-E issued<C observation freezes receive/settlement with
cursor_ahead and a diagnostic; never wait for new traffic to overtake C.

In WAL mode persist a random WAL-directory identity and the last checkpointed
segment ID/LSN in redb, and a matching identity plus chained segment headers in
the WAL directory. Startup checks both identities, the checkpoint anchor and
the complete required segment chain before replay/admission. Missing directory,
mismatched identity, missing anchor or segment gap triggers a durable recovery
pass rotating E for every affected inbox (all WAL-backed inboxes if association
cannot be narrowed). A replacement empty WAL is never silently accepted under
the old E. New-store initialization is distinct from opening redb with a prior
WAL identity. Checkpoint segment retirement persists its new anchor in redb
before unlink; recovery tolerates extra older files, never a missing required
segment. Crash during rotation resumes it before any traffic. This detects
separate/volatile WAL-volume loss, including a reused empty directory, while
the explicit operator rule above covers undetectable whole-volume rollback.

Carry E in SessionEstablished, each Deliver, resume_page, Entry/TooLarge/Gone,
Resync, issued probe, submit assignment and ACK request/result, including mesh
forward. Legacy wire omission is only the explicitly restricted compat case in
section 4.3. A first-ever connection to a truly old node uses a persistent local
compatibility namespace U (random 128 bits, marked unverified in epoch state),
never sent as router E. First capable binding from U with prior work/C uses the
same atomic reset below, with reason incarnation_first_verified and
legacy_unverified classification; this does not claim proven router volume loss.
First binding from empty U with C=0 is initialization without a reset event.
Router validates E under the same mutation serialization as ACK;
mismatch returns incarnation_mismatch with current E and changes no row. A
queued push/hint belongs to its captured E; registration reset clears it before
new-E data. Pages, probes and gateway E caches cannot upgrade old queued frames.

When authenticated current-session evidence changes E, fence the old network
generation and pause receive/ACK flush. Fetch the new E's first authoritative
page with after=0; it carries settled_through_seq S (the router's contiguous
durable settled cursor, NOT the issued watermark P or an out-of-order ACK maximum).
Validate 0<=S<=issued, E, T and page bounds under one router snapshot. A changed
E while preparing this transition restarts validation; no old-E page supplies S.
An empty inbox supplies S=0. No new-E push is applied before this page binds E.

S maps to the published durable CursorAckState.settled_inbox_seq, not inbox_seq.
The existing advance_settled also crosses expiry/dead-letter retirements
(`crates/ramflux-node-core/src/inbox.rs:32-46`,
`crates/ramflux-node-core/src/inbox.rs:561-583`,
`crates/ramflux-node-core/src/inbox.rs:591-614`). Therefore S is not proof that
every historical row was delivered. Import it only at reset as an explicitly
legacy_unverified historical floor: it avoids inventing losses for ACKed history
but cannot reconstruct exact pre-reset losses among already retired rows. The
single reset event preserves that uncertainty; no extra CursorAckState field or
new ACK-only cursor is inferred. Same-E ordinary pages continue accounting gaps
from C, even below a later S, so normal expiry/dead-letter gaps are still visible.

Before reset, WJ publishes ALL pending old-E loss events into the local durable
journal using their unique source keys. A projection failure pauses reset and
preserves the old ranges/outbox/intents. A crash after WJ but before reset safely
retries; no socket subscriber acknowledgement is required. Then perform ONE
expected-E reset transaction: verify no old-E unpublished loss event remains,
drop old-E ACK intents and projected loss range rows, release terminal compat
receipts/work whose intents are dropped (including footprint bindings and
reserved quota slots), and record one typed
`inbox_reset{target_delivery_id,old_incarnation,new_incarnation,old_cursor,
reason:router_reset,classification:legacy_unverified}`. Set active E, C=S,
activated_cursor=S and legacy_uncertain_through=S. The first-page fence below S
marks pre-existing coverage legacy_unverified/historical: it is never expanded
into unavailable OR legacy_unverified loss events for already ACK-settled rows.
For U->E use reason incarnation_first_verified with the identical S/fence rule.
This overrides migration's issued-watermark uncertainty rule for a reset.

The reset event represents an unknown old tail, not a fabricated finite loss
count. Published journal events and cumulative counters remain historical; no
pending committed event is retired or pruned. Old staged/held work is locally
redriven or erased under its original E without any new-E ACK or C movement.
Its terminal local event releases its slot. Terminal compat rows are instead
released in reset, never redriven as held work or left orphaned after intent
deletion. All cleanup is erasure-safe and quota accounting is transactional.
SettleRetained explicitly names its original E: inactive-E work permits only
local recovery/cleanup, never network settlement or active-E checkpoint writes.

After reset, catch up from S. Discard first-page coverage/entries at or below S;
if that page stops below S, re-fetch from S rather than inferring a gap. Above S
accept new-E sequences independently of old C. Logical dedup uses the
authenticated application marker, never (E,s): restored, previously completed
content redelivered above S has exactly one application effect, while different
content reusing an old sequence is processed normally. A crash before/after
reset sees all old or all new state. Old callbacks, late results and old pages fail E+generation
checks. Retain up to 64 retired E values per T; hitting that fence capacity
pauses for explicit recovery rather than forgetting an E and oscillating on
stale frames. Reconnect validates the current E before enabling ACK flush.
Repeated evidence for the same E creates no second reset event.

### 2.6 Held-work isolation and every removal path

All holds together have at most 256 receipts and 16 MiB work per inbox, inside
W0's 1,024/64 MiB total: at least 768 slots and 48 MiB cannot be consumed by
holds. Per authenticated source root/device, all hold classes together allow
64 rows/4 MiB. Unknown sources share ONE unverified bucket, never a bucket per
claimed sender. Source attribution and class are read from registered work or
existing policy state; no source identifier is added to metadata-only receipts.

| Hold class | Additional cap, inside the aggregate | Full/expiry disposition |
| --- | --- | --- |
| Unrouted/legacy group/v2-blocked | 64 rows total, preserving today's unrouted cap; original 7-day maximum | Oldest first_seen, then seq, settled held_evicted on row/byte pressure; held_expired on local expiry |
| Policy/quarantine retries | Existing 64 active retries, 128 policy rows, 16 untrusted, 8 trusted or 2 untrusted per verified source | Preserve smaller existing quota/lifetime; terminal quota refusal or oldest eligible hold eviction uses the same W-path event+intent |
| Contact admission backpressure | 64 rows total, 1 per authenticated root; no 1,024-root retained-work allowance | Oldest held entry settles held_evicted; expiry settles held_expired |

Before converting staged work to a hold, settle oldest holds in the exceeded
source/class/global budget until both row and byte quotas fit. Complete the
terminal event+intent+cleanup atomically; transfer its reserved intent slot rather
than needing a new one. Under pressure WA is scheduled between bounded turns;
terminal intents still have the 1,024 cap, so network outage or full loss-event
storage can pause admission. The guarantee is isolation from *retained holds*,
not unconditional delivery during disk/network outage. Sustained unroutable
traffic with a functioning router/DB/journal must not starve a normal DM.

Local terminal events use `inbox_receive_failure` with reason held_evicted,
held_expired or policy_rejected and (T,E,s). They are typed local delivery loss,
not inferred missing-router gaps, and do not increment inbox_gaps_total. Below C,
WS leaves C and prior gap rows unchanged; above C, ordered W2 accounts the entry.
No receipt may remain staged/held without work, nor may work survive without its
receipt. Eviction selects only holds, never active uncommitted W1 work.

| Existing removal / commit site at product base | Required S6b adaptation |
| --- | --- |
| `crates/ramflux-storage/src/account_db/journal/quarantine.rs:32-34` | Replace 7-day purge and oldest-64 eviction by the atomic terminal W-path; no raw DELETE before event+intent |
| `crates/ramflux-storage/src/account_db/journal/quarantine.rs:62-64` | Success cleanup only inside terminal W2/WS (or erasure), never standalone receipt orphaning |
| `crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:10-20` | expire_inbox_holds joins receipt/work accounting before retry/dead-letter/unrouted cleanup |
| `crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:35-82`, `crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:160-163` | dead_letter_inbox and retry removal join event+intent transaction; repeated terminal receipt is idempotent |
| `crates/ramflux-storage/src/account_db/journal/inbox_legacy.rs:53-95` | Parking releases network policy only, retains indexed work; orphan cleanup must terminally settle or prove another live receipt owns the work |
| `crates/ramflux-storage/src/account_db/journal/inbox_policy.rs:127-129` | Policy GC may remove only policy metadata after receipt disposition is committed; never a receipt/work owner |
| `crates/ramflux-sdk/src/bus/contact_backpressure.rs:41-44`, `crates/ramflux-sdk/src/bus/contact_backpressure.rs:54-79` | Expiry and record/remove-retry update joined hold state; replace router-rescan floor with indexed local WS redrive |
| `crates/ramflux-sdk/src/client/group_quarantine.rs:30-41`, `crates/ramflux-sdk/src/client/group_quarantine.rs:115-150` | Retain/isolate group holds through the same quotas and terminal transition |
| `crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:60-65` | Erasure first marks receipt erased then removes content in the same transaction; later W2/WS may only settle erased metadata |

## 3. Crash-consistency matrix

### 3.1 Client writes and all adjacent crash cuts

A transaction interrupted before its commit is absent; after commit it is whole.
The table includes cuts between each processing subcommit, not just before W2.
All rows apply with both router storage modes; mode-specific router absence is
resolved by W0/receipt reconciliation, never assumed redelivery.

| Durable write / crash cut | Recovery sees | Required action and oracle |
| --- | --- | --- |
| Migration/epoch write; crash before/after | old schema / complete tables, imported local holds and epoch | Retry atomic migration or open migrated DB; no half-enabled loss inference |
| Before W0 / inside W0 | no receipt/work | C fixed, no local effect or ACK; next available page/push can stage it; actual expiry before staging may be unavailable |
| After W0 before first W1 | receipt(staged)+work, C unchanged | Redrive local work even if router now omits s; no gap for s |
| Each W1 subcommit k, before k+1 | W0 plus partial idempotent effects | Recover by committed marker/receipt, complete remaining effects once; raw work is not pruned by router TTL |
| After terminal W1 before W2 | W0 plus completed effects, no intent, C unchanged | Recover as Duplicate/Completed and W2; no false gap if router expired; capacity pause has same oracle |
| Inside / after terminal W2 | none / all of preceding losses+outbox+intent+cleanup+C | Never partial intent/C or loss/C; restart resumes at C and retries intent |
| Inside / after held W2 | old C / C>=s plus held receipt+work+retry, no intent | Local hold survives while later entries advance C; router loss below C creates no new content gap |
| Between successive W2 steps / final gap-only W2 | C at last complete step | Re-fetch suffix; every missing interval is counted once |
| Below-C WS, including intervening W1 subcommits | held work, or terminal intent plus cleanup | Before WS commit retry safely; after commit ACK from intent; C unchanged in both cases |
| Incarnation reset before/after commit | all old E state / new E+C=S+one reset event, old intents/projected loss rows removed | WJ precedes reset; S from first page suppresses settled-prefix losses; no orphan compat work or old callback settlement |
| Local hold terminal expiry/eviction before/after commit | full held work+receipt / failure event+intent+cleanup | Below-C WS leaves C unchanged; above-C ordered W2 never skips a predecessor |
| Erasure transaction during staged/held work | old content+receipt, or erased receipt without content | Restart can only finish erased accounting; late outcomes cannot resurrect copies |
| Before send / after ACK send but before router WR | intent on disk | Resend, in push or compat mode; do not delete on network uncertainty |
| After WR before reply / WA | intent on disk, router may have settled | Idempotent ACK or legacy exact lookup; delete after terminal evidence |
| WA retry/expiry/delete transaction | old intent / complete updated or deleted intent | Never a partial batch delete; only named requested rows affected |
| Loss outbox before journal projection WJ | loss+C+unpublished outbox | journal_outbox inserts one unique source-key event and marks publication |
| Inside / after WJ, before subscriber send | no / one journal row per outbox source key | Replay journal on reconnect; socket delivery may repeat the same journal seq |
| Projected-loss pruning WP | old ranges / pruned projected ranges | Counters and C unchanged, no new loss events; unpublished rows never pruned |
| Backup sanitization commit | snapshot not yet usable / sanitized snapshot | Publish backup only after strip+sync; never restore ledger with a stale target/C |

The W1 subcommit row above expands to the following concrete stages. Every
listed commit has a before/after crash hook, with local W0 retained. These are
required S6b changes, not assertions that current code already has this behavior.
All source ranges are at the product base. Dedup state containing message identity,
reply content or source attribution stays registered for erasure.

| Stage / actual source entry and commit points | Durable dedup / redrive result | Network work and exact S6b adaptation |
| --- | --- | --- |
| Seen/committed probe: `crates/ramflux-sdk/src/bus/sync_driver.rs:399-400`; `crates/ramflux-sdk/src/client/routed/committed.rs:37-58`; `crates/ramflux-sdk/src/client/routed/receive.rs:138-175` | Existing routed seen hash and authenticated committed key identify a prior crypto/content commit; mismatch is rejected | A hit skips crypto only. It must still drain the required projection/reply stages below; do not return Completed merely because seen exists |
| Own-device receive: `crates/ramflux-sdk/src/bus/sync_driver.rs:402-403`; `crates/ramflux-sdk/src/client/own_device_copy.rs:370-475` | Existing RECEIPTS packet-id/fingerprint plus control+inline-key-slot+receipt transaction; duplicate returns Duplicate after required local projection | Manifest reads run outside actor; commit revalidates generation/authority. Pair recovery work uses durable courier admission, no socket await in actor |
| Routed bootstrap/open: `crates/ramflux-sdk/src/client/routed/receive.rs:100-135`, `crates/ramflux-sdk/src/client/routed/receive.rs:178-235` | Authenticated admission key; contact bootstrap/own-history import retain their per-event receipts; retries resume from these markers | Manifest/discovery/group preparation/own-history network reads become Prepare -> external bounded call -> generation-fenced Apply. Preserve input and result across each local commit, no actor-held DB across await |
| Routed crypto/content commit: `crates/ramflux-sdk/src/client/routed/receive.rs:236-264`, `crates/ramflux-sdk/src/client/routed/receive.rs:531-610` | Existing authenticated committed receipt, pair snapshot, projection/message watermark in transaction; Duplicate reconstructs outstanding local stages | Pair-reset reply becomes durable courier outbox admission in the same effect/marker transaction. Attachment fetch stays external and uses existing object/import identity; auto-fetch=false for resident receive. Cache refresh is replayed from committed state |
| Surface answer: `crates/ramflux-sdk/src/bus/sync_driver.rs:407-408`; `crates/ramflux-sdk/src/client/surface/resync_request.rs:304-314`; `crates/ramflux-sdk/src/bus/sync_driver.rs:75-83` | Existing surface/resync-response key is atomically transferred to durable courier outbox keyed by authenticated receive identity; a transfer marker makes redrive Duplicate | Replace remove-before-send and in-memory reply vector. Outbox retains immutable prepared envelope/id until submit acknowledgement; lost reply retries same envelope. Remote replay dedup applies, no claim of exactly-once physical network send |
| Legacy group retention: `crates/ramflux-sdk/src/bus/sync_driver.rs:422-425`; `crates/ramflux-sdk/src/client/group_quarantine.rs:30-41` | legacy_key + existing legacy-held and unique unrouted journal source key, joined receipt disposition | HeldLocal, not Completed; quotas/evictions section 2.6; explicit group receive calls WS, never C setter |
| V2-blocked/unbound: `crates/ramflux-sdk/src/bus/sync_driver.rs:427-436`, `crates/ramflux-sdk/src/bus/sync_driver.rs:456-461` | admission_key and unrouted:{key} journal identity committed together with held disposition | Combine hold_unrouted + append_journal + receipt in one transaction. Redrive returns HeldLocal; no reply, expiry/eviction only W-path |
| Legacy bound receive: `crates/ramflux-sdk/src/bus/sync_driver.rs:438-454`; `crates/ramflux-sdk/src/client/dm.rs:374-481`, `crates/ramflux-sdk/src/client/dm.rs:567-595` | legacy_committed_key and projection identity; ratchet, application effect and terminal marker become one commit; existing partial projection is deduped before decrypt retry | Split authorization/attachment reads outside actor; remove embedded C writes and inbox ACKs, delegate W2/WS/WA. Rejection and receipt-control effects share terminal marker transaction |
| Failure policy: `crates/ramflux-sdk/src/bus/sync_driver.rs:320-329`, `crates/ramflux-sdk/src/bus/sync_driver.rs:472-505` | admission_key plus retry/dead-letter/policy marker joined to held/terminal receipt | Retryable -> HeldLocal; deterministic refusal -> terminal Rejected. Storage error propagates and retains staged input, never ACK; section 2.6 owns terminal deletion |
| Contact pressure: `crates/ramflux-sdk/src/bus/sync_driver.rs:303-313`; `crates/ramflux-sdk/src/bus/contact_backpressure.rs:54-79` | Existing authenticated root admission + receipt/work disposition, saved atomically | HeldLocal; local indexed retry replaces hidden Resume scan. No extra network reply; root/class quotas section 2.6 |
| Application projection: `crates/ramflux-sdk/src/bus/sync_driver.rs:145-165`, `crates/ramflux-sdk/src/bus/sync_driver.rs:335-337`; `crates/ramflux-sdk/src/client/routed/committed.rs:100-129` | projected marker and durable application outbox event share ONE transaction with unique authenticated receipt source key | project_committed_message propagates claim/write errors: HeldLocal with retry, never Completed. Replace marker-before-RAM-publish by atomic marker+outbox; journal replay rebuilds RAM. Existing seen/crypto Duplicate still executes this stage |

Completed means every applicable local stage above is committed, including
courier admission for replies and projection outbox creation. Courier transmission
is independent; a local reply-outbox write failure is held, not success. Reply
outbox entries use existing courier caps, footprint/erase/backup policy and at
most one immutable reply per authenticated input; capacity refusal retains W0.
S6b must enumerate the actual nested commit hooks under the named helpers in its
implementation report. New kinds or additional irreversible stages beyond this
inventory require a controller scope amendment before implementation acceptance.

No guarantee relies on router rows surviving a client crash. Power-loss claims
are limited to the configured DB/WAL sync and filesystem guarantees. Tests kill
a child process and reopen actual files; a task cancellation test alone does not
establish crash durability.

### 3.2 Router writes, modes and recovery cuts

S6 adds a batch operation, not a second router receive ledger. Apply a candidate
ACK batch on a cloned affected shard state; accumulate ALL acknowledged and
retired sequences across individual ACK calls, then commit once and publish the
new in-memory shard. Hold that shard's mutation serialization through publication.
On storage error publish nothing, return no success and retire the request/session;
if durable commit outcome is uncertain, reload/abort rather than serve a fork.

The page/issued APIs read only the durable published shard view. For each (T,E),
track assigned sequences still in flight in an in-memory ordered set. Let A be
highest assigned and P the published durable watermark. Each assigned sequence
<=P has exactly one durable disposition: accepted entry or aborted tombstone.
Assignment creates an owned in-flight guard under allocation synchronization,
before exposing the tentative row or releasing that synchronization. Durable
terminal success removes it, then P advances to min(in_flight)-1 (or A when
empty). Completed rows above P remain private. Short shard synchronization
publishes rows/tombstones and P together. No blocking mutex is held over storage
I/O; same-target submissions stay concurrent and WAL batching is preserved.
Existing bounded ingress permits (reference queue 4,096) also reserve guard and
tombstone persistence capacity before allocation, including native custody.

The guard owns the final persistence outcome, not a request continuation. A
Drop caused by panic/unwind, early return, cancelled future or an allocated
non-persisting outcome synchronously commits a sequence-only tombstone
`(T,E,s,aborted)` through the store, without a shard mutex held. It does not abort
the process. Drop must not panic or rely on spawning an unowned async cleanup;
it returns only after durable disposition or an explicit storage-fault quarantine.
Before allocation refusal/replay/forward-only outcomes need no guard. Audit each
should_persist_submission=false outcome: if it owns an allocation, Drop resolves
it; a no-allocation assertion alone is insufficient for an injected allocated
branch. A successful accepted write disarms Drop only after durable completion.

Cancellation racing persistence must serialize on the store's per-assignment
terminal state: accepted and aborted are mutually exclusive, selected atomically
with their record. Drop joins any already committing operation; accepted wins
if committed, otherwise aborted commits and a late accepted completion cannot
resurrect it. Redb uses one terminal transaction; WAL terminal records and replay
resolve that same single winner. Never tombstone an accepted row or expose both.
An aborted record stores no envelope ID, ciphertext, sender or replay tuple.
Remove tentative content/index effects before publishing its tombstone. Retain
tombstones until a durable contiguous settled/checkpoint prefix subsumes them;
never prune an unsettled tombstone into unknown on ordinary restart. Coalesce
adjacent aborted ranges; include them in the sparse index and page bounds.
Reserve one of at most 4,096 uncheckpointed aborted-range slots per inbox before
allocating, in addition to the ingress permit; full reason storage pauses new
allocation before effects. Checkpoint only after the durable settled prefix
subsumes the range, preserving its sequence disposition in recovery state.

On tombstone I/O failure, keep the guard's reservation in store-owned recovery
state, quarantine this inbox and return transient persistence_unavailable to its
waiters; publish nothing beyond the hole. No success or silent frozen inbox is
permitted. Recovery retries the terminal write/reloads durable state before
reopening admission. A process crash can bypass Drop; that separate residual is
unknown after restart, not an invented aborted reason. A watchdog exports
oldest_in_flight_age_seconds and in_flight_count; WARN when oldest age >30 s
(rate limited once/minute per affected inbox), without aborting the process or
claiming that WARN resolves a still-live storage operation.

**Reply enforcement:** router submit/fan-out/forward and native custody Submitted
responses wait until P(T,E)>=s for EVERY assigned target before returning
success. The gateway remains reply-driven; it cannot push s+1 on its own write
alone. No new publishable bit or later notification channel is introduced.
Wait outside shard/store locks using a cancellation-safe notification predicate;
if the request is cancelled after commit, its accepted guard stays resolved.
Sender acknowledgement latency therefore includes earlier same-target writes
or their tombstone commits, in addition to its own commit. Healthy storage
batch deadlines apply; the 30 s watchdog is diagnostic, not a hard latency bound.
Persistent replay responses referring to s also wait for its published P.
For fan-out, gate each assignment before exposing any reply/push for it.

Pages, covered_through_seq, FetchEntry, probes, legacy and custody reads expose
only rows <=P and issued=P. A tombstone supplies known reason aborted, including
EntryGone; it is never a live Deliver. Do not reuse any durably assigned sequence
after failure/restart. Recover the durable high-water counter, and prevent
old-process callbacks from publishing into a recovered incarnation.

| Assignment / read site at source baseline | S6a disposition |
| --- | --- |
| `apps/ramflux-router/src/router_engine.rs:61-103`, `apps/ramflux-router/src/router_engine.rs:182-225` | Sync/async submit, local completion of forwarding and fan-out: allocator guard, terminal persist, wait P>=s before response; audit `apps/ramflux-router/src/router_engine.rs:448-459` non-persisting outcomes |
| `apps/ramflux-router/src/router_engine.rs:342-382`, `crates/ramflux-node-core/src/router.rs:754-770`, `crates/ramflux-node-core/src/router.rs:822-841` | Own-device fan-out's separate record_fanout_increment owns every returned allocation guard through the batch commit; any early error drops unresolved guards; wait for each target P before exposing the fan-out result |
| `crates/ramflux-node-core/src/custody_delivery.rs:57-73` | Native custody submit uses the SAME allocator guard/store disposition and reply gate, replacing its independent acceptance/persistence boundary |
| `crates/ramflux-node-core/src/router.rs:1159-1178` | Both online/offline append_at allocation branches create guard before releasing shard; all wrappers, including fan-out, share it |
| `apps/ramflux-router/src/handlers.rs:1098-1129`, `crates/ramflux-node-core/src/custody_service/admission.rs:347-363` | HTTP and native custody Inbox both read the same durable published view bounded by P, even for legacy response shapes |
| `crates/ramflux-node-core/src/router.rs:709-739`, `crates/ramflux-node-core/src/router.rs:1181-1194` | mvp1_inbox, mvp1_inbox_at and resume wrappers enforce P before their pull_after/pull_live_after access |
| `crates/ramflux-node-core/src/router.rs:254-257`, `crates/ramflux-node-core/src/router_abuse.rs:90-96` | Pending-entry administrative snapshot/abuse count also read published state; no tentative row escapes through diagnostic APIs |
| `crates/ramflux-node-core/src/inbox.rs:197-229`, `crates/ramflux-node-core/src/inbox.rs:303-343` | Low-level append wrapper/allocator and pull methods sit behind the same guard/publication boundary; raw in-memory fixture construction has explicit test-only durable initialization, never a production bypass |
| `apps/ramflux-gateway/src/session.rs:1272-1343`, `apps/ramflux-gateway/src/session.rs:1444-1468` | Gateway reply-driven push/fan-out needs no separate watermark cache; actual pushed frame is the enforcement oracle |

The two-submission test holds s's write, completes s+1's own write, and captures
both submit responses, the actual gateway recipient frame, custody Inbox, page,
FetchEntry and issued probe. None exposes s+1 before P advances. Release s or
durably abandon it, then s+1's response and push become available. Independently
inject guard drops at every exit above and a panic inside persistence; the
process survives, aborted is durable in both modes and P progresses. Mutations
that reply on own-write durability or omit Drop tombstones must fail these
respective oracles. Process death before terminal durability is tested separately.

| Write / cut | WAL-enabled submissions (reference default) | Redb-only submissions | Recovery / response rule |
| --- | --- | --- | --- |
| Inbox E creation / restore rotation | E persisted in WAL association and redb counter before service | E persisted with redb counter before service | Crash resumes complete recovery pass; never serve mixed old/new E |
| R0 before durable submission, after in-memory preparation | no committed WAL record | no committed redb submission | No successful acceptance sent; restart has only prior durable state |
| R1 submission commit | append+sync submission, including E and acceptance time; may have no redb inbox row | one redb transaction: E+counter+replay tuple+inbox/deadline indexes/local-delivery metadata | Reply only after durable success AND P>=s for each target; crash before reply may be sender retry; preserve replay behavior |
| RA guard abandonment | sync aborted terminal WAL record and counter, before P publication | atomic aborted record+counter, before P publication | No process abort on Drop; recovery preserves aborted reason; accepted/aborted race has one winner |
| R1 then crash before sweep/checkpoint, restart before expiry | merge WAL with redb cursor exclusions | restore redb pending rows | Entry live in both modes |
| R1 then crash, restart past expiry before sweep | WAL replay/retention filters may remove entry, issued watermark remains | restored expired row remains, with deadline | Page omits live entry; WAL can give unknown, redb derives expired; client suppresses gap when W0 exists |
| WR batch ACK commit | redb cursor checkpoint plus union of all row/index retirements; WAL records remain, excluded on merge | same redb atomic operation | Before commit all old; after commit all settled. No cursor-only or last-ACK-only retirement |
| WR then crash before in-memory publication/reply | redb cursor controls WAL merge | redb cursor and row deletion restored | Resend returns already_settled/not_found; no duplicate content application |
| RN NACK commit | existing redb cursor/attempts/retirements | same | Async handler responds after commit; third NACK retirement preserved |
| RE retention deletion commit | remove due durable rows/replay indexes, retain/checkpoint issued state; WAL memory prune is separate | remove due rows/indexes, keep watermarks | Crash before commit may restore expired rows; readers still hide them. No exact reason persistence is promised |
| RC cursor checkpoint commit | preserve recovered issued watermark before WAL segment retirement | retain issued watermark after expiry of last row | Crash yields old/new complete checkpoint; do not reuse issued sequences |
| RP WAL memory prune / closed-segment unlink | volatile record pruning is not a new durable transaction; unlink only under existing retention margin after durable watermark recovery/checkpoint | not applicable | After restart exact expiry reason can be unknown; coverage still includes issued seq. Tests include another restart after pruning |
| Page/FetchEntry/issued probe | no write | no write | One locked consistent view; cannot manufacture durable loss history |
| Ephemeral routing, marker insertion, enqueue, expiry | no durable write | no durable write | After restart transient state is absent, never reconstructed from WAL/redb |

RE/RC refer to existing retention/checkpoint transactions; tests hook each actual
commit, including separate transactions inside the retention pass. S6 must not
change storage recovery to force identical reasons in the two modes. If durable
issued watermarks would be lost on any existing prune path, fix that path in S6a
before claiming coverage; retaining a reason record is unnecessary.

## 4. Wire contract and compatibility

### 4.1 Capability and exact frame shapes

JSON uses existing frame_type snake_case tags and existing Open/Auth envelope
shapes. New frames require signed capability_scope containing
`gateway.session_push.v1` AND its echo in SessionEstablished.session.capabilities.
Absent echo means compat. A gateway advertises it only with a router implementing
all S6a routes; mixed new gateway/old router fails capability readiness and serves
legacy protocol. Unknown new frames on an unnegotiated session are refused.
A new client may disable its advertisement for interoperability testing; this is
compat mode. No extra deployment input is introduced.

Node readiness discovery is read-only: gateway calls
`GET /mvp1/session-push-capabilities` over authenticated mesh with a two-second
deadline. Reply is `{capabilities:Vec<String>}`; S6a router lists
gateway.session_push.v1 only after all its routes/publication rules exist, and
S6c adds gateway.ephemeral.v1. A missing endpoint, invalid reply or timeout gives
no capability; retry once per 60 seconds in the background, without blocking
legacy session service. Each session freezes the intersection at establishment;
later readiness changes apply to new sessions. A route disappearing after node
rollback retires the active capable session and renegotiates on reconnect.

Primitive aliases: Seq=u64, Deadline=i64 Unix seconds, Target=existing target
string; Incarnation is the 32-hex E above. Omitted Optional fields decode as None.
Entries retain the existing InboxEntry shape. EntryRecord is `{entry: InboxEntry, retain_until: Deadline}`.
RangeReason is `expired|ack_window_overflow|nacked|aborted`; local reasons also include
`oversize|unknown`. Requests are implicitly scoped to the authenticated session T;
when a legacy-shaped request includes target, it must equal T. No request_id is
needed because S2 permits exactly one request in flight; an unexpected reply
retires that session, never satisfies a later call.

| Direction / tag | Exact fields beyond frame_type | Reply set / meaning |
| --- | --- | --- |
| C->G resume | resume:{target_delivery_id:Target,after_inbox_seq:Seq,limit:usize,resume_token:String}, incarnation_id:Incarnation | Capable request adds E; omit E on legacy wire. Capable reply is resume_page or nack |
| G->C resume_page | target_delivery_id:Target, incarnation_id:Incarnation, after_inbox_seq:Seq, covered_through_seq:Seq, issued_inbox_seq:Seq, settled_through_seq:Seq, entries:Vec<EntryRecord>, known_losses:Vec<{from_seq:Seq,to_seq:Seq,reason:RangeReason}>, oversize_next:Option<Seq>, more:bool | Authoritative range, section 5; cannot mix with unsolicited pushes |
| C->G fetch_entry | incarnation_id:Incarnation, inbox_seq:Seq | entry, entry_too_large, entry_gone, nack |
| G->C entry | incarnation_id:Incarnation, record:EntryRecord | Exact s and T from request; full frame <=F |
| G->C entry_too_large | incarnation_id:Incarnation, inbox_seq:Seq, retain_until:Deadline | Live legacy entry exceeds single-entry cap. No envelope/message ID or content |
| G->C entry_gone | incarnation_id:Incarnation, inbox_seq:Seq, observed_issued_inbox_seq:Seq, reason:expired\|ack_window_overflow\|nacked\|aborted\|unknown | Point view says no live entry at s<=issued. No TTL invented |
| C->G ack_batch | incarnation_id:Incarnation, inbox_seqs:Vec<Seq> | Strictly increasing, 1..64, all positive; ack_batch or nack |
| G->C ack_batch | incarnation_id:Incarnation, cursor:InboxCursorResponse, results:Vec<{inbox_seq:Seq,outcome:acked\|already_settled\|not_found\|invalid_seq\|rejected,reason:Option<String>}> | Exactly one result per requested seq, no others; reason bounded 256 UTF-8 bytes |
| G->C submit_accepted | incarnation_id:Incarnation, envelope_id:String, target_delivery_id:Target, inbox_seq:Seq | Durable submit reply; compact acknowledgement, no recipient content |
| G->C deliver | entry:InboxEntry, incarnation_id:Option<Incarnation>, retain_until:Option<Deadline> | Unsolicited only in push mode, and only for T; E and retain_until required in capable sessions, omitted for legacy |
| G->C resync | incarnation_id:Incarnation, target_delivery_id:Target, after_inbox_seq:Seq, reason:queue_full\|not_pushed | Hint to fetch from local C, never authority to move it |
| G->C ephemeral | envelope:Envelope, expires_at_ms:u64 | Event, no inbox_seq |
| G->C ephemeral_result | envelope_id:String, outcome:accepted\|dropped, reason:Option<EphemeralDropReason> | Reply to ephemeral submit; reason present iff dropped |
| establishment addition | session.capabilities:Vec<String>, default empty, omit empty; session.inbox_incarnation_id:Option<Incarnation> (required for every capable inbox, absent legacy) | Echo only negotiated capabilities |

EphemeralDropReason is
`offline|queue_full|expired|rate_limited|not_local|target_refused|recipient_unsupported|invalid|unsupported|replayed`.
Unsupported is also produced locally without a request. New frame types do not
change legacy Resume/Deliver decoding. Keep old public SDK call signatures with
adapters; add explicit resume_page/fetch_entry/ack_batch operations. For legacy
submit only, S2's dispatch recognizes the matching Deliver as a reply; self-target
legacy submit is consumed once through that reply path. In capable mode Deliver
is always an event, including self-target submit; sender reply and recipient push
are built separately. Tests must cover actual recipient receipt, not just reply
decoding. A compact submit_accepted adapter can reconstruct the existing public
submit result from its authenticated submitted envelope and returned assignment.

### 4.2 Mesh endpoints and authorization

All new endpoints are available only to authenticated authorized gateway peers;
they never trust a target supplied by an end client without binding it to T.
The gateway/router version pair is upgraded together; no assumption of independent
per-request capability discovery from a legacy router.

Durable submission/fan-out mesh results must supply the router's actual
retain_until beside each assigned entry, sourced from its acceptance deadline
index. The gateway carries it unchanged through push and forward. It cannot
reconstruct the acceptance cap from the sender clock. This is additive response
metadata; the public InboxEntry and legacy response shapes stay unchanged.

- `POST /mvp0/ack-bound-batch` body `{target_delivery_id,incarnation_id,inbox_seqs}` ->
  `{incarnation_id,cursor,results}` as above. ACKs by seq are authorized by the session binding;
  derive envelope diagnostics from the router row, never client-supplied content.
  An E mismatch rejects the whole batch as incarnation_mismatch.
  A seq above published issued is terminal invalid_seq and cannot advance router
  state. not_found is terminal only for an already issued absent row; an unknown
  target has issued=0, not permission to create a future ACK cursor.
- `GET /mvp1/inbox/{target}?after=&limit=&session_push=1&incarnation_id=` -> the resume_page fields
  without frame_type. Absent session_push returns the legacy response.
- `GET /mvp1/inbox-entry/{target}/{seq}` with incarnation_id query -> tagged entry/entry_too_large/entry_gone, each with E.
  Gateway authenticates and enforces s<=issued; s=0 or s>issued -> nack invalid_seq.
- `POST /mvp0/issued-seqs` body `{targets:Vec<Target>}` ->
  `{issued:Vec<{target_delivery_id,incarnation_id:Option<Incarnation>,inbox_seq}>}`; 1..1,024 unique targets, exactly
  one result each, unknown target gives 0. No missing-key interpretation as zero.
- `POST /mvp0/envelope-ephemeral` body `{envelope,expires_at_ms}` ->
  `{outcome:online,gateway_id,session_id}` or `{outcome:dropped,reason}`.
  Recompute the signed deadline and reject a mismatched supplied value. Use
  read-only source/current-authority validation and volatile replay insertion;
  do not accidentally refresh durable identity/replay state on this route.
- Mesh forward keeps existing request fields and frame. Response adds
  `outcome:Option<queued|overflowed|no_session|full|unsupported|expired>` alongside
  existing `delivered:bool`. The selected session token/capability is rechecked
  at final enqueue; routing lookup alone is not an acceptance reservation.

Ack/Nack/AckBatch use async mesh calls with the existing bounded request deadline;
no blocking router_post_json on a Tokio session worker. Validate counts/sequence
order/frame bytes before router I/O. Ephemeral-marked and unknown-mode envelopes
are rejected before any durable submit/federation/migration append or spool.

### 4.3 Compatibility matrix and pending intents

| Client | Node pair | Selected mode | Durable receive and replies | Ephemeral |
| --- | --- | --- | --- | --- |
| old | old | legacy | Existing polls, Deliver submit reply, per-entry ACK | unavailable |
| old | new | legacy | Exact legacy frames, no resync/resume_page; node may drop queued push overflow because client polls | never sent to legacy recipient |
| new | old | compat | Ledger retained; legacy Resume/ACK adapter, five-second sweep | local dropped unsupported, no frame |
| new | new | push | New reply/event split, coverage pages, AckBatch, event-driven receive | section 8 |
| new | new | compat (advertisement disabled) | Same ledger and legacy adapter as old node; no new frames | unsupported |
| old | new | push requested | impossible: no signed capability; do not infer support from node version | unavailable |
| new | old | push requested | echo absent selects compat; do not optimistically send frames | unavailable |
| old | old | push requested | impossible: neither endpoint implements negotiation; existing legacy behavior | unavailable |

**Legacy settlement of intents left by push mode:** scan due intents by sequence
in bounded groups of 16 per actor/network turn. For each s<=C, make a legacy
Resume(after=s-1,limit=1), on S2's host with unsolicited Deliver kept separate.
Before any lookup-based retry, establish the original E with a capable node
or prove exact authenticated content equality against a surviving registered
local work/committed copy. A truly old node supplies no E: sequence equality
alone NEVER authorizes ACK. An inherited sequence-only intent without such
content proof is suspended as incarnation_unverified until capable reconnection
validates E or its deadline expires. This safety restriction replaces the former
unconditional legacy-retry promise; it cannot ACK newly reused sequences.
New compat processing keeps its existing registered W0 copy and terminal receipt
until legacy ACK/verified absence/expiry WA, so retries can compare normalized
source/id/payload with the original. Erasure removes that proof and suspends
network retries; terminal metadata may still expire. These terminal compat
receipts count within the same staging/reserved-intent caps and are never W1
redriven. WA atomically releases their work/receipt after settlement.
This special lookup does not use the public merge-pushes resume_after adapter,
does not call normal receive, and never changes C. Old pull_live_after returns
the lowest live entry above after. An exact (T,s) result supplies envelope ID in
memory: construct the existing signed ACK and await both Ack and Cursor replies.
Then WA deletes intent. If the complete valid reply is empty or its first entry
is greater than s, s has no live router row: settle the intent as absent. Within a proven E, the
router never issues s again. Under a proofless legacy session, absence retires
only local intent metadata; it authorizes no ACK or assertion about future reuse.
Timeout, malformed/oversized reply, target mismatch,
or ACK refusal retains intent with backoff. Never infer absence from a partial
frame, discarded push, or failed call. A crash after that ACK but before WA simply
repeats lookup, now absent. Legacy lookup serializes on the one host wire slot;
normal calls get a turn after each intent, not after the whole table.

The transition push->compat->push therefore neither strands nor discards intent
rows without an explicit status/deadline. Same-E capable reconnection re-enables
suspended retries; new-E reconnection atomically resets them. New entries in compat
still use W0/W1/W2 before their per-entry ACK; legacy
ACK-before-C ordering is not carried forward. Compat Resume lacks authoritative
issued coverage: apply returned entries and advance over missing intervals only
with classification legacy_unverified, after reconciling receipts. An empty
legacy page never moves C. No typed claim of definite content loss or tail
coverage is made from it. For normal compat receive, start with limit 64. On a
frame-size failure, retire the failed session and retry once on a fresh session with limit 1, sticky for
that connection. If a single entry still exceeds F, pause receive with
paused_reason=legacy_entry_too_large; do not loop reconnects or move C.
A legacy node unable to send an old oversized entry can
pause settlement until its expiry or a node upgrade; status exposes this delay.
A truly old node cannot attest counter continuity: on observed regression
freeze C and settlement for recovery; do not silently wait for reused numbers
to pass old C. Undetectable legacy restores remain a legacy limitation; the
incarnation guarantee requires the capable protocol. These are explicit
interoperability limits, not unsupported-frame retries.

## 5. Paging, byte bounds and progress proofs

F=1,048,576 serialized JSON bytes, excluding the existing transport length prefix.
B=F-65,536 is the whole resume_page cap; metadata reserve is subtracted exactly
once. Request limit 0 is nack invalid_limit; positive limit is clamped to 256
(gateway and router). Client normally requests 64. Hard limits per page: 256 live
entries, 64 known-loss ranges, 512 actual stored-row/boundary visits. The fixed
header/empty vectors/max-width fields must fit B; invalid huge target strings
are refused by existing identity validation plus an explicit serialized-header
check before walking. All caps include the actual JSON escaping/encoding cost.

The empty mandatory header with max-width numeric fields is capped at 16 KiB;
each known-loss record is capped at 256 bytes. Therefore the first reason record
always fits an empty page. A target/header violating this bound is refused before
the walk, so a metadata-only first boundary cannot create an empty continuation.

### 5.1 Sparse range algorithm

The existing pending Vec cannot support a bounded seek above a huge watermark.
S6a changes the private per-target sequence container to an ordered map keyed by
s (or an equivalent maintained ordered index with stable ownership), including
all submit, ACK, NACK, expiry and restore paths. Dead-letter lookup gets a sorted
sequence index as well. It is reconstructed from durable rows at startup; the index
itself needs no new
on-disk format; incarnation persistence is separately required in section 2.5. Seek
O(log P), then merge actual pending and
dead-letter boundaries. Never enumerate every integer from after+1 to issued.

Under one shard lock snapshot issued I=P and settled_through_seq S (0<=S<=I),
then walk sparse boundaries above after. Carry S on every page, including the
first reset page and empty pages; it never grants absent-range loss authority
below S. Normal same-E catch-up does not overwrite C with later S.

The walk is:

1. Skip an absent interval in constant work, extending coverage to just before
   the next boundary (or I). Missing intervals need no serialized router record.
2. For an expired pending row, append/merge an expired reason; do not delete it.
   Dead-letter and durable tombstone rows add their known reason; no live row may overlap a reason.
3. For a live row, measure the ACTUAL serialized one-item resume_page with its
   mandatory header, max-width coverage/I, retain_until, vectors and delimiters.
   If it cannot fit B alone, stop with oversize_next=s and covered=s-1. If it fits
   alone but not the current page, stop before s; the current page already made
   progress. Include no reason beyond coverage. A FetchEntry marker is allowed
   after a preceding gap-only span; the actor covers that span first.
4. Stop before exceeding any range/item/visit/byte cap. A visit budget reached
   after rows processed covers through the last processed boundary, not through
   the next unexamined live row. Yield and resume from that C. Every completed
   boundary either returns its entry or accounts its absence. Lookahead to the
   next key is one of the 512 visits; it grants no coverage over that key.

Measure using a counting serializer with the SAME JSON schema and worst-width
mutable numeric header fields; serialize the completed frame once, then assert
actual bytes<=B. No guess from envelope payload length or Submit-frame size.
Page algorithm cost is O(log P+512) row/index visits plus bounded serialization
(up to 256 candidate frame sizes, each <=F), not O(I-after). Client subtracts up
to 1,024 receipt keys using a range seek/merge, splits into <=64 boundaries per
turn, and uses checked inclusive-range arithmetic; a range of 10^15 missing
sequences costs one interval operation. Counts across mixed reasons do not overlap.
At u64::MAX use checked successor/exclusive-bound operations, never wrap to zero.

Before staging, SDK validates E against the active epoch, then target and
echoed after against its request,
after<=covered<=issued, 0<=settled_through_seq<=issued, sorted unique entry sequences inside coverage, and sorted
disjoint known-loss ranges inside coverage with no live-entry overlap. A marker
must equal covered+1 and be <=issued. more is true exactly when covered<issued;
an invalid/nonprogressing page retires the session with C unchanged. A point
reply must match the requested sequence/target, never a later entry substituted
for it. Receipt reconciliation cannot confer authority beyond these bounds.

### 5.2 Admission and FetchEntry

Before assigning/committing a NEW inbox row on every creating path (gateway,
own-device fan-out, federation inbound, migration forward, native custody submit), measure the largest
serialized downstream single-entry frame: capable Deliver including retain_until,
legacy Deliver, and Entry{record}. Substitute u64::MAX and worst-width signed
deadline; include node-added franking/authority metadata AFTER normalization.
If max length>F reject payload_too_large before append/replay commit/fan-out
assignment for that target. A compact submit_accepted always fits independently.
This measurement, not a reserved constant, proves newly admitted entries can be
fetched alone. Replay of an already stored oversized legacy row is handled below.

For oversize_next=s the client requires local C=s-1 after finishing the preceding
span, then issues FetchEntry(s). Complete outcomes:

- Entry: W0/W1/W2 accounts s as usual, retaining the advertised actual deadline.
- EntryTooLarge: if a local receipt exists, recover it first. Otherwise W2 writes
  oversize unavailability, its outbox, the intent with the supplied retain_until,
  and C=s. No invented TTL and no payload storage. A crash before W2 repeats the
  point fetch; after W2 the intent retires the row by seq.
- EntryGone: verify s<=observed_issued; recover any local receipt first. Otherwise
  W2 writes the supplied available reason (unknown if none), outbox and C=s.
  No intent is necessary: point view says no live row remains. Do not report
  oversize when expiry/sweep/restart removed it. A subsequent push at s is a
  duplicate and cannot undo committed accounting.
- Nack/transient failure: C fixed, backoff; no empty Resume/FetchEntry tight loop.
  Invalid seq is a protocol fault, not content loss.

For after<I, a successful page must satisfy covered>after OR
oversize_next=after+1. A page with covered=after, no marker and more=true is a
protocol violation. If after=I it returns terminal empty with more=false. If
client after>I (e.g. rollback lost a storage volume), return nack cursor_ahead;
freeze that same-E session, revalidate incarnation and require the recovery
procedure in section 2.5; a new E resets C atomically to its first-page settled cursor S and catches up from S. An empty
terminal tail at I after
absent ranges still has covered=I>after. Each successful point outcome accounts
s or supplies recoverable local work; thus successful catch-up strictly advances
until I. Finite backlog terminates; sustained writes yield after 16 pages and
coalesce another run. Pause/error is explicitly outside the progress guarantee.

## 6. Node queue, Resync, probing and mesh semantics

### 6.1 Registration-owned writer

Each registration owns its writer, generation token, durable FIFO, volatile
transient FIFO and coalesced resync slot. Replacement cancels only the old token.
Hub lookup is O(log N), then release hub lock before nonblocking try_push. Queue
mutation is O(1); no await under queue lock. Frames are serialized/size-checked
before admission. Durable limit=clamp(Open.max_inflight_downstream,16,256) and
4 MiB including the in-flight frame until its write completes. Sender work never
awaits the recipient's sink. All three existing callers must switch: durable
submit, own-device fan-out and mesh forward (`serve.rs` forward handler).

Overflow drops only a durable push copy and sets slot=min(slot,s-1). It means
handled, not offline. Legacy recipients get no new Resync frame; their polling
recovers. For capable sessions, emit Resync only when occupancy is <=half of
BOTH frame and byte capacities. An eligible Resync precedes durable work; otherwise
serve durable FIFO, then unexpired ephemeral FIFO. Once a slot is pending, reject
new durable enqueue attempts as overflow until the queue drains to the threshold
and Resync is written; this admission latch prevents continuous arrivals starving
the half-drained signal. Further overflows coalesce. While writing Resync detach
its slot; arrivals create a fresh slot that is not cleared by completion of the
older write. Control/reply and push writes share a frame-atomic sink; the writer
releases it after each frame, allowing replies to progress.

Queue wait may exceed a frame timeout; an actual sink write has a 15 s deadline.
On expiry close/unregister only that token and signal the client disconnect.
A queued transient expiring before its write is dropped silently. A stream write
already begun is not cancelled halfway merely because its deadline passes;
the SDK rechecks freshness on receipt and drops it. There is no second sender
result. No offline wake is issued for a live durable overflow.

### 6.2 D6 probe with population-dependent bounds

Use per-registration **contiguous offered coverage**, not max pushed sequence.
A high out-of-order push cannot hide a lower missed router-origin commit. Track
covered prefix plus at most 256 offered sequence intervals; a jump/interval-cap
exhaustion conservatively schedules Resync. Successful complete Resume coverage
and completed Resync writes advance the offered prefix; unflushed/dropped pushes
do not. This is gateway hint state, never client C or an ACK.

One process task visits ALL live registrations each round. Batches have <=1,024
unique targets, <=4 requests concurrently, 1.5 s per request, no overlapping rounds;
next starts two seconds after completion. Registration iteration uses a stable
round ID/high-water registration token and paged 1,024-registration snapshots,
not an unbounded vector clone under the hub lock. Existing registrations at round
start are visited once; later ones start next round. Replacement resets coverage
and confirmations. Maintain a round cursor/fairness so churn cannot starve older
registrations. Deduplicate target lookups inside a batch, fan results to every
matching live token. Missing response items fail that batch, not issued=0.

Two consecutive successful observations issued>offered_prefix enqueue a Resync
with after=offered_prefix; a timeout/failure resets confirmations, leaves coverage
unchanged, and logs at most once/minute. Record the observed issued watermark in
the pending slot's internal coverage; advance prefix only when Resync is actually
written. If pushes/Resume filled coverage meanwhile, suppress an obsolete hint.
Legacy registrations need no new hint but must not stall the round.

For stable N registrations and bounded local scheduler/lookup overhead L per
round, R<=ceil(ceil(N/1024)/4)*1.5 s+L. A previously missed commit is signalled
within 2*(2 s+R) plus queue drain/write time. Without queue/network failure,
excluding L and drain, N<=4,096 gives 7 s and N=40,960 gives 34 s. These are not
population-independent four-second guarantees. Router cost per target includes
its actual shard/map lookup, O(log mailboxes), not an invented O(1). Cost per
round <=ceil(N/1024) requests before deduplication; memory for requests <=4,096
targets plus per-registration state. Fair shard lookup and queue draining are
required premises; router outage falls back to the client safety sweep.

### 6.3 Mesh result interpretation

| Frame kind and final outcome | delivered boolean | New sender action | Legacy sender action |
| --- | --- | --- | --- |
| durable queued | true | handled | handled |
| durable overflowed with Resync pending | true | handled, no wake | handled, no wake |
| durable no_session | false | existing offline wake policy | existing offline wake policy |
| ephemeral queued on capable live token | true | accepted once | legacy cannot originate this frame |
| ephemeral full/unsupported/expired/no_session | false | dropped queue_full/recipient_unsupported/expired/offline; no wake | no transient request supported |

If a new durable sender sees no typed outcome from an old peer, use its existing
boolean. Do not originate ephemeral mesh frames toward a peer without transient
support; return recipient_unsupported. All recipient-capability and registration
replacement checks occur at final try_push. For an old forwarder sending legacy Deliver
without E/retain_until to a
capable recipient gateway, discard only that deficient push copy and schedule
Resync(not_pushed), tagged with the current registration's E and a conservative
after hint. Never enqueue the deficient frame, invent a deadline/incarnation,
or block the sender on a metadata lookup. Durable handled=true prevents an
offline wake; authoritative catch-up recovers the content. A legacy recipient
registration still receives the existing legacy frame. This explicit
old-forwarder/new-recipient cell is required in sender_recipient_matrix.

Cross-node ephemeral delivery remains not_local until a live federation transport exists; never use a durable federation
spool as a fallback. Same-node cross-gateway delivery is supported.

## 7. SDK runtime and S2 integration contract

S6b replaces the receive polling task; S2's host remains the only socket reader.
The receive child subscribes to Deliver/Resync/Lagged, while ephemeral intake is
separate. No child runs its loop inside ConnectionHandle.call. Actor messages:

- PrepareReceive{generation,incarnation_id} -> C, ledger limits, due intents/receipts (bounded).
- ApplyPage{generation,incarnation_id,expected_cursor,page} -> {cursor,paused,need_point_fetch}.
  Page is the exact authoritative structure, including EntryTooLarge/EntryGone
  point outcomes; actor performs W0/W1/W2 as bounded steps. Network calls happen
  outside these steps. A stale generation/E applies nothing. For a validated same-E page with
  after<=current C<=covered, trim entries/loss ranges to the suffix >current C
  and replan W2 against that cursor; discard no useful suffix. If C>=covered,
  coverage is already accounted; if C<after, re-fetch from C. Reconcile staged
  receipts before any suffix loss. A push racing each page must not starve
  catch-up progress.
- SettleRetained{generation,target,incarnation_id,inbox_seq,expected_disposition} -> WS result;
  explicitly allowed below C and distinct from a network duplicate.
- AckResults{generation,incarnation_id,requested_seqs,results} -> WA result; exact-set validation.
- ReceiveObservation{generation,incarnation_id,mode,counters,times} -> manager snapshot update
  only after actor commit; DB remains the source for durable counters.

S6 adds host.last_read_at()->Instant, updated in the single frame-read path on
EVERY complete frame, including replies and heartbeats. It is monotonic host
state, not inferred from a subscription. A child issues heartbeat after 25 s
without a frame read, with an absolute 10 s call deadline; lack of reply retires
the session under S2's timeout-after-write rule. S7 later adds disconnect_after
and server watchdog. Session children are aborted on lock/disconnect/stop and
restarted on a new generation. Ticket renewal in S8 without a new session must
not emit a duplicate Connected.

On Connected: load/reconcile local work; attempt due intents (all pending rows
are considered, capped turns, not wait-for-ever on rejected entries); perform
exactly one initial catch-up. ACK flush triggers: 16 eligible intents, oldest
eligible age 1 s, and before a catch-up. One batch on wire, max64 seqs. Flush
failure does not spin or suppress all catch-up; capacity pressure pauses W0.

In push mode, s=C+1 applies directly; higher pushes first W0-stage, then buffer
references up to256 entries/8 MiB
and start one 500 ms gap timer. Hole filled before deadline -> no Resume. Timer,
Resync, S2 resync_needed, due local retry, Connected or safety sweep coalesce into
one catch-up plus at most one follow-up. Pushes during catch-up remain separate
from authoritative pages; lowest seq wins buffer retention, overflow drops the
highest in-memory reference and requests catch-up without ACK; an already
staged copy remains on disk. Before any W2 missing-range write reconcile all
those staged pushes, even if the router meanwhile expired/dead-lettered them.
If W0 capacity refused a push, it is not admitted into the reorder buffer. Local retry
does not require a pull
when durable work alone suffices. Catch-up pages64, max16 pages before yield.

Default push safety sweep900 s since last completed catch-up, configurable
RAMFLUX_SESSION_SAFETY_SWEEP_SECS clamped60..3600 once at process start. Compat
sweep5 s, regardless of that push-only setting. Old RAMFLUX_SYNC_MIN_MS/MAX_MS
are ignored with one warning naming the replacement. Parsing is pure/testable,
not process-global test mutation. A catch-up stopped by backpressure is not
“completed” for the idle timer. No old tick or courier can secretly pull inbox.

Status adds receive:{mode,last_catch_up_at,catch_ups_total,inbox_gaps_total,
legacy_unverified_total,ack_intents_pending,held_entries,paused_reason}.
Status also exposes active incarnation, inbox_resets_total, held_evicted_total
and incarnation_unverified settlement count. Manager is the snapshot's single writer;
actor supplies committed counters.
Old public SDK APIs and unchanged desktop consumers must compile against the
published product SHA. S6 may add internal entry/page methods; it may not force
desktop callers to adopt a new connection runtime.

### 7.1 Complete receive-entrypoint and cursor-writer inventory

This inventory is from repository-wide Rust searches for
persist_gateway_receive_cursor, gateway_receive_cursor_checkpoint_name,
resume_after, receive_gateway_deliveries, receive_gateway_plaintext_deliveries,
ack_gateway_entry, ack_gateway_delivery, engine.ack and remove_unrouted
at the product base. Paths below are full source citations; all listed production
paths are S6b scope. Search again on the merged S2/S3 dispatch SHA; no unlisted
writer, puller, ACK sender or hold remover is grandfathered into push OR compat mode.

| Source at base | Existing behavior | Required disposition in both new-client modes |
| --- | --- | --- |
| `crates/ramflux-sdk/src/client/account.rs:244-279`; `crates/ramflux-sdk/src/dm.rs:334-336` | Public C reader/setter and checkpoint-name helper | Reader remains read-only. Keep setter signature but refuse managed-ledger writes outside an actor receive transaction; private W2/reset operation owns checkpoint mutation. No caller can use generic checkpoint write to bypass this guard |
| `crates/ramflux-sdk/src/bus/sync_driver.rs:182-198` | Primary Resume plus contact backpressure floor rescan | Sole receive child requests transport pages; floor scan becomes local indexed WS work, no hidden network pull |
| `crates/ramflux-sdk/src/bus/sync_driver.rs:219-223` | advance_cursor wrapper, reached by ready/held/error/ACK branches | Remove direct setter; each branch returns a disposition into ordered W2 or below-C WS |
| `crates/ramflux-sdk/src/bus/dispatch/group.rs:1336-1365` | Sync then unrouted group receive and routed C write | Request/coalesce shared catch-up; local holds explicitly redrive WS, read projected group results |
| `crates/ramflux-sdk/src/bus/dispatch/group.rs:1412-1425`; `crates/ramflux-sdk/src/bus/dispatch/group.rs:1456-1459` | Sender-key and two group-message C writes | Local redrive through W1+WS; no direct C write or ACK in group dispatch |
| `crates/ramflux-sdk/src/bus/dispatch/a2i_a2ui.rs:45`; `crates/ramflux-sdk/src/client/a2i.rs:72-78` | a2i.list calls a separate inbox pull | Coalesce shared receive, read committed A2I projection; no independent wire pull |
| `crates/ramflux-sdk/src/client/a2i.rs:114-115`; `crates/ramflux-sdk/src/client/a2i.rs:134-140`; `crates/ramflux-sdk/src/client/a2i.rs:206-210` | Routed, unbound and finish_a2i_receive C writes / ACK | W1 returns Completed/Held/Rejected, W2/WS covers and WA settles; existing legacy A2I effect/ratchet/receipt transaction remains its idempotency marker |
| `crates/ramflux-sdk/src/client/dm.rs:284-294` | Opaque public receive pulls from gateway cursor, appends entries | Adapter invokes shared ledger receive and reads committed opaque projection; appending opaque delivery alone cannot account/ACK a body as processed |
| `crates/ramflux-sdk/src/client/dm.rs:302-326` | Plaintext public receive pulls from C and writes C after routed processing | Adapter invokes shared receive and filters local projection; local held entries use WS |
| `crates/ramflux-sdk/src/client/dm.rs:360-369`; `crates/ramflux-sdk/src/client/dm.rs:477-481`; `crates/ramflux-sdk/src/client/dm.rs:584-595` | Legacy catch-up/success/terminal helper C writes | Keep content/ratchet marker transactions inside W1, remove embedded C mutation; W2/WS alone finish coverage/settlement |
| `crates/ramflux-sdk/src/bus/dispatch/message.rs:702-703`, `crates/ramflux-sdk/src/bus/dispatch/message.rs:804-855` | message.receive sync plus conversation-bound legacy hold redrive, direct ACK and raw hold removal | Coalesce shared catch-up; all held redrive goes through W1+WS (ordered W2 above C), cleanup joined to terminal transition and WA owns wire ACK; read committed conversation projection |
| `crates/ramflux-sdk/src/bus/dispatch/message.rs:21-40`, `apps/rf/src/handlers/dm.rs:49-65` | message.ack / rf dm ack ACK by envelope ID and mark local acknowledgement | Preserve public request signature; in managed mode return typed SdkError::InboundRejected with stable code receive_ledger_managed_ack, no engine acquisition/wire ACK/mark_acked. Internal WA remains the sole settler; no message-keyed intent column is added |
| `crates/ramflux-sdk/src/bus/dispatch/group.rs:1483-1494` | Direct group ACK and three raw remove_unrouted calls | Terminal W2/WS creates intent and joins all hold deletes; WA alone sends ACK |
| `crates/ramflux-sdk/src/client/dm.rs:702-740` | Public ack_gateway_entry/ack_gateway_delivery call engine.ack directly | Same typed managed-ledger refusal outside internal WA token; standalone ledger owns WA too. Caller-supplied envelope ID never creates a terminal intent or bypasses held accounting |
| `crates/ramflux-sdk/src/bus/sync_driver.rs:339-351`, `crates/ramflux-sdk/src/bus/sync_driver.rs:508-512` | Successful ACK cleanup and terminal refusal raw hold removal | Return disposition; terminal W2/WS joins deletes, WA owns ACK |
| `crates/ramflux-sdk/src/client/dm.rs:350-355`, `crates/ramflux-sdk/src/client/dm.rs:573-580`, `crates/ramflux-sdk/src/client/group_quarantine.rs:115-150` | Legacy decrypt/success/policy hold cleanup | Remove only within terminal W2/WS or the explicit erasure transaction; no receipt/work orphaning |
| `crates/ramflux-sdk/src/gateway/engine.rs:477-511` | Public raw Resume transport merges pushes | Preserve signature as a transport adapter, separate unsolicited frames in managed mode. Only shared receive or bounded compat exact lookup may issue inbox requests; raw caller cannot write C. Standalone public receive uses the same ledger executor under its existing exclusive client borrow |
| `crates/ramflux-sdk/src/client/dm_session.rs:264`; `crates/ramflux-sdk/src/bus/state.rs:354` | Delivery-state snapshot and startup maximum read C | Read-only; startup must load active E+C atomically, never write max into C or use a stale session cursor to override it |
| `crates/ramflux-sdk/src/client/dm_session.rs:320-335`; `crates/ramflux-sdk/src/client/dm.rs:1082-1090` | Test fixtures seed/read checkpoint | Replace direct writes by test-only fixture initialization; exclude no production caller from the guard |
| `crates/ramflux-sdk/src/bus/receipt_tests/erasure.rs:75`, `crates/ramflux-sdk/src/client/routed/root_ack_tests.rs:81-127` | Fixture-only direct ACK and forged-ACK refusal probes | Tests explicitly use unmanaged raw protocol fixtures or internal WA setup; retain refusal assertions and never exempt a production caller |

The actor executor and standalone executor share W0/W1/W2/WS/WA routines and
exclusive account writer ownership; a standalone receive call on an actor-owned
account returns the existing typed ownership error instead of starting a second
receiver. Public API signatures remain source compatible. Neither executor uses
a hidden polling task. Generic checkpoint APIs reject the receive-checkpoint
namespace except with the internal transaction token; no exported setter can
forge that token. Managed host/raw ACK adapters likewise require internal WA
authority before any outgoing ACK frame; direct engine calls cannot bypass the
guard. Raw transport Resume cannot apply messages or move C.

The guard test traces actual receive-checkpoint SQL writes, every outgoing
Ack/AckBatch frame (including legacy ACKs) and every hold-table delete, as well
as inbox requests. Invoke group receive, message.receive with a conversation,
message.ack/rf dm ack, a2i.list, both public DM APIs, legacy success/rejection
and retry/expiry/erasure paths with an interleaved gap/hold. Every C write is
W2 or explicit migration/reset; every ACK is WA for a terminal intent with s<=C
and matching E/content proof; every hold delete belongs to W2/WS, reset terminal
compat cleanup or explicit erasure. Refused managed ACK APIs produce no frame
or delete. No WS changes C. Hooks carry the real transaction/WA authority, never
a caller-supplied label. Classify fixture-only direct ACK sites separately in
the source inventory; production has no exemptions. A source assertion catches
new unclassified calls but does not replace the behavioral wire/SQL hooks.

## 8. Ephemeral delivery and S0 input

### 8.1 Contract consumed from approved S0

Generic mode=durable|ephemeral, no plaintext typing field, no new delivery class.
Until S10a introduces the signed/AEAD-bound named outer field, the signed
Envelope.ext.delivery_mode selects mode. Absent/durable uses durable route;
unknown mode is invalid everywhere. S10a replaces the bridge, not a parallel
transport. TTL is 1..5 seconds (default5), low priority; frame<=32 KiB. Per-session
token bucket20/s, burst40. Final live queue64 envelopes/256 KiB INCLUDING a frame
being written; receiver channel64/256 KiB, dedup<=4,096 live digests. Router
volatile replay set<=65,536 authenticated digests; saturation refuses, does not
evict live markers to admit replays. Receiver saturation drops new indicators;
no transient retry queue on disk.

Validate signature, current source/target authorization, mode, priority, clock,
size and rate before router I/O or enqueue. Router uses equivalent read-only
authority checks. Route only to an already live registration. Never create an
inbox_seq, inbox/WAL/redb/replay-store record, federation spool, durable retry,
dead letter, notification queue or offline wake. Return exactly one typed result:
accepted at final enqueue, dropped with section 4 reason otherwise. Accepted
queued work can expire without delivery; no second reply or later durable ACK.
SDK authenticates/decrypts before its transient consumer; S10a owns typed inner
consent, supersession and S0's endpoint Unsupported policy.

### 8.2 Pinned S0 r4 clock and indicator contract

The following text is verbatim from the approved S0 r4 Decision 6 pinned in
section 1.2 at `61d96751b550c661d15444a7ddecff116897498d`:

Throughout this document `ttl_seconds` names the sender-signed TTL in seconds.
During the S6 bridge it is the existing `Envelope.ttl: u32`
(`crates/ramflux-protocol/src/core_types.rs:56`); S10a names that same semantic
field `ttl_seconds` in the reset outer profile. It is not a second TTL or an
independently renewable interval.

Ephemeral TTL has the explicit bound `1 <= ttl_seconds <= 5` (default 5),
in integer seconds, and priority low. The lifetime uses
sender-signed Unix-second `created_at` and `ttl_seconds`: compute the checked
sum D = created_at + ttl_seconds and checked expires_at_ms = D * 1000. Reject
overflow, TTL outside 1..5, created_at > node_now + 2 seconds, or now_ms >=
expires_at_ms. Every gateway, router, federation hop, live writer and receiver
enforces that same exclusive deadline; no grace, first-receipt renewal or
restart extension. Within the 2-second future tolerance acceptance can be
immediate, so remaining life at first receipt can reach ttl_seconds + 2 seconds.

Endpoints accept Typing only in this mode. The typing indicator lifetime is
**at most 5 s**, bounded by the signed interval `[created_at, D)`: it is visible
only when created_at*1000 <= now_ms < expires_at_ms, and clears at D even
after restart or replay. The 2-second future tolerance permits early transport
acceptance, not early display or a longer indicator lifetime; any early input
stays only in bounded transient memory until its signed start, or is dropped.
The receiver independently checks its own clock: checked created_at*1000 must
be <= checked(local_now_ms + 2000), otherwise drop immediately, never hold it.
Accepted early input is held for at most 2 s, with the same future/deadline
checks repeated before display; backward clock movement cannot extend that
hold (use a monotonic 2 s hold deadline too). Clock overflow drops input.
Late arrival shortens the indicator lifetime; duplicate/reconnect never renews
the signed interval.

S0 r4 also resolves all three former approval gaps: integer TTL 1..5/default 5,
the at-most-5-second visible interval despite early transport acceptance, and
the signed ext.delivery_mode bridge followed by complete replacement with the
required named sender-signed/AEAD-bound field. At the S10a profile reset, remove
bridge emission AND parsing; reject bridge and dual-field input, never choose
precedence. These are the three L6 dependencies, all present in the pinned SHA.

expires_at_ms is carried unchanged and verified on every hop. Router marker is
a domain-separated digest of authenticated source root/device, envelope ID and
payload hash until D. Receiver dedups authenticated source/id, rejecting a
conflicting payload hash. Router-only restart may admit another queued copy;
a surviving receiver drops it. Router and receiver restarts, including repeated
restarts, can expose duplicates within the remaining signed lifetime: there is
no bound of at most one duplicate. All copies are rejected at or after D.
A sender clock lagging the node by its TTL can lose transient delivery; never
retry durably. No marker, transient history or renewed lifetime survives D.

## 9. Implementation split, tests and acceptance

### 9.1 Complete cards and merge order

Each row is a complete component delivery with its own tests. No row is “Part A
now, remaining business logic in a follow-up.” S6 completion means all rows below
merged and accepted. Do not reactivate the superseded monolithic implementation
card. Controller writes new cards from this approved design with explicit SHAs.

| Card | Complete scope and principal files | Dependency / enablement | Affected slices |
| --- | --- | --- | --- |
| S6a node durable session protocol | node-core gateway_frames, inbox_page, entry_bound, inbox sparse index; router handlers/router_engine/router_store/router_wal incarnation lifecycle, settled cursor, WAL identity, tombstones and ACK batch; node-core custody_delivery and custody_service/admission guard/read/reply paths; gateway push_queue, issued_probe, session, state, clients, serve; compact reply split, FetchEntry and capabilities, async ACK/NACK; node docs | Current main; no S2 dependency. Advertise capability only after the entire durable protocol exists. Legacy clients remain supported | id02, s39a, s51, s35, call01, s50 plus node protocol fixtures |
| S6b SDK durable receive ledger | storage account_db/receive/{schema,stage,cover,settle,privacy}, schema migration, footprint and backup paths; SDK bus/push_receiver/{apply,reorder,ack_batch,compat,keepalive}, S2 host dispatch/read timestamp and actor arm; bus/sync_driver and contact_backpressure; bus/dispatch/{group,a2i_a2ui,message}; client/{account,dm,a2i,group_quarantine,own_device_copy,routed/{receive,committed},surface/resync_request}; storage journal/{quarantine,inbox_failure,inbox_legacy,inbox_policy}; exact stage/entrypoint adaptations in sections 3.1/7.1, events/status, docs and CHANGELOG | S6a + merged S2/S3. Adapts provisional interfaces; no changes in S2 work-in-progress branch. Complete push and compat receive at delivery | id02, contact02, s74, s39a, s51, s35, call01, s50; push01 durable cases |
| S6c ephemeral transport | gateway ephemeral validation/queue/mesh result; router ephemeral_route and volatile replay; SDK transient API/dispatch/channel; durable-origin refusal; ephemeral docs | S6a/S6b; S0 dependency satisfied by approved complete Decision6 at 61d96751, including section8.2. Advertise separate `gateway.ephemeral.v1` signed/echoed capability only when the full path exists; session_push alone never implies it during staged merge | push01 transient case, id02, s50, s51 refusal fixtures |
| S6d acceptance harness | itest src/tests/push01_session_push.rs and realnet.yml; mixed-version fixtures, ledger crash scenarios in product test modules if fixtures need shared plumbing | S6b/c delivered, exact published product pin; all three push01 cases execute green before this card READY | all selectors below |

Final capability rule: ephemeral requires BOTH session_push.v1 and ephemeral.v1
on sender and final recipient; section4's “capable ephemeral” means both. S6a
nodes drop unsupported locally; no node with only the durable protocol can accept
a transient as durable. This separate bit permits complete component merges
without advertising unimplemented behavior.

Merge order S6a -> S6b (after S2 and S3) -> S6c -> S6d pin. S1 precedes deployed
acceptance. S7 may start design after S6a but merges after S6b, preserving this
host/keepalive contract. S8 design/security review may overlap; implementation
merges after S6b and retains one initial catch-up per real Connected. S10a
implementation dispatch waits for complete S6a/b/c on main and S2; its S0 design
dependency is satisfied by approved r4 at 61d96751.
S6d acceptance must be green before S6 is declared delivered. S10a owns inner
schema/typing semantics and replacement of the ext bridge. S4/S9 reuse S2 without
reopening the receive contract. Gateway/router images must share the node-protocol
SHA. No new compose/env/key input is required.

### 9.2 Tests with a killable mutation for each invariant/decision

Every test name below is NEW, not an assertion that a filter exists today. Tests
run the real account DB and real node inbox/store unless a network barrier is
specifically the subject. Discover positive test counts with --list before runs.
Each listed mutation is applied alone, all competing recovery timers are held,
and the actual failing assertion is recorded before reverting it. The table is
a minimum acceptance set; functionality without its stated oracle is incomplete.

| Owner / test | Oracle | Single mutation that must fail |
| --- | --- | --- |
| S6a page_sparse_coverage_and_caps | limit0 refuses, limit10000 clamps256, 10^15 absent span plus sparse live rows <=512 visits, nonoverlap coverage and checked counts | Enumerate numeric sequences; visit watchdog/budget fails even though bytes stay small |
| S6a page_exact_serialized_boundary | Actual whole frame<=B immediately below/at/above B, including escaped metadata and known reasons; either progress or first marker | Decide oversize from raw entry bytes; one boundary produces empty more=true or oversized frame |
| S6a entry_admission_all_origins | Gateway, fan-out, federation, migration and native custody normalize then measure Entry and both Deliver shapes; exact cap succeeds, +1 refuses without append | Omit post-authority bound on one origin; its oversized row appears |
| S6a fetch_all_terminal_races | Entry/TooLarge/Gone after expiry, sweep and router restart; supplied deadline is original; no loop | Return TooLarge for vanished row; reason/intent/deadline oracle fails |
| S6a ack_batch_reopen_equivalence | Compare twin sequential/batch routers after reopen in both modes: pending, receipts, dead letters, indexes, cursor; one store txn | Retain only last ACK's retired list; reopened pending differs |
| S6a ack_batch_atomic_failure | Fault commit and crash after commit before publication; no successful reply on failure, reload consistent | Publish candidate in memory before failed commit and continue serving; state-vs-reopen comparison fails |
| S6a durable_view_publication | Allocate s/s+1 on each section 3.2 allocator, hold s write, complete s+1; s+1 submit/fan-out/forward/custody success reply AND actual gateway push stay held; HTTP/custody Inbox, FetchEntry and probe expose no s+1; release s then progress in both modes | Reply on own-write durability; actual gateway capture sees s+1 before barrier release. Independently publish at allocation or bypass custody read watermark; respective snapshot fails |
| S6a guard_drop_tombstone | Early return, cancellation, panic inside write, and allocated should_persist=false branch each persist aborted without process death; s+1 reply/push progress, reopen retains typed aborted in both modes; accepted-vs-drop race has exactly one winner; oldest live guard>30s emits WARN/metric | Omit Drop tombstone; P/reply watchdog stalls. Separately allow late accepted record to replace aborted or omit WARN; terminal-state/metric assertion fails |
| S6a guard_tombstone_storage_fault | Inject tombstone commit failure: affected target quarantines with transient error, P stays fixed, no success; recover store and resolve reservation before admitting traffic; unrelated target continues | Remove reservation without durable disposition; page crosses unresolved s or recovery aliases it |
| S6a out_of_order_process_crash | Complete s+1 while s uncommitted, no replies beyond P, kill process without Drop, restart with durable s+1/high counter; missing s emits unavailable/unknown once, never expired or aborted, sender retry remains safe | Fabricate expired or aborted for absent never-accepted s; exact gap-reason assertion fails |
| S6a wal_identity_and_restore_rotation | Explicit snapshot recovery rotates E before traffic in both modes; independently delete/recreate WAL directory, change identity and remove required segment/anchor; first request observes new E, old intent cannot ACK reused seq; ordinary complete restart retains E | Skip recovery rotation or accept empty/mismatched WAL under old E; new-E assertion fails even if cursor_ahead freeze otherwise prevents delivery |
| S6a/b delayed_old_incarnation_ack | Send real old-E ack_batch and hold at router ingress, rotate E/reuse s with new content, release raw batch directly without client filtering; router rejects whole batch and new row remains pending | Remove router E comparison; stale in-flight batch deletes unseen new-E row |
| S6b same_incarnation_regression | Same E issued<C freezes receive/settlement with cursor_ahead and diagnostic; advance traffic past C, freeze remains until explicit recovery | Wait for issued to overtake C and resume; wire/SQL hook sees forbidden ACK or C write |
| S6b retired_incarnation_fence | Fill 64 retired E values, attempt 65th transition: pause with recovery diagnostic, no fence forgotten, no new C/ACK or reset write | Evict oldest E or grow set; bound/state assertions fail |
| S6a retention_mode_oracles | WAL pre-sweep unknown, redb pre-sweep expired, post-sweep/prune unknown permitted; issued retained through second reopen | Remove observe_issued_seq restoration loop; expired-only WAL target loses issued coverage. Separately skip expired redb row restore; pre-sweep expired reason fails |
| S6a sender_isolation | Hold recipient at sink-write-entered, issue second submit on SAME sender after first reply; it completes before release | Await recipient write on sender task; second reply misses barrier watchdog |
| S6a queue_half_drain_and_inflight | 16 admitted incl held in-flight, 4 overflows -> min after16; no Resync above8; fresh overflow during its write survives; latch guarantees eventual hint under arrivals | Exclude in-flight occupancy; admitted count differs |
| S6a resync_threshold | Resync appears only <=half frames AND bytes, with continuous traffic latch test | Give unconditional Resync priority; frame captured above threshold |
| S6a stalled_writer | Queued returns immediately, only that token closes at15s, replacement unaffected | Keep2s sender timeout; liveness/deadline assertion fails |
| S6a population_probe | 1,025/5,000/40,960 tokens, all batches visited once, <=4 concurrent, missing/timeouts reset confirmations, no overlapping rounds | Probe first1,024 only; untouched token lacks hint |
| S6a probe_hole_below_high_push | Router-origin s1 plus pushed s2 cannot hide s1; only second successful observation hints | Use max pushed seq as coverage; hint missing |
| S6a mesh_compat_overflow | Old boolean decoder sees durable overflow true, no wake; new outcome agrees | delivered=(outcome==queued); wake recorder nonempty |
| S6a sender_recipient_matrix | Sender x recipient old/new, local/mesh; old forwarder to capable recipient discards deficient frame, schedules Resync, no wake; actual target and capable self-target separate reply+push without probe | Keep self-target suppression; recipient frame missing. Separately enqueue deficient old-forwarder frame with invented E/deadline; wire capture finds forbidden Deliver |
| S6a async_ack_nack_and_input_caps | Held router call on current-thread runtime does not block other heartbeat; bad/65/empty batch refused before router call | Use blocking router helper; independent heartbeat misses watchdog |
| S6b staging_survives_router_expiry | Crash at EVERY W1 commit then advance beyond router retention, restart both modes, no false loss and one effect | Omit W0 or delete it after first W1 subcommit; receipt reconciliation cannot recover |
| S6b atomic_cover_crash_sweep | Interleaved loss1/live2, gap-only page, trailing gap, capacity pause; all-or-none loss/outbox/intent/C at every commit cut | Split cursor then intent; k between commits exposes partial W2 |
| S6b loss_before_cursor_crash | Same sweep; exactly one journal source key per expected gap | Commit loss/outbox before C separately; intermediate on-disk invariant fails (even if later dedup masks an event) |
| S6b loss_after_cursor_crash | Gap survives restart before any later writes | Commit C before loss/outbox; gap missing at cut |
| S6b held_below_cursor_settles | Hold1, advance through later entries, router dead-letters1, local retry succeeds; retained input survives, C unchanged, one eventual intent | Run completed cleanup in held W2; work/retry missing |
| S6b retry_settlement_atomic | Crash before/after every below-C WS subcommit, eventual intent or surviving work; no C regression | Delete retry then commit intent separately; cut leaves neither |
| S6b ack_lost_before_and_after_commit | Real router inbox empties after retry; intents survive death before flush and lost reply after WR | Delete intent on uncertain send; pending row remains |
| S6b never_ack_above_c | At write hook every ACK seq<=durable C with terminal accounting; held never selected | Send before W2; hook finds seq>C |
| S6b receipt_reconciles_absent_range | W1 completed, crash before W2, router expires; mixed staged/held/erased receipts subtracted by indexed range merge | Infer every missing page seq as loss; false gap count |
| S6b compat_intent_transition | push lost ACK -> compat proof lookup -> push; proofless intents suspend, same-E settles, new-E resets; crash after legacy ACK before WA retains original equality-proof work and C fixed within E; populate terminal compat rows then U->E, kill around reset, reopen has zero orphan work/receipts/reserved slots; held work retained; reset C=S | Authorize legacy ACK by sequence alone; unseen reused content ACKed. Separately retain terminal compat work after dropping intents; reopened orphan/quota assertion fails |
| S6b legacy_prior_crash_classification | Old ACK-before-C crash then first capable epoch emits legacy_unverified, never definite content loss | Omit epoch fence; classified unavailable count is wrong |
| S6b push_without_polling | Initial catch-up then idle DM commits with Deliver and no Resume in measured interval | Retain old5s schedule; exact idle Resume count fails |
| S6b reorder_and_gap | C+2 then C+1 at200ms -> ordered apply, no pull; missing sibling -> one pull at500ms | Apply arrival order; ordered projection assertion fails |
| S6b gap_timer | No Resume before500ms, exactly one then | Wait5s; 500ms capture empty |
| S6b connected_and_sweep | One initial Resume within100ms; none until900s; probe/gap/retry held beyond experiment | Remove Connected trigger; 100ms frame count0 |
| S6b sweep_setting | Default900s; pure parser clamp60..3600; deprecated variables one warning/no effect | Default60s; premature Resume |
| S6b ack_batch_timing | 16 eligible->one batch;3->one at1s; every seq passed W2 | ACK each entry; batch count differs |
| S6b coalesced_resync | Resync+Lagged+sweep during held run -> exactly one follow-up; buffer256/8MiB | Spawn catch-up per hint; concurrent/follow-up count differs |
| S6b lifecycle_fence | Held page/result, lock<1s, release old generation -> no DB write or ACK; unlock recovers disk | Drop generation check; stale row/write appears |
| S6b keepalive_all_reads | Reply/push/heartbeat update activity even without subscribers; missing reply retires at35s idle scenario | Derive activity from push-only subscription; ping sent after recent reply |
| S6b ledger_privacy_restore | Exact metadata columns, delete/replay fence removes all work+aliases, erased receipt survives; decrypted backup/import contains no ledger or stale C; account erase DB/WAL | Omit work footprint registration; forbidden wire ID/payload found after reopen |
| S6b old_writer_refusal | Migrated DB opened by previous writer returns AccountSchemaTooNew with unchanged contents | Weaken writer-version guard; old writer opens or changes DB |
| S6b capacity_and_range_work | Reserve before W1; full intents or64MiB staging pauses, local retries still run; huge hole uses intervals | Reserve after W1; processing hook fires despite unavailable capacity |
| S6c ephemeral_persistence_absence | Generic before/after every redb table, WAL length, spool, notify queue, client DB/journal; no changes for live/offline/full/expired | Send ephemeral down durable route; persistent artifact found |
| S6c ephemeral_deadline | Stale signed input under fresh request refused before router I/O, D exact on every hop, now==D expires | Recompute D from receipt time; delayed/replayed envelope accepted |
| S6c ephemeral_restart_window | Router-only restart receiver dedups; combined/repeated restarts duplicate only beforeD, never durable; no marker afterD | Keep marker pastD; live-marker inspection fails |
| S6c ephemeral_admission_result | 40 same paused-instant submits,41st rate-limited,50ms refill1; invalid ttl0/6 refuses before routing; accepted then expired gets no second reply | Validate after route; router recorder sees invalid input |
| S6c final_registration_capability | Replace capable token with legacy between route/enqueue -> dropped recipient_unsupported | Check capability only at routing; accepted with no capable queue |
| S6a/b inbox_incarnation_reset | Both modes start old C=100 then restore lower counter/new E with settled1..30/live31..50; first page S=30: zero prefix gap events, one reset and all live rows delivered below old C; same U->E case. WJ publishes pending old loss once before reset. Redeliver completed content above S and new content reusing old seq: one effect per application marker. Same-E expiry crossing settled cursor still yields a gap | Reset C/fence to0 produces false prefix gaps; keep old C loses live31..50. Separately drop pending old outbox, dedup by (E,s), or overwrite C with S on ordinary pages; corresponding journal/projection/gap oracle fails |
| S6a/b invalid_seq_terminal | invalid_seq deletes named intent once, emits diagnostic and revalidates E; later reused seq never receives an old retry | Classify invalid_seq as transient; capture a later unsafe ACK retry |
| S6b all_receive_writers_guard | All section 7.1 APIs incl conversation message.receive and message.ack/rf dm ack with gap/hold; SQL, inbox-request, outgoing ACK and hold-delete hooks enforce W2/WS/WA/reset/erasure; held never ACKed, managed public ACK typed refusal | Leave message.rs direct ACK; wire hook detects ACK outside WA or s>C. Separately leave group raw remove_unrouted; delete hook detects missing transaction authority |
| S6b hold_source_class_quotas | Submit >64 unrouted entries from one verified source and many-source burst, exercise 256/16MiB aggregate and 4MiB source bound, then routable DM; DM arrives, oldest holds have typed held_evicted+intent, no orphan rows | Keep legacy 1,024 shared hold budget or delete oldest unrouted row without W-path; starvation/orphan/event assertion fails |
| S6b held_local_expiry_and_eviction_crash | Force quarantine purge/64-cap eviction, expire_inbox_holds, dead_letter_inbox and contact expiry; kill before/after terminal transaction; exactly one failure event+intent or full old work/receipt, C unchanged below C | Execute quarantine.rs raw DELETE first; reopen finds held receipt without work or missing event/intent |
| S6b receive_stage_redrive | Kill before/after EVERY concrete W1 commit in section 3.1; one crypto/application effect, required projection event and immutable reply outbox survive even when router row is gone | Keep seen-marker early Completed; crash after crypto before projection/reply admission loses required stage |
| S6b projection_write_failure | Fail projection claim and outbox writes; held work remains, no terminal ACK, retry creates one event | Swallow project_committed_message write error; Completed/ACK appears without projection |
| S6b reply_outbox_crash | Crash after preparing surface answer and pair-reset reply, before/after outbox transfer and after network write before receipt; same prepared envelope eventually acknowledged, one application reply | Remove response state before durable courier admission; crash loses reply |
| S6b buffered_push_survives_router_retirement | Stage push C+2, retire router row before fetching gap; local receipt reconciles missing page interval, C+2 processed once with zero loss for it | Keep out-of-order copy only in RAM; page marks locally available content lost |
| S6b legacy_deadline_clock_skew | At client lag120s fallback is no earlier than router acceptance cap; lag>120s marks fallback_clock_unverified and never claims guaranteed retirement | Remove +120 or suppress assumption/status; boundary deadline or diagnostic assertion fails |
| S6b staged_content_conflict | Conflicting same (T,E,s) on repeated reconnects preserves first authenticated work, one bounded diagnostic, no repeated retirement, original completes | Retire session on every mismatch or overwrite first work; progress/content authority assertion fails |
| S6b erasure_late_stage_and_process | Erase while W0 or W1 result is held before commit; release late work, reopen, no content/alias resurrection and only erased receipt settlement | Remove late W0 fence, then independently remove late W1 fence; forbidden registered/unregistered copy remains |
| S6b loss_storage_backpressure | Fill 2,048 ranges and separately 1MiB unpublished-loss budget; next W2 pauses with C/work/outbox unchanged; projection/pruning then permits one atomic retry | Remove range cap, then separately byte cap; forbidden commit occurs. Split pause from C commit; immediate durable state fails |
| S6b compat_frame_limit_fallback | 64-entry legacy reply exceeds F, fresh-session retry limit1 succeeds; oversized single entry pauses with status and fixed C, no reconnect loop | Retain limit64 after frame failure; session repeatedly fails or good entry never arrives |
| S6b stale_page_suffix_progress | Pushes advance C while page is in flight, after<=C<covered; useful suffix applies with loss reconciliation and no duplicate effect, repeated races do not starve | Reject entire stale-C page; page suffix never commits under continuous pushes |
| S6c s0_r4_lifetime_bridge | ttl_seconds aliases Envelope.ttl; ttl0/6 invalid, ttl1/5 valid; receiver own-clock ahead>2s drops immediately, exact2s bounded hold, backward wall clock never extends monotonic2s hold, overflow drops; display inside signed interval <=5s, no renewal; signed bridge and reset rejection | Omit receiver own-clock check; skewed input retained. Separately use wall-clock-only hold deadline, renew duplicate display or retain bridge parser at reset; corresponding oracle fails |
| S6d push01 wire capture | Actual Deliver to B and zero Resume between send and event, after initial catch-up; sweep3600s | Re-enable receive poll; capture finds Resume with competing paths held |

Crash sweep hooks count real commits W0/W1*/W2/WS/WA/WJ/WR/RA/RE/RC and WAL
identity/rotation writes, rerun once per
cut k, kill immediately after k, and reopen DB/router files. For each split
mutation there MUST be a k between the two writes and an immediate durable-state
assertion; merely placing a fault before W2 is insufficient. Include loss ranges
before/after live entries and gap-only pages, W0 capacity pause and erasure cuts.
Mutations are serial, reverted individually, with no competing safety/probe/retry
path allowed to rescue the failing oracle. Timing liveness tests use named release
barriers; paused time tests isolate the timer under test; cross-thread watchdogs
use wall time and a 30 s outer budget. Busy-core reruns cover sender isolation,
push latency, reorder and overflow; report measured samples rather than a
blanket latency guarantee.

### 9.3 Affected realnet selectors

Membership and selectors below were read at itest
`e5e4d4a8fbcb461a1df56543c5489f94c7871322`, `realnet.yml` and corresponding test
sources. Existing hosted matrix does NOT include contact02 or s50. push01 is new,
so S6d must add it; no execution is claimed by this table.

| Slice | Exact selector (prefix tests::) | Current membership / environment |
| --- | --- | --- |
| push01 | push01_session_push::push01_realnet_dm_arrives_by_push_without_polling | new; add hosted matrix; daemon safety sweep3600s |
| push01 | push01_session_push::push01_realnet_offline_then_reconnect_delivers_once | new; stop B, send3, restart, one copy each<15s |
| push01 | push01_session_push::push01_realnet_ephemeral_is_never_stored | new; capable raw sessions, live accepted/offline dropped, restart Resume empty and issued unchanged |
| id02 | id02_custody::id02_born_v3_realnet_register_session_and_dm | hosted |
| contact02 | contact02_contact_requests::contact02_realnet_request_then_first_message | QA-only; source exists, no hosted matrix entry |
| s74 | mvp_s74_event_stream::mvp_s74_realnet_autonomous_sync_replay_and_daemon_restart | hosted |
| s39a | mvp_s39_gateway_resume::mvp_s39_realnet_gateway_session_resume_token_rejoin | hosted |
| s51 | mvp_s51_home_node_migration_forward::mvp_s51_realnet_home_node_migration_forwards_within_window | hosted; router-origin delivery probe |
| s35 | mvp_s35_multi_device::mvp_s35_realnet_multi_device_activation_fanout | hosted |
| call01 | call01_voice::call01_realnet_voice_round_trip | hosted; RAMFLUX_ITEST_VOICE=1 |
| s50 | mvp_s50_cross_gateway::mvp_s50_realnet_cross_gateway_forward_deliver | QA-only; RAMFLUX_CROSS_GATEWAY=1 |

All use realnet feature, RAMFLUX_ITEST_REALNET=1 and exact selectors with
--nocapture --test-threads=1. Current hosted defaults also set RAMFLUX_OBJECT_V3=1
and RAMFLUX_CROSS_GATEWAY=1; preserve the appropriate overlay when running these
selectors outside CI. Voice requires its voice overlay/env; a printed skip or
zero matched test is failure, not green. QA acceptance uses images/binaries built
from the product pin under test, never a previously deployed node as proof.

### 9.4 Gate and publication rules for the implementation cards

The current deliverable is documentation only; Cargo is not a design gate.
Implementation cards must copy the then-current CI commands and freeze a single
gate policy in each card. Required product fast gates: license/identity checks,
cargo fmt --check --all, clippy workspace/all-targets with AND without all-features
and -D warnings, gateway itest-local-mint clippy, cargo machete, file-size check,
positive-count targeted tests and the mutations above. Full SDK/gateway/workspace
suites belong to product CI under the controller's CI-first dispatch policy;
focused reruns do not clear a red full suite. An unchanged base-reproduced failure
remains explicitly red with both logs and the card's permitted handoff exception.

Every Cargo command uses the assigned macOS cargo slot plus outer alarm. Exit75
permits the same Cargo command through the cargo-only QA wrapper; it does not
authorize containers/deployment/realnet. Only controller test agents execute QA
slices and deployment. One serial mutation target<=80GiB, clean only owned
mutation artifacts after evidence is saved; no test timeout/assertion weakening.

For any card owning itest: PRODUCT_HEAD -> controller publication of exact product
SHA -> PRODUCT_PUBLISHED -> pin-only itest commit. Verify both product remote
and public Git URL, metadata --locked --all-features root dependency resolution,
own-pinned TUI provenance and all transitive product revisions. No path/patch
source substitute. Then itest fmt, all-target/all-feature and realnet clippy with
-D warnings, build --all-features and non-realnet tests. Compile unchanged desktop
against the published product in a scratch checkout, rev swap only. Internal
branch publication remains a controller action, never a lane push.

Before S6d READY: ITEST_HEAD -> controller publication -> ITEST_PUBLISHED ->
execute all three exact push01 selectors -> record PUSH01_QA result at BOTH SHAs.
Only green execution clears the new-slice gate. A source/pin change invalidates
it. If that checkpoint cannot complete, report pending/BLOCKED per the new card,
never infer success. Controller then runs full hosted matrix and the affected QA
selectors serially, reviews the delivered SHA, merges product then matching pin,
and runs post-merge CI. Node rollback prohibits opening an S6 store with a
pre-S6 writer and requires the explicit restore rotation procedure; new SDK compat settlement obeys the proof restriction
in section 4.3. Client rollback is
forward-only schema refusal, distinct from node rollback. No stale claim about
new CursorAckState gap fields survives: S6 adds none.

## 10. Audit finding closure map

Identifiers are requirements, not an assertion that executable verification has
already passed. Every original finding has a normative answer and a test/card
owner in section9; review must validate the implementation separately.

| Finding | Design answer |
| --- | --- |
| r0-H1 volatile ACKs below cursor | I3; sections2.3 WA/W2,3.1,4.3; persistent sequence intents and uncertain-send recovery |
| r0-H2 expiry hidden before sweep | sections1.1,2.4,3.2,5.1; locked fetch-derived reason plus local reconciliation, no dependence on sweep timing |
| r0-H3 unsafe page authority | I5; sections4.1,5; exclusive coverage and independent push stream |
| r0-H4 renewed transient lifetime | sections8.2,4.2; signed exclusive deadline, repeated-restart exposure stated |
| r0-M1 absent S2 ACK/read interfaces | sections1.2,7; S6b owns explicit actor inputs and host read clock |
| r0-M2 probe beyond1,024 | section6.2; paged whole-population rounds, population-dependent cost/latency |
| r0-M3 contradictory half-drain priority | section6.1; conditional priority, in-flight counts, overflow latch and detached slot |
| r0-M4 nonisolating mutations | section9.2 same-sender second request, Connected capture, competing timers held, real wire capture |
| r0-M5 accepted then later drop reply | sections6.1,8.1; one result at enqueue, later expiry silent; paused burst/refill tests |
| r0-M6 recipient/self-target missing | sections4.1,4.3,6.3,9.2; separate frames and actual local/mesh recipient matrix |
| r0-M7 nonexistent existing test filter | section9.2 new-test labeling; --list positive counts, dependency tests re-listed on merged S2 |
| r0-M8 unpublished itest QA fallback | section9.4 exact product and itest publication checkpoints before push01 acceptance |
| r0-M9 conflicting gates/targets | section9.4 one implementation-card policy, cargo-only fallback, one serial mutation target |
| r0-L1 realnet membership/upgrade reference | sections9.3 and2.2; contact02/s50 QA-only, migration test named directly |
| r0-L2 stale authenticated IP cap | No server authenticated-session-cap claim; section9.4 acceptance/publishing rule; controller scheduling limits are not capacity guarantees |
| r1-H1 cursor passes loss event | sections2.3 W2,3.1,9.2; preceding loss+outbox+intent+C one commit, gap-only and interleaved cuts |
| r1-H2 WAL forgets expired row | sections1.1,2.4,3.2; unknown reason permitted, durable issued coverage and W0 recovery |
| r1-M1 first-item byte proof invalid | sections5.1-5.2; measured complete one-item page, measured largest Entry/Deliver at admission |
| r1-M2 ACK privacy and lifecycle | section2.2; sequence-only intents, exact allowlists, backup/merge erase; added staged content explicitly registered |
| r1-M3 client downgrade changed | sections2.2,9.4; AccountSchemaTooNew forward-only guard, unchanged-file oracle |
| r1-M4 S0 replay horizon mismatch | sections1.2,8.2; markers end at signed D, S0 approval satisfied at 61d96751, no grace |
| r1-M5 mesh overflow wakes device | section6.3; durable overflow true for old/new decoders, no offline wake |
| r1-M6 crash fault not between split writes | sections3,9.2; enumerate every real commit and immediate durable-state oracle between split writes |
| r2-H1 held cleanup / no below-C settlement | I4; section2.3 outcome-specific W2 and WS, local hold lifecycle and crash tests |
| r2-M1 absent router row may exist locally | I2/I5; W0 precedes effects, keyed receipts reconcile all absent ranges even after router expiry/capacity pause |
| r2-M2 push intents stranded in compat | section4.3 proof-checked exact legacy lookup, no C movement, same ledger both modes; proofless inherited intents suspend until E validation/expiry; section2.4 pre-ledger uncertainty |
| r2-M3 point-fetch disappearance / missing TTL | sections4.1,5.2 EntryGone and explicit TooLarge retain_until; complete host reply set section7 |
| r2-M4 empty page at byte boundary | section5.1 full serialized one-item measurement, zero-limit refusal and progress predicate |
| r2-M5 unbounded sequence walk | section5.1 sparse ordered index and512 actual visits; section2.3 interval subtraction/counts |
| r2-M6 redb/WAL restart oracle conflated | section3.2 and retention_mode_oracles: WAL unknown, redb pre-sweep expired; common exactly-once local accounting |
| r2-L1 operative affected slices removed | section9.3 all nine named slices with exact selectors and environment/membership |

### 10.1 Design r1 review closure (round r2)

All 14 design-review findings have the following normative closures. The earlier
31 implementation-card audit IDs above remain separate and are preserved.

| Finding | Design answer and implementation oracle |
| --- | --- |
| design-r1-H1 publication ordering | Section 3.2 per-inbox in-flight set and contiguous durable prefix; durable_view_publication with two concurrent writes and actual push/page/probe capture |
| design-r1-M1 other cursor writers/pullers | Section 7.1 complete inventory and W2/WS/read-only dispositions; S6b scope section 9.1; all_receive_writers_guard |
| design-r1-M2 hold starvation/removal | Section 2.6 source/class/aggregate quotas, reserved routable capacity and terminal W-path; hold_source_class_quotas and held_local_expiry_and_eviction_crash |
| design-r1-M3 router regression | Sections 2.5/4 incarnation persistence, wire fences, atomic reset and terminal invalid_seq; inbox_incarnation_reset, invalid_seq_terminal, compat_intent_transition |
| design-r1-M4 real W1 commits | Section 3.1 concrete stages, markers, external network calls, durable replies and propagated projection failure; receive_stage_redrive, projection_write_failure, reply_outbox_crash |
| design-r1-L1 buffered copy loss | Section 7 stages out-of-order pushes before buffering; buffered_push_survives_router_retirement |
| design-r1-L2 old mesh forwarder | Section 6.3 deficient push copy discarded with Resync and sender_recipient_matrix old-forwarder cell |
| design-r1-L3 fallback clock skew | Section 2.3 fallback adds 120s and states its clock assumption/residual; no unconditional upper-bound claim |
| design-r1-L4 repeated content mismatch | Section 2.3 first-copy authority and bounded diagnostic without reconnect livelock; staged_content_conflict |
| design-r1-L5 weak/missing mutations | Section 9.2 retention mutation edits product restore loop, late W0/W1 erase-fence mutations, independent range/byte budget mutations |
| design-r1-L6 S0 approval completeness | Sections 1.2/8.2 pin approved r4 61d96751, verbatim clock/display wording and three explicit L6 dependencies; s0_r4_lifetime_bridge |
| design-r1-L7 compat frame failure | Section 4.3 sticky limit1 fresh-session fallback and single-entry pause/status; compat_frame_limit_fallback |
| design-r1-L8 stale-C page | Section 7 validates E/generation then applies suffix above current C; stale_page_suffix_progress |
| design-r1-L9 S2 provenance | Section 1.2 marks snapshots uncommitted, SHA-256 identity only, provisional recheck on merged S2; no file:line attributed to 08c056a5 |

### 10.2 Design r2 review closure (round r3)

These are design closures; all tests remain future implementation requirements.

| Finding | Design answer and implementation oracle |
| --- | --- |
| design-r2-N-M1 reply enforcement / custody | Sections 3.2/5.2/9.1 enumerate allocators/readers, gate every assigned response on P; durable_view_publication captures actual gateway push and native custody Inbox |
| design-r2-N-M2 abandoned assignment | Section 3.2 owned guard, durable aborted tombstone without process abort, single terminal winner and watchdog; guard_drop_tombstone, guard_tombstone_storage_fault |
| design-r2-N-M3 ACK/removal inventory | Section 7.1 adds message.receive/message.ack/group raw cleanup and public ACK helpers; W2/WS/WA authority and managed refusal; all_receive_writers_guard |
| design-r2-N-M4 settled prefix | Sections 2.5/4.1/5.1 import first-page S into C/activation/fence for restore and U->E, no settled-prefix loss; inbox_incarnation_reset |
| design-r2-L1 pending loss publication | Section 2.5 WJ barrier before reset; retain pending events on projection failure; inbox_incarnation_reset |
| design-r2-L2 terminal compat release | Section 2.5 reset atomically releases terminal compat work/receipts/quotas; compat_intent_transition reopen oracle |
| design-r2-L3 effective E/dedup tests | delayed_old_incarnation_ack bypasses client masking; inbox_incarnation_reset redelivers completed content and rejects (E,s) dedup |
| design-r2-L4 missing mutations | wal_identity_and_restore_rotation, same_incarnation_regression, retired_incarnation_fence and independent old-forwarder sender_recipient_matrix mutation |
| design-r2-L5 crash hole | Sections 3.2/11 residual and out_of_order_process_crash pin unknown, never expired/aborted |
| design-r2-L6 S0 r4 delta | Sections 1.2/8.2 pin approved 61d96751 verbatim; S6c S0 dependency satisfied; s0_r4_lifetime_bridge receiver-clock and monotonic-hold cases |
| design-r2-L7 table columns | Section 9.2 ACK timing and ephemeral admission rows each have three correctly separated cells |
| design-r2-L8 WAL counter continuity | Section 2.5 redb WAL identity/checkpoint anchor and segment chain; rotate before traffic on mismatch; wal_identity_and_restore_rotation |

## 11. Residuals and owner questions

Technical choices are made above; no owner technical question remains. S0 r4's
complete Decision 6 is approved at 61d96751 and satisfies S6c's S0 dependency.
The merged S2/S3 interface recheck remains a dispatch prerequisite, not a product
question or blocker to reviewing this design.

A process crash bypassing Drop can leave a permanent hole s below a durable
s+1 assignment recovered from disk, even though no s+1 success reply/push was
published before the crash. The abandoned s may never have been accepted and
its sender can retry at a new sequence; without a durable tombstone the client
reports this missing delivery evidence as unavailable/unknown, never expired or
aborted. This is a possible spurious logical-message gap, not proof of lost
accepted content. out_of_order_process_crash pins this residual in both modes.

Reset imports the router's settled prefix as historical/unverified; because it
also includes lifecycle retirement, reset cannot recover exact old loss counts
from that prefix. The reset diagnostic carries the uncertainty, while ordinary
same-E coverage continues to report missing sequences from C.

Residual product behavior is explicit: an unrecoverable inbox gap cannot retrieve
history from an E2EE router; a user must obtain another device/sender copy through
future product flows. Legacy pre-ledger uncertainty is labeled, not counted as
proven content loss. Persisted holds have isolated sub-budgets and explicit terminal eviction;
network/disk/journal exhaustion can still pause admission. A proofless old-node
connection suspends inherited sequence-only ACK intents; wholly undetectable
legacy counter rollback cannot receive the capable incarnation guarantee. Legacy oversized
entries may delay compatibility settlement until expiry/upgrade. Volatile
transient restarts permit duplicates only within the signed lifetime, and clock
skew can drop typing. None of these silently converts transient input to durable
history. Journal replay can repeat delivery of the same event sequence to a
subscriber; uniqueness refers to accounting and journal identity.

Owner questions: none. The existing product choices (companion-only watch,
seven-day attachment retention/default quota and previews disabled by default)
require no new S6 decision. Retry/recovery UI and sender-assisted repair remain
product work outside this transport design; this document does not invent their
inner message schema or claim they exist.
