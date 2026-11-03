# Session push v1

Design revision 1. Proposal for review; no implementation or runtime acceptance is
claimed. All decisions below supersede the earlier S6 implementation-card recipes.
The implementation must be dispatched from approved dependency SHAs, not from this
proposal's source baseline.

## 1. Source facts and decision basis

### 1.1 Reproducible baseline

Product base: `081c88117d78b542b321d513a2984d1b032d4869`, fetched `origin/main`.
All product file:line citations in this section refer to that immutable object.
Line intervals describe a source region; they are not links to mutable main.

| Fact | Source at the base |
| --- | --- |
| The gateway already pushes a committed durable entry, using the same Deliver as the submit reply; self-target push is suppressed | `apps/ramflux-gateway/src/session.rs:1224-1351` |
| Own-device fan-out pushes separately; a local miss forwards through the gateway mesh and can wake an offline device | `apps/ramflux-gateway/src/session.rs:1444-1468`, `:1570-1651` |
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

### 1.2 Provisional dependencies

S2 branch `fix/s2-account-runtime-background` has committed head
`08c056a5adbfc4a55363da74dd90868c8eba1117` plus uncommitted work. Its observed
`bus/connection_manager/account_work.rs:18-22` has ReceiveApply returning bool;
`receive.rs:20-106` still schedules pulls; `mod.rs:129-164` has SessionContext
without last_read_at. These are SDK-relative paths in that provisional tree,
not facts at the product base and not merged evidence. S6 owns adapting these
interfaces after S2 merges. S2 remains sole owner of the stream, cancellation-safe
reader, call queue, generation, connection retry, lifecycle cancellation and
courier/transfer task framework.

S0 input is `design/s0-msg-schema` at
`e505565eb2e5c573ec10210125056b307b2143aa`,
`docs/design/message_schema_v1.md:283-311` and `:4048-4074`. It is under review.
Its transient transport and endpoint Unsupported retention are distinct: S6 has
no transient DB write; S10a may implement S0's authenticated unknown-content
endpoint policy. S0 must approve the lifetime clarification in section 8 before
S6c implementation dispatch. Do not treat either dependency as accepted here.

### 1.3 International practice and the local choice

[Telegram update recovery](https://core.telegram.org/api/updates#recovering-gaps)
uses local sequence state, a short reorder wait, and explicit difference fetches.
We adopt the 500 ms gap wait and 15-minute safety trigger, with inbox coverage
instead of server message history. [MTProto acknowledgements](https://core.telegram.org/mtproto/service_messages_about_messages#acknowledgment-of-receipt)
batch identifiers; our device-scoped sequences replace message identifiers.
These are architectural precedents, not evidence for the crash guarantees below.

[SQLite atomic commit](https://www.sqlite.org/atomiccommit.html) provides a
single-transaction all-or-none boundary. We use that boundary for cursor,
settlement intent and loss publication. Processing currently has several commits,
so this proposal adds durable input staging before processing. It does not assume
that placing a later receipt beside the cursor makes earlier processing atomic.

## 2. Receive invariants, owners and durable state

### 2.1 Definitions and invariants

T is the authenticated device's target_delivery_id; s is a positive u64 inbox
sequence; C is that target's durable receive coverage cursor. C is not a cumulative
router ACK. The account actor is the sole SQLite writer. Every write below checks
current account/network generation and erasure state before committing; tasks
pass immutable inputs to the actor and never hold a DB handle across network I/O.

- **I1 Coverage:** for every newly covered sequence since ledger activation,
  exactly one local disposition exists: completed, durably held, explicitly
  rejected/erased, or unavailable with a committed gap event. C never regresses.
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
  effects rather than deleting recovery evidence.
- **I8 Protocol isolation:** negotiation controls new frames in both directions;
  sender replies are never interpreted as recipient entries in push mode.
- **I9 Transience:** accepted ephemeral means queued, with one immutable signed
  deadline; it never means durable delivery or application acceptance.

### 2.2 Account DB schema and lifecycle

The following are exact column allowlists, not permission to add opaque JSON to
metadata tables. Sequences use fixed-width big-endian 8-byte BLOBs in SQLite
(indexable unsigned order); timestamps use signed Unix seconds unless suffixed
_ms. Range counts and checked u64 arithmetic are encoded without SQLite signed
integer overflow. Existing string checkpoint C is updated by compare-and-set in
the same transaction as these tables; no second authoritative C is introduced.

| Table / state | Columns and key | Owner and lifetime |
| --- | --- | --- |
| gateway_receive_receipt | target_delivery_id, inbox_seq, disposition, retain_until, first_seen; PK(T,s) | Actor W0 creates staged; W1 may set held/quarantined; erasure sets erased. W2 removes terminal receipts after covering them and creating intent; held receipts remain below C until WS. No message ID, sender or digest |
| gateway_receive_work | target_delivery_id, inbox_seq, entry_json, admission_key, byte_len; PK(T,s), FK to receipt | Actor W0 creates a recoverable encrypted input. This IS a message-linked copy. W2/WS removes only after terminal disposition; held processing keeps it. Indexed footprint, bindings and erase fence are mandatory |
| gateway_ack_intent | target_delivery_id, inbox_seq, created_at, attempts, next_attempt_at, expires_at; PK(T,s), due index(T,next_attempt_at,inbox_seq) | W2/WS creates; WA retries or deletes after a terminal router result/verified legacy absence/deadline. Lock preserves it |
| gateway_inbox_loss | target_delivery_id, from_seq, to_seq, count, reason, recorded_at, classification; PK(T,from_seq,to_seq) | W2 creates nonoverlapping ranges plus outbox. Keep at most 1,024 projected ranges per target, prune oldest only after journal projection; counters survive pruning |
| gateway_receive_epoch | target_delivery_id, activated_cursor, legacy_uncertain_through; PK(T) | Migration/first capable coverage initializes the pre-ledger uncertainty boundary once; no later mode transition resets it |
| projection_checkpoint | existing receive checkpoint | W2 alone moves C; WS/WA never move it |
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
newer. Router rollback has no new on-disk format to interpret.

Loss storage has a hard total cap of 2,048 ranges per T, including unpublished
ranges. If a W2 would exceed it after pruning eligible projected ranges, pause
before that W2 and let journal projection drain; never prune an unpublished
event or split its cursor transaction. Its metadata-only outbox records fit a
bounded 1 MiB pending-loss budget as a second limit. Duplicate staging of an
existing receipt consumes no second slot; receipt+reserved-intent capacity is
tracked transactionally, including erasure/WS release.

### 2.3 Ordered receive and below-cursor settlement

**W0 Stage:** before processing an entry, reserve both staging capacity and a
potential ACK-intent slot. In ONE transaction create receipt(staged) and work,
register footprint and validate target/sequence/erase fence. Existing same-seq
work must be identical after authenticated normalization; mismatched bytes retire
the session and preserve the original evidence. Reserve capacity before W1, not
after it. Maximum per T: 1,024 receipts/work and 64 MiB serialized work; 1,024
intents plus reserved terminal slots. Held work retains its reserved slot until
WS or explicit terminal disposal. This can pause a mailbox behind prolonged
local recovery; it cannot evict a hold merely to make the ACK window look clear.

**W1 Process:** execute the existing authenticated/idempotent receive stages on
the durable work. Their individual commits may include ratchet/seen marker,
message/control projection, policy, retries and local outbox. W0 survives EVERY
such commit. Processing may prepare network work for S2 couriers but never await
it on the actor. Each content kind must retain its current committed-receipt
recovery, and commit each irreversible local effect with its dedup marker; S6b
owns adapting any receive stage that violates this rule. Reopening W0 redrives
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
expire_inbox_holds and all retry removal sites must go through that transition.

**WA Settle ACK intent:** acked, already_settled and not_found delete only the
matching requested intent. Rejected backs off 1,2,4,...60 s. A malformed/missing
per-seq result or lost response retains it; duplicate/foreign results are protocol
errors. At expires_at, delete with a metadata diagnostic, never a content-loss
event: content was already accounted. Timeout after write retires the session.

Actual router retain_until is carried with push/page/FetchEntry metadata. If an
old node cannot supply it, use the safe upper bound
`min(created_at + min(ttl,604800), first_local_seen + 604800)` with checked
arithmetic; it can retain an intent too long, never discard one earlier than the
router's acceptance cap. For EntryTooLarge use its explicit retain_until. The
clock can be past that bound already: W2 still accounts the sequence atomically,
then WA expires the intent without network traffic.

### 2.4 What a gap means, including old history

A modern epoch's `classification=unavailable` means the router's authoritative
coverage contains no live entry and this device has no durable staged/held copy
or terminal receipt for that sequence. Reason is expired, ack_window_overflow,
nacked, oversize, or unknown. This is missing delivery evidence, not proof that
an entire logical message has no copy on any other device. Gap events contain
only T, from_seq, to_seq, count, reason and classification.

Migration initializes activated_cursor=C. Existing local retry/unrouted work is
indexed into receipts before enabling loss inference. On the first capable page,
atomically set legacy_uncertain_through to its issued watermark before applying
any coverage. Missing intervals in (activated_cursor,legacy_uncertain_through]
without recoverable work get `classification=legacy_unverified`, not a claim of
content loss: an old client might have ACKed after processing and crashed before
its C write. Report these separately in status. A fresh device initialized with
this ledger has legacy_uncertain_through=0. New-client compatibility sessions use
the same ledger, so later compat-to-push transitions add no new uncertainty epoch.
Known local work always suppresses both kinds of gap, including a capacity pause
after W1 and before W2.

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
| Erasure transaction during staged/held work | old content+receipt, or erased receipt without content | Restart can only finish erased accounting; late outcomes cannot resurrect copies |
| Before send / after ACK send but before router WR | intent on disk | Resend, in push or compat mode; do not delete on network uncertainty |
| After WR before reply / WA | intent on disk, router may have settled | Idempotent ACK or legacy exact lookup; delete after terminal evidence |
| WA retry/expiry/delete transaction | old intent / complete updated or deleted intent | Never a partial batch delete; only named requested rows affected |
| Loss outbox before journal projection WJ | loss+C+unpublished outbox | journal_outbox inserts one unique source-key event and marks publication |
| Inside / after WJ, before subscriber send | no / one journal row per outbox source key | Replay journal on reconnect; socket delivery may repeat the same journal seq |
| Projected-loss pruning WP | old ranges / pruned projected ranges | Counters and C unchanged, no new loss events; unpublished rows never pruned |
| Backup sanitization commit | snapshot not yet usable / sanitized snapshot | Publish backup only after strip+sync; never restore ledger with a stale target/C |

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

The page/issued APIs read only the durable published shard view. S6a must also
serialize submit/fan-out/forward/retention publication against that view: prepare
the candidate, finish the existing durable write, then publish its pending rows
and issued watermark together. A sequence allocated only in a tentative candidate
is not page coverage. This requires a per-shard mutation sequencer and immutable
read snapshot (or equivalent publication barrier), not a blocking mutex held
across async storage I/O. A persistence error cannot leave a tentative row visible
to a successful page. Test a held submission commit while a page and issued probe
run, then fail the commit: neither read may expose that tentative sequence.

| Write / cut | WAL-enabled submissions (reference default) | Redb-only submissions | Recovery / response rule |
| --- | --- | --- | --- |
| R0 before durable submission, after in-memory preparation | no committed WAL record | no committed redb submission | No successful acceptance sent; restart has only prior durable state |
| R1 submission commit | append+sync submission, including acceptance time; may have no redb inbox row | one redb transaction: replay tuple+inbox/deadline indexes/local-delivery metadata | Reply only after durable success; crash before reply may be sender retry; preserve existing replay behavior |
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
string. Omitted Optional fields decode as None. Entries retain the existing
InboxEntry shape. EntryRecord is `{entry: InboxEntry, retain_until: Deadline}`.
RangeReason is `expired|ack_window_overflow|nacked`; local reasons also include
`oversize|unknown`. Requests are implicitly scoped to the authenticated session T;
when a legacy-shaped request includes target, it must equal T. No request_id is
needed because S2 permits exactly one request in flight; an unexpected reply
retires that session, never satisfies a later call.

| Direction / tag | Exact fields beyond frame_type | Reply set / meaning |
| --- | --- | --- |
| C->G resume | resume:{target_delivery_id:Target,after_inbox_seq:Seq,limit:usize,resume_token:String} | Legacy request shape. Capable reply is resume_page or nack |
| G->C resume_page | target_delivery_id:Target, after_inbox_seq:Seq, covered_through_seq:Seq, issued_inbox_seq:Seq, entries:Vec<EntryRecord>, known_losses:Vec<{from_seq:Seq,to_seq:Seq,reason:RangeReason}>, oversize_next:Option<Seq>, more:bool | Authoritative range, section 5; cannot mix with unsolicited pushes |
| C->G fetch_entry | inbox_seq:Seq | entry, entry_too_large, entry_gone, nack |
| G->C entry | record:EntryRecord | Exact s and T from request; full frame <=F |
| G->C entry_too_large | inbox_seq:Seq, retain_until:Deadline | Live legacy entry exceeds single-entry cap. No envelope/message ID or content |
| G->C entry_gone | inbox_seq:Seq, observed_issued_inbox_seq:Seq, reason:expired|ack_window_overflow|nacked|unknown | Point view says no live entry at s<=issued. No TTL invented |
| C->G ack_batch | inbox_seqs:Vec<Seq> | Strictly increasing, 1..64, all positive; ack_batch or nack |
| G->C ack_batch | cursor:InboxCursorResponse, results:Vec<{inbox_seq:Seq,outcome:acked|already_settled|not_found|rejected,reason:Option<String>}> | Exactly one result per requested seq, no others; reason bounded 256 UTF-8 bytes |
| G->C submit_accepted | envelope_id:String, target_delivery_id:Target, inbox_seq:Seq | Durable submit reply; compact acknowledgement, no recipient content |
| G->C deliver | entry:InboxEntry, retain_until:Option<Deadline> | Unsolicited only in push mode, and only for T; retain_until required in capable sessions, omitted for legacy |
| G->C resync | target_delivery_id:Target, after_inbox_seq:Seq, reason:queue_full|not_pushed | Hint to fetch from local C, never authority to move it |
| G->C ephemeral | envelope:Envelope, expires_at_ms:u64 | Event, no inbox_seq |
| G->C ephemeral_result | envelope_id:String, outcome:accepted|dropped, reason:Option<EphemeralDropReason> | Reply to ephemeral submit; reason present iff dropped |
| establishment addition | session.capabilities:Vec<String>, default empty, omit empty | Echo only negotiated capabilities |

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

- `POST /mvp0/ack-bound-batch` body `{target_delivery_id,inbox_seqs}` ->
  `{cursor,results}` as above. ACKs by seq are authorized by the session binding;
  derive envelope diagnostics from the router row, never client-supplied content.
  A seq above published issued is rejected invalid_seq and cannot advance router
  state. not_found is terminal only for an already issued absent row; an unknown
  target has issued=0, not permission to create a future ACK cursor.
- `GET /mvp1/inbox/{target}?after=&limit=&session_push=1` -> the resume_page fields
  without frame_type. Absent session_push returns the legacy response.
- `GET /mvp1/inbox-entry/{target}/{seq}` -> tagged entry/entry_too_large/entry_gone.
  Gateway authenticates and enforces s<=issued; s=0 or s>issued -> nack invalid_seq.
- `POST /mvp0/issued-seqs` body `{targets:Vec<Target>}` ->
  `{issued:Vec<{target_delivery_id,inbox_seq}>}`; 1..1,024 unique targets, exactly
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
This special lookup does not use the public merge-pushes resume_after adapter,
does not call normal receive, and never changes C. Old pull_live_after returns
the lowest live entry above after. An exact (T,s) result supplies envelope ID in
memory: construct the existing signed ACK and await both Ack and Cursor replies.
Then WA deletes intent. If the complete valid reply is empty or its first entry
is greater than s, s has no live router row: settle the intent as absent. The
router never issues s again. Timeout, malformed/oversized reply, target mismatch,
or ACK refusal retains intent with backoff. Never infer absence from a partial
frame, discarded push, or failed call. A crash after that ACK but before WA simply
repeats lookup, now absent. Legacy lookup serializes on the one host wire slot;
normal calls get a turn after each intent, not after the whole table.

The transition push->compat->push therefore neither strands nor discards intent
rows. New entries in compat still use W0/W1/W2 before their per-entry ACK; legacy
ACK-before-C ordering is not carried forward. Compat Resume lacks authoritative
issued coverage: apply returned entries and advance over missing intervals only
with classification legacy_unverified, after reconciling receipts. An empty
legacy page never moves C. No typed claim of definite content loss or tail
coverage is made from it. A legacy node unable to send an old oversized entry can
pause settlement until its expiry or a node upgrade; status exposes this delay.
That is an explicit limit of interoperability, not an unsupported frame retry.

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
sequence index as well. It is reconstructed from durable rows at startup; no new
on-disk router format is needed. Seek O(log P), then merge actual pending and
dead-letter boundaries. Never enumerate every integer from after+1 to issued.

Under one shard lock snapshot issued I and walk sparse boundaries above after:

1. Skip an absent interval in constant work, extending coverage to just before
   the next boundary (or I). Missing intervals need no serialized router record.
2. For an expired pending row, append/merge an expired reason; do not delete it.
   Dead-letter rows add their known reason; no live row may overlap a reason.
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

Before staging, SDK validates target and echoed after against its request,
after<=covered<=issued, sorted unique entry sequences inside coverage, and sorted
disjoint known-loss ranges inside coverage with no live-entry overlap. A marker
must equal covered+1 and be <=issued. more is true exactly when covered<issued;
an invalid/nonprogressing page retires the session with C unchanged. A point
reply must match the requested sequence/target, never a later entry substituted
for it. Receipt reconciliation cannot confer authority beyond these bounds.

### 5.2 Admission and FetchEntry

Before assigning/committing a NEW inbox row on every creating path (gateway,
own-device fan-out, federation inbound, migration forward), measure the largest
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
never decrease C or pretend there are no gaps. An empty terminal tail at I after
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
replacement checks occur at final try_push. Cross-node ephemeral delivery remains
not_local until a live federation transport exists; never use a durable federation
spool as a fallback. Same-node cross-gateway delivery is supported.

## 7. SDK runtime and S2 integration contract

S6b replaces the receive polling task; S2's host remains the only socket reader.
The receive child subscribes to Deliver/Resync/Lagged, while ephemeral intake is
separate. No child runs its loop inside ConnectionHandle.call. Actor messages:

- PrepareReceive{generation} -> C, ledger limits, due intents/receipts (bounded).
- ApplyPage{generation,expected_cursor,page} -> {cursor,paused,need_point_fetch}.
  Page is the exact authoritative structure, including EntryTooLarge/EntryGone
  point outcomes; actor performs W0/W1/W2 as bounded steps. Network calls happen
  outside these steps. A stale generation/C applies nothing for that step.
- SettleRetained{generation,target,inbox_seq,expected_disposition} -> WS result;
  explicitly allowed below C and distinct from a network duplicate.
- AckResults{generation,requested_seqs,results} -> WA result; exact-set validation.
- ReceiveObservation{generation,mode,counters,times} -> manager snapshot update
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

In push mode, s=C+1 applies directly; higher pushes buffer up to256 entries/8 MiB
and start one 500 ms gap timer. Hole filled before deadline -> no Resume. Timer,
Resync, S2 resync_needed, due local retry, Connected or safety sweep coalesce into
one catch-up plus at most one follow-up. Pushes during catch-up remain separate
from authoritative pages; lowest seq wins buffer retention, overflow drops the
highest and requests catch-up without ACK. Local retry does not require a pull
when durable work alone suffices. Catch-up pages64, max16 pages before yield.

Default push safety sweep900 s since last completed catch-up, configurable
RAMFLUX_SESSION_SAFETY_SWEEP_SECS clamped60..3600 once at process start. Compat
sweep5 s, regardless of that push-only setting. Old RAMFLUX_SYNC_MIN_MS/MAX_MS
are ignored with one warning naming the replacement. Parsing is pure/testable,
not process-global test mutation. A catch-up stopped by backpressure is not
“completed” for the idle timer. No old tick or courier can secretly pull inbox.

Status adds receive:{mode,last_catch_up_at,catch_ups_total,inbox_gaps_total,
legacy_unverified_total,ack_intents_pending,held_entries,paused_reason}.
Manager is the snapshot's single writer; actor supplies committed counters.
Old public SDK APIs and unchanged desktop consumers must compile against the
published product SHA. S6 may add internal entry/page methods; it may not force
desktop callers to adopt a new connection runtime.

## 8. Ephemeral delivery and S0 input

### 8.1 Contract consumed from provisional S0

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

### 8.2 S0 input: recommend the sender-signed lifetime

Proposed normative addition to S0 Decision 6:

> The lifetime uses sender-signed created_at and ttl_seconds. Let D be their
> checked sum in Unix seconds. Reject unless 1<=ttl_seconds<=5,
> created_at<=node_now+2 and node_now<D. Every hop and receiver enforces the same
> exclusive deadline D*1000 milliseconds; no grace or deadline extension is
> allowed. Replay digests expire at D. A sender clock behind by its TTL can lose
> transient delivery; this never falls back to durable delivery.

This resolves boundary equality consistently: now>=D is expired in gateway,
router, mesh, writer and SDK. If created_at is slightly future, acceptance is
allowed immediately within the two-second tolerance; maximum remaining life at
first receipt is ttl+2 s. Thus “within the five-second lifetime” refers to the
signed interval ending at D, not an unconditional five seconds after first
receipt. Clock skew trades transient availability for a finite authenticated
replay horizon. Recommend this choice because a first-gateway-time lifetime needs
an authenticated durable first-seen binding across restarts/gateways to stop a
fresh request renewing old signed input; that conflicts with S0's no durable
transient state. No owner technical decision is needed, but S0 review must approve
the exact wording and full SHA before S6c dispatch.

expires_at_ms is checked multiplication of D, carried unchanged and verified on
every hop. Router marker=domain-separated digest of authenticated source root,
source device, envelope ID and payload hash until D. Receiver similarly dedups
by authenticated source plus envelope ID until D, checking payload hash collision
as invalid. Router-only restart can admit another queued copy but a surviving
receiver drops it. Router AND receiver restart (or repeated such restarts) can
expose duplicates inside the remaining signed lifetime; there is NO guarantee
of at most one duplicate across arbitrarily many restarts. After D all copies
are rejected, even under a fresh transport request. This bounded-time exposure
is accepted for transient indicators; no durable history/event appears.

## 9. Implementation split, tests and acceptance

### 9.1 Complete cards and merge order

Each row is a complete component delivery with its own tests. No row is “Part A
now, remaining business logic in a follow-up.” S6 completion means all rows below
merged and accepted. Do not reactivate the superseded monolithic implementation
card. Controller writes new cards from this approved design with explicit SHAs.

| Card | Complete scope and principal files | Dependency / enablement | Affected slices |
| --- | --- | --- | --- |
| S6a node durable session protocol | node-core gateway_frames, inbox_page, entry_bound, inbox sparse index; router handlers/router_engine/router_store ACK batch; gateway push_queue, issued_probe, session, state, clients, serve; compact reply split, FetchEntry and capabilities, async ACK/NACK; node docs | Current main; no S2 dependency. Advertise capability only after the entire durable protocol exists. Legacy clients remain supported | id02, s39a, s51, s35, call01, s50 plus node protocol fixtures |
| S6b SDK durable receive ledger | storage account_db/receive/{schema,stage,cover,settle,privacy}, schema migration, footprint and backup paths; SDK bus/push_receiver/{apply,reorder,ack_batch,compat,keepalive}, S2 host dispatch/read timestamp and actor arm, events/status, docs and CHANGELOG | S6a + merged S2/S3. Adapts provisional interfaces; no changes in S2 work-in-progress branch. Complete push and compat receive at delivery | id02, contact02, s74, s39a, s51, s35, call01, s50; push01 durable cases |
| S6c ephemeral transport | gateway ephemeral validation/queue/mesh result; router ephemeral_route and volatile replay; SDK transient API/dispatch/channel; durable-origin refusal; ephemeral docs | S6a/S6b + approved complete S0 Decision6 including section8.2. Advertise separate `gateway.ephemeral.v1` signed/echoed capability only when the full path exists; session_push alone never implies it during staged merge | push01 transient case, id02, s50, s51 refusal fixtures |
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
implementation dispatch waits for complete S6a/b/c on main, S0 approval and S2;
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
| S6a entry_admission_all_origins | Gateway, fan-out, federation and migration normalize then measure Entry and both Deliver shapes; exact cap succeeds, +1 refuses without append | Omit post-authority bound on one origin; its oversized row appears |
| S6a fetch_all_terminal_races | Entry/TooLarge/Gone after expiry, sweep and router restart; supplied deadline is original; no loop | Return TooLarge for vanished row; reason/intent/deadline oracle fails |
| S6a ack_batch_reopen_equivalence | Compare twin sequential/batch routers after reopen in both modes: pending, receipts, dead letters, indexes, cursor; one store txn | Retain only last ACK's retired list; reopened pending differs |
| S6a ack_batch_atomic_failure | Fault commit and crash after commit before publication; no successful reply on failure, reload consistent | Publish candidate in memory before failed commit and continue serving; state-vs-reopen comparison fails |
| S6a durable_view_publication | Hold/fail submit commit while page/probe run; neither exposes tentative issued or row | Publish issued before commit; read capture contains uncommitted sequence |
| S6a retention_mode_oracles | WAL pre-sweep unknown, redb pre-sweep expired, post-sweep/prune unknown permitted; issued retained through second reopen | Require expired row in WAL; actual page reason/missing-row assertion fails |
| S6a sender_isolation | Hold recipient at sink-write-entered, issue second submit on SAME sender after first reply; it completes before release | Await recipient write on sender task; second reply misses barrier watchdog |
| S6a queue_half_drain_and_inflight | 16 admitted incl held in-flight, 4 overflows -> min after16; no Resync above8; fresh overflow during its write survives; latch guarantees eventual hint under arrivals | Exclude in-flight occupancy; admitted count differs |
| S6a resync_threshold | Resync appears only <=half frames AND bytes, with continuous traffic latch test | Give unconditional Resync priority; frame captured above threshold |
| S6a stalled_writer | Queued returns immediately, only that token closes at15s, replacement unaffected | Keep2s sender timeout; liveness/deadline assertion fails |
| S6a population_probe | 1,025/5,000/40,960 tokens, all batches visited once, <=4 concurrent, missing/timeouts reset confirmations, no overlapping rounds | Probe first1,024 only; untouched token lacks hint |
| S6a probe_hole_below_high_push | Router-origin s1 plus pushed s2 cannot hide s1; only second successful observation hints | Use max pushed seq as coverage; hint missing |
| S6a mesh_compat_overflow | Old boolean decoder sees durable overflow true, no wake; new outcome agrees | delivered=(outcome==queued); wake recorder nonempty |
| S6a sender_recipient_matrix | Sender x recipient old/new, local/mesh, actual recipient target; capable self-target gets separate reply+push without probe/Resume | Keep self-target suppression; recipient frame missing |
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
| S6b compat_intent_transition | push lost batch -> legacy exact lookup/ACK -> push; crash after legacy ACK before WA; C fixed, all intents settle | Resume only after C; old intent remains despite live router row |
| S6b legacy_prior_crash_classification | Old ACK-before-C crash then first capable epoch emits legacy_unverified, never definite content loss | Omit epoch fence; classified unavailable count is wrong |
| S6b push_without_polling | Initial catch-up then idle DM commits with Deliver and no Resume in measured interval | Retain old5s schedule; exact idle Resume count fails |
| S6b reorder_and_gap | C+2 then C+1 at200ms -> ordered apply, no pull; missing sibling -> one pull at500ms | Apply arrival order; ordered projection assertion fails |
| S6b gap_timer | No Resume before500ms, exactly one then | Wait5s; 500ms capture empty |
| S6b connected_and_sweep | One initial Resume within100ms; none until900s; probe/gap/retry held beyond experiment | Remove Connected trigger; 100ms frame count0 |
| S6b sweep_setting | Default900s; pure parser clamp60..3600; deprecated variables one warning/no effect | Default60s; premature Resume |
| S6b ack_batch_timing |16 eligible->one batch;3->one at1s; every seq passed W2 | ACK each entry; batch count differs |
| S6b coalesced_resync | Resync+Lagged+sweep during held run -> exactly one follow-up; buffer256/8MiB | Spawn catch-up per hint; concurrent/follow-up count differs |
| S6b lifecycle_fence | Held page/result, lock<1s, release old generation -> no DB write or ACK; unlock recovers disk | Drop generation check; stale row/write appears |
| S6b keepalive_all_reads | Reply/push/heartbeat update activity even without subscribers; missing reply retires at35s idle scenario | Derive activity from push-only subscription; ping sent after recent reply |
| S6b ledger_privacy_restore | Exact metadata columns, delete/replay fence removes all work+aliases, erased receipt survives; decrypted backup/import contains no ledger or stale C; account erase DB/WAL | Omit work footprint registration; forbidden wire ID/payload found after reopen |
| S6b old_writer_refusal | Migrated DB opened by previous writer returns AccountSchemaTooNew with unchanged contents | Weaken writer-version guard; old writer opens or changes DB |
| S6b capacity_and_range_work | Reserve before W1; full intents or64MiB staging pauses, local retries still run; huge hole uses intervals | Reserve after W1; processing hook fires despite unavailable capacity |
| S6c ephemeral_persistence_absence | Generic before/after every redb table, WAL length, spool, notify queue, client DB/journal; no changes for live/offline/full/expired | Send ephemeral down durable route; persistent artifact found |
| S6c ephemeral_deadline | Stale signed input under fresh request refused before router I/O, D exact on every hop, now==D expires | Recompute D from receipt time; delayed/replayed envelope accepted |
| S6c ephemeral_restart_window | Router-only restart receiver dedups; combined/repeated restarts duplicate only beforeD, never durable; no marker afterD | Keep marker pastD; live-marker inspection fails |
| S6c ephemeral_admission_result |40 same paused-instant submits,41st rate-limited,50ms refill1; invalid ttl0/6 refuses before routing; accepted then expired gets no second reply | Validate after route; router recorder sees invalid input |
| S6c final_registration_capability | Replace capable token with legacy between route/enqueue -> dropped recipient_unsupported | Check capability only at routing; accepted with no capable queue |
| S6d push01 wire capture | Actual Deliver to B and zero Resume between send and event, after initial catch-up; sweep3600s | Re-enable receive poll; capture finds Resume with competing paths held |

Crash sweep hooks count real commits W0/W1*/W2/WS/WA/WJ/WR/RE/RC, rerun once per
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
and runs post-merge CI. Node rollback keeps router formats but loses newer wire
features; new SDK enters compat and settles its intents. Client rollback is
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
| r1-M4 S0 replay horizon mismatch | sections1.2,8.2; markers end at signed D, exact S0 approval prerequisite, no grace |
| r1-M5 mesh overflow wakes device | section6.3; durable overflow true for old/new decoders, no offline wake |
| r1-M6 crash fault not between split writes | sections3,9.2; enumerate every real commit and immediate durable-state oracle between split writes |
| r2-H1 held cleanup / no below-C settlement | I4; section2.3 outcome-specific W2 and WS, local hold lifecycle and crash tests |
| r2-M1 absent router row may exist locally | I2/I5; W0 precedes effects, keyed receipts reconcile all absent ranges even after router expiry/capacity pause |
| r2-M2 push intents stranded in compat | section4.3 exact legacy lookup, no C movement, same ledger both modes; section2.4 pre-ledger uncertainty |
| r2-M3 point-fetch disappearance / missing TTL | sections4.1,5.2 EntryGone and explicit TooLarge retain_until; complete host reply set section7 |
| r2-M4 empty page at byte boundary | section5.1 full serialized one-item measurement, zero-limit refusal and progress predicate |
| r2-M5 unbounded sequence walk | section5.1 sparse ordered index and512 actual visits; section2.3 interval subtraction/counts |
| r2-M6 redb/WAL restart oracle conflated | section3.2 and retention_mode_oracles: WAL unknown, redb pre-sweep expired; common exactly-once local accounting |
| r2-L1 operative affected slices removed | section9.3 all nine named slices with exact selectors and environment/membership |

## 11. Residuals and owner questions

Technical choices are made above; no owner technical question remains. S0 lifetime
approval and merged S2/S3 interface recheck are dispatch prerequisites, not product
questions or blockers to reviewing this design.

Residual product behavior is explicit: an unrecoverable inbox gap cannot retrieve
history from an E2EE router; a user must obtain another device/sender copy through
future product flows. Legacy pre-ledger uncertainty is labeled, not counted as
proven content loss. Persisted local holds consume bounded disk and can pause new
receive admission until they settle/expire under existing policy. Legacy oversized
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
