# Revocation placeholder erasure v1

Status: proposed design; no implementation or runtime acceptance is claimed.
Revision: r2, closing the first independent design review.
Evidence base: `0d6da88fb189201a44eefe611d5e79c39ef77661` (2026-11-04).
This base contains attachment erasure commit
`38e41095de34ada4e711390e96a577dbaea717f5` and revocation commit
`81e59c3032f69b627e421ced8b137c5e995e0a2c`.
Citation verification: fetched `origin/main` at
`aebc4901e53a6f0aacc1c87a67fc1c5e578db2c5` (2026-11-04). Every cited
product source range is unchanged from the evidence base; the intervening
changes affect deployment files only. Proposed behavior remains unimplemented.

## 1. Facts at the evidence base

All source locations below refer to the immutable evidence base. Abbreviations:
`S` = `crates/ramflux-storage/src`, `A` = `S/account_db`,
`R` = `A/object_retention`, `K` = `crates/ramflux-sdk/src`,
`J` = `K/bus/backup_jobs`. Locations describe existing behavior; mechanisms
marked **proposed** in later sections do not exist at this base.

### 1.1 Identity and row inventory

A selector is a device-local attachment name; it need not equal the wire object
ID. The payload identity is `(principal root, wire ID, ciphertext manifest)`.
`C = object_erasure_commitment(root, wire, manifest)` and
`L = object_erasure_lookup(root, selector)` are different identities. The
revocation control's envelope ID is provenance, not either identity.

| Store or row type | Contents and indexes relevant to this design | Base source |
| --- | --- | --- |
| `object_index` | PK `object_id`; ciphertext identity, tombstoned flag, chunks, content key and `object_body`. A pre-import placeholder has `tombstoned=1`, zero chunks, empty ciphertext, no content key; body includes selector, owner, sender, revocation envelope ID and manifest. There is no separate placeholder table or typed placeholder Rust record. | `S/schema.rs:449-466`; `A/object.rs:187-207` |
| `ObjectWrite<T>`, `StoredObject<T>`, `ObjectPayloadRow` | General object write/read representations; none distinguishes a private-selector placeholder from a wire payload. | `S/records/object.rs:6-20`; `A/object.rs:12-20` |
| `object_retention_payload` | PK commitment; unique `(wire_id,manifest_hash)`; `wire_lookup`, retention class, expiry, owner count. Indexes `object_retention_expiry`, `object_retention_wire`. | `R/schema.rs:20-25` |
| `object_retention_reference` | PK reference hash; commitment, selector, selector lookup, complete private reference JSON. Indexes `object_reference_payload(commitment)`, `object_reference_selector(selector)`. | `R/schema.rs:26-30` |
| `object_message_reference` | PK `(message_id,reference_hash)`; metadata JSON; reverse index `object_reference_message(reference_hash,message_id)`. Insert/delete triggers update payload owner count. Two messages can share a hash; two distinct hashes can share a selector. | `R/schema.rs:31-36` |
| `ObjectReferenceOwner`, `ReceivedAttachment`, `SdkDmAttachmentRef` | Registration supplies message, selector, wire, manifest, reference and metadata. Received state also contains authenticated sender and prepared key slot; wire references contain grants, relay information and key slots. | `R/mod.rs:34-43`; `K/client/deferred_attachment.rs:24-45`; `K/dm.rs:90-110` |
| `SdkOwnDeviceSyncEnvelope`, `SdkOwnDeviceHistoryBundle` | Signed history transport reference and serialized message/content history can carry attachment material indirectly. They are authenticated input types, not permission to insert arbitrary backup-table rows. | `K/own_device_sync.rs:9-76` |
| `runtime_actor_state` | PK `state_kind`, JSON BLOB. Selector projections: `attachment/reference/<s>`, `directory/object/<s>`, `sync/attachment/<s>`; indirect `attachment/reference-by-sender/…` and `attachment/reference-by-slot/…` values can contain the selector. Chunk actors contain wire/manifest. A client record is actor state, not a separate object directory table. | `A/runtime/schema.rs:28`; `R/actors.rs:8-64`; `K/client/deferred_attachment.rs:225-239,592-699` |
| `object_reference_actor`, `object_payload_actor`, `object_transport_actor` | Binding rows, PK `(reference_hash,state_kind)` or `(commitment,state_kind)`; reverse kind indexes on reference/payload bindings. They link prepared slots, actor copies and history transports to erasure. | `R/schema.rs:37,40-43`; `R/actors.rs:71-76` |
| `object_payload_dependency` | PK `(parent_commitment,child_commitment)`; reverse `object_dependency_child`. Only transport parents are recursively retired. | `R/schema.rs:38-39,135`; `R/mod.rs:217-229` |
| `object_erasure_fence` | Unique commitment; append-only update/delete triggers. Covers a payload identity, including all its selectors. | `R/schema.rs:46,52-53` |
| `object_erasure_lookup` | PK lookup, commitment value. Contains wire and selector lookup witnesses. Base ERASE records a selector lookup when a reference hash dies, even if another hash with the same selector survives. A lookup alone therefore does not prove that every reference to that selector died. | `R/schema.rs:47,121-123,150-151` |
| `object_identity_replacement` | PK commitment; receipt for an explicitly checked new wire identity, not permission to resurrect its old identity or an arbitrary private alias. | `R/schema.rs:45`; `A/object.rs:41-64`; `A/backup_object_erasure.rs:263-265` |
| `object_erasure_work` | PK commitment, wire and manifest; `object_erasure_work_wire(wire_id,manifest_hash)`. Transaction work, consumed by payload cleanup. | `R/schema.rs:48-49,105` |
| `object_reference_erasure_work`, `object_projection_erasure_work` | PK reference hash with selector, selector lookup and commitment; PK selector respectively. Preserve the identities that destructive SQL is about to lose. | `R/schema.rs:50-51,110-131` |
| `account_erasure_generation`, `runtime_privacy_maintenance` | Singleton generation and pending physical maintenance flag. Shared-reference removal advances the account generation even without a new payload fence. | `R/schema.rs:14-15,69,119,152`; `A/message_footprint/erasure.rs:24-25` |
| `object_retention_upgrade`, `object_legacy_reference_context` | Discovery phase/cursor/budget and legacy selector/message/manifest metadata; PK singleton/selector; `object_legacy_context_message(message_id)`. Legacy ownership is not inferred merely from an object row. | `R/schema.rs:16-19`; `R/legacy.rs:159-179` |
| `schema_migration`, `runtime_account_identity` | Migration version/checksum and singleton principal root. Version 12 and migration-1 writer sentinel validate before private archive merge. | `S/schema_object_erasure.rs:8-38,80-110`; `A/runtime/schema.rs:38-40`; `A/backup_object_erasure.rs:15-38` |
| `message_copy_binding`, `message_footprint` | PK `(copy_id,message_id)` and `(message_id,kind,locator)`; message indexes and `message_footprint_locator(kind,locator,message_id)`. Both `object:<selector>` and `object:<wire>` bind to owners. Footprints enroll actor, event, archive, inbox, outbox, journal and projection copies. | `A/message_footprint/schema.rs:15-29,43-95`; `R/mod.rs:248-251` |
| `message_footprint_actor_stage`, `message_footprint_outbox_stage`, `message_footprint_journal_stage` | Transaction staging can contain actor/copy/binding JSON and journal locators. Consumers drain rows within the writer operation; require empty staging at commit and in exported snapshots. They add no independent lifetime authority. | `A/message_footprint/schema.rs:100-143,250-275` |
| `backup_archived_actor_state`, `backup_archived_local_event`, `local_event_log` | Private historical copies can retain selector/reference/provenance JSON even when no current directory row remains. Archive PK `(source,state_kind)` / unique `(source,event_id)`; live event key is event ID with gateway-envelope index. | `A/backup_merge.rs:320-335`; `S/schema.rs:76-99` |
| `backup_erased_copy` | Base TEMP exclusion set, PK `(database_name,table_name,row_id)`, used by object merge, generic merge and archive preservation. `merge_graph` does not consult it; excluding an object does not exclude a retention reference. | `A/backup_object_erasure.rs:28,186-190`; `A/backup_merge.rs:324-335,358,454-459`; contrast `A/backup_object_erasure.rs:347-354` |
| `backup_missing_attachment` | PK selector with manifest/plaintext hash; preparation also installs `backup_object_reference_hashes(manifest_hash,plaintext_hash)` on `object_index`. Records are scanned in both databases and excluded separately. | `A/backup_missing.rs:60-91`; `A/backup_object_erasure.rs:99-109` |
| `object_manifest`, `object_key_slot`, `object_chunk` | Wire-owned encrypted metadata and keys/chunk locators; PK object/slot/chunk; unique manifest hash and `(object_id,chunk_index)`; `idx_object_chunk_state`, added `object_key_slot_wire`. No placeholder is stored here. | `S/schema.rs:467-507`; `R/schema.rs:10` |
| `object_transfer_state`, `object_operation`, `object_share_grant_projection`, `object_tombstone` | Wire/manifest progress, responses, grants and tombstone provenance; PK transfer/operation row, composite grant owner, tombstone ID; `object_transfer_wire`, `idx_object_operation_operation`, `idx_object_share_grant_recipient`, `object_tombstone_target`. Cleanup must retain a different live wire manifest. | `S/schema.rs:508-528,688-699,772-785`; `R/schema.rs:10,76-105` |
| `ObjectTransferRecord/Write`, `ObjectShareGrantRecord/Write`, `ObjectOperationRecord/Write` | Rust representations of the corresponding wire/progress/grant/operation rows above; no independent selector-fence representation. Fence and lookup rows are SQL commitment/lookup tuples, not public Rust revocation records. | `S/records/object.rs:22-115` |
| `object_runtime_response`, `runtime_operation`, `runtime_outbox`, `runtime_journal` | Commitment/operation binding; cached response JSON; actor change/outbox rows; journal body/source/subject. Responses become erased receipts; footprint locators remove or redact message-owned copies. Outbox indexes include `runtime_outbox_pending`, `runtime_outbox_source`, `runtime_outbox_actor_kind`. | `R/schema.rs:44,142-149`; `A/runtime/schema.rs:14-25,42-54,79-83`; `A/message_footprint/erasure.rs:30-65` |
| `PreSendObjectHold`, `ObjectRetirementObserver`, registered privacy resources | Hold carries commitment and connection; post-commit callbacks/resource registrations retire caches/readers/spools. They are process resources, not backup rows or ownership proof. | `R/holds.rs:8-14,32-43`; `R/mod.rs:45-54,84-120` |
| Message deletion authority and replay copies | `direct_message_projection`, `message_tombstone_projection`, `group_message_tombstone_projection`, and account-bound `message/deleted/…` / `message/deleted-envelope/…` actor markers reject stale owners. Footprints also cover `runtime_unrouted`, `runtime_inbox_retry`, `runtime_inbox_dead_letter`, their policy, raw envelopes, ACK/NACK and cursor pointers. | `A/deleted_messages.rs:17-40,70-80,91-105,167-175`; `A/message_footprint/schema.rs:61-95`; `A/message_footprint/erasure.rs:52-99` |

This inventory includes indirect copies: the footprint dispatcher, rather than
a second hand-maintained JSON-table list, remains the authority for their
message-level deletion. SQL work and restore classification must not create
untracked copies of private selectors.

### 1.2 Complete lifecycle entrypoints

| Path | Existing behavior and commit boundary at the base |
| --- | --- |
| Revocation creation | `K/client/routed/control.rs:143-165` checks owner and invokes `A/object.rs:158-230` in `write_transaction`. Actor-reference manifest precedes display manifest; absent sources produce 32 zero bytes at line 203. Existing rows are tombstoned without replacing their payload identity. |
| Received reference / deferred import | `K/client/deferred_attachment.rs:191-242` registers retention ownership and reference/directory actor state together. `R/mod.rs:235-253` checks deleted message and payload fence, but does not check selector lookup. `A/object.rs:75-145` prevents ordinary upsert from overwriting a tombstone. |
| Message delete, including group/sibling deletion projections | `A/deleted_messages.rs:35-39` sets `deleted=1`; `A/message_footprint/erasure.rs:18-20` installs footprint and object triggers in that transaction. `R/schema.rs:109-166` collects reference hashes, removes message owners, expands transport retirement, deletes payloads and projects remaining selectors. Placeholder cleanup at line 104 wrongly also requires payload retirement in the same pass. |
| Payload-only erase: direct transport retirement | `R/mod.rs:205-212` queues a transport commitment and executes `payload_erasure_body` in `write_transaction`. The shared `PAYLOAD_ERASE` expands parents at `R/schema.rs:135`, then deletes references at lines 136-137 without capturing their selectors. |
| Payload-only erase: pre-send release/drop | `R/holds.rs:20-55` begins an immediate transaction, queues only an unreferenced `pre_send` child, runs the same body and commits before notifications. Registering a message reference promotes pre-send retention (`R/mod.rs:243`); a referenced direct hold is not release-eligible. A transport ancestor can still own a selector. |
| Payload-only erase: identity replacement | `A/object.rs:41-64` checks expected old identity, active owners and ciphertext manifest, queues the old identity, erases it, then inserts the replacement and receipt in one writer transaction. |
| Payload-only erase: legacy maintenance | `R/legacy.rs:183-211` selects one eligible bounded payload. Explicit reference/revocation guards at lines 194-204 preserve a directly referenced placeholder. Retired transport ancestors still require the shared capture. |
| Account erase | No product account-wide erase entrypoint was found at this base. `apps/rf/src/cli/account.rs:17-31` lists supported account actions; `K/bus/dispatch/account.rs:163-187` is a lock/unload and does not erase a database. An index state named `removed` (`S/account_index.rs:224`) is not erasure implementation. This row is an explicit coverage boundary, not a claimed passing path. |
| Backup export | `A/backup.rs:79-137` copies every table using SQLite backup and reads counts from that exact encrypted snapshot; all non-excluded object rows count at line 158. It does not filter orphan placeholders. `J/workers.rs:178-180,254-266` captures a reader and authorizes publication against its captured erasure generation. |
| Restore, local fence → incoming live reference/placeholder | `A/backup_merge.rs:155-165` attaches incoming, begins `IMMEDIATE`, merges fences before objects, archives and generic tables. `A/backup_object_erasure.rs:64-74` unions fences and dependencies; lines 239-267 scan object IDs as wires, missing a private alias's payload identity. |
| Restore, incoming fence → local live reference/placeholder | `A/backup_object_erasure.rs:146-158` deletes local references of fenced commitments before calling the shared payload body, losing alias identities. `merge_graph` at lines 347-354 filters references only by payload fence; a selector lookup alone does not block reference import. |
| Restore merge/export copies | `A/backup_merge.rs:164-165,218-236,320-335,340-438` preserves private copies and applies object/generic arbitration before the final deleted-message update and commit; rollback at lines 239-242. `erased` returns early on an unfenced referenced payload (`A/backup_object_erasure.rs:212-218`), bypassing selector lookup. `check_object_access` has the same early-return shape (`R/mod.rs:137-159`). |
| Restore installation, full/native/fresh | Existing full restore copies local then merges (`J/install.rs:145-158`); native data restore calls the same merge mode (`J/native.rs:218-247`; `A/backup_native.rs:49-55`). Fresh full restore directly copies incoming and archives outbound (`J/install.rs:238-249`), bypassing merge. Generation publication is a separate durable index-pointer operation after staging/integrity checks. |
| Own-copy import | Signed history page authentication precedes decoding; `K/client/own_device_sync.rs:269-325` imports a page, binds transport owners and receipt in a writer transaction. Bundle import is transactional at lines 677-683; own deletion and message import at lines 694-760 use ordinary deletion authority. It stores no history-message attachment references. Its only registration is `K/client/object.rs:1014-1066`, specifically line 1053: a transport-owner edge with selector equal to the history object ID and reference JSON `{}`. |
| Legacy discovery | Bounded pages (256 rows, 1 MiB) inspect current and archived actors, including archived attachment actors in phase 4 (`R/legacy.rs:8-11,55-123`). `discover_reference` at lines 126-181 directly inserts a retention reference after a payload-fence check; its owner insertion is conditional on a live DM projection. It bypasses registration and can leave an ownerless reference. |

The four destructive retention-reference statements are `R/schema.rs:123,129,137`
and `A/backup_object_erasure.rs:157`. The five callers of the payload-only body
are replacement, hold release, maintenance, transport retirement and restore as
listed above. Message erasure embeds the shared SQL directly; changing only the
Rust payload wrapper cannot cover it.

## 2. One invariant and its state interpretation

For an accepted revocation on this device, **a placeholder exists if and only if
a live reference to its selector exists on this device and no erase fence covers
it**. This is the single lifecycle invariant. Revocation means the accepted
result of the existing tombstone/timestamp merge arbitration, not merely an
incoming losing row. It does not require making placeholders for attachments
that have never been revoked. An existing payload-bearing tombstone satisfies
the revocation veto without creating a second, payload-free placeholder.

The following definitions make the invariant implementable:

- A live managed reference is an authenticated reference row joined to its
  payload identity and at least one non-erased message owner. A registration
  may precede the message projection in the enclosing receive transaction;
  the authenticated owner edge is sufficient unless a sticky deletion marker
  or either restore side's deletion authority vetoes that owner. A bare JSON
  actor or a reference with no admissible owner cannot resurrect managed
  ownership. The legacy revoke exception below preserves an existing live
  actor's veto without manufacturing a managed owner edge.
- A live legacy received reference may not yet have a retention owner edge:
  discovery can still be paging, or the reference is classified
  `unowned_legacy`. For revocation only, an existing authenticated reference
  actor plus its agreeing client-record owner is a live legacy witness, unless
  known owner-deletion authority, a closed selector lookup or a payload fence
  vetoes it. This exception cannot authorize graph insertion by discovery or
  restore, and cannot reopen an erased selector from JSON alone.
- A payload fence covers exactly `C`, unconditionally. It dominates all
  selectors, reference hashes and timestamps. A selector lookup covers an
  erased selector in the absence of a surviving independently admitted
  reference for that selector/identity. It is not a payload fence for another
  selector that shares `C`.
- Existing partial-reference lookups are historical witnesses: if a distinct
  reference for the same selector still has a valid owner, retain that
  reference and its revocation veto. For historical imports this live witness
  is established before candidate rows are admitted; an archive cannot declare
  its candidate live to bypass a target's closed lookup. A new authenticated
  message with a non-deleted owner can reopen an unfenced selector, including
  a deterministic received selector used by an earlier deleted message. Its
  admitted owner then takes precedence over the historical lookup for G6.
- Explicit identity replacement is the existing checked wire operation and
  exact new-commitment receipt. It can establish the new identity despite an
  old wire lookup; it never clears an old payload fence. It grants no blanket
  exception for private aliases or old references.

The invariant applies inductively to compliant state and to the complete touched
closure of each operation below. Existing unmanaged store orphans are a stated
upgrade residual (§8), not evidence that a new operation may create another
orphan. New restores normalize legacy placeholders before publication (§5).

### 2.1 Proposed common decisions

**G1 — owner-keyed reference admission.** Within the writer transaction, check
the candidate's payload fence and exact message deletion authority before any
retention row, owner edge, binding or actor write. Carry explicit admission
context from the authenticated caller: `fresh_message` versus historical
`restore`, `archive_discovery` or `own_copy`. A signed history page remains
historical; a signature alone does not make an old owner fresh. The storage
registration default must not silently grant the fresh-message exception.

A new authenticated message with a non-deleted owner is admitted even if its
deterministic selector has an old lookup (`K/client/deferred_attachment.rs:659-668`).
Keep the opaque lookup; the newly admitted owner reopens access under G6. A
replay of the old deleted message still fails its owner-deletion check. Payload
fences always refuse, even for a new owner. Preserve conflicting-identity
checks; ordinary registration cannot mint a replacement receipt.

Only historical candidates face the additional closed-selector veto. Allow an
independently admitted same-identity survivor, but never let a candidate prove
its own survival against a target lookup. Discovery (`R/legacy.rs:126-181`)
must use this decision before inserting anything: skip fenced/closed candidates
and skip reference insertion when no admissible owner can be reconstructed.
Classify the latter as `unowned_legacy`; do not persist an ownerless retention
reference or binding. Archived actor copies obey the same rule.

Storage may expose typed `ObjectErased` internally, but every SDK call site
must consume that narrow refusal as an erased-item skip or deterministic
inbound rejection with quarantine/ACK, never an error keeping a whole message
in retry. Fresh-message success, deleted-owner replay and unrelated-message
progress are checked together in E16. Storage/I/O errors still propagate.

**G2 — manifest and placeholder admission.** One shared resolver decides whether
a missing row has an admissible reference identity; callers do not add redundant
fallback guards that would mask a mutation of that decision. New missing-row
placeholders require a live managed or live legacy received reference as defined
above, and a nonzero manifest. Resolve actor reference first,
then the retention reference/payload join, then client record. Retention identity
must agree across live references; verify that any selected actor/display
manifest agrees with the authenticated mapping. In the legacy branch retain
the control handler's client-record owner authorization: the actor must be
that owner's received reference, and its manifest must agree with any known
client-record manifest or retention identity. Accept a valid peer revoke
while discovery is incomplete or has left a live `unowned_legacy` reference:
create its nonzero placeholder from the actor manifest, without creating a
retention owner. Closed lookup/fence or known deleted owner still vetoes it;
the base erased-object consumed no-op comes from `A/object.rs:167-169`.
Display-only owner metadata is not ownership proof. No source or disagreement
means `AuthorizationRejected`
and no inserted row. Existing payload-bearing rows retain their ordinary
tombstoning behavior. Map this narrow refusal to the existing deterministic
owner-refusal inbound class, without converting storage/I/O failures into
authorization outcomes.

**G3 — capture before destructive erasure.** Use shared SQL after dependency
closure expansion, before reference/owner deletion. Capture reference hash,
selector, selector lookup and commitment while the join still exists. Keep the
matching `object_retention_payload` identity row until common cleanup; it pins
the resolved manifest even after reference deletion. The existing reference
work schema is sufficient: G4 joins captured commitment to this retained payload
row, or to `object_erasure_work` for the same commitment. Preserve earlier captures until common cleanup
finishes. Capture source references selected by message deletion before deleting
their owner edges; remove from the retirement set any reference hash still
owned elsewhere. Capture all additional references selected by final payload
closure. Do not clear earlier capture at payload-body entry.

**G4 — selector cleanup and remaining-reference projection.** For each captured
selector, delete its matching payload-free tombstone when no admitted live
reference remains, regardless of whether the payload is retired. Match the
known manifest from captured identity, never `hash(root, selector, manifest)`
for an alias. Record the selector lookup in the same transaction. Preserve the
placeholder if another reference hash with the same selector survives. Rebuild
reference/directory projection from surviving references, or remove it when
none survive. Drain reference-actor bindings and their unshared actors, outbox
and footprint links for all captured reference hashes. Remove selector-bearing
`object_payload_actor` links for removed actor keys even when their payload C
survives, and remove retired `object:<selector>` copy bindings and synthetic
`copy:object:<selector>` footprint locators. Preserve bindings supported by an
admitted surviving owner; a shared wire binding is evaluated against all its
surviving selectors. No orphan binding key may export the erased alias. Do this in the shared
path, including payload-only erasure. It must not depend on the optional message
PROJECT block. Work tables are empty on commit.

Going forward, write a new selector lookup only when the last live reference
for that selector is gone; continue interpreting existing partial lookups by
the survivor rule. Wire lookups continue to be written on payload retirement.
The opaque witness survives; plaintext selector/provenance does not. A
standalone payload does not justify retaining a private-selector placeholder
after its final reference dies.

**G5 — one restore admission decision for the whole selector graph.** Build the
accepted reference/owner set and blocked selector identities once from the two
authenticated input graphs, final fence union, deletion authority and captured
target survivors. Use this set in graph merge, placeholder merge, generic row
merge, archived-copy preservation, missing-attachment preparation and access
checks. Removing a placeholder alone is insufficient. Detailed order is §4.2.

**G6 — read and export consistency.** A lookup-bearing selector with no admitted
owner cannot return early through an orphan reference or placeholder. Resolve
aliases through authenticated references before checking payload identity.
An independently surviving or freshly authenticated same-selector reference, a
live legacy revoke witness without a closed lookup, or valid new wire replacement
keeps access to its unfenced identity; unrelated selectors sharing `C` remain
accessible. Snapshots export the committed graph, including opaque fences, and
the existing generation-publication check rejects snapshots overtaken by any
selector retirement, including payload-only cases that retire no new payload.

### 2.2 Proposed enforcing code responsibilities

These are new responsibility modules, not existing base APIs. Matrix references
to G1-G6 mean these modules plus the named current call sites, so each outcome
has a concrete implementation owner.

| Decision | Proposed code and integration points |
| --- | --- |
| G1/G2 identity and admission | `A/object_retention/selector_admission.rs`: one identity resolver with explicit fresh/historical registration and legacy-revoke decisions; call from `R/mod.rs` registration, `R/legacy.rs::discover_reference` before its direct INSERTs, `R/actors.rs` actor guard (including selector in the actor key and indirect alias values), and `A/object.rs` missing-row revocation. SDK peer receive passes fresh authenticated owner context; own-copy transport registration passes historical context. `K/client/routed/control.rs` and reference callers consume narrow refusals without retry loops. |
| G3/G4 capture and cleanup | `A/object_retention/selector_erasure.rs`: SQL builders for capture, surviving-owner projection and retirement cleanup; compose them into the existing `R/schema.rs` message and payload bodies after dependency expansion (P1). Restore's additional pre-delete capture in `A/backup_object_erasure.rs` is P2, witnessed by E6/U5/U6. The existing payload/work rows keep the manifest available until cleanup. |
| G5 graph classification | `A/backup_selector_admission.rs`: encrypted operation decision tables, two-input classification and single-input normalization. `A/backup_object_erasure.rs`, `A/backup_merge.rs`, `A/backup_missing.rs`, `A/backup_native.rs` and fresh `J/install.rs` consume that decision; archive preservation cannot invent a separate veto interpretation. |
| G6 access/publication | Shared resolver used by `R/mod.rs::check_object_access` and restore copy filtering; preserve existing generation advances in `R/schema.rs:69,119`. `J/workers.rs` keeps the current publication authorization boundary. The actual own-copy transport-owner registration uses historical G1 context within its page transaction; history attachment materialization is not implemented at this base. |

Restore scratch names are `backup_reference_admission` with columns
`side,reference_hash,message_id,selector,commitment` and PK
`(side,reference_hash,message_id)`, and `backup_selector_admission` with columns
`side,selector,commitment,decision` and PK `(side,selector,commitment)`.
Decisions are `keep`, `erase` or `unowned_legacy`; only accepted owner edges enter
the reference table. Add indexes `(side,selector,commitment)` and
`(side,commitment,reference_hash)` on accepted edges, and retain local witnesses
as a separately identified pre-merge side until classification finishes. A third
table, `backup_lookup_origin(side,lookup,commitment)`, has PK `(side,lookup)`
and index `(lookup,side)`. Populate both `target` and `incoming` sides before
the first lookup union (base `A/backup_object_erasure.rs:64`); never infer origin
from the unioned main table. A fourth table,
`backup_target_delete(reference_hash,message_id,selector,commitment)`, has PK
`(reference_hash,message_id)` and indexes `(selector,commitment)` and
`(message_id,reference_hash)`. It tracks the physical target edges that must
survive until the final deletion pass; these are never accepted owner edges.
Stage unresolved legacy rows in existing row exclusions rather than inventing C.
All four operation tables are in encrypted main and are dropped before COMMIT.

## 3. Path × state matrix

Each cell states the proposed result and enforcing mechanism. `P+` retains or
admits the winning revocation veto; `P−` removes/excludes the placeholder and
its retired selector graph; `K` keeps an independently surviving reference;
`X` refuses a new invalid operation without partial writes. **L-live** means a
valid local witness; **I-live** is only a candidate until G5 admits it.
**Erased** is a closed selector lookup without a survivor; **fenced** means its
payload commitment is fenced. Legacy column applies to both sides.

| Path | L-live | L-erased | L-fenced | I-live | I-erased | I-fenced | Legacy zero manifest |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Authenticated revoke | P+ via G2; K with partial lookup | No row, consumed no-op from base `A/object.rs:167-169` | No row, stronger veto via access check | Managed or live legacy actor/owner witness permits G2; no discovery prerequisite | No resurrection via G2 | No resurrection via G2 | New zero forbidden; refusal G2; old row §5 |
| New authenticated message / peer reference creation | K; preserve live tombstone | Admit fresh non-deleted owner, reopen unfenced selector via G1/G6; replay of deleted owner skipped/rejected without retry | Refuse fenced item via G1, consume narrow inbound refusal | Admit non-deleted owner via G1 | Lookup alone cannot veto a fresh owner; owner deletion still vetoes | Payload fence always vetoes | Cannot use unknown manifest to admit reference; §5 only on archive boundary |
| Late payload import / own-copy transport-owner registration | K; tombstone still vetoes ordinary upsert | Historical closed-selector veto/skip via G1 | Payload fence veto/skip via G1 | Historical G1 before transport-owner/binding writes | Exclude stale transport owner via G1 | Exclude stale transport owner via G1 | No history attachment reference materialization at base; not a new zero source |
| Message delete (DM, group, sibling) | P− on last selector owner, otherwise K; G3/G4 | Idempotent P−; G4 | P−; G3/G4 | Incoming delete runs same trigger after authenticated import; G3/G4 | No restored owners; G1/G5 | No restored owners; G1/G5 | Touched row normalized from captured reference then erased, or retained with surviving reference; §5 |
| Payload-only transport retirement | Capture full ancestor closure, P−; G3/G4 | Idempotent P−; G4 | P−; G3/G4 | No raw incoming payload cleanup; G5 classifies first | G5 P− | G5 P− | G4 uses captured identity, not zero hash; §5 |
| Pre-send hold release/drop | Direct referenced hold ineligible; eligible child retires referenced ancestors, P− via G3/G4 | No selector to recreate; G4 | Idempotent G3/G4 | No incoming hold release API | G5 excludes instead | G5 excludes instead | Ancestor case handled by §5/G4 |
| Legacy retention maintenance / discovery | Direct reference/revocation guard K; eligible ancestor closure G3/G4 | Discovery skips closed historical selector; G1 before direct INSERT | Discovery skips fence; cleanup G3/G4 | Only reconstructible admissible owner permits reference insertion; otherwise `unowned_legacy`, no new reference | Archived actor cannot reopen closed selector; G1 | Fence checked before discovery writes; G1 | Preserve ambiguous untouched rows; live legacy revoke still accepted by G2; normalize touched closure §5 |
| Explicit wire identity replacement | Active old owner forbids replacement; otherwise retire old G3/G4 and insert verified new identity | Only checked expected-absence/new receipt may succeed; §4.3 | Old C stays fenced, new C may succeed; §4.3 | Exact receipt for new wire C accepted; G5 | Old aliases excluded; G5 | Old C always excluded; G5 | Never infer a replacement receipt from zero manifest |
| Account erase | No supported API at base; §4.4 specifies required future behavior | Same boundary | Same boundary | No account erase import API | No account erase import API | No account erase import API | No claim that lock, unload or index removal erases old rows |
| Backup export | P+ and K exported in committed graph; G6 | P−, opaque lookup exported; G4/G6 | P−, opaque fence exported; G4/G6 | No incoming graph in export | No incoming graph in export | No incoming graph in export | Existing untouched store limitation §8; normalized restore output has no unresolved zero row |
| Restore A: target veto, archive candidate | K independent target survivors; G5 | P− incoming selector graph, successful restore; G5 | P− all incoming references to C; G5 | Admit only if no target veto; P+ after arbitration | Source closed selectors excluded; G5 | Source fences unioned first; G5 | Resolve and classify before arbitration; §5 |
| Restore B: archive veto, target live | Payload fence retires target graph; selector-only witness preserves independent target survivor; G5/G4 | Remain P−; G5 | Remain P−; G5 | Independent unfenced selectors survive; G5 | Closed source selector cannot import its stale graph; G5 | Retire local/incoming graph for C; G3/G5 | Same classification as A, never an unconditional exemption; §5 |
| Restore C: archive deletes m2, target revoked alias owned by m2, C live through m1 | m2 is not a survivor; keep its target link pending final deleted-message pass, then G3/G4 P−; m1 selector stays usable | Idempotent P− | Fenced cleanup remains G3/G4 | Incoming undeleted m2 cannot override deletion authority | Source deletion dominates exact m2 owner | Fence dominates too | Preserve captured manifest through load-bearing final trigger, then normalize/erase §5 |
| Restore generic merge / preserved archives / missing preparation | Keep only copies backed by surviving owners; G5/G6 | Exclude selector copies in every destination; G5 | Exclude payload copies; G5 | Filter by accepted references before archiving or inserting; G5 | No graph or archived alias provenance; G5 | No graph or archived payload provenance; G5 | Normalize in private generation, never rewrite source archive; §5 |
| Fresh full restore / native data restore | Normalize copied target before index publication; G5/G6 | Existing local veto applied by native/shared merge; G5 | Same | Fresh graph accepted only after normalization; G5 | Honor archive's own lookup/deletion authority; G5 | Honor archive's own fences; G5 | Same normalizer on fresh-copy path; §5 |

The three restore rows are different witnesses. A target with only a payload
fence and no alias reference cannot test local pre-delete capture. A target with
a live alias and an incoming fence must test that capture. Neither substitutes
for the lookup-only case where another selector still owns the payload, or for
incoming deletion authority that must retire a still-linked target alias.

## 4. Commit-boundary arguments

### 4.1 Erasure transactions

The transaction is `AccountDb::write_transaction` (`A/runtime/config.rs:154-165`),
or the hold's explicit immediate transaction. The message trigger runs within
its caller's transaction. Do not rely on relative execution order of independent
AFTER triggers: the object body must capture its own graph before its own
destructive statements; footprints use their existing indexed ownership rules.

1. Begin writer transaction; initialize operation work once. For message delete,
   capture exact references attached to the deleting message before owner-edge
   deletion; retain hashes still owned by another non-erased message.
2. Seed payload retirement according to existing retention classes. Expand
   transport parents recursively to a fixed point. Only then capture every
   still-present reference of every retired commitment, including ancestors,
   and copy selector identities into projection work. Earlier captures survive.
3. Persist opaque lookup witnesses when final selector ownership becomes empty.
   Delete owner/reference edges and reference-actor links, perform G4 projection
   cleanup, and remove matching placeholders before deleting their payload
   identity rows. G4 can use the captured manifest even if restore deleted the
   reference earlier. A surviving same-selector reference prevents deletion;
   surviving other-selector ownership does not.
4. Retire payload copies/resources as already required, write append-only payload
   fences and wire lookups, advance account erasure generation if any private
   selector/reference state was removed, drain work and commit. The generation
   must advance for alias-only removal with `C` still live. Post-commit observers
   continue to retire cached keys/spools; they do not repair missing SQL cleanup.

Before COMMIT, a fault rolls back the reference, placeholder and lookup changes
together. After COMMIT, reopening and another export see no retired alias. The
reference-deletion inventory in §1.2 is the proof obligation: each DELETE must
consume identities captured in this transaction after final closure expansion.

Hold reachability is concrete: create unreferenced pre-send child, transport
parent with private alias reference and placeholder, and dependency
parent→child. Assert the child is still `pre_send` and has no reference before
release. Release seeds child; recursive expansion adds parent; G3 captures the
parent's reference. Repeat with a grandparent and with message deletion seeding
the child. Never manufacture a referenced direct pre-send hold to bypass its
eligibility guard.

### 4.2 Restore: classification precedes every writer

Run all steps within the existing `BEGIN IMMEDIATE`/COMMIT of
`A/backup_merge.rs:94,159-160,236`. Keep incoming read-only. Put new private
classification work in the encrypted staging database, not plaintext TEMP:
operation tables keyed by `(side,reference_hash,message_id)` for accepted owner
edges, `(side,selector,commitment)` for selector decisions, and `(side,lookup)`
for pre-union lookup origin (§2.2), plus the existing row exclusions. Index
selector/commitment, reference hash and lookup/side; pending target deletion
uses `backup_target_delete` rather than the accepted-edge table. Drop work before
commit, rollback and discard staging on errors. These are scratch tables,
excluded from generic merge and snapshots; they add no wire/archive field.

1. Validate account roots, schema sentinel, authenticated payload commitments,
   reference→payload consistency, selector lookups recomputed with the target
   root and reference-hash/selector identity consistency. Recompute reference
   hashes over the canonical inner attachment reference used by the SDK, not
   the `ReceivedAttachment` wrapper containing prepared local state. Verify imported lookup
   witnesses against their reference when present. Preserve opaque orphaned
   lookup witnesses when no plaintext mapping remains. Validate dependency
   classes. Snapshot **both** inputs' selector lookup witnesses into
   `backup_lookup_origin` now, before any union; preserve dual provenance when
   the same lookup exists on both sides. Capture wire witnesses as well when
   the existing table does not distinguish wire and selector lookups. No later
   classification may reconstruct side from main after it has been unioned.
   Failure rolls back the entire attempted restore.
2. Union payload fences and wire/selector lookup witnesses. Expand dependency
   fences over both input graphs to a fixed point. Build deletion authority
   from **both** sides' deleted projections, sticky markers and message/group
   tombstones, before admitting any reference. Incoming undeleted projections
   cannot overwrite that authority later.
3. Capture local live witnesses from the pre-merge target graph after applying
   deletion and payload fences. A witness needs a non-deleted owner; the mere
   presence of a reference row, actor or placeholder is insufficient. A partial
   lookup plus a genuinely surviving target witness stays live. For a new wire
   identity, require the exact existing replacement receipt and full existing
   wire-identity checks. An old alias is never authorized by that receipt.
   Separately mark existing target reference hashes whose owners are deleted
   only by incoming authority in `backup_target_delete` (called
   `pending_target_delete` below). This is cleanup work,
   not an admitted live witness. Retain those physical reference/owner links
   until step 9 unless step 6 captures and erases them via G3/G4 for a payload
   fence. A reference shared with another non-deleted owner retains that owner.
4. Classify **all** incoming references, even selectors without a placeholder.
   Exclude if payload fenced, every owner deleted, identity malformed, or target
   selector closed. Query `backup_lookup_origin(side='target')`, not unioned
   main, for the target veto. A target lookup with no local witness blocks incoming stale
   same-identity rows even if the source claims a live owner. A lookup learned
   only from `backup_lookup_origin(side='incoming')` can retain incoming references only when that same input
   has independently valid surviving owners (legacy partial lookup); closed
   incoming lookup never creates new target references. Independent valid target
   witnesses are preserved under selector-only incoming history. Payload fences
   dominate these exceptions.
5. Resolve every candidate placeholder selector through the **unfiltered** input
   reference→payload mapping before deleting it. Classify its known or legacy
   manifest (§5). Retain an `original_legacy_zero` flag through arbitration even
   if the staged manifest has been normalized. If blocked, record an opaque selector lookup using the resolved
   `C`, exclude the placeholder **before** wire-ID reuse conflict checking, and
   exclude all of its rejected reference hashes/owner edges. Do not put an alias
   into payload erasure work as though it were a wire. If unresolved and unowned,
   exclude its provenance without inventing a payload identity or payload fence.
6. Immediately before the local fenced-reference DELETE (base line 157), capture
   every local reference it will remove, with resolved manifest. Also seed local
   `object_erasure_work` from fenced **retention payload identities**, including
   unmaterialized aliases; do not rely solely on `scan_objects` finding a wire
   row. Run G3/G4 after shared dependency expansion, preserving the pre-delete
   capture. Remove local selector copies classified closed, except the
   `pending_target_delete` reference/owner links, their placeholders and cleanup
   bindings needed by step 9. Do not detach them with generic DELETE/filter SQL:
   their last-owner retirement must run G3/G4. References removed in this step
   cannot be recreated by step 7.
7. Import payload rows subject to payload fences; reference rows only from the
   admitted reference set; message edges only from admitted owner edges;
   reference-actor rows only from admitted reference hashes. Copy bindings and
   footprints are reconstructed only from admitted owners. Never import a
   reference first and hope the final deleted-message trigger removes it: N4's
   missing message edge prevents that cleanup.
8. Apply the **same decision set** to actor and archived actor/event copies,
   generic SQL merge, missing selectors, object merge and private archive
   preservation. For a shared actor, reproject from admitted references; do not
   retain rejected reference JSON inside a shared value. For a mixed archived
   event, redact the rejected selector/reference subvalue into a non-replayable
   historical copy, preserving unrelated content/owners; mark redacted event
   copies `signature_status='retired'` and clear their signature rather than
   claiming the changed body authenticates under the original signature. Never reinsert the
   original bytes into another archive table. Exact selector actor keys and
   reference-actor bindings are indexed candidates. Decode bounded historical
   JSON only in the existing archive traversal; oversized/unclassifiable
   selector-bearing candidates fail closed with ownership-unverified rather
   than silently bypassing exclusions. Object arbitration is unchanged for
   admitted identities: current tombstones win; ordinary timestamp rules and
   payload identity conflict checks still apply. For `pending_target_delete`,
   filter all incoming/archive copies now but retain the existing target
   reference/owner links and cleanup state until step 9. Their physical
   presence does not admit their provenance to a preservation writer.
9. The final deleted-message pass (`A/backup_merge.rs:236`) is **load-bearing**
   for target aliases whose owner is deleted by incoming authority while C
   remains live through another selector (matrix Restore C). Apply the merged
   tombstones/deleted projections and re-fire `UPDATE ... SET deleted=1 WHERE
   deleted=1` with those target links intact; the installed object/message
   triggers then capture and retire that alias through G3/G4. E20 must prove
   the alias was still linked immediately before this pass and its captured
   placeholder/reference/actors are gone afterwards, with m1 still usable.
   Never call this pass optional defense in depth. Verify no rejected
   reference/owner/binding/projection or placeholder exists, surviving selectors
   still resolve, and work is empty; then COMMIT. This is a bounded check over
   the operation decision set, not a scan of unrelated account history.

The lookup-only witness must finish with successful restore, no alias reference,
owner edge, reference actor, placeholder, directory value or archived alias
provenance, `check_object_access(alias)=ObjectErased`, and continued access
through the other selector owning the unfenced payload. Fence union alone
cannot achieve this: base `merge_graph` tests only the commitment.

### 4.3 Replacement, access, export and installation

Replacement captures the old reference closure after its existing expected
identity/active-owner checks, then G3/G4 and new verified payload/receipt share
the same writer transaction. It does not delete the old fence. Replacements
have a different commitment; an archive cannot relabel an old alias as the new
wire to evade selector erasure. Test both valid new wire access and stale old
private-selector refusal in the same fixture.

The replacement alias-capture subcase uses explicitly injected or legacy
ownerless reference/placeholder rows: compliant G2/G4 state cannot produce that
combination once the last owner is gone. The public replacement eligibility
check (`A/object.rs:49`) must still pass. This is defense against historical
state, not a claim that an actively message-owned alias can be replaced.

Access must consult the admitted ownership/identity interpretation before either
base early return (`R/mod.rs:146-151`, `backup_object_erasure.rs:217-218`). A
known-manifest alias placeholder is not a wire payload. Resolve its reference
identity, check the payload fence, and interpret any selector lookup using a
live owner or exact replacement witness. No witness plus lookup returns
`ObjectErased`, even if an orphan reference was injected by a regression.
No lookup and an existing unmanaged legacy orphan retain the documented upgrade
boundary; do not label it newly authenticated ownership.

Export requires no account-size cleanup scan on the writer. G4/G5 establish the
committed graph before snapshot; SQLite pins a coherent snapshot. Capture its
account privacy generation, then recheck via the ordered writer before archive
publication as today. G4 must advance that generation on selector-only erasure.
If deletion wins, discard staged archive/key; if publication authorization wins,
the archive is an external pre-delete copy. Add a race witness where only an
alias is erased and another selector still owns `C`.

Staging COMMIT and selecting an account generation are distinct boundaries.
Existing writer/generation leases remain held through integrity verification
and durable index publication (`J/install.rs:98-101,160-186`,
`J/native.rs:182-247`). On fresh full restore, direct copy at
`J/install.rs:245-248` must invoke the same single-input normalization/admission
logic before archive activation and index selection. It must honor the archive's
own fences and deletion authority; absence of a current local account does not
justify retaining an internally orphaned placeholder. Native restore uses the
same two-input classification. Fault before index commit leaves the selected
old generation intact; fault after it follows existing generation recovery.

Own-copy history import authenticates the page outside the SQL transaction.
Its actual transport-owner registration (`K/client/object.rs:1053`) passes
historical G1 context inside the page transaction, alongside deletion
projection, transport binding and receipt. A narrow refusal must be consumed
without indefinite retry; it cannot grant the transport a fresh-message
exception merely because the page was signed. Base history import does not
materialize message attachment references, so no attachment-alias absence
fixture or mutation is claimed for it (E15/U24 withdrawn). Future history
attachment materialization would need G1 before all row/binding/actor writes
and separate acceptance; it is not part of these proposed cards. Never apply a
historical revocation just because its event was archived. No history wire
format change is proposed.

### 4.4 Account erase coverage boundary

There is no current account-erasure transaction to extend. Locking/unloading
an account, changing an index flag, deleting a manifest or deleting a key file
does not establish removal of encrypted database generations and snapshots.
No implementation card here invents that API. If account-wide erase is added,
its contract must acquire the account writer/generation lease, prevent export
publication/import, revoke readers/resources, retire **all** selected/staged
generations and locally owned keys, and commit a durable removal/recovery marker
before reporting completion. A database-only DELETE is insufficient. Tests and
fault recovery for that capability belong to its own prerequisite design; the
present matrix records it as unsupported, with no account-erase acceptance claim.

## 5. Compatibility and legacy zero-manifest placeholders

Keep archive authentication, schema checksum floor, explicit replacement receipts
and ordinary object arbitration. Never mutate the user's input archive. New
missing-row revocations do not manufacture a zero manifest. Update the existing
missing-source zero test to assert `AuthorizationRejected` and absence; fixtures
for old archives may still write zero rows explicitly. The base late-import
test creates a placeholder from display metadata alone
(`A/object_revocation_tests.rs:90-100`). Give that fixture an authenticated live
reference/owner before revocation; keep all tombstone shape and late-import
assertions. Add a separate display-only refusal case. This changes the admitted
fixture to match G2, rather than weakening the late-import veto assertion.

Nonzero legacy actor manifests have a separate compatibility obligation from
the zero-row table below. A valid peer revoke with an undiscovered received
actor and an agreeing client-record owner must still create a veto, as it does
at the base (`K/client/routed/control.rs:143-164`, `A/object.rs:172-186`). The
same holds for a live ownerless legacy reference after discovery; no known
deletion/fence may veto it. G2's legacy branch is evaluated without requiring
a retention owner edge or finishing all discovery pages. E19 checks this
storage behavior, and E11 exercises its signed inbound outcome. This branch
does not let discovery insert an ownerless row or an archive reopen a closed
selector; those are historical G1/G5 decisions.

At restore or when an erasure closure touches a legacy payload-free row:

| Legacy case | Decision |
| --- | --- |
| Live admitted selector mapping resolves one manifest | Normalize the private staged row to that manifest and classify exactly like a known-manifest placeholder. Keep sender/envelope provenance only while the reference survives. |
| Incoming zero placeholder restores over a live known wire object | Keep the base identity-neutral conflict exemption and timestamp arbitration; if the tombstone wins and a live reference is admitted, inherit its verified manifest. A newer live row can still win as in the existing regression. |
| Another same-selector reference survives a partial lookup | Preserve and normalize the revocation veto using that reference. Never use the historical lookup alone to delete it. |
| Selector/payload erased, or all its owners rejected | Exclude zero placeholder and rejected graph in the same transaction; record resolved selector lookup where identity is known. Successful restore does not retain erased provenance. |
| No authenticated ownership can be resolved | Omit the unowned payload-free placeholder and its selector-only copies from the staged restore; do not mint a payload commitment from zeros. Other valid data can restore. Missing graph integrity or conflicting authenticated identities fail with existing ownership-unverified/authorization errors, rather than guessing. |
| Existing untouched live-store zero/orphan row | No startup account-wide scrub in this round. Its historical export limitation remains §8. Reset or a separately authorized reconciliation is needed for a global guarantee. |

This deliberately supersedes the input proposal's blanket “all zero-manifest
rows keep restoring unchanged.” Accepting old archives does not require
republishing an unowned or erased placeholder. Existing tests with a real live
reference keep their behavioral assertions and zero-fixture coverage; additional
tests require omission for unowned/fenced zero rows. The mutation must actually
exclude a **live admitted** legacy row to fail the compatibility test; merely
removing a nonzero predicate may match no fence and prove nothing.

No new persistent domain table or wire field is required. Keep the existing
reference-work columns and pin manifests by retaining their payload identity
rows through cleanup, as G3 specifies. Restore uses encrypted scratch admission
tables with explicit reference/owner and selector keys (§4.2), dropped before
publication. Their indexes must be installed before candidate classification.

P1 introduces schema version **13**, a new migration checksum and a migration-1
writer-floor sentinel naming version 13. Rebuild generated erasure triggers in
that upgrade transaction. The published migration-12 checksum remains unchanged;
retain explicit v12 validation when accepting older archives, then normalize a
private staged copy and advance it to v13 before installation. Do not rewrite
the original archive or pretend v12 had the stronger selector semantics. An
older binary must refuse a v13 account/archive through the established sentinel
and version checks. This floor protects the changed reference-admission and
trigger behavior even though no persistent domain columns are added. Upgrade
does no whole-account orphan scrub. Add v12-read/v13-write, old-writer refusal
and migration-rollback tests: P1 owns live-store upgrade/old-writer/rollback
subcases in E10; P2 owns private archive upgrade/rollback subcases in E14.

## 6. Review closure

Labels below identify the three earlier review rounds. They describe design
closure, not a claim that the corresponding implementation/test already passes.

| Round / finding | Design closure |
| --- | --- |
| r0 H1: capture before final recursive retirement misses parents | G3, §4.1 after-closure capture in the shared SQL; parent and grandparent tests E3/E4; mutations U3/U4. |
| r0 M1: two different selectors cannot test the surviving-selector guard | E2 uses distinct hashes sharing one selector, both with valid owners; U2 removes the survivor condition. |
| r0 M2: referenced direct hold cannot reach release deletion | §4.1 eligible unreferenced child→referenced transport ancestor, with eligibility assertion; E3/U3. |
| r0 M3: row counts and SEARCH plan do not prove bounded work | §7.3 per-statement and end-to-end SQLite VM-step assertions, independent index-defeating mutations U15/U16. |
| r0 source masking / inbound outcome notes | G2; E10/E11 remove both alternative manifest sources and run valid authenticated input through receive/quarantine/ACK. |
| r0 legacy / payload-only projection scope notes | §5 replaces blanket restore exemption; G4 includes projections/bindings for retired selectors on payload-only paths; untouched legacy stores and account erase remain explicit §8. |
| r1 N1: target payload fence misses incoming private alias placeholder | G5 steps 1-5 resolve the unfiltered incoming graph, exclude row and graph, write alias lookup; E5/U7/U8. |
| r1 N2: wrong restore direction cannot test pre-delete capture | G5 step 6; E6 starts with a local live alias and incoming fence, separately asserts local capture and work survival; U5/U6. |
| r1 N3: display manifest masks retention fallback removal | E10 asserts absent actor and owner-only display metadata before revocation; U11 must fail. |
| r2 N4: lookup-only successful restore resurrects reference despite missing owner edge | G5 steps 3-9 cover the whole selector graph before generic/archive merge; G1/G6 guard later imports and reads. E7 asserts all-table absence, access refusal and other-selector access; U9 restores commitment-only reference merge while placeholder exclusion remains. |
| r2 partial same-selector and explicit replacement caution | §2 definitions, G1/G5, E2/E8/E9 preserve independent live references and exact new wire replacement without reviving old aliases. |
| r2 mutation feasibility note for legacy exclusion | §5, E12/U14 require a live admitted zero row with an observable winning revocation; no nonmatching predicate-only mutation is counted. |
| Design review H1: permanent selector veto breaks fresh authenticated receipt | Owner-keyed G1 and G6 admit fresh m3 after m2 deletion, even for the same deterministic selector; E16 also rejects m2 replay without retry. E17/U17 isolate the historical lookup veto with no deleted candidate owner. |
| Design review M1: own-copy attachment materialization absent at base | §1.2 and §4.3 state the real transport-owner registration; E15/U24 withdrawn. Future attachment materialization is a residual, not an acceptance claim. |
| Design review M2: discovery bypasses registration | G1/§2.2 wire `discover_reference` before its INSERTs; E18/U27 check archived aliases and ownerless candidates. |
| Design review M3: undiscovered/unowned legacy revoke lost | G2/§5 explicitly preserve the nonzero actor/authorized-owner legacy branch; E19 storage and E11 signed inbound subcases. |
| Design review M4: lookup origin lost on union | §2.2/§4.2 step 1 snapshot both sides before step 2; step 4 queries origin scratch; E8 reverse case and U28. |
| Design review M5: incoming deletion leaves target alias orphaned | Restore C, `backup_target_delete`, steps 3/6/8/9 preserve links until load-bearing final trigger; E20/U29. |
| Design review M6: acceptance assignment gaps/duplicates | §7 tables give exactly one owner to every active E/U; P2 owns restore capture and its E6/U5/U6, plus E8/E9/U26; P1 owns U15/U16. |
| Design review M7: generation mutation masked | U19 withdrawn: existing `R/schema.rs:119` (message owner deletion) and `:69` (payload work) already bump every named path. E13 retains generation/publication assertions, without an independent U19 kill claim. |
| Design review L1: U9 access assertion masked by G6 | U9 fails graph/all-table/snapshot absence; hardened access still returns `ObjectErased`. |
| Design review L2: replacement alias capture needs historical state | §4.3 and E4 label injected/legacy ownerless alias state explicitly; compliant code cannot produce that fixture. |
| Design review L3: fact/mechanism corrections | §1.1 contrasts `merge_graph` with row exclusions; matrix attributes revoke no-op to `A/object.rs:167-169`; own-copy facts corrected. |

The old “payload-only projection residue is out of scope” decision is obsolete
for copies belonging to selectors this operation retires: leaving those copies
would defeat N4 closure and subsequent snapshot absence. Broad historical
reconciliation of unrelated pre-existing residue remains outside this round.

## 7. Implementation split and acceptance evidence

These are proposed cards, not authority to start implementation. Split by
responsibility; do not claim the lifecycle invariant delivered until all cards
and affected controller acceptance complete. Each card must pin its actual
merged base and retain the base regression suite, full SDK gates when receive
behavior changes, and the normal provenance/transaction checks.

| Proposed card | Complete implementation responsibility | Acceptance |
| --- | --- | --- |
| P1: storage selector lifecycle | G1-G4/G6 identity resolution, explicit fresh/historical admission API and legacy discovery/revoke branches, nonzero creation, shared erasure capture/cleanup; message trigger and non-restore payload callers, preserving generation advances. New responsibility modules rather than growing large object/SQL files. | E1, E2, E3, E4, E10, E18, E19; U1, U2, U3, U4, U10, U11, U13, U15, U16, U18, U25, U27, U30; capture/cleanup and delete/retire VM budgets (§7.3). |
| P2: restore graph admission | Depends on P1. G5 lookup-origin capture, two-input/single-input classification; restore pre-delete capture with work survival; inverse directions, final target-owner deletion; all copy filters, legacy normalization, native/fresh hooks. No deferred generic-copy fix. | E5, E6, E7, E8, E9, E12, E14, E17, E20; U5, U6, U7, U8, U9, U14, U17, U20, U21, U22, U23, U26, U28, U29, U31; restore classification VM budget (§7.3). |
| P3: SDK receive and transport-owner integration | Depends on P1/P2. Pass correct authenticated fresh/historical context at peer receive and actual own-copy transport registration; consume narrow refusals without retry loops; signed control compatibility, snapshot-publication race, public lifecycle docs and release note. No new history attachment materialization. | E11, E13, E16; U12; full SDK and attachment CLI tests, controller slices below. |

The fixture/mutation owner columns below are exhaustive: no cross-card double
credit. P1 exports primitives that P2 later wires to restore; P1 does not claim
restore witnesses before P2 exists. E15, U19 and U24 are withdrawn, not deferred
implementation obligations. Keep their IDs unused to preserve review history.

### 7.1 Required fixtures and observations

Every successful erasure/restore test must reopen storage, assert operation work
empty, take an encrypted snapshot and inspect all its relevant tables. Use the
existing generic `sqlite_master`/all-column canary scan
(`A/message_footprint/tests.rs:220`, `R/tests.rs`) for private selector, revocation
sender and revocation-envelope canaries. At a stage with another legitimately
live reference, use unique retired-reference/slot canaries and explicit graph
checks; do not forbid a shared payload's still-authorized provenance. After
both owners die, no plaintext canary remains anywhere. Opaque hashes may remain.

| Test | Owner | Required witness and assertion |
| --- | --- | --- |
| E1 selector lifetime | P1 | `m1→wire`, `m2→alias` share C, revoke alias, delete m2 then m1 and reverse order. Alias dies with its own last reference even while C remains; other selector stays usable; no exported alias row. Direct G6 subcase injects an ownerless alias reference behind a closed lookup and requires `ObjectErased`; no restore dependency. |
| E2 selector survivor | P1 | Two distinct reference hashes with different message owners share alias and manifest. First delete puts alias in work but retains its tombstone; second deletes it. Also shared-hash/two-owner case. Exercise historical partial lookup explicitly. |
| E3 recursive erasure | P1 | Eligible hold child→transport parent and two-hop ancestor chain, message-seeded chain and direct transport retirement. Distinct private selectors/wires prevent incidental wire-row cleanup from masking capture. Assert hold eligibility and G4 projection/reference-actor cleanup as well as placeholder absence. |
| E4 other payload callers | P1 | Replacement with checked eligibility, legacy maintenance with direct guard and reachable retiring ancestor. Replacement alias capture explicitly injects legacy ownerless reference/placeholder rows (§4.3); never call that state producible by compliant G2/G4. The reachable hold/transport E3 cases independently kill U4. Assert projections/bindings as well as placeholder absence. |
| E5 target payload fence | P2 | Target has C fence, no alias row/reference/lookup. Archive contains live alias reference, owner, actors and known placeholder. Restore succeeds; alias lookup now exists, graph/provenance absent; alias access erased. |
| E6 incoming payload fence | P2 | Target has live alias reference/placeholder and no alias lookup. Archive has C fence learned through another selector. Prove reference exists before pre-delete, capture survives body entry, row/graph removed and lookup recorded. No local wire object is required. |
| E7 lookup-only N4 | P2 | Target deletes m2 alias while m1 wire keeps C live; no C fence. Older archive contains m2 alias graph/placeholder, actor aliases and archived copies. Successful restore must not import alias reference even though C is unfenced; no owner, actor/binding/provenance or subsequent snapshot canary; `ObjectErased(alias)`, `Ok(wire)` and unchanged m1 payload. Retain D7-style object exclusion for U9: graph/all-table/snapshot assertions kill it; G6 still refuses access. Also incoming reference with no placeholder. |
| E8 partial historical lookup | P2 | Target partial alias lookup plus distinct live alias owner: archived deleted reference rejected, existing reference/placeholder survive. Reverse case has **no target alias lookup or witness**, incoming partial lookup plus valid source owner: restore admits that source survivor and its winning veto. Assert pre-union origin rows and run U28. Shared selector with conflicting identities refuses atomically. |
| E9 explicit replacement | P2 | Real checked new wire manifest/receipt restores and remains accessible despite old wire lookup; old payload fence retained, old aliases cannot return. Removing/forging receipt refuses replacement. |
| E10 manifest sources and live-store upgrade | P1 | No actor/display manifest, retained live reference only: correct manifest required. No sources: typed refusal, no row. Conflicting retention manifests and no alternatives: refusal. Stale display metadata cannot override authenticated mapping. Display-only owner metadata cannot create a placeholder. Live-store v12→v13 writer floor, old-writer refusal and migration rollback subcases (§5). Existing late-import/upsert regression uses a live owned reference and proves its veto survives. |
| E11 signed control receive | P3 | Owning peer sends a valid signed revocation; metadata owner-only, actor/retention sources absent: `InboundRejected`→`routing_rejected`, remove retry/unrouted, dead-letter and attempt ACK, no retry on second receive. Also valid legacy actor + agreeing owner with no retention edge: success, nonzero placeholder and late-fetch veto, no dead-letter. Base chain: `K/client/routed/mod.rs:336-337`, `K/client/inbox_failure.rs:43-44`, `K/bus/sync_driver.rs:472-510` and following quarantine/ACK. Storage/I/O failures still propagate. |
| E12 legacy archive compatibility | P2 | Zero incoming over live known wire, current tombstone over newer payload and current-newer live row retain arbitration. Alias zero with live reference, fenced zero, unowned zero and zero against closed lookup: first remains revocation-capable, erased/unowned cases cannot export provenance. |
| E13 publication generation | P3 | Pause export before authorization, delete alias with other selector alive, resume: job refused and discarded. Repeat payload-only erasure and authorization-first ordering. Assert generation increases independently of payload fence count. Existing bumps already cover these paths; no U19 kill is claimed. |
| E14 atomic staging and archive upgrade | P2 | Fault after capture, fence union, graph admission, archive preservation, before SQL COMMIT and index selection. Selected generation unchanged on failure, all four scratch tables absent on success, source archive hash unchanged. Full/native/fresh normalization and staged v12→v13 upgrade/rollback subcases (§5). |
| E16 fresh owner reopens selector | P3 | Bob's m1 owns wire, Carol's m2 owns deterministic alias, same C. Delete m2 while C stays live; assert closed alias lookup and absent alias reference. Carol sends fresh authenticated m3 with the same wire/selector: admit reference/owner/actors, alias usable after reopen. Replay m2: owner deletion still refuses, ACK/skip or deterministic rejection without retry. A payload fence still refuses m3. Exercise actual routed receive, pending-contact release and direct reference callers; unrelated valid messages progress. |
| E17 historical lookup alone | P2 | On one device, delete m2 alias while m1 wire keeps C live. A sibling archive contains distinct historical m3 using the same selector, never seen/deleted on target. Assert `message_is_deleted(m3)==false` and no m3 deletion authority on either input, C unfenced, no target alias survivor, target lookup present. Restore succeeds but omits m3's attachment reference/owner/bindings while unrelated m3 content follows normal merge. U17 omits only historical lookup admission: forbidden graph rows appear; graph absence is the kill, with no claim about access under the mutation. This is a historical owner, unlike fresh E16. |
| E18 legacy discovery | P1 | Archived alias actor/context behind closed lookup, with a distinct live non-deleted m3 projection and unfenced C retained through another selector; the lookup came from deleted m2, not m3. Run the bounded discovery page: no reference/owner/binding is inserted. A separate no-lookup candidate without an admissible projection is classified `unowned_legacy`, also inserts no reference. Control with valid owner/no veto registers normally. U27 removes the historical lookup check only in discovery; graph absence fails, independent of deletion/fence guards. |
| E19 live legacy revoke | P1 | Existing received actor with nonzero manifest and agreeing client-record owner, no placeholder and no retention owner edge: valid caller-authenticated revoke creates correct placeholder before discovery completes. Repeat with live `unowned_legacy` state after discovery. Neither fixture has closed lookup, payload fence or known deleted owner. Deferred import still vetoed; no fabricated retention edge. Known owner deletion/fence and conflicting manifest cases refuse/no-op as specified. |
| E20 incoming deletion against target alias | P2 | Target m2 owns revoked alias, m1 owns wire sharing C; no fence/lookup. Archive supplies m2 tombstone only. Prove alias reference/owner link intact immediately before final deleted-message pass, and no m2 live witness admitted. After pass: alias placeholder/reference/actors/bindings gone, alias lookup exists, C unfenced and m1 usable; reopen/snapshot has no retired alias provenance. U29 omits the final deletion pass; remaining graph rows must fail absence. |

### 7.2 Independent mutation witnesses

Run each mutation alone, record failing assertion and nonzero exit, restore
source hashes, and rerun its healthy test. A compile failure, unrelated timeout
or zero test matches is not a mutation kill. These clauses are consequences of
the single invariant, not separate lifetime rules.

| Mutation | Owner | Consequence isolated by a required test |
| --- | --- | --- |
| U1 restore old payload-work-dependent placeholder predicate | P1 | E1 leaves alias row after m2 deletion while m1 owns C. |
| U2 remove same-selector survivor guard | P1 | E2 first deletion wrongly removes still-needed tombstone. |
| U3 move shared capture before recursive expansion | P1 | E3/E4 lose parent/grandparent selector capture. |
| U4 omit shared capture | P1 | Reachable E3 hold/transport aliases survive retirement; E4 historical replacement is additional coverage, not the only witness. |
| U5 omit restore pre-delete capture | P2 | E6 loses the already-deleted local alias. |
| U6 clear captured references at payload-body entry | P2 | E6 loses nonempty restore work; P2 owns restore-specific placement even though the shared body originates in P1. |
| U7 omit incoming alias identity classification | P2 | E5 imports orphan alias placeholder. |
| U8 exclude placeholder but omit discovered selector lookup | P2 | E5 access is not `ObjectErased`; target began with no lookup. |
| U9 restore commitment-only incoming reference merge, retaining placeholder exclusion | P2 | E7 imports alias reference without owner edge; graph/all-table/snapshot absence fails. G6 still returns `ObjectErased`, so access is not its kill. |
| U10 replace shared missing-reference/manifest refusal with old zero-manifest insertion | P1 | E10 succeeds or inserts a row when refusal required; mutate the single G2 decision, not an unreachable fallback behind another guard. |
| U11 remove retention manifest source with both alternatives absent | P1 | E10 valid fallback refuses instead of creating correct veto. |
| U12 propagate narrow authorization refusal as raw storage error | P3 | E11 loses deterministic classification/ACK and retry outcome. |
| U13 accept first disagreeing retention identity | P1 | E10 conflict fixture creates forbidden row. |
| U14 unconditionally exclude live legacy zero placeholder | P2 | E12 loses incoming winning tombstone over older live wire row. |
| U15 defeat object selector candidate index (`object_id||''`) | P1 | Standalone G4 VM-step budget fails at large unrelated N. |
| U16 defeat commitment capture index (`commitment||''`) | P1 | Standalone G3 VM-step budget fails independently of U15. |
| U17 omit historical closed-selector check in G5 admission, keeping owner-deletion/payload checks | P2 | E17 imports forbidden reference/owner/binding; both inputs lack deletion authority for candidate m3, so the lookup is the sole refusing guard. This does not mutate fresh-message admission. |
| U18 return payload-access success before closed lookup with orphan reference | P1 | Direct E1 injected-ownerless-reference subcase returns Ok. |
| U20 run placeholder exclusion after wire reuse conflict | P2 | E7 restore aborts rather than succeeding without alias. |
| U21 omit exclusion/redaction in archive preservation while graph stays filtered | P2 | E7 post-restore all-table/snapshot canary finds alias provenance. |
| U22 omit fresh-copy normalization | P2 | E14 publishes copied archive with internally erased/orphaned placeholder. |
| U23 treat every historical lookup as unconditional selector erasure | P2 | E8 loses live same-selector reference/veto, or E9 rejects verified new wire. Run exception branches separately if implemented separately. |
| U25 let ordinary upsert replace tombstone | P1 | E10 existing late-import/upsert regression loses live revocation veto. |
| U26 defeat restore admission candidate indexes while preserving row decisions | P2 | Isolated classification VM-step budget (§7.3) grows with unrelated local N and fails, outside whole-archive traversal. |
| U27 bypass historical lookup admission only in `discover_reference` | P1 | E18 archived alias gains reference/owner despite closed lookup; candidate m3 is not deleted and C not fenced, so no masking guard. |
| U28 classify lookup origin from unioned main instead of `backup_lookup_origin` | P2 | Reverse E8 wrongly treats source-only partial lookup as closed target veto and loses valid incoming reference/winning placeholder. |
| U29 omit final deleted-message pass as a whole | P2 | E20 keeps target m2-linked alias reference/placeholder; retained links prove steps 6/8 did not already do that retirement. Do not mutate only redundant re-fire SQL after another deletion update has already fired the trigger. |
| U30 write zero instead of resolved authenticated creation manifest | P1 | E1 last-message cleanup leaves a placeholder whose manifest no longer matches captured identity. Distinct from missing-source refusal U10. |
| U31 remove identity-neutral legacy conflict exemption | P2 | E12 live-wire restore conflicts instead of accepting winning legacy zero tombstone. Distinct from live-row exclusion U14. |

Withdrawn U19 had no independent witness: existing generation bumps at
`R/schema.rs:69,119` mask omission of an extra G4 advance on every named path.
Keep E13's ordinary generation/publication regression and preserve those bumps;
do not invent another bump solely to create a mutation. E15/U24 targeted absent
own-copy attachment materialization and are withdrawn for that reason.

### 7.3 Work budgets

Use SQLite VM operations, not deleted-row counts or plan wording. Measure the
actual G4 candidate DELETE, each G3 capture/lookup statement, restore admission
candidate lookup and full message-delete/transport-retire operations. For a
fixed affected closure at unrelated N = 0, 1,000, 10,000 references, payloads,
placeholders and actor bindings, require for **each** measurement:

```text
steps(N) <= ceil(steps(0) * 1.05) + 64
```

Read `StatementStatus::VmStep` on fully stepped standalone statements. Count
end-to-end VM operations with a progress hook at interval 1, enabled only for
test builds if an extra feature is needed. Prepare/fixture creation, archive
encryption, physical checkpointing and test-only canary enumeration are outside
the measured SQL window; triggers are inside it. Keep identical affected graph
and statement parameters across N; warm/reset counters explicitly. Do not
silently raise budgets after a failing mutation. Preserve exact selectivity and
EXPLAIN index checks as supporting evidence.

Restore necessarily traverses incoming data and already scans local object/copy
tables. Do **not** claim the entire restore is independent of archive/account
size. Measure its new classification statements separately over fixed candidates
with unrelated local N using the bound above; then fix local state and vary
incoming candidates M = 1, 10, 100, requiring classification VM work no greater
than `M * steps_one_candidate + 64` after scratch-index setup. Full restore work
can grow with rows/bytes it actually reads. U15/U16 must each fail its isolated
constant-closure budget; a third mutation bypassing classification indexes must
fail the restore candidate budget. Neither can be masked by archive traversal.

### 7.4 Gates and controller realnet

Implementation cards must run product license/provenance/identity/transaction
checks, file-size gate, fmt, strict workspace all-target/all-feature Clippy and
required full product tests; P3 runs full SDK plus attachment CLI tests. Verify
test filter counts before targeted tests and retain existing erasure, legacy
restore, replacement and cached-import regressions. Storage/SDK local tests do
not establish cross-service acceptance.

Controller acceptance slices: `att_cli_born_v3` (revoke/fetch/delete/backup
behavior), `s35` (sibling-copy deletion and replay ordering),
`restore_cli_born_v3` (native data restore after selector-only and payload
erasure). These born-v3 names identify required controller acceptance surfaces;
do not assume they are literal CI matrix keys. The inspected integration
workflow at `1287c93bde6c2619c5410527521f0add8a85e811` has literal keys `s35`
(activation/fanout), `s48` (own-history sync), `k12` (deferred attachment fetch)
and `s47` (restore/rejoin). Controller dispatch must select the born-v3 harness
tests for the new witnesses, plus the applicable existing sync/restore slices;
existing activation/fanout alone does not test alias deletion. Product storage/SDK changes require no server
deployment; controller test agents own containers, QA and realnet. This design
round runs none of those slices.

## 8. Residuals

- This document is a proposal at its stated base. It repairs the design, not
  the running privacy defect; no implementation gates or mutation kills have
  been executed for the proposed behavior.
- No unconditional whole-store claim is made for pre-existing untracked orphan
  placeholders, ambiguous legacy keys or unrelated historical projection
  residue. No startup scrub is introduced. New operation closures and normalized
  restore outputs must satisfy the invariant; a fresh/reset compliant store is
  the premise for its global inductive form.
- History-message attachment materialization is absent at the evidence base.
  This design wires historical admission at the existing transport-owner call;
  it does not introduce the missing materialization feature or count an
  attachment-alias fixture against that nonexistent path.
- Account-wide erase is unsupported in the reviewed surface (§4.4). Lock/unload
  and local generation replacement are not account erasure acceptance.
- A fresh restore from only a pre-delete external archive has no knowledge of
  later deletion. Data on other devices, relays, published archives and bytes
  already returned to callers are outside device-local erasure.
- Existing restore scans and bounded legacy decoding remain costs; the new
  constant-closure budgets do not turn whole-account restore into constant work.
- Mixed archived copies must be filtered before any preservation writer. If
  implementation cannot classify one safely within the existing bounds, it
  must refuse that restore atomically with an ownership diagnostic; it cannot
  call placeholder-only absence successful privacy closure.
- No protocol, service architecture, license, toolchain or cryptographic domain
  change is proposed. The public backup lifecycle prose must be corrected with
  implementation: its current last-message claim is broader than the base
  alias-cleanup behavior (`docs/account_backup.md:329-342`).
