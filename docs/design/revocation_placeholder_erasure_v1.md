# Revocation placeholder erasure v1

Status: proposed design; no implementation or runtime acceptance is claimed.
Evidence base: `0d6da88fb189201a44eefe611d5e79c39ef77661` (2026-11-04).
This base contains attachment erasure commit
`38e41095de34ada4e711390e96a577dbaea717f5` and revocation commit
`81e59c3032f69b627e421ced8b137c5e995e0a2c`.

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
| `backup_erased_copy` | Base TEMP exclusion set, PK `(database_name,table_name,row_id)`, used by object merge, generic merge and archive preservation. Excluding an object does not automatically exclude a retention reference. | `A/backup_object_erasure.rs:28,186-190,347-351`; `A/backup_merge.rs:324-335,358,454-459` |
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
| Own-copy import | Signed history page authentication precedes decoding; `K/client/own_device_sync.rs:269-325` imports a page, binds transport owners and receipt in a writer transaction. Bundle import is transactional at lines 677-683; own deletion and message import at lines 694-760 use ordinary deletion authority. It is not a raw backup-table importer. Attachment references materialized from messages must use the same registration guard as peer receive. |

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
  actor or a reference with no admissible owner cannot resurrect ownership.
- A payload fence covers exactly `C`, unconditionally. It dominates all
  selectors, reference hashes and timestamps. A selector lookup covers an
  erased selector in the absence of a surviving independently admitted
  reference for that selector/identity. It is not a payload fence for another
  selector that shares `C`.
- Existing partial-reference lookups are historical witnesses: if a distinct
  reference for the same selector still has a valid owner, retain that
  reference and its revocation veto. This live witness is established before
  candidate incoming rows are admitted. An incoming row cannot declare itself
  live to bypass a target's closed selector lookup.
- Explicit identity replacement is the existing checked wire operation and
  exact new-commitment receipt. It can establish the new identity despite an
  old wire lookup; it never clears an old payload fence. It grants no blanket
  exception for private aliases or old references.

The invariant applies inductively to compliant state and to the complete touched
closure of each operation below. Existing unmanaged store orphans are a stated
upgrade residual (§8), not evidence that a new operation may create another
orphan. New restores normalize legacy placeholders before publication (§5).

### 2.1 Proposed common decisions

**G1 — reference admission.** At receive/own-copy registration, after acquiring
the writer transaction, check payload fence, message deletion authority and
selector status before writing any retention row, owner edge, binding or actor.
For a lookup-bearing selector, allow an already surviving same-identity
reference to gain another authenticated non-deleted owner; otherwise refuse
stale reference admission with `ObjectErased`. Ordinary import cannot create an
explicit replacement receipt. Reject conflicting selector identities rather
than choosing an arbitrary reference hash.

**G2 — manifest and placeholder admission.** One shared resolver decides whether
a missing row has an admissible reference identity; callers do not add redundant
fallback guards that would mask a mutation of that decision. New missing-row placeholders require
an admitted live reference and a nonzero manifest. Resolve actor reference first,
then the retention reference/payload join, then client record. Retention identity
must agree across live references; verify that any selected actor/display
manifest agrees with the authenticated mapping. Display-only owner metadata is
not ownership proof. No source or disagreement means `AuthorizationRejected`
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
An independently surviving same-selector reference or valid new wire replacement
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
| G1/G2 identity and admission | `A/object_retention/selector_admission.rs`: one selector identity resolver and reference-admission decision; call from `R/mod.rs` registration, `R/actors.rs` actor guard (including selector in the actor key and indirect alias values), and `A/object.rs` missing-row revocation. `K/client/routed/control.rs` owns the narrow error mapping. |
| G3/G4 capture and cleanup | `A/object_retention/selector_erasure.rs`: SQL builders for capture, surviving-owner projection and retirement cleanup; compose them into the existing `R/schema.rs` message and payload bodies after dependency expansion. `A/backup_object_erasure.rs` performs its additional pre-delete capture. The existing payload/work rows keep the manifest available until cleanup. |
| G5 graph classification | `A/backup_selector_admission.rs`: encrypted operation decision tables, two-input classification and single-input normalization. `A/backup_object_erasure.rs`, `A/backup_merge.rs`, `A/backup_missing.rs`, `A/backup_native.rs` and fresh `J/install.rs` consume that decision; archive preservation cannot invent a separate veto interpretation. |
| G6 access/publication | Shared resolver used by `R/mod.rs::check_object_access` and restore copy filtering; erasure generation advanced by the G4 builders. `J/workers.rs` keeps the current publication authorization boundary. Own-copy materialization uses the G1 storage entrypoint within its existing page transaction. |

Restore scratch names are `backup_reference_admission` with columns
`side,reference_hash,message_id,selector,commitment` and PK
`(side,reference_hash,message_id)`, and `backup_selector_admission` with columns
`side,selector,commitment,decision` and PK `(side,selector,commitment)`.
Decisions are `keep`, `erase` or `unowned_legacy`; only accepted owner edges enter
the reference table. Add indexes `(side,selector,commitment)` and
`(side,commitment,reference_hash)` on accepted edges, and retain local witnesses
as a separately identified pre-merge side until classification finishes. Stage
unresolved legacy rows in existing row exclusions rather than inventing C.
Both operation tables are in encrypted main and are dropped before COMMIT.

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
| Authenticated revoke | P+ via G2; K with partial lookup | No row, consumed no-op via G1/G2 | No row, stronger veto via G2 | Admit live reference first; then G2 | No resurrection via G1 | No resurrection via G1 | New zero forbidden; refusal G2; old row §5 |
| Reference creation / peer receive | K; preserve tombstone via G1/G2 | X before retention/actors via G1 | X via identity check + G1 | Admit non-deleted owner via G1 | X via G1 | X via G1 | Cannot use unknown manifest to admit reference; §5 only on archive boundary |
| Late payload import / own-copy reference materialization | K; tombstone still vetoes upsert via G1 and existing upsert guard | X/skip erased item via G1 | X/skip erased item via G1 | G1 before actor or copy binding | Exclude stale copy via G1 | Exclude stale copy via G1 | Not a source of new zero placeholders |
| Message delete (DM, group, sibling) | P− on last selector owner, otherwise K; G3/G4 | Idempotent P−; G4 | P−; G3/G4 | Incoming delete runs same trigger after authenticated import; G3/G4 | No restored owners; G1/G5 | No restored owners; G1/G5 | Touched row normalized from captured reference then erased, or retained with surviving reference; §5 |
| Payload-only transport retirement | Capture full ancestor closure, P−; G3/G4 | Idempotent P−; G4 | P−; G3/G4 | No raw incoming payload cleanup; G5 classifies first | G5 P− | G5 P− | G4 uses captured identity, not zero hash; §5 |
| Pre-send hold release/drop | Direct referenced hold ineligible; eligible child retires referenced ancestors, P− via G3/G4 | No selector to recreate; G4 | Idempotent G3/G4 | No incoming hold release API | G5 excludes instead | G5 excludes instead | Ancestor case handled by §5/G4 |
| Legacy retention maintenance | Direct reference/revocation guard K; eligible ancestor closure G3/G4 | No recreation; G4 | G3/G4 P− | Discovery must not accept erased owners; G1 | G1 rejects | Payload fence checked by discovery/G1 | Preserve ambiguous untouched store rows; normalize touched closure §5 |
| Explicit wire identity replacement | Active old owner forbids replacement; otherwise retire old G3/G4 and insert verified new identity | Only checked expected-absence/new receipt may succeed; §4.3 | Old C stays fenced, new C may succeed; §4.3 | Exact receipt for new wire C accepted; G5 | Old aliases excluded; G5 | Old C always excluded; G5 | Never infer a replacement receipt from zero manifest |
| Account erase | No supported API at base; §4.4 specifies required future behavior | Same boundary | Same boundary | No account erase import API | No account erase import API | No account erase import API | No claim that lock, unload or index removal erases old rows |
| Backup export | P+ and K exported in committed graph; G6 | P−, opaque lookup exported; G4/G6 | P−, opaque fence exported; G4/G6 | No incoming graph in export | No incoming graph in export | No incoming graph in export | Existing untouched store limitation §8; normalized restore output has no unresolved zero row |
| Restore A: target veto, archive candidate | K independent target survivors; G5 | P− incoming selector graph, successful restore; G5 | P− all incoming references to C; G5 | Admit only if no target veto; P+ after arbitration | Source closed selectors excluded; G5 | Source fences unioned first; G5 | Resolve and classify before arbitration; §5 |
| Restore B: archive veto, target live | Payload fence retires target graph; selector-only witness preserves independent target survivor; G5/G4 | Remain P−; G5 | Remain P−; G5 | Independent unfenced selectors survive; G5 | Closed source selector cannot import its stale graph; G5 | Retire local/incoming graph for C; G3/G5 | Same classification as A, never an unconditional exemption; §5 |
| Restore generic merge / preserved archives / missing preparation | Keep only copies backed by surviving owners; G5/G6 | Exclude selector copies in every destination; G5 | Exclude payload copies; G5 | Filter by accepted references before archiving or inserting; G5 | No graph or archived alias provenance; G5 | No graph or archived payload provenance; G5 | Normalize in private generation, never rewrite source archive; §5 |
| Fresh full restore / native data restore | Normalize copied target before index publication; G5/G6 | Existing local veto applied by native/shared merge; G5 | Same | Fresh graph accepted only after normalization; G5 | Honor archive's own lookup/deletion authority; G5 | Honor archive's own fences; G5 | Same normalizer on fresh-copy path; §5 |

The two restore rows are different witnesses. A target with only a payload
fence and no alias reference cannot test local pre-delete capture. A target with
a live alias and an incoming fence must test that capture. Neither substitutes
for the lookup-only case where another selector still owns the payload.

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
edges and `(side,selector,commitment)` for selector decisions, plus the existing
row exclusions. Index selector/commitment and reference hash; drop work before
commit, rollback and discard staging on errors. These are scratch tables,
excluded from generic merge and snapshots; they add no wire/archive field.

1. Validate account roots, schema sentinel, authenticated payload commitments,
   reference→payload consistency, selector lookups recomputed with the target
   root and reference-hash/selector identity consistency. Recompute reference
   hashes over the canonical inner attachment reference used by the SDK, not
   the `ReceivedAttachment` wrapper containing prepared local state. Verify imported lookup
   witnesses against their reference when present. Preserve opaque orphaned
   lookup witnesses when no plaintext mapping remains. Validate dependency
   classes. Failure rolls back the entire attempted restore.
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
4. Classify **all** incoming references, even selectors without a placeholder.
   Exclude if payload fenced, every owner deleted, identity malformed, or target
   selector closed. A target lookup with no local witness blocks incoming stale
   same-identity rows even if the source claims a live owner. A lookup learned
   only from incoming can retain incoming references only when that same input
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
   capture. Remove local selector copies classified closed. References removed
   in this step cannot be recreated by step 7.
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
   payload identity conflict checks still apply.
9. The final deleted-message pass remains defense in depth. Verify no rejected
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

Own-copy history import authenticates the page outside the SQL transaction and
then runs G1 before ownership/reference materialization inside the page writer
transaction, together with deletion projection, transport binding and receipt.
Never apply a historical control simply because its event was archived. A stale
attachment is skipped with the existing typed erased-item outcome; no reference
or selector provenance is added by that skipped item. Unrelated page messages
and valid surviving selectors remain importable. This does not add propagation
of object revocations to the history wire format.

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
and migration-rollback tests to P1/P2.

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
| P1: storage selector lifecycle | G1-G4/G6 shared identity resolution, reference admission/read checks, nonzero creation, erasure capture and cleanup, generation advance; all five payload-only callers and message trigger. New responsibility modules rather than growing large object/SQL files. | E1-E4, E8-E10, E13; U1-U6, U10-U13, U17-U19; VM budgets for capture/cleanup and delete/retire. |
| P2: restore graph admission | Depends on P1. G5 two-input and single-input normalization; inverse restore directions; object/reference/owner/actor/archive filters; legacy normalization; native and fresh installation hooks. No deferred generic-copy fix. | E5-E9, E12/E14; U5-U9, U14/U20-U23; existing merge/replacement/attachment verification regressions. |
| P3: SDK receive and own-copy integration | Depends on P1/P2. Narrow deterministic refusal mapping, real receive path, history/copy materialization guard, snapshot-publication race evidence, public lifecycle docs and release note. | E11/E13-E15; U12/U19/U24/U25; full SDK and attachment CLI tests; controller slices below. |

### 7.1 Required fixtures and observations

Every successful erasure/restore test must reopen storage, assert operation work
empty, take an encrypted snapshot and inspect all its relevant tables. Use the
existing generic `sqlite_master`/all-column canary scan
(`A/message_footprint/tests.rs:220`, `R/tests.rs`) for private selector, revocation
sender and revocation-envelope canaries. At a stage with another legitimately
live reference, use unique retired-reference/slot canaries and explicit graph
checks; do not forbid a shared payload's still-authorized provenance. After
both owners die, no plaintext canary remains anywhere. Opaque hashes may remain.

| Test | Required witness and assertion |
| --- | --- |
| E1 selector lifetime | `m1→wire`, `m2→alias` share C, revoke alias, delete m2 then m1 and reverse order. Alias dies with its own last reference even while C remains; other selector stays usable; no exported alias row. |
| E2 selector survivor | Two distinct reference hashes with different message owners share alias and manifest. First delete puts alias in work but retains its tombstone; second deletes it. Also shared-hash/two-owner case. Exercise historical partial lookup explicitly. |
| E3/E4 all erase callers | Eligible hold child→transport parent and two-hop ancestor chain, message-seeded chain, direct transport retirement, replacement with checked eligibility, legacy maintenance with direct guard and a reachable retiring ancestor. Distinct private selectors and wire IDs prevent incidental wire-row cleanup from masking missing capture. Assert G4 projection/reference-actor cleanup as well as placeholder absence. |
| E5 target payload fence | Target has C fence, no alias row/reference/lookup. Archive contains live alias reference, owner, actors and known placeholder. Restore succeeds; alias lookup now exists, graph/provenance absent; alias access erased. |
| E6 incoming payload fence | Target has live alias reference/placeholder and no alias lookup. Archive has C fence learned through another selector. Prove reference exists before pre-delete, capture survives body entry, row/graph removed and lookup recorded. No local wire object is required. |
| E7 lookup-only N4 | Target deletes m2 alias while m1 wire keeps C live; no C fence. Older archive contains m2 alias graph/placeholder, actor aliases and archived copies. Successful restore must not import alias reference even though C is unfenced; no owner, actor/binding/provenance or subsequent snapshot canary; `ObjectErased(alias)`, `Ok(wire)` and unchanged m1 payload. Retain D7-style object exclusion while testing graph mutation U9. Also test an incoming reference with no placeholder. |
| E8 partial historical lookup | Target has partial alias lookup and a distinct live alias reference/owner; archived deleted reference is rejected but existing alias reference/placeholder survive. Reverse input side for source partial lookup with a valid source owner and no target veto. Shared selector with conflicting identities refuses atomically. |
| E9 explicit replacement | Real checked new wire manifest/receipt restores and remains accessible despite old wire lookup; old payload fence retained, old aliases cannot return. Removing/forging receipt refuses replacement. |
| E10 manifest sources | No actor and no display manifest, retained live reference only: correct manifest required. No sources: typed refusal, no row. Conflicting retention manifests and no alternatives: refusal. Stale display metadata cannot override authenticated mapping. Display-only owner metadata with no live ownership cannot create a placeholder. |
| E11 authenticated receive refusal | Owning peer sends a valid signed revocation; metadata owner-only, actor/retention sources absent. Real receive loop must yield `InboundRejected`→`routing_rejected`, remove retry/unrouted, dead-letter and attempt ACK, then no retry on second receive. Base chain: `K/client/routed/mod.rs:336-337`, `K/client/inbox_failure.rs:43-44`, `K/bus/sync_driver.rs:472-510` and its following quarantine/ACK flow. Storage failure outside the narrow refusal still propagates. |
| E12 legacy compatibility | Zero incoming over live known wire, current tombstone over newer payload, and current-newer live row cases retain base arbitration. Add alias zero with live reference, fenced zero, unowned zero and incoming zero against closed lookup. First remains revocation-capable; erased/unowned cases cannot export provenance. |
| E13 publication generation | Pause export after snapshot but before authorization, delete only alias with other selector alive, resume: staged job refused as erased and discarded. Repeat a payload-only erasure and authorization-first ordering. No dependence on new payload fence count. |
| E14 atomic staging | Inject failure after capture, fence union, graph admission, archive preservation, before SQL COMMIT and before index selection. Verify selected generation unchanged on failure, scratch absent after success and source archive hash unchanged. Run full and native paths; fresh full copy normalizes its own internally fenced/deleted graph before publication. |
| E15 own-copy | Valid authenticated page/copy with stale alias after local lookup-only erasure: no reference, actor or binding reappears; valid other selector and unrelated messages import. Both deletion-before-copy and copy-before-deletion; replay and reopen. Revoked live reference still vetoes late payload import. |

### 7.2 Independent mutation witnesses

Run each mutation alone, record failing assertion and nonzero exit, restore
source hashes, and rerun its healthy test. A compile failure, unrelated timeout
or zero test matches is not a mutation kill. These clauses are consequences of
the single invariant, not separate lifetime rules.

| Mutation | Consequence isolated by a required test |
| --- | --- |
| U1 restore old payload-work-dependent placeholder predicate | E1 leaves alias row after m2 deletion while m1 owns C. |
| U2 remove same-selector survivor guard | E2 first deletion wrongly removes still-needed tombstone. |
| U3 move shared capture before recursive expansion | E3/E4 lose parent/grandparent selector capture. |
| U4 omit shared capture | E3/E4 payload-only direct/ancestor aliases survive retirement. |
| U5 omit restore pre-delete capture | E6 loses the already-deleted local alias. |
| U6 clear captured references at payload-body entry | E6 loses nonempty restore work. |
| U7 omit incoming alias identity classification | E5 imports orphan alias placeholder. |
| U8 exclude placeholder but omit discovered selector lookup | E5 access is not `ObjectErased`; target began with no lookup. |
| U9 restore commitment-only incoming reference merge, retaining placeholder exclusion | E7 imports alias reference without owner edge; graph/access/all-table assertions fail. |
| U10 replace the shared missing-reference/manifest refusal with the old zero-manifest insertion | E10 succeeds or inserts a row when refusal is required; mutate the single G2 decision, not an unreachable fallback behind another ownership guard. |
| U11 remove retention manifest source with both alternatives absent | E10 valid fallback case refuses instead of creating the correct veto. |
| U12 propagate narrow authorization refusal as raw storage error | E11 loses deterministic classification/ACK and retry outcome. |
| U13 accept first disagreeing retention identity | E10 conflict fixture creates a forbidden row. |
| U14 unconditionally exclude live legacy zero placeholder | E12 loses the incoming winning tombstone over an older live wire row. |
| U15 defeat object selector candidate index (`object_id||''`) | Standalone G4 VM-step budget fails at large unrelated N. |
| U16 defeat commitment capture index (`commitment||''`) | Standalone G3 VM-step budget fails independently of U15. |
| U17 omit selector check in registration | E15/E10 stale lookup-only alias gets a reference/owner/binding. |
| U18 return payload-access success before closed lookup with an orphan reference | Direct E7 access hardening subcase, with an intentionally injected ownerless alias reference, returns Ok. |
| U19 omit generation advance on last-selector removal | E13 publishes the overtaken snapshot. |
| U20 run placeholder exclusion after wire reuse conflict | E7 restore aborts rather than succeeding without alias. |
| U21 omit exclusion/redaction in archive preservation while graph stays filtered | E7's post-restore all-table/snapshot canary finds alias provenance. |
| U22 omit fresh-copy normalization | E14 publishes a copied archive with an internally erased/orphaned placeholder. |
| U23 treat every historical lookup as unconditional selector erasure | E8 loses live same-selector reference/veto, or E9 rejects verified new wire. Run the two exception mutations separately if implemented in separate branches. |
| U24 bypass admission in own-copy materialization | E15 restores stale alias on authenticated copy/page import. |
| U25 let ordinary upsert replace tombstone | Existing late-import regression/E15 loses live revocation veto. |
| U26 defeat the restore admission candidate indexes while keeping row decisions unchanged | The isolated restore classification VM-step budget in §7.3 grows with unrelated local N and fails; whole-archive traversal is outside this measurement. |

Retain existing zero-manifest-at-creation and legacy-conflict regression intent:
replace authenticated known manifest with zeros to fail last-message cleanup;
remove identity-neutral legacy conflict exemption to fail the live-wire restore
case. These are distinct from U10 and U14 and require actual runtime failures.

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
