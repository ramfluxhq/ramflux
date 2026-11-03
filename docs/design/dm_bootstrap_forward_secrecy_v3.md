<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026 Span Brain -->

# Born-v3 DM bootstrap forward secrecy

**Design revision 2, 2026-11-03. Proposal; no production implementation or runtime
acceptance is implied.** Rotating private prekeys belong exclusively to unlocked account
data. The vault supplies long-term branch agreement authority for individual bootstraps,
but contains no prekey derivation API. New bootstrap requires the signed
`ramflux.dm.bootstrap.fs.v1` profile. After ordinary gateway handoff, branch-signed prekey
requests use the existing authenticated gateway grant; the custody session is not retained.

Policy is settled: weekly SPK rotation, 14-day public validity, at most 21 days of normal
private SPK retention, seven-day delivery, durable account/pair/target/prefix lease quotas,
strict directory lease-time expiry, and a bounded receive-only old-format activation grace.
The constants and failure policies below are contracts for the subsequent implementation
cards. Every future test and mutation in this note remains unexecuted in this design round.

## 1. Source baseline and write-path inventory

The branch's unchanged runtime baseline is `51d9222a100d5c2800229d3fc4b98e39c2f710b4`.
The following contracts were rechecked against main snapshot
`fa3d6917f75bc3d2ab23c7458b3bb325a9bcf485`; the listed SDK bootstrap, custody,
gateway, node and protocol sources are unchanged at fetched main
`361f5c53b9b7fa1041280ed53e8204f9e4b7855e`. Historical lifecycle work at `76e78846`
and `d384e25e` is reference evidence; its legacy authority and retention policy are not
native acceptance evidence.

| Source | Current behavior / required implementation boundary |
| --- | --- |
| [Vault credentials](../../crates/ramflux-sdk/src/custody/vault.rs) | `signed_prekey_seed` derives an SPK from the retained agreement secret; `prekey_bundle` uses a fixed native ID. Remove these constructors, not just their callers. |
| [Native initializer](../../crates/ramflux-sdk/src/client/native_branch.rs) | Reconstructs SPK state and copies `identity_seed` into account events. Replace it with verified branch/provider loading and explicit migration. |
| [Account networking](../../crates/ramflux-sdk/src/bus/state.rs) | `prepare_native_branch` invokes initialization only when `device_branch.is_none()`. Every later bootstrap/registration must validate the provider independently of this once-per-daemon signer guard. |
| [Private prekeys](../../crates/ramflux-sdk/src/client/private_prekeys.rs), [DM bootstrap](../../crates/ramflux-sdk/src/client/dm_session.rs) | Read secret-bearing events; send DH1 and receive DH2 currently load `identity_seed` from the store. Replace both with the vault-backed operation described in section 2. |
| [Custody registration](../../crates/ramflux-sdk/src/custody/network.rs), [node admission](../../crates/ramflux-node-core/src/custody_service/admission.rs) | Registration independently calls the credential bundle constructor; node Register writes a public row. Both must use the canonical provider and the common verified transaction. |
| [Ordinary router publish](../../apps/ramflux-router/src/handlers.rs), [native directory](../../crates/ramflux-node-core/src/custody_authority/directory.rs) | `handle_mvp1_prekey_publish` calls `publish_custody_prekey`, which accepts a public branch-signed bundle and overwrites native storage without a fresh requester proof or counter floor. This is a replay/rollback bypass to close. |
| [SDK handoff](../../crates/ramflux-sdk/src/gateway/custody.rs), [ordinary engine](../../crates/ramflux-sdk/src/gateway/engine.rs), [gateway proxy](../../apps/ramflux-gateway/src/custody.rs) | Handoff drops the custody proxy and sends Disconnect. Keep that lifetime contract; add explicit signed prekey frames to the ordinary engine. Ordinary PrekeyFetch remains a public read. |
| [Native redb](../../crates/ramflux-node-core/src/router_store/custody.rs) | Existing public rows lack lease/floor/result storage. New state belongs to native custody authority, without legacy device-set fallback. |
| [Envelope limits](../../crates/ramflux-protocol/src/replay.rs), [inbox retention](../../crates/ramflux-node-core/src/inbox.rs) | `MAX_ENVELOPE_TTL_SECONDS = 604_800`; `inbox_retain_until` caps at `min(created_at + ttl, accepted_at + 7 days)`. This determines the delivery horizon. |
| [Custody limits](../../crates/ramflux-protocol/src/custody/mod.rs), [account admission storage](../../crates/ramflux-node-core/src/router_store/custody_accounts.rs) | Roster ceiling 1024, ordinary enrollment ceiling 960, skew 300 seconds; node admission ceiling 65,536 accounts and existing authority-row ceiling 16 MiB. Prekey accounting must be added explicitly. |

Only native DM bootstrap is activated by this design. Established ratchets and legitimate
historical message access remain intact. This is X25519/X3DH, with no post-quantum claim.
Native home migration remains unavailable until its authority fence exists.

## 2. Canonical secrets, agreement-key access and unlock

One mutable device-local account actor owns current/retained SPKs, private OPKs, counters,
public publication snapshots, lease metadata, activation floors and erasure markers.
It is keyed by account anchor, device ID, epoch and signing/agreement commitments. A pool
generation has an increasing ordinal plus fresh incarnation tag; SPKs and OPKs have their
own monotone serials and fresh IDs. None of these identifiers derives a private key.

The vault retains long-term signing/agreement authority only. Delete
`BranchCredentials::signed_prekey_seed`, `BranchCredentials::prekey_bundle`, the fixed
`custody-prekey-v1` constructor ID, and `custody/network.rs::prekey_bundle`. Registration
must accept only a committed public `PrekeyPublicationSnapshot` from the unlocked provider.
Do not replace these methods with a renamed deterministic helper or a native call into
`identity.rs::create_and_store_prekey_bundle`. The removal must compile with all native
callers adapted; production-source inventory also checks for reintroduced rebuild APIs.

**Long-term agreement source: load branch credentials from the vault per new bootstrap.**
Send DH1 and receive DH2 borrow `BranchCredentials.agreement` in a zeroizing operation
context, after checking current native authority and both key commitments. They do not
read `identity_seed` from account data. Load only branch credentials, never primary signing
authority. Drop the operation context and temporary secret buffers on success, error and
cancellation. Transport retains no agreement key and no SPK/OPK private bytes.

Perform a blocking vault load outside the account writer. Recheck the account unlock
and vault unlock epochs, selected owner and authority before entering the writer/crypto
operation and committing its result;
a lock racing the load invalidates it and drops the credentials. No writer guard spans a
network await. An explicit data/vault lock suspends maintenance and new bootstraps and
closes the corresponding networking path through the existing lock lifecycle. A vault
access refusal is temporary, not permission to use a cached agreement secret. History
remains readable whenever account data itself is unlocked; no locked-data networking mode
or authority-only connection mode is added.

`initialize_born_v3_branch` becomes verified signer/provider loading. It must never write
an actor from credentials. Fresh authorized branch creation explicitly provisions CSPRNG
state once; a recorded legacy-data migration is separate. An initialized marker with a
missing, corrupt or foreign actor yields `prekey_repair_required`. Unknown missing state
is also repair-required, not fresh creation. Data-only restore requires attended new-device
recovery. The once-per-daemon initializer does not replace per-operation provider checks.

Migration retires every secret-bearing `x3dh.prekey.private` event, `x3dh_private:*`
projection/checkpoint, actor and archived copy containing `identity_seed`. The canonical
actor stores only the vault reference and public agreement commitment. Verify decoded
storage-API absence, secure deletion, actual checkpoint completion and reopen; an encrypted
file byte scan is not an agreement-secret erasure proof.

## 3. Time, rotation and delivery contract

Let `T = MAX_ENVELOPE_TTL_SECONDS = 604_800` seconds and
`S = CLOCK_SKEW_SECONDS = 300` seconds. Deadlines are exclusive: accept a bootstrap only
while `now < D`; equality and later are expired. Skew does not extend `D` or public SPK
validity. Reject a directory lease time later than `now + S`. Use a durable monotone local
maintenance watermark; erase nothing while wall time is behind it. New bootstraps/leases
fail with `prekey_clock_untrusted` until time is usable, while history stays readable.

| Item | Contract |
| --- | --- |
| SPK generation | Independent CSPRNG, fresh ID/serial; rotate every `T` while online. |
| SPK signed validity | `expires_at <= created_at + 2T` (14 days); reject a new selection at expiry. |
| SPK private bound | Retire at `expires_at + T`, no later than `created_at + 3T` (21 days). Four total private/pending SPK slots, including any temporary old-format receive slot. Expiry is enforced on reads. |
| OPK pool | Start with 8; below 2 directory-unleased keys, add fresh IDs to restore 8. Preserve outstanding private keys. |
| OPK private bound | 200 slots across retained generations, including erasure-pending keys. Process retirement before refill; at the bound use a valid new-profile SPK-only result. |
| Consumed OPK | After successful authentication, remove in the advanced-ratchet/replay transaction. Complete storage retirement before releasing its slot. |
| Unused leased OPK | Remove individually only when `now > leased_at + T + S`. At the exact threshold, just before it, unleased and missing-time entries survive this rule. No extra local-observation grace. |
| OPK bootstrap deadline | `D <= min(leased_at + T, SPK expires_at + T, envelope created_at + ttl)`, with `ttl <= T`. |
| SPK-only bootstrap deadline | `D <= min(bootstrap issued_at + T, SPK expires_at + T, envelope created_at + ttl)`, with `ttl <= T`. This is the new profile's explicit no-OPK mode. |
| Lease-result retention | Only through `D`, at most `T` after lease; at six target leases/hour, at most 1008 live results per target. |
| Initiator secrets | Fresh independent X3DH `E` and initial ratchet `R0`; never persist `E` or the original X3DH root. |

The node's existing inbox cap still applies and may expire an entry earlier than `D`.
The sender never renews envelope creation time/TTL to extend a frozen bootstrap. No
sender-side store is promised to provide delivery beyond this horizon. SPK retention
covers every permitted deadline: a lease selects an unexpired SPK, then delivery lasts at
most another `T`. The additional OPK skew margin is a retirement safeguard, not extra
message-validity time. Normal canonical SPK access ends at 21 days; a blocked WAL checkpoint
remains visibly erasure-pending and cannot be advertised as completed forward secrecy.

Before transmitting or retrying a frozen packet, check `D`. If it expired before emission,
retire that unsent bootstrap operation/session, retain the application's pending message,
and obtain a new lease/operation with new `E`, `R0`, envelope and increasing bootstrap
sequence. Never resend the expired ciphertext or reuse its lease under a new header.
If prior emission is uncertain, preserve existing delivery/idempotency evidence while
settling the old attempt; a fresh attempt cannot rewind replay/ordering floors or duplicate
the application's send. The receiver refuses an expired `D` even if a private key remains.

OPKs belong to the pool generation, not one SPK rotation. Unleased keys can remain through
rotation; the lease binds one to the then-current SPK. Lease times come only from the
current authenticated home for known IDs. Unleased/missing status never undoes a known
lease, consumption or retirement. A false old directory timestamp can cause availability
loss; the directory can already withhold messages, and this design adds no observation grace.

## 4. Native writes, public views and OpenSession

Make one floor-checked redb transaction the only writer of native prekey state. It accepts
a verified native owner update, produced by either custody Register proof verification or
the signed ordinary owner operation in section 5. Both paths enforce the same profile,
current authority/capability, counter, generation, serial, resource and byte rules.
`admission.rs` Register must call this transaction instead of writing the row directly.
The raw `record_custody_prekey` writer cannot remain an alternate unverified entry point.

**Ordinary `/mvp1/prekey` publication is closed for native identities.** HTTP publish and
old `GatewayClientFrame::PrekeyPublish` return the typed refusal
`native_publication_requires_custody`, with no native row/floor change and no fallback to
`mvp1_publish_prekey`. Resolve native anchors from all claimed qualified identity/principal
bindings before the legacy writer can run. Known native, fenced and unavailable native
authority never become a legacy fallback merely because current verification failed.
A replayed older public base or deterministic bundle is refused even if branch-signed.
The new signed ordinary owner frame is a custody-authorized operation; it is distinct from
this old public-bundle publish endpoint.

| Proposed type | Contents / visibility |
| --- | --- |
| `SignedNativePrekeyBase` | Profile, qualified branch and commitments, agreement public key, generation, SPK ID/serial/public key, times, public counter/capabilities and branch signature. At most 2 KiB encoded. |
| `SignedNativeOpk` | Domain, qualified branch/generation, increasing serial, fresh ID/public key and independent branch signature. At most 512 bytes. |
| `OwnerPrekeyUpdate` | Signed base, additive OPK batch and completed-retirement acknowledgements. Owner-authenticated; public counter identity excludes independent idempotent retirement control metadata. |
| `PublicPrekeyView` | Independently verifiable signed base plus current native authority evidence; no OPK pool, chosen OPK or owner ledger. No legacy compatibility projection. |
| `PrekeyLeaseIntent` | Qualified requester/target, expected base/profile, issue/selection times and random nonce. Operation ID hashes every intent field except itself with a domain separator. |
| `PrekeyLeaseResult` | Current verified base, zero or one signed OPK, requester/target/operation binding, lease time/deadline or a bounded fallback reason. No owner ledger. |
| `OwnerPrekeyStatus` | Durable publication/floor acknowledgement, activation time, retirement-ack digest, unleased count and status for at most 200 requested owner IDs. No requester identity or private material. |

`base_hash` commits to the canonical signed base. The new `prekey_bundle_hash` commits to
that hash, selected OPK record or explicit absence, and lease/deadline binding. The
bootstrap carries the signed public base/selected record so it need not reconstruct an
old whole-pool publication. Length-prefix variable fields and fix canonical vectors.
Ordinary GET/Lookup, custody Peer, nested manifests, SDK projections, discovery and public
acknowledgement fields all use `PublicPrekeyView`, never the upload object unchanged.

Initial custody operations are versioned Register with `OwnerPrekeyUpdate` and owner-only
proof `PrekeyStatus` before OpenSession (register capability). Cold status reconciles a
lost acknowledgement, expired SPK or full old lease pool without requiring an existing
messaging session. It can acknowledge historical expired publication bytes but cannot
make them a fresh base. `OpenSession` requires a current native-authorized, correctly
bound, unexpired new-profile base at the durable profile/counter floor and `message`
capability. Zero available OPKs does not prevent opening. Expiry routes to cold status,
local rotation and fresh Register; stale raw rows never grant a session.

## 5. Post-handoff authentication: selected transport

**Chosen: grant-bound branch-signed ordinary gateway frames.**

| Alternative | Authentication | Session/resources and cleanup | Test/implementation cost |
| --- | --- | --- | --- |
| Retain custody session after handoff | Existing custody proof/session, plus signed requests and current authority checks. | Changes Proxy Drop/Disconnect, TCP/QUIC handoff and session renewal; keeps a node custody slot alongside the ordinary connection. | Requires new lifetime/renewal ownership and generic custody-wrapper interleaving. Rejected. |
| Grant-bound signed prekey frames | End-to-end branch signature over action, audience, grant/session context, fresh nonce and expiry; gateway attestations and current native authority independently checked. | Uses the existing ordinary grant; custody Disconnect remains at handoff, with no new held slot or cleanup lifetime. | Adds specific frames, common request verification and bounded durable nonce markers. Selected. |

Add ordinary `NativePrekeyLease`, `NativePrekeyPublish` and `NativePrekeyStatus` frames
carrying a branch-signed `NativePrekeyRequest`; use a correlated bounded result frame.
This is not the old unauthenticated `PrekeyPublish` and not a generic `CustodyRequest`
wrapper. Initial Register/cold proof status still use the custody connection before handoff.
No additional live custody-session action or second control connection is needed.

The outer signed body binds a domain/profile, operation kind and canonical argument hash,
source qualified branch/current authority hash, target/home generation, receiving node
ID/current node-record hash, gateway ID and ordinary session ID, fresh request nonce,
issued time and expiry (at most five minutes). The immutable lease operation ID is
separate from this fresh outer request. The existing branch signer signs; transport sees
only public provider snapshots and never the agreement/SPK/OPK secret.

The gateway requires its actual validated native grant/session to match the signed source
and session context, derives identity and observed client source as ordinary Submit does,
and forwards unchanged signed bytes with that grant-derived evidence over the production
authenticated async mesh. Caller JSON cannot manufacture a grant or source prefix. The
router verifies authorized gateway evidence, branch signature, current native certificate,
key/epoch/head/home fence, action capability and body hash, audience/session binding, nonce
and expiry. Lease needs `message`; owner publish/status need `register` and exact owner
scope. The node applies its existing ingress prefix masking to the verified source; the
shared gateway address and caller-selected prefixes never become quota identities.

Request nonce admission and the action's state changes commit together. Keep bounded
nonce markers through the full possible request lifetime (600 seconds), including restart;
a duplicate outer envelope is Replay. A legitimate retry signs a fresh outer nonce and
session binding but keeps the lease operation ID. Durable idempotency returns its original
OPK without another charge. This adds small nonce writes even for read/fallback operations;
owner rate limits and the global prekey request budget below bound the cost. No TLS-binding
mode is weakened, and no credential-derived or legacy-authority fallback is introduced.

SDK replies use existing ordinary response serialization/Deliver buffering; test that a
lease wait never discards an interleaved Deliver. Existing ordinary grant expiry/reconnect
continues unchanged. After reconnect sign fresh context, retry the same live operation,
and never reuse a signed request on another socket. Test TCP/QUIC native handoff, router
restart, a one-session-per-principal setting and multiple devices without raising limits.

## 6. Atomic leasing, publication and bounded retirement

A native write transaction rechecks current authority/home fences and admits the fresh
request nonce. For owner operations it also checks the owner rate/storage reservation.
Publications accept increasing counters/generations and serials; equal counter plus equal
public bytes is idempotent, conflicting/lower values fail. Persist a serial high-water
mark: an absent serial at or below it is retired, not a candidate to upload again.
Authority transitions advance the same durable fence the transaction checks. Do not hold
a general router lock over network I/O or whole-registry serialization.

For lease requests, check an existing operation result before selecting again. Return it
only to the same currently authorized requester/target while `now < D`; SPK rotation does
not invalidate this particular retained lease. Revocation does. For a first selection,
both the five-minute intent freshness and ten-minute selection-expiry upper bounds must
hold, as must current base/profile/expiry and all quotas. Atomically select one OPK, record
its SPK/time/result and charge budgets; commit before exposing the key. Failure rolls back
selection/charges and returns `PersistenceUnavailable`, without exposing a new OPK.

Quota or pool exhaustion returns a verified new-profile SPK-only view and counted reason.
It creates no seven-day lease-result row, but fresh outer nonce protection still applies.
Freeze the chosen mode/header/ciphertext before emission; do not later upgrade the same
emitted bootstrap. A lost no-OPK reply before freezing can be retried against new availability.
A leased ID is never returned to the pool after a lost reply or sender crash.

Requester results expire at `D`; an old intent cannot select again after result GC because
its first-selection window has closed. Owner status is different: a device returning after
`T + S` still needs the directory's lease times to retire 200 unused private keys. Keep
owner lease metadata until authenticated retirement acknowledgement, independently of
requester-result GC. Retained-generation status remains owner-readable without authorizing
new selection/publication under that old generation.

Keep at most 200 unretired owner slots on node and device. An erasure-pending key still
charges its slot. After successful checkpoint completion, queue a durable public retirement
acknowledgement. The node applies acknowledgements before admitting replacement keys in
the same transaction. Retrying an acknowledgement is idempotent and never resets a serial
floor. An acknowledgement is an owner assertion, not proof of endpoint erasure.

Permit one outstanding public publication until acknowledgement or cold-status reconciliation.
Keep at most 400 local retirement references (one unacknowledged batch plus current slots);
confirm the exact batch by digest. Queue pressure blocks new publication preparation,
not logical deletion or checkpoint completion. At capacity, valid SPK-only delivery works.
Unchanged publication does not rewrite the identity registry.

Restore node lease/results/floors atomically or refuse fresh leasing for that incarnation.
Do not treat an empty restored cursor as available keys. A terminal branch revocation
fences new operations permanently, invalidates its bootstrap generation and retires local
private material; it is distinct from ordinary unused-key expiry. Retired branch metadata
continues to count against account slots until bounded cleanup, then only compact authority
retirement floors remain. Total loss/rollback of all surviving evidence is outside a local
store's independent detection ability; existing native pins and fences remain mandatory.

## 7. Quotas and node resource accounting

All successful-lease limits are durable and charged in the selection transaction. Retries
of a stored result do not charge again. Device, session or pool rotation cannot reset an
account's budget. Exceeding these limits yields SPK-only, not account admission Capacity.

| Scope | Rolling limit / key |
| --- | --- |
| Requester | 60/hour by authenticated account anchor, shared by its devices. |
| Requester-target | 1/24 hours by requester account and complete qualified target branch. |
| Target | 6/hour across requesters by complete qualified target. |
| Verified source prefix | 120/hour, using current ingress masks and observed client provenance. |
| Owner operations | 12/hour combined per qualified branch for Register, proof status and signed publish/status, including admitted no-op retries. Durable across reconnect/restart. Over limit: Busy with a bounded node-bound retry hint, no write/false acknowledgement. |

The client coalesces owner work every 30 minutes plus startup/read-time maintenance and
batches retirement acknowledgements with publication. Node enforcement is independent of
that cadence. Owner limits do not reset when credentials/grants are reloaded. Busy on an
optional owner read does not burn an hour inside the 90-second connection flight: schedule
the hinted retry; a mandatory refresh remains pending, while a still-valid base can open.

New prekey resource ceilings below are design limits, not claims about existing code:

| Resource | Limit / accounting |
| --- | --- |
| Public base and OPK record | At most 2 KiB/base and 512 bytes/OPK after canonical encoding. IDs have encoded-byte limits. |
| Owner update | At most 64 KiB including fields; batch at most 64 public OPKs and 400 compact generation/serial retirement references. Acknowledgement/status at most 200 owner entries. Counts never override the byte limit. Existing proof (8 KiB) and custody frame (5 MiB) caps also remain. The 64 KiB limit bounds the prekey-specific payload, not a newly truncated native authority record; authority evidence retains its existing validation and frame bounds. |
| Per branch | At most 200 unretired slots, 1008 live requester results, 400 retirement references, one current base plus at most 1008 result-referenced bases; no history row for an unreferenced idempotent publication. |
| Global request work | At most 1024 prekey request admissions/minute and 256 in flight, in addition to existing authenticated ingress/source controls. Verify identity before allocating per-owner durable state. Pressure returns Busy, not weaker authentication. |
| Request replay storage | At most 16,384 nonce markers of at most 128 bytes through the 600-second horizon; no eviction of live markers to admit replay. Full cache returns Busy. |
| Account/node byte budgets | Charge keys, values and explicit indexes atomically: 4 MiB/branch, aggregate `D × 4 MiB`/account where `D <= MAX_ROSTER = 1024` counts active and retained branch-state slots; 64 GiB/node for all new prekey state, including a reserved 32 MiB global-control allowance. These do not enlarge existing authority/admission limits. |

Worst-case logical per-branch payload is explicitly bounded:

| Stored component | Maximum bytes |
| --- | --- |
| Referenced/current signed bases | `1009 × 2048 = 2,066,432` |
| Compact lease-result records (references plus selected OPK data) | `1008 × 1024 = 1,032,192` |
| Unretired OPK records and lease metadata | `200 × (512 + 256) = 153,600` |
| Retirement references | `400 × 64 = 25,600` |
| Pair/target rolling charges | `144 × 256 = 36,864` |
| Floors, owner budgets, keys/index bookkeeping and maintenance reserve | `65,536` |
| Sum | `3,380,224 < 4,194,304` (4 MiB branch ceiling) |

Use compact bounded result records referencing bases, not a full authority publication in
each result. Account quota includes all branch generations, retained retired-device slots,
requester indexes and compact terminal floors; no unlimited device/epoch churn bypass.
The protocol's 1024 roster ceiling is conservative (ordinary enrollment is 960); encoded
record limits can admit fewer. At the ceiling, new prekey state is at most 4 GiB/account.
The account budget is shared, so it does not promise simultaneous maximum branch payloads,
all possible terminal floors and every optional index without admission checks.
A theoretical 65,536 full accounts would request 256 TiB, so the separate 64 GiB node cap
is essential, not an allocation promise. Requester-account pair indexes are charged to that account, not a global cache: at
60 leases/hour for 24 hours, at most 1440 live outgoing pair records of at most 256
bytes require 368,640 bytes/account, within the remaining branch-budget slack even for
one admitted branch. Target-side rolling pair charges are in the table above. Any
additional index or terminal floor also consumes the account allowance; reaching it
refuses new state rather than growing an uncharged table. Global prefix charges expire
after one hour: the 1024/minute admission cap allows at most 61,440 compact 128-byte
charge records (7,864,320 bytes). With nonce markers, their keys/indexes and bounded
control counters, the separate global-control ceiling remains 32 MiB; check encoded
reservations, never assume the payload calculation alone covers index overhead.

The existing 16 MiB/account authority-row limit and 65,536-account/new-principal admission
budgets stay separate and are never multiplied away or reset by prekey publication. Check
both old limits and new prekey reservations before committing. Charge retained branch slots
until cleanup; compact terminal floors share the account allowance. New-account admission
must reserve minimum prekey/cleanup headroom as part of usable networking admission.

These are serialized logical budgets, not a claim that redb COW/page/WAL overhead or disk
usage equals them. Reserve backend/disk headroom and handle storage errors before accepting
writes. A 64 KiB per-branch maintenance allowance inside its budget cannot be borrowed for
new leases: retirement, GC and fresh-base replacement must still progress under pressure.
Expired rows are swept before new reservations. Do not evict active quota entries or reset
floors. A genuine byte-cap shortage may yield counted SPK-only if a current base is safely
readable; owner updates remain pending with `prekey_capacity` if they cannot be committed.
A read/commit integrity failure is PersistenceUnavailable, never a fake success.

For 256 admitted request/response pairs, prekey-specific buffers bounded at 64 KiB each
require at most 32 MiB. Native authority evidence can exceed that individual payload bound:
retain its existing full verification and 5 MiB outer-frame limit, with a separate 32 MiB
aggregate in-flight evidence-buffer allowance. Acquire byte permits before allocation;
when exhausted, queue with a fixed bound or return Busy, never truncate an authority
record or allocate 256 maximum-size frames independently. Thus these new serialized
buffers total at most 64 MiB before crypto/transport overhead. This transient memory cap
is separate from the 32 MiB durable global-control budget. No operation serializes a
whole multi-GiB account to answer a branch status. Boundary/pressure tests must cover
large valid authority records as well as same-window timing evidence.

## 8. Failure and networking policy

The following is the single policy table. Error/event names are proposed typed outcomes;
no implementation is implied. Preserve node-bound admission Capacity hints, existing-principal
admission and the account's single-flight Busy retry ceiling of 90 seconds.

| Stage / failure | Data/history | Network, message and retry outcome |
| --- | --- | --- |
| Core account authentication, decryption or database integrity failure | Preserve existing unlock failure; never turn it into success. | Fail closed. This is not a prekey maintenance warning. |
| Open/unlock: missing, corrupt or foreign initialized prekey actor | Unlock succeeds if account data is valid; history remains readable. Warn with `prekey_repair_required`. | No Register, no key regeneration; initial networking pending/fails closed until repair or attended recovery. |
| Vault unavailable or explicit vault/data lock | History available only while data is unlocked. | Suspend new bootstraps/maintenance; close networking via existing lock lifecycle. Temporary vault access failure never uses a stored agreement seed. |
| Expired SPK at connect | History readable. | Cold owner status, due retirement/rotation and fresh Register; otherwise pending `prekey_refresh_required`. OpenSession never reads a stale base as success. |
| Live recoverable status/publish/rotation failure, including owner Busy | History/established ratchets continue while their data/authority are valid. Emit a bounded typed maintenance warning. | Warn-and-continue while a valid base is published; do not demote live solely for OPK shortage. Do not skip local expiry/erasure. At base expiry, fresh bootstrap/registration fail closed pending refresh. |
| Critical ownership/authority/actor invariant failure while live | Keep valid local history accessible; emit repair/fence event. | Fail closed for new network work and re-registration; no repair by derivation. This differs from recoverable maintenance I/O. |
| Checkpoint busy, coalesced or failed | Logical removal remains; erasure-pending and charged slots persist. | Warn, retry through checkpoint coordinator; never emit erasure-complete or free the slot early. |
| Authenticated inbound first packet: missing/consumed/expired key or expired deadline | No plaintext accepted. | Fail closed for that message; commit bounded metadata-only dead-letter/event `bootstrap_key_unavailable`, then ACK. If that transaction fails, no ACK; retry under existing bounds. Exact committed duplicates use prior replay/session outcome instead of re-consuming. |
| Inbound temporary locked vault/data, or unavailable current authority | No speculative decrypt or consumption. | Retain/no ACK, suspend or bounded retry until unlock/authority recovery or the node TTL expires. Do not misclassify a temporary refusal as a missing key. |
| Invalid request/profile/signature/replay/authority binding, or AEAD failure | No OPK deletion or consumption marker. | Typed refusal, no automatic weaker-profile retry. Outer-authenticated terminal poison follows existing bounded dead-letter handling. |
| Valid lease quota/pool/capacity fallback with current verified base | Normal new-profile SPK-only bootstrap works; record bounded reason/count. | No send failure for ordinary OPK quota exhaustion; no networking demotion. This is not admission Capacity. |
| Directory/lease persistence unavailable; fresh authority/base cannot be established | History and established valid sessions remain usable. | New bootstrap fails closed with retryable `prekey_lease_unavailable`; retain the job within its deadline. Do not invent an SPK-only result from an unverified stale view. |
| Frozen packet reaches deadline | Keep application job and existing delivery/idempotency evidence. | Never emit/retry old ciphertext. Re-lease/re-encrypt as a new operation/sequence when valid authority returns; do not extend the old envelope. |

Unknown or malformed data cannot consume a key before authentication. Terminal inbound
records contain only bounded identifiers/reasons, not new ciphertext/plaintext copies.
The ACK follows the durable terminal record, preventing infinite inbox retry loops.
Genuine admission Capacity and prekey resource Busy/Capacity reasons stay distinguishable;
no fabricated admission reset time or weaker channel binding is used to get online.

## 9. Bootstrap crypto, storage retirement and private-copy inventory

Retain reviewed X3DH/ratchet primitives. The new canonical header/transcript binds domain
and version; both qualified identity public keys and branch refs; signed base/hash and
SPK ID/serial; generation and selected OPK ID/public key or explicit absence; independent
`E`/`R0`; lease operation/time; conversation/session, ordering sequence/version, deadline
and routed envelope AD. Length-prefix every variable field and fix OPK/SPK-only vectors.

Send derives X3DH with fresh `E`, initializes with independent `R0`, encrypts and persists
only advanced ratchet plus exact public header/ciphertext/outbound idempotency state.
Erase `E`, X3DH root inputs/DH outputs and all secret load/serialization buffers on every
exit. Receive selects the named retained keys and obtains agreement DH2 from the vault
operation. Authenticate on a working session copy; only then atomically persist advanced
ratchet/replay/message outcome, remove the consumed OPK and record erasure-pending.
Rollback retains the key/prior state and emits no ACK. Concurrent uses cannot both commit.
The persisted receive ratchet has already replaced its bootstrap SPK DH secret.

```text
Authenticate first packet
  -> writer: advanced ratchet + replay outcome + OPK removal + pending slot
  -> durable commit
  -> actual successful post-commit TRUNCATE
  -> durable completion + owner retirement acknowledgement + slot release
```

Enable secure deletion for ordinary secret rows; retire old event payloads/signatures and
secret-selecting pointers. A queued/coalesced checkpoint, busy reader or I/O failure is
not completed retirement. Reopen resumes pending work without restoring keys. Logical
expiry at the key deadline is unconditional; the forward-secrecy claim waits for completed
software retirement. This is not a promise to erase external snapshots or SSD remanence.

| Copy | Required treatment |
| --- | --- |
| Branch vault / credential type | Long-term authority only; remove prekey builders. Load agreement for one bootstrap, zeroize context, never serialize it into account state. |
| Canonical actor | Four SPK slots and 200 OPK slots including pending retirement; mutable private rows, qualified ownership, read-time expiry. |
| Old events/checkpoints/archives | Retire every `identity_seed`, private SPK/OPK payload/signature and pointer, including legacy and archived tables. Only the bounded receive-only SPK slot in section 10 may migrate. |
| Session / outbound snapshots | Advanced ratchet and public frozen packet only; no `E`, original root or extra bootstrap-SPK copy. Existing bounded skipped-message-key/history semantics remain explicit exceptions. |
| Writer, vault, decoder and serializer buffers | Zeroizing private wrappers; no untracked raw agreement/prekey arrays, Debug output or plaintext temp files. |
| Database / WAL / readers | Secure deletion, completion-aware checkpointing, pending markers and reopen proof; no plaintext scan of encrypted files as evidence. |
| Backup export/import and own-device history/sync | Filter all private prekey actors/events/checkpoints and active bootstrap state; old archives cannot overwrite live floors, consumed markers or ratchets. Sibling devices create independent pools. |
| Node/gateway stores | Public keys, bounded lease/status/quota metadata and floors only, never private prekeys. |
| Logs / external snapshots / endpoint history | Counts and redacted typed events only. Existing plaintext/history access and pre-existing private snapshots are outside later bootstrap-secret deletion claims. |

## 10. Activation, restore, compatibility and migration

Deploy node support first. The new SDK sends only the signed new profile, including its
legitimate SPK-only mode. Missing/unknown profiles or old software get update-required.
Remove the old send header (`R0 = E`), separately signed legacy projection and any
legacy-authority fallback. There is no compatibility configuration option. Pin the
minimum profile and publication/generation floors durably on observation/activation.

A first local migration transaction freezes activation time `A`; the owner-signed update
carries it and the node pins that branch's first activation/floor. Validate that the time
is not in the future beyond `S`; node acknowledgement can shorten, never extend, the local
grace. Neither retries, pool rotation nor archive merge may advance/reset `A`. Status
reconciles lost acknowledgements without recreating keys.

For at most `T` after `A`, accept old-format bootstrap receive-only if the ordinary outer
authority/replay/TTL checks hold, its creation time is no later than `A`, and `now < A + T`.
Never send or publish that profile. Preserve the already-owned old SPK in one explicitly
receive-only slot during migration, counted within the four-SPK bound; obtain its agreement
key from the vault, not old `identity_seed` data. Copy the old SPK from verified existing
state, never derive it from vault credentials. With no recoverable old key, report key
unavailable rather than manufacture one. Retire this slot/parser access at grace end.
The creation-time restriction does not prove historical delivery against a malicious
backdating sender; all old-format acceptance within the grace is outside the FS claim.

Existing established ratchets remain readable independently of that grace. Old deterministic
SPKs remain mathematically derivable from retained agreement material; deleting their rows
cannot provide retrospective forward secrecy. Only fresh random keys get the new claim.

| Lifecycle event | Contract |
| --- | --- |
| First authorized branch | Commit CSPRNG actor/public snapshot before publication. No private state is advertised before commit. |
| Restart/reconnect | Load the same actor, counters, activation and pending work. Due maintenance is explicit; registration never constructs keys from credentials. |
| Data-only restore / key loss | History restores without private prekeys, active bootstrap sessions or branch authority. Networking remains pending for attended new-device recovery; no same-branch reset. |
| Merge old archive into live state | Exclude all private actor/event/checkpoint copies; preserve live activation/profile/generation/consumption floors and outbound/receive ratchets. |
| Revocation/key/epoch change | Fence new operations, terminally retire old bootstrap keys and use the new qualified branch. Retained history does not grant current send authority. |
| Future home migration | Refuse until a real source fence exists. Then preflight a bounded fresh destination generation, fence old-home publication/leasing before destination activation, preserve required old-delivery private state within bounds and carry retirement floors. Never activate the same pool at both homes. |

## 11. Threat statement

After authenticated OPK-backed receive, logical consumption, transient-secret destruction
and completed storage retirement, later compromise of long-term agreement/signing material,
current prekeys and advanced device state must not reconstruct the captured bootstrap from
its old secrets. The adversary must not already have the erased OPK, initiator `E`, original
X3DH root, old message keys or a private snapshot. Test sender/recipient compromise separately
and together. Intended plaintext/history access is not a bootstrap-key reconstruction claim.

SPK-only protection begins only after the selected random SPK is retired from all software
copies; its normal logical retention is at most 21 days, and pending physical retirement
is explicitly not completion. A malicious directory can withhold OPKs, report false lease
times or drop envelopes; signatures do not prove availability. Active unlocked-process
compromise, total rollback without surviving evidence, old external snapshots, retained
skipped-message keys and the receive-only old-format grace remain outside this claim.
Native current authority, signed transcript vectors and erasure mutations remain prerequisites.

## 12. Implementation test and mutation matrix

These are required future tests, not results from this document change. A mutation must
compile and fail a meaningful assertion; a compiler error, timeout, skipped case or mocked
owner ledger is not a kill. Independent mutations exercise independent rebuild paths.

| Scenario / layer | Required assertion | Compiling mutation to kill |
| --- | --- | --- |
| Initializer non-resurrection (SDK) | Real initialized actor/key retirement, same-vault restart, missing marker/actor combinations: history unlock succeeds, no derivation/write/Register. | Reintroduce derivation in `initialize_born_v3_branch`; fails its own runtime non-resurrection test. |
| Registration non-resurrection (SDK/transport) | Different provider snapshot and vault legacy material; actual Register uses only the provider's public bytes. Removed APIs/fixed production ID absent. | Re-add the credential prekey builder and call it from `registration_actions`; compile, then fail the separate snapshot-only regression. |
| Agreement-source migration (SDK/storage) | Send DH1/receive DH2 work through vault loads; decoded actor/events/checkpoints/archives contain no agreement seed after retirement/checkpoint/reopen. Vault/data lock blocks bootstrap with no persisted fallback. | Keep/select `identity_seed`, skip an archive/event retirement, or use a cached agreement key after vault refusal. |
| Native ordinary-publish replay (router/gateway) | Older public base and old deterministic bundle via HTTP and old PrekeyPublish frame produce `native_publication_requires_custody`; rows/floors unchanged, including fenced/unavailable native authority. | Re-enable `publish_custody_prekey` write or return None into the legacy writer; each route's negative test fails. |
| Register/common writer (node) | Proof Register and signed publish enforce identical monotone/profile/byte rules. | Restore admission's direct row overwrite or skip the floor transaction. |
| Deadline/TTL boundaries (unit/SDK) | `D-1` accepted, `D`/`D+1` refused; over-seven-day TTL refused/capped by node policy; expired unsent operation re-leases with new keys/sequence, no old emission. | Extend deadline on retry, skip receive expiry, exceed T, or reuse the old operation/ciphertext. |
| Rotation / retained keys (SDK) | Seven-day rotation, 14-day public expiry, 21-day private limit, four total slots, matching SPK for every valid queued OPK. Clock rollback cannot resurrect or erase early. | Keep old longer windows, skip read expiry, derive SPKs, or delete matching SPK too soon. |
| OPK lifecycle (SDK/native node) | Seven queued leases across valid target windows survive additive refill/restart. At 200, real owner status after `T+S` frees expired keys before refill; exact threshold, just-before, unleased and missing-time survive. | Replace pool, use `>=` for lease GC, skip expiry at cap or GC owner timestamps with requester results. |
| Consumption / WAL (SDK/storage) | Authenticate before atomic advanced state/key removal; crash/rollback/concurrent use/duplicate/failed commit safe. Busy reader remains pending until actual TRUNCATE/reopen absence. | Delete before auth, split commits, skip erasure, mark queued checkpoint complete or free slots early. |
| Reconstruction/call controls (SDK) | Native equivalent of `client/routed/call_tests.rs::committed_call_controls_retain_neither_ciphertext_nor_consumed_pair_message_keys` inverts its current reconstructible-static-prekey assertion: retained vault/advanced state cannot decrypt the captured new-profile bootstrap after retirement. | Retain OPK or E/original root; the native negative-decryption assertion fails. Keep a positive reconstruction control so the oracle is not vacuous. |
| Atomic leases and replay (node/real transport) | Concurrent leases distinct; failed durable write exposes no key; lost reply/restart returns same live result without charge. Fresh outer nonce required; old intent after GC cannot lease again. | Reply before commit, omit result/counter/nonce durability, reset selection on restart or accept expired intent. |
| Owner bounds (node) | Combined 12/hour across Register/proof/live operations, persisted over reconnect/restart; over-limit Busy/hint, no write. | Count only client cadence, key by session, or skip proof-status charging. |
| Byte/account/node bounds (node) | Exact/max+1 encoded update and row sizes, 200 slots, 1008 results, roster/retired generations, account aggregate and node byte reservations; cleanup/rotation still progress. | Omit a write path/counter, duplicate full bases in results, omit retired slots or bypass byte cap with character counts. |
| Current authority/source/handshake (native transport) | Actual gateway grant + branch signature, node audience/session/action binding, current head/cert/revocation and observed-prefix provenance. Proxy still Disconnects at handoff; ordinary lease works at session limit 1 with Deliver interleaving. | Accept client-made grant/prefix, skip signature/current head/audience, retain a stale OpenSession base, or drop Deliver while awaiting result. |
| Quota isolation (node/SDK) | Account with three devices shares one pair lease/day; other accounts work; 60/1/6/120 survive restart; 5000 valid pairs under admitted resources/clock windows do not globally starve a newcomer. | Key by device, use gateway shared prefix, reset durable ledgers, or use a global 4096-pair full-table denial. |
| Own-device sync (SDK/integration) | `own_device_sync.rs` calls the same lease helper: self-account target gets OPK or counted new-profile SPK-only, without sync failure or private-key transfer. | Bypass leasing for self-account, allocate separate requester quota, or export the private actor. |
| Group first-contact fan-out (SDK/native integration) | 61 distinct targets through the group paths used by k2b/k5a: first 60 eligible account leases, subsequent counted SPK-only, no send failure; existing source/target limits remain. | Turn requester quota fallback into an error, skip the helper for distributions or reset account quota per target transport. |
| Public carriers / strict profile (node/SDK) | Every GET/Lookup/Peer/manifest/ack verifies a base without OPKs/ledger; unknown/old profile is update-required. | Forward upload unchanged, bypass native freshness, add legacy projection or send old E=R0 header. |
| Restore / activation / grace (SDK) | Fresh restore pending; attended new branch random; live merge keeps floors; old receive only before A+T, no grace reset across restart/archive/pool change; history/established sessions preserved. | Restore private rows or active bootstrap, reset A/floor, re-enable old send, accept old header after grace or rebuild a same-branch missing actor. |
| Failure-policy matrix (SDK/bus) | Each row in section 8: unlock/history success where specified, networking refusal, maintenance warning, no infinite unavailable-key retries, terminal record then ACK, temporary lock no ACK. | Propagate optional prekey repair as unlock failure; swallow repair into success; ACK before commit or repeatedly retain permanent missing-key packets. |

Use production Register/proof-status/signed-frame verification, durable node storage,
real async mesh and owner acknowledgements for integration cases. Inject failures at each
commit boundary. Unit clock/source fixtures must obey the quotas they test; a directory
ledger injected into a helper alone does not establish end-to-end expiry behavior.

Future implementation **does require an itest-repo change**, with a matching product pin
and its own gates; none is made or claimed in this design round:

| Realnet slice | Planned extension / unchanged boundary |
| --- | --- |
| `contact01_realnet_add_then_dm` | Preserve first add/accept/OPK DM and safety-number assertions. Add six auxiliary authenticated requesters: the original first DM is target lease 1, five auxiliaries take leases 2–6, the sixth takes attempt 7 and receives quota SPK-only while keys remain. Verify a real fallback DM/receipt. This adds explicit itest setup/steps, not a changed old expectation. |
| `k2b_realnet_surface_round_trip` | Existing DM/group surfaces through new-profile lease/fallback, additive refill and reconnect; prove group entry uses the common helper. The 61-target pressure case is SDK/native integration, not 61 extra realnet actors. |
| `k5a_realnet_agent_replies_in_dm_and_group` | Agent first DM and group replies use OPK/fallback across restart. Restored-device pending behavior is SDK coverage, not moved into this slice. Agent surface-specific assertions remain k5a2. |

No existing realnet assertion, timeout or budget changes. Measure new contact setup cost
and lease/write critical sections in paired same-window main/candidate runs. If the added
steps exceed the budget, optimize setup/production work or obtain a new scope decision;
do not loosen acceptance. Unit, SDK, in-process transport and controller realnet evidence
remain separate claims.

## 13. Implementation cards and runtime documentation

Adopt the component order below; no native-profile production activation before the final
wiring card. Each component has complete local unit/failure tests and explicit dependencies,
not a silent stub for a missing sibling. Constructor removal includes the compiling provider
call-site adaptation; the integration card enables the complete wire path only when all
components and strict-profile nodes are available.

| Card | Complete responsibility / acceptance |
| --- | --- |
| DM-FS-V3-02 | SDK/crypto profile/header/transcript, independent E/R0, OPK-aware receive, zeroization, fixed vectors and mutations; no network activation. |
| DM-FS-V3-03 | Canonical account actor, vault constructor removal, per-bootstrap agreement access, identity-seed/event retirement, rotation/expiry/erasure, unlock/failure policy and backup/sync/restore exclusions. Depends on 02. |
| DM-FS-V3-04 | Native directory common transaction, ordinary-publish refusal, public views, durable leases/results/quotas/owner acks and all resource caps. Uses 02 types; parallel with 03. |
| DM-FS-V3-05 | Initial custody proof/status/OpenSession, signed ordinary frame wiring, own-device/group flows, activation/grace/floors, complete failure policy and real SDK→gateway→router/itest contact01/k2b/k5a acceptance. Depends on 02–04. |

Implementation documentation must update [root key custody](../root_key_custody.md),
especially “Ordinary DM security boundary”: remove the pending legacy DM-FS-01/stable-SPK
claim and document the actual new-profile claim, per-bootstrap vault boundary, horizons
and exclusions. Also update [custody networking](../custody_networking.md),
[account backup](../account_backup.md), [client read model](../client_read_model.md),
[home migration SDK](../home_node_migration_sdk.md) and [local bus errors](../local_bus_errors.md)
for typed repair/dead-letter events, history availability, strict activation and unsupported
migration; add the implementation release note. Do not present this proposal as those
runtime documents already having changed.

Rollback after activation preserves floors, actor state and new-profile verification or
refuses unsupported bootstrap. It cannot select retired events, reset activation, restore
vault derivation, or silently send the old profile.

### Open questions for the controller

None of Q1–Q6 remains open: this revision adopts the controller decisions. The additional
encoded-byte and aggregate resource ceilings in section 7 are concrete design proposals
for review, rather than existing protocol constants. Encoding vectors and measured
resource/performance acceptance belong to the four named implementation cards.
