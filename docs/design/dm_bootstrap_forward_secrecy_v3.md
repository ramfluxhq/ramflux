<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026 Span Brain -->

# Born-v3 DM bootstrap forward secrecy

**Proposal, 2026-11-03. No implementation or runtime acceptance is implied.** This note
proposes independently generated rotating signed prekeys (SPKs), authenticated one-time
prekey (OPK) leases, and deletion of bootstrap secrets for native custody accounts.
The decisions at the end require approval before implementation.

The recommended private-key owner is the unlocked account data store. The branch vault
continues to hold long-term signing and agreement authority, but cannot recreate a
new-profile SPK, OPK, or X3DH ephemeral. Custody registration publishes a committed public snapshot from
the account store. Successful first-message authentication, advanced receive-ratchet
persistence, and OPK deletion share one account-writer transaction. Directory lease
selection and its retry record share one durable node transaction.

## 1. Baseline and boundaries

The source snapshot is main `51d9222a100d5c2800229d3fc4b98e39c2f710b4`. Historical
lifecycle evidence was checked at `76e788463f35fdd41333e92021ba034b2a5dbb7d` and the
rebased checkpoint `d384e25ef151df60d237d07c3ed15d3e77a7f148`. That implementation
uses the legacy identity registry; its successful tests do not establish native support.

| Current source | Observed behavior that the implementation must replace or preserve |
| --- | --- |
| [Branch credentials](../../crates/ramflux-sdk/src/custody/vault.rs), `signed_prekey_seed` and `prekey_bundle` | The SPK is derived from the retained agreement secret; the fixed native bundle has no OPK. Deleting a data-store row cannot erase this derivation. |
| [Native initialization](../../crates/ramflux-sdk/src/client/native_branch.rs), `initialize_born_v3_branch` | Fresh daemon setup reconstructs and persists that same SPK. Native initialization requires unlocked account data. |
| [Custody transport](../../crates/ramflux-sdk/src/custody/network.rs), `connect`, `registration_actions` | Vault-only connection independently constructs another credential-derived bundle, publishes authority, registers prekeys, opens a session, then persists networking live. Fixing only initialization leaves this reconstruction path. |
| [Identity initialization](../../crates/ramflux-sdk/src/client/identity.rs) and [private prekeys](../../crates/ramflux-sdk/src/client/private_prekeys.rs) | Private prekey state currently uses `x3dh.prekey.private` events plus projection pointers. A single current SPK is selected. Native ownership must never fall back to legacy root-signed device-set authority. |
| [DM bootstrap](../../crates/ramflux-sdk/src/client/dm_session.rs) | Send initialization reuses the X3DH ephemeral as the ratchet key; receive initialization supplies no private OPK. |
| [Native directory](../../crates/ramflux-node-core/src/custody_authority/directory.rs) and [native redb storage](../../crates/ramflux-node-core/src/router_store/custody.rs) | `custody_prekeys_v3` stores public bundles; there is no native lease cursor, lease ledger, or durable publication floor. |
| [SDK handoff](../../crates/ramflux-sdk/src/gateway/custody.rs), [ordinary engine](../../crates/ramflux-sdk/src/gateway/engine.rs), and [gateway custody proxy](../../apps/ramflux-gateway/src/custody.rs) | `into_gateway_parts` hands the socket to the ordinary engine. Gateway handoff drops the proxy and sends Disconnect; ordinary `PrekeyFetch` is a read path. New lease enum variants alone would not reach ordinary first-DM bootstrap. |
| [Custody frames](../../crates/ramflux-protocol/src/custody/network.rs) | Register currently carries a JSON value. Session actions have lookup but no prekey lease or owner-status operation. Native home-migration actions currently return unsupported. |
| [Native SDK verification](../../crates/ramflux-sdk/src/client/identity_authority/verify.rs) | The native return path checks current custody authority, bindings and signature; a proposed SPK freshness policy must also execute on that path. |
| [Native backup handling](../../crates/ramflux-storage/src/account_db/backup_native.rs) | Data-only restore must remain separate from branch authority and active outbound sessions. New private-key rows and all old event copies need explicit exclusions. |

Scope is native DM bootstrap, including the transport, directory and storage changes
needed for it to work. Existing established ratchets and legitimate historical message
access remain intact. This is an X25519/X3DH proposal, without a post-quantum guarantee.
It does not import the legacy authority fallback or declare home migration implemented.

## 2. Ownership and the vault-only API decision

Use one device-local account actor as the canonical owner of random private prekeys.
Its key is the complete qualified branch identity: account anchor, device ID, device
epoch, and branch signing/agreement key commitments. Literal device names are insufficient.
A pool generation identifies one private-state incarnation: a durable increasing ordinal
plus a fresh random incarnation tag. The server fences the ordinal and rejects a changed
tag at the same ordinal. An SPK sequence identifies one rotation within it. None of these
identifiers is a seed or a derivation input for secrets.

The actor contains current and retained SPKs, private OPKs, public publication snapshots,
monotone counters, owner-acknowledged lease metadata, and pending erasure markers. Use
mutable rows, not new secret-bearing append-only events. Store only the reference to the
vault's agreement key; do not duplicate the long-term agreement secret in this actor.
The account writer serializes maintenance, receive consumption and backup sanitization.

| Candidate | Benefit | Cost / decision |
| --- | --- | --- |
| Account data store, recommended | OPK removal and advanced receive state commit atomically with existing account work. | First registration and maintenance require an unlocked account prekey provider. This changes the vault-only connection contract. |
| Separate private state in branch vault | Could retain the existing vault-only connection entry point. | Receive commit crosses two stores. A new durable prepare/commit/recovery protocol would be required to prevent key loss or resurrection. Not recommended here. |
| Copies in both stores, or vault-derived seeds | Convenient reconstruction after missing data. | Reintroduces recoverable private copies and makes deletion ineffective. Reject. |

Proposed connection input is a public `PrekeyPublicationSnapshot` plus a device-local
provider for acknowledgements and maintenance. Transport receives no SPK/OPK private
bytes. Prepare the snapshot in a writer transaction, release the transaction, sign/send
the public action, then apply the authenticated acknowledgement in another transaction.
Never keep a database transaction or writer guard across a network await.

`CustodyConnection::connect(config, vault)` cannot silently preserve its current behavior.
Under the recommended contract it becomes a typed `PrekeyStateRequired` outcome unless
an unlocked canonical provider is supplied. The public SDK entry point and daemon call
sites must change together. An authority-only or locked-data networking mode would be a
separate approved API; this proposal does not invent one to hide the incompatibility.

Fresh branch creation generates state once with the OS CSPRNG and commits it before
publication. Ordinary restart loads that state byte-for-byte. A missing row after an
initialization marker, failed ownership check, or corrupt counter is a typed repair
condition. The vault must not derive a replacement, resurrect an old ID, or silently
create a new incarnation. A genuinely new authorized branch may initialize a fresh pool.

## 3. Rotation, reachability and bounded retention

All values in this table are proposed policy. Durations use trusted wall time for
expiry and a monotone local maintenance watermark to avoid resurrecting keys after a
clock rollback. Require positive, ordered times and no advertised validity longer than 30 days. A suspicious
future timestamp is refused, not treated as an early erasure instruction. Boundary tests must specify the clock-skew tolerance used by the implementation.

| Item | Proposed policy |
| --- | --- |
| SPK generation | Independent CSPRNG key, fresh ID and increasing SPK sequence; rotate after 7 days while online. |
| SPK public validity | Creation through creation + 30 days. New initiators reject expired material on every native carrier and request a refresh. |
| SPK private retention | Keep through public expiry + 30 days; erase only strictly after that deadline, including on read. At weekly rotation retain at most 10 keys, counting current. |
| OPK initial pool | 8 independently generated keys with fresh IDs. The signature binds the qualified branch and pool generation. |
| OPK replenishment | Below 2 directory-unleased keys, add enough fresh keys to restore 8, subject to the private-state bound. Never replace outstanding keys with a freshly generated pool. |
| Private OPK bound | 200 per qualified branch, including retained pool generations and leased keys awaiting delivery. Process authenticated expiry/consumption first, then replenish. At the bound remain reachable through a valid SPK-only result. |
| OPK successful consumption | Delete after first-message authentication in the same transaction as the advanced ratchet and replay/ordering state. |
| Unused leased OPK | Delete individually only when `now > leased_at + 30 days`; exactly 30 days, 29 days, unleased and missing timestamps survive this rule. |
| Bootstrap delivery | A new-profile packet has a bound delivery deadline no later than SPK expiry + 30 days and, when leased, lease time + 30 days. The receiver enforces it. |
| X3DH ephemeral `E` | Fresh per bootstrap attempt; erase immediately after X3DH and initial ratchet construction. Never persist it. |
| Initial ratchet key `R0` | Fresh and independent of `E`. It may live in the ordinary advanced ratchet state until that ratchet advances. |

The longer SPK retention is deliberate. A queued OPK-backed bootstrap still requires its
matching SPK. Keeping an OPK for 30 days while deleting that SPK two days after weekly
rotation loses valid queued messages. A 30-day public validity window plus 30-day delivery
window needs up to 60 days of private SPK retention. This also delays the SPK-only forward
secrecy boundary. A shorter policy must explicitly shorten signed validity or delivery
promises; it cannot retain the old two-day grace and promise the same offline window.

OPKs belong to the pool generation, not to one SPK sequence. An unleased OPK may remain in
the public pool across SPK rotations without changing its ID or private key. The lease
transaction binds the selected OPK to the current SPK snapshot. A previously leased ID
never becomes unleased after rotation or publication. This avoids abandoning eight
unleased private keys on every weekly rotation. Old SPKs remain addressable by ID for
queued delivery; only the current SPK is selected for a new directory lease.

The owner accepts lease timestamps only from the current authenticated home and only for
known local OPK IDs. `Unleased` or a missing status cannot undo a known lease or consumption;
conflicting lease times are a protocol error, not a reason to shorten retention. Missing
metadata does not justify deletion. At 200 retained keys this can reduce service to
SPK-only until a valid status arrives. A lying directory can report a false old lease and
cause availability loss; a minimum locally observed grace would mitigate that attack but
would change the expiry policy and is an explicit question below.

## 4. Proposed public types and custody operations

The names below are proposed wire types, not existing Rust definitions. Use an explicit
profile tag, `ramflux.dm.bootstrap.fs.v1`, inside the value carried by native Register.
Keep legacy parsing separate. Define canonical encoding, field bounds, signatures and
fixed test vectors before implementation; unknown profiles are typed update-required
outcomes, never an excuse to choose legacy authority.

| Type | Required contents and visibility |
| --- | --- |
| `SignedNativePrekeyBase` | Profile, qualified branch reference and commitments, agreement identity public key, pool generation, SPK sequence/ID/public key, issued/expiry times, bundle counter, signed bootstrap capabilities, branch signature. No OPK pool is needed to verify this base. |
| `SignedNativeOpk` | Domain, qualified branch and pool generation, increasing OPK serial, fresh OPK ID/public key, branch signature. It is independently verifiable and cannot be substituted between branches or pool generations. |
| `NativePrekeyPublication` | Signed base plus additive public OPK records. Owner upload only, with the complete action hash covered by the registration proof. No private bytes. |
| `PublicPrekeyView` | Signed base only, plus current native authority evidence. Safe for ordinary lookup, manifests, discovery, anonymous prekey fetch and compatibility projections. |
| `PrekeyLeaseIntent` | Requester qualified branch, target qualified branch, expected base hash/profile, issue time, selection expiry, random 32-byte nonce, operation ID. The ID hashes the preceding intent fields, excluding itself, with a domain separator; the outer signed-request nonce is separate. |
| `PrekeyLeaseResult` | Verified base, zero or one independently signed OPK, target and requester binding, operation ID, selected-base hash, lease time and delivery deadline when leased; otherwise a bounded fallback reason. No pool or owner ledger. |
| `OwnerPrekeyStatus` | Publication counter/hash acknowledged, unleased count and a bounded per-ID `Unleased` / `LeasedAt` ledger for the owner's requested local IDs only. No private key or other requester's identity. |

Define `base_hash` over the canonical signed base with its own domain. Define the new
profile's `prekey_bundle_hash` over that base hash, the canonical selected OPK record or
explicit absence, and the lease binding/delivery fields. It never hashes a hidden full
pool or owner status. Include the signed public base and selected record in the versioned
bootstrap header so the recipient can verify the commitment without retaining every old
publication snapshot. The hash encoding is profile-specific; do not reinterpret a legacy
bundle hash as this commitment.

Identifiers and collections have encoded-byte bounds, not character-count assumptions.
Limit upload/public-pool and owner-status response entries to 200 and enforce the current 64 KiB prekey decode limit
as well as the enclosing 5 MiB custody frame limit before allocating. Reject duplicate IDs,
key/ID rebinding, counter overflow, malformed times and mismatched signatures explicitly.

Proposed operations reuse the current native transport and proof boundary:

1. `CustodyProofAction::Register { prekey_bundle: NativePrekeyPublication }` uses the
   existing `register` capability and action-hash proof. A versioned registered response
   includes the acknowledged hash/counter and owner status. Reconnect sends the exact same
   committed publication until its acknowledgement is durable.
2. `CustodySessionAction::PrekeyLease { intent }` uses an established message-capable
   requester session. The result contains at most one OPK. Ordinary `Lookup` stays read-only.
3. `CustodySessionAction::PrekeyPublish { publication }` updates the owner's pool while
   live. Reauthorize the current branch's `register` capability, verify its publication
   signature and signed request, and apply the same idempotent durable publication rules
   as initial Register. A message-only capability does not authorize owner publication.
4. `CustodySessionAction::PrekeyStatus { pool_generation, opk_ids, known_publication_counter }`
   returns only the authenticated connection owner's ledger, restricted to at most 200
   named local IDs. A branch cannot request another branch's private status. Publication
   and status use explicit operation tags and do not masquerade as Submit.

Preserve current authority verification, branch certificate authorization, node pins,
TLS holder/exporter or explicitly selected existing proxy binding, session proof hash,
request body/action hash, fresh request nonce, expiry, and the signed POST path
`/v3/custody/session`. Reconnect retries use a fresh connection, challenge and request
nonce; the lease operation ID remains stable. No new no-binding fallback is introduced.
The gateway forwards the actual verified source prefix and requester identity through
its authenticated mesh to the router. Caller-supplied identity/prefix and the gateway's
shared address are not quota identities.

### Ordinary-session handoff must retain the custody owner

The current handoff is a hard boundary: the SDK drops its `CustodySession` from the
returned parts, and the gateway proxy destructor sends Disconnect. Preserve the session,
proof hash and connection ownership on both sides instead. Transfer a non-deserializable
custody owner into the ordinary gateway grant; do not manufacture one from client JSON.
It retains the original mesh connection ID, node/binding identity, observed client source,
expiry and cleanup responsibility. Send Disconnect exactly once when the actual connection
closes, including error/cancellation paths, rather than at protocol handoff.

Add a bounded ordinary `GatewayClientFrame::CustodyRequest { session_id, request, action }`
and `GatewayServerFrame::CustodyResult { response }` for the three prekey session actions
above. Accept them only on an existing native handoff with the same live session/connection
owner. Forward the unchanged signed request to `CustodyMeshRequest::Request` through the
production async authenticated mesh; derive source and holder context from that connection.
The router still checks the original custody proof hash, current authority, action hash,
fresh nonce, capability and expiry. Never translate a legacy gateway identity into native
authority. Direct custody connections use the same actions without the ordinary wrapper.

The ordinary engine keeps the public custody session context and existing branch signer,
not private prekeys. Its native bootstrap helper leases through this wrapper; ordinary
`PrekeyFetch`, manifests and discovery remain SPK-only reads. Update
`load_or_create_send_dm_session` and every other native fresh-bootstrap caller to use the
lease helper. An offline cached manifest is not an OPK lease. Response handling must
preserve interleaved Deliver frames and existing request serialization, rather than lose
messages while waiting for a lease/status response.

On session expiry, use the existing bounded native reconnect and obtain a new proof;
retry the same lease intent with a fresh outer request. Do not extend the old session or
reuse its proof on another socket. Live maintenance uses PrekeyPublish/Status on this same
channel, so no second custody connection competes with the ordinary one. The current
listener permits 1..64 authenticated sessions per principal (default 4); this design must
also work at 1 and with several devices, without raising that limit. Test handoff ownership,
exactly-once disconnect, expiry/reconnect, interleaved deliveries and the production mesh
explicitly. Multiplexing is part of the proposed implementation scope, not existing behavior.

All ordinary public surfaces must construct `PublicPrekeyView`: custody `Peer`,
`CustodyManifestDevice`, SDK manifest adapters, ordinary native prekey GET, publication
acknowledgement public fields, identity discovery and any manifest nested in another
response. No serializer may accidentally forward the owner upload value unchanged.
Only the authenticated lease result exposes an individual OPK. Owner acknowledgements
may expose IDs/status, but never public OPK material through the public projection.

New nodes recognize the versioned Register body; old nodes cannot accept it. The SDK
surfaces update-required rather than falling back to credential-derived registration.
Node/SDK rollout ordering and whether to keep a separately signed compatibility projection
are approval decisions. Peer capability negotiation is addressed in section 9.

## 5. Atomic directory leasing and retry safety

Extend native redb storage rather than porting the legacy registry's authority model.
Use per-qualified-branch rows for the current public base, publication floor, pool
incarnation, OPK availability and immutable lease records. Add an index from operation ID
to the selected OPK/result and a durable counter floor for publication rollback detection.
OPKs have increasing serials within a pool generation as well as fresh IDs. Persist the accepted serial high-water mark; an
absent serial at or below it is retired and cannot be uploaded again. Existing unleased
rows may be repeated unchanged. This prevents reuse after old per-ID records are compacted
without retaining every consumed ID forever.

Current authority/revocation and migration fencing are checked before selection and again
within the serialized authority/lease commit boundary. A concurrent revoke wins or the
lease commits before it; a revoked branch cannot race a later accepted publication. Authority
updates must advance the same durable branch/home fence that the lease transaction checks;
an unchecked in-memory authority snapshot is insufficient. Keep this coordination local to
the affected authority/target, rather than holding a general router control lock over network
I/O or unrelated registry serialization.

A single durable redb write transaction must:

1. Check current native ownership/capability, target bindings, authority/migration fences,
   operation-ID derivation and intent integrity.
2. Look up a previous successful lease for the same operation ID. Return that same result
   to the same authorized requester within its delivery window without selecting another
   OPK or charging quotas twice. Rotation of the current SPK does not invalidate a queued
   lease's retained SPK; revocation still refuses the request. A changed intent is rejected.
3. For a new operation, check expected current profile/base hash, SPK expiry, monotone
   generation/counter floors, intent freshness and all lease quotas. If permitted, select one
   available OPK, mark it leased with its timestamp and SPK binding, persist the operation result, and
   charge the durable quotas together. Commit before returning public OPK material.
4. If the pool is empty or a lease quota is exhausted, return a valid signed SPK-only
   view with a reason. This is reduced forward secrecy, not account admission Capacity.
   A failed durable write returns `PersistenceUnavailable` and exposes no newly selected OPK.

The lease is assignment, not a reservation later recycled to another caller. A lost reply
or sender crash may burn a key until its 30-day expiry; it must never put that ID back in
the pool. Publication unions fresh unleased IDs with the existing ledger. Repeating the
same hash/counter is idempotent; the same counter with different bytes or an older counter
is refused. Reuploading a leased or consumed ID cannot reset it. Unchanged publication
must not rewrite the whole identity registry. Durable selection remains serialized only
for the per-target commit; keep unrelated directory work outside that critical section.

For a new selection, propose an intent created within five minutes of trusted server time
and a selection expiry at most ten minutes after issue. Successful lease results remain
queryable through the delivery deadline, using a fresh authenticated request, even when
the original selection window has closed. After result GC, the old intent is too old to
select again. Because the operation ID hashes its issue time, changing that time creates
a different operation. A delayed replay cannot become a fresh lease after GC.

The sender durably prepares its intent and the already verified expected base before
leasing. Fresh lookup/selection always checks public SPK expiry and the current observed
profile/counter floor. A retry of that specific pending intent may use its original signed
base through the stored lease's delivery deadline, even after SPK rotation/public expiry;
it cannot become a general stale-bundle exception for new sessions. Keep fresh-public-view,
pending-lease retry and inbound queued-delivery validation purposes explicit. Current
branch revocation, target/key binding and profile integrity are checked in all three.

A no-OPK response has no consumptive side effect and need not allocate a 30-day result row.
If that response was lost before the client durably froze its bootstrap, a retry may see
new availability. Once a response is selected, the SDK persists the exact selected mode,
header and ciphertext before emitting a packet, and never upgrades that operation later.
A successful OPK lease, in contrast, always returns the same key on retry. This distinction
bounds result storage by successful leases instead of arbitrary fallback requests. With
six target leases per hour, a 30-day result window holds at most 4320 results per target;
this is distinct from the 200-key current pool. Owner-status requests name at most 200 local
IDs, so old consumed results do not make owner replies grow without bound.

Expired result rows can be compacted only after their delivery deadline; publication
floors and retired-ID protection survive compaction. On node data loss or rollback, do
not reopen an old pool with an empty cursor. Refuse new leases for that incarnation until
a fresh fenced generation is authorized. Restoring a node backup must restore the ledger
and floors together or trigger this refusal. Existing signed current-head pins and owner
publication floors detect rollback where evidence exists; arbitrary total node rollback
without surviving evidence is outside a local database's ability to detect by itself.

## 6. Quotas, capacity and networking state

Recommended lease limits carry forward the historical numerical policy, with stronger
persistence proposed for native leasing:

| Scope | Limit | Identity |
| --- | --- | --- |
| Requester across targets | 60 successful leases per rolling hour | Authenticated account anchor, shared by its devices |
| Requester-target pair | 1 per rolling 24 hours | Requester account anchor and full qualified target branch |
| Target | 6 per rolling hour across requesters | Full qualified target branch |
| Source prefix | 120 per rolling hour | Verified, masked ingress prefix using the existing ingress policy |

Record successful charges in the same transaction as the lease. Retries do not charge
again. A target's rolling 24-hour success ledger is bounded by its six-per-hour limit
(144 events); requester and prefix indexes expire after their windows. Their aggregate
space is bounded by admitted registered targets and actual successful leases. Unused
requester/prefix identities allocate no successful-lease state. Bounded ingress request
limits still cover repeated rejected/fallback requests. Physical storage exhaustion is
a typed persistence failure, not a global logical quota that silently denies all new pairs.

This proposal does not inherit the historical 4096-entry LRU reset as if it were durable
protection. That implementation sweeps then evicts at capacity, so it avoids global
starvation but can reset an evicted account's allowance; restart also resets those budgets.
The proposed durable rolling ledger avoids those resets. Approval is needed for this
stronger native quota contract. A 5000-pair regression must show that table pressure does
not globally deny a new pair and that recent limits remain effective across restart.

Account admission limits are a different mechanism. Preserve node-bound Capacity reset
hints and readback, existing-principal admission, per-prefix/global new-principal daily
limits, and the current single account connection flight with at most 90 seconds of Busy
retry. Do not regenerate prekeys on Busy, clear a Capacity hint by rotating a pool, weaken
channel binding on retry, or mark an account live before its existing registration/session
and persistence requirements succeed.

With the recommended provider requirement, missing/locked private prekey state or an
expired SPK that cannot be refreshed leaves first connection pending with an explicit
prekey-required/update-required reason. It does not fabricate an admission reset time.
Once a valid SPK and session exist, OPK exhaustion, the 200-key bound, and lease-rate
fallback do not themselves change live to pending. Owner status/maintenance errors remain
visible and cannot falsely report publication success. On explicit account lock, suspend
prekey maintenance and new DM work through the existing account-lock lifecycle; reopening reloads the canonical provider. Do not open a new custody
connection with missing private state. Whether an already live authority-only connection
may survive the lock is part of the connection API decision, rather than a private-key
cache workaround. While live and unlocked, propose owner status/expiry maintenance every
30 minutes, as well as at startup and before relevant key reads; publish only if state
changed. A transport holding private copies to work around a lock violates ownership.

## 7. Bootstrap transcript and local erasure

Retain the existing reviewed X3DH and double-ratchet primitives. This proposal changes
key lifecycle and a versioned transcript/header, not the DH construction. The new profile
binds a domain and version; both qualified identity public keys and branch references;
SPK ID/sequence and selected signed public base/hash; pool generation; selected OPK ID/public key
or explicit absence; initiator `E` and independent `R0` public keys; lease-operation binding
when present; conversation/session identity; bootstrap ordering sequence/version; delivery
deadline; and routed envelope associated data. Every variable-length component is
length-prefixed, with canonical encoding and vectors for both OPK and SPK-only modes.
A changed field or ambiguous concatenation must fail authentication.

The initiator draws independent `E` and `R0`. Derive X3DH using `E`, initialize the sending
ratchet with `R0`, encrypt, then persist only the advanced ratchet plus exact outbound
ciphertext/header/idempotency state. Erase `E`, DH outputs, X3DH root input and serialization
buffers on success and every failure/cancellation path. Never persist a pre-encryption
ratchet snapshot or a retry record containing `E` or the original root seed.

The recipient selects the exact retained SPK and named private OPK by qualified owner,
pool generation and IDs. Missing/consumed OPKs, expired retained keys or inconsistent
profile/transcript are typed refusals. Do not retry a failed OPK packet by dropping DH4 or
choosing an arbitrary other private key. Perform authentication on a working session copy;
unauthenticated input cannot delete an OPK or commit a consumption marker.

After authentication, the account-writer transaction atomically persists the advanced
receive ratchet, existing replay/ordering and message outcome, removes the consumed OPK,
and writes a nonsecret erasure-pending record. A rollback retains the OPK and prior session
and emits no ACK. Duplicate delivery uses the committed receive/replay outcome without
trying to consume again. Concurrent first packets for the same OPK cannot both commit.
The receive session must already have replaced the SPK used as its initial DH ratchet key;
never persist that bootstrap SPK as an extra long-lived session copy.

```text
Authenticate first packet on a temporary session
  -> account writer: advanced ratchet + replay outcome + OPK removal + erasure pending
  -> durable transaction commit
  -> post-commit checkpoint request
  -> successful TRUNCATE, no pinned-reader residual
  -> durable erasure-complete marker
```

Use `secure_delete=ON` for secret-bearing SQLite rows and explicit retirement of old
secret events/projection pointers. Successful transaction commit establishes logical
absence; physical WAL retirement is a separate completion condition. A busy checkpoint
or pinned reader keeps erasure pending and schedules a later attempt through the existing
checkpoint coordinator. A coalesced/rate-limited request is not evidence that TRUNCATE
completed. After a crash, reopen resumes pending checkpoint work without restoring the
key. Never clear the durable erasure-pending marker merely because a request was queued.

These are software storage guarantees, not proof of SSD block erasure or destruction of
an older filesystem snapshot. SQLite documents the scope of
[secure deletion](https://www.sqlite.org/pragma.html#pragma_secure_delete) and the
[TRUNCATE checkpoint mode](https://www.sqlite.org/pragma.html#pragma_wal_checkpoint).
Implementation evidence must use storage API absence, actual checkpoint completion and
reopen failure to load the key; plaintext byte scans of SQLCipher files are not proof.

## 8. Registration, upgrade, restore and home migration

| Event | Proposed behavior |
| --- | --- |
| First native registration | Commit fresh random private state and its public publication; publish current authority, register that exact snapshot, open session, apply acknowledgement and persist existing live state. A failed publish leaves retryable committed state. |
| Daemon restart / reconnect | Load the same pool and counters; perform due rotation/expiry through the provider; retry identical committed publication across Busy/lost replies. Neither credential construction nor registration derives a key. |
| Upgrade from deterministic native SPK | Stop deterministic publication in both initializer and custody transport. Commit a fresh random pool, advance a durable profile/publication floor, then advertise. Retire old event copies securely. Existing ratchets remain; the compatibility grace for old bootstrap packets must be explicit. |
| Data-only fresh restore | Restore permitted history without local private prekeys, branch authority, live sessions or active outbound bootstrap plans. Networking remains pending until attended recovery authorizes a new branch and that branch creates fresh random prekeys. |
| Merge an old archive into a live device | Preserve current private rows, consumed/retired markers, counter/profile floors and outbound ratchet state. Filter private prekeys and legacy secret events from every input/archive table; the archive cannot overwrite them or turn pending into live. |
| Same-branch loss of canonical prekey data | Typed repair-required. Vault possession is not authority to reconstruct old material or reset counters. Prefer an attended fresh branch/epoch; a same-branch pool reset would need an explicit monotone server-fenced authorization. |
| Authority revocation / epoch or key change | Deny new lease/publication and ordinary lookup under the old identity. Pin the new qualified identity; never reinterpret old IDs under it. Existing retention of permitted history is separate from granting new authority. |
| Home migration | Currently unsupported on the native transport. A future migration must transfer lease state/floors atomically with the authority fence, or activate a fresh pool generation only after the old home is fenced. No destination may reissue an old lease. |

Upgrade cannot retroactively erase the old deterministic SPK while the retained agreement
secret can still derive it. A later agreement-secret compromise can reconstruct that old
SPK even if every event row was scrubbed. The forward secrecy claim begins with newly
random prekeys. Any compatibility grace for old captured bootstrap packets is expressly
outside that claim; stronger retrospective protection requires changing retained authority
material and still cannot revoke an adversary's prior copies.

For migration, a fresh destination pool is the simpler recommendation: retain source-era
private keys locally for their existing delivery windows, fence source publication/leases,
and activate a new signed pool incarnation at the destination. The authority handoff must
carry a durable retirement floor for the old generation and a home generation binding.
Preflight and commit destination private state within the same total retention bounds
before committing the source fence; if there is no room, refuse/defer migration without
erasing valid source-era keys or disabling the still-active source. Pool changes do not
reset the qualified branch's lease quotas. Until the native migration service provides
that fence, refuse the operation rather than publish the same live pool independently at
two homes. This is a dependency and proposed
contract, not an extra implemented migration feature.

Maintain counters and retired-ID protection by the complete qualified branch and pool
incarnation, not a display principal or literal device name. A current-authority check
and durable floor are both needed: a valid old signature alone does not make a stale
bundle current. Ordinary caches may keep a base until its signed expiry; a new lease
against a superseded expected base returns refresh-required. Receive retention for a
previously valid packet does not authorize new leases against that old base or override a
current branch revocation when accepting a new bootstrap.

## 9. Compatibility and downgrade boundaries

Distinguish a modern peer receiving a legitimate zero-OPK result from older software that
does not implement the new transcript and independent `R0`. A valid SPK-only result under
the new profile still works; its reduced guarantee is tied to SPK erasure. An OPK quota or
exhaustion is observable through bounded reason counters and owner warnings, not raw keys.

Negotiate using branch-signed bootstrap capability/profile fields, validate against
current native authority, and durably pin the minimum profile after it has been observed.
A directory cannot remove a signed capability without invalidating its signature, but
may withhold an entire newer bundle until expiry or a surviving client floor rejects it.
No response parsing/authentication failure automatically triggers a weaker retry.

For an older peer, recommend an explicitly selected legacy-compatible SPK-only profile
only if the product permits reduced guarantees. Its signed compatibility projection uses
the same independently random SPK and expiry but no OPK pool; it must be a separately valid
signature, not an edited new-profile signature. Legacy header semantics still equate
`E` and `R0`, so that session does not receive the new initiator-erasure guarantee.
Do not send independent `R0` to a receiver that interprets the old header as `R0 = E`.
A strict new-profile policy instead returns update-required. The default needs approval;
this note does not introduce a new configuration key.

Existing established sessions keep their protocol. Versioned new bootstrap applies only
when a fresh session is created. New peers on old nodes must fail registration clearly or
use an explicitly approved rollout adapter; neither missing lease support nor an unknown
profile permits restoring legacy root authority for a native account.

## 10. Storage-copy inventory and threat statement

| Copy | Required treatment |
| --- | --- |
| Branch vault, recovery seed, credential constructors | Retain long-term authority only; no derivation or backup of random SPK/OPK/`E`. Audit every `prekey_bundle` construction path. |
| Canonical account actor | Mutable private SPKs and OPKs with qualified ownership, bounds, consumption and expiry rules. Only one canonical private copy. |
| Legacy events and projection checkpoints | Securely retire payloads/signatures and remove secret-selecting pointers, including archive/event-history copies. Never select them again after migration. |
| Live/archived DM session snapshots | Persist only advanced ratchets. No `E`, bootstrap root or retained bootstrap SPK copy; retire obsolete secret-bearing snapshots through existing ratchet retirement. Skipped message keys retain their established bounded semantics. |
| Receive transaction, decoder and serializer buffers | Zeroizing secret wrappers on every load/drop/error; avoid untracked seed arrays, Debug output and plaintext temporary files. |
| SQLite database, WAL and pinned readers | Logical removal plus explicit post-commit retirement; erasure stays pending until a successful checkpoint. Reopen is part of evidence. |
| Backup snapshot and all archive tables | Sanitize private actors and legacy events before export finalization; filter again on import/merge. A live-state merge preserves the live device's canonical state. |
| Own-device sync / history transfer | Exclude private prekey events, checkpoints and actors; sibling devices generate their own pools. Public status and counts are not seeds. |
| Outbound retries and process restart records | Exact public header/ciphertext and advanced session only; never an X3DH ephemeral or pre-ratchet root. |
| Directory, router backups and gateway mesh | Public material, lease/status metadata and floors only. Restore cannot reset consumed IDs. No private prekeys. |
| Logs, metrics, crash dumps, external snapshots | No key bytes in diagnostics. Counts and bounded error codes suffice. Previously captured dumps/backups or endpoint plaintext remain outside later deletion claims. |

Under the proposed scheme, after a successfully authenticated OPK-backed bootstrap,
logical OPK removal, transient-secret destruction and completed storage retirement,
later compromise of retained long-term agreement/signing keys and current device state
must not reconstruct the captured bootstrap ciphertext. The attacker must not already
possess the erased OPK, initiator `E`, original X3DH root, old ratchet/message keys or an
old private snapshot. Test the recipient and initiator compromise cases separately and
together. Retained plaintext/history can reveal content through its intended access path;
this claim concerns reconstruction from bootstrap secrets, not deletion of that history.

SPK-only bootstrap gains its corresponding boundary only after the selected random SPK
has been retired from every software copy; under the proposed windows that may be 60 days
after creation. Retaining independent `R0` does not retain `E`. Existing skipped message
keys can still decrypt the packets they intentionally cover; do not claim those packets
are erased before their normal retention ends.

A malicious directory can withhold OPKs and force a valid SPK-only result, or lie about
lease metadata and harm availability. Signatures prevent substitution, not withholding.
Compromise before erasure, an active attacker in an unlocked endpoint, rollback of all
surviving evidence, and pre-existing external private snapshots remain excluded. These
limits follow the compromise/server-trust distinction in the
[X3DH security analysis](https://signal.org/docs/specifications/x3dh/#security-considerations)
and the state-erasure requirement in the
[Double Ratchet security analysis](https://signal.org/docs/specifications/doubleratchet/#security-considerations).
The proposed native transcript still needs review and vectors before a security claim.

## 11. Required implementation tests and mutation plan

This is a future acceptance matrix. None of the tests or mutations below is claimed to
have executed for this design-only change. Mutations must compile and fail a behavioral
assertion; a compiler error, timeout, skipped case or substituted mock ledger is not a kill.

| Layer / scenario | Required assertion | Mutation that must be killed |
| --- | --- | --- |
| SDK native non-resurrection | Create a new random pool, consume/retire a key, remove every recoverable private copy, restart daemon with the same vault, then register through custody. Key stays absent and publication cannot recreate it. Capture/reconstruct probe fails under agreement-secret compromise. | Restore either vault-derived SPK construction or initializer overwrite; test each independently. |
| SDK missing-state contract | Initialized marker plus missing/locked/corrupt actor returns the typed pending/repair outcome, with no public Register. Fresh authorized branch alone can initialize. | Treat missing actor as fresh and silently rebuild from credentials. |
| Unit crypto / vectors | Independent `E` and `R0`, explicit OPK absence, both identity keys and all qualified/header/AD bindings agree; each substitution fails. | Reuse `E` as `R0`; omit one identity, field length, OPK selection or ordering/AD binding. |
| SDK consumed-key compromise | Authenticate a captured first packet, commit and checkpoint, reopen; API cannot load OPK; reconstruct using retained agreement key, current SPKs, advanced sender/receiver snapshots and sanitized backup fails. | Keep the consumed OPK, persist `E`/initial root, or retain a pre-authentication snapshot. |
| SDK atomic receive / races | Crash before/after each transaction boundary, invalid ciphertext, duplicate packets, concurrent OPK use and storage failure do not lose an unused key or accept it twice. ACK follows durable commit. | Delete before authentication; split ratchet save and OPK deletion; clear marker before commit; ignore failed commit. |
| SDK WAL retirement | Pinned reader yields pending, not complete; after release a real TRUNCATE succeeds and reopen cannot load the key. | Count queued/coalesced/busy checkpoint as successful or clear the durable pending marker early. |
| SDK rotation and read expiry | Fresh randomness, weekly rotation, old SPK readable through its full deadline, strict expiry on read, at most 10 retained keys and no clock-rollback resurrection. | Derive SPKs, erase after only two days, skip read-time expiry, or discard the matching SPK for a valid queued OPK. |
| SDK additive pool | Seven queued bootstrap leases across the target quota window, followed by replenishment and restart, keep every required private OPK; current unleased keys survive SPK rotation. Advance an injected trusted test clock for the seventh lease; restart must not reset the limit. | Replace the private pool wholesale, tie unleased OPKs to a discarded SPK, or reuse an ID. |
| SDK 200-key lifecycle | 200 unused leases at 31 days are individually erased before refill; 29-day, exactly-30-day, unleased and missing-time keys survive. Expired bootstrap fails after reopen. | Skip expiry at capacity; use `>= 30 days`; clear the whole pool; erase a missing-time entry. |
| SDK authentic owner status | Real Register/Status acknowledgements drive expiry; foreign IDs, stale home, missing ledger, regressed counter and conflicting times cannot cause early deletion. | Inject a foreign ledger, accept unauthenticated status, or shorten a known lease from a conflicting ack. |
| Node atomic lease | Concurrent authenticated native requests get distinct keys; fail commit -> no key response; lost reply/restart -> same operation returns the same OPK without extra quota. | Return before commit; remove transaction/selection serialization; omit durable result/cursor. |
| Node publish/restart/GC | Same publication is idempotent, lower/conflicting counters fail, leased IDs never return, old operation cannot lease again after result GC. | Clear consumed state on republish/restart; delete counter floor; accept stale intent after GC. |
| Native transport authentication | Real SDK -> gateway -> authenticated mesh -> router tests cover current branch proof, session, holder, source and body hash; anonymous/forged/stale/revoked callers cannot lease. | Remove each current-authority/revocation, capability, connection/session or action binding in turn. |
| SDK/gateway handoff reachability | Actual ordinary first DM leases an OPK after handoff; same socket/session owner survives until close, interleaved deliveries arrive, expiry reconnect preserves operation ID, and a one-session-per-principal limit still works. | Leave proxy Disconnect at handoff; use ordinary read-only PrekeyFetch for bootstrap; accept a foreign connection/session or drop a Deliver frame while waiting. |
| Native quota isolation | One account with three devices gets one target OPK per day; another account can lease; target/requester/prefix limits persist across restart; 5000 valid pairs do not globally starve a newcomer. | Key by device; share gateway prefix; reset durable charges; replace target limit with a global full-table denial. |
| Public carrier serialization | Every ordinary lookup/manifest/ack projection has zero OPK material and verifies its base signature; only a lease has at most one key and only owner status has a ledger. | Forward owner upload unchanged in each carrier or strip fields without a valid projection signature. |
| Native authority and freshness | Current native head/cert/key bindings and signed expiry enforced on direct GET, custody lookup, nested manifests and cache reads. Equal names across anchors stay isolated. | Skip the native expiry return path or one current-head/revocation/key commitment check; fall back to legacy authority. |
| SDK restore / backup / sync | Export/import, old archive merge, own-copy history and independent fresh restore cannot resurrect private rows, secret events, consumed IDs, profile floors or active outbound bootstrap. Attended new branch gets new random pool. | Include private actor/event/checkpoint or let archive state overwrite live floors/ratchets/authority. |
| SDK networking / rollout | Pending/live, locked provider, lost acknowledgements, node-bound Capacity hint, 90-second Busy single-flight and unknown-profile refusal obey section 6. | Rebuild pool on retry; mark live early; bypass Capacity with rotation; silently retry a weaker profile. |
| Future native migration | Old-home fence precedes destination activation; no key can be leased at both homes and delayed source packets obey original retention. | Activate destination first or reset the source generation's consumed floor. |

Integration tests must use real custody Register/Status replies and durable node storage,
not just a synthetic lease timestamp injected into a helper. Inject a write failure at
each durable boundary. Use account-writer APIs and existing ingress identity provenance;
no test-only authority path may stand in for the native production path.

Integration acceptance uses product/itest pins recorded together:

| Realnet slice | Native scenario and evidence |
| --- | --- |
| `contact01` (`contact01_realnet_add_then_dm`) | Fresh born-v3 accounts: contact add/accept and first DM using OPK, exhausted/quota SPK-only fallback, directory refresh and restart. Safety number/contact authority remain available and stable across prekey rotation. Verify receipt, delivered plaintext and selected profile without logging keys. |
| `k2b` (`k2b_realnet_surface_round_trip`) | Existing DM/group surface workflow plus first-DM OPK lease, additive replenishment, reconnect and retained-key delivery. Record last STEP, phase timings, native networking state and typed outcome for failures. Preserve existing budgets/assertions. |
| `k5a` (`k5a_realnet_agent_replies_in_dm_and_group`) | Agent-host first DM and group replies on native accounts across restart; compatibility/fallback and independent restored-device pending state do not duplicate sends or restore private prekeys. Surface-specific agent-host assertions belong to the separate `k5a2` slice and are not claimed by `k5a`. |

Run through the real public gateway/custody/router path on supported controller-managed
infrastructure. Unit/SDK/in-process transport evidence is separate from these realnet
results. Compare performance against main in the same time window, with repeated phase
measurements if variance obscures attribution. Measure lease commit critical-section time
and unchanged publication cost. Do not attribute a whole-workflow slowdown to a small
manifest change without paired evidence. No acceptance timeout or assertion is weakened.

## 12. Implementation boundary and rollout prerequisites

A complete implementation must cover canonical private state/migration, both native key
construction paths, custody registration/session frames and ordinary handoff ownership/multiplexing, node transactional lease
storage and quota persistence, all public projections and freshness checks, bootstrap
versioning/erasure, every backup/sync copy and the above tests. Delivering a crypto helper
alone would leave the native reconstruction and registration holes open.

Deploy support at nodes before SDKs require the new registration body. Gate activation on
approved ownership, delivery windows and compatibility decisions. An upgrade must never
roll back by selecting retired private events or re-enabling deterministic key construction.
Rollback after activation either preserves the new public profile/state or explicitly
refuses unsupported new bootstrap; it cannot safely restore old secret derivation.
Runtime-contract documentation and an implementation release note belong in that later
change. This proposal changes no runtime behavior and creates no migration by itself.

## 13. Open questions for approval

1. **Canonical ownership / connection API:** approve account data as the single rotating
   private-key owner and require an unlocked provider for custody connection? If vault-only
   or locked-data connectivity must remain, which explicit authority-only API and networking
   semantics should replace the recommended pending outcome? Confirm the proposed transfer
   of custody ownership and bounded prekey multiplexing across ordinary gateway handoff.
2. **Validity and delivery:** approve 7-day rotation, 30-day public validity, up to 30-day
   queued delivery and up to 60-day SPK private retention (at most 10 keys)? If a shorter
   forward-secrecy window is required, which signed validity/delivery promise is shortened?
3. **Lease metadata trust:** preserve strict expiry from authenticated directory lease time,
   or additionally require 30 days from first local observation to limit false-old-timestamp
   denial of service? Confirm trusted-clock skew and rollback handling.
4. **Native quotas / operation lifetime:** approve durable rolling 60/hour requester,
   1/day requester-target, 6/hour target and 120/hour source limits instead of LRU-reset
   budgets; five-minute fresh intent / ten-minute selection window; result retention through
   delivery? Confirm masks follow the existing ingress policy and publication/status cadence.
5. **Compatibility and activation:** allow explicitly selected legacy SPK-only sessions by
   default with their reduced guarantee, or require the new signed profile? Approve node-first
   deployment, profile floors and the separately signed compatibility projection if allowed.
6. **Upgrade / recovery / migration:** what explicit grace is allowed for old deterministic
   native bootstrap packets, whose keys remain derivable? Approve attended new-branch recovery
   after private-state loss and a fenced fresh destination pool for future home migration?
   Native migration remains unavailable until that authority fence exists.
