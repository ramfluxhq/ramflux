# Account-authorized home-node migration

Design revision 3; review before implementation. The minimal demo subset below
is the **plan of record**, superseding revision 2's broader surfaces and work lists.
This document specifies a cooperative **born-v3-only** operation, not implemented
production behavior. There are no legacy accounts to support after the v3-only
client rollout. Do not implement a v2 authorization mode or create synthetic
legacy roots for this feature.

## Source baseline and implementation dependencies

The fetched product main is `9a8961a9566cf241bd5111c07cfc6167b6347a06`; the docs
branch is based on that main. The inspected custody networking r3 interfaces are
`feat/id-02-impl-2` at `ac89988f858094a47e38435622152968338842a1`. The inspected
local forwarding train is `train/2026-10-27` at
`c18ce82964abf051d2aa517a0bc055de2c1cc973`; its approved predecessor
`626aa37bef0b6085e91080c89fa4809ed88577af` contains the forward-signature fix.
These are source-reading dependencies, not implementation commits in this branch.

Relevant current code and interfaces:

- [SDK migration](../crates/ramflux-sdk/src/client/federation.rs) changes only the
  in-memory federation model. It cannot establish production migration success.
- [Router lifecycle](../apps/ramflux-router/src/lifecycle.rs) currently exposes
  admin-token apply routes. Their request-supplied `now`, timestamp ordering and
  legacy migration proof are not the new user operation.
- [Existing migration state](../crates/ramflux-node-core/src/home_node_migration.rs)
  and [router forwarding](../crates/ramflux-node-core/src/router.rs) need the
  explicit deltas below; retaining the train does not supply them automatically.
- [Custody wire](root_key_custody_wire.md) and
  [custody model](root_key_custody.md) define master-certified management authority,
  current records, branch leases, exporter proofs and mode/fork floors. Their
  historical legacy-transition text does not authorize migration compatibility.
- At the inspected custody r3 revision, `Envelope<DeviceSet>`, `DeviceRef`,
  `BranchProofV3`, `Publication`, `NodeIdentityRecord`, `AuthorityPins`,
  `RouterCore::custody_record`, `CustodyConnection`, `CustodyNetworkConfig` and
  `PrimaryVault` exist. The ordinary SDK/bus session integration and removal of
  legacy creation/registration are separate v3-only rollout dependencies.

Implementation cards start on the inspected custody r3 head with the forwarding
train retained, then integrate the ordinary v3 rollout. Design source dependencies
are not cherry-picked into this docs branch.

The demo gate is the ordinary desktop/bus/CLI E2EE stack with v3 accounts, not the
custody-native provisional single-message DM API. Both nodes must support v3,
share admitted federation, and advertise the completed migration capability.

## Actors, trust and management authorization

The account keeps its anchor, principal id, immutable kind, device identities,
delivery ids, conversations, history and ratchets. Migration changes its home,
not its identity. No node admin credential, internal mesh key or node signing
seed enters a client operation. Migration does not copy or recover a master seed.

| Actor | Responsibility |
| --- | --- |
| Account custody authority | Approve the exact move with the current master-certified primary self-signing key; a branch possession proof alone is insufficient. |
| Initiating device | Authenticate with its current v3 branch, persist the job and submit an exactly authorized intent; it cannot mint management permission. |
| Old home A | Check its own stored custody head, sequence exactly one E+1 against E, durably commit the move and backlog forwarding, and retain discovery for offline devices. |
| Destination B | Check its own authority floors plus A's fresh registration attestation; reserve capacity, create inboxes at seal, courier the commit to A and activate only on A's proof. |
| Senders, contacts and own siblings | Verify the committed home chain, retain monotonic floors, re-resolve signed migrated rejections and retry the original ciphertext. |

The ordinary account passphrase unlocks local account data. **That does not
reconstruct the master or grant custody authority.** A migration confirmation
also requires a management-signing operation using the separate primary/custody
credential. The demo uses the current master-certified primary self-signing key.
Add the custody operations-table row **Home-migration authorization | Primary
self-signing key and exact current record** during implementation. Do not overload
`delegate`: that scope is for the existing group Delegations. The fixed master
scope array is unchanged. Direct-master ceremonies are deferred to
**MIGRATE-MASTER-01**; ordinary migration never asks for the recovery phrase.

The SDK exposes `sign_home_authorization(&proposal_digest)`, which binds account,
destination fingerprint, predecessor, next epoch and exact authorization bytes.
On macOS, re-store the separate primary Keychain item using
`kSecAccessControlUserPresence` through security-framework; require an OS-enforced
LocalAuthentication/Keychain interaction for each migration signature (Touch ID
or the OS login credential). A passphrase-only data unlock or application prompt
is insufficient. Sign once and zeroize the loaded key; do not retain an unlocked
management credential between operations. The current `load_primary` item uses
access-control flags 0 and must not enable migration as it stands. Other OSes
refuse migration with `custody_user_presence_unavailable` until a real provider
implements equivalent protection. The test-memory vault is not a demo provider.

Nodes verify the management signature/current certificate, not a client boolean
claiming user presence. The native SDK/provider is the enforcement boundary.
A stolen secondary cannot migrate; an unattended unlocked primary must still
require OS presence. Compromise of the running primary/OS remains management
compromise; this design does not promise containment of that compromise.

Every request is anchored to v3 `DeviceRef {account_anchor, device_id,
device_epoch}`. Both nodes verify master-certificate range, principal ownership,
current record hash/epoch, branch key/certificate/lease, revocation checkpoint,
kind and fork/mode latches against **their own durable registry**. A client copy
is evidence, never the authoritative floor. A newer client record must first
pass normal verified custody publication; an older or fenced record is refused.
B refreshes through A over admitted mesh before reservation/seal; A rechecks its
own current head atomically at commit. A primary/actor superseded in A's stored
current record cannot commit through a stale B. This is node-local freshness enforcement, not proof that no withheld
newer custody record exists anywhere. After commit, revoking an
actor prevents its later sessions but does not undo the already committed home.

The first demo supports human accounts with a locally available management
signer. External-human-custodian/headless migration is refused with
`custody_approval_required` until the exact remote-approval UI and signer routing
in **MIGRATE-CUSTODIAN-01** are implemented. A headless branch never becomes its
own management authority. This is a declared capability limit, not a v2 fallback.

## Node discovery, pins and existing custody TLS

The destination fingerprint is mandatory, supplied out of band as
`--expected-node-fingerprint`. A missing or changed pin fails closed; no TOFU,
`--confirm-tofu` or `--pin-from-home` path is enabled in the demo. A independently
checks B against its admitted peer record; a user pin never overrides peering.
The existing display fingerprint algorithm remains
`hash_hex(CLIENT_DISCOVERY_DOMAIN, node_public_key.as_bytes())`.

Use `CustodyConnection` on the **existing custody TLS connection**. Resolve/dial
`gateway_tcp_addr` from the pinned, signed v1 client record, with its explicit
`gateway_server_name` and `node_ca_cert_pem`. Dial IP and signed DNS server name
are separate, so bare-IP nodes work. TLS 1.3 uses only the node CA; WebPKI roots
are disabled. In `direct_exporter` mode additionally verify the leaf against
`NodeIdentityRecord.client_tls_certificate_sha256`. Preserve existing node-record
floors and, for the already-supported proxy mode, its authorized proxy receipt.
`no_channel_binding` is refused for every migration mutation.

Extend `CustodyProofAction::HomeMigration {control_hash}` and
`CustodySessionAction::HomeMigration {request}` on that channel, with the matching
`CustodyServerFrame` response. Bind the closed Control/action hash, node audience,
DeviceRef, one-use challenge and actual TLS exporter using the existing v3 proof
flow. Every request requires its fresh action proof; an open message session is
not migration management permission. These are proposed variants, not existing
functionality. Matching request framing must support operation-scoped proofs for
sessionless resolve/status after A refuses ordinary message sessions; it must
not reopen a general message session or bypass current branch authentication.
No HTTP pooling, new control listener or discovery schema v2 is
needed. No public unauthenticated GET is enabled.

B's courier authenticates as B on the existing admitted federation mesh, never
as the account or by replaying B's client TLS proof to A. It forwards the immutable
account authorization and seal; A verifies its own stored custody/head floors.
Before reservation, B obtains A's fresh nonce-bound registration attestation and
current publication, verifies them against B's own pins, and atomically accepts a
new registry entry with admission after possession/capacity checks. Never charge
a victim root's budget before verified membership. Existing safety floors survive
a refused admission.

### Action and reader inventory

The client actions below are typed custody actions, **not new HTTP routes**.
Resolve/status remain sessionless, branch-authenticated custody operations at A
after normal register/open-session is refused. A returning sibling renews expired
credentials through the normal custody path before that authenticated read.

| Action | Node and reader |
| --- | --- |
| `prepare` | B; initiating current device, after A attestation. |
| `seal` | B; initiating device with exact OS-presence-approved authorization. |
| `commit` | A; B mesh courier or authenticated client recovery. |
| `activate` | B; proof-only transition, courier or authenticated own device. |
| `status` | A/B; own current device, signed phase and bounded disjoint counts. |
| `abort` | B before seal; A after seal with a fresh A-audience proof, racing A's noncommit CAS. |
| `resolve` | Authenticated sender or sibling; public chain evidence only. |
| `fence` | B; any authenticated party may relay A's standalone signed fence. |
| internal `attest`, `commit`, `status` | Admitted federation peer, relayed to A's router at `/internal/home-migration/{attest,commit,status}`; no public listener aliases. |

The first prepare preflight asks B to resolve/attest the initiating account at
its known A. `resolve` accepts an optional `old_node_hint` for this purpose; it is
only an admitted-peer routing hint. B asks A to attest; A's node-signed genesis
establishes the missing base. Return that verified record before the client signs
Prepare with its exact hash and the returned HomeAttestation.delivery_map_hash.
The preflight returns A's signed attestation only when the requester owns the
target anchor; the full routing map stays on the A/B mesh. This adds no custody
unlock and allocates no B reservation. Do not sign a made-up predecessor or weaken Prepare's required hash.

PrivateStatus and public GET are deferred. Own status receipts disclose phase and
counts, not delivery maps; maps/publications stay in authenticated A/B service
state. Unknown-root queries allocate no authority cache or operation.

## Wire formats and hash chain

Use strict UTF-8 I-JSON and [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785),
following [RFC 7493](https://www.rfc-editor.org/rfc/rfc7493). Reject duplicates,
unknown fields/versions, lone surrogates, non-finite/fractional/unsafe counters,
trailing input and noncanonical base64url before verification. New fields are
mandatory; nullable fields use explicit null. Existing embedded custody objects
retain their exact versioned encoding and nested signatures. No normalization of
signed strings or recursive signature stripping is permitted.

Notation: `H` is a canonical unpadded base64url 32-byte digest; `N` is 32 random
bytes encoded likewise; `K` is a validated Ed25519 public key; `U` is an integer
in `[0, 9007199254740991]`; `Time` is U in UTC Unix seconds; `Ref` is the existing
v3 DeviceRef; `Id` is a bounded validated identifier; `T?` is T or null.

Migration messages use a closed role-bound envelope:

```json
{"schema":"DOMAIN","domain":"DOMAIN","body":{},"signers":[],"signatures":[]}
```

This is schema metasyntax, not a valid empty message. Sign exactly JCS of
`{schema,domain,body,signers}` with strict Ed25519; enforce `schema == domain ==`
the expected type domain. Signers are exactly `{role,key}`, in the order below;
`signatures[i]` corresponds to `signers[i]`. Reject missing/extra/reordered roles.
The signed metadata fixes key identity and role. Key forms:

- management: `{kind:"master_certified_custody", account_anchor,
  master_certificate_hash, authority_record_hash, public_key}`; the demo has no
  direct-master signer variant;
- actor: `{kind:"branch_v3", device_ref:Ref, branch_certificate_hash, public_key}`;
- node: `{kind:"node", node_id, public_key}` matching the pinned node signer.

There is no `root_v2`, `branch_v2` or legacy branch-proof alternative. The custody
certificate/public record is still its existing `Envelope<T>` type; the new
role-bound message type must not reinterpret that preimage.

Use custody's NUL-framed BLAKE3 convention for new object hashes:
`H(tag,x) = base64url(BLAKE3(UTF8(tag) || 0x00 || JCS(x)))`.
Signed message references use existing `CUSTODY_OBJECT_HASH` through
`custody::framed_hash` with the **complete**
message, including signatures. Existing custody envelopes use `custody::object_hash`
unchanged. A home-record hash uses new
`ramflux.identity.home_record_hash.v1`; delivery-map hashes
use new `ramflux.identity.home_delivery_map.v1`. A discovery reference is the
object hash of the existing signed v1 record; no discovery v2 format is
introduced. No old v1 hash or signature bytes change.
These new labels are reservations to add to `domain.rs`/`ALL` during implementation.

### Closed message bodies

Each row lists all body fields after common required `{version:1}`. All new
schema/domain strings are the full reserved spelling below. Generic `Receipt`
is not the commit proof: its body may report outcomes but cannot activate a home.

| Type / reserved domain | Remaining required body fields | Roles |
| --- | --- | --- |
| Prepare / `ramflux.identity.home_prepare.v1` | `migration_id:N, account_anchor:H, actor:Ref, authority_record_hash:H, branch_certificate_hash:H, previous_home_hash:H, previous_home_epoch:U, old_node:Id, destination_node:Id, destination_key:K, discovery_hash:H, delivery_map_hash:H, nonce:N, issued_at:Time, expires_at:Time` | actor |
| Offer / `ramflux.identity.home_route_offer.v1` | `migration_id:N, account_anchor:H, prepare_hash:H, authority_record_hash:H, previous_home_hash:H, next_home_epoch:U, old_node:Id, destination_node:Id, destination_key:K, discovery_hash:H, server_record_hash:H, gateway_tcp_addr:Id, federation_endpoint:Id, delivery_map_hash:H, admission_id:N, nonce:N, issued_at:Time, accept_until:Time, max_commit_delay:U, forward_seconds:U` | node B |
| Authorization / `ramflux.identity.home_authorization.v1` | `migration_id:N, account_anchor:H, actor:Ref, authority_record_hash:H, management_certificate_hash:H, previous_home_hash:H, next_home_epoch:U, old_node:Id, destination_node:Id, destination_key:K, gateway_tcp_addr:Id, offer_hash:H, delivery_map_hash:H, nonce:N, issued_at:Time, seal_until:Time, max_commit_delay:U, forward_seconds:U` | management, actor |
| Genesis / `ramflux.identity.home_genesis.v1` | `account_anchor:H, home_epoch:0, home_node:Id, home_node_key:K, custody_record_hash:H, registered_at:Time` | node A |
| Control / `ramflux.identity.home_control.v1` | `action:Id, audience_node:Id, migration_id:N, requester:Ref, authority_record_hash:H, payload_hash:H, nonce:N, issued_at:Time, expires_at:Time` | actor |
| Receipt / `ramflux.identity.home_receipt.v1` | `action:Id, migration_id:N, account_anchor:H, node_id:Id, request_hash:H, request_nonce:N, authorization_hash:H?, seal_hash:H?, home_record_hash:H?, phase:Id, state_version:U, sealed_at:Time?, commit_deadline:Time?, commit_proof_hash:H?, response_payload_hash:H, issued_at:Time, expires_at:Time, reason_code:Id?` | answering node |
| Commit proof / `ramflux.identity.home_commit.v1` | `migration_id:N, account_anchor:H, old_node:Id, destination_node:Id, destination_key:K, previous_home_hash:H, next_home_epoch:U, authority_record_hash:H, authorization_hash:H, offer_hash:H, seal_hash:H, commit_deadline:Time, committed_at:Time, forward_until:Time, backlog_manifest_hash:H` | node A |
| Node commit delivery / `ramflux.identity.home_commit_delivery.v1` | `migration_id:N, account_anchor:H, source_node:Id, audience_node:Id, authorization_hash:H, offer_hash:H, seal_hash:H, admission_evidence_hash:H, nonce:N, issued_at:Time, expires_at:Time` | node B |
| Home attestation / `ramflux.identity.home_admission_attestation.v1` | `account_anchor:H, audience_node:Id, previous_home_hash:H, authority_record_hash:H, device_set_epoch:U, delivery_map_hash:H, nonce:N, issued_at:Time, expires_at:Time` | node A |
| Noncommit fence / `ramflux.identity.home_noncommit_fence.v1` | `migration_id:N, authorization_hash:H, seal_hash:H?, fenced_at:Time` | node A |

Identifiers are at most 256 UTF-8 bytes; origins/endpoints are at most 2048 and
are parsed by their explicit URL/address type, not the Id grammar. Actor refs and
key metadata must match verified certificates. Offer echoes prepare's nonce;
controls use fresh per-request nonces. Check equality of anchor, operation id,
predecessor, next epoch, destination, map and all referenced hashes across the
bundle. `next_home_epoch = previous_home_epoch + 1`, checked for overflow.

Control actions are `prepare|seal|commit|activate|status|abort|resolve|fence`,
matched to their audience. Exact payloads: prepare is Signed<Prepare>; seal
`{authorization_hash,offer_hash}`; commit `{authorization_hash,offer_hash,seal_hash}`;
activate `{home_record_hash,commit_proof_hash}`; status/abort
`{account_anchor,migration_id}`; resolve
`{target_anchor,after_home_hash:H?,limit:U,old_node_hint:Id?}`; fence
`{noncommit_fence_hash}`. Nullable fields are explicit. The requester signs resolve
as itself, never as the target. Abort before seal requires the preparer or current
management approval; an uncommitted sealed operation is cancelled at A as below.

A request is `{control:Signed<Control>,payload:object,evidence:object}`.
Evidence is a closed action-specific selection of `prepare`, `offer`,
`authorization`, `seal_receipt`, `commit_proof`, `home_record`, `authority`,
`branch_proof`, `delivery_map`, `client_record`, `server_record`, `attestation`,
`node_identity_record`, `proxy_receipt`, `predecessors` and `noncommit_fence`.
Authority is existing Publication with complete record/compacted evidence, never
a client-asserted epoch. Missing referenced evidence is `evidence_required`;
matching node-stored evidence may satisfy it. Fresh TLS proofs wrap unchanged
immutable business messages. The courier supplies the same evidence with
NodeCommitDelivery and admitted mesh authentication.

The response is exactly `{receipt:Signed<Receipt>,offer:Signed<Offer>?,
commit_proof:Signed<CommitProof>?,noncommit_fence:Signed<NoncommitFence>?,
resolve_result:ResolveResult?,backlog_progress:BacklogProgress?,
attestation:Signed<HomeAttestation>?}`. Unused members
are null. Attestation is returned only for own-account prepare preflight.
Receipt.response_payload_hash hashes those six payload members under
the Receipt domain, excluding the receipt itself. A seal receipt's own seal_hash,
home_record_hash and commit_proof_hash are null to avoid a self-reference.

BacklogProgress is exactly `{scheduled:U,forwarded:U,receiver_acked:U,expired:U,
rejected:U,evidence_required:U,remaining:U}`. Forwarded, receiver_acked, expired,
rejected and remaining are disjoint current-outcome counts, not cumulative event
totals; evidence_required is a **subset of remaining**, not another subtraction.
Node delivery is not an E2EE ACK. Only an own-device status or the A/B mesh may
receive counts; contact resolve returns only RecordEvidence. No PrivateStatus
client route or recursive private admission dump is enabled.

### Idempotence and expiry context

The durable business key is `(account_anchor,migration_id,action)` and its value
binds the immutable payload/authorization hash, not a replaceable transport
nonce. Same business key/hash returns the original outcome; a changed payload
is `idempotency_conflict`. A recovery request may use a new Control nonce, TLS
challenge or B-courier signature after restart; it does not create another
admission or commit. Responses bind that fresh request hash/nonce while returning
the same stored commit proof. One-use transport proofs remain bounded by the
existing custody challenge/session store and are not replayed on new connections.

Let `S = 300`, `MAX_SEAL_DELAY = 600`, `MAX_COMMIT_DELAY = 600`, all seconds.
Control/node-courier requests live at most 300 seconds. The client rejects an
Offer unless `abs(Offer.issued_at-client_now) <= S` and
`accept_until == issued_at+600`. It signs
`seal_until <= min(Offer.accept_until, Authorization.issued_at+600)` and
`max_commit_delay <= min(Offer.max_commit_delay,600)`. B signs its actual sealed_at and
`commit_deadline = sealed_at+max_commit_delay`, with sealed_at <= seal_until.
Checked arithmetic and safe-integer limits apply everywhere.

A independently requires account authorization freshness (issued_at is not more
than S in A's future), verifies those inequalities, and refuses a first commit
if either `A.now > commit_deadline` or
`A.now > Authorization.issued_at+600+max_commit_delay+2*S`.
The hard upper bound is therefore Authorization.issued_at+1800, independent of
B's clock. Neither retries nor a new receipt extends it. A may record terminal
noncommit once either bound passes, or immediately if client cancellation wins.
Order still comes from base CAS, never from client timestamp ranking.

Receipt expiry only limits fresh status assertions; it does not expire immutable
proofs. A sealed client can cancel **until A commits** by winning A's shared
cancel/noncommit-versus-commit CAS. Cancellation after a successful commit
returns that original proof, not rollback. NoncommitFence is standalone,
A-signed and non-nonce-bound: any party can relay it to B. B's matching stored
seal/authorization hashes and A's previous-home key determine acceptance.
Commit proofs/home records are permanent. Terminal noncommit and transient replay
retention are bounded separately below; a contradiction is equivocation.

### Committed home records, bundles and floors

Define a closed tagged HomeRecord:

```json
{"kind":"genesis","genesis":"Signed<Genesis>"}
```

```json
{"kind":"committed","authorization":"Signed<Authorization>","commit_proof":"Signed<CommitProof>"}
```

Strings here denote typed nested objects. A non-genesis record **carries A's
commit proof**, not a mutable side-channel status hint. The account signature
in Authorization authenticates the complete next-home choice and predecessor;
A's proof signs that authorization hash, predecessor and E+1. The whole composite
record is hashed. A's proof intentionally does not contain that resulting hash:
this avoids a circular hash dependency. A computes/persists the full record hash
after signing the proof, in the same atomic commit. Activation receipts reference
that derived hash. No extra primary signature after commit is needed, so B can
complete a cooperative move while the initiating client is asleep.

ResolveResult is exactly `{home:RecordEvidence,predecessors:[RecordEvidence]}`.
RecordEvidence is `{authority:Publication,record:HomeRecord,
management_certificate_chain:[Envelope<MasterCertificate>],
actor_certificate:Envelope<BranchCertificate>?,node_record:Envelope<NodeIdentityRecord>}`.
Each committed entry supplies **its own historical evidence**, never just a
current directory lookup. Genesis has an empty management chain and null actor;
its node record verifies its node signer. A committed entry's node record is
that of its commit issuer (the preceding home). The authorization names the
next home's pinned key. The authority publication supplies the signed device set and compacted membership
evidence needed to verify its hash, manager and the actor's non-revoked membership.
Offer/admission ids, seal/activation receipts and delivery maps are not
contact-resolution fields.

Predecessors are ordered oldest-to-newest from the caller's cached hash (or
genesis) and link without gaps to home. For each non-genesis entry, derive A's
signer key from the previous verified record; verify A's node record, embedded
proof, every referenced hash and management/actor signatures. committed_at must
be inside that actor's branch lease and nondecreasing along the chain.
Manager ranges never decrease along the home chain. Same-range certificate forks
are fenced; a later custody floor does not invalidate earlier historical moves.
A's proof signs the authority_record_hash of its stored current record and thus
establishes the manager's validity at commit. Never compare client master
certificate issued_at with A's committed_at. Verify every record's authority hash,
manager certificate and active non-revoked actor membership against its own
publication. A recovery certificate can be signed while a move is commit_pending,
then published after activation; contacts still accept the older valid move. Preserve known later home/custody floors. A contact that missed three
moves including a primary replacement must verify all three historical
certificate sets; compacting the current roster cannot erase this evidence.
The typed historical verifier does not relax current-session branch proofs.

### Primary recovery during migration

For the minimal demo, **refuse primary recovery while a migration is
commit_pending, commit_outcome_unknown or activating**, including sealed courier
work. Return typed `migration_in_progress` with the operation id and instructions
to finish/cancel/recover that move first. Apply this to every primary replacement
entry point and higher-range publication; direct publication must not bypass it.
A/B persist the guard with migration transitions, serialize recovery publication
and the A commit against the same account state, and retain it across restart.
If recovery already won, the stale move fails `authority_update_required` before
A commits. If migration won, B refuses replacement until activation. A releases its own
recovery guard atomically at commit because it is no longer the home. Normal current-custody publication/branch revocation remains
available and never rolls back the committed home. B releases its guard only after verified activation or proved noncommit. A
retains no guard after commit or proved noncommit. Integrating primary recovery into an
in-doubt move is **MIGRATE-RECOVERY-01**, not an undocumented reconfirmation state
that can leave both homes unusable. B still fails closed on conflicting custody
floors; it must accept the same current publication needed for authorized sessions.

The home chain has its own durable `(account_anchor, home_epoch, home_record_hash)`
floor. The v3 device-set record still has exactly one epoch/state and **no
conditional home section**. Its optional future `home_binding_floor {epoch,hash}`
would be an unconditional checkpoint only, in a separately reviewed version;
ordinary lease renewal cannot authorize/revive a pending home. The initial demo
uses the separate signed chain without changing the v3 DeviceSet schema.

Reject lower home epochs, a gap, a changed hash at the same epoch, or an invalid
commit proof. Identical epoch/hash is idempotent. A serializes one successor per
base by CAS. Concurrent B/C moves from the same honest A cannot both commit;
the loser receives A's signed base-mismatch/noncommit outcome. Two conflicting
A-signed commit proofs are retained as equivocation evidence and yield
`home_fork`; never choose by timestamp. Recovery/forced move is a later explicit
custody operation, not an implicit largest-epoch rule.

Retain home records and commit proofs permanently; transient operations and
noncommit fences use the pruning rules below. A resolve page contains
at most 64 linked records within 1 MiB. First-version admission stops before a
chain exceeds that verifiable 64-record limit (`home_checkpoint_required`). A
reviewed checkpoint/pagination extension is **MIGRATE-CHECKPOINT-01**; do not drop
history or reset the epoch to make room. Cached peers may request a suffix.

## Cooperative protocol, deadlines and recovery

### Prepare and seal at B

1. Verify A and B discovery, pins, capabilities, existing peer admission and the
   current v3 account. On B's first attestation request, A atomically CASes an
   absent home head to node-signed Genesis, only for an account actually
   registered at A as its current home. A's signer binds account, home node/key,
   stored custody hash and registered_at. Return it in prepare preflight before
   signing Prepare. No client-chosen genesis time, second custody unlock or
   alternate genesis at a non-home node. First Authorization binds its hash.
2. B obtains A's fresh nonce-bound HomeAttestation over admitted mesh **before
   creating a reservation**, proving current registration, home base and stored
   custody head. This is mandatory for new-to-B roots and refreshed for existing
   roots as well. The attestation is nonce-bound to this B request, valid for
   at most 60 seconds, and cannot be reused for another prepare. Self-generated
   roots cannot fill reservations merely by
   supplying self-signed authority. Registration PoW can be an additional policy;
   it is not a substitute for this attestation in the demo flow.
3. B compares that attested v3 head with its own persisted floors, validates its
   current publication and denies stale/forked/revoked claims. It reserves one
   bounded admission against the exact base and returns Offer. Offer acceptance
   expires 600 seconds after B's issue time; delayed user approval requires a new
   offer, not an extension through client timestamps.
4. The user explicitly unlocks/confirms custody authorization. Persist the
   management+actor signed Authorization before sending seal. Its `seal_until`
   obeys the account-time and A-clock bounds above; B cannot choose an
   indefinitely executable authorization or freeze cancellation.
5. B atomically CASes prepared -> sealed, saves the exact authorization/map and
   creates **normal router inbox routes for every eligible delivery-map device**,
   including offline siblings. A seal receipt states `sealed_at = B.now` and
   `commit_deadline = sealed_at + Authorization.max_commit_delay`. Persist a B-side `commit_pending_at_A`
   courier item in that same transaction. Own-device seal notice is deferred
   to **MIGRATE-NOTICE-01**; do not claim stolen-primary detection in this demo.

The delivery map is the complete authorized recipient routing map, sorted by
DeviceRef, with no duplicates; each entry is exactly `{device_ref:Ref,
target_delivery_id:Id}` and matches the node-verified roster/current target
bindings. Its hash is H with `home_delivery_map.v1`. Cross-root target collision,
missing initiating device, revoked entries or roster mismatch refuse seal.
A's HomeAttestation signs delivery_map_hash. B rejects a mismatching map at seal.
Routing-map installation does not authenticate an absent sibling session or
publish its prekeys on its behalf. The returning sibling proves its own v3 branch. Include non-revoked offline
members even when their current branch lease needs renewal; creating an inbox
does not extend that lease. They renew through the normal custody path before
access. At commit A rechecks that the map equals its current roster/target
bindings; an intervening enrollment/removal returns `authority_update_required`
before commit rather than leaving a newly enrolled device without a B inbox.
Apply normal revocation/retention policy to any excluded old queue.

Abort and seal use one B reservation CAS. After seal the client can still
request cancellation at A: A atomically commits or creates NoncommitFence.
The SDK routes post-seal abort directly over A's custody connection with a fresh
A-audience proof. B never releases based on a local abort or timeout alone; it requires the fence.
An abort racing a successful commit returns the proof and continues activation.
One sealed/window operation per root excludes only another in-progress window;
after completion a later B -> C -> B move is permitted.

### Commit at A; B drives completion

B delivers the sealed request to A over admitted mesh, retries idempotently and
queries signed status. Client liveness is not required. A verifies the Offer,
B's seal, management/actor signatures and **A's own stored current v3 head**.
Verify the exact predecessor and custody range, admission deadline, actor lease
and revocations, destination pin/admission, map, 600-second maximum and allowed
24-hour forwarding duration. Do not accept a caller-supplied `now`. An A status
query for an unknown authorization must include the verified Authorization alone
before A can assert deadline expiry; an arbitrary guessed id does not acquire a
terminal fence. Both CAS operations are keyed by authorization_hash, not the seal
or migration id. Check the permanent commit index first; an existing commit
returns its proof. An optional seal_hash on a fence is diagnostic only: B matches
the authorization hash. Only account authority can cancel before expiry; mesh
peers can request status/expiry and cannot cancel. The terminal noncommit CAS and commit CAS share the same lock/
durable state, so a delayed request cannot win after A has proved noncommit.

A applies both commit_deadline and the account-time/A-clock hard bound above.
All commit, fence and cleanup checks use max(now, persisted trusted-time floor),
so rollback cannot revive a first commit after its fence was pruned. Admitted A/B
clocks must stay within S=300 seconds; attestation checks this bound. A uses B's
signed deadline without an added grace interval, so honest skew can shorten the
usable window; the independent account-signed hard bound is never extended.
The commit must be one durable transaction/atomic batch that:

- CASes home base E/hash to this unique E+1;
- records the versioned migration, full HomeRecord, commit proof and epoch floor;
- sets `committed_at = A.now` and `forward_until = committed_at + 86400`;
- captures a stable per-device inbox high-water mark and backlog-manifest hash;
- installs forwarding for new inbound submissions and enqueues a durable,
  bounded-cursor backlog drain covering all mapped devices through those marks;
- persists the receipt and idempotence result before returning success.

The high-water barrier covers accepted but not receiver-ACKed online/in-flight
entries as well as offline queues. Audit the retained WAL/inbox source bytes;
where an online path lacks a recoverable entry, retain it until ACK before
advertising migration support. An online sender ACK is not a receiver ACK.

Backlog *scheduling* is atomic with commit; do not copy an unbounded inbox while
holding the commit transaction. The due-work drain pages entries and uses the
same forwarding reservations/leases as new traffic. Submissions racing commit
are serialized into either the captured backlog range or the new forwarding
path; there must be no unowned gap. B creates the routes at seal and processes
forwarded backlog/new messages through its **ordinary router local delivery and
WAL**, never an unrelated provisional buffer.

Forward work includes A's commit proof in node-authenticated routing evidence;
B may verify/persist it and activate before acknowledging that delivery. No
forwarded submission is an alternate activation authority. Until a valid commit
proof is available, there is no successful delivery ACK from an invented buffer.
B also fetches the proof through its commit courier and activates when it arrives,
including when the original client lost its reply. A peer can independently
check that A sequenced the same exact successor from the previous home key.

B's activation predicate is explicit: the proof verifies under the previous
home's key; destination_node equals self and destination_key equals B's own key;
seal_hash equals B's stored seal; authorization_hash, offer_hash, predecessor and
next epoch match its sealed operation; committed_at <= commit_deadline and the
account hard bound; and B's home floor is below next_home_epoch. An identical
already-active epoch/hash is an idempotent success; a different/elevated floor
cannot be overwritten. Proof replay at another destination always fails.

### Backlog, deduplication and outbound traffic

Already ACKed offline inbox entries at A cannot be stranded by switching the
client manifest. Transfer every mapped device's unacknowledged pre-commit range,
including offline siblings. Preserve envelope bytes, sender authority and target
ids. A releases an entry only after B's durable normal-inbox commit/duplicate
ACK, a real receiver ACK already recorded at A, or original inbox_retain_until with
an explicit expired outcome accounted for; any further window-plus-retention
deletion requires a reviewed policy.
It never treats scheduling an attempt or a lost reply as success.

Sealed inbox routes are dormant for ordinary delivery until A's proof is
verified. An A forward carrying that proof can atomically advance B's home state
and then use the normal inbox path; an unrelated direct submission cannot gain
an early delivery ACK merely because its guessed target id already exists.

For each queued entry, first verify the unchanged envelope against the sender's
**current live authority**, including B's independently verified sender anchor,
matching branch key/lease and latest revocation/fork floors. If it verifies, use
the normal forwarding path with no historical receipt requirement. Otherwise
hold the entry at A and report `backlog_evidence_required`/its precise reason in
progress; do not refuse the entire seal, fabricate an intake receipt, bypass
verification, delete it or report delivery. Recheck held items with bounded
backoff until normal inbox retention expires. The demo demonstrates current-lease
senders; an expired sender stays visible as held, without blocking other entries.

The intake-time adapter is deferred to **MIGRATE-BACKLOG-HISTORY-01**. Its receiver
trust rule is part of that card: a purpose-message home_relay receipt is trusted
only when its issuer is the receiving account's home in the verified home-chain
interval covering accepted_at, and accepted_at <= that record's successor
committed_at+S. Verify the authorized receipt-key/node record at original
acceptance, exact sender bytes/signature hash, source/target and branch issuance
intervals; current revocations/floors still dominate. Both B and the receiving
SDK must enforce this historical-home rule. A newly stamped forward/commit is
not old acceptance evidence. No partial historical exception ships in the demo.

Deduplicate across backlog replay, A-forwarded new traffic and a sender's direct
retry. The server tuple is `(verified sender anchor, envelope_id,
target_delivery_id)`; **envelope_id is the transport message id** in the owner's
(sender, message id, delivery id) rule. It is visible/authenticated without
opening ciphertext. Keep normal receiver-side E2EE message-id/replay checks for
the encrypted application message id as well; a node cannot deduplicate by a
plaintext field it cannot read. B derives the sender anchor from its own v3
verification, never forwarder-supplied source metadata. Never drain past the
original inbox_retain_until. Do not regenerate ids or ciphertext on reroute.
Use the train's persistent local-delivery index, independent of the forwarding
peer's source_node_id, rather than only federation Pending/Committed seen keys.
A duplicate must not consume a second local inbox entry after restart.

Persist each backlog cursor/ACK so a crash after B commits but before A records
the ACK only replays the same entry. Preserve original TTL/retention timestamps;
migration does not extend message TTL. Window close does not itself delete held
backlog: retain/report `backlog_incomplete` until its original inbox_retain_until,
then account for normal expiry explicitly. Forwarding retries stop at the window;
expiry is not a delivery receipt. End-to-end receiver receipts, not node ACKs, prove recipient delivery.

A continues delivering already-accepted **outbound federation spools** for this
account after commit. They are not recipient inbox backlog, are not deleted by
migration and do not acquire another forward hop. The client stops creating new
submissions through A as soon as commit is confirmed, before manifest switch;
if commit outcome is uncertain after seal, pause submissions and query status.
Queued local sends retain ids and resume through B after reconnection. Do not
resubmit uncertain old outbound sends under fresh ids. Existing online sessions
at A may receive already accepted work/receipts, but must not submit new account
traffic after the home commit. Registration refusal alone is insufficient.

### Deadline outcomes and finality

There is **no automatic fallback, unilateral activation or late-commit path**.
B activates only from A's valid commit proof. A fixes its first commit time and
window once; duplicate requests return that original result after their request
nonce/transport proof expires. Initial commit deadlines are not extended by
retries. Fresh channel proofs and status nonces authenticate a recovery query.

At the earlier B deadline/account-bound expiry plus skew, B queries A; client
cancellation may query earlier. If A committed in time, recover the proof and
activate. Otherwise A atomically creates NoncommitFence after either A-clock
bound, or immediately when authorized cancellation wins. The standalone signed
fence can reach B via the mesh **or the client**, including during an A/B
partition. B verifies issuer and exact stored authorization/seal hashes, releases
unused staged capacity/routes and cannot reopen that operation. The client
returns to expired/aborted and resumes at A only after its authenticated outcome
is known; a local timeout does not prove that A never committed.

**Absence of a received receipt is not proof of absence of a commit.** If A is
unreachable or the reply is lost, B records `commit_outcome_unknown`, does not
activate, does not silently delete potentially committed inboxes/capacity, and
backs off status recovery. Such in-doubt allocations are separately capped per
peer/root and consume reserved capacity; exhaustion refuses new seals, not old
promises. Once a signed terminal result proves no receipt exists, release it.
This is the honest two-phase uncertainty limit. A may maliciously block progress;
resolve it through node recovery or the future explicit **MIGRATE-FORCE-01**
protocol, never by assuming that a local timer authorizes a new home. This
interpretation of timed release is essential when A committed before the deadline
but its receipt was lost. The demo fault tests cover this case.

A's signed commit makes the home final. A later actor revocation does not roll
it back; B still imports/enforces current authority before allowing sessions,
including source revocations arriving after seal. Primary recovery uses the
explicit migration_in_progress gate above. A newer committed home or
identity tombstone wins over a delayed activation. A return move is a fresh
higher-epoch operation after the previous one-hop window closes. On a return to an earlier node, that
node verifies the new committed chain, installs the higher home floor and derives
registration eligibility from the **current** head naming itself. Historical
migration records/proofs remain immutable; their mere existence must not keep
rejecting registration forever. v1 refuses
chained A -> B -> C forwarding (`previous_window_active`).

### Permanent bootstrap and closing the window

A permanently serves authenticated home resolve/status for a migrated anchor. The
signed registration/session refusal carries the current home-record hash and a
resolve hint, so an offline sibling returning only to A can obtain the verified
bundle and find B. It need not first read a notice trapped in B's inbox.

After `forward_until`, stop new forwards, retain the home head/floor and return
a **signed** migrated rejection. The sender verifies A from its previous binding,
resolves/verifies the full successor chain, updates target_node_id/prekey origin,
and retries the unchanged envelope. Unsigned hints never change a route. A must
refuse migration-capability startup without the matching node signer; an empty
signature is not a degraded working mode. A malicious/offline A can withhold the
bundle; independent replicas/user-supplied verified locators and forced moves
are later availability work, not guarantees of this first version.

## Required deltas against the forwarding train

| Current train behavior | Required first-version change |
| --- | --- |
| Migration effective/window uses account `proof.effective_at`. | Version the durable migration record. Effective away-home state follows the committed home head, independent of clock/window expiry. Forward only while `committed_at <= node_now < forward_until`. Window closure or clock rollback must never re-enable old-home registration/session submits. |
| Route-proof `expires_at > now` can truncate forwarding. | Admission/offer expiry limits accepting the offer, not an active route. Remove that gate for the committed route or derive active-route validity from the persisted forward_until. |
| Apply accepts request `now` and rejects by issued_at timestamp ordering. | Delete client now; node clocks only. Order by expected predecessor/home epoch CAS and idempotent hashes, never client timestamps. |
| A may send a terminal migrated Nack after a forward failure. | B inboxes exist at seal; only normal durable delivery can be ACKed. Preserve lease/backoff/uncertain-outcome semantics. Retryable failures must not be treated as success; a migrated Nack is signed and carries a verifiable resolve path. Sender retries may reach the same normal B inbox. |
| A migration affects new submissions only. | Atomically schedule the pre-commit high-water backlog for every mapped device, with durable drain cursors and safe ACK deletion. |
| Federation seen keys include the forwarding source node. | Preserve normal local-delivery dedup across differing forwarders using sender anchor/transport-message id/delivery id. Cover backlog + direct retry in the same WAL path. |
| B would otherwise need a provisional buffer until activation. | Install delivery-map routes at seal and store through the normal router/WAL dedup path, with A commit proof verified before successful forwarding ACK. |
| Migrated Nack signer can be absent. | Matching node signer is mandatory for capability/startup and every migrated refusal, including offline sibling registration. |
| Sender-signing helper excludes the appended hop marker. | Retain the exact approved exclusion for `home_node_migration_forward_count`; the federation signature authenticates it. Preserve source root/device claims and every other signed extension. Never mutate ciphertext or weaken v3 sender verification. |
| Forward work has bounded reservation leases, Pending/Committed inbound seen records and recovery. | Preserve them for backlog and new work; lease expiry is not an ACK, and an expired lease must not duplicate B's local delivery. Keep per-target isolation and original replay/TTL fences. |
| Historical migrated-away state can refuse registration after a return move. | Derive that gate from the current committed home head; a higher-epoch return permits registration without erasing old proofs/floors. |

## Durable SDK, bus, CLI and UI

Use the ordinary per-account actor/DB and its transactional event outbox. Keep
one immutable migration journal with exact signed bytes, authority/node pins,
predecessor/head hashes, remote state versions, deadlines, backlog counters,
manifest revisions and retry schedule. Commit before every external step. No
primary/master secret or passphrase is journaled. No daemon-wide lock spans
network work. A different current own device may query/finish a committed job;
it cannot use a revoked actor's pre-commit authorization to evade A's checks.

| Durable client phase | Action and restart recovery | User state |
| --- | --- | --- |
| `intent` | Verify pins, local v3 mode and known home; persist id/base. | Checking destination. |
| `prepare_sent` | Retry same request or query B; persist signed offer. | Requesting admission. |
| `awaiting_custody_unlock` | Confirm exact target/base, load separate custody authority and sign authorization. | Unlock/confirm migration. |
| `seal_sent` | Query B or query A with the Authorization; on A fence enter aborted/expired; aborted/expired is terminal; sealed recovers its deadline. | Authorizing move. |
| `sealed` | Persist B receipt; B's durable `commit_pending_at_A` courier runs independently. | Waiting for old home; cancellation races A commit. |
| `commit_pending` | Query A/B; pause uncertain outgoing submissions; never activate from a timer. | Waiting / needs attention if A unavailable. |
| `activate_sent` | Submit/recover A proof at B or observe B's autonomous receipt-based activation. Query B after a lost reply. | Activating destination. |
| `backlog_transferring` | B activation and inboxes are ready; track durable A drain counters without requiring offline devices online. | Moving queued messages. |
| `reconnecting` | Register existing v3 refs at B, republish authorized prekeys and connect ordinary QUIC/TCP-TLS/inbox stack. | Connecting at new home. |
| `manifest_switch_pending` | Persist desired config then atomic replace/fsync; reconcile against verified journal/head after crash. | Saving new home. |
| `forwarding` | B connected, signed home resolution published; retain drain/forward progress. | Moved; backlog/forwarding progress shown separately. |
| `complete` | Window closed and backlog accounted for; preserve floors/proofs. | Move complete. |
| `expired` / `aborted` / `refused` | Proved noncommit, account-bound expiry confirmed by A, or pre-seal abort; resume at A and retain the bounded fence. | Not moved; safe retry available. |
| `needs_attention` | Unknown commit, fork, incomplete backlog, trust/storage error; preserve last confirmed state and query. | Action required; no false success. |

The destination journal has explicit prepared, sealed/commit_pending_at_A,
commit_known, active, terminal_noncommit and commit_outcome_unknown phases.
Every source/destination crash boundary is tested, including after durable A
commit but before any reply, and after B activation before client observation.
The per-account manifest switches gateway addresses, CA/server names, prekey and
signaling endpoints and new-object defaults together, preserving identity/DB
location/ratchets and existing objects' recorded relay ownership. Migration does
not transfer old attachments or backups; those are **MIGRATE-OBJECTS-01** work.

The bus/event contract for **MIGRATE-SDK-01 and DESK-MIGRATE-01** is:

- `account.home_node.migrate {operation_id,target_discovery_url,expected_node_fingerprint}`;
  all fields required, no null/missing pin or automatic alternate pin source.
- `account.home_node.migration.status {operation_id}` and
  `account.home_node.migration.abort {operation_id}`; after seal abort asks A to
  race commit and obtains its fence/proof, never cancels a committed home.
- Protected `account.home_node.migration.confirm {operation_id,proposal_digest}`;
  the OS user-presence operation signs the exact pending authorization, not an
  arbitrary caller digest or an ordinary data-unlock boolean.
- Durable `home_migration.progress {operation_id,seq,phase,source,target,
  home_epoch,home_hash,commit_deadline,forward_until,backlog:{scheduled,forwarded,
  receiver_acked,expired,rejected,evidence_required,remaining},reason?}`.
  Pending times/hash fields are explicitly null until known. Status returns the
  same latest snapshot; transactional outbox replay resumes by sequence. Field
  sizes/types follow the wire budgets. No secret or delivery map enters events.

`rf account migrate-home --account ID --to DISCOVERY_URL
--expected-node-fingerprint FINGERPRINT` drives the same job/confirmation. Status
and abort use the durable operation id. Terminal success requires B's live v3
session and verified committed home; backlog/window completion is separate.
Typed failures map to nonzero exits; pending/needs_attention does not report a
completed move. CLI automation does not replace OS presence.

The minimal **desktop** migration screen is on the demo critical path, supplied
by DESK-MIGRATE-01 consuming exactly these bus methods/events. Show source/target,
mandatory fingerprint, OS confirmation, cancellation outcome, deadline, held and
forwarded queue counts, B connectivity and remaining window. Lost A shows honest
needs_attention. TUI consumes the same state; advanced UI is MIGRATE-UI-01, but
that does not defer the minimal desktop screen.

Exclude migration journals/active timers from v1 backup export/import entirely.
The signed public home floor still survives account restoration through current
node resolution; stale backup state cannot lower a locally retained floor or
restart a job. **MIGRATE-BACKUP-01** will add inert diagnostic job history later.
Before networking, a restored v3 device refreshes custody and the home chain.

## Bounds, errors and minimal work packages

Require 64 KiB ordinary control messages, 8 KiB individual signed migration
objects and a 10-second whole-exchange deadline (not reset by trickle reads).
Admission evidence uses the existing 5 MiB custody frame ceiling with
streamed caps before allocation, retaining existing 512 KiB v3 record and 4 MiB
revocation-list bounds. Both individual and aggregate limits apply; no roster
or revocation truncation. Resolve pages are bounded as above. Heavy verification
is off the sole socket-reader worker; at most 16 migration crypto jobs/node.

After verifying identity and A's attestation, allow prepare burst 2, 6/hour/root,
one unsealed and one in-progress sealed/window operation/root, at most 1024
unsealed reservations/node and a configured admitted-peer share. In-doubt seals
have a small explicit per-peer cap (initially 16) and consume account capacity.
Authenticated status/resolve: burst 10, 60/minute/requesting root, no durable
allocation for an unknown query. Retrying an id/hash consumes no new reservation. Cheap
source/connection limits apply before crypto; authenticated root quotas are
charged only after verification. Preserve configurable per-source CGNAT ceilings
and independent global/root caps. A signed registration attestation prevents
anonymous-root reservation exhaustion; an admitted peer can still deny service,
so capacity and per-peer caps remain necessary.

Keep typed refusal codes: `v3_required`, `custody_approval_required`,
`authority_update_required`, `actor_revoked`, `migration_in_progress`,
`custody_user_presence_unavailable`, `pin_mismatch`, `channel_binding_required`,
`base_mismatch`, `home_fork`, `idempotency_conflict`, `admission_expired`,
`commit_expired`, `commit_outcome_unknown`, `previous_window_active`,
`home_genesis_required`, `home_checkpoint_required`, `backlog_incomplete`,
`backlog_evidence_required`,
`capacity_refused`, `peering_unavailable`, `evidence_required`, `rate_limited` and
`storage_unavailable`. Unauthenticated control errors are generic; no private
map or private-operation oracle is exposed. No public movement-history GET
exists. Log bounded ids/codes, not secrets/full evidence.
Transport replay keys are anchor-qualified/action/audience/nonce-bound. Business
keys use the separate idempotence tuple. Keep at most 256 **live** operations/root
and 16384/node; completed/expired operations do not consume live admission budgets.
Delete expired unsealed reservations and their business/replay keys after
accept_until+S. Keep terminal noncommit fences/replay outcomes until at least
Authorization.issued_at+1200+2*S; no first commit can execute after that hard bound.
Then prune them. Persist the trusted-time floor used by cleanup; a clock rollback
pauses admission until time is safe again, so expiry cannot become executable
after its fence was pruned. An already-expired replay must not allocate another operation.
A can reissue a standalone expiry fence without storing a new transient row,
after checking its permanent commit-proof index first; it must return any
existing commit proof instead. Keep home floors, records and proofs permanently.
A completed committed operation can compact to its proof and final counts after
its forwarding/drain obligations settle; in-doubt and unfinished drains remain
live. Expiration cleanup is crash-safe, bounded and restores capacity; cheap
expired prepares cannot permanently exhaust the node.

A removed dead peer's in-doubt records are retained in bounded quarantine, not
charged to unrelated peers' admission shares. Do not erase a potentially
committed seal to free capacity. Durable peer retirement/quarantine accounting
must survive restart. Never restore migration/home state backwards from a node
backup; reconcile external known floors before enabling a restored node's
migration capability. Refuse node-key rotation while migration records depend
on that key until MIGRATE-NODE-ROTATE-01 supplies a reviewed rotation protocol.

Drain pages are at most 64 entries, 128 transitions/tick and four concurrent
forwards/peer, retaining train leases. Every item verifies or is held; a poison
entry cannot abort all groups/accounts' drain work. Fresh status never renews
authorization or rewinds floors. General pruning beyond these mandatory M7 rules
is MIGRATE-RETENTION-01; chain checkpoints remain MIGRATE-CHECKPOINT-01.

## Minimal demo subset: plan of record

This is the reviewed subset and file-level implementation plan. It preserves
one E+1 per base, A-proof-only activation, mandatory pin, exporter-bound control,
OS-presence management approval, backlog forwarded or visibly held, dedup and
signed migrated refusals. It supersedes the six broad r2 work packages.

**Schedule gate: rewritten s51 must be green on the QA host by 2026-10-31.**
Otherwise omit migration from the 2026-11-02 demo and inform the owner. Never
substitute admin routes, fixture-forged proofs or a weaker custody gate.

### Explicitly deferred surfaces

| Deferred surface / card | Demo behavior |
| --- | --- |
| New control HTTPS listener, discovery v2, additional proxy deployment: MIGRATE-DISCOVERY-01 | Existing custody node-CA/leaf-pinned exporter connection suffices. |
| A-derived pin / `--pin-from-home`: MIGRATE-PIN-01 | Explicit destination fingerprint required. |
| Direct-master ceremony: MIGRATE-MASTER-01 | Current primary self-signing key only. |
| PrivateStatus: MIGRATE-PRIVATE-STATUS-01 | Own signed phase/count status; maps remain inside homes. |
| Public GET / independent replicas: MIGRATE-REPLICA-01 | Authenticated resolve at A for senders/siblings. |
| Intake-time historical RelayAcceptance: MIGRATE-BACKLOG-HISTORY-01 | Current-live sender authority or held/reported, never seal refusal. |
| Own-device seal notice: MIGRATE-NOTICE-01 | No stolen-primary detection claim. |
| Forced move, recovery, external custodian | MIGRATE-FORCE-01, MIGRATE-RECOVERY-01, MIGRATE-CUSTODIAN-01; fail closed. |
| Attachments, backup job history, advanced UI | MIGRATE-OBJECTS-01, MIGRATE-BACKUP-01, MIGRATE-UI-01; minimal desktop remains required. |
| Checkpoint/retention beyond M7 and node-key rotation | MIGRATE-CHECKPOINT-01, MIGRATE-RETENTION-01, MIGRATE-NODE-ROTATE-01. |

### MIGRATE-SRV-01: reviewed file-level work list

Implementation starts on custody r3 with TRAIN-01, integrating ordinary v3-only
clients (ID-02-IMPL-3), S51-REG-01 and the second-node deployment as dependencies.
Paths below are implementation targets, not files claimed to exist already.

**SRV-01a protocol/crypto, review before server work:**

- `crates/ramflux-protocol/src/domain.rs` and `ALL`: reserve full
  `ramflux.identity.` domains home_prepare.v1, home_route_offer.v1,
  home_authorization.v1, home_genesis.v1, home_control.v1, home_receipt.v1,
  home_commit.v1, home_commit_delivery.v1, home_admission_attestation.v1,
  home_noncommit_fence.v1, home_record_hash.v1 and home_delivery_map.v1.
- New `crates/ramflux-protocol/src/home_migration.rs`: closed types, role-bound
  Signed<T>, per-record ResolveResult, strict I-JSON/JCS. New
  `crates/ramflux-crypto/src/home_migration.rs`: sign/verify, historical verifier,
  framed hashes and pure activation predicate.
- `crates/ramflux-protocol/src/custody/network.rs`: HomeMigration proof/session
  actions and server response; keep actual TLS exporter/node audience binding.
- `crates/ramflux-crypto/tests/home_migration_vectors.rs`: every golden,
  role/schema mutations and cross-schema negatives; three missed moves plus
  primary replacement; wrong-destination proof replay.
- Add the primary self-signing home-migration row in `docs/root_key_custody_wire.md`.

**SRV-01b persistence:** new
`crates/ramflux-node-core/src/home_migration_store.rs` (redb):

| Table / key | Value |
| --- | --- |
| home_head[anchor] | epoch, record_hash, record |
| home_records[record_hash] | immutable record plus per-record evidence |
| migration_ops[(anchor,migration_id)] | A/B role, phase, prepare, offer, authorization, seal receipt, proof/fence, deadlines, state_version, recovery guard |
| business_keys[(anchor,migration_id,action)] | payload hash, outcome, expiry |
| courier_due[(due_at,anchor,migration_id)] | retry work |
| backlog_cursor[(anchor,migration_id,target_delivery_id)] | high_water, next_seq, disjoint counts |
| budgets[root] | live operation/reservation charges |

One transaction per transition; mandatory M7 cleanup and atomic recovery/commit
serialization are part of this package, not a later optimization.

**SRV-01c destination B:** `crates/ramflux-node-core/src/custody_service.rs` and
`apps/ramflux-router/src/custody_listener.rs` dispatch prepare/seal/status/activate/
abort/resolve/fence; `apps/ramflux-gateway/src/custody.rs` passes frames through
existing proxy-receipt mode. `router_wal.rs`/`router.rs` install dormant inboxes:
no delivery ACK before the matching commit proof activates that exact home.
`apps/ramflux-router/src/router_runtime.rs` runs the durable courier on admitted
mesh via `apps/ramflux-federation/src/flow.rs` and `federation_crypto.rs`, relayed
to federation `apps/ramflux-federation/src/admin_http.rs`, then router internal
`/internal/home-migration/{attest,commit,status}` in
`apps/ramflux-router/src/handlers.rs`. Implement
A-clock-bound deadline queries and the 16-per-peer in-doubt cap.

**SRV-01d old home A:** attest atomically creates node Genesis; commit against
A's own custody head does base CAS, both time bounds, map equality, proof/record,
forward_until=A.now+86400 and per-device backlog cursors in one redb transaction.
Cancel/noncommit uses the same CAS. Recovery publication respects its durable
guard. `router.rs::effective_migration_for_registration` derives the signed
HomeNodeMigrated register/session/submit refusal from home_head. Startup requires
the node service signer. Authenticated resolve persists after migration.

**SRV-01e forwarding/drain:** version `HomeNodeMigrationRecord` in
`home_node_migration.rs`; effective state follows home_head and forwarding uses
committed_at <= now < forward_until. Remove route.expires_at, caller now and
issued_at ordering gates in `router.rs`. Page 64 inbox entries with train leases;
release A only on durable B/duplicate ACK, receiver ACK or inbox_retain_until.
B derives v3 sender keys itself. Implement current-authority-or-held per entry,
normal persistent WAL dedup, source revocation/floors, and every delta table row.

**SRV-01f legacy removal, after rewritten s51 is green:** delete
`/admin/home-node-migration/apply` and `/admin/home-node-route/update/apply` from
`handlers.rs` and test listeners, their caller-now DTOs and seed-forging fixture.
No combined mode or client admin-token escape hatch.

Native crash/regression tests: after seal/before courier; after A commit/before
reply; after B activation/before observation; every backlog ACK; concurrent B/C
base CAS; malicious far-future Offer; cancellation/commit race; blocked primary
recovery; client-relayed fence during mesh partition; lost commit reply/in-doubt;
expired-prepare budget recovery; backlog/direct retry after B restart; stale-map
enrollment; current-live delivery and expired-lease held progress.

### MIGRATE-SDK-01 / DESK-MIGRATE-01: reviewed file-level work list

- **SDK-01a vault:** `crates/ramflux-sdk/src/custody/vault.rs`, OS userPresence
  primary item and `sign_home_authorization(&proposal_digest)` with exact pending
  destination/base/epoch, one signature and zeroization. Refuse other OSes.
- **SDK-01b journal:** new `crates/ramflux-sdk/src/client/home_migration.rs`, durable
  account DB table under `bus/journal`, phases above, persist before sends,
  restart reconciliation, manifest switch; replace the in-memory
  `federation.rs::migrate_home_node`.
- **SDK-01c transport:** `custody/network.rs` uses the new custody actions and a
  fresh operation challenge; no parallel HTTP/TLS implementation.
- **SDK-01d sender:** submit-outcome handler verifies signed HomeNodeMigrated,
  the cached-head chain with per-record evidence, updates target/prekey origin
  and retries unchanged envelopes. Sibling resolves A's refusal then connects B.
- **SDK-01e bus/CLI:** implement the exact methods/events above; add
  `rf account migrate-home` in `apps/rf`, typed terminal exit states/status/abort.
- **SDK-01f desktop:** DESK-MIGRATE-01 consumes exactly SDK-01e; minimal screen,
  OS presence and progress are required for the two-Mac desktop demo.
- **SDK-01g s51:** rewrite the existing itest file with ordinary v3 rfd/CLI users,
  real fingerprint and node-issued proofs, restart boundaries and exactly-once
  E2EE decryption. The default-off `itest-memory-vault` is harness-only.

The scenario has A/B already admitted, a primary Mac and offline sibling,
a same-A sender exercising local forwarding and a third sender with the old
route exercising signed-refusal resolution. Desktop invokes the same bus flow
as CLI. Rewritten s51 must not contain `S51_ROUTER_ADMIN_TOKEN`,
`realnet_node_signing_seed` or admin home-migration paths. Add s51 to the push
Realnet workflow. Clock/window overrides require a default-off test feature;
release/demo-image provenance must assert it is absent (and no memory vault).

## Acceptance matrix

- **Cryptography and schema:** every signature/hash golden; role order and
  schema==domain; reject old r1 root/branch-v2 payloads, custom/null/default
  ambiguity, I-JSON violations, mismatched anchor/ref/certificate/offer/predecessor,
  map, node pin, TLS audience, account/A-clock bounds and expired authorizations.
  Cross-schema vectors
  enumerate existing root/branch/node preimages and prove none can substitute
  for the top-level `{body,domain,schema,signers}` migration transcript.
- **Authority and network attacks:** stale-but-valid client publication, primary
  recovery refused while migration is pending/activating, actor revocation
  against each node's stored head; wrong node
  CA/SNI, WebPKI-only trust, attacker first-use discovery, wrong/deployed-missing
  proxy key, wrong exporter/operation or no-channel-binding downgrade; all fail.
- **Concurrent migration:** B and C seal the same base; A commits exactly one,
  signs the losing refusal; no destination activates without the winning proof.
  Retain conflicting A-signed proofs and fence on simulated A equivocation.
- **Crash boundaries:** before/after prepare/seal, B commit-courier persistence,
  A's atomic commit/drain scheduling, B activation, each backlog ACK/cursor,
  manifest replace and journal event ACK. Lost A receipt before deadline then
  A unreachable after deadline remains uncertain, not expired/active by a timer.
  Once A recovers, recover the original proof/deadline or a terminal noncommit
  fence; never extend the window or destroy potentially committed storage.
- **Backlog/dedup:** ACK messages into A before commit for initiating and offline
  devices, race more submits at commit, replay backlog and direct retries after
  B restart, lose destination ACKs. One normal B inbox entry per authenticated
  sender/transport-message/delivery tuple, successful E2EE decryption and stable
  receiver replay protection. Do not acknowledge mere scheduling as delivery.
- **Outbound and siblings:** A completes accepted outbound spools; new source
  submits stop at commit. Offline sibling starts with A only, verifies signed
  migrated refusal, resolves B from A and reconnects without a new identity.
- **Privacy and abuse:** contact resolve lacks delivery map/full roster; own-device
  and admitted-home status views are separately authorized; no public GET.
  New roots without
  A attestation cannot reserve; CGNAT peers share source limits without spending
  a victim root's budget. Oversized/trickle clients cannot allocate unboundedly.
- **Return and expiry:** after the first window, B->A works without a permanent
  active-root exclusion. Advance test-only clocks/durations to close the window;
  A still serves signed resolve/rejection, sender retries directly to B. Pending
  backlog is explicit attention, never silently deleted. Restarts and stale
  backups cannot reopen forwarding or resurrect an old migration.

**Rewritten s51 live boundary:** create/contact the v3 account at A through the
ordinary CLI/bus, establish normal E2EE sessions, leave a sibling offline and
queue DMs at A, invoke `rf account migrate-home` with a real pin, and observe
B-issued admission/seal plus A-issued commit proof. Restart both nodes and the
daemon at lost-response boundaries. Receive/decrypt both the pre-commit backlog
and DMs submitted via the cached A route during the window, exactly once. Verify
sender re-resolution/direct B delivery and sibling bootstrap. Blackhole A during
commit in a separate negative case: no B activation, honest needs-attention.
After the window test signed migrated rejection and direct retry. The fixture
never constructs a destination proof from its seed or calls an admin apply route.

Implementation remains gated on design approval, the merged forwarding train,
completed v3-only ordinary clients and realnet evidence. Native unit/bus evidence
must not be described as this live acceptance boundary.

## Checkpoint corrections: authorization finality and historical authority

Without a cached head, accept genesis only from the independently pinned node
already used for this contact, including the issuer of a signed migrated refusal.
An arbitrary admitted node cannot bootstrap another contact's home. B asks A to
attest only when requester.account_anchor equals the target anchor. The closed
A-bound AttestRequest carries the owner's Signed<Control> with action attest,
audience A, fresh nonce, current authority hash and a HOME_ATTEST_REQUEST-framed
payload hash over {account_anchor,destination_node,nonce}. A verifies this before
creating genesis. B-to-A terminal queries use a node-signed PeerStatus containing
version, account_anchor, migration_id, authorization_hash, audience_node,
destination_node, nonce, issued_at and expires_at under home_peer_status.v1;
peer admission and destination matching remain mandatory. Neither peer request
grants cancellation authority.

Prepare.expires_at must be after issued_at and no more than 300 seconds later.
A cancel from seal_sent requires only the verified Authorization; B withholding
its seal reply cannot wedge the owner's terminal query. After the signed hard
bound A reissues a fence from that Authorization, after checking permanent proofs.
The fence remains until that bound regardless of peer-supplied operation fields.
Use a separate home_backlog_manifest.v1 domain for the high-water cursor manifest.

SDK-01a re-stores a primary credential into a versioned Keychain item with
userPresence (security-framework 3.7.0), reads it back under OS presence, then
journal-deletes the old flags-0 item. Resume this journal after crashes; do not
enable migration while an old unprotected primary item remains. Access-control
flags cannot be changed in place. Branch items keep flags 0 so routine sessions
do not prompt. Existence checks use attributes only or authentication-UI-skip;
never trigger presence by probing whether an item exists. The provider has no
custom operation prompt text API, so the UI explains the destination separately.
A daemon must run in the user's GUI/login session for OS interaction; headless
or noninteractive daemons refuse rather than silently bypass presence. Previously
copied primary seeds remain a residual risk. The two-Mac manual demo step checks
both successful presence and cancel-without-commit.

The SDK s51 work item refers to the separate ramflux-itest repository. Its final
fixture uses real account signatures and both live homes; product tests cannot
substitute for that acceptance boundary.
