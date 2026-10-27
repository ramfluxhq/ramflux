# Account-authorized home-node migration

Design revision 2; review before implementation. Revision 2 replaces the earlier
v2-account, TOFU, automatic-fallback and conditional-custody-record proposals.
This document specifies a cooperative **born-v3-only** operation, not implemented
production behavior. There are no legacy accounts to support after the v3-only
client rollout. Do not implement a v2 authorization mode or create synthetic
legacy roots for this feature.

## Source baseline and implementation dependencies

The fetched product main is `9a8961a9566cf241bd5111c07cfc6167b6347a06`; the docs
branch is based on that main. The inspected custody networking r2 interfaces are
`feat/id-02-impl-2` at `aa2165487d4308081de724c65c5993399f1becdf`. The inspected
local forwarding train is `train/2026-10-27` at
`15ffa9f4827bbc2f4722aea723334f713d63b449`; its approved predecessor
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
- At the inspected custody r2 revision, `Envelope<DeviceSet>`, `DeviceRef`,
  `BranchProofV3`, `Publication`, `NodeIdentityRecord`, `AuthorityPins`,
  `RouterCore::custody_record`, `CustodyConnection`, `CustodyNetworkConfig` and
  `PrimaryVault` exist. The ordinary SDK/bus session integration and removal of
  legacy creation/registration are separate v3-only rollout dependencies.

The demo gate is the ordinary bus/CLI E2EE stack with v3 accounts, not the
custody-native provisional single-message DM API. Both nodes must support v3,
share admitted federation, and advertise the completed migration capability.

## Actors, trust and management authorization

The account keeps its anchor, principal id, immutable kind, device identities,
delivery ids, conversations, history and ratchets. Migration changes its home,
not its identity. No node admin credential, internal mesh key or node signing
seed enters a client operation. Migration does not copy or recover a master seed.

| Actor | Responsibility |
| --- | --- |
| Account custody authority | Approve the exact move with the v3 master or a currently master-certified custody signer; a branch possession proof alone is insufficient. |
| Initiating device | Authenticate with its current v3 branch, persist the job and submit an exactly authorized intent; it cannot mint management permission. |
| Old home A | Check its own stored custody head, sequence exactly one E+1 against E, durably commit the move and backlog forwarding, and retain discovery for offline devices. |
| Destination B | Check its own authority floors plus A's fresh registration attestation; reserve capacity, create inboxes at seal, courier the commit to A and activate only on A's proof. |
| Senders, contacts and own siblings | Verify the committed home chain, retain monotonic floors, re-resolve signed migrated rejections and retry the original ciphertext. |

The ordinary account passphrase unlocks local account data. **That does not
reconstruct the master or grant custody authority.** A migration confirmation
also requires a management-signing operation using the separate primary/custody
credential. The recommended demo path is the master-certified primary
self-signing key, authorized by the current master certificate's `delegate`
scope for this narrowly defined, one-operation migration authorization. It is
not an implicit generic branch delegation or a new privilege inferred from
`register`/`message` capability. The master-certified path avoids requesting the
recovery phrase for a routine move. An explicit direct-master ceremony can sign
the same authorization, but is not required for the demo and never persists the
master in runtime state.

The SDK must expose a purpose-bound signing interface: explicit user unlock and
confirmation bind the account, destination fingerprint, predecessor hash, next
home epoch and authorization digest. Passphrases go through the protected
existing unlock channel/TTY, never argv, logs or progress events. The inspected
`PrimaryVault::load_primary` is a credential-loading API, not evidence of such
confirmation; the SDK work list must add the gated operation. Nodes verify the
resulting signature and certificate chain, not a client boolean saying that a
passphrase was entered. A stolen secondary containing branch credentials cannot
migrate. Compromise of the unlocked primary/custody signer remains management
compromise; this design does not claim to contain it cryptographically.

Every request is anchored to v3 `DeviceRef {account_anchor, device_id,
device_epoch}`. Both nodes verify master-certificate range, principal ownership,
current record hash/epoch, branch key/certificate/lease, revocation checkpoint,
kind and fork/mode latches against **their own durable registry**. A client copy
is evidence, never the authoritative floor. A newer client record must first
pass normal verified custody publication; an older or fenced record is refused.
B refreshes through A over admitted mesh before reservation/seal; A rechecks its
own current head atomically at commit. A primary/actor superseded in A's stored current record cannot commit through
a stale B. This is node-local freshness enforcement, not proof that no withheld
newer custody record exists anywhere. After commit, revoking an
actor prevents its later sessions but does not undo the already committed home.

The first demo supports human accounts with a locally available management
signer. External-human-custodian/headless migration is refused with
`custody_approval_required` until the exact remote-approval UI and signer routing
in **MIGRATE-CUSTODIAN-01** are implemented. A headless branch never becomes its
own management authority. This is a declared capability limit, not a v2 fallback.

## Node discovery, pins and TLS

B's node key must be established by either:

1. a user-supplied expected node-key fingerprint obtained out of band; or
2. A's fresh, node-signed peer-admission attestation naming B's admitted key.

There is **no TOFU or `--confirm-tofu` migration path**. An unverified candidate
can be displayed, but cannot authorize a move. A changed pin is a security
failure. The existing display fingerprint remains
`hash_hex(CLIENT_DISCOVERY_DOMAIN, node_public_key.as_bytes())` over the encoded
key string; changing the discovery schema must not silently change that display
algorithm. A's commit independently compares B's key to A's own admitted peer
record; a user pin does not override A's federation policy.

Version the signed client record as `ramflux.well_known_client.v2`, with a new
signature domain `ramflux.client_discovery.v2`. Retain all v1 fields and add exactly
`control_https_origin`, `control_server_name` and `custody_node_record_hash`.
The full closed v2 type and its signature bytes include these fields. Do not
append fields to the current `deny_unknown_fields` v1 type or accept v1 as
migration-capable. Ordinary discovery may explicitly decode either schema;
migration requires v2. A signed capability alone without these fields is not
sufficient. The referenced v3 node identity record must verify under the same
pinned node key and its retained node-record floor.

The client connects to the address in `control_https_origin`, but TLS validates
the explicit `control_server_name`, using **only `node_ca_cert_pem` from the
pinned, signed record**. Require TLS 1.3; built-in WebPKI roots are off. A valid
public-CA certificate that does not chain to this node CA is refused. Node-CA
expiry, hostname mismatch and changed CA evidence fail closed.

For an IP-only deployment, the origin may contain the dial IP and port while
the certificate's DNS SAN is the signed control server name. Use the existing
`GatewayTcpTlsStream` pattern: resolve/dial the origin separately and pass the
signed server name explicitly to rustls for SNI/verification. HTTP Host remains
the signed origin authority. Do not let an HTTP client's default IP-derived SNI
or default root store replace this rule. Fetching a signed discovery record over
HTTP is permitted only before control, with its signature/key checked against
one of the pin sources above before accepting its CA.

Serve control on a public **client TLS listener**, separate from the plaintext
federation read origin and all federation administration. Keep the existing
public read port's contract; add a separately configured demo control TLS port.
The v2 record advertises that actual dial origin. No admin route is exposed by
this listener. Forwarding, commit delivery and node-local authority lookup stay
on authenticated internal/peer service channels.

Reuse custody r2's one-use challenge, operation hash, `BranchProofV3`, and
`direct_exporter` binding on the actual client TLS connection. Extend its typed
action vocabulary with migration actions; do not disguise a mutation as
`OpenSession` or `Register`. The audience is the specific receiving node id.
Where TLS terminates before the router, use the existing node-authorized proxy
receipt with the client exporter, exact action/challenge and device reference.
Its key must appear in the signed node identity record and match the deployed
proxy; in-process test wiring is insufficient. `no_channel_binding` is refused
for migration, including when another feature separately opts into it.

B's mesh courier never replays B's client TLS proof as if it belonged to A. A
verifies the account authorization/actor signatures, its own current authority,
B's seal and the admitted B mesh identity. Fresh client requests to A use fresh
A-audience proofs; the internal courier authenticates as B, not as the account.

Before a control POST, on the **same TLS connection**, request
`POST /v3/home-migration/challenge` with exactly `{device_ref:Ref,
http_method:"POST", http_path:Id, control_hash:H}`. The response is exactly
`{challenge:BranchChallenge, action_hash:H, node_identity_record_hash:H}`.
Extend `CustodyProofAction` with a typed migration action covering that method,
canonical path and full signed Control hash. Client and verifier compare its
`custody_action_hash`; the server's one-use lease stores the same action. This is
an explicit r2-interface extension, not a claim that the existing Challenge
response already exposes action_hash. The subsequent POST's evidence contains
`Envelope<BranchProofV3>` and any required node proxy receipt, verified against
the actual exporter and lease. A public-status proof cannot authorize the
private-status route. No HTTP pooling may move the proof to another connection.

For a root new to B, preliminary signature/anchor checks do not establish current
membership. B obtains A's attestation and publication over admitted mesh and
validates them with the custody verifier against its own existing pins. Final
branch/management admission uses that accepted head. For a new root, commit its
registry entry and reservation together only after possession,
attestation and capacity checks pass; a rejected prepare must not allocate an
unbounded new authority cache. Existing-root revocation/equivocation floors still
persist through the normal custody safety path even when admission is refused.
Never charge a victim's root budget before possession and membership checks.

### Route and reader inventory

All client control POST routes below are on the node-CA TLS listener, with
operation-bound v3 authentication. Public record reads return only the public
projection and grant no account/session privilege.

| Method / route | Node and reader |
| --- | --- |
| POST `/v3/home-migration/challenge` | A or B; bounded pre-auth one-use operation challenge, no account/reservation allocation. |
| POST `/v3/home-migration/prepare` | B; authenticated initiating device. |
| POST `/v3/home-migration/seal` | B; same account, with exact custody authorization. |
| POST `/v3/home-migration/commit` | A; optional client recovery path using the same sealed authorization. |
| POST `/v3/home-migration/activate` | B; current own device presents A's proof; B's worker can do the same without client presence. |
| POST `/v3/home-migration/status` | A or B; public outcome view for an authorized query. |
| POST `/v3/home-migration/private-status` | A or B; own current device only; admitted A/B mesh callers have an equivalent private service method. |
| POST `/v3/home-migration/abort` | B; original preparer before seal, or explicit current management approval. |
| POST `/v3/home-record/resolve` | A or B; authenticated query of public chain/route evidence. |
| GET `/v3/home-record/{anchor}` | A or B; bounded public chain read for senders and offline siblings, without first registering at the migrated-away node. Query selectors are `after_hash` and `limit` (at most 64). |
| POST `/v3/internal/home-migration/commit` | Admitted peer mesh only; B's commit courier to A. Never an alias on either public HTTP listener. |
| POST `/v3/internal/home-migration/attest` | Admitted peer mesh only; B asks A for nonce-bound registered-home/current-head evidence. |

Sessionless v3 resolve/status authentication remains available at A even after
normal registration is refused. The public GET is deliberately only a signed
record read: no branch proof, roster, delivery map, mutable status or secret is
returned. Apply source/global read caps before serving it, and verify its hash
chain against cached floors/the signed migrated rejection. Expired sibling
credentials do not prevent fetching that public locator; normal custody renewal
is still required before opening a B session. Read-only discovery is not a
`no_channel_binding` mutation mode. A contact's first-use authority limitations
remain those of existing custody lookup, not a claim of globally freshest state.

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
  master_certificate_hash, authority_record_hash, public_key}`, or explicit
  `{kind:"master", account_anchor, public_key}` in the reviewed master ceremony;
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
`ramflux.identity.home_record_hash.v1`; delivery-map and discovery-object hashes
use new `ramflux.identity.home_delivery_map.v1` and
`ramflux.identity.home_discovery_hash.v1`. Discovery hashes cover
`{kind:"client"|"server", record:object}`. No old v1 hash or signature bytes change.
These new labels are reservations to add to `domain.rs`/`ALL` during implementation.

### Closed message bodies

Each row lists all body fields after common required `{version:1}`. All new
schema/domain strings are the full reserved spelling below. Generic `Receipt`
is not the commit proof: its body may report outcomes but cannot activate a home.

| Type / reserved domain | Remaining required body fields | Roles |
| --- | --- | --- |
| Prepare / `ramflux.identity.home_prepare.v1` | `migration_id:N, account_anchor:H, actor:Ref, authority_record_hash:H, branch_certificate_hash:H, previous_home_hash:H, previous_home_epoch:U, old_node:Id, destination_node:Id, destination_key:K, discovery_hash:H, delivery_map_hash:H, nonce:N, issued_at:Time, expires_at:Time` | actor |
| Offer / `ramflux.identity.home_route_offer.v1` | `migration_id:N, account_anchor:H, prepare_hash:H, authority_record_hash:H, previous_home_hash:H, next_home_epoch:U, old_node:Id, destination_node:Id, destination_key:K, discovery_hash:H, server_record_hash:H, control_https_origin:Id, federation_endpoint:Id, delivery_map_hash:H, admission_id:N, nonce:N, issued_at:Time, accept_until:Time, max_commit_delay:U, forward_seconds:U` | node B |
| Authorization / `ramflux.identity.home_authorization.v1` | `migration_id:N, account_anchor:H, actor:Ref, authority_record_hash:H, management_certificate_hash:H?, previous_home_hash:H, next_home_epoch:U, old_node:Id, destination_node:Id, destination_key:K, control_https_origin:Id, offer_hash:H, delivery_map_hash:H, nonce:N, issued_at:Time, seal_until:Time, max_commit_delay:U, forward_seconds:U` | management, actor |
| Genesis / `ramflux.identity.home_genesis.v1` | `account_anchor:H, actor:Ref, authority_record_hash:H, management_certificate_hash:H?, home_epoch:0, home_node:Id, home_node_key:K, control_https_origin:Id, issued_at:Time` | management, actor |
| Control / `ramflux.identity.home_control.v1` | `action:Id, audience_node:Id, migration_id:N, requester:Ref, authority_record_hash:H, payload_hash:H, nonce:N, issued_at:Time, expires_at:Time` | actor |
| Receipt / `ramflux.identity.home_receipt.v1` | `action:Id, migration_id:N, account_anchor:H, node_id:Id, request_hash:H, request_nonce:N, authorization_hash:H?, seal_hash:H?, home_record_hash:H?, phase:Id, state_version:U, sealed_at:Time?, commit_deadline:Time?, commit_proof_hash:H?, response_payload_hash:H, issued_at:Time, expires_at:Time, reason_code:Id?` | answering node |
| Commit proof / `ramflux.identity.home_commit.v1` | `migration_id:N, account_anchor:H, old_node:Id, destination_node:Id, previous_home_hash:H, next_home_epoch:U, authority_record_hash:H, authorization_hash:H, offer_hash:H, seal_hash:H, commit_deadline:Time, committed_at:Time, forward_until:Time, backlog_manifest_hash:H` | node A |
| Node commit delivery / `ramflux.identity.home_commit_delivery.v1` | `migration_id:N, account_anchor:H, source_node:Id, audience_node:Id, authorization_hash:H, offer_hash:H, seal_hash:H, admission_evidence_hash:H, nonce:N, issued_at:Time, expires_at:Time` | node B |
| Home attestation / `ramflux.identity.home_admission_attestation.v1` | `account_anchor:H, audience_node:Id, previous_home_hash:H, authority_record_hash:H, device_set_epoch:U, nonce:N, issued_at:Time, expires_at:Time` | node A |

Identifiers are at most 256 UTF-8 bytes; origins/endpoints are at most 2048 and
are parsed by their explicit URL/address type, not the Id grammar. Actor refs and
key metadata must match verified certificates. Offer echoes prepare's nonce;
controls use fresh per-request nonces. Check equality of anchor, operation id,
predecessor, next epoch, destination, map and all referenced hashes across the
bundle. `next_home_epoch = previous_home_epoch + 1`, checked for overflow.

Control actions are `prepare|seal|commit|activate|status|abort|resolve` and must
match the endpoint/audience. Prepare's signed payload is its Prepare message;
other exact payloads are: seal `{authorization_hash,offer_hash}`; commit
`{authorization_hash,offer_hash,seal_hash}`; activate `{home_record_hash,
commit_proof_hash}`; status/abort `{account_anchor,migration_id}`; private-status uses the same status
payload at its separately authorized route; resolve
`{target_anchor,after_home_hash:H?,limit:U}`. `payload_hash` is H with the control
domain over that object. The requester signs as itself for resolve, never as the
target. The response wire wrapper is exactly `{receipt:Signed<Receipt>,
offer:Signed<Offer>?,commit_proof:Signed<CommitProof>?,
resolve_result:ResolveResult?,private_status:PrivateStatus?}`. Only prepare returns
an offer; commit/recovery may return the immutable commit proof; resolve returns
the public result; the separately authorized private-status route is the sole
client route returning PrivateStatus. Other entries must be null. PrivateStatus
is `{delivery_map:array,backlog_progress:object,authority:Publication,
admission_evidence:object}` with the exact nested fields defined below, not an
arbitrary recursive account dump. Pre-seal abort requires the original preparer or explicit management
approval; a branch cannot cancel another device's operation by guessing its id.

A control request is exactly `{control:Signed<Control>,payload:object,evidence:object}`,
authenticated through the operation-bound v3 TLS exchange. Evidence is a closed
map selected from `prepare`, `offer`, `authorization`, `seal_receipt`,
`commit_proof`, `home_record`, `authority`, `branch_proof`, `delivery_map`,
`client_record`, `server_record`, `attestation`, `node_identity_record`,
`proxy_receipt` and `predecessors`. Missing referenced evidence is `evidence_required`; a node's
stored matching object may satisfy it. The node courier uses the same evidence
with its signed NodeCommitDelivery and authenticated mesh instead of a client's
Control/branch TLS proof. Authority is the existing `Publication`/
`CustodyPublication` (complete v3 record and compacted-id evidence), never a v2
set or a client-asserted epoch. Reissue channel proofs on a new TLS connection;
retry the identical immutable migration messages without re-signing them.

PrivateStatus's exact nested `backlog_progress` fields are
`{scheduled:U,durably_forwarded:U,receiver_acked:U,expired:U,rejected:U,
remaining:U,phase:Id}`. These are disjoint current-outcome counts, not cumulative event totals:
receiver_acked excludes durably_forwarded, and remaining is scheduled minus
those accounted outcomes. Rejection/expiry is not delivery success.
`admission_evidence` has exactly the operation's `prepare`, `offer`,
`authorization`, `seal_receipt`, `attestation`, `client_record`, `server_record`
and `node_identity_record`, using the types already defined. Authorization and
seal_receipt are null while prepared; the remaining entries must be present. The authority and
delivery map are the separately named fields, not duplicated recursively. The
Receipt's `response_payload_hash` is H with the Receipt domain over exactly
`{offer,commit_proof,resolve_result,private_status}`; the receipt itself is
excluded to avoid a signature/hash cycle. The seal receipt's own `seal_hash`,
`home_record_hash` and `commit_proof_hash` are null; later status receipts may
reference its derived hash. Private-status responses obey the 5 MiB aggregate
custody ceiling, not the 64 KiB ordinary control-message size.

### Idempotence and expiry context

The durable business key is `(account_anchor,migration_id,action)` and its value
binds the immutable payload/authorization hash, not a replaceable transport
nonce. Same business key/hash returns the original outcome; a changed payload
is `idempotency_conflict`. A recovery request may use a new Control nonce, TLS
challenge or B-courier signature after restart; it does not create another
admission or commit. Responses bind that fresh request hash/nonce while returning
the same stored commit proof. One-use transport proofs remain bounded by the
existing custody challenge/session store and are not replayed on new connections.

Control and node-courier requests live at most 300 seconds with the existing
300-second custody skew checks; freshness is not a home-ordering rule. A signed
Offer can be sealed only until its B-issued accept_until. Authorization.seal_until
limits **sealing**, and its signed max_commit_delay separately authorizes commit
within the B-seal deadline. A checks sealed_at <= seal_until and the exact
seal-derived deadline, not whether a previously accepted offer is still open.
Generic receipt expiry limits fresh status assertions; a preserved seal receipt
is historical commitment evidence until its commit deadline. Commit proofs and
home records have no expiry that could reopen admission or delete a home floor.
After commit, recovery rechecks current node/custody state, not a retired client
nonce. A late receipt contradicting a known terminal noncommit fence is source
equivocation evidence; it never silently reopens B's released admission.

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

The public ResolveResult is exactly `{home_record:HomeRecord,
predecessors:[HomeRecord], commit_receipt:Signed<CommitProof>?,
offer:Signed<Offer>?, seal_receipt:Signed<Receipt>?,
activation_receipt:Signed<Receipt>?, management_certificate_chain:[object],
actor_certificate:object, node_records:[object]}`. The included custody/branch
certificates and node records use the existing closed versioned types above. Genesis has null
migration-related entries; all non-genesis entries are required and commit_receipt
must equal the record's embedded proof. Predecessors are ordered oldest-to-newest,
start at the caller's known hash (or genesis), and link without gaps to the head.
The previous record supplies A's node key; verify the commit signer against that
key, not a directory-supplied replacement. Management/actor certificates verify
under the account's master and known custody floors. Missing current authority
is fetched through the ordinary custody lookup path, never trusted from a hint.

Contacts receive this public binding/route evidence only: **no full device-set
publication, delivery map, delivery ids or admission-private evidence**. Only
current own devices and the two admitted homes may request PrivateStatus, which
adds `{delivery_map, backlog_progress, authority, admission_evidence}`. Server-side
authorization is required, not a client `include_private:true` flag. An unknown
root cannot enumerate private operation state. Store public and private views
separately so a generic serializer cannot accidentally expose the private map.

Historical verification is a distinct, typed home-record verifier: check
certificates/signatures at A's committed_at, including the management range and
actor lease then, while retaining every locally known later authority/home floor.
It never relaxes `verify_branch_proof_v3` for current sessions or mutations.
Before **first activation**, B also checks the management certificate against its
own current custody range; a superseded manager cannot first activate a stale
move through B. If primary recovery raced a committed-but-not-yet-activated move,
retain the committed home and return `custody_reconfirmation_required`; do not
roll back to A or use an old range. Exact current-custody reconfirmation/recovery
is **MIGRATE-RECOVERY-01**, outside the demo. Already active homes survive ordinary
branch revocation/lease renewal, with fresh session authorization still enforced.

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

For the demo retain all home records, commit proofs and terminal replay fences;
no pruning or `outcome_pruned` behavior is implemented. A resolve page contains
at most 64 linked records within 1 MiB. First-version admission stops before a
chain exceeds that verifiable 64-record limit (`home_checkpoint_required`). A
reviewed checkpoint/pagination extension is **MIGRATE-CHECKPOINT-01**; do not drop
history or reset the epoch to make room. Cached peers may request a suffix.

## Cooperative protocol, deadlines and recovery

### Prepare and seal at B

1. Verify A and B discovery, pins, capabilities, existing peer admission and the
   current v3 account. Initialize/persist an epoch-0 home genesis at A if absent,
   using management approval and A's existing registration; never overwrite an
   existing head. A migrated account is not bootstrapped again at epoch zero.
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
   is no later than Offer.accept_until and it explicitly permits at most a
   600-second commit delay from B's actual seal time. Client `issued_at` is for
   request freshness, not a cutover/window clock.
5. B atomically CASes prepared -> sealed, saves the exact authorization/map and
   creates **normal router inbox routes for every eligible delivery-map device**,
   including offline siblings. A seal receipt states `sealed_at = B.now` and
   `commit_deadline = sealed_at + 600`. Persist a B-side `commit_pending_at_A`
   courier item in that same transaction. Send an own-device seal notice via A's
   existing own-device/inbox control path, not solely through a B inbox that an
   offline sibling cannot find. The notice is node-signed metadata with the
   authorization hash and destination fingerprint; it does not impersonate an
   encrypted branch message or replace account consent.

The delivery map is the complete authorized recipient routing map, sorted by
DeviceRef, with no duplicates; each entry is exactly `{device_ref:Ref,
target_delivery_id:Id}` and matches the node-verified roster/current target
bindings. Its hash is H with `home_delivery_map.v1`. Cross-root target collision,
missing initiating device, revoked entries or roster mismatch refuse seal.
Routing-map installation does not authenticate an absent sibling session or
publish its prekeys on its behalf. The returning sibling proves its own v3 branch. Include non-revoked offline
members even when their current branch lease needs renewal; creating an inbox
does not extend that lease. They renew through the normal custody path before
access. Recheck roster/map against A's current record at commit, and apply normal
revocation/TTL policy explicitly to any excluded old queue.

Abort and seal use one reservation CAS. Client cancellation is possible only
before seal. After seal, B can release a **proved uncommitted** admission after
the commit deadline as below; there is no client cancellation of an in-flight
commit. One sealed/active operation per root means one **in-progress window**,
not a lifetime exclusion: after completion B can later admit a B -> C -> B move.

### Commit at A; B drives completion

B delivers the sealed request to A over admitted mesh, retries idempotently and
queries signed status. Client liveness is not required. A verifies the Offer,
B's seal, management/actor signatures and **A's own stored current v3 head**.
Verify the exact predecessor and custody range, admission deadline, actor lease
and revocations, destination pin/admission, map, 600-second maximum and allowed
24-hour forwarding duration. Do not accept a caller-supplied `now`. An A status
query for an unknown id must include the verified seal/authorization evidence
before A can assert deadline expiry; an arbitrary guessed id does not acquire a
terminal fence. The terminal noncommit CAS and commit CAS share the same lock/
durable state, so a delayed request cannot win after A has proved noncommit.

A refuses first commits after `commit_deadline` on A's clock. The commit must be
one durable transaction/atomic batch that:

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

### Backlog, deduplication and outbound traffic

Already ACKed offline inbox entries at A cannot be stranded by switching the
client manifest. Transfer every mapped device's unacknowledged pre-commit range,
including offline siblings. Preserve envelope bytes, sender authority and target
ids. A releases an entry only after B's durable normal-inbox commit/duplicate
ACK, a real receiver ACK already recorded at A, or its original TTL expires with
an explicit expired outcome accounted for; any further window-plus-retention
deletion requires a reviewed policy.
It never treats scheduling an attempt or a lost reply as success.

Sealed inbox routes are dormant for ordinary delivery until A's proof is
verified. An A forward carrying that proof can atomically advance B's home state
and then use the normal inbox path; an unrelated direct submission cannot gain
an early delivery ACK merely because its guessed target id already exists.

For an older queued v3 message, preserve A's **original durable receiver-home
acceptance evidence**, its authorized receipt-key/node record and source branch
certificate. The existing custody queued-message exception requires purpose
`message`, exact signed-object/source/target binding, original accepted_at inside
the branch/key issuance intervals, and current revocation/mode floors. It is
not an expired-branch registration or fresh-send exception. Add the missing
production adapter for this path: custody r2's native DM does not implement it.
The forwarder's new timestamp or A's migration commit is not an intake receipt.
Capture/sign and persist this evidence at original message acceptance with the
inbox/WAL entry; never fabricate/backdate it when migration begins. Existing
queues lacking required evidence must drain normally or cause a typed
`backlog_evidence_required` refusal before seal, not silent loss.

For this routing-envelope receipt, reserve
`ramflux.identity.home_accepted_envelope.v1` and compute H over exactly
`{sender_bytes:base64url(envelope_sender_signed_bytes(envelope)),
sender_signature:Sig}`. These bytes preserve all sender-authenticated content
and the original signature while ignoring only the already approved appended
node metadata. Bind that digest as RelayAcceptance.message_hash. Carry the
receipt/node-record evidence in the **node-signed outer federation forward
request**, not in a newly unsigned sender extension or changed ciphertext.
Keep the one-hop marker and approved sender projection unchanged. B uses the
typed historical-message verifier, never a global bypass of v3 proof/lease checks.
If normal policy now rejects an entry (for example a revoked sender), retain an
explicit rejected/expired outcome in backlog progress; do not count it as B
delivery. Pending missing evidence/authority is retryable, not such an outcome.

Deduplicate across backlog replay, A-forwarded new traffic and a sender's direct
retry. The server tuple is `(verified sender anchor, envelope_id,
target_delivery_id)`; **envelope_id is the transport message id** in the owner's
(sender, message id, delivery id) rule. It is visible/authenticated without
opening ciphertext. Keep normal receiver-side E2EE message-id/replay checks for
the encrypted application message id as well; a node cannot deduplicate by a
plaintext field it cannot read. Do not regenerate ids or ciphertext on reroute.
Use the train's persistent local-delivery index, independent of the forwarding
peer's source_node_id, rather than only federation Pending/Committed seen keys.
A duplicate must not consume a second local inbox entry after restart.

Persist each backlog cursor/ACK so a crash after B commits but before A records
the ACK only replays the same entry. Preserve original TTL/retention timestamps;
migration does not extend message TTL. The initial release does not silently
prune undelivered backlog at window close: retain it and report
`backlog_incomplete` for operator/client attention until a later retention policy
is reviewed. Forwarding retries stop at the window; expiry is not a delivery
receipt. End-to-end receiver receipts, not node ACKs, prove recipient delivery.

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

At `commit_deadline + 300 seconds` (custody clock-skew allowance), B queries A.
If A committed in time, recover that proof and activate. Otherwise A atomically
records a terminal `not_committed`/expired fence once its own clock is past the
deadline; B verifies this signed nonce-bound result, releases its unused sealed
allocation and removes empty staged routes. A can never later commit that id.

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
including source revocations arriving after seal. A newer committed home or
identity tombstone wins over a delayed activation. A return move is a fresh
higher-epoch operation after the previous one-hop window closes. On a return to an earlier node, that
node verifies the new committed chain, installs the higher home floor and derives
registration eligibility from the **current** head naming itself. Historical
migration records/proofs remain immutable; their mere existence must not keep
rejecting registration forever. v1 refuses
chained A -> B -> C forwarding (`previous_window_active`).

### Permanent bootstrap and closing the window

A permanently serves public home resolve/status for a migrated anchor. The
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
| `seal_sent` | Query B before retry; aborted/expired is terminal; sealed recovers its deadline. | Authorizing move. |
| `sealed` | Persist B receipt; B's durable `commit_pending_at_A` courier runs independently. | Waiting for old home commit; no cancellation. |
| `commit_pending` | Query A/B; pause uncertain outgoing submissions; never activate from a timer. | Waiting / needs attention if A unavailable. |
| `activate_sent` | Submit/recover A proof at B or observe B's autonomous receipt-based activation. Query B after a lost reply. | Activating destination. |
| `backlog_transferring` | B activation and inboxes are ready; track durable A drain counters without requiring offline devices online. | Moving queued messages. |
| `reconnecting` | Register existing v3 refs at B, republish authorized prekeys and connect ordinary QUIC/TCP-TLS/inbox stack. | Connecting at new home. |
| `manifest_switch_pending` | Persist desired config then atomic replace/fsync; reconcile against verified journal/head after crash. | Saving new home. |
| `forwarding` | B connected, signed home resolution published; retain drain/forward progress. | Moved; backlog/forwarding progress shown separately. |
| `complete` | Window closed and backlog accounted for; preserve floors/proofs. | Move complete. |
| `expired` / `aborted` / `refused` | Only proved noncommit/pre-seal outcomes; retain operation fence. | Not moved; safe retry available. |
| `needs_attention` | Unknown commit, fork, incomplete backlog, trust/storage error; preserve last confirmed state and query. | Action required; no false success. |

The destination journal has explicit prepared, sealed/commit_pending_at_A,
commit_known, active, terminal_noncommit and commit_outcome_unknown phases.
Every source/destination crash boundary is tested, including after durable A
commit but before any reply, and after B activation before client observation.
The per-account manifest switches gateway addresses, CA/server names, prekey and
signaling endpoints and new-object defaults together, preserving identity/DB
location/ratchets and existing objects' recorded relay ownership. Migration does
not transfer old attachments or backups; those are **MIGRATE-OBJECTS-01** work.

Proposed ordinary bus methods are `account.home_node.migrate`,
`account.home_node.migration.status` and `account.home_node.migration.abort`.
Start input is `{operation_id,target_discovery_url,expected_node_fingerprint?}`;
a null fingerprint requires verified A-admission pin evidence, never TOFU.
Status/abort take the operation id. A separate protected custody-confirmation
step signs the exact proposal digest after passphrase/data unlock plus the
separate custody credential approval; no secret is an ordinary bus JSON field.
Typed progress/result bodies include operation id, phase/sequence, source/target,
confirmed home epoch/hash, commit deadline, forwarding deadline, backlog progress
and reason/retry code. Outbox subscription replay and status survive restart.

`rf account migrate-home --account ID --to DISCOVERY_URL
--expected-node-fingerprint FINGERPRINT` drives that job and confirmation. An
explicit `--pin-from-home` alternative uses A's verified admission. No automatic
TOFU switch exists. Status/abort subcommands use the durable id. Success means
B's live ordinary session and verified committed home record, with backlog and
forwarding completion reported separately. A node ACK is not an E2EE receipt.

Desktop/TUI follow the same bus state: show pin provenance and source/target,
explicit custody confirmation, commit deadline, no-cancel-after-seal boundary,
queued-message progress, B connectivity and remaining forward window. Lost A
shows needs-attention, not a countdown to automatic success. The CLI is sufficient
for the demo; polished screens are **MIGRATE-UI-01**. Own-device seal notice and
safe signed sibling bootstrap are not deferred with those screens.

Exclude migration journals/active timers from v1 backup export/import entirely.
The signed public home floor still survives account restoration through current
node resolution; stale backup state cannot lower a locally retained floor or
restart a job. **MIGRATE-BACKUP-01** will add inert diagnostic job history later.
Before networking, a restored v3 device refreshes custody and the home chain.

## Bounds, errors and minimal work packages

Require 8 KiB headers, 64 KiB ordinary control messages, 8 KiB individual signed
migration objects and a 10-second whole-request deadline (not reset by trickle
reads). Admission evidence uses the existing 5 MiB custody frame ceiling with
streamed caps before allocation, retaining existing 512 KiB v3 record and 4 MiB
revocation-list bounds. Both individual and aggregate limits apply; no roster
or revocation truncation. Resolve pages are bounded as above. Heavy verification
is off the sole socket-reader worker; at most 16 migration crypto jobs/node.

After verifying identity and A's attestation, allow prepare burst 2, 6/hour/root,
one unsealed and one in-progress sealed/window operation/root, at most 1024
unsealed reservations/node and a configured admitted-peer share. In-doubt seals
have a small explicit per-peer cap (initially 16) and consume account capacity.
Authenticated status/resolve: burst 10, 60/minute/requesting root, no durable
allocation for an unknown query. Public record GET: burst 10, 60/minute/source
subject to the configured CGNAT/global read ceiling; it performs bounded cached
record reads and never allocates an account/reservation or returns private state. Retrying the same id/hash consumes no new reservation. Cheap
source/connection limits apply before crypto; authenticated root quotas are
charged only after verification. Preserve configurable per-source CGNAT ceilings
and independent global/root caps. A signed registration attestation prevents
anonymous-root reservation exhaustion; an admitted peer can still deny service,
so capacity and per-peer caps remain necessary.

Keep typed refusal codes: `v3_required`, `custody_approval_required`,
`authority_update_required`, `actor_revoked`, `custody_reconfirmation_required`, `pin_mismatch`, `channel_binding_required`,
`base_mismatch`, `home_fork`, `idempotency_conflict`, `admission_expired`,
`commit_expired`, `commit_outcome_unknown`, `previous_window_active`,
`home_genesis_required`, `home_checkpoint_required`, `backlog_incomplete`,
`backlog_evidence_required`,
`capacity_refused`, `peering_unavailable`, `evidence_required`, `rate_limited` and
`storage_unavailable`. Unauthenticated control errors are generic; no private
map or private-operation oracle is exposed. The public GET intentionally reveals
a published locator for a known opaque anchor, not private admission status. Log bounded ids/codes, not secrets/full evidence.
Transport replay keys are anchor-qualified and action/audience/nonce-bound;
durable business keys are the separately defined idempotence tuple. Store at
most 256 retained operations/root and 16384/node in the first version, refusing
new prepares before those budgets are exhausted rather than pruning a floor.
Drain work uses pages of at most 64 inbox entries and 128 transitions/tick,
with at most four concurrent forwards/peer and the train's per-target leases.
A fresh status proof never reissues authorization, extends a deadline or rewinds
a home/custody floor. No pruning of proof/fence state is in the initial release.

### MIGRATE-SRV-01: required for the first two-node CLI demo

Implement in ordered reviewable commits, on the merged forwarding/custody base:

1. **Protocol and crypto:** all closed v3 migration messages, home record and
   public/private bundle types, management-authority verification against the
   node-owned current record, canonical/hash vectors and strict domain registry.
   Keep current custody Envelope/branch-exporter semantics. Add v2 client
   discovery with control TLS fields and the exact no-TOFU pin contract.
2. **B admission/seal:** A registration attestation, capacity/one-root CAS,
   normal mapped-device inbox installation at seal, durable B->A commit courier,
   own-device seal notice, signed status/abort and deadline/noncommit recovery.
3. **A commit/backlog:** one durable base CAS with commit proof, route/window and
   high-water drain jobs for all devices; A-timestamped window, no client now or
   issued_at ordering; preserve outbound spools and close existing submit paths.
4. **Activation/forwarding:** B proof-only activation and normal WAL delivery;
   persistent cross-forwarder dedup; backlog leases/cursors/ACK deletion and
   uncertain-outcome recovery; adapt source-authority import to v3 Publication/
   BranchCertificate/DeviceRef (no synthetic legacy IdentityRoot), implement
   original receiver-home message acceptance/history verification for queued
   v3 data, and retain approved sender-signing exclusions/authority checks;
   all forwarding deltas above, permanent A
   resolve and signed migrated registration/session/send refusals.
5. **Deploy and acceptance:** node-CA control TLS listener, matching mandatory
   node signer and deployed proxy-key publication, signed v2 discovery and
   already-admitted peering on two IP-reachable nodes. No WebPKI or test-memory
   vault escape in the actual demo. Run node/crypto/custody tests and the new
   server fault scenarios before enabling `home_migration_v1` capability.
6. **Remove legacy migration surface:** after rewritten s51 passes, remove admin
   migration/route apply from both router mesh and itest listeners, DTOs containing
   client now, and seed-forging fixtures. Retain pure validators only if needed;
   no combined mode or admin-token CLI escape hatch.

### MIGRATE-SDK-01: follows the server contract, same demo

1. Reuse the ordinary v3 session/bus integration from the v3-only rollout. Add
   purpose-bound custody signing/confirmation to the existing independent vault
   boundary; do not recreate the legacy root or require the phrase routinely.
   Verify that the supported demo platform has the real custody provider; a
   branch/data unlock alone must fail migration authorization.
2. Implement the durable client phases, restart queries and exact manifest switch;
   no automatic fallback; pause source sends at confirmed/uncertain commit;
   reconnect the same device/ratchets and preserve queued outgoing ids.
3. Implement sender-side signed `HomeNodeMigrated` handling in the SDK **and**
   federation target lookup: verify A/chain/commit proof, update target_node_id
   and prekey origin, and retry the unchanged envelope. It is not enough to
   update only the migrated account's own endpoints.
4. Ordinary bus migrate/status/abort plus protected custody approval, durable
   typed events, CLI flags/exit states and own-sibling bootstrap/notice handling.
5. Rewrite s51 through the real CLI and daemon socket using v3 identities and
   real node-issued offers/proofs. Feed the test agents exact flags and artifact
   SHAs; no client migration request contains an admin token or a node seed.

The minimal demo is two already-admitted IP-reachable nodes, a v3 human account
with management authority available, its offline sibling, and a third sender
retaining A's route. Forced move, general replicas/contact fanout
(**MIGRATE-REPLICA-01**), custody-external signer routing, attachment moves,
polished UI, backup job history, checkpoint/pruning and node-root-key rotation
(**MIGRATE-NODE-ROTATE-01**) are named later work. General proof/operation
retention and compaction require **MIGRATE-RETENTION-01**; until then budgets
refuse new work rather than erase a safety fence. Normal proxy/receipt-key
rotation in the existing v3 node record remains enforced; no weakened verifier
or indefinite ambiguity is used to defer these features.

### Demo implementation boundary and order

The target is a small cooperative CLI demonstration, not all deferred recovery
or UI features. Review the protocol/types first; server admission, commit and
forwarding form one acceptance unit. SDK journal/CLI work may proceed against
those reviewed types, but capability enablement waits for the real v3 rollout,
node TLS/proxy setup and the production historical-message acceptance adapter.
The final unit is rewritten s51 plus a manual two-node run with an offline
sibling and a third sender. These dependencies are critical-path gates, not a
claim that the inspected custody r2 branch already supplies them. Use an actual
supported primary-vault provider on the initiating client; node OS and client
vault OS need not be the same.

## Acceptance matrix

- **Cryptography and schema:** every signature/hash golden; role order and
  schema==domain; reject old r1 root/branch-v2 payloads, custom/null/default
  ambiguity, I-JSON violations, mismatched anchor/ref/certificate/offer/predecessor,
  map, node pin, TLS audience and expired authorizations. Cross-schema vectors
  enumerate existing root/branch/node preimages and prove none can substitute
  for the top-level `{body,domain,schema,signers}` migration transcript.
- **Authority and network attacks:** stale-but-valid client publication, primary
  replacement and actor revocation against each node's stored head; wrong node
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
  and admitted-home private views are separately authorized. New roots without
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
