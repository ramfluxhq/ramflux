# Account-authorized home-node migration

Design proposal, revision 1. Review is required before implementation. This
file defines proposed behavior; it does not claim that the production flow
exists or that live migration has passed acceptance tests.

## Current implementation and scope

The inspected product base is `9a8961a9566cf241bd5111c07cfc6167b6347a06`.

- [The SDK migration method](../crates/ramflux-sdk/src/client/federation.rs)
  delegates to an in-memory
  [federation model](../crates/ramflux-sync/src/federation.rs). It does not
  move a daemon account, register it at another gateway, or install forwarding.
- [Router lifecycle handlers](../apps/ramflux-router/src/lifecycle.rs) apply
  migration and route proofs using an operator admin token. They are reachable
  through privileged router mesh handlers and an additional test listener.
- [Existing migration proofs](../crates/ramflux-protocol/src/home_node_migration.rs)
  have a device signature and previous-binding hash. Their
  [crypto verifier](../crates/ramflux-crypto/src/home_node_migration.rs) explicitly
  leaves lineage/fork enforcement to its caller. A primitive signature check is
  not sufficient authorization for this flow.
- [Router migration state](../crates/ramflux-node-core/src/home_node_migration.rs)
  defines a 24-hour forwarding window. A new-node route proof is separate from
  the account migration proof. The existing destination route commitment does
  not bind an account, admission reservation or migration nonce.
- [Client node discovery](../crates/ramflux-protocol/src/client_discovery.rs)
  and [node pins](../crates/ramflux-sdk/src/node/store.rs) already provide signed
  endpoints, expiry checks, key-change detection and explicit pin confirmation.
  They do not provide destination admission or migration publication.

The approved forwarding work at `626aa37bef0b6085e91080c89fa4809ed88577af`
(FU-BATCH-03 and its prerequisite train) is an implementation dependency, not
part of this documentation change. It includes bounded forwarding reservations,
recovery/retry behavior and correct sender-signature treatment of the appended
hop marker. Integration must retain all of those semantics.

The user outcome is one unchanged account identity moving from A to B, with
messages addressed to A forwarded during the cooperative window. Account roots,
contacts, conversation ids, message ids, device ids, delivery ids and ciphertext
are preserved. Local history and ratchet state stay in the existing account DB;
no new identity or account secret is generated. Moving a home does not migrate
historical relay object ownership, transfer server backups, or promise delivery
of traffic already lost at an unavailable A. Attachments already hosted at A
continue using their recorded owner/relay; moving those objects is separate work.

## Actors, authority and invariants

| Actor | Authority and responsibility |
| --- | --- |
| Account and initiating device | Authorize the exact next home binding, retain a durable operation journal, and authenticate requests without node admin credentials. |
| Old home A | Verify account authority and B's admission, atomically install forwarding and a durable commit receipt; A does not authorize the account's choice of home. |
| Destination B | Verify account ownership, current device authority, capacity and federation policy; reserve admission, sign its route, durably seal authorization, then activate the same identity. |
| Other own devices | Verify the new binding through account authority, update their per-account endpoints and reconnect independently. They do not automatically move other accounts using A. |
| Contacts and peer nodes | Resolve the account-signed home record, maintain rollback/fork floors and retry unchanged envelopes using the verified route. A forwarding hint alone is not authority. |

No client receives an admin token, node private key, mesh client key or signing
seed from either node. Internal service authentication remains server-side.
Normal migration does not change federation peer admission: A and B must already
be mutually permitted by their operators' federation policy. A missing link is a
typed preflight failure, not an automatic client-authorized peer admission.

This proposal deliberately requires two signatures for account-changing
messages: the active initiating branch and account-management authority. With
current root-bound v2 accounts, management authority is the pinned identity root
key, alongside a fresh root-signed device set and valid v2 branch proof. Every
lookup, replay key and authority cache uses the root-qualified device reference,
never a bare device id. Check immutable principal kind, branch key/epoch binding,
device-set floor, revocation tombstones and identity lineage before authorization.
An included public key is evidence to verify against that chain, not a new pin.

Under [root key custody](root_key_custody.md), management authority becomes the
primary self-signing key within its master-certified range. A secondary can
prepare an exact intent, but needs primary approval of its hash before sealing;
no new migration delegation scope is granted by this proposal. The offline
master/recovery phrase is not requested for normal migration. v3 branch proof,
lease and current public-record verification replace v2 checks only through
explicit version negotiation. No v3 record may fall back to v2 root material.
A headless participant cannot make itself primary or bypass this approval.
The extra management signature is a proposed migration permission, to review
alongside the custody operations table; it is not present in today's verifier.

Current devices still hold legacy root copies. This design cannot make a stolen
legacy root harmless or prove global freshness from signatures alone. Once v3
is enabled, the public record's single authority epoch and custody latch apply;
its home section is new and distinct from custody-erasure migration metadata.
The primary-signed record names the old active binding plus a conditional
pending binding hash and seal/activation condition. A verified activation receipt
selects that already-approved pending binding without inventing a second
public-record epoch or requiring the primary to sign again while offline.
Clearing/superseding that conditional authorization requires a later primary-
signed authority record. The exact v3 section is a custody integration work
item; v2 migration must not be advertised as v3-compatible before it is reviewed.
Do not introduce another competing v3 authority head.

## Discovery and transport

Reuse node lookup to fetch and verify B's signed client record, its freshness,
node id, pinned node-key fingerprint and signed CA/endpoints. An expected
fingerprint must match the exact discovered node key, using existing node lookup's
`hash_hex(CLIENT_DISCOVERY_DOMAIN, node_public_key.as_bytes())` fingerprint of
the encoded public-key string. First-use trust requires
an explicit user confirmation of that fingerprint; absent confirmation is
`trust_confirmation_required`. A changed stored pin is a security error, not a
new TOFU opportunity. Record pin provenance and the exact discovery-record hash
in the journal. Refresh expired discovery before preparing or resuming.

Obtain B's signed server/mesh record for its federation endpoint. Its node id and
signing key must match the client-discovery pin. Deployments with separate
signing keys need an explicit signed key-binding certificate in a later reviewed
version; this initial version rejects that configuration. HTTPS authentication
uses the verified node CA/pinned deployment trust. An HTTP discovery origin may
be fetched to display an untrusted candidate, but migration control and authority
publication require verified TLS; the demo must provide an HTTPS client origin.

Proposed client endpoints use the public client origin. They are authenticated
account operations, deliberately extending the currently read-only public route
inventory; they do not expose federation administration. The public gateway
handler enforces limits and proxies to router/gateway services using existing
internal authenticated transport. Clients never choose an internal mesh address
or supply an admin token. Responses must return 404 for old admin paths on this
listener, including when a client supplies an admin token.

| Method and path | Serving node | Caller / reader |
| --- | --- | --- |
| POST `/v1/account/home-migration/prepare` | B public origin | Initiating device; returns B's signed route/admission commitment. |
| POST `/v1/account/home-migration/seal` | B public origin | Account-approved intent; returns durable sealed receipt. |
| POST `/v1/account/home-migration/commit` | A public origin | Client presents the sealed intent; installs the forwarding window. |
| POST `/v1/account/home-migration/activate` | B public origin | Client presents A's receipt, or completes the bounded fallback after its deadline. |
| POST `/v1/account/home-migration/status` | A or B public origin | Account/device-authenticated, nonce-bound recovery query. |
| POST `/v1/account/home-migration/abort` | B public origin | Account-authorized cancellation of an unsealed reservation only. |
| POST `/v1/account/home-binding/publish` | B or permitted directory replica | Account-authorized publication; replica verifies the complete activation bundle. |
| POST `/v1/account/home-binding/resolve` | Known home or directory replica | Authenticated account/device or admitted peer holding the target's opaque identifier; returns the signed current bundle, not a bare URL. |

All paths above are proposed. Router commit/route application and federation
admission checks use private service calls with mTLS service identities. A and B
exchange bounded status/seal evidence over their admitted mesh; those internal
paths must not become public aliases. A public origin does not accept arbitrary
proxy URLs, redirects to another origin, or user-supplied mesh endpoints.

## Canonical wire rules

Use [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785) over the
[RFC 7493 I-JSON](https://www.rfc-editor.org/rfc/rfc7493) subset. Reject duplicate
keys, invalid UTF-8, lone surrogates, unknown fields, trailing data and non-finite
or out-of-range numbers before deserializing to a generic map. Do not normalize
Unicode. Integers are exact nonnegative JSON integers at most `9007199254740991`;
timestamps are UTC Unix seconds. Nonces and operation ids contain 32 random bytes,
base64url without padding (43 characters). Keys and digests are exactly 32 bytes;
Ed25519 signatures exactly 64 bytes, using the same encoding. No implicit nulls,
defaults or optional fields: a nullable field must be present with JSON `null`.

These closed-field/null rules apply to the new envelopes and bodies. Embedded
existing authority, branch and discovery documents retain their own versioned
wire rules, including any signed optional-field omission; do not rewrite them
by inserting nulls or stripping nested signatures.

Use existing `ramflux_protocol::canonical_json_bytes` and
`hash_base64url(domain, bytes)` semantics: BLAKE3 of UTF-8 domain bytes followed
by canonical bytes, encoded base64url without padding. No SHA-256 substitute or
implicit delimiter is introduced. Each message's complete signed envelope hash
uses its own domain. Nodes compare canonical object hashes, not transport JSON
formatting. These new schemas require typed canonical builders; do not recursively
strip signatures from nested evidence using a generic signing helper.

Define the following closed signed envelope `Signed<T>`:

```json
{
  "schema": "DOMAIN",
  "domain": "DOMAIN",
  "body": {},
  "signers": [],
  "signatures": []
}
```

`DOMAIN` and `{}` here are metasyntax; body fields are defined below. The signature
preimage is JCS of exactly `schema`, `domain`, `body`, `signers`. Each signer signs
the same bytes. `signatures[i]` corresponds to `signers[i]`; array length and order
must match the required role list, with no duplicate/extra roles. Signer metadata
is therefore authenticated. The object hash is
`hash_base64url(DOMAIN, JCS(complete Signed<T>))`, including signature bytes.
Embedded documents are referenced by this hash; re-signing an operation is not
an idempotent retry. Persist and resend the original signed bytes.

A signer is exactly `{role, key}`. Node key: `{kind:"node", node_id, public_key}`.
Account v2 key: `{kind:"root_v2", root_commitment, public_key}`. Future v3 key:
`{kind:"self_signing_v3", root_commitment, public_key, authority_record_hash}`.
Actor key: `{kind:"branch_v2", root_commitment, device_id, device_epoch,
public_key}`; replace `branch_v2` with `branch_v3` only when v3 is negotiated.
All signatures are Ed25519; other algorithms are rejected. Account and actor
signer roots must match the body's `root_commitment` and authenticated
`identity_commitment`. Derive/check the commitment using the existing root
commitment function; do not equate a display principal name with its root.

### Reserved domains and exact bodies

The existing domain `ramflux.home_node_migration_proof.v1` and its preimage remain
unchanged. The following are **new reservations**, to add to the protocol domain
registry during implementation. Route/proof v2 extend the existing migration
family; v1 handlers cannot reinterpret them or drop new fields.

Notation: `H` = 32-byte digest; `N` = nonce/id; `U` = integer; `S` = bounded UTF-8
string; `K` = 32-byte key; `E` = signed envelope; `T?` = type T or null. Each row
lists all required body fields. Identity/node strings are nonempty and at most
256 bytes; URLs at most 2048 bytes. The root/account/device binding is verified
from the evidence, not inferred from the labels.

| Type / reserved domain | Required body fields | Signer roles in order |
| --- | --- | --- |
| Prepare / `ramflux.home_node_migration.prepare.v1` | `migration_id:N, identity_commitment:S, root_commitment:H, actor_device_id:S, actor_device_epoch:U, authority_hash:H, branch_proof_hash:H, base_binding_hash:H, base_home_epoch:U, delivery_map_hash:H, old_home_node:S, destination_node:S, destination_node_key:K, discovery_record_hash:H, nonce:N, issued_at:U, expires_at:U` | `actor` |
| Route commitment / `ramflux.home_node_route_record.v2` | `migration_id:N, identity_commitment:S, root_commitment:H, prepare_hash:H, delivery_map_hash:H, base_binding_hash:H, next_home_epoch:U, old_home_node:S, destination_node:S, destination_node_key:K, discovery_record_hash:H, mesh_record_hash:H, federation_endpoint:S, client_origin:S, admission_id:N, nonce:N, issued_at:U, accept_until:U, max_forward_seconds:U` | `node` (B) |
| Migration statement / `ramflux.home_node_migration_proof.v2` | `migration_id:N, identity_commitment:S, root_commitment:H, actor_device_id:S, actor_device_epoch:U, authority_hash:H, branch_proof_hash:H, base_binding_hash:H, next_home_epoch:U, old_home_node:S, destination_node:S, destination_node_key:K, route_commitment_hash:H, delivery_map_hash:H, nonce:N, issued_at:U, expires_at:U, fallback_after:U, forward_seconds:U` | `account`, `actor` |
| Home binding / `ramflux.identity.home_binding.v1` | `identity_commitment:S, root_commitment:H, home_epoch:U, previous_binding_hash:H?, home_node:S, home_node_key:K, client_origin:S, migration_id:N?, migration_statement_hash:H?, route_commitment_hash:H?, authority_hash:H, issued_at:U` | `account`, `actor` |
| Control / `ramflux.home_node_migration.control.v1` | `action:S, audience_node:S, migration_id:N, identity_commitment:S, root_commitment:H, statement_hash:H?, home_binding_hash:H?, admission_id:N?, authority_hash:H, branch_proof_hash:H, target_identity_commitment:S?, target_root_commitment:H?, nonce:N, issued_at:U, expires_at:U` | `actor` for status/resolve; `account`, `actor` for seal, commit, activate, abort, publish |
| Node receipt / `ramflux.home_node_migration.receipt.v1` | `action:S, migration_id:N, identity_commitment:S, root_commitment:H, node_id:S, request_hash:H, request_nonce:N, statement_hash:H?, home_binding_hash:H?, admission_id:N?, state:S, state_version:U, accepted_at:U?, effective_at:U?, forward_until:U?, fallback_after:U?, observed_home_epoch:U, observed_binding_hash:H?, issued_at:U, expires_at:U, reason_code:S?` | `node` (the answering node) |

`Control.action` is exactly `seal|commit|activate|status|abort|publish|resolve` and
must match the endpoint. Resolve uses `identity_commitment` for the requesting
account and includes the target in its signed body as described below; it does not
pretend that the requester owns the target. For `status`, `abort` and `resolve`,
`statement_hash`/`home_binding_hash` may be null; mutation operations otherwise
require their exact hashes. `admission_id` may be null only for status/resolve
or the genesis-publication exception below.
For `resolve`, `target_identity_commitment` and `target_root_commitment` are
required non-null and identify the target; the message's identity/root identify
the authenticated requester. Other actions require these two target fields to
be null. A resolve operation uses a fresh random `migration_id` solely as its
correlation id, and its binding/statement/admission fields are null. Its receipt
binds the requester and request hash; observed epoch/hash and returned bundle
refer to the signed query's target. Resolver access never implies authority to
mutate that target.

The HTTP request wrapper is exactly `{message:E, evidence:object}`. Evidence
keys are selected by endpoint from: `authority`, `branch_proof`, `base_binding`,
`prepare`, `route_commitment`, `statement`, `home_binding`, `seal_receipt`,
`commit_receipt`, `activation_receipt`, `discovery_record`, `mesh_record`, `delivery_map`.
No other keys are accepted. Required evidence is the full set of referenced
objects not already present under the same hash in the authenticated server's
store. The server returns `evidence_required` with a bounded list of missing
hashes rather than treating omission as approval. `branch_proof_hash` uses the existing
`ramflux_crypto::branch_proof_document_hash` for v2. `authority` in this version
is exactly `{mode:"root_v2", root_public_key:K, device_set:SignedDeviceSetRecord}`,
using the existing signed-set/profile schema and complete revoked roster.
`authority_hash = hash_base64url("ramflux.home_node_migration.authority.v1",
JCS(authority))`. This hash is not the safety-number device-list hash.
`discovery_record_hash` and `mesh_record_hash` are respectively
`hash_base64url("ramflux.home_node_migration.discovery.v1", JCS({kind:"client",
record:WellKnownClientRecord}))` and the same expression with `kind:"server"`
and `FederationServerRecord`. These two tags are additional hash-only domain
reservations. Verify each record's existing signature with its own verifier;
this hashing rule does not change its signature preimage. All other signed
references use the envelope hash above; delivery-map hashing is defined below.
The v3 adapter is reserved future work and must be rejected until its exact
custody evidence grammar and conditional home section are reviewed. The response is exactly `{receipt:E,
route_commitment:E|null, home_bundle:object|null}`. Only prepare supplies a route
commitment; only resolve supplies a home bundle. Receipts bind the full
request message hash and nonce. Prepare receipts have null statement/binding
hashes; seal binds both and every subsequent mutation of that admission must preserve them.

Admission expiry and route validity are separate: `accept_until` closes new
acceptance of an offer, not an already activated home. Never copy it into a
legacy route-expiry field and thereby cut off a 24-hour forwarding window.
The new versioned router record retains the active binding and forwarding
anchor independently; fresh signed B status renews readiness, not admission.

A home bundle is exactly `{binding:E, prepare:E|null, statement:E|null,
route_commitment:E|null, seal_receipt:E|null, activation_receipt:E|null,
authority:object, branch_proof:object, discovery_record:object,
mesh_record:object|null, delivery_map:array|null}`. Non-genesis bundles require
all entries non-null; genesis has only binding, authority, branch proof and
client discovery non-null. Referenced historical discovery/proof documents
remain intact; refresh current node/authority status separately. Peers anchor B's
key in the account-signed binding, rather than implicitly accepting a new node
pin supplied by a directory. Changing B's key or the bound client origin requires
another account-authorized binding; a readiness refresh cannot change them.
The immutable home binding has no TTL: it is account authority history, not a
permission to reopen admission. Its separate signed activation/status evidence
supplies route readiness and freshness. Fresh directory responses never extend
an expired operation or erase a higher home/authority floor.

### Cross-document validation

For a migration id, identity/root, predecessor, epochs and target key must
agree wherever present across prepare, commitment, statement, binding and
receipts. The original actor and migration nonce match prepare and statement;
B's commitment echoes that nonce. Each later control has its own fresh request
nonce, which its response echoes. A different currently authorized own device
may recover a sealed job; it authenticates with its own current authority/proof,
not the original actor's expired proof. `next_home_epoch = base_home_epoch + 1`; arithmetic overflow is a hard
error. The binding's predecessor is that exact base; its home/route/statement
references must match the sealed documents. Client origin and federation endpoint
come exclusively from the pinned discovery/server records referenced by the
commitment. The statement's requested window cannot exceed B's offer. A receipt
from an unrelated node or naming another action/request nonce is unusable.

`delivery_map` is an array of exactly `{device_id, device_epoch,
target_delivery_id}` entries, sorted by device-id UTF-8 byte order, without duplicates and with
at most 256 entries. Its hash is
`hash_base64url("ramflux.home_node_migration.delivery_map.v1", JCS(delivery_map))`.
This is an additional hash-only domain reservation, not a signed-envelope type. It names only current,
non-revoked members of the exact authority hash. The account's management
signature binds this map through the statement/commitment, so B can create
bounded offline inbox routes for already-authorized siblings without receiving
their private keys. Target-id collisions with another root, missing initiating
device, malformed ids or epoch mismatch refuse admission. A later sibling
registration must prove the same root-qualified branch and its target binding;
a mapping alone cannot open a session or publish that sibling's prekeys.

Genesis publication is the sole mutation exception: `action:publish`, a fresh
correlation `migration_id`, `statement_hash:null`, the epoch-0 binding hash and
`admission_id:null`. The binding has null predecessor/migration/route fields and
must name the authenticated account's existing home. An old home verifies its
registered account when serving this request; permitted independent replicas
can verify the account's management signature against existing root trust.
Publishing genesis never allocates an admitted account on another node, replaces
a known home head, or requires old-node approval for B's fallback admission.

Control requests bind fresh authority/proof hashes independently of the older
sealed statement. The request wrapper supplies those documents. Status is not
an unauthenticated oracle, and an actor revoked after seal cannot keep issuing
controls using the historical proof. Historical accepted account signatures are
verified in their preserved authority context; a valid later authority head,
revocation floor, identity tombstone or resolved fork always overlays that history.
A newly presented expired intent cannot bootstrap admission from its own claim
of an old accept time. Late recovery requires matching durable node status and
the current account-authorized home/authority head, not a bare expired receipt.
Nodes may be Byzantine: a fresh B status is not proof that no newer account head
exists elsewhere. Peers retain floors and require existing account trust or an
independently verified account authority checkpoint; first-contact/bootstrap
under withheld history retains the same freshness limitation as device lookup.

### Time, replay and admission bounds

Prepare/control request lifetime is at most 300 seconds, with at most 30 seconds
future clock skew. A route commitment can be accepted for at most 600 seconds
from its node issue time; the account statement must expire no later than that
`accept_until`. `fallback_after` is exactly statement `issued_at + 300` and must
be strictly before its `expires_at`; re-prepare if the remaining admission window
cannot accommodate this. `forward_seconds` is 86400 in the initial version and
cannot exceed the commitment's cap. Nodes use their own clock, never a request's
claimed `now`. Receipts are fresh for at most 300 seconds; an expired receipt is
historical proof, and a nonce-bound status query supplies current state.

Replay keys include root, migration id, action, audience and request nonce.
Same key and same canonical request returns the stored outcome; a different hash
is `idempotency_conflict`. Keep original accept times and never extend a lease or
forwarding window on retries. Fresh authenticated status with a new nonce can
retrieve an expired request's outcome. Admission/commit ids and the per-root
home-epoch floor survive restart, retention and backup merge. Expired prepare
requests cannot recreate a reservation or replay an older home binding.

One unsealed reservation and one sealed/active migration per account root are
allowed at a node. Every transition is a durable compare-and-set on the expected
phase, base-binding hash and home epoch. Unsealed reservations expire and release
capacity at `accept_until`. A sealed migration is an irrevocable admitted account
allocation, not an indefinitely held anonymous reservation; its bounded pending
phase automatically activates by the fallback deadline, or reports a durable
service/storage failure. A node cannot promise admission without reserving the
capacity needed to fulfill this transition.

## Cooperative flow and old-node failure

1. **Resolve and persist intent.** The client validates both node records and
   pins, refreshes current account authority, and resolves the latest signed home
   binding. A legacy account first creates an account/branch-signed epoch-0
   binding for its existing home, with null predecessor/migration fields. A
   verifies it against the existing registered identity before accepting a move;
   B and peers verify its root against their existing account trust. Genesis
   creation cannot replace a binding already known at epoch 0 or higher.
2. **Prepare at B.** Persist the random migration id, exact prepare message and
   expected predecessor before sending. B verifies current authority, principal
   kind, revocation/lease state, target pin and client/server record consistency.
   B enforces storage/capacity/peering policy, reserves the same account identity
   and returns its signed commitment. Existing principal/device/delivery ids are
   carried forward; an old-home component in an opaque id is not rewritten.
3. **Authorize locally.** Verify the commitment against the pinned B key and
   exact request. Construct account-and-branch-signed statement and epoch E+1
   home binding, referencing the commitment and statement hashes respectively.
   There is no hash cycle: commitment -> statement -> home binding. Persist the
   signed bytes before any external authorization is sent. Future custody users
   wait for the primary to approve these exact bytes, not a generic permission.
4. **Seal at B.** Submit control plus statement, binding and evidence. B
   atomically consumes its reservation, seals the exact hashes and records the
   automatic fallback deadline. A sealed receipt proves durable admission, not
   old-home forwarding. This seal/abort CAS prevents a reservation being released
   while A is committing it. No subsequent abort is permitted.
5. **Commit at A.** Present B's sealed receipt and the complete signed bundle.
   A verifies B's pin/route signature, both account signatures, current authority,
   exact old-home/base binding, E+1 and unexpired initial admission. Atomically
   install the migration record, route proof, epoch floor, forwarding plan and
   commit receipt before returning success or changing routing. `effective_at`
   is A's first commit time; `forward_until = effective_at + 86400`. Retry returns
   those original values. Do not ACK installation with only volatile state.
6. **Activate B and reconnect.** B accepts A's valid commit receipt and activates
   immediately, or activates at/after the signed fallback deadline if A cannot
   supply one. Both paths use the same sealed account/binding. Persist that B is
   ready, register the existing root-qualified devices at B, publish current
   authority and prekeys, verify a live gateway session and inbox access, then
   change the per-account manifest and live endpoints. B automatically exposes the
   already account-signed active bundle through resolve once activation commits; client publication retries that same bundle
   and propagates it to replicas. B queues authenticated
   forwarded traffic already admitted after sealing until inbox activation; it
   must not reject such traffic simply because the first client reconnect lags.
7. **Publish and converge.** Publish the home bundle at B and bounded permitted
   directory replicas; deliver an encrypted own-device notice and contact/peer
   home-update notice referencing its hash. Recipients validate the bundle and
   fetch authority as needed. They update routing, prekey and gateway hints for
   the account, retain decryption/ratchet state, and retry with original message
   and envelope ids. Neither A's unsigned hint nor a node's directory entry can
   replace the account-signed home record. The client does not mark delivery
   ready until B is connected and at least B's signed resolve result confirms
   the new bundle. Replica/contact notification progress is reported separately.
8. **Close the window.** A stops forwarding at the persisted deadline. It keeps
   the authenticated migrated Nack/new-home hint and epoch floor, so peers
   re-resolve; expiry never restores A as the account's home. A closing timer and
   a delayed retry cannot reopen the window. B's periodic live route evidence
   can refresh readiness without changing the immutable home binding.

If A is unreachable, withholding status or refusing to commit, the account and B
can finish after five minutes without A's signature. Peers that receive the
account-signed active bundle route directly to B. This is a bounded escape from
A's control, **not a guarantee that an offline/malicious A forwards messages**.
Messages sent only to an unreachable A remain sender-pending; senders must retry
resolution through a known independent replica, a received signed home update,
or a contact-provided B origin with its pin. No global discoverability is
assumed: if every locator is withheld and no independent path is available,
show `publication_unreachable`; do not claim the move reaches all contacts.

A delayed A commit after fallback may install a *remaining* cooperative window
only if its signed account operation was durably sealed before admission expiry,
its current binding is still the exact base, B reports that exact binding active,
and no later home epoch is known. Use the sealed receipt's `accepted_at` as the
forward-window anchor in this late path; there is no new 24-hour extension.
An expired prepare/statement alone is insufficient. Once the corresponding
24-hour window is over, return migrated status without reopening forwarding.

The forwarder retains FU-BATCH-03 bounded leases, retryable uncertain outcomes,
durable receipts and isolation between targets. The original sender envelope
and root claim remain authenticated. Only the existing appended forwarding-count
metadata is excluded by the specific sender-signing helper and authenticated by
the federation request; do not strip arbitrary extensions or change the signed
sender principal. Enforce one forwarding hop. A second move during an active
window must first synchronize peers and reject/resolve a required multi-hop
path; the initial release returns `previous_window_active` rather than silently
creating A -> B -> C chains.

## Durable client state and user contract

One encrypted account-DB journal row owns the operation. Commit each transition
and its typed event outbox in one storage transaction **before** the next external
step. Never serialize this job only in process memory or in the global nodes
store. Account actor serialization applies; network work has request deadlines
and must not hold a daemon-wide lock or block another account's socket reads.

| Durable phase | External action / restart rule | User-visible state |
| --- | --- | --- |
| `intent` | Persist node pins, discovery hashes, id and base binding; refresh stale evidence before prepare. | Checking destination and trust. |
| `prepare_sent` | Retry identical prepare or query B by id; persist commitment before proceeding. | Requesting admission. |
| `awaiting_approval` | Obtain exact management/branch signatures; no remote seal yet. | Confirm destination fingerprint / approve on primary. |
| `seal_sent` | Query B; if prepared, retry identical seal; if aborted/expired, stop. Never guess from a lost reply. | Authorizing move. |
| `sealed` | Persist B receipt and fallback deadline; journal exact A commit request before sending. | Destination reserved; completing move. |
| `commit_sent` | Query A and B with fresh nonces; same committed hashes resume, absent A result retries before deadline; at fallback activate B. | Waiting for old home / bounded fallback countdown. |
| `destination_active` | Query B, establish authenticated gateway/inbox and prekeys; recover the same account if a reply was lost. | Connecting to new home. |
| `manifest_switch_pending` | Store new desired per-account config and operation hash before atomically replacing/fsyncing the manifest. Startup reconciles manifest with journal, not vice versa. | Saving new home. |
| `publishing` | Persist local binding floor; retry publication/own-device notices idempotently. Never reconnect to A because notification failed. | Connected; notifying devices and contacts. |
| `forwarding` | B connection and B publication verified; show A deadline only when its signed receipt confirms installation. | Moved; old-home forwarding until deadline, or moved without confirmed forwarding. |
| `complete` | Persist window closed/receipt status and retain current binding/floor. | Move complete. |
| `aborted` / `rejected` | Only pre-seal terminal outcomes; retain bounded replay fence. | Not moved, reason and safe retry action. |
| `needs_attention` | Uncertain/forked/security/storage outcome; query before any mutation, retain last safe phase. | Action required; no false success or automatic rollback. |

Persist the exact request/response hashes, signed bytes, authority evidence,
phase/event sequence, last confirmed remote states, fallback/window deadlines,
manifest old/new revisions and retry schedule. Do not store node secrets or
recovery phrases. Events contain only ids, phase, timestamps, reason codes and
public fingerprints. Ordinary backup may include diagnostic job history but
must restore it inert: do not resurrect expired/sealed work as a live job, lower
binding floors, or send an old commit without querying current node status.

A disk failure before intent persistence sends no request. Failure after a
remote mutation keeps the job uncertain and queries status on restart. The
manifest's account identity/secret/DB location stay unchanged. If it points to B
but the journal lacks a verified active receipt, reconcile against B before
networking; do not manufacture a new account or fall back to A automatically.
Endpoint switching updates gateway QUIC and TCP-TLS, signed CA/server names,
prekey origin, signaling and defaults for newly created relay objects together.
Other accounts' node preferences and existing object owner paths are untouched.

Abort is allowed only while B is prepared. It is an account-authorized control
message, CAS against that admission id. Abort racing seal has exactly one durable
winner; `already_sealed` is not a successful cancellation. After sealing, rollback
means a new reviewed migration to a previous node with a higher binding epoch,
not deletion of records or decrementing a floor. A blocked/disabled destination,
revoked actor before seal, changed pin, authority fork or admission expiry stops
before seal. A later branch revocation does not undo an already root/primary-
authorized sealed move; the revoked branch loses status/mutation access and a
remaining authorized device can recover it. A newer account-authorized move or
identity tombstone supersedes it and must be checked before delayed activation.

### Proposed local bus and CLI

- `account.home_node.migrate {operation_id, target_discovery_url,
  expected_node_fingerprint, confirm_tofu}` starts or resumes the account-scoped
  durable job. `expected_node_fingerprint` may be null only with explicit
  `confirm_tofu:true`; it cannot override an existing mismatched pin.
- `account.home_node.migration.status {operation_id}` reads durable progress;
  `account.home_node.migration.abort {operation_id}` attempts pre-seal abort.
- Response/progress/result events carry typed `operation_id`, `home_epoch`,
  `old_node_id`, `new_node_id`, `phase`, monotonic `sequence`, `reason_code`,
  `retry_after`, `fallback_after`, `forward_until` (nullable when unconfirmed),
  and `forwarding_confirmed`. Events are committed through the existing durable
  outbox/journal; subscription replay and status survive daemon restart.
- `rf account migrate-home --account ID --to HTTPS_ORIGIN
  --expected-node-fingerprint FINGERPRINT` prints typed JSON progress/results.
  Explicit first-use `--confirm-tofu` prints the discovered fingerprint for
  confirmation; noninteractive callers must pass that fingerprint back in a
  second invocation, not approve an unseen candidate with a boolean alone.
  Add status/abort subcommands selecting the durable operation id.
- Exit 0 means B is connected and its resolve result confirms publication; it
  does not mean all contacts updated or the 24-hour window elapsed. A detached
  accepted job returns its id with a distinct pending result; the CLI must not
  label a queued request “migrated”. Restart/resume does not require the phrase.

Desktop/TUI show source/destination names plus fingerprints, approval state,
cutover/fallback countdown, forwarding confirmation and a recoverable progress
screen. Confirmation includes whether the node pin is established or first-use.
Disable cancellation after sealing with a concrete explanation. Keep the screen
recoverable after app exit; use bus state, not a UI-only timer. Never ask for an
admin token, destination node seed, or routine recovery phrase. A secondary
shows the exact primary-approval request and can stay pending without losing
its old connection before the irreversible seal.

## Peer convergence, replay floors and failure limits

Home binding forms a root-authorized hash chain: E+1 references the exact E hash.
Peers persist `(root_commitment, highest_home_epoch, binding_hash)` and authority
floors before changing routing. Reject lower epochs; identical epoch/hash is
idempotent. Same epoch/different hash is `home_binding_fork`, never “higher time
wins”. Require a bounded predecessor proof from the cached head or a verified
current account authority record. A self-declared high epoch from a node cannot
skip account signatures or a fork. This is not a globally consistent directory:
partitions can temporarily hide conflicting signatures from legitimate legacy
root copies. Stop automatic moves and routing changes on discovered conflict.

Recovery from such a fork is an explicit account-management operation, not
silent last-writer choice: the primary/root selects a known valid branch,
publishes a signed current authority checkpoint naming *both* conflicting home
hashes and the chosen binding, and increments the account authority epoch. This
uses the custody public record/checkpoint machinery when v3 is enabled. For v2,
a new root-signed checkpoint schema and vectors are a required protocol work item
before enabling concurrent-device migration; until implemented, migration is
limited to one initiating device and a detected fork needs operator-visible
manual account recovery. Do not claim that local actor serialization supplies a
global lock across devices or nodes.

B and directory replicas retain current binding, epoch floor and signed closure
or tombstone; A retains the corresponding floor and final outcome after window
expiry. Retention can prune bulky receipts, but not those security fences.
After receipt pruning, status returns `outcome_pruned` plus current signed head,
never `not_found` that could restart an old migration. Do not import old replay
rows, migration reservations or job timers from backups as live operations.

If a peer's cached A route Nacks, it first verifies the signed home bundle or
performs authenticated resolution, then updates its routing cache and prekey
origin. Contacts without the feature cannot be promised transparent migration;
announce required capabilities before seal. Signed home-binding/notice support
and a working independently reachable B locator are demo prerequisites.

## Abuse, privacy and resource controls

These are proposed initial limits, not claims about current configuration.
Bounds may be lowered by node policy; responses identify a policy refusal before
seal. Raising wire maxima requires a negotiated protocol version.

| Resource | Initial bound / enforcement |
| --- | --- |
| Request header/body | 8 KiB / 256 KiB; count streamed bytes, never allocate from declared length; reject malformed lengths and oversize before signature work. |
| Whole request / internal call | 10 seconds / 5 seconds, including trickle reads; no per-read timeout reset. Replies and evidence fetches are also size/deadline bounded. |
| Concurrency | Existing public listener cap plus at most 16 migration signature jobs per node; 1 active mutation per root; no synchronous expensive crypto on the sole socket-reader worker. |
| Prepare attempts | After authentication, burst 2 and 6/hour per root, one outstanding reservation per root; repeats with the same id/hash cost no new admission allocation. |
| Status/resolve | After authentication, burst 10 and 60/minute per requesting root; mutations share a 20/minute/root budget. Authenticated missing queries allocate no durable row. |
| Anonymous/source pressure | Cheap connection/byte limits and configurable per-source ceilings before crypto; use the node's existing source classification/CGNAT controls. Never substitute an IP for an authenticated root. |
| Pending state | At most 1024 unsealed reservations per node, with a node-capacity cap on sealed/active accounts. A full node refuses before seal. |
| Evidence | At most 128 KiB of authority evidence, 64 predecessor links and 16 additional documents per request; verify exact referenced hashes. Larger accounts/chains require a bounded checkpoint path or `evidence_too_large`, never truncation. |
| Retention | Delete unsealed payloads within 1 hour after expiry/abort; retain small operation replay tombstones 48 hours. Keep only current/last sealed payloads per root and the permanent highest epoch/current-hash/closure floor. Bulk historical receipts follow a documented retention budget. |
| Work and notifications | At most 128 due transitions per worker tick; per-item errors are logged by code/id and do not abort unrelated accounts. Contact fanout is paginated, retryable and bounded, not a synchronous commit prerequisite. |

Pre-auth source throttles protect CPU but must not charge an arbitrary supplied
account's admission budget. Authenticate and verify all bindings before charging
per-root limits. Capacity checks and reservation creation are atomic. A fresh
self-generated key is not proof that an account is already admitted: new-to-B
roots still pass its registration/admission policy, including the existing PoW
challenge where configured. Source limits must be configurable for shared CGNAT
populations; retain independent per-root and global ceilings so loosening a
source cap cannot remove abuse protection.

Check destination routes against the pinned signed server record and operator
federation policy before dialing. DNS rebinding, redirects, private-address
routing and cross-origin fetches use the existing node transport policy, with
explicit operator permission for LAN deployments. Do not let a signed account
statement turn a node into an arbitrary URL fetcher. A malicious destination can
refuse service or observe normal routing metadata; it cannot manufacture the
account/root signature or change the committed destination. A malicious old
home can withhold data and lie about progress, so status is signed, nonce-bound
and checked against B's evidence; it cannot forge a higher account binding.

Logs exclude admin credentials, seeds, raw authority documents, full signatures,
message bodies and contact lists. Public errors are typed and generic; detailed
operator diagnostics use bounded operation ids and reason codes. A home change
reveals the new home to contacts and serving nodes; it is not an anonymity or
unlinkability feature. Prefer authenticated lookup and contact notices over an
index enumerating all migrated identities. Resolve authentication bounds abuse;
it does not require the node to learn or reconstruct encrypted contact graphs.
Knowing an opaque target id can reveal its public home record, but never grants
contact consent, identity-management authority or access to its inbox.

### Result and error vocabulary

HTTP status is transport classification; the node-signed receipt carries the
semantic result once a request is authenticated. Valid result states are
`prepared|sealed|committed|active|published|aborted|expired|superseded|unknown`.
A receipt state version increments monotonically for that node's operation.
Before authentication, return a generic bounded error without disclosing whether
an identity or operation exists; no fabricated signed account outcome is needed.

| Class | Reason codes and client action |
| --- | --- |
| Trust / authority (403) | `pin_mismatch`, `trust_confirmation_required`, `authority_stale`, `actor_revoked`, `authority_fork`, `custody_approval_required`; refresh or require user/primary action, never downgrade. |
| Conflict (409) | `base_mismatch`, `home_binding_fork`, `idempotency_conflict`, `already_sealed`, `previous_window_active`, `superseded`; fetch signed status/current head before deciding. |
| Expiry (410) | `admission_expired`, `request_expired`, `outcome_pruned`; a fresh query can recover a previously accepted result; an expired request is not retried as a new authorization. |
| Policy / size (413/422/429) | `evidence_too_large`, `evidence_required`, `capacity_refused`, `peering_unavailable`, `rate_limited`, `unsupported_capability`; bounded backoff or a new user-approved prepare, never skip admission. |
| Retryable / uncertain (503 or transport failure) | `storage_unavailable`, `service_unavailable`, `publication_unreachable`, `outcome_unknown`; retain the last confirmed phase and query status before repeating a mutation. |

Signed receipts must not echo requester-controlled error messages or URLs.
`Retry-After` and `retry_after` hints are capped at 300 seconds; they are scheduling
advice and never extend admission, authority, seal or forwarding deadlines.
Terminal rejections before a durable mutation may use a generic error instead
of a receipt. A timeout/500/503 after sending a mutation is always uncertain to
the caller; it must not be interpreted as proof that the mutation did not occur.

## Implementation work packages and readers

| Layer | Required work; producer and readers |
| --- | --- |
| Protocol/crypto | Version the existing route commitment and migration-proof family; add typed envelope builders, reserved domains, binding/receipt/control types and strict ingress. Devices produce account/actor signatures; nodes produce route/receipt signatures; clients, old/destination routers and peers verify them. Add current-head/fork checkpoint handling before multi-device enablement. |
| Router | Account-authorized prepare/seal/commit/activation/status state; current-authority and epoch checks; one transaction for migration, route, forwarding anchor and receipt; bounded due-work worker. Add v2 bundle validation rather than coercing a commitment/seal into a v1 node signature. Existing forwarding runtime reads only committed records and retains the approved train's leases/replay behavior. |
| Federation public origin | Add only the client routes listed above with auth, body/deadline/cap controls; proxy through authenticated internal services. Signed client/server records advertise `home_migration_v1` and `home_binding_v1` capability strings once complete. Keep admin handlers unreachable here. Update the route inventory and demo HTTPS origin configuration. |
| Federation mesh/directory | Admission-policy query, sealed/active status and signed home-bundle replication among admitted peers; no client admin credential. Destination produces route/activation evidence; contact and own-device resolution consume it. Validate immutable node pin and endpoint binding before forwarding. |
| Gateway/identity | Admit migration registration for the same root/branch/delivery ids using the sealed bundle; preserve identity kind, signed revocation floors and fresh session proof checks. Do not let generic foreign-home registration bypass migration admission. Publish current device authority/prekeys and make offline sibling inboxes available before claiming readiness. |
| Storage/retention | Incremental per-root operation rows, immutable exact-byte blobs, CAS phase updates and transactional outbox; persistent binding/authority/replay floors. Manifest reconciliation is crash-safe. Backup restore imports jobs inert and cannot lower floors or replay old timers. Avoid whole-registry snapshot rewrites for each status query. |
| SDK | Replace the in-memory method as the user operation's authority with an async durable migration coordinator; retain/model-test the existing method as appropriate but do not call it to claim network success. Reuse node lookup, pin verification, TLS, account authority, registration and gateway reconnection. Bind retry work to the exact account actor and journal id. |
| Bus and `rf` | Account-scoped migrate/status/abort, durable typed progress/result/errors, journal replay and nonblocking subscriptions. CLI flags and fingerprint confirmation above; real bus/CLI tests verify actual transitions and restart recovery. |
| Desktop/TUI | Trust review, exact primary approval where required, persisted progress/recovery view, cancellation boundary and truthful distinction between destination connectivity, publication and confirmed old-home forwarding. |
| Deploy/itest | Configure two genuinely client-reachable HTTPS origins and already-admitted peers; update production/itest capability and route inputs. Rewrite s51 to drive CLI/bus with production service paths and real node-generated proofs. No node seed or admin token enters the client or the test's migration requests. |

The public directory home bundle becomes the authoritative home reader for
contact routing, gateway recipient resolution, principal lookups, prekey URL
selection, own-device activation/restore and account status. Audit all of these;
merely changing the initiating daemon's gateway leaves cached senders behind.
Account backup, exported contact cards and stale node profiles are hints, not
permission to lower that reader's persistent binding floor. Existing contacts'
trust in the account root is retained; this operation does not make them
re-accept a contact or device invitation.

### Development-stage removal of the old control path

Remove the admin-token migration/apply and route/update/apply request schemas and
production/test routes after s51 uses the account-authorized path. There is no
combined mode, public admin alias or CLI `--admin-token` escape hatch. Operator
health/status tooling can inspect signed outcomes through its separate private
administration surface, but cannot impersonate account authorization. Keep pure
core signature/route validation helpers if still used, behind the new durable
transaction boundary. Old v1 fixtures may remain protocol-history vectors, but
must not be accepted as v2 migration authorization. Update operator docs and
remove fixture code that forges B's route proof from a known B seed.

Existing stored account data and current identities remain readable. An account
without a binding bootstraps epoch 0 once from its pinned existing node and
account authority; the first server/peer observation persists that floor.
An existing migrated admin fixture must be recreated through the real flow in
development, rather than silently upgraded from an admin token to account
consent. No change to root derivation, principal kind or device ids is allowed.
Capability negotiation fails closed until both nodes and the relevant clients
implement and advertise the flow. Landing the forwarding prerequisite alone
does not enable the migration UI.

## Acceptance tests and release ordering

Protocol vectors must cover each exact preimage/domain, JCS property order and
number edge cases, UTF-16 sort behavior, I-JSON duplicate/surrogate/numeric
rejects, strict unknown-field handling, base64 lengths, signature role order,
and nested-evidence substitution. Mutate every identity/root/device/epoch,
destination pin, predecessor hash, nonce, audience, deadline and route endpoint
individually; no signature accepted in another message domain or role.

Server tests use the actual public listener and private service path. Check
public admin paths stay 404, clients cannot pass admin credentials as authority,
invalid/revoked/forked devices cannot charge another root's budget, and
root-correct but account-unrelated documents cannot satisfy an evidence hash.
Adversarial requests include private-URL/redirect/DNS rebinding attempts, huge or
malformed Content-Length, trickle clients, oversized authority chains, duplicate
ids with changed payloads, expired admission and shared-source CGNAT load.

Crash injection is required immediately before and after each store commit and
response: B prepare/seal/activation, A migration+route+receipt, manifest replace,
publication and outbox acknowledgment. Verify exact replay returns original
windows/outcomes; lost replies recover through nonce-bound status; cleanup of an
unsealed reservation cannot cancel a sealed move. Abort/seal races have one
winner. Delayed old-node commit, changed/newer bindings, revoked actors,
backup import, multi-device epoch conflicts and pruning all fail closed without
resurrecting a route or extending the forwarding period.

SDK bus tests run through a real Unix socket and persisted account DB, with
local stub *services* implementing the reviewed protocol rather than stubbing
the migration coordinator's success. Restart the daemon in every phase. Check
journal event sequence/replay, exact endpoint/manifest switch, sibling
convergence, safe inert restore, timeout recovery, other-account responsiveness
and CLI JSON/exit behavior. Primary approval tests bind exact destination and
statement hashes; a secondary or headless caller cannot widen that approval.

Rewrite realnet s51 as follows:

1. Start two production-path nodes with verified HTTPS discovery and admitted
   peering, plus a sender. Provision server keys only through normal node setup.
   Create and contact the migrating account through the real client path at A.
2. Establish a ratchet and receive an encrypted DM before migration. Invoke
   `rf account migrate-home` through its real daemon socket using B's discovered
   fingerprint; assert signed admission/seal/commit/active/publication evidence.
   The fixture must not construct B's proof, call admin migration routes, or
   supply an admin token to the account/CLI operation.
3. Keep the sender intentionally using its cached A route; send new encrypted
   DMs during the confirmed window. Assert forwarding to B, unchanged sender
   signature/root and ciphertext identity, exactly one delivery and successful
   decryption. Confirm the sender later resolves the signed binding and sends
   directly to B. Verify the offline sibling can reconnect without new identity.
4. Lose a commit reply and restart the client daemon; also restart A and B after
   durable transitions. Assert the same migration id, base/head, window anchor
   and operation outcome, with no second identity, duplicate ACK or lost DM.
5. Blackhole A's control path while keeping the independent B locator available;
   after the bounded fallback verify B activation and peer rerouting. Do not
   assert forwarding from a deliberately unreachable A. Separately test no
   independent publication path and require an honest pending/attention result.
6. Close the window using an injected server clock in focused tests and a bounded
   configurable *test-only* duration in realnet. A emits migrated Nack/hint,
   sender verifies/re-resolves and delivers directly to B. Restart/restore must
   not reopen A forwarding. Exercise original-forward retry and revocation
   regressions from the forwarding train alongside s51.

Release order: review this design and the authority/expiry choices; land the
forwarding dependency train; implement protocol/crypto and vectors; implement
server transactions and genuine client routes; implement signed home discovery
and all routing readers; implement SDK durable job/bus/CLI; wire UI and deploy
inputs; run rewritten s51 plus identity, sibling restore, receipts, DM, backup
and forwarding regressions. Enable the capability/UI only after live acceptance.
Implementation reports must distinguish unit/bus evidence from realnet results.
