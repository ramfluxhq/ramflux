# Root-bound device keys

The protocol, node authority and SDK bind a device's exact signing/agreement
keys to its identity root and complete signed device set. SDK enrollment emits
v2 proofs; live key use verifies the chain and preserves the highest observed
set across restart. Signed revocation and authorized rotation retire obsolete
pair state and produce safety changes. This implementation still requires
independent review and cross-service acceptance before deployment.

## Authority chain

The root signs an existing branch-proof document with an optional `key_binding`:
`version: 2`, `principal_kind`, `branch_signing_public_key` (Ed25519), and
`agreement_identity_public_key` (X25519). Public keys use canonical unpadded
base64url encoding of 32 bytes. Weak signing keys and non-contributory agreement
keys are rejected. The existing principal, device, device epoch, audience,
capabilities and validity interval remain signed.

`branch_proof_signing_bytes` uses the existing RFC 8785 canonical JSON encoder.
For bound proofs its signing body additionally contains
`domain: "ramflux.branch_proof.v2"`. The outer proof document retains its existing
shape plus `key_binding`; the domain is added by the signing-body encoder.
`verify_root_bound_branch_proof` compares both advertised keys and the expected
kind with that binding, then verifies the root signature, audience, capability
and validity interval. Future issuance is accepted within the documented
`BRANCH_PROOF_CLOCK_SKEW_SECONDS = 300` second bound; expiry is still enforced. Callers must obtain the expected keys from the bundle and
compare them, rather than treating a generic proof-signature check as key
validation. The node performs this comparison for registration and prekey writes.

A prekey bundle's existing device signature remains required. The node additionally
compares its device ID/epoch, Ed25519 identity, both X25519 identity fields and
principal with the registered root-bound values. A valid attacker-signed bundle
cannot replace the device key while retaining a genuine root authorization.

## Complete signed device set

`SignedDeviceSetRecord` uses schema/domain
`ramflux.identity.signed_device_set.v1`, version 1, and contains:

- `principal_id`, the existing `principal_commitment`, and `principal_kind`;
- `device_set_epoch`, a positive monotonically increasing integer;
- sorted, unique `devices` entries containing `device_id`, `device_epoch`,
  `signing_key_commitment`, `agreement_key_commitment`, `status` (`active` or
  `revoked`), and `revoked_at` for revoked entries;
- an Ed25519 root `signature` over canonical JSON of all other fields, including
  the domain. The signature field is excluded from its own signing body.

Key commitments use `blake3_256_base64url` over the raw 32-byte public key under
`ramflux.identity.device_signing_key.v1` and
`ramflux.identity.device_agreement_key.v1`, respectively. The root commitment
continues to use `ramflux.identity.root_public_key.commitment.v1`.

Records retain every known device, including immutable revocation tombstones.
Exact retransmission is idempotent. A different record at the same or a lower
epoch, an omitted known device, changed principal/root/kind, or resurrection of a
revoked ID is rejected. Rotating either key requires a higher device epoch in a
higher set epoch. Old prekeys are immediately removed; the new active device
remains unusable until a matching v2 registration and prekey publication succeed.
Revocation removes prekeys and makes the existing node device-auth response
revoked. An all-revoked identity still has a manifest containing its complete
signed set and an empty active-device array.

Limits are 1024 lifetime device IDs per identity, a 512 KiB record/request budget,
256-byte identifiers, and epochs/timestamps within the protocol's safe JSON
integer range. `SignedDeviceSetRecord::from_wire_bytes` rejects duplicate keys,
non-I-JSON values and oversized input. All cryptographic verification and
transition checks remain mandatory after decoding. Signed device IDs are sorted
by Rust string order before signing; canonical JSON orders object property names
using the shared encoder. Array order is part of the signature.

## Node publication and storage

`IdentityRegisterRequest.device_set` can carry the initial signed record or an
updated record together with a v2 branch proof. Initial authority is admitted only
through identity enrollment and its existing registration policy/rate/PoW gates.
Publishing a record alone cannot enroll a new root.
Exact record/root retransmissions take a read path without cloning or persisting
the registry. Gateway publication admission is bounded by both the actual source
IP and principal commitment. Per-minute defaults are 60 per principal and 120 per
source, with separate bounded source and root tables, each holding at most 4096 buckets. Signatures and root commitments are
verified before charging root quotas; malformed claims never spend a victim's
root allowance. Within an admission window, replayed epochs at or below its
highest observed epoch do not consume mutation quota. Ascending replay of distinct
historical epochs in a new window remains a documented quota limitation. Source admission still applies to every decoded publication. IPv4 sources
use addresses (including mapped IPv4); IPv6 sources aggregate by /64. Saturated
admission state evicts least recently used entries within its own table instead of denying all new
publishers. Root churn cannot evict source quotas. Signature verification holds neither bucket
lock; ordered eviction and updates take logarithmic work without scanning the tables. Configuration uses
`RAMFLUX_GATEWAY_DEVICE_SET_PER_PRINCIPAL_PER_MINUTE`,
`RAMFLUX_GATEWAY_DEVICE_SET_PER_SOURCE_PER_MINUTE`, and
`RAMFLUX_GATEWAY_DEVICE_SET_MAX_BUCKETS`; values must be positive and are capped
at 10000, 20000 and 65536, respectively. Every gateway framed runtime rejects
duplicate keys before generic-value normalization. The node pins the identity root
and kind, and rejects key updates outside the expected root's device namespace.

`POST /mvp2/device-set` accepts `{ "root_public_key": "...", "record": { ... } }`
for an enrolled root and returns the accepted record. `GET /mvp2/device-set/<principal_commitment>` returns the complete record or null.
The routes are available on the router's existing authenticated mesh interface
and its optional integration-test HTTP interface, and through gateway generic
QUIC request dispatch and optional integration-test HTTP forwarding.
`GET /mvp1/device-manifest/<principal_commitment>` additionally includes
`signed_device_set`; its active-device list is a convenience view, not signed
revocation evidence. Root-bound identities must revoke through a newer complete
record; the old device-revoke endpoint is rejected for those identities.

`RouterCore::publish_signed_device_set` and `register_identity_durable` validate a
candidate registry and durably store it under the control writer lock before
publishing its authority changes to readers. Identity snapshot persistence also
uses that lock and the current registry, so a captured older snapshot cannot
replace a newer signed epoch. Deletion cleanup also takes its current identity state and commits cleanup under
that same writer lock; it cannot persist an earlier captured identity snapshot.
The service's durable deletion finalizer computes the candidate identity/lifecycle
and target cleanup under that lock, commits them in one storage transaction, then
publishes the candidate. Its non-durable variant remains for in-process callers.
Session persistence retains its existing lifecycle.

Irreversible identity deletion removes its key/route records but retains a minimal
root-commitment/kind deletion fence. The deleted root cannot reenroll or change
kind through a new principal label. `human`, `headless_ai`, `bot` and `workflow`
are immutable root assertions for an enrolled identity, not attestations that an
unknown new root belongs to a biological human. Distinct new roots still need
identity trust and policy; the enum does not solve Sybil identity classification.

## Root-scoped device routing

Device/prekey storage and revocation indexes use `(root_commitment, device_id)`;
one root's signed set does not reserve another root's local device name. A local
ID can therefore exist independently under different roots. New records use scoped
storage keys; historical unscoped rows remain readable through their pinned owner.
Gateway session authentication selects the device by its signed principal claim
and then verifies the claim with that root's registered device key.

The existing prekey/device-auth lookup endpoints accept an opaque lookup token:
`root~BASE64URL(JSON([root_commitment,device_id]))` or
`principal~BASE64URL(JSON([principal_id,device_id]))`. The gateway uses the latter
for session authentication. Responses keep the original signed local device ID.
Bare lookups serve only unambiguous legacy pre-v2 registrations. Root-bound devices
always require qualified lookups. Missing, ambiguous or unqualified root-bound
lookups return explicit errors rather than keys or an empty successful lookup. SDK consumers must retain root context
when selecting a target, rather than treating the raw local ID as globally unique.

## Legacy migration and client integration

Historical branch proofs without `key_binding` retain their exact v1 signing
bytes and can be verified as legacy metadata. Previously stored registrations and
bundles remain readable. Such proofs cannot authorize a new registration or
prekey write, including replacing an existing legacy key. To migrate, the root
signs a complete set covering every existing device and issues v2 proofs binding
the existing keys. A changed legacy key requires a higher device epoch. Publishing
the set fences old registrations until matching v2 registrations/prekeys arrive;
there is no automatic unsigned upgrade or trust-on-first-use exception. Legacy
rows whose root commitment is empty are fenced by their principal's accepted
signed set too. Omitted blank-commitment devices become unusable for routing and
own-device copies, and their legacy IDs cannot later be resurrected as active
under that root. Explicit inclusion still requires matching root-bound registration
before the device becomes usable.

Client integration must verify the bundle signature, exact branch key and
agreement-key binding, root commitment, principal kind, signed-set membership and
highest accepted epoch. It must expose safety changes and stop using revoked or
rotated devices. A server may withhold a newer record; monotonic storage prevents
rollback after observation but is not a transparency log or freshness oracle.
The SDK now verifies that chain before caching live key material. It pins roots by
commitment, persists the highest signed record, rejects same-epoch conflicts and
rollback, and retires device-pair/reset work after signed revocation or rotation.
Group pins change only under an ownership-bound compare-and-swap authorized by a
newer signed set. A root change under an existing principal label is a hard safety
failure. Prekey lookups retain the expected root through qualified lookup tokens.
An unsigned omission from the ready-device list never implies revocation.

Outgoing prekey discovery requires an explicit recipient Root commitment or a
previously authenticated directory entry; bare device IDs are never used to
obtain a Root from the server. New routed ciphertext wrappers carry an optional
`source_principal_commitment` hint covered by the sender's outer signature. A
first-contact receiver fetches that Root's manifest and verifies the complete
chain before accepting the sender. The hint is lookup context, not an identity
attestation, and cannot override a pinned Root. Historical wrappers without a
hint require existing Root context. All live prekey paths, including A2I and
own-device history key slots, use qualified lookups and exact bundle checks.
Own-device key-slot exports create fresh X3DH sessions rather than reusing a
conversation checkpoint after remote key rotation.


Registration/prekey writes use v2 proofs and a complete signed set. A pending root
proposal is persisted before network submission and retried unchanged while the
remote epoch remains unchanged. A differing own-root fork is reconciled before
re-proposing the retained intent at a later epoch. Observed signed revocations are retained even if local reenrollment fails.
Standalone revocation publishes a newer signed set and requires an exact record
acknowledgement. Upgrade the compatible client/node chain together.

The design follows the authenticated key hierarchy principle in
[Matrix cross-signing](https://spec.matrix.org/v1.16/client-server-api/#cross-signing),
which signs device keys through identity-controlled signing keys and requires
verification of actual key material. Ramflux uses its existing direct root-to-device
hierarchy rather than adopting Matrix's wire format or extra signing-key tiers.
[Signal X3DH authentication](https://signal.org/docs/specifications/x3dh/#authentication)
also makes the identity authentication boundary explicit: a valid prekey signature
alone does not authenticate a human identity. Root trust/fingerprint comparison
and the subsequent client safety policy remain necessary.


## Client migration and verification interfaces

For a single legacy device, migration binds its locally held signing/agreement
keys. For multiple devices, collect a v2 root-signed authorization independently
from each device; the SDK never upgrades server-advertised v1 keys by signing them.
The complete set includes remote directory devices, independently supplied
authorizations and known local account devices. Missing authorizations fail
closed. Devices remain fenced between publication and matching v2 registration /
prekey installation; each legacy sibling must migrate with its own private keys.
A complete root-signed set already observed remains authoritative after restart.

```sh
rf --socket /path/to/device-two.sock device authorize --account account > device-two.json
rf --socket /path/to/device-one.sock device migrate --account account --authorization-file device-two.json
rf --socket /path/to/device-one.sock device refresh --account account --principal-commitment ROOT_COMMITMENT
rf --socket /path/to/device-one.sock device revoke --account account --device DEVICE_ID
```

The generic C ABI JSON request interface uses the same `device.authorize`,
`device.migrate {authorizations:[...]}`, `device.refresh {principal_commitment}` and
`device.revoke {device_id}` methods; no C struct layout or exported symbol changes
are required. Revocation responses include `device_set_epoch`; the TUI verifies
the matching device/result/epoch before reporting success.

`root_asserted_principal_kind` exposes authenticated immutable root assertions.
`verified_principal_kind` additionally requires user verification of the contact's
current safety material and complete signed device set. Identity-directory rows
and refresh responses distinguish `kind_asserted` from `kind_verified`. A signed
`human` assertion is not proof that the holder is human. The headless account
creation path rejects a human kind; headless/bot/workflow kinds can be explicit.
Contact verification uses authenticated manifest key material and binds the
verification to the complete signed set. Missing active-device key material
prevents safety verification; device-set changes require verification again.
Old unbound state remains readable but cannot authorize live key use.

The SDK accessor is the integration boundary for task actors on branches that
carry task projection support: `actor_kind_verified` must use
`verified_principal_kind`, never a display label, client mode or root assertion
alone. Local source, restore and peer paths must retain that distinction.
All gateway framed runtimes (quinn QUIC, TCP-TLS and compio QUIC) share strict
I-JSON parsing, a 1 MiB frame limit and signed-publication admission before router
dispatch. The compio transport's later JSON frames also use the strict parser.

## Device address and authority lifecycle

Local device metadata, directory entries, pair references, revocation fences and
bound group pins distinguish `(root commitment, literal device id)`. SDK-owned
sends require `recipient_principal_commitment` alongside the literal id, or a
qualified `root~` address. Names inside an address are decoded exactly once.
Bare foreign names never select live authority, even when only one directory row matches. Historical unsigned metadata and orphan
sessions cannot supply live key authority. Account opening atomically migrates
metadata and pins into separate scoped and legacy storage namespaces; it does
not endorse old unsigned keys. Unscoped pair secrets move to a separate read-only
legacy archive instead of guessing their root ownership. Old active pointers and
recovery work are removed; authenticated automatic bootstrap/recovery creates a
fresh live pair. The archive grants no live authority. Historical deferred slots
that lack verified root context can require a verified resend; the migration
preserves the original encrypted-at-rest secret records for explicit recovery. Scoped pair pointers use a separate hash domain and records carry
an explicit root-addressed marker. Unsolicited root hints cannot establish contacts:
an accepted relationship naming that root and a verified envelope signature must
precede first-contact persistence.

Signed device-set authority is independent of a ready device's proof expiry.
An expired authorization prevents a new session to that device; existing sessions
remain subject to the newest accepted signed set and local revocation fences.
The daemon's live-account maintenance re-registers proofs after 55 minutes for
the one-hour proof lifetime. Library embedders must drive the live-session
maintenance or explicitly re-register; creating a client does not start a
background scheduler. Own-device history imports apply the same monotonic set
and revocation checks before verifying a sibling's signature or fetching history.

Concurrent own-root publications reconcile against the latest verified node
record. A stale pending proposal is discarded with a safety event, its revocation
intents are retained, and a successor is re-proposed within three attempts.
Submission acknowledgements are echoes, not independently witnessed storage
receipts. A successful submission does not prove that a malicious node serves the
record to peers. Withholding and peer freshness still require independent checks.

## Current root custody boundary

Each enrolled terminal currently retains the root seed in its protected local
account material. A compromised terminal therefore has root authority, even
after its device entry is revoked: it can sign newer sets, rotate other devices,
revoke siblings, or enroll another id. Device revocation fences the removed
branch under the highest observed set; it cannot revoke a stolen root seed.
Moving the root offline or introducing constrained enrollment subkeys requires
an owner decision and a separate migration. This implementation does not change
root custody or claim recovery from root compromise.

Peer revocation does not itself rotate existing group sender keys. A previously
issued group key remains known to that terminal until the group advances its key
epoch; delivery filtering alone cannot erase that knowledge. Legacy migration
still requires independently root-authorized material for every listed device;
a lost or phantom legacy entry can block migration and needs explicit recovery.


## Group controls and literal device names

New group controls use `ramflux.client_event.v2` with the existing group signature
domain. The signed `group_device_roots` extension binds the actor and each member
selector to their root commitments; the body retains literal device names. The
actor must match a pinned group key and current root authority. An accepted
invite must also match the root recorded for that exact invite. A legacy join
without a root uses only its group's invite provenance. Missing or conflicting
provenance leaves the event pending and does not pin a directory candidate.

New enrollment and ready-proof verification reject `root~` and `legacy~` device
name prefixes, blank names, Unicode control/format and line/paragraph separator characters,
and names over 256 bytes. Printable Unicode names remain supported. Storage
address encoding continues to preserve historical literal names. Historical
message sender names never acquire a new principal from today's device directory;
receipts resolve roots through their conversation's explicit route or participant
relationship, or a group-specific pin. Pending own-root revocations are checked
explicitly before sibling history imports. A failed scheduled proof refresh
surfaces `OwnDeviceAuthorizationRefreshFailed` in the sync status reason code.


Direct-conversation authorization compares the verified sender principal (or an
explicit root-qualified participant address), never a sender-selected literal
device name. Delivered/read receipt payloads must name their authenticated route
and literal sending device. Root-bound receive stores receipt deduplication and
read/delivery state under the verified root-qualified device reference, so peers
with equal device names remain distinct. Legacy receipts remain in their original
namespace and do not acquire new root attribution. Self-conversation receipts use
the account's own root, including when a foreign peer reuses a sibling's name.

Root-qualified group-pin reads exclude unscoped legacy rows even if their public
key matches. Explicit qualified pin creation stores its root at insertion; it does
not adopt an old by-name pin. Sender admission still verifies that key's root
proof and active signed set. Old unscoped rows remain historical data. Direct-add
v1 joins from administrators without the signed-root extension/invite witness
stay pending; later epoch changes may wait too. Administrators must upgrade and
provide a root-bound join/invite to resume that group's control sequence.
