# Root-bound device keys

The protocol and node authority layer bind a device's exact signing and agreement
keys to its identity root. SDK verification, safety notifications, peer revocation
cleanup and actor-kind projection are a separate integration step. Existing SDK
clients do not yet consume this authority chain or produce the new registration
inputs. This change alone is not an end-to-end client security fix.

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
and validity interval. Callers must obtain the expected keys from the bundle and
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
Publishing a record alone cannot enroll a new root. The node pins the identity
root and kind; it rejects a device ID already owned by another identity.

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
replace a newer signed epoch. Session persistence retains its existing lifecycle.

Irreversible identity deletion removes its key/route records but retains a minimal
root-commitment/kind deletion fence. The deleted root cannot reenroll or change
kind through a new principal label. `human`, `headless_ai`, `bot` and `workflow`
are immutable root assertions for an enrolled identity, not attestations that an
unknown new root belongs to a biological human. Distinct new roots still need
identity trust and policy; the enum does not solve Sybil identity classification.

## Legacy migration and client integration

Historical branch proofs without `key_binding` retain their exact v1 signing
bytes and can be verified as legacy metadata. Previously stored registrations and
bundles remain readable. Such proofs cannot authorize a new registration or
prekey write, including replacing an existing legacy key. To migrate, the root
signs a complete set covering every existing device and issues v2 proofs binding
the existing keys. A changed legacy key requires a higher device epoch. Publishing
the set fences old registrations until matching v2 registrations/prekeys arrive;
there is no automatic unsigned upgrade or trust-on-first-use exception.

Client integration must verify the bundle signature, exact branch key and
agreement-key binding, root commitment, principal kind, signed-set membership and
highest accepted epoch. It must expose safety changes and stop using revoked or
rotated devices. A server may withhold a newer record; monotonic storage prevents
rollback after observation but is not a transparency log or freshness oracle.
The current SDK path has not been switched over, so client registration with its
old proof builder fails against this node write policy until that integration is
completed. Roll out the compatible client/node chain together.

The design follows the authenticated key hierarchy principle in
[Matrix cross-signing](https://spec.matrix.org/v1.16/client-server-api/#cross-signing),
which signs device keys through identity-controlled signing keys and requires
verification of actual key material. Ramflux uses its existing direct root-to-device
hierarchy rather than adopting Matrix's wire format or extra signing-key tiers.
[Signal X3DH authentication](https://signal.org/docs/specifications/x3dh/#authentication)
also makes the identity authentication boundary explicit: a valid prekey signature
alone does not authenticate a human identity. Root trust/fingerprint comparison
and the subsequent client safety policy remain necessary.
