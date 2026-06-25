# Threat Model

This document describes the security model for the Ramflux core workspace: the
node services, SDK, `rf` CLI, protocol, cryptography, storage, transport, sync,
and node-core crates.

Ramflux is an end-to-end encrypted messaging and federation core. Servers route,
store, wake, relay, and federate opaque records. Clients own account identity,
device identity, end-to-end encryption keys, safety verification, and local
authorization decisions.

## Trust Boundaries

### Trusted Boundary: Client Devices

The client device is the primary trusted boundary. A correct client is expected
to:

- generate and protect account root and device keys;
- verify contact identity commitments, device manifests, branch proofs, and
  prekey bundles before computing safety numbers or encrypting to a device;
- encrypt message content before handing it to a node;
- sign device-bound requests and local authorization grants;
- enforce risk floors and confirmation requirements for delegated tools;
- store local account state and recovery material under local OS protections.

The SDK and CLI are part of this client boundary when they hold account secrets.

### Untrusted Boundary: Node Services

Ramflux node services are treated as opaque-message infrastructure. A node may
authenticate transport peers, rate-limit, persist queues, enforce delivery
cursor rules, and route frames, but it must not need message plaintext.

The node can see routing metadata required to operate the service, including
delivery identifiers, node identifiers, timing, sizes, transport endpoints, and
some coarse delivery classes. It is not trusted for message content
confidentiality.

### Federated Boundary: Peer Nodes

Federation peers are independent administrative domains. A local node admits a
peer through explicit trust pinning, node-key verification, protocol overlap,
transport overlap, and capability negotiation. A federated peer is trusted only
for the capabilities negotiated for that peer. It is not trusted with user
plaintext.

### Local Automation Boundary

Agents and tools connected through the local bus are untrusted until authorized.
The SDK requires device-signed grants, applies a default risk floor, emits
approval events for interactive confirmation, and records audit events for tool
execution.

## Attacker Model

Ramflux considers the following attackers in scope:

- **Passive network observer.** Can observe packet timing, size, endpoint
  addresses, and connection metadata.
- **Active network attacker.** Can drop, delay, replay, reorder, or inject
  network traffic, but does not possess trusted private keys.
- **Malicious or compromised node.** Can run arbitrary server code for one node,
  misroute or withhold messages, lie about local availability, replay old
  server-side records, and attempt to serve malformed manifests or prekeys.
- **Malicious federation peer.** Can advertise false capabilities, replay old
  handshakes, attempt key substitution, and send malformed cross-node delivery
  requests.
- **Compromised client device.** Can access that device's local plaintext,
  local secrets, and delegated grants, and can sign as that device until the
  device is removed or rotated.
- **Malicious local agent or tool.** Can request broad capabilities, attempt to
  reuse approvals, or submit misleading tool metadata through the local bus.
- **Storage attacker without live keys.** Can read or copy persisted node state
  or local client files, but does not have the live device keys or passphrases
  needed to unwrap protected client material.

## Security Guarantees

### End-to-End Content Confidentiality

Message content is encrypted by clients before submission to the gateway. Nodes
route `Envelope` records and inbox entries but do not need plaintext message
bodies. A node compromise should not reveal protected message content that was
encrypted for uncompromised recipient devices.

### Device-Aware Safety Verification

Safety material is derived from verified device manifests. The SDK verifies that
the manifest root key matches the contact identity commitment, verifies branch
proofs, verifies device prekey material, and fails closed on mismatch. The
safety-number input is symmetric when both sides map the same published
manifest representation into device safety material.

### Federation Trust Pinning

Federation admission requires a pinned or invited peer node key, verified
handshake signature, replay protection, protocol-version overlap, transport
overlap, and capability negotiation. Mesh service traffic uses mTLS with service
identity checks; federation node certificates can be pinned through peer route
state.

### Device-Signed Grants and Risk Floors

Local tool grants are bound to device signatures and scoped capabilities. The
SDK rejects grants whose scope, registry hash, manifest hash, expiry, or risk
floor does not match the requested operation. High-risk or unknown capabilities
cannot be silently downgraded to low-risk automation.

### Dual-Mode Confirmation

Ramflux supports attended CLI and headless operation modes. Attended mode can
surface approval events for human confirmation. Headless operation relies on
standing approvals and risk floors, and the same grant validation rules apply in
both modes.

### Fail-Closed Cryptography

Cryptographic verification errors are treated as hard failures. Invalid
identity commitments, invalid branch proofs, invalid prekey bundles, invalid
request signatures, and invalid federation handshakes must not fall back to
synthetic single-device material or unauthenticated routing.

### Replay Protection

Signed requests include request identifiers, nonces, creation times, and expiry
windows. Gateway sessions track replay windows and inbox cursors. Federation
handshakes are keyed by source node and handshake identifier. Router delivery
state rejects duplicate or expired envelopes according to the replay policy.

### Durable Delivery and Cursor Semantics

The router persists offline inbox entries, acknowledgements, negative
acknowledgements, and delivery cursors. Within the local node's delivery model,
acknowledgement state is idempotent and prevents duplicate advancement of a
cursor. Exactly-once effects are defined at the persisted inbox/cursor boundary,
not as a claim about arbitrary application handlers.

## Non-Guarantees and Known Limits

### Metadata and Traffic Analysis

Ramflux does not hide all metadata. Nodes and network observers may learn timing,
message sizes, delivery identifiers, node identifiers, endpoint addresses,
federation relationships, coarse delivery classes, and traffic volume. Padding,
mixing, cover traffic, and global anonymity are outside the current core.

### Node Operator Trust

Node operators control availability, retention policy configuration, deployment
security, logs, and network exposure. A malicious operator can deny service,
delay delivery, delete queued records, retain metadata, or misconfigure TLS and
storage. End-to-end encryption limits plaintext exposure but does not make a
node operator harmless.

### Device-Aware Safety-Number Boundary

The current device-aware safety-number implementation verifies the device set
that is published through the gateway manifest path. A known DA-1 boundary is
that adding a new device does not automatically force the remote party's already
displayed safety number to change until clients fetch and compare the updated
published manifest and surface the resulting verification state. Clients must
treat device-set changes as verification-stale events and show them to users.

### Compromised Endpoint

If an endpoint is physically controlled or fully compromised while unlocked, the
attacker can read plaintext available on that device, use local credentials,
approve grants, and sign device requests. Ramflux can support revocation and
rotation after detection, but it cannot protect plaintext already exposed on a
compromised device.

### Malicious or Vulnerable Client UI

The core can produce verification errors, approval events, and audit records,
but a client UI must display them accurately. A client that hides stale safety
state, mislabels tool risk, or suppresses approval prompts can weaken the user
security outcome.

### Cross-Node Availability

Federation trust pinning authenticates peer nodes and negotiated capabilities;
it does not guarantee that a peer stores, forwards, or wakes messages reliably.
Federated peers can still deny service or delay delivery.

### Legal and Operational Policy

This threat model does not define legal retention obligations, abuse response,
moderation policy, or jurisdiction-specific deployment requirements. Operators
must evaluate those responsibilities separately.

## Disclosure

Report vulnerabilities through the private channels in `SECURITY.md`. Do not
open public issues for exploitable security bugs.
