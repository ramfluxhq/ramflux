# Protocol Versioning

This document defines the public wire-version contract for the Ramflux core
workspace. It covers the client gateway session, node federation, and local SDK
bus surfaces.

The current public baseline is `0.1.0`. All surfaces below are version `v1`
unless explicitly stated otherwise.

## Versioned Surfaces

| Surface | Current version | Version field | Transport | Primary owner |
|---------|-----------------|---------------|-----------|---------------|
| Gateway session | `ramflux.gateway_session.v1` | `GatewayOpenFrame.protocol_version` | QUIC or TCP/TLS session stream | gateway + SDK |
| Federation | `v1` | `FederationHandshake.protocol_versions` and discovery records | service mesh HTTP/TLS and federation endpoints | federation service |
| Local bus | `ramflux.local_bus.v1` | `LocalBusFrame.bus_protocol` | length-prefixed canonical JSON over local socket | SDK daemon + CLI |
| Signed protocol objects | schema-specific `*.v1` | `schema`, `version`, `domain` | embedded in gateway, federation, bus, and storage records | protocol crate |

## Server API Version

`server_api_version` is the SemVer version of a service's externally supported
API surface. It is release metadata, not a replacement for per-surface wire
negotiation.

Rules:

- Services that expose a JSON status, health, or discovery document should
  report `server_api_version` using SemVer, for example `0.1.0`.
- Clients must not infer gateway, federation, or bus compatibility from
  `server_api_version` alone.
- Clients must first evaluate the relevant wire-version field:
  `protocol_version`, `protocol_versions`, or `bus_protocol`.
- If `server_api_version` is absent, clients use the surface-specific version
  field and local compatibility policy.

## Gateway Session Contract

The gateway session starts with `GatewayClientFrame::Open` and
`GatewayClientFrame::Auth`.

Current client-to-server frame types:

- `open`
- `auth`
- `submit`
- `identity_register`
- `prekey_publish`
- `prekey_fetch`
- `ack`
- `cursor`
- `resume`
- `nack`
- `heartbeat`
- `close`

Current server-to-client frame types:

- `session_established`
- `deliver`
- `identity_registered`
- `prekey_published`
- `prekey`
- `ack`
- `cursor`
- `resume`
- `nack`
- `heartbeat`
- `drain`
- `in_band_wake`
- `close`

Compatibility rules:

- `GatewayOpenFrame.protocol_version` must equal
  `ramflux.gateway_session.v1` for the current release.
- A server must reject an unsupported gateway protocol version before accepting
  authentication.
- A client must treat an unknown `frame_type` as a protocol error for the
  current session.
- Adding a new optional field to a gateway frame is a compatible change only
  when old peers can ignore it without changing signed bytes or security
  decisions.
- Adding a new `frame_type`, changing a required field, changing request
  signature input, or changing delivery cursor semantics requires a new gateway
  session version.

## Federation Contract

Federation discovery records and handshakes advertise supported protocol
versions as strings. The current protocol list is `["v1"]`.

The federation handshake includes:

- `schema`
- `version`
- `domain`
- signed fields
- `handshake_id`
- `source_node_id`
- `target_node_id`
- `source_capabilities`
- `protocol_versions`
- `transport_backends`
- `trust_state_hash`
- `nonce`
- `created_at`

Admission requires:

- a route and invitation or pin state that binds the source node key;
- a valid handshake signature from the pinned node key;
- no replay for the source node and handshake identifier;
- source node and route identity match;
- overlap between remote and local `protocol_versions`;
- overlap between remote and local `transport_backends`;
- source capabilities within the invitation or pin policy;
- non-empty negotiated capabilities including `opaque_delivery`;
- no downgrade of previously negotiated capabilities.

Compatibility rules:

- A peer must reject admission when there is no protocol-version overlap.
- New federation protocol versions are additive in `protocol_versions`; a peer
  can advertise multiple versions during a migration window.
- Removing `v1` support requires a major compatibility decision and a documented
  minimum-supported release.
- Federation structs that use signed canonical JSON must not accept unknown
  signed fields unless those fields are carried through an explicit extension
  field and are covered by the canonical signature policy.

## Local Bus Contract

Local bus frames are length-prefixed canonical JSON. Each frame carries:

- `bus_protocol`
- `frame_id`
- `kind`
- `request_id`
- `account_id`
- `sdk_api`
- `method`
- `body`
- `trace_id`
- optional `ok`
- optional `error`

Current `bus_protocol` is `ramflux.local_bus.v1`.

Current request methods include:

- account: `account.create`, `account.list`, `account.switch`,
  `account.status`, `account.lock`, `account.unlock`,
  `account.backup.export`, `account.backup.import`,
  `account.passphrase.rotate`
- device: `device.list`, `device.activate`
- message and conversation: `message.submit`, `message.receive`,
  `message.ack`, `message.delete`, `message.receipt.delivered`,
  `message.receipt.read`, `message.list`, `message.read`,
  `conversation.disappearing.set`, `conversation.disappearing.expire`,
  `conversation.mute`
- contacts: `contact.add`, `contact.accept`, `contact.request`,
  `contact.list`, `contact.safety_number`, `contact.verify`,
  `contact.verification.status`, `contact.remove`, `contact.block`,
  `contact.unblock`, `contact.rejected`
- groups: `group.create`, `group.member.add`, `group.member.remove`,
  `group.members`, `group.list`, `group.send`, `group.read`,
  `group.receive`, `group.sender_key.export`, `group.sender_key.import`
- objects: `object.put`, `object.get`, `object.list`, `object.share`,
  `object.import`, `object.delete`
- calls and bots: `call.invite`, `call.answer`, `call.hangup`,
  `bot.trust.add`, `bot.install`, `bot.list`, `bot.revoke`
- grants and MCP: `grant.list`, `grant.request`, `grant.revoke`,
  `grant.create_standing_approval`, `grant.revoke_standing_approval`,
  `grant.list_standing_approvals`, `grant.approve`, `grant.deny`,
  `mcp.server.add`, `mcp.server.list`, `mcp.server.refresh`,
  `mcp.tool.list`, `mcp.tool.started`, `mcp.approval.list`,
  `mcp.approval.granted`, `mcp.approval.denied`, `mcp.audit.list`
- daemon: `daemon.status`, `daemon.stop`

Compatibility rules:

- A daemon must reject an unsupported `bus_protocol`.
- A daemon must reject an unknown `method` with a structured local-bus error.
- Adding a new method is compatible for clients that do not call it.
- Adding an optional body field is compatible when old peers can ignore it.
- Removing a method, changing a required request field, changing response
  shape, or changing error semantics requires a local-bus version bump.

## Unknown Versions and Fields

Unknown versions:

- Gateway: reject unsupported `protocol_version`.
- Federation: reject if there is no version overlap.
- Local bus: reject unsupported `bus_protocol`.
- Signed objects: reject unsupported `schema`, `domain`, or major `version`
  unless a specific compatibility rule exists for that object.

Unknown fields:

- Unsigned request and response objects may add optional fields when old peers
  can safely ignore them.
- Signed canonical objects must treat unknown signed material as security
  relevant. New signed material belongs in a new schema/version or an explicit
  extension field with defined canonicalization.
- Unknown enum variants and frame types are not forward-compatible on the same
  surface version.

## Minimum Supported Floor

The current minimum-supported floor is:

- Gateway session: `ramflux.gateway_session.v1`
- Federation: `v1`
- Local bus: `ramflux.local_bus.v1`
- Signed protocol object schema: object-specific `*.v1`

A release may raise the floor only when:

- the old version is documented as deprecated;
- clients can detect the incompatibility before sending sensitive material;
- a migration path exists for persisted local state or node state;
- release notes identify the affected surfaces.

## Bump Rules

Patch release:

- documentation clarification;
- validation tightening that rejects data already invalid under the documented
  contract;
- internal refactor with no wire change;
- adding tests or fixtures.

Minor release:

- adding an optional field to an unsigned request or response;
- adding a new local-bus method;
- adding a new federation capability without removing existing capabilities;
- adding a new event type that old subscribers can ignore.

Major wire-version bump:

- changing canonical signed bytes;
- changing required fields;
- renaming or removing frame types or methods;
- changing identity, device, safety-number, grant, replay, or cursor semantics;
- changing federation admission requirements in a way that old peers cannot
  negotiate;
- changing error behavior from fail-closed to permissive or fallback behavior.

## Persistence and Replay Compatibility

Persisted cursors, replay windows, grants, account manifests, federation pins,
and delivery queues are part of the compatibility surface when a release can
read or write them across upgrades. A release that changes these records must
include a migration plan, tests, and rollback expectations.

Replay-protection fields such as request identifiers, nonces, timestamps,
expiry windows, handshake identifiers, and cursor sequence numbers are security
fields. They must not be silently ignored for compatibility.
