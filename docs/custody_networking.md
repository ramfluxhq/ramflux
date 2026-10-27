# Experimental born-v3 networking

Born-v3 creation remains explicitly disabled by default. Creation uses the existing
local-bus recovery-phrase ceremony: enable `LocalBusConfig.enable_born_v3_creation`,
show the phrase once, hide it, and confirm the three requested words. Confirmation
persists local authority and returns `NetworkingPending`; it does not establish a
network session. Existing account APIs retain their identity profile.

The explicit Rust SDK entry point is
`ramflux_sdk::custody::CustodyConnection::connect`. Supply a
`CustodyNetworkConfig` and an `Arc<dyn PrimaryVault>`. The native SDK currently
uses TCP with TLS 1.3. The gateway also accepts the same native framing over QUIC.
The config identifies the account directory/id, device, gateway address, TLS CA
and server name, and the independently approved receiving-node id/public key and
router service audience. A discovery response cannot choose those trust anchors.
Choose `HomeRelayReceipt` for a gateway, or `DirectExporter` for an explicitly
configured client-facing router TLS listener. There is no automatic mode downgrade
or legacy-proof fallback.

The connection publishes the locally signed record, registers the certified
branch's prekey bundle, and obtains a fresh authenticated session. Only after all
three operations succeed does local account state become `Live`. This state means
registration completed. It grants no restored session: reconnect always performs
a new TLS handshake and new one-use challenges. Sessions expire within five
minutes; expiry or a changed authority head requires reconnecting. Selecting a
born-v3 account on `RamfluxClient` does not authorize its legacy session methods.
Use the explicit custody connection for the native operations.

`send_dm`, `receive_dm`, and `ack_dm` use current root-qualified peer authority,
existing X3DH and the committing double ratchet, and the router's durable opaque
inbox/ACK machinery. This initial native path polls the inbox; it does not install
a legacy gateway push session. Each sent envelope has a fresh ephemeral bootstrap
and a single-message ratchet, so reconnect cannot restore and reuse a sending
message key. Plaintext returned by `receive_dm` is zeroized on drop. A caller ACKs
only after accepting the decrypted delivery. The initial native lookup/send path
addresses devices registered with the same router; unavailable targets fail with
a typed refusal. It does not silently use a legacy or cross-node directory path.
Current branch leases and revocations apply to reception; this path does not
implement a historical message-receipt exception for an expired branch.

## Receiving-node configuration

The optional profile follows [the custody wire specification](root_key_custody_wire.md).
Provision its node-root signature separately from the gateway's proxy credential.

| Setting | Service | Meaning |
| --- | --- | --- |
| `RAMFLUX_CUSTODY_NODE_RECORD_FILE` | router | Bounded signed node identity JSON; absent/empty leaves native custody disabled. |
| `RAMFLUX_CUSTODY_NODE_PUBLIC_KEY` | router, gateway | Independently configured receiving-node identity key; a proxy TLS certificate cannot supply it. |
| `RAMFLUX_CUSTODY_PROXY_SIGNING_SEED` | gateway | Dedicated software Ed25519 proxy seed, canonical base64url; required for receipt mode. Keep it separate from node-root and relay receipt keys. |
| `RAMFLUX_CUSTODY_TCP_ADDR` | router | Optional direct client TLS listener, disabled when unset; uses the configured router TLS certificate. |
| `RAMFLUX_CUSTODY_ALLOW_NO_CHANNEL_BINDING` | participating services | Explicit operator opt-in (`1`); the signed node record must independently advertise this mode. |

This gateway signer is explicitly software custody. No hardware/nonexportable-key
claim is made. The node profile must authorize its exact gateway id, key id,
public key and router audience. The proxy observes the actual client TLS exporter;
JSON/header assertions about a different transport hop are not evidence. The
router checks the signed receipt against independently pinned node metadata and
current cumulative proxy revocations. Direct mode obtains its exporter at the
verifying router itself. TLS 1.2 and unavailable exporters fail closed, including
when no binding was explicitly selected; 0-RTT exporters are never used.

Apply a higher signed node profile through a coordinated service restart. Profiles,
key-id/public-key bindings and revocations persist monotonically. Keep old signing
descriptors through the specified rotation overlap; signing deadlines cannot be
extended by that overlap. Historical node records are retained permanently and
can be fetched by hash. The SDK follows at most 64 predecessor records per connect
before returning `UpdateRequired`; it never discards a retained pin to accept an
unreconciled head. Node identity-key replacement still requires the existing
explicit node trust procedure.

`NoChannelBinding` additionally requires the SDK's
`allow_no_channel_binding: true` and explicit mode selection. It is absent from
normal node advertisements and service opt-ins. The active session exposes its
mode, and `security_warning()` supplies the user-visible warning for callers to
display. Services emit a structured warning per unbound connection; the SDK also
fsyncs an unbound-connection security log. Exporter derivation is still mandatory.

## Challenge and session lifecycle

A challenge binds the requested operation hash, device, audience, selected mode,
authenticated proxy and server-generated connection id. Invalid possession cannot
reserve a principal id or consume the challenge. Successful admission consumes
both nonce and proof id atomically before any publication or registration write.
A subsequent persistence error requires a fresh challenge rather than reusing the
consumed one. Principal names are first-come reservations by an authenticated root;
a different root receives `PrincipalIdTaken`.

Challenge, consumed-proof and session maps are process-local and bounded. A
challenge has a 300-second monotonic deadline; its consumed marker/proof id remains
for 600 seconds, covering expiry plus clock skew. There are at most 4096 entries
per global map, 64 retained challenges per authenticated proxy/source IP and 256
request nonces per session. Full maps refuse admission rather than evicting live
entries. Queueing behind another writer cannot extend authentication deadlines.
Sessions require branch signatures over their operation and proof hash, exact
connection ownership, the current unfenced authority head and live capabilities.

Disconnect loses the connection holder; its challenges/session cannot be used
from another connection and expire at their fixed deadline. Router restart loses
all challenge/session grants immediately. Neither map is serialized, backed up,
or restored as live state. Durable records/prekeys and local `Live` status survive;
a caller must authenticate again. Native gateway connection slots are capped at
32 per process, direct router TLS slots at 64, and connection lifetimes at fifteen
minutes regardless of traffic. These limits are independent of existing legacy
listener limits.

## Integration fixture and production boundary

Production Linux primary-vault support is separate work; unsupported production
providers continue to return `CustodyVaultUnavailable`. The SDK feature
`itest-memory-vault` is disabled by default and exposes an in-memory fixture only
for integration tests. It permits provider injection into the same local-bus
creation flow, still requiring the creation option and the complete ceremony.
It is not a production vault or a file fallback, and losing the fixture process
loses its credentials.

Official release and production Docker builds set `RAMFLUX_PRODUCTION_BUILD=1`.
The SDK emits a compile error if that build also enables `itest-memory-vault`.
`scripts/check-production-features.py` checks the resolved default feature graph
and the guarded production build recipes in CI. Integration builds may explicitly
enable the fixture; production artifacts must not.
