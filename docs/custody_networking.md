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
receiving node id as the proof audience. A discovery response cannot choose those trust anchors.
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

`send_dm`, `receive_dm`, and `ack_dm` are a temporary experimental path and
require the separate explicit `allow_experimental_native_dm: true` setting.
Leave it false for normal clients. This bootstrap **does not provide forward
secrecy**: the recipient prekey is derived from its long-lived branch agreement
key, has no one-time prekey, and each message starts a fresh single-message
ratchet. Compromise of that branch agreement key can decrypt previously captured
messages. The v3-only ordinary-client integration retires this path and uses the
ordinary persistent E2EE ratchet and prekey stack before default creation changes.

This temporary path addresses devices registered with the same router and polls
its durable opaque inbox. Current root-qualified authority, branch signatures and
recipient-side AEAD are verified; it does not install a legacy gateway push
session or silently use a cross-node directory. Reception enforces the signed
creation time and TTL (at most one day), and rejects future or expired messages.
After the caller accepts a decrypted message, `ack_dm` fsyncs its receiver-scoped
receipt before sending the real inbox ACK. Up to 4096 receipts are retained
through their signed expiry, across reconnect/restart; full capacity refuses new
ACKs rather than evicting live replay evidence. An uncertain remote ACK can be
retried. Unacknowledged messages remain redeliverable; this receipt window is not
an application transaction or a substitute for the ordinary ratchet replay window.
Plaintext is zeroized on drop. Current branch leases and revocations apply;
there is no historical-receipt exception for an expired branch.

## Receiving-node configuration

The optional profile follows [the custody wire specification](root_key_custody_wire.md).
Provision its node-root signature separately from the gateway's proxy credential.

| Setting | Service | Meaning |
| --- | --- | --- |
| `RAMFLUX_CUSTODY_NODE_RECORD_FILE` | router | Bounded signed node identity JSON; absent/empty leaves native custody disabled. |
| `RAMFLUX_CUSTODY_NODE_PUBLIC_KEY` | router, gateway | Independently configured receiving-node identity key; a proxy TLS certificate cannot supply it. |
| `RAMFLUX_GATEWAY_ID` | gateway | Exact proxy instance identity in the signed node record; defaults to `ramflux-gateway`. Every instance needs its own authorized proxy key. |
| `RAMFLUX_CUSTODY_PROXY_SIGNING_SEED` | gateway | Dedicated software Ed25519 proxy seed, canonical base64url; required for receipt mode. Keep it separate from node-root and relay receipt keys. |
| `RAMFLUX_CUSTODY_TCP_ADDR` | router | Optional direct client TLS listener, disabled when unset; requires separate public TLS credentials and a signed certificate pin. |
| `RAMFLUX_CUSTODY_TLS_CERT_FILE`, `RAMFLUX_CUSTODY_TLS_KEY_FILE` | router | Public client-facing certificate chain/key, separate from mesh TLS. The signed node record pins the leaf DER SHA-256 hash as canonical base64url in `client_tls_certificate_sha256`. Shared mesh signing keys are refused, including differently encoded certificates using the same key. |
| `RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS` | gateway, router | Whole unauthenticated exchange deadline, default 10000 ms; accepted range 100–30000. Frame activity never renews it. |
| `RAMFLUX_CUSTODY_ALLOW_NO_CHANNEL_BINDING` | participating services | Explicit operator opt-in (`1`); the signed node record must independently advertise this mode. |

This gateway signer is explicitly software custody. No hardware/nonexportable-key
claim is made. The node profile must authorize its exact gateway id, key id,
public key and router audience. The proxy observes the actual client TLS exporter;
JSON/header assertions about a different transport hop are not evidence. The
router checks the signed receipt against independently pinned node metadata and
current cumulative proxy revocations. Compose overlays can change gateway identities:
the cross-gateway integration topology uses `gw-a` and `gw-b`, so its signed
fixture authorizes both with distinct keys and supplies each instance its own
credential and receiving-node trust anchor. Authorizing only the base instance
name does not authorize these instances. Direct mode obtains its exporter at the
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

Challenge, consumed-proof and session maps are process-local. A challenge has
a 300-second monotonic deadline; consumed nonce/proof markers remain for 600
seconds. A connection may have four outstanding challenges. Sources normalize
IPv4-mapped addresses and share IPv4 /24, IPv6 /64 and IPv6 /48 budgets; no prefix
may hold more than 64 outstanding challenges. Issuance windows permit 32/IP,
128/small-prefix and 256/IPv6-/48 challenges per minute, plus 1024 per node.
Under global pending-challenge pressure (4096 entries), the oldest unconsumed challenge
from the heaviest prefix is evicted. Consumed markers are never evicted to admit
unauthenticated work. Source tracking uses an 8192-entry idle LRU; table occupancy
does not itself deny another source. Consumed nonce/proof tables separately retain up to 12288 entries, above the
maximum eleven issuance windows across their 600-second horizon. Sessions cap
admitted work at 4096. No live replay evidence is discarded; a holder
replaces its previous session when it authenticates again.
Sessions permit 256 request nonces and require branch signatures, the holding
connection, the exact current unfenced head and live capabilities.

Disconnect releases unconsumed challenges and sessions while preserving consumed
markers. Gateway disconnect notification is best effort over authenticated mesh;
missed notifications remain unusable from another holder and expire monotonically.
Router restart invalidates every grant. No grants are serialized, backed up or
restored. Durable registration and `Live` survive, but reconnect authenticates again.
Listener admission permits four live connections/streams per IP, eight per /24 or
/64, sixteen per /48, and four streams per QUIC connection. Gateway/direct global
caps remain 32/64, with fifteen-minute authenticated lifetimes. Source open-rate
windows and idle LRU accounting apply before a slot is granted. The direct public
TLS handshake has a five-second deadline; subsequent unauthenticated reads,
processing and writes share the short whole-exchange deadline. Slow reading does
not retain a pre-auth slot indefinitely.

New principal admission is durable and atomic with its per-account publication:
eight per IPv4 /24 or IPv6 /64 per UTC day, thirty-two per IPv6 /48 per day,
sixteen per node per minute and 256 per node per day. A node supports at most
65,536 custody accounts. Clock rollback never resets a budget: correct the clock
and retry after the retained window. Existing-account updates do not charge a
new-principal budget; an identical re-publish performs no durable write.
Publication updates only the affected account's transactional redb row, capped at
16 MiB including its retained authority/pins, rather than cloning and rewriting
the whole identity registry. Prefix receipts retain at most the current/previous
day; the global cumulative count remains durable. Principal names remain bound
to their first authenticated root even after compromise or abandonment; a new
anchor must choose a different name. Publication is not an administrative release.

## Integration fixture and production boundary

Production Linux primary-vault support is separate work; unsupported production
providers continue to return `CustodyVaultUnavailable`. The SDK feature
`itest-memory-vault` is disabled by default and exposes an in-memory fixture only
for integration tests. It permits provider injection into the same local-bus
creation flow, still requiring the creation option and the complete ceremony.
It is not a production vault or a file fallback, and losing the fixture process
loses its credentials.

Every non-test SDK build enabling `itest-memory-vault` fails to compile unless
explicitly marked `RAMFLUX_ITEST_BUILD=1`; the itest repository supplies that marker
in its own Cargo configuration. Production builds additionally set
`RAMFLUX_PRODUCTION_BUILD=1` and reject the feature even with the fixture marker.
`scripts/check-production-features.py` checks the resolved default feature graph
and the guarded production build recipes in CI. All-feature lint/test fixture builds
set `RAMFLUX_ITEST_BUILD=1` explicitly; default consumer builds need no marker.
Integration builds may explicitly
enable the fixture; production artifacts must not.
