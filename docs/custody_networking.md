# Native v3 networking

Native creation is enabled by default with no creation opt-in. The ordinary
[account creation ceremony](local_bus_account_creation.md) returns a typed
unlocked account after its data actor opens, with networking either `live` or
`networking_pending`. Its passphrase unlocks data independently of primary
custody. A selected trusted node can be configured later for a pending account.

Ordinary native sessions use `GatewaySessionEngine` with
`GatewaySessionConfig::with_native_custody` and `with_account_identity`. The
configuration binds the account directory/id, certified device, gateway address,
TLS CA/server name and independently approved receiving-node id/public key.
The same automatic QUIC/TCP selection, socket and normal session engine serve
ordinary features after native proof; a discovery response cannot choose the
trust anchors, and there is no legacy-proof fallback.

Native authentication publishes the locally signed authority, registers the real
branch's signed prekeys and obtains a fresh authenticated session. A private
one-use gateway handoff binds the normal session to that exact verified head,
device, epoch and remaining monotonic lifetime. Each ordinary operation rechecks
current head/capabilities. Data unlock itself neither loads primary credentials
nor manufactures a legacy identity root. Loading a real branch for networking
also installs its signer for ordinary account events and its private prekeys for
the persistent ordinary X3DH/ratchet stack.

Local `Live` means registration completed; it is not a restored session grant.
Reconnect authenticates a new TLS connection with new one-use challenges.
Sessions expire within five minutes; expiry or a changed head requires reconnect.
`CustodyConnection` supplies the shared native authentication transport inside
that ordinary session engine. The temporary custody-only `send_dm`, `receive_dm`
and `ack_dm` API, its experimental opt-in and its separate receipt store are
removed. Normal clients send and receive through ordinary message methods.

Those messages use the persistent ordinary X3DH/double-ratchet stack and its
receiver replay protections. See the precise [ordinary DM security
boundary](root_key_custody.md#ordinary-dm-security-boundary), including the remaining
bootstrap forward-secrecy limitation on this implementation baseline. Native
registration and channel binding do not independently provide DM forward secrecy.

## Receiving-node configuration

The optional profile follows [the custody wire specification](root_key_custody_wire.md).
Provision its node-root signature separately from the gateway's proxy credential.

| Setting | Service | Meaning |
| --- | --- | --- |
| `RAMFLUX_CUSTODY_NODE_RECORD_FILE` | router | Bounded signed node identity JSON; absent/empty leaves native custody disabled. |
| `RAMFLUX_CUSTODY_NODE_PUBLIC_KEY` | router, gateway | Independently configured receiving-node identity key; a proxy TLS certificate cannot supply it. On the gateway, absent/empty disables custody and skips its pool/nofile initialization. |
| `RAMFLUX_GATEWAY_ID` | gateway | Exact proxy instance identity in the signed node record; defaults to `ramflux-gateway`. Every instance needs its own authorized proxy key. |
| `RAMFLUX_CUSTODY_PROXY_SIGNING_SEED` | gateway | Dedicated software Ed25519 proxy seed, canonical base64url; required for receipt mode. Keep it separate from node-root and relay receipt keys. |
| `RAMFLUX_CUSTODY_TCP_ADDR` | router | Optional direct client TLS listener, disabled when unset; requires separate public TLS credentials and a signed certificate pin. |
| `RAMFLUX_CUSTODY_TLS_CERT_FILE`, `RAMFLUX_CUSTODY_TLS_KEY_FILE` | router | Public client-facing certificate chain/key, separate from mesh TLS. The signed node record pins the leaf DER SHA-256 hash as canonical base64url in `client_tls_certificate_sha256`. Shared mesh signing keys are refused, including differently encoded certificates using the same key. |
| `RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS` | gateway, router | Whole custody exchange deadline (from CustodyOpen on shared gateway listeners; from accept on the dedicated router listener), default 10000 ms; accepted range 1–10000; empty selects the default. Frame activity never renews it. |
| `RAMFLUX_CUSTODY_HANDSHAKE_POOL` | gateway, router | Per-listener unauthenticated ceiling H, default 256; accepted range 1–65536, empty selects default. |
| `RAMFLUX_CUSTODY_AUTHENTICATED_POOL` | gateway, router | Per-listener authenticated ceiling A, default 1024; accepted range 1–65536, empty selects default. |
| `RAMFLUX_CUSTODY_AUTHENTICATED_SESSIONS_PER_PRINCIPAL` | gateway, router | Authenticated sessions per account anchor per listener, default 4; accepted range 1–64. |
| `RAMFLUX_CUSTODY_ALLOW_NO_CHANNEL_BINDING` | participating services | Explicit operator opt-in (`1`); the signed node record must independently advertise this mode. |
| `RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_MINUTE` | router | Global new-principal burst budget, default 16; capped by the daily value. |
| `RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_DAY` | router | Global daily new-principal budget, default 256; accepted runtime value is clamped to 32–65536. |

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
may hold more than 64 outstanding challenges. Issuance windows permit 32/IP and
at most eight per IPv4 /24, IPv6 /64 and
IPv6 /48 per minute, plus 1024 per node. These limits include IPv4-mapped sources.
The node-wide issuance window reserves two challenges when admitting a prefix;
its second challenge can use that reservation even if other prefixes fill the
remaining window. A new prefix is refused when no reservation fits. Neither
reserved issuance nor outstanding challenges are retired by other sources.
The pending challenge ceiling is 4096; saturation returns a retryable `Busy`.
Only expiry, consumption and holder disconnect release outstanding challenges.
Expired source windows are pruned; source tracking is bounded at 8192 entries.
Consumed nonce/proof tables separately retain up to 12288 entries, above the
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
Each listener has separate handshake (H) and authenticated (A) pools, defaulting
to 256 and 1024. Neither ceiling is ever exceeded. There is no arrival-driven
revocation. On the dedicated direct router listener, full H closes a new TCP
socket before
TLS work. Shared gateway TCP and QUIC listeners acquire H only after TLS and a
first `CustodyOpen` frame; full H returns typed retryable `Busy` on that custody
connection/stream. Ordinary connections and streams never touch custody pools
and keep the existing generic ingress behavior. Full A replies `Busy` to Prove
and closes the
connection, releasing H. The first successful Prove (publication, registration or
session opening) moves H to A under one limiter lock; the authenticated count,
per-principal limit and source-share limit are checked
in that same critical section. Direct session creation also checks its holder
under that lock, so a closed or revoked holder cannot recreate a grant.

The handshake pool permits at most four holders per IP, IPv4 /24, IPv6 /64 and
IPv6 /48, including IPv4-mapped addresses. Across both pools, the listener-wide
outer limits remain four per IP, eight per IPv4 /24 or IPv6 /64 and sixteen per
IPv6 /48. A QUIC connection permits at most four custody streams across both
pools. The entire
custody exchange, starting with direct-listener TCP accept (including TLS) or
the first `CustodyOpen` frame on a shared gateway listener, has a single deadline
of at most ten seconds. TLS and frame activity never renew it.
Authenticated holders are limited to sixteen per IPv4 /24 or IPv6 /48, and four
per principal by default (configurable from 1 to 64). IPv4-mapped IPv6 uses the
IPv4 share. Disconnect, the handshake deadline, explicit revoke/fence and the
fifteen-minute transport lifetime cancel the holder; a new arrival cannot.
Gateway disconnect notices and router proof handling serialize with session
creation. Cleanup removes unconsumed challenges and sessions under the same
service admission lock used by proof execution, so queued proofs cannot recreate
a disconnected grant.

At startup each custody-enabled binary raises its soft `RLIMIT_NOFILE` to its
hard limit and
requires total H + total A + 512 descriptors, summed over its listeners. An
insufficient limit refuses startup with all three values. Gateway TCP and QUIC
have independent pools; the optional direct router listener has one pair.
A gateway without a receiving-node key does not parse custody pool settings or
apply custody nofile requirements. Shared gateway TLS and first-frame waits use
a separate ten-second generic timeout, without allocating custody permits. Compose
sets both soft and hard `nofile` limits to 65536. TCP accept errors are logged once
per kind and retried with a 50 ms to one second backoff; QUIC handshake failures
are retried as well.

### Residual cost

Filling the handshake pool requires at least ceil(H/4) distinct IPv4 /24s or IPv6
/48s, reconnecting at least once per ten-second deadline. Blocking challenges for
fresh prefixes requires at least 128 distinct source shares (1024 / 8) per minute;
each IPv4 /24 or IPv6 /48 can spend at most eight challenges, and IPv6 /64 has
the same cap. Two-slot reservations for new shares also count toward the
node-wide bound; reservations are never retired by other sources. These custody
bounds do not gate ordinary gateway ingress. Filling the authenticated
pool requires at least ceil(A/16) source shares and, with the default four sessions
per principal, ceil(A/4) registered accounts. The listener-wide source caps may
raise those minimums. Attacks beyond these bounds are network-layer DoS, outside
this profile's admission guarantees.

Compose interpolation uses `RF_COMPOSE_CUSTODY_*` inputs; the container's runtime
settings retain their `RAMFLUX_CUSTODY_*` names. The mapping in
`deploy/compose-inputs.json` is applied by the fixture generator and integration
harness.

New principal admission is durable and atomic with its per-account publication.
The defaults are sixteen per node per minute and 256 per node per day. Set them
with `RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_MINUTE` and
`RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_DAY`; malformed, zero or out-of-range settings
refuse node startup instead of silently selecting another limit. Each /24,
/64 and /48 receives at most one thirty-second of the configured global daily
budget (rounded up), additionally capped by the prior eight-per-small-prefix and
thirty-two-per-/48 daily ceilings. Thus eight /48s cannot consume the node-wide
budget reserved for fresh prefixes. The process-local challenge window reserves a
prefix's first two issuance slots without cancelling another prefix's outstanding
work. A node supports at most
65,536 custody accounts. Clock rollback never resets a budget: correct the clock
and retry after the retained window. Existing-account updates do not charge a
new-principal budget; an identical re-publish performs no durable write.
Publication updates only the affected account's transactional redb row, capped at
16 MiB including its retained authority/pins. Custody records, pins and custody-only
principal reservations are omitted from the legacy whole-registry snapshot and
rebuilt from those rows; legacy candidate clones share the in-memory custody map
without deep-copying it. Prefix receipts retain at most the current/previous
day; the global cumulative count remains durable. Principal names remain bound
to their first authenticated root even after compromise or abandonment; a new
anchor must choose a different name. Publication is not an administrative release.

## Ordinary native contact consent

Contact requests, acceptance and decline use the exact
`ramflux.identity.contact_request.v2` envelope from the
[wire specification](root_key_custody_wire.md#contact-consent-v2). The certified
self-signing key approves an intent independently of the current branch's
transport signature. Data unlock or branch possession alone cannot create that
approval. An unavailable primary credential leaves a delivery intent pending;
there is no legacy signer fallback. The sender persists the signed public intent
for retries and rechecks its endpoints, certificate range, current branch keys,
capability and lifetime before reuse.

An encrypted request uses the ordinary X3DH/ratchet control carrier. For a
stranger, a speculative decrypt runs inside a managed rollback transaction;
no speculative directory facts or ratchet counters survive. The receiver then
resolves any delayed authority outside the writer transaction. Endpoint, lifetime,
transport branch and primary-signature checks precede that lookup. The final
receive transaction decrypts again and verifies the exact historical record plus
current pinned authority before projecting consent and consuming pair counters.
A retransmitted committed envelope uses its durable receipt. Tampered requests
cannot retain stranger metadata or advance receive replay state.

`GET /mvp1/custody-history/<account_anchor>/<record_hash>` returns exactly the
requested public publication or null. It never substitutes the current record
for a historical hash. Current fences still apply; historical authority grants
only the delayed-consent exception, never a current session, enrollment or device
capability. A newer revision with the same certified range and unchanged sending
branch can preserve consent. A changed range/certificate or revoked branch
invalidates it.

Directories retain superseded records for at least 605700 seconds after
supersession. Incremental transactional history is bounded to 4096 records and
64 MiB per account, and 65536 records and 1 GiB per node. Admission at capacity
returns a typed capacity failure atomically with the unchanged previous head;
unexpired authoritative records are never evicted. The ordered expiry index
prunes at most 256 expired records per changed publication. Records, accounting
and expiry survive restart; process loss cannot release an unexpired retention
obligation. Identical publication remains a no-op. Current authority pins and
fences do not expire with history.

The SDK's separate public payload cache is evictable: at most 256 records,
32 MiB total and eight records per actor. Cache eviction never removes durable
mode/head/denial pins; a miss requires an exact-hash fetch or a typed unavailable
result. Historical cache misses have per-actor and account-wide lookup budgets.
Unaccepted requester retirement removes full directory payloads and device-pair
state while preserving native rollback and mode pins. Accepted relationships
retain the normal verified directory authority.

## Current-head freshness in the ordinary SDK

Positive cached device authorization requires a verified current head fetched at
most 300 seconds ago, in addition to current pins, branch scope, keys and lease.
The freshness clock is monotonic and belongs to the live client process. It binds
the account anchor and exact head hash; accepting a different head invalidates an
older observation. The cache holds at most 512 roots and evicts the oldest
observation when full. Eviction, restart and expiry require another successful
current-directory fetch; refresh failure supplies no stale fallback.

Public JSON observation, own-device history and backup snapshots retain signed
public evidence and rollback/denial floors without refreshing this clock. A
restored timestamp cannot manufacture a new network observation. An ordinary
native account session refreshes its own directory when the current-head clock
is missing or expired. Read-only account data remains separate from this
permission to use a device for a new operation.

The ordinary SDK separately checks certified `call`, `group` and `sync` branch
scopes before new call controls/media access, group creation/signing/sender-key
publication and network group delivery, and own-device copies/history transfer.
A live `message` scope cannot substitute for these permissions. These checks do
not gate decryption of data already stored in local history.

## Durable local own authority

A completely verified own publication advances the independent public authority
file before updating actor caches. The update preserves local credential
references, the local device selector, creation mode and registration state.
Checkpoint id lists and attached custodian publication evidence are retained;
reconnects publish that complete evidence. Unchanged publications are no-ops,
rollback is refused, and equivocation fences remain durable across restart.
The local file has a 32 MiB read/write bound covering its record, retained pins
and public evidence; wire record/frame bounds remain unchanged.

Ordinary reconnect preparation first reads the public directory over the
configured TLS/QUIC peer, before accessing branch credentials or making an
account proof. Missing authority is allowed only for an account still awaiting
initial registration. A missing previously live head, invalid signature or
legacy-only result fails closed. Actor permissions refuse a cache behind the
independent local floor, including when a reconnect advanced the file first.

An authority fence blocks credentials and networking. It still permits opening
existing data with the correct data passphrase, without loading a primary key.
List/status distinguish `authority_blocked` and `networking_pending` from the
ordinary locked/unlocked data state. No legacy proof fallback is available.

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

### Temporary legacy integration fixtures

The `itest-legacy-accounts` SDK/CLI feature is disabled by default. It is compiled
only in explicitly marked integration builds (`RAMFLUX_ITEST_BUILD=1`) and is
rejected by guarded production builds even with that marker. Production feature
provenance checks forbid it alongside the memory-vault fixture.

An integration daemon must also opt in with `--itest-legacy-accounts` (or
`LocalBusConfig::with_itest_legacy_accounts`). Unsupported builds refuse this
startup setting before binding the local bus. The only seed-taking creation
method is `account.itest_legacy.create`; the corresponding hidden CLI command is
`rf account itest-legacy-create`. The ordinary `account.create` ceremony and
`rf account create --display-name` stay native regardless of fixture opt-in.
The fixture path refuses an existing native account and cannot downgrade its
latched authority. The integration harness selects it explicitly for scenarios
awaiting native migration; native account scenarios keep the normal ceremony.
