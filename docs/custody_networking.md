# Native v3 networking

Native creation is enabled by default with no creation opt-in. The ordinary
[account creation ceremony](local_bus_account_creation.md) returns a typed
unlocked account after its data actor opens, with networking either `live` or
`networking_pending`. Its passphrase unlocks data independently of primary
custody. A selected trusted node can be configured later for a pending account.

The daemon keeps local reads independent of admission and relay transfers. Account,
contact, message, conversation, group, grant, object and device listings use bounded
reader queues opened with the account; a saturated queue returns a retryable refusal.
Networking continues in the background. A command that requires a session returns
`NetworkingPending` within five seconds of admission when no session is live;
ordinary queued requests share that five-second residence bound, and a command
already claimed finishes or fails within 25 seconds of admission, including its
session-call queue wait. Status retains the `networking` string and adds the current
attempt, retry and selected transport in `networking_snapshot`. Cached attachment
GETs remain available offline, including with a saved relay profile; only a GET
that actually needs relay I/O checks for Live after its local lookup. PUT and PUT
finish select their network requirement from request, account and saved upload
options. Object deletion is also conditional: a local tombstone works offline,
while a selected relay requires Live before an operation receipt is reserved.
Lock and daemon shutdown cancel background work before returning.

For a group authority freshness refusal, `details.networking` carries the current
session snapshot when the command waited for refresh (or `null` without a handle).
A residual freshness refusal from dispatch instead carries
`{"phase":"pending","reason":"authority_refresh"}` with a retry hint; this is a
refresh reason, independent of the session's transport phase.

Native group mutations enqueue refreshes for stale own and group-member authority
roots and wait against the same five-second budget measured from command admission.
A successful verified fetch permits the command to continue. Held or unavailable
fetches return `NetworkingPending` with `retry_after_ms` and `details.networking`,
including when the session is Live. Legacy freshness refusals are serialized as
this typed pending outcome. `group.history` reads stored history, name and roster
through the local reader pool without a session, sync or inbound application.
Already-admitted projection skips only the 300-second freshness clock; revocation,
signature/authority and erasure fences remain. New sends, mutations and inbound
admission still require fresh authority. Existing inline peer refresh can admit
on the first receive pass. Otherwise, authority-dependent entries remain in the
durable inbox retry path; verified refresh makes matching retries immediately
eligible and wakes the existing receive courier for ordered, once-only admission.
Failed or old refreshes leave them pending; unrelated retry backoff is preserved.
`group.read` and `group.receive` keep network/admission semantics. Only a decoded,
authenticated route for the requested group can hold those RPCs pending; unknown
routes and unrelated conversations continue background refresh and retry.

Within one account command, `group.read` and `group.receive` reuse a successfully
completed admission sync only when its first freshness check found no stale roots.
If the command waits for head refresh, dispatch syncs again to admit ready entries.
The marker belongs to the command future: cancellation, lifecycle preemption,
failure and completion discard it. Later requests and direct dispatch sync again.
The original admission deadline and fresh inbound authority checks still apply.
At the timeout boundary, receive can have committed only part of a page. Each
applied entry has a durable admission receipt before ACK. Inline receive advances
its cursor after ACK, or after retaining an ACK retry on transport failure.
Head-refresh tracking is an in-memory hold over a durable inbox retry row;
deferred entries retain durable retry state before cursor advancement. An
interrupted exchange can replay through the same admission key without applying
a committed message twice. Cancellation does not roll back messages already
committed, nor mark an unfinished sync complete.

Background refresh runs on connect and demand, with periodic sweeps on a fixed
schedule at 150-second intervals while Live. Wake delivery cannot shift that
schedule. Roots become due after 120 seconds to allow for fetch and wake latency. New
demands take priority between fetches. Each periodic trigger permits at most 32
retries of previously failed demands, then reserves remaining work for sweep roots;
separate cursors preserve continuation. Each account fetches one root at a time, in
batches of at most 32 roots and at most four batches (128 roots) per trigger, with
25 ms between batches. Large rosters may take several triggers to refresh. The
pending-demand cap is 512. Repeated failures back off per root from 5 seconds,
doubling up to 150 seconds.

Fetches run off the account writer; Apply checks generation, session, root and
current membership and retains the conservative fetch-start time. Lock or session
loss cancels the pass. Freshness is process-local: backups preserve data and
authority evidence, never observation clocks. A restored account starts without
fresh observations and refreshes on connect; there is no schema or wire migration.
For recovery, reconnect or restart the daemon to sweep due roots, or use
`device.refresh` with networking available to refresh the named principal (the
account's own principal by default). That explicit command does not redrive inbox retries.
Peer device-set changes are observed eventually through reconnect, the timer,
demand or inbound processing. There is no device-set change push notification.
Desktop adoption is a separate integration.

A native connection attempt has one 120-second outer deadline. Its admission
retry budget is 90 seconds, and each open or frame read retains its 15-second
bound. An ordinary live session call has a 20-second budget. These are separate
from the five-second command admission wait; polling status does not renew an
attempt or a saved retry deadline. A timed-out call that has written to the
uncorrelated session stream retires that session before another call can use it.

The account has two local reader workers with 64 queued requests each; a request
tries both queues before refusing. The ordinary actor mailbox has 64 places and
lifecycle work has four reserved places. The resident session admits 32 waiting
calls and one exchange, with bounded subscriptions. Unsolicited deliveries are
buffered up to 256 entries or 8 MiB. Overflow is left unacknowledged and triggers
receive from the durable cursor. Attachment work has two running transfer slots
and 16 waiting places. Upload bitmap and received-chunk checkpoints are durable
before the next network step; received objects are verified and committed before
relay acknowledgement. Cancellation retains durable resumable progress and
removes the request's spool files.

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

Each gateway mesh certificate identifies one instance with the SPIFFE URI
`spiffe://{node_id}/ramflux-gateway/{gateway_id}`. The instance id grammar is
`[a-z0-9][a-z0-9-]{0,62}`. `RAMFLUX_GATEWAY_ID` selects the local id (default
`ramflux-gateway`) and must match both the certificate URI and the gateway
configuration. For multi-instance issuance, set `RAMFLUX_GATEWAY_INSTANCES` to
a space-separated list; `issue-certs.sh` writes each instance under
`certs/gateway-{id}/`. DNS SANs remain the shared `ramflux-gateway` name used
for TLS server-name verification.

| Setting | Service | Meaning |
| --- | --- | --- |
| `RAMFLUX_CUSTODY_NODE_RECORD_FILE` | router | Bounded signed node identity JSON; absent/empty leaves native custody disabled. |
| `RAMFLUX_CUSTODY_NODE_PUBLIC_KEY` | router, gateway | Independently configured receiving-node identity key; a proxy TLS certificate cannot supply it. On the gateway, absent/empty disables custody and skips its pool/nofile initialization. |
| `RAMFLUX_GATEWAY_ID` | gateway | Exact proxy instance identity in the signed node record and mesh SPIFFE URI; defaults to `ramflux-gateway`. Must match the local gateway certificate. Every instance needs its own authorized proxy key. |
| `RAMFLUX_GATEWAY_INSTANCES` | deploy | Optional space-separated gateway ids to issue as `certs/gateway-{id}/`; each id uses the gateway instance grammar above. |
| `RAMFLUX_CUSTODY_PROXY_SIGNING_SEED` | gateway | Dedicated software Ed25519 proxy seed, canonical base64url; required for receipt mode. Keep it separate from node-root and relay receipt keys. |
| `RAMFLUX_CUSTODY_TCP_ADDR` | router | Optional direct client TLS listener, disabled when unset; requires separate public TLS credentials and a signed certificate pin. |
| `RAMFLUX_CUSTODY_TLS_CERT_FILE`, `RAMFLUX_CUSTODY_TLS_KEY_FILE` | router | Public client-facing certificate chain/key, separate from mesh TLS. The signed node record pins the leaf DER SHA-256 hash as canonical base64url in `client_tls_certificate_sha256`. Shared mesh signing keys are refused, including differently encoded certificates using the same key. |
| `RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS` | gateway, router | Whole custody exchange deadline (from CustodyOpen on shared gateway listeners; from accept on the dedicated router listener), default 10000 ms; accepted range 1–10000; empty selects the default. Frame activity never renews it. |
| `RAMFLUX_CUSTODY_HANDSHAKE_POOL` | gateway, router | Per-listener unauthenticated ceiling H, default 256; accepted range 1–65536, empty selects default. |
| `RAMFLUX_CUSTODY_AUTHENTICATED_POOL` | gateway, router | Per-listener authenticated ceiling A, empty/unset = unlimited (default); a finite value accepts 1–1048576. |
| `RAMFLUX_CUSTODY_AUTHENTICATED_SESSIONS_PER_PRINCIPAL` | gateway, router | Removed. A nonempty old value is ignored with one process-wide warning; authenticated sessions are not capped per principal. |
| `RAMFLUX_CUSTODY_PREAUTH_HANDSHAKES_PER_SOURCE` | gateway, router | Concurrent pre-authentication holders per IP and each prefix tier; default 4, range 1–4096. |
| `RAMFLUX_CUSTODY_CHALLENGES_PER_IP_PER_MINUTE` | router | Challenge issuance per source IP; default 16, range 1–65536. |
| `RAMFLUX_CUSTODY_CHALLENGES_PER_PREFIX_PER_MINUTE` | router | Challenge issuance per IPv4 /24, IPv6 /64 and IPv6 /48; default 32, range 1–65536. |
| `RAMFLUX_CUSTODY_CHALLENGES_PER_NODE_PER_MINUTE` | router | Node challenge issuance/reservation budget; default 1024, range 1–65536. Startup requires IP <= PREFIX <= NODE. |
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
may hold more than 64 outstanding challenges. Issuance windows permit sixteen per
IP and 32 per IPv4 /24, IPv6 /64 and
IPv6 /48 per minute, plus 1024 per node. These limits include IPv4-mapped sources.
The node-wide issuance window reserves two challenges when admitting a prefix;
its second challenge can use that reservation even if other prefixes fill the
remaining window. A new prefix is refused when no reservation fits. Neither
reserved issuance nor outstanding challenges are retired by other sources.
The pending challenge ceiling is 4096; saturation returns a retryable `Busy`.
Only expiry, consumption and holder disconnect release outstanding challenges.
Expired source windows are pruned; source tracking is bounded at 8192 entries.
Consumed nonce/proof tables separately retain up to 12288 entries, above the
maximum eleven default issuance windows across their 600-second horizon.
Authenticated sessions have no separate 4096 ceiling. No live replay evidence is discarded; a holder
replaces its previous session when it authenticates again.
Sessions permit 256 request nonces and require branch signatures, the holding
connection, the exact current unfenced head and live capabilities.

Disconnect releases unconsumed challenges and sessions while preserving consumed
markers. Gateway disconnect notification is best effort over authenticated mesh;
missed notifications remain unusable from another holder and expire monotonically.
Router restart invalidates every grant. No grants are serialized, backed up or
restored. Durable registration and `Live` survive, but reconnect authenticates again.
Each listener has a handshake pool H (default 256) and an optional authenticated
pool A (unlimited by default). No arrival revokes an existing holder. Full H on
the dedicated direct router listener closes a new TCP socket before TLS; that
path cannot send a retry frame. Shared gateway TCP/QUIC listeners acquire H after
TLS and `CustodyOpen`; full H returns `Busy` with a `node_capacity` retry hint.
Ordinary connections and streams do not consume custody pools. A configured full
A refuses Prove with `Busy` and a 30000 ms `node_capacity` hint, then releases H
when the connection closes. Clear or raise `RAMFLUX_CUSTODY_AUTHENTICATED_POOL`
and restart to recover from a finite authenticated ceiling.

Prove checks the holder and reserves A under the limiter mutex, then releases
that mutex before the synchronous durable publication/prekey/session callback.
The existing service admission lock still orders the callback against disconnect
cleanup. A second limiter critical section commits H to A or rolls back the
reservation. If the holder was revoked or expired during the callback, the
service closes any new session before replying with a refusal; it never sends
SessionEstablished for that failed grant. Both limiter critical sections perform
only in-memory operations; durable commits do not hold the limiter mutex. Deadline indexes prune expired holders/sessions without scanning
all authenticated holders; pre-auth counters are removed exactly once on
promotion or unauthenticated removal. Direct session creation is fenced by its
holder, so a closed/revoked holder cannot recreate a grant.

Only unauthenticated holders consume the per-source handshake counters (default
four per IP, IPv4 /24, IPv6 /64 and IPv6 /48). IPv4-mapped IPv6 normalizes to IPv4.
A QUIC connection allows four unauthenticated custody streams; authenticated
streams do not consume those slots. Authenticated sessions have no source,
prefix, principal or default node-wide count cap. The entire
custody exchange, starting with direct-listener TCP accept (including TLS) or
the first `CustodyOpen` frame on a shared gateway listener, has a single deadline
of at most ten seconds. TLS and frame activity never renew it.
Disconnect, the handshake deadline, explicit revoke/fence and the unchanged
fifteen-minute transport lifetime cancel a holder; a new arrival cannot.
Gateway disconnect notices and router proof handling serialize with session
creation. Cleanup removes unconsumed challenges and sessions under the same
service admission lock used by proof execution, so queued proofs cannot recreate
a disconnected grant.

At startup each custody-enabled binary raises its soft `RLIMIT_NOFILE` to its
hard limit and
requires total H + configured total A + 512 descriptors, summed over its listeners.
With A unlimited it reserves H * listeners + 512 only and logs the effective soft
limit once at info; descriptors and memory then bound authenticated population. An
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
fresh prefixes requires at least 32 distinct source shares (1024 / 32) per minute,
using at least two
IPs per share to fill it. Each IP can spend only sixteen challenges per minute;
an IP alone cannot consume its /24 or /48 share, and the same 32 cap applies
to IPv6 /64. Two-slot reservations for new shares also count toward the
node-wide bound; reservations are never retired by other sources. These custody
bounds do not gate ordinary gateway ingress. Authenticated fill is bounded by A
when configured, otherwise by process descriptors and memory; there is no
minimum source-share or principal count. The 8192 issuance-bucket table remains
fail-closed when full and drops only expired windows. Attacks beyond these bounds
are network-layer DoS, outside this profile's admission guarantees.

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
only in explicitly marked development/test integration builds (`RAMFLUX_ITEST_BUILD=1`).
Release profiles reject it independently of that marker or debug-assertion settings;
guarded production builds reject it in every profile. Production feature
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

## Retrying custody admission

Every admission budget refusal with `Busy`/`Capacity` supplies
`retry: {scope, retry_after_ms}` unless it already supplies a daily `capacity`
hint. Scope is `pre_auth_source` or `node_capacity`. The node clamps to 1000–3600000
ms, and the SDK clamps again. Busy retries wait that value plus 0–10% added jitter,
never less than the node minimum. Without a retry hint, the legacy 1/2/4/8/16-second
schedule remains (upper-quarter jitter, one-second floor). Each attempt has a
90-second budget including account-flight and transport setup. A hinted wait
that would exhaust the budget returns the Busy error carrying the hint immediately.

`AdmissionRetry` retains a monotonic `not_before` across attempts. Read-only status
peeks never move it; the next attempt waits before obtaining a fresh 90-second
budget and account-local `.network.lock` lease. One-shot callers create one state
per call; a persistent background connection manager is a separate feature.
Capacity with `retry` and no daily metadata starts a shared cooldown of the hint
(for example 5000 ms), while unhinted Capacity retains 300 seconds. Daily reset
metadata keeps its existing reset/floor policy. Local cooldown checks do not move
the deadline. Other accounts/nodes remain independent; restart loses local state.

BREAKING wire change: older strict decoders reject a refusal carrying `retry`;
rebuild clients and node services together. Non-refused frames are unchanged.

Ordinary native gateway sessions use this same retry path and account lease, including TCP-TLS
and QUIC. Their outer connection deadline is ninety seconds as well; the shorter timeout used by
legacy session operations does not truncate native admission backoff. Completed operations keep
their exact payload and ACK checks across fresh transports.

An account-local filesystem lease serializes connection attempts even across
daemons sharing that account directory. A refused transport is dropped before
backoff. Each retry authenticates a new TLS connection and receiving-node record,
then requests a fresh one-use challenge and signs a new exporter-bound proof.
Completed publication/registration steps are retained as progress; the pending
action is retried with the same payload. This also handles a gateway refusal after
a durable operation: a retry does not reuse its old nonce or proof. `Live` is
persisted only after publication, registration and session authentication complete.

Sources behind one NAT share the configured per-IP challenge window (default
sixteen per minute). Initial bootstrap and reconnect each need three fresh
challenges. For N accounts, `windows = ceil(3 * N / challenges_per_ip_per_minute)`;
20 accounts take four windows at defaults, with refusal hints naming the remaining
window wait. This does not promise any arbitrary batch completes within one
90-second attempt. The full fast-bootstrap tuple IP=128, PREFIX=128, NODE=1024
admits 60 challenges in one window; raising IP alone above PREFIX refuses startup.
Durable new-principal quotas remain separate and are not spent by known principals.

A forward that does not preserve source addresses collapses all clients onto one
pre-auth source budget. Preserve the actual transport source or deliberately
raise the pre-auth knobs together. Forwarded header claims cannot supply trusted
transport identity and do not bypass normalization or proof binding.

## Operator admission diagnostics

Each custody `Capacity` or `Busy` budget refusal emits one warning named
`custody admission refused` with `budget`, `count`, `limit` and `refusal` fields.
Warnings contain no credential material, nonces, account identifiers or full
client addresses. `holder` and `prefix` identify outstanding-challenge ceilings;
`global` is the global pending ceiling; `replay` and `request`
identify the unchanged 12288 proof-marker and 256 per-session nonce safety bounds. `source_*_rate` means issuance rate, while `handshake`, `authenticated`,
`connection_stream` and `listener_source_handshake` describe pre-auth listener
admission. `authenticated` appears only with a configured finite A. Removed
`listener_source`, `principal_session` and `authenticated_prefix` budgets no longer
refuse authenticated sessions. State-bound retry hints are 30000 ms; handshake
hints use the earliest relevant pre-auth deadline; rate hints use the remaining
60-second window. Missing/revoked/invalid-principal holder errors carry no hint. Durable publication and consent-history warnings identify
their own budget and scope separately.

A pending challenge expires after 300 seconds and is removed from admission
accounting when consumed, rejected or its connection disconnects. The node
prunes expired process-local leases on the next operation. Consumed nonce/proof
markers remain for their 600-second replay horizon. Sessions expire within
300 seconds; a full request-nonce budget requires a fresh session. Restarting
the node clears these process-local leases and markers. Durable new-principal
and authority-history quotas survive a restart: daily quotas reset on the next
UTC day, minute quotas on the next UTC minute, and retained consent history
expires after seven days plus fifteen minutes. A restart cannot clear a durable
account-count or byte ceiling. Use the warning's budget before choosing a remedy.

The outstanding source ceiling remains 64, independent of successful issuance:
N well-behaved bootstrap flows use three challenges each in sequence, with at
most one pending per flow. Only unauthenticated flows consume per-source listener
slots. Promoted connections can continue sequential challenge work without
consuming H or source handshake slots, so authenticated population does not imply
the old eight-flows-per-gateway bound. The independent 64-outstanding-per-prefix
bound and issuance windows still apply. Increasing the pending ceiling or
restarting a node does not increase the configured issuance rate.

### Daily new-principal quotas and operator inspection

Publication admission is durable. Its UTC-day counters reset at 00:00 UTC;
restarting the router does not clear them. A client receiving `Capacity` waits
at least 300 seconds before another attempt. A daily quota can remain exhausted
until midnight, independently of the process-local challenge limits.

The router accepts `RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_PREFIX_PER_DAY` in
`1..4096`. It caps an explicit value at
`RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_DAY` (default 256). IPv4 /24 and IPv6 /64
use that value; the wider IPv6 /48 uses `max(32, value * 4)`, also capped at
the global daily limit. Invalid values fail startup. When unset, the old
fair-share policy remains: narrow `min(8, ceil(global / 32))`, wider
`min(32, ceil(global / 32))`. With default global 256, all prefix limits are 8.
For a shared demo network, set prefix 128 and global 1024: IPv4 /24 and IPv6 /64
allow 128 new principals per UTC day, IPv6 /48 allows 512, and the whole node
allows 1024. Existing principals do not spend another daily admission on update.
The independent global per-minute limit remains 16 by default.

In the trusted demo operator env, configure:

```sh
RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_PREFIX_PER_DAY=128
RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_DAY=1024
```

The demo wrapper retains these inputs across upgrades and snapshot rollback and
passes them only to the router. Omitted inputs stay absent, preserving the unset
policy. Apply configuration through the normal operator-managed deployment flow.

Inspect the running router through the existing authenticated mesh admin listener:

```sh
# Load the private operator environment; never put the token in argv.
set -a
. "$DEMO_DATA_DIR/identity.env"
set +a
"$DEMO_TOOL" custody-budgets 127.0.0.1:59488 "$DEMO_DATA_DIR/certs" router
```

Enable the independent router administration opt-in first: set
`RAMFLUX_ROUTER_ADMIN_ENABLED=1` for the demo wrapper, or explicitly select
`docker-compose.router-admin.yml` with `RAMFLUX_ROUTER_ADMIN_PORT`
for direct Compose. The federation admin overlay does not publish this port. The router listener
uses loopback TCP 59488 (`RAMFLUX_ROUTER_ADMIN_PORT`). `DEMO_MESH_PORT` reaches
federation and does not serve this router route. The tool
uses the existing gateway mesh certificate and router admin token. Keep both
operator-only. This path is not forwarded by the public gateway.
The JSON result includes `observed_at` and a row per durable daily/minute window,
plus the global lifetime ceiling: `scope`, truncated node-keyed `prefix` hash,
`budget`, `count`, `limit`, and `reset_at` (Unix seconds, UTC). A null reset is a
non-expiring ceiling. Counts belong to the retained window: a reset in the past
means that count no longer applies; inspection never resets, charges, or prunes
receipts. Empty rows mean no principal has yet been admitted. No full source IP
or prefix is returned. Inspect the `publication_daily` prefix row to distinguish
a used venue quota from challenge, minute, or global capacity pressure.

### Server-supplied daily reset hints

A durable prefix-day or global-day publication refusal keeps the `Capacity` code
and includes `capacity: { scope, resets_at_unix }`. The scope is `prefix_daily`
or `global_daily`; the reset is copied from the durable UTC-day window. Minute,
lease, byte, listener, and other capacity refusals omit this field.

The client accepts daily resets strictly in the future and no more than two days
ahead of its wall clock. It logs discarded past or out-of-range reset values and
falls back to the generic 300-second cooldown; CLI errors never repeat a past
reset time. Saved deadlines are bound to both the node id and pinned public key;
changing either clears the old cause. Old unbound hints are discarded on bind.

A loaded or persisted deadline beyond the writer's bound (two days with a usable
hint, 300 seconds without one) is clamped to a 300-second fallback and logged
once at info with `clamped: true`. The derived view retains that marker for the
captured cooldown. An unhinted cooldown uses a shared monotonic anchor during
this process, including across account reloads; changing the wall clock cannot
renew or bypass it. After restart, the saved wall-clock value is advisory and
bounded again. No additional storage field or custody wire field is introduced.

Account status, account lists and `account.networking.changed` serialize the same
`networking_view(now)`: the cause keeps the existing `kind`, `retry_after_ms` and
optional `capacity` fields; capacity deadlines additionally expose `remaining_ms`,
a future-only `resets_at`, and `clamped: true` when repaired. Expired capacity
causes disappear. The event captures its view at event time, while later status
reads derive the current view. Local blocked retries do not extend the captured
deadline or repeatedly rewrite authority.json. A valid daily hint still waits
until the server's reset; the networking backoff also retains its monotonic floor.

This is a breaking development v3 wire change: older strict decoders reject a
refusal carrying `capacity`. Rebuild clients and node services together; the
version stays unchanged for the current development deployment.

Pending-account Capacity refusals persist their node-bound retry deadline,
including short server-hinted Capacity refusals. Another process opening the same account observes
the remaining delay; status reads and blocked retries do not renew it. Relative
hints use the protocol's one-second to one-hour bounds and round up to the stored
wall-clock second, while an active process also keeps a monotonic anchor.
Busy refusals, including those carrying a retry hint, do not install a shared
deadline and clear an earlier Capacity deadline. Their view retains the Busy
retry hint without a persisted countdown or reset time.

### Networking view and event cadence

Status and account-list reads derive their current remaining delay without
rewriting the persisted refusal. An expired hint is discarded with one warning
per account binding and hint value across consecutive reads. The 300-second
legacy Capacity retry floor is still enforced when a shorter daily hint expires.

`account.networking.changed` reports cause, node binding, and state transitions.
For native accounts its additive `session` object carries `state` (`live` or
`networking_pending`), `phase` (`connecting`, `live`, `backoff`, `stopped`),
`generation`, typed `cause` and capture-time `retry_after_ms` from the latest
resident connection snapshot when an observation is applied. Custody `state`
stays `live` during session loss; pending and restored Live events require no
status read. Starting a new connection manager first resets the persisted session
to pending/connecting, preserving custody fields. Each writer preserves the other
half. Equality ignores session generation and countdown-only changes, retaining
complete refusal codes and nested details, capacity scope, node binding and the
absolute `capacity.resets_at_unix` deadline.
It does not publish every countdown decrement or blocked retry. Its
`networking_reason` is the derived view captured at that event's time. Delay
fields describe the captured transition rather than a live countdown; obtain a
fresh status view for the current remaining delay. Hinted blocks also retain the
server's absolute reset time.
`node_binding` is the existing opaque hash of node id and public key, or null
when no binding is selected. An expiry event clears `networking_reason` even
without another user networking attempt. The account writer checks expiry on its
ordinary background sync and before commands, projecting that transition before
a new connection attempt can replace the view. These expiry publications use
runtime attribution, including retries after publication failure, rather than an
unrelated command's request id. Failures log one WARN until publication succeeds;
account commands and background synchronization continue.

The router administration inputs are `RAMFLUX_ROUTER_ADMIN_ENABLED` and
`RAMFLUX_ROUTER_ADMIN_PORT`. The former remains an independent opt-in. For one
release the demo wrapper also accepts `DEMO_ROUTER_ADMIN_LOOPBACK_PORT` as an
input alias; the canonical port takes precedence and is the only new runtime
spelling saved. Historical snapshots retain their own frozen Compose/runtime
files, and maintenance can read their old `RAMFLUX_ROUTER_ADMIN_LOOPBACK_PORT`
key. Rollback and recovery inspect the target snapshot's selection and refuse an
invalid, conflicting, or occupied router admin port before restoring any files.

### Local-first unlock and lifecycle retries

Account unlock, creation confirmation and recovery promotion reply after local data,
vault and readers are ready. Admission continues asynchronously: observe
`account.networking.changed` for Live or a typed networking refusal. A client
deadline or closed connection ends only the wait for a keyed lifecycle operation.
Retrying the same key and intent joins its live execution or returns its saved
response. If the holder was lost with a pending receipt, only `account.unlock`,
`account.lock` and `account.switch` re-execute. Other lifecycle methods return
`OperationReconciliationRequired` (message: "operation requires reconciliation");
retry with a fresh key. This can repeat an earlier effect whose result was lost.
Changed intent under the same key remains a conflict. Startup restore is unkeyed
and does not adopt pending receipts. Account mutation receipts remain fail-closed
with the same `OperationReconciliationRequired` code.
