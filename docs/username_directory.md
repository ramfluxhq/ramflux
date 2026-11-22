# Username directory

The directory is under implementation. Provisioning inputs and wire admission exist;
public routes and SDK support remain disabled until the complete flow is available.
Configuration does not enable a partial implementation.

The product supports one explicitly provisioned centre. The centre orders uniqueness,
directory epochs and profile commitments; homes retain signed account data. Account
master keys sign bindings, profile sidecars and operations during an explicit transient
ceremony. Homes authenticate serving; their node keys do not replace master signatures.
Master seeds must never be persisted by the directory.

## Trust and availability

Homes and clients independently receive the centre's URL, DNS identity, signing key,
TLS server name, CA file and trust generation. They never adopt pins from query replies.
The TLS server identity and document signing key are separate checks. There is no
automatic key rotation, alternative centre or cached-authority fallback.

Every positive lookup requires fresh centre and current-home revalidation. Centre or
witness outage makes username lookup/profile publication unavailable; ordinary account
unlock and existing messaging remain independent. The independent witness protects
against primary-only rollback, not joint compromise or rollback of both stores. It
owns authority publication, not just a startup health check.

A malicious centre can substitute another valid account on first contact, suppress
lookups or equivocate about unseen history. There is no transparency log. Clients
verify master signatures and preserve observed directory/profile floors, but a first
contact still requires out-of-band identity verification. A username does not accept a
contact request or authorize sending. Foreign-home contact requests remain unsupported
in this module.

Exact authenticated lookup reduces bulk scraping but does not hide the query or prevent
dictionary enumeration. The centre sees root/home/name and timing. Per-reporting-home
quotas and fixed global/durable caps bound storage; they do not prevent Sybil squatting.
Public deployment requires an operator/key-rotation policy and an accepted admission
cost or explicit acceptance of this limit.

## Provisioning inputs

All names below begin with `RAMFLUX_USERNAME_`. No secrets are accepted inline.
Entirely absent inputs leave the feature unconfigured. Partial inputs, blank values,
unexpanded substitutions, foreign-role fields and noncanonical integers fail closed.
Paths must be absolute. The endpoint is a canonical HTTPS origin without credentials,
query, fragment or path; IPv4 endpoints require a separately provisioned DNS TLS name.

| Suffix | Required by | Meaning |
|---|---|---|
| `ROLE` | All services | Exactly `home`, `center` or `witness`. |
| `CENTER_URL` | All | Explicit centre HTTPS origin, optional canonical nonzero port. |
| `CENTER_ID` | All | Canonical lowercase DNS identity of the signing centre. |
| `CENTER_PUBLIC_KEY` | All | Canonical base64url 32-byte nonweak Ed25519 public key. |
| `CENTER_TLS_SERVER_NAME` | All | DNS name verified by TLS, distinct from signing pin. |
| `CENTER_CA_FILE` | All | Operator-supplied TLS trust-anchor file. |
| `TRUST_GENERATION` | All | Explicit positive safe JSON integer; no inferred/default generation. |
| `HOME_DB` | Home | Ordinary home intent/prepared/committed store. |
| `PRIMARY_DB` | Centre | Serving projection, private to the writer incarnation. |
| `WITNESS_DB` | Witness | Independently protected authoritative store. |
| `WITNESS_SOCKET` | Centre/witness | Witness-owned Unix socket path. |
| `CENTER_UID` | Centre/witness | Pinned nonroot centre UID. |
| `WITNESS_UID` | Centre/witness | Pinned nonroot witness UID, different from centre UID. |

Shape validation does not prove OS protection. Before activation the service must check
ownership, modes, peer credentials, exclusive front-door ownership, intact independently
initialized witness and primary reconciliation. The centre must have no write access to
the witness state or socket directory. Missing anchors are not initialized by startup.

## Reporting-home contract, version 1

All four operations use POST and the same bounded JSON envelope:
`{proof:{body,signature},evidence:{discovery,history},request}`. Every envelope and new
inner object is closed. Input is bounded before parsing, decoded with strict I-JSON and
compared byte-for-byte against its canonical representation. Unknown, missing, duplicate,
noncanonical and oversized input refuses. No wire normalization of names is allowed.
Local CLI input alone may trim, lowercase and strip one presentation `@`.

| Request method | Exact path | Remaining request members |
|---|---|---|
| `mutate` | `/v1/usernames/mutate` | `phase` (`reserve`, `commit`, `abort`), `operation`, `profile` (explicit signed v2 or null). |
| `status` | `/v1/usernames/status` | `operation_id` (explicit ID or null for current). |
| `resolve` | `/v1/usernames/resolve` | Exact `name`, request `nonce`. |
| `revalidate` | `/v1/usernames/revalidate` | `request`: existing closed HomeRevalidateRequest. |

`proof.body` has exactly `version,audience,generation,home,root,method,path,body_hash,
evidence_hash,channel_binding,nonce,issued_at,expires_at`. Version is 1; method is POST;
path is the table's literal path. Audience and generation match the independently
provisioned centre. Root, hashes, channel binding and nonce are canonical base64url32.
All times are safe JSON seconds, `issued_at <= now < expires_at`, with lifetime 1–10s.
Body/evidence hashes are raw BLAKE3 of their exact canonical JSON documents. The node
signature covers ASCII `ramflux.identity.username_reporting_home.v1`, one NUL byte,
then canonical JSON of the complete proof body. This request-proof transcript does not
change any binding/profile/operation/checkpoint/receipt/resolve transcript.

The transport adapter obtains the reporting node ID/key from authenticated TLS and
binds the proof to the current TLS exporter. JSON labels, proxy headers and old channel
facts cannot supply these values. Signed fresh federation discovery must match the same
node/key and validated service TLS possession. Discovery does not enrol an administrator
or authorize changing account state.

Evidence is at most 1MiB; the whole report at most 1MiB+16KiB. Account home history uses
the existing genesis/committed-history verifier with its existing chain and size caps.
First observation starts at verified account genesis; subsequent observations extend
the retained home floor. The authenticated caller must equal the terminal home node AND
key. Mutation root/profile/binding signatures verify under the account master recovered
from that verified history, with exact root and binding-home correlation. Home history
does not replace current native session/branch authorization at the gateway.

Before dispatch, the witness durably consumes `(home,nonce)` in a bounded replay ledger,
checks request/global quotas and retains verified home floors. A retry preserves the
exact signed account operation and operation ID but obtains a fresh proof/nonce/channel
binding. Transport proof replay is rejected even when the underlying operation has an
idempotent result. Account operation expiry is never extended by a fresh node proof.

## Error contract

Errors use the existing closed DirectoryFailure code strings, unchanged through bus and
CLI. Lookup maps missing/hidden/held/deleted/nonresolvable names to `not_found`; it never
offers availability, prefix, list, batch, count or former-owner redirect endpoints.

| HTTP status | Directory codes |
|---|---|
| 401 | `authentication_required` |
| 400 | `invalid_username`, `invalid_profile`, `invalid_avatar`, `unsupported_version` |
| 403 | `signature_invalid` |
| 404 | `not_found` |
| 409 | Taken/held/reserved, stale epoch/profile, replay, ownership, pending/deleted, key/name change and profile-floor conflicts. |
| 429 | `rate_limited` |
| 503 | `directory_unavailable`, `capacity`, `clock_unsafe` |

Only rate, capacity, unavailable and pending failures carry `retry_after_ms` in
1000–60000. Authentication/channel failures give no authoritative name facts. No hint
or status permits bypassing witness publication fencing. Transport errors become
`directory_unavailable`; corrupt protected state closes serving.

## Profile and client boundary

This module includes username and bio. A v2 sidecar's avatar is always null; a non-null
avatar candidate refuses before publication. Native Profile/DeviceSet bytes do not
change. Bio uses the existing trim/NFC/140-scalar/560-byte limits.

The local bus surface is `username.mutate`, `username.status`, `username.resolve`,
`username.contact.add` and `profile.update`. New methods receive explicit denied native policy rows and generated
manifest entries. They never enter executable C ABI discovery or native execution.
The descriptor, executable native method set and CAS product pin remain unchanged.

Development verification builds real binaries and drives scratch-script runs through
rf daemons, real services and product reads: same-node set/resolve/contact add, rename
hold/exact match, and two-node lookup through one centre. Restart and lost-reply cases
also require captured direct-run evidence. An unpublished candidate has completed the
shortest set/resolve flow; contact acceptance, rename and foreign-home acceptance
remain outstanding. This is not complete release evidence.

## Live transport configuration under development

Home provisioning additionally requires `RAMFLUX_USERNAME_HOME_URL`,
`RAMFLUX_USERNAME_HOME_TLS_SERVER_NAME`, and `RAMFLUX_USERNAME_LISTEN_ADDR`.
Witness provisioning requires `RAMFLUX_USERNAME_LISTEN_ADDR`; the centre primary
has no public username listener. The HTTPS origin parser accepts canonical DNS,
IPv4 and bracketed IPv6 origins with an optional nonzero port, without credentials,
paths, queries or redirects. `RAMFLUX_USERNAME_PRIVATE_PEERS_FILE` is reserved for
explicit private-network home pins; it is not an admission substitute.

A signed home service locator contains the already verified terminal home identity,
HTTPS origin, TLS server name and CA certificate. Its canonical frame is at most
4096 bytes, including a CA PEM of at most 2048 bytes; its lifetime is at most one day.
The reporting proof binds this locator as part of its evidence hash. The protected
home-history floor retains the immutable master public key and locator. An expired
locator closes resolution; it never authorizes an archival profile or creates a
centre signing pin. A home refreshes the locator autonomously through a genuinely enrolled native root.

The dedicated TLS listener requires client-certificate key possession during the
handshake. Before account admission, it validates that exact certificate chain
under the bounded signed discovery CA and requires the federation SPIFFE identity
of the reporting node. This deferred root selection is local to the username
listener and does not change mesh trust or enrol federation administrators.

Both clients and servers bind node-key possession to the TLS exporter and a fresh
client challenge using `ramflux.identity.username_transport.v1`. This identity
proof contains no account data and grants no publication permission. Canonical
HTTP response framing, including status and length headers, is queued inside the
witness fence. Each nonblocking encrypted socket write re-enters the same fence;
pending ciphertext is dropped when the context, head, incarnation or lease retires.

Protected centre/witness processes currently require Linux peer credentials and
distinct nonroot UIDs. Private primary and witness DB directories must be owned by
the corresponding UID with mode0700, files0600, witness socket directory0750 and
socket0660. Symlinked private paths are refused. Redb's exclusive process lock is
required before a new writer may reopen the primary; its head must reconcile before
serving. Missing primary initialization requires explicit `--username-rebuild` at
the primary and `--username-initialize` or `--username-recovery` at the witness.
Missing witness state is never silently recreated. These operator recovery actions
do not bypass peer credentials, semantic admission or the exact primary fsync gate.

The release gate remains false. A private candidate has completed a real set and
second-account exact resolve. The complete acceptance flow remains unfinished.

## Home reconciliation and profile publication

The native detached JSON request carries the SDK's independently configured centre
URL, ID, key and generation. Router and home compare them with their own pin before
dispatch. This adds no protobuf field or executable C ABI method. The router reuses
its configured native home authority and the existing
`RAMFLUX_HOME_MIGRATION_FEDERATION_ADMIN_ORIGIN`/`TOKEN` internal bridge. A username
home therefore requires that native authority configuration, including its genuine
node record and existing mounted node signer. No migration destination is fabricated.

`--username-home-initialize` explicitly initializes ordinary home storage. Normal
startup refuses missing storage. The home starts its durable outbox coordinator and
renews its signed locator through a real enrolled root. Latest authenticated locator
metadata is shared by a home; protected service entries have a lifetime cap of one
million. Read operations use the existing read quotas; mutations retain their separate
10/minute/root and60/minute/home ceilings. All counters fail closed at capacity.

Profile transport validates the exact centre tuple, master signatures and real native
home history. Native principal/kind must match the profile; native workflows use the
public bot category. Target DNS is resolved once and the exact addresses are dialled.
Private targets require an explicit matching node/key/origin pin (at most64 entries).
There are no redirects. The resolver has two fixed workers and sixteen queued jobs.

The home retains the master-signed operation with committed profile bytes. Its
publication context contains no durable permit: every bounded nonblocking write
checks the current local floors and suppression/deletion under the same mutex used
by H1/H3 writes. Both wall time and a monotonic deadline bound the fresh wrapper.
A concurrent restrictive change or expiry closes a partial reply. Current signed
operations also let account restrictions cover profiles without names and release;
restore unions independent directory/profile floors, retaining conflicts and delete
restrictions. Historical records are never sufficient for a positive profile read.

SDK/bus/CLI signing, status and exact resolution are wired. Contact-by-name and
account-owned asynchronous delivery are under verification; the remaining real runs
and final-head CI still gate release.

## CLI and account jobs under verification

`rf username set @name --account ACCOUNT` requests a fresh unsigned draft, then
performs the master ceremony locally and submits only signed public records. The
phrase is read from a private owned file or hidden terminal input. Neither recovery
words nor master material enter the daemon bus or the durable operation journal.
`rf username status`, `resolve`, `release`, `delete` and `profile` use the same
account identity and explicit centre pin. Bio/profile updates never populate avatar.

`rf contact add @name --account ACCOUNT` resolves the exact name, persists observed
signed floors, and refuses a foreign home before staging a contact request. On the
configured home it pins the name on explicit Add and reuses the existing native
current-authority, consent, request delivery and recipient acceptance path. The
username is never resolved again to choose a recipient at send time. A historical
name pin can survive a failed transport attempt; reuse by another root requires
explicit review and cannot silently redirect an existing contact.

One account-owned network job carries captured connection inputs and public signed
documents. The account writer prepares the journal before I/O and applies verified
results afterwards. It remains available for receive work during network waits.
Retries read fresh home/centre status before resending identical signed bytes, use
bounded backoff up to sixty seconds, and never extend operation expiry or rebase a
signed change. Lock and shutdown cancel these jobs before writer teardown. Restored
bytes and expired uncertain intents do not become autonomous live send work.
