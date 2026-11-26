# Username directory

The directory supports the `rf` CLI and local bus when the centre, homes and client
are explicitly provisioned. Unconfigured installations have no directory authority.
Partial configuration fails closed.

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
Before authentication, TCP and QUIC share a limit of sixty connections per source
prefix per minute. Exhaustion closes new connections; it grants no name facts.
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
| `REGISTERED_NODES_FILE` | Witness | Absolute path of the centre-provisioned registered-node list (see below); required, any other role refuses it. |
| `AUTH_NODE_RATE_PER_MIN` | Witness | Optional positive integer, default 1200: admissions per 60 s per node key. 0 or non-numeric refuses to start. |
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

## Registered home nodes

The witness admits a reporting home only if its node key is listed `active` in the
centre-provisioned list at `REGISTERED_NODES_FILE`. Document (UTF-8 JSON, strict I-JSON,
closed members at both levels):

```
{"v":1,"generated_at":<unix seconds>,"nodes":[{"node_key":"<base64url 32 B>","state":"active"|"suspended"}]}
```

Limits: file at most 1 MiB; at most 10 000 entries; `v` is 1; `generated_at` is a safe
integer; `node_key` is canonical (decodes to 32 bytes and re-encodes identically);
duplicate keys are invalid; an empty `nodes` array is valid and refuses every node;
`revoked` is not a state. Examples, valid and invalid, are in
`deploy/central/registered-nodes/` (replace `generated_at` in `valid.example.json` with a
current value before use).

- **Startup.** The file is read before the socket is bound. Missing, unreadable or invalid
  (including `generated_at` more than 300 s in the future) refuses to start. A list that is
  already expired starts, refuses every node and logs ERROR.
- **Reload.** Polled every 5 s (mtime, size or inode change). The producer must replace the
  file by writing a temporary file and renaming it, and the witness must see the DIRECTORY
  (mount the directory, not the single file, or the rename is not followed). An invalid or
  missing update keeps the last good list and logs one WARN with the reason.
- **Expiry.** The list expires at `generated_at + 86 400 s`, evaluated on every request; an
  expired list refuses every node until a fresh one is loaded.
- **Refusal.** An unlisted, `suspended` or expired-list reporter gets `authentication_required`
  before any nonce or rate charge.
- **Readiness.** There is no health endpoint; state changes are logged once: INFO
  `registered_nodes loaded count=N generated_at=T`, ERROR `registered_nodes expired`, INFO
  `registered_nodes valid`.
- **Quota.** After the global limit, each node key is limited to `AUTH_NODE_RATE_PER_MIN`
  (default 1200 per 60 s, 10x the per-prefix lookup limit) for lookups and mutations alike.

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
`username.contact.add` and `profile.update`. Those five methods are executable for
native hosts. `profile.update` accepts only a profile change. The master phrase
enters only through `ramflux_v2_username_authorize` and never through a bus field,
event, or log. The contact-verify descriptor and CAS product pin stay unchanged.
The executable native method set includes these five methods.

Deployment verification must cover set/resolve/contact add through real daemons and
services, original-request contact acceptance, default conversations, rename holds,
exact matching, two-home lookup and the foreign contact barrier. It also covers
visibility/release/delete, uncertain committed operations, protected-store restart,
lost replies and exact signed-state recovery after ordinary-home loss. Public
deployment requires the operator and abuse-policy decisions described above.

An account owns at most one reusable native directory transport. Every reuse rechecks
local pairing admission, current native authority, branch credentials and capacity;
each request retains native session authorization and fresh centre/home verification.
Cancellation and transport failure close the stream. Replies are never cached as
serving authority. A failed command can have committed: inspect fresh operation status
before authorizing another mutation.

## Live transport configuration

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

The directory release flag is on. Installations without an explicit centre pin
still have no directory authority. Explicit provisioning does not enable general
public directory service.

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

SDK/bus/CLI signing, status, exact resolution and contact-by-name use the
explicitly provisioned directory. The demo deployment below enables these paths.

## CLI and account jobs

`rf username set @name --account ACCOUNT` requests a fresh unsigned draft, then
performs the master ceremony locally and submits only signed public records. The
phrase is read from a private owned file or hidden terminal input. Neither recovery
words nor master material enter the daemon bus or the durable operation journal.
`rf username status`, `resolve`, `release`, `delete`, `profile` and
`visibility --discoverable true|false` use the same
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


## Restore and pending deletion

Backup imports and expired uncertain intents retain at most eight inactive public
candidates per account, with a total encoded bound of128KiB. Their presence never
retries a mutation. The authenticated native repair action checks the current
master and terminal home, then consumes a new pinned-centre revalidation. Only an
exact already-committed operation/binding/profile tuple repairs home bytes; the
original commit must fall inside the signed operation lifetime. Local restrictions
and a different pending restrictive intent remain in force throughout the repair.

A newly master-authorized delete can replace another pending change once a
committed v2 profile exists. The account journal preserves the predecessor as an
inactive hint, and the home stores deletion and suppression before network I/O.
If the centre still has a reservation, the witness derives the existing atomic
abort/delete pair. Retained-pair retries reconstruct the original request head and
time; they never become a standalone abort or a newly based delete.

Anonymous reporting refusals have a separate bound of sixteen live contexts,
within the existing sixty-four global contexts. They contain no claimed account
or home and can carry only authentication, rate, capacity, unavailable or version
failures. They cannot enter a positive response builder or disclose name conflicts.
Their encrypted writes use the same primary-application, witness-boot, incarnation,
lease, head and channel fence as every authenticated response.

## Single demo node

The demo can host the home, centre writer and witness together. This is a beta
configuration: separate Linux UIDs and volumes protect the writer and witness;
they share the node failure domain and the existing online node signing identity.
It does not protect against loss or compromise of the whole node.

First bring up the normal demo, then provision its existing identity with
`rf node custody-init` as described in [demo custody provisioning](../deploy/README.md#demo-custody-provisioning).
Keep the custody fragment in the trusted operator env. Add:

```sh
DEMO_USERNAME_DIRECTORY=1
# Optional; distinct from every other demo port:
DEMO_USERNAME_CENTER_PORT=59484
DEMO_USERNAME_HOME_PORT=59485
```

Run `sh deploy/scripts/demo-node.sh up /absolute/path/demo.env`. The node ID must
be a lowercase DNS identity. The demo host must be reachable from its own
containers as well as by clients; do not use a loopback address. Open the centre
port for TCP/UDP and the home port for TCP. These are dedicated authenticated TLS
listeners using the existing federation certificate and CA, separate from the
public discovery reverse proxy. All three roles use trust generation 1.
The private federation admin body budget defaults to 5 MiB with this switch,
as required by the home authority; a smaller explicit budget is refused.

The tooling writes `username-pin.json` next to `identity.env`, mode 0644, with only
`url`, `id`, `public_key`, `generation`. Transfer this public file over a trusted
channel and provide its `username_directory` object to native clients when opening
the SDK. For `rf`, set `RAMFLUX_USERNAME_CENTER_URL`, `_ID`, `_PUBLIC_KEY` and
`RAMFLUX_USERNAME_TRUST_GENERATION` from those fields **before starting each daemon**
and for signing commands. Clients never learn this pin from lookup replies.

A separate short-lived provisioning container prepares the six owned volumes
before the services start; it exits and is removed after checking their modes.
The centre joins the witness's private PID namespace so Linux Unix-socket peer
credentials contain visible peer PIDs. Their UIDs and protected volumes remain
separate; neither service uses the host PID namespace.
The initial provisioning consumes `--username-home-initialize`,
`--username-initialize` and `--username-rebuild` once. Normal restart opens existing
stores. Missing/corrupt protected stores require explicit operator recovery; the
demo never silently reconstructs them. Keep the six username volumes with the
node, including across upgrades. Restore the same switch and ports for maintenance.
Rollback requires the same directory selection and ports in its saved snapshot.
Recovery also requires the saved selection and stops the owned container cohort
before restoring configuration, so removed roles cannot continue serving.
Enabling on an existing custody-provisioned demo is supported; changing an already
selected directory identity/port or disabling it requires a fresh demo deployment.

With two unlocked accounts on separate daemons, check the business flow:

```sh
python3 deploy/scripts/demo-username-check.py --pin /private/demo/username-pin.json \
  --name @a_unique_demo_name \
  --socket-a /private/a/bus.sock --account-a ACCOUNT_A --phrase-a /private/a/words \
  --socket-b /private/b/bus.sock --account-b ACCOUNT_B --phrase-b /private/b/words
```

Both phrase files must be owner-only. The check commits A's name, verifies that B
resolves A's exact root, and requires B's duplicate claim to fail with `username_taken`.
The check uses existing accounts and never prints recovery words. Ordinary demos
with the switch absent retain their existing service set and configuration.
