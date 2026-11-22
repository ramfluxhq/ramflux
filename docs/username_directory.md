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
| `mutate` | `/v1/usernames/mutate` | `operation`, `profile` (explicit signed v2 or null). |
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

The local bus surface is `username.mutate`, `username.status`, `username.resolve` and
`profile.update`. New methods receive explicit denied native policy rows and generated
manifest entries. They never enter executable C ABI discovery or native execution.
The descriptor, executable native method set and CAS product pin remain unchanged.

Development verification builds real binaries and drives scratch-script runs through
rf daemons, real services and product reads: same-node set/resolve/contact add, rename
hold/exact match, and two-node lookup through one centre. Restart and lost-reply cases
also require captured direct-run evidence. These runs have not been performed yet.
