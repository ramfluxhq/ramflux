# Resolved contacts and contact cards

An account can call `contact.add` with exactly one of `{"principal_id":"alice"}` or
`{"card":"ramflux-card:v1:..."}`. No link ID, commitment or device hint is required.
`contact.accept` accepts the same selectors, or a stored pending `link_id`. Resolution
verifies the peer's device manifest before atomically caching devices, delivery aliases,
root commitment, safety number and accepted link. Lookup does not mark safety verified.

`contact.card.export` returns `{"card":"...","link":"..."}` for an account bound to a
configured home node. `rf contact add --account ACCOUNT --principal PRINCIPAL`,
`rf contact add --account ACCOUNT --card CARD` and `rf contact card --account ACCOUNT`
provide the corresponding CLI operations. The legacy explicit link request and CLI
flags remain supported, and also resolve the contact before returning accepted.

Successful add/accept responses contain a `contact` object with `principal_id`,
`display_name`, `reachable`, `verified`, `kind_asserted`, `root_commitment` and `node`.
Contact rows also expose outgoing `request_id` and `request_state` (null when absent).
`kind_asserted` is a root-signed self assertion: `human`, `headless_ai`, `bot`, `workflow`,
or null. It does not change safety verification. `verified` uses the same verification
record and device-set comparison as `identity.directory`. The directory exposes these
contact fields and a cached safety number. Durable `contact.changed` events cover
identity resolution and safety verification changes.

Successful explicit `contact.add` and `contact.accept` cache the safety number before
returning, including an accepted retry after inbound automatic acceptance. Retry
completes a missing cache from local verified authority without network lookup or
vault access. It preserves lookup, card and verified provenance except for an explicit
card upgrade of lookup provenance, and never marks the contact verified. Native
automatic acceptance already caches algorithm version 2; legacy automatic acceptance
can leave the number absent until an explicit operation. Directory polling does not
compute a missing number. Once filled, the cache is not refreshed by accepted retries;
only an explicit safety-verification flow refreshes an existing cached number.

Principal lookup is TOFU through the account's authenticated home-node session.
The directory refuses to choose between conflicting active roots. The SDK applies its
existing root-commitment, device manifest, branch-proof and prekey checks. A known root
cannot be silently replaced. A card supplies the expected root rather than taking the
first root from node lookup. Safety numbers still require comparison by the users.

## Card formats

Native accounts emit version 3 and refuse version 1 import. Version 1 below is the
legacy format retained only until legacy identity support is retired.

## Native card version 3

Text uses `ramflux-card:v3:BASE64URL`; links use
`ramflux://contact/v3/BASE64URL`. The complete encoded input is bounded to 1 MiB.
The payload is canonical JSON `{body, signature}`. The version-3 body contains
`principal_id`, `account_anchor`, `master_public_key`, the master-signed
`master_certificate`, `authority_head_hash`, the complete signed-authority device
list `devices`, `node_url`, `node_key_fingerprint`, `display_name`, `issued_at`,
and `expires_at`. The self-signing key signs the exact JCS transcript
`{"domain":"ramflux.contact.card.v3","body":BODY}`. It never uses a legacy signer.

Import verifies the master anchor, master certificate, self-signing signature,
expiry, canonical encoding and safe locator/display metadata. Online resolution
requires the current authenticated directory head hash and master-certificate hash
to equal the card commitments. A replaced self-signing key cannot make its old
certificate current by copying the new head hash into another card. Export a fresh
card after authority changes. Device permission comes from the current verified
authority and possession proofs, not from portable display metadata.

First contact pins the master anchor with `root_source: card` under the existing
TOFU model. A later native card with a different pinned anchor returns code
`AnchorMismatch`, reason `anchor_mismatch`; a card cannot replace that pin.
Primary replacement preserves the anchor. Contact safety comparison remains a
separate user action.

## Legacy card version 1 encoding

The text form is `ramflux-card:v1:BASE64URL`; the link is
`ramflux://contact/v1/BASE64URL`. Both are single-line strings of at most 4096 bytes.
The unpadded base64url payload is canonical JSON with `body` and `signature` fields.
The body contains:

- `version`: 1; `principal_id`; `root_commitment`; `root_public_key`.
- `node`: `{url, key_fingerprint}`. The fingerprint is hex BLAKE3 of the UTF-8 domain
  `ramflux.contact.node-key.v1` followed by the decoded 32-byte node public key.
- Optional `display_name` and `kind_asserted`. Display names must satisfy the shared
  single-line text safety policy and occupy at most 256 UTF-8 bytes.
- `issued_at` and `expires_at`: Unix seconds, with validity at most 30 days. Export
  uses seven days. Import allows at most 60 seconds of future clock skew.

The Ed25519 signature is made by the identity root over the JCS bytes of
`{"domain":"ramflux.contact.card.v1","body":BODY}` using the exact received body.
Import verifies the commitment of the root public key, signature and expiry before
network lookup. Signed node discovery must match the card's node key fingerprint;
gateway TLS then verifies against the CA in that authenticated discovery record.
Display metadata is untrusted text even after signature verification.

Automatic contact routing currently covers the account's home node. A card naming
another home node fails explicitly before contact publication; it does not create a
contact advertised as reachable through an unavailable automatic federation route.
The existing explicit federation route API remains separate.

User input errors return `ValidationFailed` and `reason_code`: `unknown_principal`,
`invalid_card`, `card_signature_invalid`, `card_expired`, `self_contact`,
`already_contact`, `home_insecure_transport`, `home_profile_missing`,
`home_profile_stale`, or `node_fingerprint_mismatch`. An unsupported card home node
uses `invalid_card` with an explanatory message. Transient directory/transport failures return `Unavailable`, preserving the
source error for socket diagnostics. Failed resolution creates no accepted contact.

## Name ownership and authenticated lookup

Names on a node are first-come registrations bound to one identity root. A different
root receives typed `principal_id_taken`, including after all devices are revoked.
The reservation survives restart and legacy metadata deletion. Legacy deletion is
not a root-signed name release; this version offers no name-release endpoint.
Pre-registration name squatting remains possible. A name is not proof of a real-world
identity: use an independently exchanged card or compare safety numbers.

Name queries use `principal_manifest_fetch {principal_id}` inside an account's
Open/Auth gateway session and return `principal_manifest` with
`{response:{manifest:<object|null>,reason_code:<string|null>}}`. Raw
`GET /mvp1/principal-manifest/NAME` and raw `/mvp1/principal-lookup` return 401 with
`{manifest:null,reason_code:"authentication_required"}` before consulting the router.
The router independently checks the current live session and active registered device.
For authenticated queries, existing and unknown names have identical outer fields;
only the optional manifest differs. Directory membership is visible to authenticated
accounts. A legacy ambiguous name returns `principal_id_ambiguous` rather than selecting
one root. Hash-addressed manifests retain their previous transport contract.

The node charges every admitted query, including unknown names, against 60 requests
per account and 120 per source per 60-second window. Devices of one account share a
quota across gateways. Each table retains at most 4096 LRU entries. IPv4-mapped IPv6
uses the IPv4 bucket; other IPv6 sources share a /64 bucket. Quotas are in-memory
admission state and reset on router restart. A quota error returns `Unavailable`,
`reason_code:"rate_limited"`, and `retry_after_ms:60000`. The source is the gateway's
socket peer, never a client-supplied body field. Known contact resolution uses its
pinned root hash and does not repeat a name lookup.

## Correcting a provisional lookup root

Contact rows and identity-directory rows expose `root_source` as `lookup`, `card`, or
`verified`. A name lookup is provisional. Importing a card pins the independently
supplied root; manual safety verification is the existing verification record, including
when a changed device set makes its verification stale. Card and verified roots cannot
be replaced through provisional recovery.

If a card supplies a different root for a lookup contact, `contact.add {card}` returns
`ValidationFailed`, `reason_code:"root_replacement_confirmation_required"`, and
`details:{principal_id,previous_root_commitment,proposed_root_commitment}`. The client
must show both roots and obtain explicit confirmation before submitting
`contact.add {card,replace_provisional_root:<previous_root_commitment>}`. The old value
is a compare-and-replace guard: stale confirmations return `root_conflict`. The CLI
exposes `--replace-provisional-root OLD_ROOT` together with `--card`.

For an out-of-band safety comparison, use
`contact.safety_number {principal_id,contact_identity_commitment:<independent root>}`
to preview the verified manifests without changing the contact. After comparison,
`contact.verify {principal_id,contact_identity_commitment,replace_provisional_root:OLD}`
confirms replacement and marks the normal safety record verified. The existing
commitment-only safety and verify requests remain available.

Replacement atomically changes cached identity/device ownership, retires old device-pair
sessions and rewrites local link aliases. It emits durable `safety.changed` with reason
`provisional_root_replaced`, in addition to `contact.changed`. Group member pins remain
immutable; conflicting group bindings reject publication and retain a safety observation.
Local display names and asserted-kind labels are preserved when a card is imported.

A card's URL must exactly match the configured home profile and its fingerprint must
match the pinned node key before any discovery request. Plain HTTP card locators are
accepted for loopback addresses (and the reserved `localhost` name), RFC 1918 IPv4
literals (`10/8`, `172.16/12`, `192.168/16`), and IPv6 ULA (`fc00::/7`) or
link-local literals (`fe80::/10`). Scoped link-local URLs with zone IDs (for example,
`%25en0`) are not supported by the URL parser and return `invalid_card`. RFC 6598 shared-address space (`100.64/10`),
IPv4 link-local, public IP addresses and other hostnames require HTTPS. DNS
resolution never exempts a hostname from this rule. Export and import use the
same policy; a disallowed HTTP locator returns `home_insecure_transport`,
distinct from malformed `invalid_card` input.

Card URLs must be bare origins (an optional root `/` is allowed), without a path, query
or fragment. Node-key fingerprint mismatches return `node_fingerprint_mismatch`,
separately from a bad card root signature (`card_signature_invalid`).

Private/link-local literal discovery URLs and `localhost` bypass configured proxies;
other hostnames retain proxy settings and receive no DNS-based private exemption.
Plain HTTP discovery lookups on a LAN are observable to that network.
Card integrity still depends on the root signature, exact configured-home URL,
pinned node-key fingerprint and verified manifests, followed by gateway TLS
against the signed discovery CA. The transport allowance does not relax these
checks or enable automatic trust of another node.

Accounts without a configured home profile receive `home_profile_missing` on
export or import. Expired, key-changed, disabled or malformed pinned profiles
return `home_profile_stale` and require refresh/operator attention. Unsupported
foreign homes are rejected locally.
Malformed or unverifiable manifests return `manifest_invalid`; network and DNS failures
return `Unavailable`. Bus consumers must handle that additive string code as retryable;
the C ABI maps network failures to `TransportUnavailable` and quota refusals to `RateLimited`. `root_conflict` requires user attention,
not an automatic retry or an automatic confirmation.

SDK consumers that need confirmation data should call
`LocalBusClient::request_frame_response(frame)`: it returns the complete response frame,
including daemon `Error` frames with `error.reason_code`, `error.details` and retry hints.
The existing `request`/`request_frame` convenience methods retain their text-error API.
The contact-add CLI prints the structured error body on failure so both compared roots
remain available. Desktop adapters should preserve those fields when presenting a
replacement confirmation rather than parsing the convenience method's error string.

Registration attempts are limited before proof-of-work and ownership checks. The
finite default is 120 attempts per transport source in 60 seconds; IPv6 sources
share a /64 bucket. Client-supplied source and clock fields are overwritten at
the gateway, and the router supplies its own clock. Taken names necessarily
reveal signup availability after this admission; unrestricted probing is not
supported. Source tables retain at most 4096 entries.

Device IDs and delivery aliases cannot be reassigned to a different root, even
after revocation or metadata removal. This interim reservation guard precedes
root-scoped device namespaces. Card import currently requires a configured home
node profile; hand-configured accounts must configure one first.

Registration admission operator notes: saved legacy unlimited/zero source limits and
zero windows are normalized on load and when set to the current defaults (120 attempts / 60 seconds);
finite operator limits are preserved. Enable registration proof-of-work on public nodes.
The per-source quota is an admission bound, not a Sybil defense: a cheap IPv6 /48 can
supply many /64 buckets and churn the bounded source table, while an IPv4 NAT shares
one quota. Stronger anti-abuse policy is an accepted follow-up. Registration PoW
currently binds the principal name rather than the transport source or time; source/time
binding for challenges is also an accepted follow-up. These limitations do not bypass
the charged source quota or the permanent ownership guard.

Registration quota rejections preserve `Unavailable`, `reason_code:"rate_limited"`
and the default-window `retry_after_ms:60000` hint across both authenticated
session frames and the gateway request/response adapter. Name/device ownership
refusals remain distinct from admission limits.

## Contact consent and message requests

Adding a principal or card now also stages a root-signed, pair-encrypted contact
request. `contact.add` accepts an optional single-line `note` (at most 140 Unicode scalar
values). Its existing `contact` result describes local consent; the additive
`contact.request_state` describes remote consent, and `request_delivery` is
`submitted`, `queued`, or `failed`. A repeated pending add resets delivery attempts and resends the same logical
request; accepted contacts still return `already_contact`. Request IDs are derived
from the requester root and nonce. Delivery retries retain that ID and validity window. An immediate first message waits for the request's gateway acknowledgement
before using the next pair-ratchet counter. Local submission is not remote acceptance.

All methods below require an unlocked account selected by the bus frame's account ID:

| Method | Body | Result |
| --- | --- | --- |
| `contact.requests.list` | `{}` | `{requests:[...],contact_requests:"manual"}` |
| `contact.requests.policy.get` | `{}` | `{contact_requests:"manual"}` or `"auto_accept"` |
| `contact.requests.policy.set` | `{contact_requests:"manual"}` or `"auto_accept"` | persisted policy |
| `contact.accept` | `{request_id:"..."}` | `{request_id,principal_id,direction,root_commitment,state:"accepted",contact}` |
| `contact.decline` | `{request_id:"..."}` | `{request_id,principal_id,direction,root_commitment,state:"declined"}` |
| `contact.block` | `{request_id:"..."}` | `{request_id,principal_id,direction,root_commitment,state:"blocked"}` |

Decision selectors may instead be a stored `link_id`, `root_commitment`, or
`principal_id`; each selector matches only its named column, and ambiguous matches fail. Existing card/principal accept and legacy
link APIs remain available. Accepting a matching inbound request by card/principal
also releases its messages and sends an accept control. Safety verification remains
an independent action.

List results contain pending inbound requests and up to 128 outgoing rows (pending
first, followed by the newest accepted/declined/expired rows). Closed request rows
are pruned after one hour; an unscheduled reply retains compact metadata until its
request expires. Contact rows retain their own outgoing state after history pruning.

Request rows include `request_id`, `link_id`, `principal_id`, `root_commitment`,
`direction`, `state`, `expires_at`, `note`, `message_count`, `preview`, and
`safety_number` (12 numeric strings). Note and preview are delimited, sanitized quoted
fields; display them as untrusted text. `preview` covers at most 256 characters of
the first held message. Subscribe through `bus.subscribe` to `contact.requested`,
`contact.accepted`, `contact.declined`, `contact.blocked`, and
`contact.request.expired`. Requested events carry counts and identifiers only; fetch private previews through
the pending list. Neither events nor list results expose the signed manifest,
private keys or raw wire control. Message arrivals refresh the requested counts. Acceptance events
on the requester include the peer principal and root.

Humans default to `manual`; new headless accounts default to `auto_accept`.
Opening an existing account initializes a missing policy from its client mode and
preserves an explicit choice. Agent-host startup preserves that policy, including
an operator-selected `manual`.
Changing policy affects future requests; it does not silently accept existing ones.

A pending sender's direct messages stay outside conversation/message/object directory
projection until acceptance, including attachment references and object keys. No
attachment is fetched during this hold. Acceptance rechecks sender authority and
projects valid messages once; revoked or invalid messages are discarded. Decline and
block delete held content. Decline permits an explicitly added fresh request after a
24-hour cooldown; a local block remains a terminal fence. Expired requests can be
explicitly added again. Old request IDs cannot reopen consent. Strangers without a
verified request still fail the existing unsolicited-message gate.

Requests and held messages expire after at most seven days. Each direction has 128
pending slots. Held messages are capped at 20 / 1 MiB per requester root and 256 /
8 MiB per account. A full queue drops the new authenticated item while consuming its
pair counter; it creates no conversation content. Each root pair admits four new
requests per hour, with 64 new requests per account per hour and 120 incoming
bootstrap authentication attempts per hour. Rate state has at most 1024 live buckets.
Delivery attempts are bounded to eight with backoff capped at 60 seconds, at most
four intents per drain and 64 target devices per manifest. Request controls are at
most 128 KiB. Local durable delivery survives restart; finite retry exhaustion is
reported as `failed`. An explicit pending `contact.add` resets and resends it.
The delivery queue allows 128 active items and at most four per peer; exhausted
reply items are discarded. Reply capacity defers transmission without rolling back
receipt or local consent. Sender-specific quota exhaustion and extra pending requests
are terminally rejected and acknowledged; exhausted known sender buckets are checked
before a manifest fetch. Only global/account capacity pressure retains a ciphertext
for paced retry. At most one deferred envelope per requester root is retained, with
1024 deferred roots per account; extra envelopes from a held root are rejected and
acknowledged. Past 1024 roots, a capacity-deferred envelope stays unacknowledged under
the replay floor without a durable deduplication slot. A per-drain in-memory
index still deduplicates its root, so later envelopes in that drain require no
additional manifest fetch. The persisted backpressure format is unchanged.
Deferred entries leave the generic retry queue and use the durable replay floor.
Global and account capacity (bootstrap attempts, account request rate, pending slots,
rate-bucket and authority-floor tables) is checked before any sender bucket is
charged, so replaying a held request never consumes the sender's bootstrap quota.
While that capacity is exhausted, rescans keep contact envelopes held without a
manifest fetch. A deferred slot expires no later than the retained state.

Decline/block fences apply to both request envelopes and authenticated pair controls
from roots that are not accepted contacts. `contact.unblock` clears the root fence; a
local `contact.add` or accept clears this side's decline fence, and a local outbound
request admits the peer's response. Declining a crossed inbound request does not
cancel an unexpired pending outbound request to that root or fence its response.
A failed local add leaves the decline fence intact; staging and fence clearing
commit together. An accepted contact link is never fenced.
A compact declined fence retains its original decision timestamp through the wire
replay lifetime after cooldown; older signed requests cannot reopen consent. Outbound
retained status also enforces cooldown after a closed row is pruned.
Maintenance runs at most once per minute, retires at most 128 closed rows per pass,
and backs off an individual failed retirement for five minutes without stopping
contact ingress. Legacy private journal redaction runs once, using a topic index.

The control binds both roots, target, request ID, nonce and validity interval under
`ramflux.contact_request.v1`. The SDK independently verifies the embedded root-signed
manifest and fetches current authority from the configured gateway, preserving device
set floors. Controls have a fixed seven-day lifetime (`expires_at = issued_at +
604800`); local request metadata excludes the manifest and complete control.
Unaccepted requester authority is bounded by 4096 compact rollback floors, retained
for fourteen days, and retired with closed requests unless independently pinned by
an accepted contact, verification, or group. Declines retain a compact 24-hour
root fence; explicit blocks retain an indefinite root fence. The special `ramflux.sdk.contact_request.envelope.v1` schema only admits a
verified request control: relabeling a direct packet cannot publish a stranger's
identity or contact. It does not authorize unrelated controls, calls or group actions.
Both peers need the request-aware SDK; older peers reject the new request schema.
Automatic routing retains the same-home limitation documented above.

The aliases `contact.request.accept`, `contact.request.decline`, and
`contact.request.block` accept the same selectors and return the same decision row.
`contact.card.import {card,note?}` aliases `contact.add {card,note?}`. A repeated
identical decision succeeds; an incompatible terminal decision returns
`ValidationFailed` with `reason_code:request_closed`. A missing request ID returns
`ValidationFailed` with `reason_code:request_not_found`. Invalid note text returns
`ValidationFailed` with `reason_code:invalid_request_note`. Outbound admission rate
refusal returns `Unavailable`, `reason_code:rate_limited`, `retry_after_ms:60000`;
this is a retry hint, and the hourly quota may still be exhausted at that time.

Verified pending peers already have identity-directory metadata, including their
signed principal and asserted kind, without an accepted relationship. Acceptance
projects held messages through ordinary message storage and `message.received`
events, preserving original send times. Held application retention begins at
release time; a signed application deadline is still enforced independently. The existing authenticated own-contact path
replicates acceptance to active siblings and releases their matching pending queues.
Locked accounts cannot list requests or subscribe/replay their account stream; lock
stops its actor and readers. Clients must discard previews already received when
processing the account lock, as they do other private message content.

### Rollback-floor capacity controls

Expired floors are evicted oldest first when a new admission needs space. Live
floors are not silently evicted. Saturation returns the typed SDK
`ContactRequestCapacity("contact_authority_floors_exhausted")`; envelopes remain
held for retry. `contact.requests.policy.get`, `.set` and `contact.requests.list`
expose `authority_floors.{retained,clearable,limit,saturated}`.

To explicitly free retired floors, call the existing policy setter with
`{contact_requests:"manual",clear_retired_authority_floors:true}` (use the
account's current policy to preserve it). The response includes
`cleared_authority_floors`. This forgets historical rollback hardening for roots
without an unexpired pending request. It does not clear decline/block fences,
request decisions, active pending floors or independently cached signed authority.
No stored encoding or schema version changes; the optional clear action is local.


### Missing manifests during sibling contact backfill

Own and contact manifest fetches share a five-second attempt window inside the
account's twenty-second sync-pass deadline. Each tick fetches at most one contact
manifest and scans at most four links. Missing manifests receive five attempts,
with 5, 10, 20, 40 and 80 second retry delays recorded before network I/O. After
five failures the contact is parked so later links can proceed.

A completed scan containing parked contacts restarts 300 seconds after completion,
or on the next tick after a changed verified directory manifest is persisted.
Identical directory refreshes do not restart it. A changed own-device roster also
restarts the scan, including its restriction-first ordering. An active scan finishes
before a directory-triggered rescan, so directory traffic cannot starve later links.
Each new scan gives missing contacts the same bounded attempt schedule. Successful
staging removes the parked marker; existing own-device queue deduplication avoids
repeated copies for unchanged contact and roster state. Retry progress survives
account restarts; older completed cursors restart once on upgrade. These intervals
are eligibility bounds: disconnected accounts resume on their next sync tick.
