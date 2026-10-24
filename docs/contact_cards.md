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
`kind_asserted` is a root-signed self assertion: `human`, `headless_ai`, `bot`, `workflow`,
or null. It does not change safety verification. `verified` uses the same verification
record and device-set comparison as `identity.directory`. The directory exposes these
contact fields and a cached safety number. Durable `contact.changed` events cover
identity resolution and safety verification changes.

Principal lookup is TOFU through the account's authenticated home-node session.
The directory refuses to choose between conflicting active roots. The SDK applies its
existing root-commitment, device manifest, branch-proof and prekey checks. A known root
cannot be silently replaced. A card supplies the expected root rather than taking the
first root from node lookup. Safety numbers still require comparison by the users.

## Card version 1

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
`invalid_card`, `card_signature_invalid`, `card_expired`, `self_contact`, or
`already_contact`. An unsupported card home node uses `invalid_card` with an explanatory
message. Transient directory/transport failures return `Unavailable`, preserving the
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
restricted to loopback development origins. Unsupported homes are rejected locally.
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
zero windows are normalized on load to the current defaults (120 attempts / 60 seconds);
finite operator limits are preserved. Enable registration proof-of-work on public nodes.
The per-source quota is an admission bound, not a Sybil defense: a cheap IPv6 /48 can
supply many /64 buckets and churn the bounded source table, while an IPv4 NAT shares
one quota. Stronger anti-abuse policy is an accepted follow-up. Registration PoW
currently binds the principal name rather than the transport source or time; source/time
binding for challenges is also an accepted follow-up. These limitations do not bypass
the charged source quota or the permanent ownership guard.
