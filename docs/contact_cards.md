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

Principal lookup is TOFU through the account's home node:
`GET /mvp1/principal-manifest/PRINCIPAL` returns an active device manifest or null.
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
