<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Root key custody wire specification

Design revision 3, proposed normative stage-1 specification. This document and
[root key custody](root_key_custody.md) describe future behaviour, not executable
support. Independent wire review and published interoperability vectors are
required before stage 2b. The legacy binding and epoch-range policy remain
proposals awaiting the decisions recorded in the design review. No migration
writer may ship on the assumption that those decisions have been approved.

## Encoding, signatures and limits

All objects use UTF-8 I-JSON and [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html).
Reject duplicate keys, malformed Unicode, unknown fields, non-finite/fractional
numbers, negative counters, unsafe integers and unknown versions before checking
signatures. Integer fields require unsigned decimal JSON tokens (`0` or
`[1-9][0-9]*`), without decimal points or exponents. JCS does not normalize strings; only the documented phrase and
profile input rules normalize human input before signing. Never normalize an
already signed body. All fields below are mandatory; nullable fields are encoded
as JSON `null`, never omitted. Arrays are ordered as specified; no duplicates.

Types used throughout:

| Type | Exact representation |
| --- | --- |
| `U53` | JSON integer in `[0, 9007199254740991]`; counter fields explicitly require positive values |
| `Time` | `U53`, Unix seconds UTC |
| `B32` | Canonical unpadded base64url of exactly 32 bytes; decode and re-encode must match |
| `Sig` | Canonical unpadded base64url of 64 Ed25519 signature bytes |
| `Key` | `B32`; validate the declared Ed25519 or X25519 key type, rejecting weak/invalid Ed25519 keys and all-zero X25519 shared secrets |
| `Id` | Nonempty UTF-8 string, at most 256 bytes, no Unicode control characters; matches current identity identifier validation, with exact bytes preserved |
| `Kind` | One of `human`, `headless_ai`, `bot`, `workflow`; immutable per anchor |
| `Ref` | Object with exactly `account_anchor: B32`, `device_id: Id`, `device_epoch: U53` (positive) |
| `Envelope<T>` | Object with exactly `body: T`, `signature: Sig` |
| `Hash` | `B32`, computed by `object_hash` below; not a public key |

For each signed body `B` with domain `D`, including the v3 record, sign exactly:

```text
signing_bytes(D, B) = JCS({"domain": D, "body": B})
signature = Ed25519.Sign(signer_seed, signing_bytes(D, B))
object_hash(E) = base64url(BLAKE3(
    UTF8("ramflux.identity.custody.object_hash.v1") || JCS(E)))
```

`B.schema` equals `D`; `B.version` equals the table's integer. Domain strings
contain no trailing NUL/newline. Use strict Ed25519 verification, matching current
crypto validation; no Ed25519ph and no generic recursive signature stripping.
Nested envelopes, including their signatures, remain in the enclosing signed
body. Arrays of `Ref` sort by decoded anchor bytes, then device-id UTF-8 bytes,
then numeric device epoch. An object's hash includes its signature. Random ids/nonces use 32 bytes of
OS CSPRNG output (`B32`), stored once for idempotent retries. Never regenerate a
certificate or binding on a retry in the same range.

These conventions deliberately define new v3 envelopes; they do not change the
flat v1/v2 signing bytes. Existing
[domain constants](../crates/ramflux-protocol/src/domain.rs) remain unchanged.
The following additions are proposed constant names, not claims of existing code:

| Constant | Exact domain | Body version / signer |
| --- | --- | --- |
| `CUSTODY_MASTER_CERTIFICATE` | `ramflux.identity.master_certificate.v1` | 1 / offline master |
| `SIGNED_DEVICE_SET_V3` | `ramflux.identity.signed_device_set.v3` | 3 / certified self-signing key |
| `CUSTODY_BRANCH_CERTIFICATE` | `ramflux.identity.branch_certificate.v1` | 1 / certified self-signing key |
| `BRANCH_PROOF_V3` | `ramflux.branch_proof.v3` | 3 / certified device branch |
| `CUSTODY_DELEGATION` | `ramflux.identity.delegation.v1` | 1 / certified self-signing key |
| `CUSTODY_ERASURE_ACK` | `ramflux.identity.erasure_ack.v1` | 1 / erasing device branch |
| `CUSTODY_LEGACY_BINDING` | `ramflux.identity.legacy_binding.v1` | 1 / legacy root |
| `CONTACT_REQUEST_V2` | `ramflux.contact_request.v2` | 2 / certified self-signing key |
| `CUSTODY_RELAY_ACCEPTANCE` | `ramflux.identity.relay_acceptance.v1` | 1 / configured relay service signing key |
| `CUSTODY_TRANSFER_BINDING` | `ramflux.identity.transfer_binding.v1` | 1 / current old-primary branch |

Reuse existing key commitment domains:
`DEVICE_SIGNING_KEY_COMMITMENT = "ramflux.identity.device_signing_key.v1"` and
`DEVICE_AGREEMENT_KEY_COMMITMENT = "ramflux.identity.device_agreement_key.v1"`.
For these and the anchor, use the existing BLAKE3 `domain || raw_key_bytes`
construction, not the new object-envelope hash.

Limits are applied before allocation/crypto: v3 envelope 512 KiB; 1024 roster
entries; 1024 delegations; 1024 erasure ACKs; depth 16. Individual master/branch
certificates and binding/ACK/proof envelopes are at most 8 KiB, delegation 16 KiB,
contact envelope 128 KiB, SAS frame 16 KiB, transfer envelope 2 MiB with decrypted
handover body at most 1 MiB. Both element and enclosing byte limits apply: a large
roster may need renewal/ACK batches, never partial-roster publication. Permanent
tombstones count toward the limit. Reaching a limit is a typed refusal, not
permission to discard history or weaken verification.

## Anchors, identity and epochs

Define `Hroot(pk)` exactly as current `identity_root_commitment`:

```text
base64url(BLAKE3(UTF8("ramflux.identity.root_public_key.commitment.v1") || raw_pk))
```

New custody account: `account_anchor = Hroot(master_public_key)`,
`origin = "new"`, `legacy_binding = null`. Enter custody mode at genesis and
reject every v1/v2 record/proof even before a later numeric epoch is observed.
Master keys never sign legacy objects. Existing identifiers remain routing labels;
all authority indices/root-qualified references use the anchor. A legacy-shaped
first observation of a born-v3 anchor has no valid legacy master signature to
substitute for custody authority; capable verifiers must request v3 evidence.

Migrated account: `account_anchor = Hroot(legacy_root_public_key)`,
`origin = "migrated"`. Every v3 record carries the same legacy binding envelope;
the master key must equal the binding's master. The anchor, principal id and kind
remain unchanged. Fingerprints display the full canonical anchor (with optional
visual grouping). For custody safety-number v2, sort the two decoded 32-byte
anchors lexicographically and compute
`BLAKE3(UTF8("ramflux.safety_number.v2") || first_anchor || second_anchor)`.
Render that 32-byte fingerprint using the existing `safety_number` 12-group
rejection-sampling procedure and `"ramflux.safety_number.group.v1"` domain
in [key verification](../crates/ramflux-crypto/src/key_verification.rs).
Show the algorithm version. Current v1 safety material includes devices and
lineage, so its saved numeric value is not silently relabelled v2; require explicit
confirmation of the new comparison while preserving the pinned account anchors.
Keep roster-change verification/alerts and device-set hashes separately. A
self-signing-key or device-set change never changes the v2 identity comparison.

The epoch is one integer, not two independent floors:

```text
range_index in [1, 2097151]       # 2^21 - 1
revision    in [1, 4294967295]    # 2^32 - 1
device_set_epoch = range_index * 4294967296 + revision
range_index = floor(device_set_epoch / 4294967296)
revision = device_set_epoch modulo 4294967296
```

Revision zero is invalid. Maximum epoch is `9007199254740991`. The certificate's
range must equal the decoded range. First custody publication (including
migration) uses range 1/revision 1 independently of any legacy counter. Compare
verified heads by `(mode_rank, epoch)`, where legacy rank is 0 and custody rank is
1; this is an ordering rule, not another independently signed counter.

Pin exactly one authenticated master certificate hash per `(anchor, range)`.
Certificate-only observations may pin/fence the certificate identity after full
anchor/master authentication, but never advance the accepted record epoch or
grant operation authority without a verified complete v3 record.
A distinct valid certificate for that range, even with the same signing key but a
different id/body, is equivocation: fence that range, retain both as evidence,
alert and require a strictly higher master-certified range. Invalid signatures
cannot poison pins. Any higher range is acceptable, including gaps; no `+1` check.
Within a range, require strictly increasing revisions or the identical envelope
hash for retransmission. A same-epoch different valid record fences that head
until a higher non-conflicting authority head resolves it; no last-writer-wins.

Recovery selects `max(all observed authenticated ranges) + 1`, retries above
returned authenticated conflicts, and never wraps on exhaustion. Skipped ranges
are not missing authority. A higher range fences all older self-signing keys and
their certificates/delegations for new operations, regardless of remaining time.

## Master certificate body

`Envelope<MasterCertificate>` uses `CUSTODY_MASTER_CERTIFICATE`:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | Exact domain above, `1` |
| `account_anchor` | `B32` |
| `principal_id`, `principal_kind` | `Id`, `Kind` |
| `master_public_key` | Ed25519 `Key` |
| `self_signing_public_key` | Fresh Ed25519 `Key`, distinct from master and every branch |
| `primary_device_ref` | `Ref`; human account's primary is in its roster; external service custodian as below |
| `custody_kind` | `"local_human"` or `"external_human"`; local only for `human`, external required for service kinds |
| `scopes` | Sorted array of exactly `"branch_certify"`, `"contact_consent"`, `"delegate"`, `"device_set"`, `"profile"` |
| `range_index` | Positive integer in the epoch range above; no wildcard/end range |
| `issued_at` | `Time`, not more than 300 seconds in the future |
| `cert_id` | Random `B32` |
| `legacy_binding_hash` | `Hash` for migrated accounts; `null` for new accounts |
| `previous_certificate_hash` | `Hash` or `null` if no authenticated predecessor is available at first setup/recovery; never silently clears a retained pin |

No expiration of the master certificate itself: branch and delegation leases
expire, and higher ranges fence it. The master never signs device sets directly.
A service certificate's `primary_device_ref` must resolve to a verified `human`
account and a non-headless device with current custody authority. It is not a
branch in the service's roster. A self-asserted kind string cannot satisfy this
check; service-key storage is on that human's vault. Verifiers need the referenced
human authority chain; missing/unsupported evidence fails closed.

## Device-set v3 body

`Envelope<DeviceSetV3>` uses `SIGNED_DEVICE_SET_V3`:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | Exact domain, `3` |
| `principal_id`, `account_anchor`, `principal_kind` | `Id`, `B32`, `Kind`, equal to master certificate |
| `origin` | `"new"` or `"migrated"`, immutable |
| `custody_mode` | Exactly `"v3"` |
| `device_set_epoch` | Epoch above |
| `previous_record_hash` | `Hash` or `null` for first v3 publication/recovery with unavailable predecessor; retained floor/tombstones still apply |
| `issued_at` | `Time` |
| `master_certificate` | Complete signed master certificate envelope |
| `legacy_binding` | Complete signed binding envelope for migrated account, else `null` |
| `profile` | Unsigned `ProfileV3` below; never a signed v1 profile |
| `devices` | Complete array of `DeviceV3`, sorted by `device_id` UTF-8 bytes |
| `delegations` | Complete currently issued delegation envelopes, sorted by `body.delegation_id` |
| `revoked_delegation_ids` | Sorted array of `B32`, permanent tombstones, disjoint from active delegation ids |
| `migration` | `MigrationV3` or `null` for new accounts |

`ProfileV3` has exactly `kind: Kind`, `display_name: string`,
`custodian: Ref|null`. Kind equals the enclosing kind. Apply current
[profile normalization and text budgets](identity_profiles.md) before signing,
including single-line safety; do not normalize on verification. Custodian is null
for human accounts and equals the master certificate's external human reference
for service accounts. The profile has no signature and no separate epoch; its
version is the enclosing record epoch. Display-name changes require the primary
self-signing key and generate alerts even when all device fields are unchanged.

Each `DeviceV3` has exactly:

| Field | Type / requirement |
| --- | --- |
| `device_id`, `device_epoch` | `Id`, positive `U53` |
| `signing_key_commitment`, `agreement_key_commitment` | `B32`, existing commitment domains |
| `status` | `"active"` or `"revoked"` |
| `revoked_at` | `Time` iff revoked, otherwise `null` |
| `branch_certificate` | Complete signed certificate when active, `null` when revoked |
| `migration_state` | `"native"`, `"pending_erasure"`, `"erased"` or `"revoked"` |

Preserve every known device id and revoked tombstone; revoked entries are
immutable and cannot reactivate. Key changes require a higher device epoch and
new commitments. Lease-only renewal preserves key epochs. All active certificates
refer to the current master certificate and match this roster entry. Higher-range
recovery re-certifies survivors, carrying known tombstones forward. A verifier
without intervening heads still rejects omission of its retained tombstones;
fetch/reconcile missing state rather than silently clearing it.

`MigrationV3` has exactly `migration_id: B32`, `started_at: Time`,
`erase_deadline: Time`, `erasure_acks: Envelope<ErasureAck>[]` sorted by device id.
Its id equals the binding migration id; deadline equals `started_at + 2592000`
(30 days), both immutable. An ACK changes a pending entry to erased only in a
subsequently published record containing that ACK. At the deadline, pending
entries cannot authorize networking even if the primary has not yet published
the default revocation. A quota-limited erasure-only endpoint is their sole
exception; fresh enrollment is required after revocation. New records cannot
extend the deadline. Native entries occur only on new accounts or devices added
after migration; migration cannot relabel existing legacy devices as native.

## Branch certificate and possession proof

`Envelope<BranchCertificate>` uses `CUSTODY_BRANCH_CERTIFICATE`:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | Exact domain, `1` |
| `account_anchor`, `master_certificate_hash` | `B32`, `Hash` |
| `device_id`, `device_epoch`, `principal_kind` | `Id`, positive `U53`, `Kind` |
| `branch_signing_public_key`, `agreement_identity_public_key` | Ed25519 `Key`, X25519 `Key` |
| `capabilities` | Sorted nonempty array from `"call"`, `"group"`, `"message"`, `"register"`, `"sync"`; no authority-management permission |
| `not_before`, `expires_at` | `Time`, `0 < expires_at - not_before <= 2592000` |
| `cert_id` | Random `B32` |

The self-signing signature covers keys, capabilities and validity. Check key
commitments against the roster, not only device-id inclusion. Certificate renewal
needs the primary; session proof renewal during a valid lease does not.

`Envelope<BranchProofV3>` uses `BRANCH_PROOF_V3`:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | Exact domain, `3` |
| `device_ref` | `Ref` |
| `certificate_hash`, `record_hash` | `Hash`, exact supplied verified certificate/head |
| `proof_id`, `challenge_nonce` | Fresh `B32`, one-use challenge issued by the receiving verifier |
| `audience` | `Id`, exact recipient service identity, never a wildcard |
| `transport_binding` | `B32`, SHA-256 of the authenticated session exporter/binding bytes |
| `issued_at`, `expires_at` | `Time`, `0 < expires_at - issued_at <= 300` |

Proof is signed by the certified branch, checked against current authority per
request, and consumed atomically in the receiver's replay cache through expiry
plus skew. A retry uses a new challenge and proof id. Missing channel-binding
support fails closed; it cannot be represented by a constant or empty value.
For TLS 1.3/QUIC use 32 exporter bytes with label
`"EXPORTER-ramflux-branch-proof-v3"` and context equal to the raw challenge nonce,
then SHA-256 those bytes. A WebSocket uses its underlying TLS connection exporter.
Other transports require a separately reviewed binding profile before v3 support;
never infer authentication from a network address.
Neither a valid TLS session nor a proof pins stale authorization for its duration.

## Delegation body

`Envelope<Delegation>` uses `CUSTODY_DELEGATION`:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | Exact domain, `1` |
| `account_anchor`, `master_certificate_hash` | `B32`, `Hash` |
| `self_signing_public_key` | Ed25519 `Key`, equal to certificate |
| `delegate` | `Ref`, own active branch only |
| `branch_certificate_hash` | `Hash`, must equal current branch certificate |
| `delegation_id` | Random `B32` |
| `scope` | `"create_group"` or `"creator_group"` |
| `group_id`, `group_genesis_hash` | Both `Id`/`Hash` for creator group, both `null` for account-level create-group |
| `operations` | Sorted: exactly `["genesis"]` for create-group; nonempty subset of `"request_result"`, `"snapshot"` for creator group |
| `not_before`, `expires_at` | `Time`, `0 < expires_at - not_before <= 604800` (7 days) |
| `subdelegation` | Exactly `false` |

Only current, roster-included, non-revoked delegations apply. Lease renewal
issues a new delegation bound to the new branch certificate; prior ids are fenced
by certificate mismatch or revocation. Group ownership transfer, changing branch
keys, device revocation and a higher master range all fence old delegations.
Delegation authorizes only the creator's existing group powers, retaining current
fresh-head/countersign/removal rules. It never grants account/device management.

## Erasure ACK and proposed legacy binding bodies

`Envelope<ErasureAck>` uses `CUSTODY_ERASURE_ACK`, signed by the erased branch:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | Exact domain, `1` |
| `device_ref` | `Ref` |
| `migration_id` | `B32`, current migration |
| `migration_record_hash` | `Hash`, the signed initial migration v3 record |
| `branch_certificate_hash` | `Hash`, certificate authorizing the erasure endpoint |
| `ack_id` | Random `B32`; reuse on retransmission |
| `erased_at` | `Time` |
| `erased_legacy_root`, `erased_unauthorized_self_signing_material` | Both exactly `true` |

The primary retains only its currently authorized self-signing key; that key is
not covered by the unauthorized-material erasure assertion. A secondary must erase
all self-signing material. The initial migrating primary also ACKs its legacy-root
erasure through the restricted migration endpoint; only after publication of the
ACK may its roster state become erased. This avoids treating an existing legacy
primary as a native device or requiring it to erase the new management key.

ACK is a cooperative software claim, not attestation. Verify using the branch
certificate/commitments at the referenced migration record and current erasure
eligibility; reject key substitution, wrong migration and replays across epochs.
Storing an ACK off-record does not complete erasure state. Preserve the initial
record as public migration evidence for ACK verification after range recovery.

`Envelope<LegacyBinding>` uses `CUSTODY_LEGACY_BINDING`, signed by legacy root:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | Exact domain, `1` |
| `account_anchor`, `legacy_root_public_key` | `B32`, Ed25519 `Key`; `Hroot(key) == anchor` |
| `principal_id`, `principal_kind` | `Id`, `Kind`, immutable legacy values |
| `master_public_key` | Ed25519 `Key`, proposed permanent master |
| `migration_id` | Random `B32` |
| `last_legacy_record_hash`, `last_legacy_epoch` | `Hash`, positive `U53`, verified legacy head at migration |
| `issued_at` | `Time` |

The referenced legacy record must authenticate the anchor, id and kind; a known
newer legacy head needs reconciliation before first transition. A high legacy
epoch cannot defeat the mode-rank rule. The binding has no secrets and no recovery
ciphertext, but must remain discoverable for phrase-only legacy recovery.

Two distinct valid binding hashes for one anchor mean `identity_compromised`:
retain both, alert, suspend both alternatives and do not automatically pick the
first or the numerically newer migration. Re-attestation requires a new
higher-range master certificate whose `legacy_binding_hash` selects the binding,
signed by the **already trusted** master (or independently reverified master for
a fresh observer), plus a valid v3 record carrying it. This does not authorize a
master change. If that trust cannot be established, remain blocked and offer new
identity with local history. A master selected solely from one conflicting binding
cannot certify itself as the resolution. Historical conflicts remain visible.

## Contact consent v2

This replaces root-signed v1 request/accept/decline in
[contact request wire](../crates/ramflux-sdk/src/client/contact_requests/wire.rs).
`Envelope<ContactConsentV2>` uses `CONTACT_REQUEST_V2`, signed by the current
self-signing key, not by a secondary or the offline master:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | Exact domain, `2` |
| `kind` | `"request"`, `"accept"`, `"decline"` |
| `request_id`, `nonce` | `B32`; retain current `ramflux.contact_request.id.v1` request-id construction |
| `requester_root`, `target_root`, `actor_root` | `B32` account anchors; these historical field names never mean self-signing public keys |
| `sending_device_ref` | `Ref`, exact authenticated transport source, anchor equals actor |
| `issued_at`, `expires_at` | `Time`, `expires_at = issued_at + 604800` |
| `note` | `string|null`, current safe single-line 140-character limit |
| `actor_record_hash`, `master_certificate_hash` | `Hash`, current authority approving this exact intent |

Authority envelopes are resolved by hash through the authenticated identity
lookup; never substitute a current record for the signed hash. Request actor is
requester; accept/decline actor is target. Keep v1 conversation-id derivation and
routing/endpoint equality checks, source branch possession, request-id matching
and existing replay/consent-state rules. The certified management key approves
exact body bytes including the sending branch. A secondary queues an intent for
primary approval and waits; the request is pending while primary is offline.
If approval head is stale at send time, require fresh approval. Legacy accounts
retain v1 until migrated; custody senders/receivers require v2 support and never
obtain/sign with the legacy root for interoperability.

## Queued-message acceptance evidence

`Envelope<RelayAcceptance>` uses `CUSTODY_RELAY_ACCEPTANCE`. Its signer is the
configured authenticated relay service signing key, never an identity branch or
a key accepted solely because the receipt supplies it. The body has exactly
`schema` (domain above), `version: 1`, `relay_id: Id`, `receipt_id: B32`,
`source_device_ref: Ref`, `target_anchor: B32`, `message_hash: Hash`,
`branch_certificate_hash: Hash`, `accepted_at: Time`. It attests durable acceptance
of those exact signed message bytes under that certificate; `message_hash` uses
the object hash convention above on the message's complete signed JSON object.
At most 8 KiB per receipt. The relay checks live branch authority when accepting,
not just when emitting the receipt; it must never issue an earlier acceptance time
for a message received after lease expiry. A repeated receipt is idempotent only
for the same exact message/source/target. Receipt authenticity still assumes a
trusted relay clock and service key; a compromised relay can lie about acceptance
time. Messages without this receipt cannot use the post-expiry queued exception.
This is a proposed new receipt profile, not a claim that existing relay ACKs
already supply this evidence.

## Time and verification order

Use verifier-local trusted time `now`, skew `S = 300` seconds. A lease is live iff
`not_before - S <= now <= expires_at + S`. Check original positive duration
without skew: skew never extends the signed maximum. Fresh proof/consent must
satisfy `issued_at <= now + S` and `now <= expires_at + S`, plus current branch
lease, epoch/range, capability, revocation and replay checks. Use checked arithmetic.

Queued-message exception is for previously accepted messages, not fresh
registration, delegation mutations or new sends. The branch-signed message time
`t` and authenticated relay acceptance time `a` must each lie in
`[not_before - S, expires_at + S]`, and `t <= a + S`, `a <= now + S`.
Require relay acceptance evidence bound to the exact signed-message hash and
source, authenticated by the configured relay service identity. Missing evidence
fails the exception; a self-claimed relay timestamp is insufficient. Current
revocations and retained authority floors still apply. Already pinned local history
remains readable regardless of current lease. Persist authenticated-time high-water
marks; rollback/unknown time blocks new authorization, never local history reading.

Every verifier (SDK, router, gateway/directory, federation, peers) performs:

1. Enforce byte/count/depth limits, I-JSON, exact versions/fields and canonical
   encodings; load durable anchor/mode/epoch/certificate/binding pins and tombstones.
2. Authenticate new anchor or legacy binding path. For migration, verify the old
   root signature and referenced legacy head; require binding on every v3 record.
   Compare master against the retained pin, never trust keys just because supplied.
   Conflicting valid bindings enter compromise handling above. New anchors prohibit
   legacy paths; no v1 master signature may be requested or accepted.
3. Verify master certificate signature and all identity, scope, custodian, time,
   legacy-binding-hash and range constraints. Compute the candidate certificate
   hash; stage a pin/conflict update only after full authentication. A claimed
   conflict with an invalid signature is
   only an invalid input, not an authority event.
4. Check epoch encoding/certified range, then verify the record self-signing
   signature over its full body, including nested envelopes. Only fully verified
   competing certificates/records may fence a range/head. Compare mode rank first,
   then epoch; exact retransmission is idempotent. Accept higher ranges with gaps.
5. Verify complete roster, key commitments, branch certificates, delegation
   envelopes, erasure evidence and unsigned profile constraints. Enforce immutable
   id/kind/origin/master, retained tombstones and primary/custodian role. Do not
   clear a known floor because predecessor material is unavailable; reconcile.
6. Atomically persist the accepted head/floor, master/binding/certificate pins and
   custody latch **before** granting authority or returning durable success. On a
   valid conflict persist the fence/evidence instead and grant no new authority.
   Backups, cache eviction and restart cannot clear these values.
7. For an operation, require current authority fetched at most 300 seconds ago;
   refresh failure has no stale-cache fallback. Check operation-specific branch
   possession, key epoch, capability, leases, replay/audience/transport binding
   and exact head. Contact consent additionally verifies the self-signing approval.
   No session, delegation or erasure ACK overrides a higher retained floor.
8. Generate persistent alerts from authenticated state changes, including roster
   additions, delegation issuance, display-name changes and removed-device state.
   Primary/self-signing changes are blocking alerts; no alert opens a phrase form.

An isolated verifier cannot prove globally latest state. Records and trusted
checkpoints reveal withholding only when compared; no clock or signature removes
that limit. Return typed update-required, range-conflict, compromised-binding,
stale-head, expired-lease, unknown-time and capacity/exhaustion failures rather than
falling back to root access or auto-creating an identity.

## SAS labels and primary handover

Invitation transport uses the existing device-pair session/routed path with a
restricted pre-enrollment bootstrap. QR/typed invitation ids only rendezvous;
no enrollment request is accepted before mutual SAS confirmation. Use seven
[Matrix emoji indices/names](https://spec.matrix.org/v1.16/client-server-api/#sas-method-emoji)
(42 bits); TUI displays their standard names, no decimal format. User mismatch
immediately consumes/cancels the invitation. Three transport/protocol failures
also consume it; maximum three live invitations and ten creations per hour.

The invitation has a five-minute lifetime. The primary's confirmed invitation
stores the expected anchor/head/purpose; changed authority invalidates the run
and requires a fresh invitation. The transcript is JCS of exactly `schema: "ramflux.identity.pairing_transcript.v1"`,
`version: 1`, `invitation_id: B32`, `account_anchor: B32`,
`master_public_key: Key`, `record_hash: Hash`, `device_set_epoch: U53`,
`principal_kind: Kind`, `purpose: "enroll"|"primary_transfer"`,
`requested_role: "secondary"|"primary"`, `capabilities: string[]` (branch vocabulary,
sorted), `initiator_sas_key: Key`, `responder_sas_key: Key` (X25519),
`initiator_branch_key: Key`, `responder_branch_key: Key` (Ed25519),
`responder_agreement_key: Key` (X25519), `sender_hpke_key: Key|null`,
`recipient_hpke_key: Key|null` (X25519, non-null only on primary transfer),
`sas_suite: "ramflux.identity.pairing.sas_emoji.v1"` and
`hpke_suite: "auth_x25519_hkdf_sha256_aes256gcm"|null`.
Initiator is the old primary. `transcript_hash` is
`SHA-256(UTF8("ramflux.identity.pairing.transcript.v1") || transcript)`.

Before public-key reveal each party commits to
`SHA-256(UTF8("ramflux.identity.pairing.commitment.v1") || role_byte ||
random_32_byte_salt || own_raw_sas_key || invitation_id_raw)`;
role byte is 0 for initiator, 1 for responder. Exchange both commitments before
either reveal; salts and keys are fixed once, and mismatch cancels. These exact
commitment/transcript bindings need provider adaptation review and vectors: a
historical library audit is not an audit of this new flow.

HKDF-SHA256 uses the X25519 shared secret as IKM, transcript hash as salt and
`"ramflux.identity.pairing.sas.v1"` as info, producing six bytes. Take the first
42 bits in network bit order as seven 6-bit Matrix emoji indices; discard the
remaining six bits. Separate 32-byte HKDF outputs use info
`"ramflux.identity.pairing.confirm.initiator.v1"` and
`"ramflux.identity.pairing.confirm.responder.v1"`; HMAC-SHA256 of transcript hash
proves each role's key possession only after its local human confirmation.
All labels are UTF-8 without NUL. Derive distinct direction channel keys using
`"ramflux.identity.pairing.channel.initiator.v1"` and
`"ramflux.identity.pairing.channel.responder.v1"` (32 bytes each), with
ChaCha20-Poly1305, 96-bit big-endian message counters starting at zero per
direction, transcript hash as AAD. Reject replay/out-of-order counters; destroy
keys at invitation expiry/cancellation. Only after both MACs and human confirmations
may this channel carry the exact enrollment proposal and approval. Stage-1 review
must validate this adaptation and provider pin before any implementation activation.

For primary transfer choose [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)
Auth mode `0x02`, KEM `0x0020` (DHKEM(X25519, HKDF-SHA256)), KDF `0x0001`
(HKDF-SHA256), AEAD `0x0002` (AES-256-GCM), no PSK. `skS` is the old primary's
fresh transfer-only sender key from the SAS transcript; `pkR` is the destination's
fresh HPKE key from that same transcript. This authenticates the sender without
reusing Ed25519 as X25519 or leaving Base-mode ciphertexts unauthenticated.
The following exact bytes bind context, with no delimiter ambiguity:

```text
info = UTF8("ramflux.custody.transfer.hpke.v1") || raw_transcript_hash
# hash is fixed 32 bytes
AAD = JCS({"schema":"ramflux.identity.transfer.aad.v1", "version":1,
           "transfer_id":transfer_id, "current_record_hash":current_record_hash,
           "device_set_epoch":current_epoch})
```

One `SetupAuthS`/`SetupAuthR` context, one `Seal`/`Open` at sequence zero, then
destroy it. No streaming/multiple sequence numbers and no HPKE key reuse. Public
transfer envelope has exactly `schema: "ramflux.identity.transfer.hpke.v1"`,
`version: 1`, `transfer_id: B32`, `transcript_hash: B32`,
`current_record_hash: Hash`, `device_set_epoch: U53`, `sender_binding:
Envelope<TransferBinding>`, `enc: B32`, `ciphertext: base64url`.
Mode/suite are fixed above and cannot be negotiated down.

`TransferBinding` uses `CUSTODY_TRANSFER_BINDING`, signed by the old primary's
current branch, with exactly `schema`, `version: 1`, `transfer_id: B32`,
`transcript_hash: B32`, `current_record_hash: Hash`, `device_set_epoch: U53`,
`sender_device_ref: Ref`, `sender_hpke_key: Key`, `recipient_hpke_key: Key`,
`issued_at: Time`, `expires_at: Time` (at most 300 seconds later and within the
invitation lifetime). Require branch possession, old-primary role, the SAS-pinned
keys and current head. This makes the transfer-only Auth sender key traceable to
existing authority, rather than trusting a key sent beside a ciphertext.

The decrypted JCS handover body has exactly:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | `"ramflux.identity.transfer.payload.v1"`, `1` |
| `transfer_id`, `transcript_hash`, `current_record_hash` | `B32`, `B32`, `Hash`, identical to envelope/AAD context |
| `device_set_epoch` | `U53`, identical to current epoch |
| `pending_invitations` | Array of `{invitation_id: B32, expires_at: Time, proposal_hash: Hash|null}`; public metadata only, cancel/restart incomplete handshakes |
| `journal` | Array of `{operation_id: B32, intent_hash: Hash, state: "pending"|"acknowledged", acknowledgement_hash: Hash|null}`; acknowledged requires hash |
| `delegation_state` | Array of signed delegation envelopes currently in the head |
| `pending_erasure` | Sorted array of `Ref`, equal to pending head entries |
| `optional_data_keys` | Array of `{key_id: Id, purpose: "history"|"attachment", key: B32}`, empty unless user explicitly selects data transfer |

Each array is bounded by 1024 entries; total plaintext at most 1 MiB. No phrase,
master/self-signing seed, branch seed, vault secret or live SAS secret is allowed.
Validate the decrypted contents against current state before staging. Journal a
transfer id and ciphertext hash once; an exact retry returns the saved result,
a different ciphertext under that id fails. Accepted/expired/cancelled transfer
ids are permanently consumed; a crash cannot restart their signing effect.

The destination separately derives the master from the user-entered phrase,
creates a fresh self-signing key/certificate at a higher range and publishes its
record. Handover receipt alone never promotes it. Require exact durable record
ACK before activation; old device demotion/erasure remains observable cleanup.
Destroy transfer/SAS keys on completion, expiry and cancellation. Lost-primary
recovery needs no HPKE sender and follows the same higher-range publication rules.

## Implementation review gates

Stage 1 must approve exact bodies/domains, legacy policy, epoch ranges, signer
inventory, provider pins/audit delta, vault failure semantics and mixed-version
behaviour. Publish cross-client JCS/signature/hash vectors for every body, max
epoch/skipped ranges/conflicts, invalid I-JSON and unsupported versions; RFC 9180
suite vectors (including Auth mode 2 / KEM 32 / KDF 1 / AEAD 2 from the
[RFC-linked vector corpus](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json))
plus application transcript/AAD/substitution/replay vectors; SAS
commitment/MAC/emoji mapping vectors and full-flow recovery benchmark plan.
Do not describe those planned vectors as already published by this document.

Stage 2a produces a complete source-reviewed private-root-use appendix. Stage 2b
cannot begin until that inventory, this wire spec and vectors pass independent
review. It implements every verifier before enabling v3 writers. Existing legacy
accounts retain one-hour branch proofs and current group/contact behaviour until
opt-in migration. Capability negotiation (`custody_v3`, `contact_consent_v2`,
`group_delegation_v1`) never strips v3 evidence for old federation/group peers;
unsupported combinations block with update-required, as described in the design.
