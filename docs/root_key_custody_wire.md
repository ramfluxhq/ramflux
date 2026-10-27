<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Root key custody wire specification

Design revision 5, proposed normative stage-1 specification. This document and
[root key custody](root_key_custody.md) describe future behaviour, not executable
support. Independent wire review and published interoperability vectors are
required before stage 2b. The legacy binding remains a proposal **pending owner confirmation**. The controller has approved epoch ranges with the r3 amendments below; exact wire formats and
vectors still require independent review. No migration writer may ship on the
assumption that the legacy-binding proposal has been approved.

## Encoding, signatures and limits

All objects use UTF-8 I-JSON and [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html).
Reject duplicate keys, malformed Unicode, unknown fields, non-finite/fractional
numbers, negative counters, unsafe integers and unknown versions before checking
signatures. Integer fields require unsigned decimal JSON tokens (`0` or
`[1-9][0-9]*`), without decimal points or exponents. JCS does not normalize strings;
only the documented phrase and profile input rules normalize human input before signing. Never normalize an
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
| `Hash` | `B32`; signed-object references use `object_hash`, section/list fields use their explicit domain below; never a public key |

For each signed body `B` with domain `D`, including the v3 record, sign exactly:

```text
signing_bytes(D, B) = JCS({"domain": D, "body": B})
signature = Ed25519.Sign(signer_seed, signing_bytes(D, B))
object_hash(E) = base64url(BLAKE3(
    UTF8("ramflux.identity.custody.object_hash.v1") || 0x00 || JCS(E)))
```

For every new BLAKE3/SHA-256 label with appended input, use
`frame(D, input) = UTF8(D) || 0x00 || input`. Labels contain no NUL; this makes
label/input boundaries unambiguous. Existing `blake3_hash_bytes` appends its input
to the label without framing: future custody callers supply the leading `0x00`
in its input, rather than changing that shared helper and breaking legacy ids.
HKDF info consisting only of a label stays its exact UTF-8 bytes; HPKE info with
a transcript suffix uses the same explicit frame. The master-seed KDF retains
its r2 bare-label info. Signature separation uses JCS object fields, not raw
concatenation. Legacy commitment and rendering domains retain their old bytes.

`B.schema` equals `D`; `B.version` equals the table's integer. Domain strings
contain no trailing NUL/newline. Use strict Ed25519 verification, matching current
crypto validation; no Ed25519ph and no generic recursive signature stripping.
Nested envelopes, including their signatures, remain in the enclosing signed
body. Arrays of `Ref` sort by decoded anchor bytes, then device-id UTF-8 bytes,
then numeric device epoch. An object's hash includes its signature. Random
ids/nonces use 32 bytes of OS CSPRNG output (`B32`), stored once for idempotent retries. Never regenerate a
certificate or binding on a retry in the same range.

These conventions define future v3 envelopes; they do not change flat v1/v2
signing bytes. All new labels below are now reserved in
[domain.rs](../crates/ramflux-protocol/src/domain.rs), including `ALL`; reservation
alone enables no custody decoder, signing path or verifier. Uniqueness, absence
of NUL and prefix-freeness are tested across the entire registry. All new labels
use `ramflux.identity.`. The transcript schema and hash label deliberately share
one constant and spelling: `ramflux.identity.pairing_transcript.v1`.

| Constant | Exact label | Purpose |
| --- | --- | --- |
| `CUSTODY_MASTER_CERTIFICATE` | `ramflux.identity.master_certificate.v1` | signature: master certificate |
| `SIGNED_DEVICE_SET_V3` | `ramflux.identity.signed_device_set.v3` | signature: complete v3 record |
| `CUSTODY_BRANCH_CERTIFICATE` | `ramflux.identity.branch_certificate.v1` | signature: branch certificate |
| `BRANCH_PROOF_V3` | `ramflux.identity.branch_proof.v3` | signature: branch possession proof |
| `CUSTODY_DELEGATION` | `ramflux.identity.delegation.v1` | signature: public account-level delegation |
| `CUSTODY_GROUP_DELEGATION` | `ramflux.identity.group_delegation.v1` | signature: private group restriction/delegation |
| `CUSTODY_ERASURE_ACK` | `ramflux.identity.erasure_ack.v1` | signature: erasure acknowledgement |
| `CUSTODY_LEGACY_BINDING` | `ramflux.identity.legacy_binding.v1` | signature: proposed legacy binding |
| `CONTACT_REQUEST_V2` | `ramflux.identity.contact_request.v2` | signature: contact consent |
| `CUSTODY_RELAY_ACCEPTANCE` | `ramflux.identity.relay_acceptance.v1` | signature: receiver-home relay evidence |
| `CUSTODY_TRANSFER_BINDING` | `ramflux.identity.transfer_binding.v1` | signature: transfer sender binding |
| `CUSTODY_REVOKED_CHECKPOINT` | `ramflux.identity.revoked_devices.checkpoint.v1` | signature: revoked-device checkpoint |
| `CUSTODY_NODE_RECORD` | `ramflux.identity.node_record.v1` | signature: proposed node identity record |
| `CUSTODY_TIME_ATTESTATION` | `ramflux.identity.time_attestation.v1` | signature: fresh node time attestation |
| `CUSTODY_MASTER_SEED` | `ramflux.identity.master.v1` | HKDF info: master seed; unchanged r2 derivation |
| `CUSTODY_OBJECT_HASH` | `ramflux.identity.custody.object_hash.v1` | BLAKE3: signed-object hash |
| `CUSTODY_SECTION_HASH` | `ramflux.identity.custody.section_hash.v1` | BLAKE3: record-section hash |
| `CUSTODY_SAFETY_NUMBER` | `ramflux.identity.safety_number.v2` | BLAKE3: anchor safety fingerprint |
| `CUSTODY_PAIRING_TRANSCRIPT` | `ramflux.identity.pairing_transcript.v1` | schema and SHA-256: pairing transcript; one shared spelling |
| `CUSTODY_PAIRING_COMMITMENT` | `ramflux.identity.pairing.commitment.v1` | SHA-256: SAS key commitment |
| `CUSTODY_PAIRING_SAS` | `ramflux.identity.pairing.sas.v1` | HKDF info: SAS bytes |
| `CUSTODY_PAIRING_CONFIRM_INITIATOR` | `ramflux.identity.pairing.confirm.initiator.v1` | HKDF info: initiator confirmation |
| `CUSTODY_PAIRING_CONFIRM_RESPONDER` | `ramflux.identity.pairing.confirm.responder.v1` | HKDF info: responder confirmation |
| `CUSTODY_PAIRING_CHANNEL_INITIATOR` | `ramflux.identity.pairing.channel.initiator.v1` | HKDF info: initiator channel |
| `CUSTODY_PAIRING_CHANNEL_RESPONDER` | `ramflux.identity.pairing.channel.responder.v1` | HKDF info: responder channel |
| `CUSTODY_PAIRING_EMOJI_SUITE` | `ramflux.identity.pairing.sas_emoji.v1` | suite tag: Matrix emoji SAS mapping |
| `CUSTODY_TRANSFER_HPKE_INFO` | `ramflux.identity.transfer.hpke_info.v1` | HPKE info label |
| `CUSTODY_TRANSFER_AAD` | `ramflux.identity.transfer.aad.v1` | schema: HPKE associated data |
| `CUSTODY_TRANSFER_HPKE` | `ramflux.identity.transfer.hpke.v1` | schema: HPKE transfer envelope |
| `CUSTODY_TRANSFER_PAYLOAD` | `ramflux.identity.transfer.payload.v1` | schema: handover payload |
| `CUSTODY_TRANSFER_HPKE_SUITE` | `ramflux.identity.transfer.hpke_suite.v1` | suite tag: Auth/X25519/HKDF-SHA256/AES-256-GCM |
| `CUSTODY_BRANCH_EXPORTER` | `ramflux.identity.branch_proof.exporter.v3` | TLS exporter label: client-facing connection in every mode |
| `CUSTODY_REVOKED_LIST` | `ramflux.identity.revoked_devices.list.v1` | BLAKE3: sorted compacted revoked-id list |
| `CUSTODY_TIME_PROBE` | `ramflux.identity.time_probe.v1` | schema: restricted time-recovery probe |

Reuse existing key commitment domains:
`DEVICE_SIGNING_KEY_COMMITMENT = "ramflux.identity.device_signing_key.v1"` and
`DEVICE_AGREEMENT_KEY_COMMITMENT = "ramflux.identity.device_agreement_key.v1"`.
For these and the anchor, use the existing BLAKE3 `domain || raw_key_bytes`
construction, not the new object-envelope hash.

Limits are applied before allocation/crypto: v3 envelope 512 KiB; 1024 roster
entries (active plus recent tombstones); 1024 account delegations; 1024 erasure ACKs; depth 16. Individual master/branch
certificates and binding/ACK/proof envelopes are at most 8 KiB, delegation 16 KiB,
contact envelope 128 KiB, SAS frame 16 KiB, transfer envelope 2 MiB with decrypted
handover body at most 1 MiB. Both element and enclosing byte limits apply: a large
roster may need renewal/ACK batches, never partial-roster publication. Revocations
older than 90 days move into the signed checkpoint below; compacted entries do
not consume the 1024 roster slots. Revocation knowledge is never discarded to
make room. Streaming checkpoint-list pages are individually bounded at 64 KiB;
The cumulative canonical list is capped at 65,536 ids and 4,194,304 bytes;
predecessor-linked deltas and full reconstruction obey both bounds. List
verification is resumable with bounded memory and disk-backed membership.
Reaching an active/recent capacity or byte limit is a typed refusal, not authority
to erase revocations.

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
`BLAKE3(frame("ramflux.identity.safety_number.v2", first_anchor || second_anchor))`.
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
| `devices` | Complete active/recent array of `DeviceV3`, sorted by `device_id` UTF-8 bytes; aged revocations covered by checkpoint |
| `delegations` | One account-level delegation per verified secondary, sorted by `body.delegation_id`; no group-specific envelopes or group ids |
| `revoked_delegation_ids` | Sorted account-level `B32` ids, disjoint from active ids; group-specific ids/revocations remain encrypted within their groups |
| `migration` | `MigrationV3` or `null` for new accounts |
| `revoked_device_checkpoint` | `Envelope<RevokedCheckpoint>` or `null` before first compaction |
| `section_hashes` | Exact per-section hash object defined below |

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

A revoked device id can never reactivate, at any device epoch. Key changes for
active devices require a higher device epoch and new commitments; lease renewal
preserves key epochs. Active certificates refer to the current master certificate.
A device id moves from the recent revoked roster into the checkpoint only after
90 days, with no gap in denial. Higher-range recovery preserves all recent and
compacted revocations. Missing predecessor/list evidence cannot clear a retained
revocation; fetch/reconcile it before granting authority.

### Section hashes, conditional fetch and retention

`section_hashes` has exactly the keys `profile`, `devices`, `delegations`,
`revoked_delegation_ids`, `migration`, `revoked_device_checkpoint`, each a `B32`:

```text
section_hash(name, value) = base64url(BLAKE3(frame(
    "ramflux.identity.custody.section_hash.v1",
    JCS({"section": name, "value": value}))))
```

Hash `null` as JCS null, never omission. The logical signed record still includes
all section bodies and these hashes, so no detached body gains authority by its
hash alone. Conditional fetch accepts the verifier's pinned `known_head_hash`
and cached section hashes. A `not_modified` result returns that exact head hash
and no bodies; it is usable only with an already verified complete matching cached
record and a retained floor no higher than it. A changed-head result returns the
non-section body fields, signature, all section hashes and only changed/missing
section bodies. Reconstruct the full logical record from verified cached sections
and supplied bodies; check every section hash, full record hash and signature
before advancing a floor. An evicted section is fetched by hash within its byte
budget; a partial reconstruction grants no authority. Never treat a claimed new
head hash or a section hash as an authenticated head on its own.

The transport request has exactly `account_anchor: B32`,
`known_head_hash: Hash|null`, `cached_section_hashes: object` (a subset of the six
section names mapped to B32 hashes). The response has exactly `status:
"modified"|"not_modified"`, `head_hash: Hash`, `header: object|null`,
`sections: object`. In not-modified mode header is null and sections is empty;
head_hash must equal the requested known hash, never null or an unknown head.
In modified mode header has exactly `body_fields: object`, `signature: Sig`.
body_fields contains every DeviceSetV3 field except the six section-valued fields,
including the full section_hashes map. sections maps only requested missing/changed
section names to their logical values. Unknown keys and a missing reconstruction
component fail closed. Header.signature is the complete record signature, **not**
a separately valid signature over body_fields; assemble the six values into the
body and then verify. Return omitted unchanged sections by hash on request.
The request is at most 4 KiB, the response at most 1 MiB, and the reconstructed
logical record still obeys its 512 KiB limit; per-section parsing is bounded before
allocation. A caller's cache claims are hints, not authentication evidence.

At each 300-second freshness check request the head conditionally. Routine lease
renewal changes the relevant device/delegation section; it must not force a peer
to download unchanged profile, migration or checkpoint bodies. A renewal with an
unchanged head returns `not_modified`. Authenticated transport and retained pins
still apply; a malicious directory can withhold a newer head as before.

Directories/home nodes retain and serve every superseded v3 record by full hash
until at least 604800 + 900 seconds after supersession (or the latest known
consent expiry plus skew, whichever is later). The extra 900 seconds cover the
300-second current-head cache bound plus issue and receive skew, without changing
the consent TTL or requiring a public consent-reference index. They
retain permanently the initial migration record, its referenced last legacy head,
legacy binding, checkpoint envelopes/lists and their verification material. Section
blobs remain available for as long as any retained record references them. Migration
and legacy evidence never expires with a consent TTL; all of it is public auth
metadata, containing no recovery secret. Failure to fetch required evidence is a
typed unavailable result, never permission to substitute a current head.

### Revoked-device compaction

Only tombstones with `revoked_at < now - 7776000` (strictly older than 90 days)
may leave the inline roster. Before publishing, the primary creates
`Envelope<RevokedCheckpoint>` under `CUSTODY_REVOKED_CHECKPOINT` with exactly:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | Exact checkpoint domain, `1` |
| `account_anchor`, `master_certificate_hash` | `B32`, `Hash`, current account/certificate |
| `device_set_epoch` | `U53`, compaction/re-sign epoch at or below enclosing record in the same range |
| `previous_checkpoint_hash` | `Hash` or `null` for first checkpoint |
| `list_hash`, `count` | `Hash`, positive `U53` |
| `compacted_before`, `issued_at` | `Time`; cutoff no newer than `issued_at - 7776000` |

Its signature is by the primary's current self-signing key. The committed list is
the full cumulative, unique array of revoked **device ids**, sorted by UTF-8 bytes:
`list_hash = base64url(BLAKE3(frame("ramflux.identity.revoked_devices.list.v1",
JCS(sorted_ids))))`. Device ids are anchor-qualified by the checkpoint and may
never be reused at a different epoch. The inline removed tombstones must all be
in the new list, and all previously checkpointed ids must remain. The count is the
exact array length, never an estimate or a substitute for membership evidence.

The cumulative list is capped at **65,536 ids and 4 MiB (4,194,304 bytes)** of
canonical JCS, including brackets, commas and UTF-8 string encoding. Enforce both
limits before accepting a checkpoint and during bounded fetch/decoding, with pages
at most 64 KiB. The 1024 inline-roster cap separately counts active devices and
recent tombstones; neither budget can be bypassed by moving entries between them.

A flat sorted-list hash + count is not a membership/non-membership proof. A first
observer fetches the bounded complete list, verifies order, uniqueness, count and
hash, and builds a disk-backed membership index. Existing verifiers fetch only
additions since their last fully verified checkpoint, following
`previous_checkpoint_hash`. A delta response has exactly `checkpoint_hash: Hash`,
`previous_checkpoint_hash: Hash`, `additions: Id[]`; it is a transport hint, not
independently authoritative. Additions are sorted, unique and disjoint from the
verified predecessor index. Merge them locally with that index, re-hash the full
canonical sorted array, and require the signed successor's exact count/list hash.
Only then atomically advance the verified checkpoint/index. No removals are
allowed. Empty additions are valid for unchanged-list re-signing. Every successor
must authenticate under the retained certificate chain and anchor. Delta bytes,
entries and reconstructed list obey the same caps; interrupted fetches cannot
advance pins. A skipped link requires its intervening authenticated checkpoints
and deltas; absent local predecessor evidence requires a bounded full fetch.

Cached verified bytes/index may be reused by list hash. Missing, truncated or
budget-interrupted evidence blocks affected authorization, never means "not
revoked". Check inline tombstones and the verified index for enrollment,
re-enrollment, proofs and operations. Retain previous checkpoints/lists/deltas for
superset verification. A fresh observer still cannot prove globally latest state.
Certificate/range replacement re-signs the same cumulative list/hash/count with a
predecessor link; it cannot clear or shrink it. Backups preserve pins and denials.

Revocation has priority over enrollment. Reserve 64 of the 1024 roster slots;
refuse new enrollment at 960 entries, and warn operators at 80% of the roster,
record-byte, compacted-count or compacted-byte cap. Revoking a known active
device replaces its existing row with a tombstone and removes its branch
certificate; it allocates no slot and does not grow the compacted list. Keep
that path publishable even at capacity. Refuse enrollment and compaction that
need unavailable capacity before refusing an in-place revocation.

A candidate exceeding either cap is rejected with
`revocation_capacity_requires_master_reattestation`; the account requires a fresh,
user-started master re-attestation (a master-signed higher-range certificate and
its authenticated v3 head). Never truncate the list, reuse ids, raise limits
locally or clear existing denial pins to recover capacity. Re-attestation is
necessary, not permission to bypass the caps: the replacement must preserve all
known revocations within the same bounds. If no bounded valid replacement exists,
authority changes needing that state remain blocked pending protocol review;
re-attestation alone cannot make an oversized list valid. Last verified history
remains readable. This finite capacity is an explicit design limit, not an
unbounded allocation or an automatic identity reset.

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
| `binding_mode` | `"direct_exporter"`, `"home_relay_receipt"` or explicit `"no_channel_binding"`; challenge and node record must allow the exact mode |
| `transport_binding` | `B32`, SHA-256 of the client-facing TLS exporter in every mode; never null |
| `issued_at`, `expires_at` | `Time`, `0 < expires_at - issued_at <= 300` |

Proof is signed by the certified branch, checked against current authority per
request, and consumed atomically in the receiver's replay cache through expiry
plus skew. A retry uses a new challenge and proof id. In **every mode**, the client
exports 32 bytes from its own TLS 1.3 connection using label
`"EXPERIMENTAL-ramflux.identity.branch_proof.exporter.v3"` and the decoded 32-byte challenge
nonce as context, then SHA-256 hashes those bytes into `transport_binding`.
Use the [TLS 1.3 exporter](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5),
including for [QUIC](https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1);
a WebSocket uses its underlying TLS connection. No 0-RTT exporter, null, constant,
client-supplied substitute or exporter from another hop is allowed. Clients without
access to their own exporter cannot create this proof, including in the opt-in mode.

In `direct_exporter`, TLS terminates at the verifying service, which independently
computes the same exporter hash and requires exact equality. The receiver's one-use challenge state
binds its nonce, audience and selected binding mode; a proof cannot change modes.

In `home_relay_receipt`, the TLS-terminating proxy is operated by the receiving
node. It holds a dedicated proxy signing key authorized in that node's signed
identity record. It independently computes the exporter hash on the **client-facing
connection**, checks equality with the signed proof's `transport_binding`, and
countersigns a proof-purpose `RelayAcceptance` containing `client_exporter_hash`.
The verifier checks the node-authorized proxy key, exact signed proof hash, source,
challenge and service audience, and requires receipt `client_exporter_hash` equal
to proof `transport_binding`. The proxy-to-service exporter is never substituted.
Receipt issuance must use the actual live TLS connection context; a forwarded
header or client-asserted hash cannot supply the proxy's observation. Internal
transport of that context to a signing service must be authenticated and bind the
connection, nonce and exact proof. The proof contains no receipt hash, avoiding a
circular commitment. This model trusts the node-operated proxy to report its TLS
observation honestly; arbitrary relays and sender-selected proxy keys are ineligible.

`no_channel_binding` is an explicit reduced-protection deployment mode, off by
default. Enabling it requires an operator opt-in published in the signed node
record and a separate explicit client opt-in. The challenge and signed proof must
name this mode. The client still includes its exporter hash, but the verifier
cannot independently associate it with the receiving connection: phishing/relay
resistance from channel binding is absent. Display this state and persist it in
the client security log on every connection. Never negotiate it automatically on
missing exporters, receipt failure or an unsupported proxy. A client policy
requiring channel binding rejects it. No mode bypasses current branch authority,
one-use challenge, audience, proof signature or per-request authorization checks.

## Account delegation and private group restriction

`Envelope<Delegation>` uses `CUSTODY_DELEGATION`:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | Exact domain, `1` |
| `account_anchor`, `master_certificate_hash` | `B32`, `Hash` |
| `self_signing_public_key` | Ed25519 `Key`, equal to certificate |
| `delegate` | `Ref`, own active branch only |
| `branch_certificate_hash` | `Hash`, current branch certificate |
| `delegation_id` | Random `B32` |
| `scope` | Exactly `"create_and_administer_own_groups"` |
| `operations` | Sorted nonempty subset of `"genesis"`, `"request_result"`, `"snapshot"`; verified-secondary default includes all three |
| `not_before`, `expires_at` | `Time`, `0 < expires_at - not_before <= 604800` |
| `subdelegation` | Exactly `false` |

Exactly one current account delegation per verified secondary; no group id,
genesis hash, group count or per-group id list is permitted in this public body
or elsewhere in the public v3 record. A group verifier checks the delegate anchor
against the group's actual creator anchor and its current roster/permissions.
The account grant never gives authority over another creator's group. Ordinary
renewal may change id/certificate/time but not scope or operations, and is silent
except in the security log. New device, first scope grant or operation widening
raises the persistent alert; changing master/self-signing keys retains its
blocking alert. Revocation, branch change, ownership transfer and higher ranges
fence old grants. Only current-head-included account delegations apply.

An optional narrower group-specific `Envelope<GroupDelegation>` uses
`CUSTODY_GROUP_DELEGATION`, signed by the current primary, with exactly `schema`,
`version: 1`, `account_anchor: B32`, `master_certificate_hash: Hash`,
`account_delegation_id: B32`, `delegate: Ref`, `delegation_id: B32`,
`group_id: Id`, `group_genesis_hash: Hash`, `operations: string[]` (subset of the
account grant), `not_before: Time`, `expires_at: Time` (inside the account lease),
`subdelegation: false`. It and any per-group revocation travel only in that group's
authenticated encrypted control channel. Group state applies the restriction
and its revocations; positive authority never widens or outlives the current
public account grant. The retained denial floor has the separate lifetime below.
Only primary-signed group control may change/remove such restrictions or their
revocations; a delegated snapshot preserves the authenticated restriction floor
and cannot omit it to regain a wider account grant. Do not publish even a
per-group delegation id/count in the identity record or its section index.
Old-primary signed restrictions and revocations remain binding denial floors across
certificate/range changes and positive-grant expiry. Authenticate their original
signatures against retained historical certificates; they grant no current positive
authority. Only an explicit replacement signed by the current primary, referencing
the prior restriction/control hash and current authority, may replace a floor. A
new account grant or missing encrypted state never removes it. Include every known
floor in the encrypted handover summary below; missing control evidence blocks
affected group mutations until reconciled. No subdelegation or account/device management; existing creator
fresh-head, transferee countersign and sticky-removal rules remain mandatory.

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

Without a permanently resolved binding pin, two distinct valid binding hashes
for one anchor mean `identity_compromised`:
retain both, alert, suspend both alternatives and do not automatically pick the
first or the numerically newer migration. Re-attestation requires a new
higher-range master certificate whose `legacy_binding_hash` selects the binding,
signed by the **already trusted** master (or independently reverified master for
a fresh observer), plus a valid v3 record carrying it. This does not authorize a
master change. If that trust cannot be established, remain blocked and offer new
identity with local history. A master selected solely from one conflicting binding
cannot certify itself as the resolution. After accepting this trusted-master
re-attestation, persist the resolved master **and chosen binding hash** permanently
for the anchor. Later competing legacy-root bindings are ignored for authority,
logged as security evidence and may alert, but can never re-suspend that verifier
or require another phrase ceremony. Invalid inputs do not establish this pin.
Higher-range same-master recovery preserves it; backups/restarts cannot clear it.
New observers lacking the resolved pin remain first-observer limited and need
independent verification if conflicting evidence appears. An untrusted copied
legacy root still calls for a new identity. Historical conflicts remain visible.

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
| `actor_record_hash`, `master_certificate_hash` | `Hash`, exact authority that approved this intent, potentially superseded at receive time under the rule below |

Authority envelopes are resolved by hash through the authenticated identity
lookup; never substitute a current record for the signed hash. Request actor is
requester; accept/decline actor is target. Keep v1 conversation-id derivation and
routing/endpoint equality checks, source branch possession, request-id matching
and existing replay/consent-state rules. The certified management key approves
exact body bytes including the sending branch. A secondary queues an intent for
primary approval and waits; the request is pending while primary is offline.
At approval/send time require a then-current verified head. At delayed receive
time, consent is valid iff the referenced record authenticates, its epoch is at
or below the receiver's fresh current head and in the **same certified range**,
the master certificate/self-signing key is unchanged, the sending certificate
covered the consent issue time, the exact sending branch
and key epoch are active/unrevoked in the current head with a live certificate,
and the consent's seven-day TTL, endpoint, time and replay checks pass. A newer
revision in that range alone does not invalidate consent. Resolve the signed
historical hash, never replace it by the current body or require hash equality
with the current head. A range/key change, device revocation or expiry invalidates
the pending consent; the primary must approve again under new authority.

Directories retain and serve the historical record for the TTL plus skew as
specified above. Historical consent lookup is a narrow exception to "exact head"
for current operations; no historical record grants new enrollment, proof or
delegation powers. Legacy accounts retain v1 until migrated; custody peers require
v2 consent support and never obtain the legacy root for interoperability.

## Relay keys and acceptance evidence

This is a proposed extension of node public authentication metadata, not a claim
that current services already publish this profile. The current deployment has a
pinned node/federation identity key (see [server data](server-data.md)).
`Envelope<NodeIdentityRecord>` uses `CUSTODY_NODE_RECORD`, signed by that existing
pinned node identity key, with exactly `schema`, `version: 1`, `node_id: Id`,
`node_signing_public_key: Key`, `epoch: U53` (positive),
`previous_record_hash: Hash|null`, `issued_at: Time`, `receipt_keys: ReceiptKey[]`,
`revoked_receipt_key_ids: B32[]`, `proxy_keys: ProxyKey[]`,
`revoked_proxy_key_ids: B32[]` (both revocation arrays sorted and cumulative), and
`channel_binding_modes: string[]` (sorted unique allowed proof modes above;
`no_channel_binding` absent by default). Each ReceiptKey has
exactly `key_id: B32`, `public_key: Key` (Ed25519), `not_before: Time`,
`sign_until: Time`, `overlap_until: Time`, `status: "active"|"retiring"`.
Each ProxyKey has exactly the ReceiptKey fields plus `proxy_id: Id` and
`audiences: Id[]` (sorted unique, at most 64). Publication under the node signature
authorizes that node-operated proxy only for branch-proof receipts to those
audiences. Proxy and relay key ids and key material are distinct. The proxy key
is not authorized by its TLS certificate alone. A proxy key's signing lifetime
`sign_until - not_before` is positive and at most 2592000 seconds (30 days).
Keep proxy signing keys nonexportable or in an HSM where the provider supports
that boundary; software custody must be identified explicitly, never advertised
as hardware isolation. Rotation overlap does not extend the signing deadline.
Node record budget is 512 KiB; at most 16 active/overlap descriptors across both
key arrays. Its epoch and
revocation pins persist monotonically; a node-identity-key replacement still
requires existing explicit node trust/pin procedures, never a supplied receipt key.

Publish/lookup the record through authenticated node/federation discovery and
verify it against the already trusted node identity. The existing v1 federation
handshake alone does not yet convey this new profile; capability rollout must
add authenticated discovery before custody receipt mode is enabled. For message
authority, a peer trusts only its **receiving account/service's
own home relay**. For proxied branch proofs it trusts only that receiving node's
authorized, node-operated proxy key. Both are selected through that
pinned home-node relationship, not the sender's home, an arbitrary forwarding
relay or a TLS-terminating proxy certificate. A remote sender may carry the public
record by hash, but cannot establish the receiver's trust anchor. A time-probe
receipt is not account authority: the separate clock-recovery flow may authenticate
an independently pinned node/relay as its second time source, never as a signer
for ordinary inbox or registration evidence.

Rotate receipt and proxy keys by publishing a higher signed node-record epoch containing
both the new active key and the old retiring key. Stop old-key signing at
`sign_until`; retain its descriptor in current records through `overlap_until`,
at least 604800 + 600 seconds after the replacement starts. This overlap permits
in-flight delivery and clock skew without simultaneously replacing the node pin.
Normal rotation does not invalidate receipts whose `accepted_at` lies within that
key's signed issuance interval. After overlap, resolve its historical node record
by hash; node records and receipt verification keys are retained permanently for
queued evidence. Current cumulative revocations always dominate historical keys:
a compromised receipt key is refused for any unconsumed proof/message, even with
a backdated timestamp; already authenticated local history remains readable.
The same overlap, historical resolution and compromise-revocation rules apply
to proxy keys using `revoked_proxy_key_ids`; a revoked proxy key cannot authenticate
an unconsumed proof. Key ids/public keys cannot be silently rebound or recycled.

`Envelope<RelayAcceptance>` uses `CUSTODY_RELAY_ACCEPTANCE`, signed by one of those
home-relay keys for messages/time probes, or an authorized proxy key for branch
proofs. All use the existing receipt domain; purpose and issuer role are checked
before granting any authority. The exact body is:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | Exact receipt domain, `1` |
| `issuer_kind` | `"home_relay"` for message/time probe; `"node_proxy"` for branch proof |
| `relay_id`, `relay_key_id`, `node_identity_record_hash` | `Id`, `B32`, `Hash`; home-relay identity/key for message/time probe, authorized proxy id/key for branch proof |
| `client_exporter_hash` | `B32` for branch proof, equal to the observed client-facing exporter hash and signed proof binding; `null` for message/time probe |
| `receipt_id`, `message_hash` | Fresh `B32`, `Hash` of the exact accepted object |
| `purpose` | `"message"`, `"branch_proof"` or `"time_probe"` |
| `audience` | `Id`, exact receiving service |
| `source_device_ref`, `branch_certificate_hash` | `Ref`, `Hash` for message/proof; both `null` for an anonymous time probe |
| `target_anchor` | Recipient `B32` for message; `null` for service proof/time probe |
| `challenge_nonce` | `B32` matching the proof/probe; `null` for ordinary queued messages |
| `accepted_at` | `Time`, inside issuer key's `not_before..sign_until` interval |

Receipt budget is 8 KiB. For a message, the relay attests durable acceptance of
that exact signed JSON message under the source certificate and checks live
branch authority at acceptance. It may not backdate receipt issuance to bypass a
lease. For proxy-mode branch proof, it binds the exact signed proof, source,
challenge, audience and observed client exporter hash as specified above. Require
`home_relay_receipt` in the proof and a matching proxy descriptor/audience in the
receiver node record, never a message/time-probe key. It does not independently
grant operation authority.
`message_hash` uses the object hash above, including signatures when present.
A repeated receipt is idempotent only for the same object/source/target/purpose.
A compromised trusted relay can lie about time: signatures authenticate a clock
claim, not UTC truth. No receipt exception defeats current account revocation.

For time recovery only, a bounded endpoint accepts a small public probe with
exactly `schema: "ramflux.identity.time_probe.v1"`, `version: 1`,
`challenge_nonce: B32`. The time-probe receipt binds its object hash, purpose and
nonce. It certifies no user/device identity or lease and cannot be used as message
or registration evidence. It is allowed while ordinary sends are time-blocked.
A queued message without a valid message-purpose receipt cannot use the
post-expiry exception. A proxied proof without a valid proof-purpose receipt
cannot replace a missing direct exporter. No TLS forwarded header is evidence.

## Time and verification order

Use verifier-local trusted time `now`, skew `S = 300` seconds. A lease is live iff
`not_before - S <= now <= expires_at + S`. Check original positive duration
without skew: skew never extends the signed maximum. Before accepting live state,
require every event timestamp (`issued_at`, `erased_at`, `accepted_at`) to be at
most `now + S`; validity endpoints are not event timestamps. Fresh proof/consent must
satisfy `issued_at <= now + S` and `now <= expires_at + S`, plus current branch
lease, epoch/range, capability, revocation and replay checks. Use checked arithmetic.

Queued-message exception is for previously accepted messages, not fresh
registration, delegation mutations or new sends. The branch-signed message time
`t` and authenticated relay acceptance time `a` must each lie in
`[not_before - S, expires_at + S]`, and `t <= a + S`, `t <= now + S`, `a <= now + S`.
Require relay acceptance evidence bound to the exact signed-message hash and
source, authenticated by the pinned receiving-home relay key and node identity
record above, with purpose `message`. Missing evidence fails the exception; a self-claimed relay timestamp is insufficient. Current
revocations and retained authority floors still apply. Already pinned local history
remains readable regardless of current lease. Persist the maximum fully
authenticated, locally plausible event time as high-water mark `H`; never use
future validity endpoints, unverified data or a bare directory clock to advance
it. A local clock rollback is detected when `now + S < H`. It blocks new
authorization until trusted local time is re-established, never local history
reading; missing/unknown trusted time has the same send-blocking behaviour. The
recovery flow below is the only explicit exception for authenticating time samples against a clock already known to be
wrong; such samples grant no operation authority by themselves. Normal time
checks precede pin/high-water updates, preventing future-dated state from poisoning
the time floor. These marks detect observed rollback; they do not establish UTC
on a device that has no trustworthy local clock.

### Re-establishing trusted time

Show a persistent "clock needs confirmation; sending paused" state. Request fresh,
nonce-bound authenticated times from at least two independent sources: the own
home node plus a separately operated federated node, or that node/relay's fresh
time-probe receipt. Different hostnames behind one operator/key are not independent.
An old inbox receipt or a bare directory timestamp is not a fresh sample.
The second source must have been independently pinned **before recovery began**,
through existing federation/contact pins or the shipped authenticated bootstrap
list installed before that attempt. Freeze eligible node identities, pin provenance
and the start marker in the recovery journal. A node first learned through the
home node during this recovery is ineligible, even if it signs a valid sample.
Restarting the attempt cannot launder that provenance: it needs separate independent
authentication outside recovery before becoming eligible. An authenticated record
rotation rooted in an eligible existing node pin does not introduce a new trust
anchor. If no eligible second source exists, stay paused or use the explicit warned
user-confirmation path; do not enroll a home-supplied source to satisfy the count. A signed node `Envelope<TimeAttestation>` uses
`CUSTODY_TIME_ATTESTATION` and exactly `schema`, `version: 1`, `node_id: Id`,
`node_identity_record_hash: Hash`, `sample_id: B32`, `challenge_nonce: B32`,
`observed_at: Time`; it is signed by that node's pinned identity key (8 KiB limit).
A relay alternative uses the distinct time-probe-purpose receipt profile above.

Use a fresh 32-byte challenge per source and local monotonic round-trip measurement
of at most 300 seconds. Require signatures, node identity/epoch pins and non-revoked
keys, and samples agreeing within 300 seconds, accounting for the measured trip.
Only the completed multi-source check may establish a new logical UTC anchor
against the monotonic clock; its initial value is the largest agreeing signed
time plus its measured return-trip bound. The agreement test includes those
bounds, so a slow path cannot silently add another skew interval. Do not set the
OS clock or treat a single authenticated source as sufficient. The assumption is
independent, honest-enough time sources; two colluding sources can still lie.

If independent samples are unavailable/disagree, ordinary sends stay paused unless
the user explicitly confirms the displayed/corrected time with the visible warning:
"This time could be wrong. Expired device permissions may appear valid. Continue
only after checking the clock independently." Never open a phrase form for this.

Persist a local time-recovery journal entry with old `H`, samples/source identities
or explicit user confirmation, chosen time, and an increasing local recovery
generation. Atomically install the new logical clock and a new-generation `H`;
this explicit flow may reset a wrongly future `H`, preventing permanent lockout
after a fast clock is corrected. It never lowers identity epochs, mode latches,
master/binding pins or revocation checkpoints. Retain the old floor as audit
history; subsequent normal authenticated events advance only the new-generation
floor. Backup/restore cannot silently replay an older time-reset generation.
Revalidate current leases and authority after the reset, before any ordinary send.
Local history stays readable throughout.

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
   clear a known floor because predecessor/list material is unavailable; reconcile.
   Apply both inline revocations and the verified compacted membership index.
6. Atomically persist the accepted head/floor, master/binding/certificate pins and
   custody latch **before** granting authority or returning durable success. On a
   valid conflict persist the fence/evidence instead and grant no new authority.
   Backups, cache eviction and restart cannot clear these values.
7. For an operation, require current authority fetched at most 300 seconds ago;
   refresh failure has no stale-cache fallback. Check operation-specific branch
   possession, key epoch, capability, leases, replay/audience/transport binding
   and exact head. Only delayed consent may use its authenticated historical
   same-range head under the receive-time rule; verify the self-signing approval
   and live current sending branch separately. Proxy-mode proofs require the
   node-authorized proxy receipt and equality of its observed client exporter hash
   with the proof binding, never an exporter from another TLS hop. Verify the exact
   challenged mode; `no_channel_binding` requires both explicit opt-ins, signed node
   advertisement and a persistent client security-log entry.
   No session, delegation or erasure ACK overrides a higher retained floor.
8. Generate persistent alerts from authenticated state changes, including roster
   additions, new delegation scopes or operation widening, display-name changes
   and removed-device state. Equivalent lease/delegation renewals are security-log
   entries without alerts; compare semantic permissions, not newly issued ids.
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
`hpke_suite: "ramflux.identity.transfer.hpke_suite.v1"|null`.
Initiator is the old primary. `transcript_hash` is
`SHA-256(frame("ramflux.identity.pairing_transcript.v1", transcript))`.

Before public-key reveal each party commits to
`SHA-256(frame("ramflux.identity.pairing.commitment.v1", role_byte ||
random_32_byte_salt || own_raw_sas_key || invitation_id_raw))`;
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
info = UTF8("ramflux.identity.transfer.hpke_info.v1") || 0x00 || raw_transcript_hash
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
| `group_restriction_summary` | Array of `{group_id: Id, group_genesis_hash: Hash, control_head_hash: Hash, restriction_hashes: Hash[], revocation_hashes: Hash[]}`; sorted by group id, nested hash arrays sorted unique and at most 1024 each |
| `pending_erasure` | Sorted array of `Ref`, equal to pending head entries |
| `optional_data_keys` | Array of `{key_id: Id, purpose: "history"|"attachment", key: B32}`, empty unless user explicitly selects data transfer |

Each array is bounded by 1024 entries; total plaintext at most 1 MiB. No phrase,
master/self-signing seed, branch seed, vault secret or live SAS secret is allowed.
The summary lists every known old-primary restriction and revocation, including
those from earlier ranges. References resolve to authenticated encrypted group
control state; verify historical signatures and preserve denial floors before
granting group mutation authority. A missing/incomplete summary or unavailable
referenced control state leaves affected groups blocked for reconciliation, never
unrestricted. It cannot be silently discarded on promotion. Group ids and hashes
stay only in this encrypted payload and group channels, never public identity
metadata. Total plaintext and array limits apply to the summary too.
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
plus application transcript/AAD/substitution/replay vectors; section-hash/cache
reconstruction and not-modified/eviction vectors; consent delay/retention across
same-range renewal and range replacement; cumulative revocation compaction,
missing-list refusal and anti-resurrection vectors; node-key overlap/revocation,
proxy receipt mode and multi-source/user-confirmed clock-reset tests; SAS
commitment/MAC/emoji mapping vectors and full-flow recovery benchmark plan.
Do not describe those planned vectors as already published by this document.

Stage 2a produces a complete source-reviewed private-root-use appendix. Stage 2b
cannot begin until that inventory, this wire spec and vectors pass independent
review. It implements every verifier before enabling v3 writers. Existing legacy
accounts retain one-hour branch proofs and current group/contact behaviour until
opt-in migration. Capability negotiation (`custody_v3`, `contact_consent_v2`,
`group_delegation_v1`) never strips v3 evidence for old federation/group peers;
unsupported combinations block with update-required, as described in the design.

## Revision 5 review vectors (required before implementation)

These are planned acceptance vectors, not executed implementation tests:

- Direct and proxy successes; another TLS session/exporter, altered receipt hash,
  client-supplied proxy observation, null binding, wrong audience/mode, replay,
  sender-selected proxy, wrong signer role and revoked proxy key all fail. Test
  proxy key rotation/overlap and explicit opt-in visibility; no automatic downgrade.
- Full list versus predecessor/additions reconstruction yields identical hashes.
  Reject duplicate/removal deltas, wrong predecessor/count/hash, 65,537 ids and
  4,194,305 canonical bytes. Interrupted evidence cannot advance the index. Test
  empty re-sign deltas, retained denials and required master re-attestation without
  truncation or cap bypass.
- A pre-existing independently pinned contact/federation/bootstrap source works;
  a source introduced by the home during recovery, including after restart, cannot
  become the second source. No eligible source preserves the send block unless
  the separate explicit warned confirmation succeeds.
- Old-primary restrictions survive a higher range, grant renewal/expiry, restore
  and HPKE handover. Omitted/unavailable private control evidence blocks affected
  mutations; only an authenticated explicit current-primary replacement changes
  the floor. Public records contain no group summary.

## Born-v3 deterministic implementation vector

The complete canonical bytes, nested signatures, hashes and inputs are published
in [custody_v3.json](../crates/ramflux-crypto/tests/fixtures/custody_v3.json).
The independent [Python reference](../crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py)
uses cryptography 50.0.2 and blake3 1.0.11, separately from the Rust implementation.
These are public test keys and must never be used for real identities.

| Input or result | Value |
| --- | --- |
| Entropy | 32 zero bytes |
| BIP39 phrase | `abandon` repeated 23 times, then `art` |
| HKDF salt / IKM / info / output | 32 zero bytes / decoded 32-byte entropy / bare `ramflux.identity.master.v1` / 32 bytes |
| Derived Ed25519 master seed (hex) | `2f5adffabe16e98d436efc55baf33ef81bbe6618adb44915eb3ac24fa8a688c8` |
| Master public key | `dpo72yjw_usfOz1CMtsiramWwlb9rLj72PwxphjlnJc` |
| Account anchor | `CFeUxoWMBsa9yAAoCz0GXjxP6R7ZQr3-SUty7OxO4EI` |
| Self-signing / branch / agreement seeds | 32 bytes each of `02` / `03` / `04` (hex) |
| Master / branch certificate ids | 32 bytes each of `05` / `06` (hex), base64url encoded |
| Principal / device / display name | `vector.example` / `primary` / `Vector Human` |
| Kind / issued time / branch expiry | `human` / `1700000000` / `1702592000` |
| Range / revision / encoded epoch | `1` / `1` / `4294967297` |
| Master certificate envelope hash | `MObK_MiUX6AkEOVT6kYbxYkkCARnCuezi6hCJgV43nc` |
| Branch certificate envelope hash | `L8pYOyKfiOUvT9J7qDWyakLgK4OWmYXnGVm9085fYo0` |

Rust tests reconstruct this genesis and compare every canonical byte, section
hash, nested signature and complete-envelope hash with the independent fixture.
This vector covers native human genesis, master and branch certificates and the
complete v3 device set; it does not claim coverage for deferred migration,
delegation, pairing or recovery protocols.
