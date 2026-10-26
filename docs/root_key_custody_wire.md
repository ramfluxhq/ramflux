<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Root key custody wire specification

Design revision 4, proposed normative stage-1 specification. This document and
[root key custody](root_key_custody.md) describe future behaviour, not executable
support. Independent wire review and published interoperability vectors are
required before stage 2b. The legacy binding remains a proposal awaiting owner
confirmation. The controller has approved epoch ranges with the r3 amendments below; exact wire formats and
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
| `CUSTODY_BRANCH_EXPORTER` | `ramflux.identity.branch_proof.exporter.v3` | TLS exporter label: direct connections only |
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
list verification is resumable with bounded memory and disk-backed membership.
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

A flat sorted-list hash + count is not a membership/non-membership proof. Serve
the canonical list by hash in bounded resumable pages; the verifier streams the
whole committed list, checks ordering/uniqueness/count/hash, and builds or updates
a local disk-backed index. Only then can it deny a member or prove an enrolled id
absent. Cached verified list bytes/index may be reused by list hash. Missing,
truncated or budget-interrupted evidence blocks the affected authorization until
verification resumes; it cannot mean "not revoked". Check both inline tombstones
and the checkpoint for enrollment, re-enrollment, proofs and operations.

Retained previous checkpoints/lists let existing verifiers prove the cumulative
superset; a first observer authenticates the current primary's complete committed
list but still cannot prove a globally latest head. A certificate/range replacement
re-signs the checkpoint under the new primary while retaining the cumulative list
hash/count (and predecessor link). It cannot clear or shrink it. The 1024 roster
cap counts only active devices and recent tombstones; the external list is not
subject to that roster-entry cap. No compaction of active or recent entries is
allowed. Full backup/restore preserves checkpoint/list pins and revocation denial.

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
| `binding_mode` | `"direct_exporter"` or `"home_relay_receipt"`, as allowed by the receiving deployment |
| `transport_binding` | `B32` in direct mode; `null` only in authenticated home-relay receipt mode |
| `issued_at`, `expires_at` | `Time`, `0 < expires_at - issued_at <= 300` |

Proof is signed by the certified branch, checked against current authority per
request, and consumed atomically in the receiver's replay cache through expiry
plus skew. A retry uses a new challenge and proof id. Direct mode requires TLS
1.3/QUIC to terminate at the verifying service. Use 32 exporter bytes with label
`"ramflux.identity.branch_proof.exporter.v3"` and raw challenge nonce as context,
then SHA-256 those exporter bytes. A WebSocket uses its underlying direct TLS
connection exporter. Do not use 0-RTT exporters or an exporter from another hop.

With a TLS-terminating proxy, the client/proxy exporter is **not** the proxy/service
exporter. Use `home_relay_receipt`: the signed proof sets transport_binding null
and travels with a `RelayAcceptance` for the exact signed proof hash, source,
challenge and service audience, signed by the receiving service's trusted home
relay. The proof itself contains no receipt hash, avoiding a circular commitment.
The signed receipt is the sole channel-evidence mechanism in this proxy mode;
forwarded TLS headers, network addresses and an arbitrary sender relay cannot
replace it. Current branch authority, one-use challenge and proof signature are
still required. The verifier chooses allowed modes; absence of a supported direct
exporter or trusted receipt fails closed, never falls back to a constant binding.
Neither TLS nor a receipt freezes authorization for a session's duration.

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
and its revocations; it never widens or outlives the current public account grant.
Only primary-signed group control may change/remove such restrictions or their
revocations; a delegated snapshot preserves the authenticated restriction floor
and cannot omit it to regain a wider account grant. Do not publish even a
per-group delegation id/count in the identity record or its section index. No subdelegation or account/device management; existing creator
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
`previous_record_hash: Hash|null`, `issued_at: Time`, `receipt_keys: ReceiptKey[]`
and `revoked_receipt_key_ids: B32[]` (sorted, cumulative). Each ReceiptKey has
exactly `key_id: B32`, `public_key: Key` (Ed25519), `not_before: Time`,
`sign_until: Time`, `overlap_until: Time`, `status: "active"|"retiring"`.
Node record budget is 512 KiB; at most 16 active/overlap descriptors. Its epoch and
revocation pins persist monotonically; a node-identity-key replacement still
requires existing explicit node trust/pin procedures, never a supplied receipt key.

Publish/lookup the record through authenticated node/federation discovery and
verify it against the already trusted node identity. The existing v1 federation
handshake alone does not yet convey this new profile; capability rollout must
add authenticated discovery before custody receipt mode is enabled. For message
or branch-proof authority, a peer trusts only its **receiving account/service's
own home relay**, selected through that
pinned home-node relationship, not the sender's home, an arbitrary forwarding
relay or a TLS-terminating proxy certificate. A remote sender may carry the public
record by hash, but cannot establish the receiver's trust anchor. A time-probe
receipt is not account authority: the separate clock-recovery flow may authenticate
an independently pinned node/relay as its second time source, never as a signer
for ordinary inbox or registration evidence.

Rotate receipt keys by publishing a higher signed node-record epoch containing
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
Key ids/public keys cannot be silently rebound or recycled.

`Envelope<RelayAcceptance>` uses `CUSTODY_RELAY_ACCEPTANCE`, signed by one of those
home-relay keys. The exact body is:

| Field | Type / requirement |
| --- | --- |
| `schema`, `version` | Exact receipt domain, `1` |
| `relay_id`, `relay_key_id`, `node_identity_record_hash` | `Id`, `B32`, `Hash`; pinned receiver-home issuer for message/proof, independently pinned clock source for time probe |
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
challenge and audience; it does not independently grant operation authority.
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
The second source is selected from independently trusted/pinned federation nodes,
not an attacker-supplied key. A signed node `Envelope<TimeAttestation>` uses
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
   receiver-home signed receipt, not an exporter from another TLS hop.
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
