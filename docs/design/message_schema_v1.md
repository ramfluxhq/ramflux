# Message schema v1

## 1. Status, scope and hard system facts

**Proposal for review. No production implementation, security audit or runtime
acceptance is implied.** This document defines the application schema, its
cryptographic framing and the implementation boundaries. It adds no runtime
feature. The design branch is a review artifact; S10a imports this exact file by
its approved commit SHA rather than merging the design branch.

The implementation checkout for this proposal starts at
`ad725d638b6d24ed15ae9f13b94733a640b75a3d`. All product `path:line` citations below
are pinned to `6b8e53106618aaee091989099ddb8dd5b1c9ad82`; `desktop/` denotes the
separate desktop repository at `08a9e63873a231a9a332c2274eeba7b819341feb`.
The intervening identity-verification/backup change does not change the schema
literal set. Counts are 182 occurrences, 70 distinct literals across the product,
and 179 occurrences, 70 distinct literals in SDK source. A literal inventory is
not a claim that each literal defines an application message: several are hash
separation domains or private persistence formats.

Terminology:

- **Inner**: the exact protobuf application bytes; only endpoints interpret them.
- **KindId**: a permanent numeric application constructor, separate from transport
  class, frame type and cryptographic profile.
- **Layer**: one unsigned integer describing a complete supported schema revision.
  There are no negotiated capability bits or per-feature switches.
- **Message id**: a source-qualified logical event id. **Envelope id** identifies
  one recipient-device delivery; **inbox sequence** is a node-assigned cursor.
  They are separate identities. Message and Service use the same logical id and
  ordering rules; neither receives a privileged parallel sequence.
- **Unsupported**: a local typed projection with retained exact Inner bytes, not
  a new peer-sent KindId and not a dead letter.
- **Durable delivery**: normal inbox/WAL/ACK delivery. **Ephemeral delivery**: the
  generic S6 live-session-only contract; it says nothing about the inner kind.

### 1.1 Measured constraints

| Fact | Current authority | Consequence |
|---|---|---|
| Out-of-order ACK window is 1,024; NACK retry limit is 3; dead-letter diagnostic limit is 128 | `crates/ramflux-node-core/src/inbox.rs:11`, `crates/ramflux-node-core/src/inbox.rs:13`, `crates/ramflux-node-core/src/inbox.rs:15` | Unsupported is committed and ACKed, never converted to UnsupportedSchema NACKs. The ACK window is not a total mailbox byte quota. |
| Retention ends at the earlier of envelope expiry and seven days after acceptance | `docs/server-data.md:13`, `crates/ramflux-node-core/src/inbox.rs:80` | Receiver retention cannot depend on a later server refetch. |
| ACK-window overflow can remove ciphertext without notifying the recipient | `docs/server-data.md:192`, `crates/ramflux-node-core/src/inbox.rs:434` | This proposal does not claim reliable gap notification on current main. S6 owns that delivery contract. |
| Envelope TTL maximum is 604,800 seconds | `crates/ramflux-protocol/src/replay.rs:9` | Padding, unknown retention and layer negotiation do not renew transport TTL. |
| Gateway serialized frame cap is 1,048,576 bytes | `crates/ramflux-transport/src/lib.rs:95`, `crates/ramflux-transport/src/quic_gateway.rs:763`, `crates/ramflux-transport/src/quic_gateway.rs:796` | Measure the complete JSON/base64 frame before enqueue, not only plaintext. |
| Local bus frame cap is 1,048,576 bytes; object chunks are 524,288 raw bytes | `crates/ramflux-sdk/src/bus/io.rs:285`, `crates/ramflux-sdk/src/bus/io.rs:296` | Typed updates are paged; large raw bytes are never automatically attached to a bus snapshot. |
| PayloadTooLarge is an enum value, not a measured universal payload limit | `crates/ramflux-protocol/src/core_types.rs:289` | There is no inferred independent node envelope-byte cap merely because this variant exists. S10a enforces the explicit limits below on every ingress. |
| Retry/dead-letter material is bounded to 64 records per queue and 1 MiB per entry | `crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:62`, `crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:102`, `crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:115` | These ciphertext failure queues are not the retained Unsupported history store. |
| One current plus eight previous receive states per device pair; default skip bound 1,000 | `docs/client_read_model.md:322`, `crates/ramflux-crypto/src/double_ratchet.rs:936` | Header trial and skipped-key work need explicit independent bounds, section 5. |

### 1.2 New admission limits, not claims about current main

S10a admits at most 524,252 bytes of exact Inner. The framing adds a 4-byte
length and a 32-byte reporting opening, making the maximum unpadded plaintext
524,288 bytes. Padded plaintext cannot exceed 524,288 bytes. A normal encrypted
header has 512 plaintext bytes; a bootstrap capsule has at most 16 KiB of
plaintext. The final sender-signed envelope/frame must still fit the existing
1 MiB transport and bus caps. Budget 64 KiB for outer metadata; identifiers keep
their current 256-byte UTF-8 limit. A measured overflow returns PayloadTooLarge
before persistence or cryptographic state exposure. Sealing uses a temporary
state; only a size-accepted envelope commits its ratchet/outbox transaction. Large content uses media
references and S9, never an enlarged inbox envelope.

Nested depth is at most 32; entities at most 4,096; media references at most 32;
text at most 256 KiB UTF-8; inline thumbnail at most 16 KiB. Control proof bytes
remain subject to their native 8 KiB proof limit. Task and Surface retain the
30,720-byte packet sublimit derived today in
`crates/ramflux-sdk/src/client/task/mod.rs:80` and
`crates/ramflux-sdk/src/client/surface/mod.rs:133`. Existing stricter call,
control, membership and parser limits are not removed by the aggregate cap.

Unsupported retention adds a separate **64-row / 32 MiB exact-raw budget per
account**, plus 4 KiB bounded metadata per row. An admission transaction reserves
that budget before ratchet/read-model commit. Exhaustion is ordinary local
storage backpressure: preserve existing rows, withhold ACK and surface
`StorageCapacity` with recovery actions (upgrade, delete selected Unsupported
messages, or provision storage). It is never UnsupportedSchema, never an
unsupported-kind NACK and never silent FIFO destruction of retained bytes.
This does not promise delivery from an arbitrarily abusive authenticated peer;
normal contact blocking, native authorization, TTL and S6 gaps still apply.
The new budget is not mislabeled an already existing inbox quota.

## 2. Numbered decisions and rejected alternatives

### Decision 1 — generation and one source (Q1, D1)

The source lives in `ramflux-protocol::message`, with authoritative proto3 files
under its planned `message/schema/` directory. A new schema crate would add a
second protocol ownership boundary without an independent dependency need;
therefore it is rejected. Schema import cycles are forbidden. Native signed
custody/prekey documents remain owned by their native protocol modules; a typed
message can carry their already specified signed bytes, not a private SDK JSON
sub-protocol.

Use a locked regeneration tool outside the ordinary build graph: pure-Rust
`protox` compiles a FileDescriptorSet, `prost-build::Config::compile_fds` emits
Rust, and `pbjson-build` emits ProtoJSON serde implementations from that same
set. Check generated Rust, descriptor bytes and a layer/field registry into
source. Ordinary `cargo build` does not need protoc or regenerate files.
CI reruns the locked tool and requires an empty diff. Unprovisioned host protoc
and handwritten parallel Rust/JSON models are rejected. This round can use the
locally available protoc solely to validate the sketch.

Proposed generator dependencies follow the existing prost 0.14 family; S10a
pins compatible protox/prost-build/pbjson releases in its lockfile, without an
MSRV change. The tool is an actual workspace consumer, so cargo-machete must
find no unused declarations. The currently unused workspace prost declaration
becomes used. Do not suppress machete to conceal it. Prepend SPDX/copyright
headers deterministically to every emitted Rust file. Split generation by real
responsibility (common, content, controls, state, API), with re-exports; no
include-based mechanical chunks and no generated file above 5,000 lines.

ProtoJSON is the only JSON mapping: lowerCamelCase field names, base64 bytes,
64-bit integers as decimal strings, numeric unknown enums retained as numbers,
explicit optional presence and no double conversion through floating point.
Input adapters reject duplicate/alias field names instead of accepting two
conflicting values. Unknown JSON input fields are rejected on local commands;
unknown **binary peer** fields follow Decision 3. These are different boundaries.

Swift/Kotlin use UniFFI over the same Rust request/update core. WASM exports the
same generated model and ProtoJSON through postMessage. TS declarations and
validators derive from the descriptor set; CLI/TUI use the Rust types. Direct
Swift/Kotlin protobuf wire codecs, if required by a transport adapter, consume
this same descriptor and conformance vectors, not a UI-maintained schema.

### Decision 2 — numeric kind plus opaque body (Q2, D4)

Choose `Inner { layer, kind, identity, body }`, where body is the exact protobuf
encoding of the constructor selected by the numeric kind. The kind registry is
the only dispatch table. This makes an unrecognized number naturally retainable
without prost consuming its unknown oneof field. A top-level oneof whose tags
are KindIds is rejected because its unknown constructor disappears from a
normal prost-decoded value. Nested closed choices can use oneof only when their
unknown-field scanner still promotes the entire Inner to Unsupported.

Padding is a cryptographic framing transform around Inner, not a protobuf bytes
field whose length varint recursively changes the target bucket. The generated
Padding/PaddedInner models below describe the logical framer input/output;
they are not an alternative protobuf wire encoding. Section 5 gives the sole
physical frame layout. No body dispatch depends on text prefixes or schema
strings. All protobuf field ids and KindIds are permanent and never reused.

### Decision 3 — unsupported input and raw bytes (Q9, D3)

After identity, authorization and AEAD verification, retain the complete exact
Inner before any lossy protobuf conversion. A bounded descriptor-driven wire
scanner recognizes unknown field numbers, unsupported field introductions,
unknown enum/entity numbers and a layer above effective receiver support.
Prost decoding is performed only after that scan. Unknown content produces
`Unsupported { layer, kind }`, with a raw-row handle, not a replacement text
message. Entity::Unknown is represented by the EntityUnknown structure; its
presence likewise makes the whole message Unsupported. No partial action is
executed. A protobuf body decode failure after authenticated framing also
produces an opaque Unsupported placeholder rather than displaying binary text.

Commit the exact raw row, placeholder, copy bindings, footprint locators, replay
claim, ratchet advancement and cursor together. ACK only after that transaction
is durable. Native authority, consent and group-origin checks precede this path;
Unsupported grants no authorization. Resource/persistence/cryptographic failures
retain their own outcomes and can withhold ACK. Unsupportedness itself is
never an error, NACK or dead-letter cause. Delete UnsupportedSchema and its
obsolete test.

Known Common/identity fields have stable meanings across every layer. Validate
them against the authenticated source. If Common cannot be decoded, address the
placeholder by an account-MAC of the authenticated source and envelope id in an
unclassified per-peer inbox. Never accept an arbitrary unvalidated target id as
an erasure owner. A future successful reparse binds the recovered logical id
and this original copy id atomically, checking both deletion fences first.

Do not reconstruct raw bytes by re-encoding prost: unknown fields would be lost.
Reparse runs after app upgrade or an effective max_layer change, in pages of 32
rows / 4 MiB with one bounded worker per account. Its idempotency key is
(account, message/copy id, raw digest, decoder layer). Decode off the writer;
under the writer recheck raw digest, native source provenance, erasure generation
and sticky deletion before replacing the placeholder. An erased raw row remains
a tombstone and cannot be fetched from a server to recreate content. Reparse
emits a typed update; it sends no second ACK or duplicate history event.

### Decision 4 — classes and routing (Q3, D6)

There are exactly two client delivery classes: **message** and **call_wake**.
All user content and controls, own-device sync, object references, task/surface
work and ordinary call signaling are message. call_wake is only a new incoming
call invitation that may require VoIP wake. It is not a way to elevate generic
controls. Keep class-to-priority/TTL mapping in one generated/shared policy.

Separate self_control and object classes are rejected: object bytes already
travel through relay protocols, and separate own-device classes disclose that
relationship. Node-to-node federation_control stays a service-frame concept,
outside this client class enum. The detailed before/after inventory is section 6.

Every envelope carries a 32-byte collapse_tag. Derive
`Kcollapse = HKDF-SHA256(SK, salt=pair_binding, info="ramflux.message.collapse_key.v1", 32)`
once per session incarnation and recipient device, then
`tag = HMAC-SHA256(Kcollapse, LP(conversation_id) || LP(recipient_device_ref))`.
Kcollapse is domain-separated session material, not a saved message key. It
survives DH steps, is erased with its pair state, and is not restored as live
from a backup. Reset/re-enrollment generates a new tag family. Use 32 CSPRNG
bytes when a conversation tag is meaningless. Missing tags are never allowed.
This deliberately exposes a conversation correlation token within a session to
the recipient's node; it does not expose the conversation id or link recipients.

### Decision 5 — uniform franking with verifiable reports (Q4)

Keep one opaque 32-byte report_commitment on **every** envelope and replace the
optional franking JSON object. Putting the entire reporting step inside the
ciphertext would prevent node attestation; retaining the optional rich object
would continue to disclose kind, event id and hashes. Both alternatives are
rejected. All old semantic franking/header fields move inside encrypted regions
or disappear. The opaque commitment is the explicit exception needed for reports.

The encoder chooses a fresh 32-byte opening kf per recipient envelope. Let I be
exact Inner bytes and A0 be canonical sender outer fields excluding ciphertext,
payload_hash, sender signature, report_commitment and appended node metadata.
Use the existing keyed BLAKE3 primitive:

`C = BLAKE3_keyed(kf, LP("ramflux.message.report_opening.v1") || LP(I) || LP(A0))`.

The encryption plaintext carries kf after I (section 5). Compute C first; header
and body AEAD bind the resulting sender outer AD, including C. Compute payload_hash
and the sender signature after encryption. This ordering has no ciphertext/AD
self-reference. The receiver verifies C before committing/rendering either a
known or Unsupported message. Sender-controlled invalid openings are integrity
failures, not schema fallback. Recipients cannot change I while preserving C.
Fresh kf and recipient-bound A0 prevent cross-device plaintext equality tests.

The accepting node appends a NodeReportReceipt for every accepted envelope,
using `ramflux.franking.node_tag.v2`. Sign the length-prefixed node id,
envelope id, authenticated source ref, target delivery id, C, payload_hash and
acceptance time with its configured node signing key. Receipt fields are not
part of the sender signature/AEAD AD; C and all sender routing claims remain
sender signed. Old domains `ramflux.franking_opening.v1` and
`ramflux.franking.node_tag.v1` are retired rather than silently reused for the
new transcript. Node receipt authentication must not remove source-root claims
or the current independently signed federation evidence.

An opt-in report supplies exact I, kf, A0, sender envelope/signature, the node
receipt and native sender authority evidence. The verifier checks sender scope,
recomputes C, verifies payload_hash/envelope binding and node receipt using the
trusted node record, then derives a human excerpt from that verified content.
It does not claim that an arbitrary redacted substring opens a whole-message
commitment. Report disclosure covers one selected complete Inner; attachment
chunks and the rest of the conversation are not implicitly disclosed. The UI
must obtain explicit consent before sending that evidence. Non-reporting controls
still have uniform commitments; the UI need not offer reports for secret-bearing
call/task controls.

Trace and replacement boundaries: producer
`crates/ramflux-sdk/src/client/dm.rs:122` and
`crates/ramflux-sdk/src/client/dm.rs:265`; constructor
`crates/ramflux-sdk/src/dm.rs:443`; sender signature exclusions
`crates/ramflux-protocol/src/envelope_sender.rs:18`; tag attachment
`apps/ramflux-gateway/src/session.rs:1508`; commitment/tag primitives
`crates/ramflux-crypto/src/franking.rs:33` and
`crates/ramflux-crypto/src/franking.rs:90`; domains
`crates/ramflux-protocol/src/domain.rs:67`; evidence verifier
`crates/ramflux-node-core/src/franking.rs:101`; report entry
`crates/ramflux-node-core/src/router_abuse.rs:29`; trusted signer configuration
`crates/ramflux-node-core/src/router.rs:259`. The mvp7_compliance scenario must
continue to prove accepted evidence, wrong-key/tamper refusal and retention.
Missing trusted node evidence fails report verification; operator recovery is
to restore the trusted signed node record/key configuration, never accept a
key supplied by the reporter.

### Decision 6 — ephemeral delivery (Q5, D9)

Every outer envelope has `delivery_mode = durable | ephemeral`; there is no
plaintext typing flag. S6 must support generic ephemeral transport before S10a
is dispatched. The leak is explicit: a node can distinguish transient traffic
and its short TTL. It cannot distinguish Typing from another permitted transient
control by decrypting it. Hiding this mode while requiring the node not to store
it is impossible without another private-delivery protocol; that alternative
is rejected here.

Ephemeral TTL is 5 seconds and priority low. S6 validates source/signature,
recipient, current authorization, TTL and frame size, then sends only to an
already live recipient session. It uses a bounded 64-envelope / 256 KiB live
queue per session, drops on saturation/offline/expiry, never allocates inbox_seq,
never writes router inbox, router WAL, federation durable spool or notify queue,
and never emits offline push. A sender gets a bounded transient accepted/dropped
result, not a durable inbox ACK. Live federation uses the same transient mode
and cannot convert it into a durable retry. Replay markers, if necessary, contain
only authenticated digests and expire within the 5-second lifetime.

Endpoints accept Typing only in this mode, keep the indicator in memory for at
most five seconds, and never create history, own-history, backup or journal body
rows for known Typing. Drop superseded indicators. Receiver typing consent and
rate limits are per authenticated peer/conversation. A malicious durable Typing
is not displayed as history; its typed policy refusal is not an unknown-schema
NACK. Unknown authenticated ephemeral content still uses Decision 3's bounded
Unsupported retention at the endpoint; that is not node inbox persistence and
cannot execute an unrecognized transient operation. The S6 transient result and
the endpoint's durable Unsupported row have different acknowledgement meanings.

### Decision 7 — signed layers (Q6, D2)

Add `message_layer: SignedLayerDeclaration` to the native custody Device record
(`crates/ramflux-protocol/src/custody/types.rs:81`). The declaration contains
exactly one capability value, max_layer, and binds DeviceRef, declaration sequence,
issue/expiry and the branch signature. The enclosing native publication endorses
it; `CustodyManifestDevice` (`crates/ramflux-protocol/src/custody/network.rs:151`)
projects that same value with its authority proof. It is not a separately trusted
unsigned directory property. S10a owns protocol, SDK publication and node
manifest verification/serialization changes needed to carry it.

Only that current device can sign its declaration; an authorized native owner
must endorse an update in a newer custody publication. Lowering max_layer is an
explicit higher-sequence declaration, not an inferred downgrade from a timeout
or old backup. Pin both native head/counter and per-device declaration sequence;
reject stale, foreign-epoch or equal-sequence conflicting declarations. Statement
validity is at most 24 hours and is also subject to the existing native authority
freshness/current-head check. An expired/missing statement is LayerUnavailable,
not max_layer=0. A stale lower declaration is repaired by updating/unlocking the
device, issuing its fresh signed declaration and publishing an endorsed native
head. Loss of the signing holder requires attended native recovery/new-device
enrollment. Local history reads do not wait for this publication.

Effective receive maximum is min(compiled maximum, active signed declaration).
Backup/restore can preserve declarations as historical evidence only; they never
restore a current head, declaration sequence floor or live capability from the
archive. Fresh admission refreshes authority/floors before new sends. A malicious
home can still withhold new publications within the pre-existing freshness
model; this design does not add a transparency-log guarantee.

### Decision 8 — encrypted headers (Q7, D7)

Use the Double Ratchet header-encryption state machine in section 5. Source device
and principal remain outer for signature verification and pair selection; session,
counter, ratchet public key, device hashes, epoch and semantic commitments are
AEAD protected. Searching all account sessions or exposing a session selector is
rejected. Bootstrap has a separately specified encrypted capsule and a public
X3DH ephemeral E; E is an explicit outer cryptographic necessity, not the ratchet
R0. The bootstrap capsule remains protected by the native agreement key, with
the compromise limitation stated in section 13.

### Decision 9 — padding (Q8, D5)

Use Padme with a 256-byte minimum, after serializing Inner/franking framing and
before sealing. Fixed power-of-two rounding is rejected because its worst-case
padding approaches 100%. Padding zeros are allowed because all bytes are inside
AEAD; unpadding validates the length and zeros and never guesses by trimming
message data. Section 5 defines the exact frame, limits, script and vectors.
The <=12% statement applies above the floor; small messages explicitly pay the
floor cost. S11 measures the complete push-wrapped envelope against 3 KiB and
uses wake-only when it does not fit, including bootstrap packets.

### Decision 10 — deletion and ordering (Q10, D4)

Device sequence and HLC define one logical event stream for Message and Service;
transport cursors and ratchet counters remain distinct. An id is BLAKE3 of a
length-prefixed qualified author, conversation id and durable device_sequence,
under `ramflux.message.id.v1`. For deterministic display order use
(HLC, qualified author, device_sequence, id); do not block on ephemeral logical
sequence gaps. Transport ordering still uses inbox_seq. A retransmission keeps
its logical id while recipient envelopes differ.

Edit targets an existing own-root message and carries a monotonically increasing
revision plus the replaced content digest; conflicting revisions become a typed
conflict, not last-write-wins by untrusted wall time. Reaction add/remove uses a
stable (target, authenticated reacting principal, token) key and operation id.
Forward creates a fresh id and an optional provenance assertion; it never copies
another sender's authority. Service actions are independently authorized native
membership/name/pin changes; a cosmetic service row cannot execute a group change.

Delete scope LOCAL erases only local copies and syncs that choice to own devices.
EVERYONE creates an authenticated replicated tombstone: sender principal can
delete its own message across its active devices; a current group moderator may
remove group content only with the existing signed group authorization and epoch
proof. A recipient cannot delete somebody else's DM for everyone. Delete before
content installs the same sticky fence. The owner of a local account may always
choose local erasure of any readable or Unsupported row.

Use the existing indexed erase path for body, origins, queued/prepared own copies,
aliases, replay references, raw bytes and media ownership edges. Attachment bytes
are erased only after the final message owner is gone; shared references and
standalone retention keep their existing rules. Revoke erases the revoked pair's
private state and stops its queued work; it is not authority for a peer to delete
unrelated history. Own-copy and imported-history tombstones apply before any
projection insert and retain private replay fences. Never resurrect raw bytes
from reparse, restored history, an attachment alias or a late own copy.

### Decision 11 — hard limits (Q11)

The table in section 1 is normative evidence, not an assumption copied from an
upstream messenger. Keep current ACK/NACK/TTL limits; S6 owns typed gap delivery.
S10a validates raw and serialized-frame lengths before allocating or committing.
It never implements unlimited raw retention by treating successful decryption as
an exemption from resource admission.

### Decision 12 — write-path threat review (Q12)

Every raw copy is registered explicitly in its writer transaction, section 9.
Relying on JSON discovery is rejected: the existing triggers use json_valid /
json_tree (`crates/ramflux-storage/src/account_db/message_footprint/schema.rs:227`),
which cannot discover ownership in protobuf blobs. A generic storage audit must
visit every persistent column even when a locator was omitted; it must not audit
only the locator registry that could itself be incomplete. ACK, reparse, restore,
backup and own-copy import use the same deletion fence. UI/local-bus exports are
separate copies with an explicit client-cache invalidation contract, not an
excuse to claim remote secure erase.

## 3. Complete proto3 sketch and allocation rules

This is the authoritative sketch to extract for syntax validation. KindId values
select body message types; the uint32 field preserves future numbers. Content is
a generated local/API view only. PaddedInner/Padding describe the crypto framer's
logical values; their protobuf encoding is **not** the encryption plaintext.
Native signed proof bytes use their independently owned, named canonical codecs.
A SignedPayload's payload has the type fixed by its containing field, not an
untrusted schema-name dispatch. Its signature authenticates those exact bytes.

```proto
syntax = "proto3";
package ramflux.message.v1;

enum KindId {
  KIND_UNSPECIFIED = 0;
  KIND_MESSAGE = 1;
  KIND_SERVICE = 2;
  KIND_EDIT = 3;
  KIND_DELETE = 4;
  KIND_REACTION = 5;
  KIND_RECEIPT = 6;
  KIND_TYPING = 7;
  KIND_CONTROL = 8;
  KIND_SURFACE = 9;
  KIND_TASK = 10;
  KIND_CALL = 11;
  KIND_SELF_SYNC = 12;
  reserved 13 to 15;
  reserved "KIND_LEGACY_OPAQUE";
}
message QualifiedDevice {
  string account_anchor = 1;
  string device_id = 2;
  uint64 device_epoch = 3;
}
message EventIdentity {
  bytes id = 1;
  string conversation_id = 2;
  QualifiedDevice author = 3;
  uint64 device_sequence = 4;
  uint64 hlc = 5;
  optional string group_id = 6;
  optional uint64 group_epoch = 7;
  reserved 8, 9;
}
message Inner {
  uint32 layer = 1;
  uint32 kind = 2;
  EventIdentity identity = 3;
  bytes body = 4;
  reserved 5 to 15;
  reserved "schema", "body_base64", "padding";
}
message Padding {
  uint32 unpadded_frame_length = 1;
  uint32 padded_frame_length = 2;
  bytes zeroes = 3;
}
message PaddedInner {
  bytes exact_inner = 1;
  bytes report_opening = 2;
  Padding padding = 3;
}
message Unsupported {
  uint32 layer = 1;
  uint32 kind = 2;
  bytes raw_inner = 3;
  bytes raw_digest = 4;
  string reason = 5;
}
message UnsupportedView {
  uint32 layer = 1;
  uint32 kind = 2;
  bytes raw_digest = 3;
  uint32 raw_length = 4;
  bytes raw_handle = 5;
  string reason = 6;
}
message SignedLayerDeclaration {
  bytes declaration = 1;
  bytes branch_signature = 2;
}
message LayerDeclaration {
  QualifiedDevice device = 1;
  uint32 max_layer = 2;
  uint64 declaration_sequence = 3;
  uint64 issued_at = 4;
  uint64 expires_at = 5;
}
message MessageRef {
  bytes id = 1;
  string conversation_id = 2;
  string author_anchor = 3;
}
message Forward {
  MessageRef original = 1;
  optional string original_display_name = 2;
  bytes origin_assertion = 3;
}
message EntityUnknown {
  uint32 kind = 1;
  bytes original_entity = 2;
}
enum EntityKind {
  ENTITY_UNKNOWN = 0;
  ENTITY_BOLD = 1;
  ENTITY_ITALIC = 2;
  ENTITY_CODE = 3;
  ENTITY_LINK = 4;
  ENTITY_MENTION = 5;
  ENTITY_SPOILER = 6;
  reserved 7 to 15;
}
message Entity {
  uint32 offset = 1;
  uint32 length = 2;
  uint32 kind = 3;
  optional string value = 4;
  EntityUnknown unknown = 5;
}
message Thumbnail {
  string mime_type = 1;
  uint32 width = 2;
  uint32 height = 3;
  bytes encoded_image = 4;
}
message MediaKeySlot {
  QualifiedDevice recipient = 1;
  bytes encrypted_key = 2;
  uint32 format = 3;
}
message MediaManifest {
  bytes manifest_id = 1;
  bytes plaintext_digest = 2;
  uint64 plaintext_length = 3;
  uint64 ciphertext_length = 4;
  uint32 encrypted_segment_bytes = 5;
  uint32 network_chunk_bytes = 6;
  repeated bytes segment_digests = 7;
  repeated MediaKeySlot key_slots = 8;
  string relay_origin = 9;
  bytes read_capability = 10;
  uint64 expires_at = 11;
  string retention_class = 12;
  reserved 13 to 15;
}
message MediaRef {
  string object_id = 1;
  bytes manifest_digest = 2;
  string mime_type = 3;
  uint64 size = 4;
  repeated MediaKeySlot key_slots = 5;
  optional string file_name = 6;
  Thumbnail inline_thumbnail = 7;
  MediaManifest large_manifest = 8;
}
message Message {
  string text = 1;
  repeated Entity entities = 2;
  MessageRef reply_to = 3;
  Forward forward = 4;
  repeated MediaRef media = 5;
  reserved 6 to 15;
  GroupSealedContent sealed_group = 16;
}
message GroupSealedContent {
  string group_id = 1;
  QualifiedDevice author = 2;
  uint64 key_epoch = 3;
  bytes group_state_hash = 4;
  bytes session_id = 5;
  uint64 counter = 6;
  bytes nonce = 7;
  bytes ciphertext = 8;
  bytes ratchet_public_key = 9;
  uint64 previous_chain_length = 10;
  bytes canonical_crypto_header = 11;
  bytes key_commitment = 12;
  bytes content_commitment = 13;
  bytes ciphertext_hash = 14;
  bytes native_authority_proof = 15;
  bytes sender_device_hash = 16;
  bytes recipient_device_hash = 17;
  uint64 device_epoch = 18;
  bytes event_id = 19;
  bytes header_hash = 20;
  bytes franking_commitment = 21;
  bytes commitment = 22;
}
message SignedPayload {
  bytes payload = 1;
  QualifiedDevice signer = 2;
  bytes signature = 3;
}
enum ServiceAction {
  SERVICE_UNSPECIFIED = 0;
  SERVICE_MEMBER_ADDED = 1;
  SERVICE_MEMBER_REMOVED = 2;
  SERVICE_NAME_CHANGED = 3;
  SERVICE_PIN_CHANGED = 4;
  SERVICE_KEY_CHANGED = 5;
}
message Service {
  ServiceAction action = 1;
  repeated QualifiedDevice subjects = 2;
  optional string text = 3;
  MessageRef target = 4;
  bytes native_authority_proof = 5;
}
message Edit {
  MessageRef target = 1;
  uint64 revision = 2;
  bytes previous_content_digest = 3;
  Message replacement = 4;
}
enum DeleteScope {
  DELETE_SCOPE_UNSPECIFIED = 0;
  DELETE_SCOPE_LOCAL = 1;
  DELETE_SCOPE_EVERYONE = 2;
}
message Delete {
  repeated MessageRef targets = 1;
  DeleteScope scope = 2;
  bytes tombstone_id = 3;
  bytes native_group_authorization = 4;
}
message Reaction {
  MessageRef target = 1;
  string token = 2;
  bool remove = 3;
  bytes operation_id = 4;
}
enum ReceiptState {
  RECEIPT_UNSPECIFIED = 0;
  RECEIPT_DELIVERED = 1;
  RECEIPT_READ = 2;
}
message Receipt {
  repeated MessageRef targets = 1;
  ReceiptState state = 2;
  uint64 at = 3;
  QualifiedDevice receiver = 4;
}
message Typing {
  bool active = 1;
  uint64 expires_at = 2;
}
enum ControlOperation {
  CONTROL_UNSPECIFIED = 0;
  CONTROL_PAIR_RESET = 1;
  CONTROL_PAIR_RESET_ACK = 2;
  CONTROL_CONTACT = 3;
  CONTROL_GROUP_STATE = 4;
  CONTROL_GROUP_KEY = 5;
  CONTROL_OWN_CONTACT = 6;
  CONTROL_OWN_HISTORY = 7;
  CONTROL_HOME_MIGRATION = 8;
  CONTROL_RECOVERY = 9;
  CONTROL_LIVE_PRESENCE = 10;
}
message Control {
  ControlOperation operation = 1;
  MessageRef target = 2;
  bytes correlation_id = 3;
  bytes native_signed_document = 4;
  HistoryPage history = 5;
  uint64 epoch = 6;
  repeated QualifiedDevice subjects = 7;
  ContactControl contact = 8;
  GroupKeyDistribution group_key = 9;
  PairRecovery pair_recovery = 10;
  RecoveryControl recovery = 11;
  OwnContactSync own_contact = 12;
}
message ContactControl {
  uint32 action = 1;
  QualifiedDevice requester = 2;
  QualifiedDevice target = 3;
  string display_name = 4;
  bytes native_consent_proof = 5;
  bytes request_id = 6;
}
message GroupKeyDistribution {
  string group_id = 1;
  QualifiedDevice sender = 2;
  uint64 epoch = 3;
  bytes state_hash = 4;
  bytes sender_key_seed = 5;
  bytes sender_signature = 6;
  bytes membership_proof = 7;
}
message PairRecovery {
  bytes old_session_id = 1;
  bytes reset_id = 2;
  bytes transcript_hash = 3;
  uint64 epoch = 4;
}
message RecoveryControl {
  uint32 action = 1;
  bytes invitation_id = 2;
  QualifiedDevice owner = 3;
  QualifiedDevice guardian = 4;
  bytes native_guardian_proof = 5;
  uint64 expires_at = 6;
}
message OwnContactSync {
  uint64 roster_revision = 1;
  repeated ContactControl entries = 2;
  repeated bytes removed_request_ids = 3;
  bytes native_owner_proof = 4;
}
message HistoryItem {
  bytes exact_inner = 1;
  bytes origin_evidence = 2;
  optional Delete tombstone = 3;
}
message HistoryPage {
  bytes transfer_id = 1;
  uint64 page = 2;
  bytes previous_page_digest = 3;
  repeated HistoryItem items = 4;
  bytes page_digest = 5;
}
message SurfaceAction {
  string id = 1;
  string label = 2;
  string method = 3;
  bytes canonical_arguments = 4;
  bytes authority_proof = 5;
}
message SurfaceState {
  string id = 1;
  uint64 revision = 2;
  string text = 3;
  repeated SurfaceAction actions = 4;
  bytes previous_state_digest = 5;
  bytes result_digest = 6;
  optional string selected_action = 7;
  optional string outcome = 8;
}
message Surface {
  uint32 operation = 1;
  SignedPayload state = 2;
}
message TaskState {
  string task_id = 1;
  uint64 revision = 2;
  string requester = 3;
  string assignee = 4;
  string step_id = 5;
  string text = 6;
  bytes canonical_arguments = 7;
  optional string grant_id = 8;
  optional string decision = 9;
  repeated MessageRef depends_on = 10;
  bytes previous_event_digest = 11;
}
message Task {
  uint32 operation = 1;
  SignedPayload event = 2;
  SignedPayload decision_certificate = 3;
  repeated bytes native_membership_witnesses = 4;
}
message CallSignal {
  bytes call_id = 1;
  QualifiedDevice caller = 2;
  repeated QualifiedDevice callees = 3;
  uint64 sequence = 4;
  uint64 expires_at = 5;
  repeated string ice_candidates = 6;
  repeated string codecs = 7;
  bytes media_key_commitment = 8;
  optional string relay = 9;
  bytes relay_lease = 10;
  optional string end_reason = 11;
}
message Call {
  uint32 operation = 1;
  SignedPayload signal = 2;
}
message SelfSync {
  uint32 operation = 1;
  MessageRef read_through = 2;
  optional Message draft = 3;
  MessageRef pin = 4;
  bool mute = 5;
  uint64 revision = 6;
}
message RatchetHeader {
  bytes session_id = 1;
  uint64 counter = 2;
  bytes ratchet_public_key = 3;
  uint64 previous_chain_length = 4;
  bytes sender_device_hash = 5;
  bytes recipient_device_hash = 6;
  uint64 device_epoch = 7;
  bytes event_id = 8;
  bytes key_commitment = 9;
  bytes body_commitment = 10;
  bytes authority_hash = 11;
  bytes bootstrap_transcript_hash = 12;
  bytes bundle_hash = 13;
  reserved 14 to 31;
}
message Content {
  oneof value {
    Message message = 1;
    Service service = 2;
    Edit edit = 3;
    Delete delete = 4;
    Reaction reaction = 5;
    Receipt receipt = 6;
    Typing typing = 7;
    Control control = 8;
    Surface surface = 9;
    Task task = 10;
    Call call = 11;
    SelfSync self_sync = 12;
  }
  reserved 13 to 15;
}
message SendMessage {
  string conversation_id = 1;
  Content content = 2;
  bytes operation_id = 3;
  MessageRef reply_to = 4;
}
message MessageRequest {
  string request_id = 1;
  string account_id = 2;
  oneof action {
    SendMessage send = 3;
    Edit edit = 4;
    Delete delete = 5;
    Reaction reaction = 6;
    Typing typing = 7;
  }
}
message MessageUpdate {
  string account_id = 1;
  uint64 journal_sequence = 2;
  EventIdentity identity = 3;
  oneof state {
    Content content = 4;
    UnsupportedView unsupported = 5;
    Delete tombstone = 6;
  }
}
```

Field numbers are unique within each message; enum values within their enum.
Reserve both a removed field's number and old name forever. Never renumber to
compact a file. 19,000–19,999 remain protobuf-reserved. New kinds start at 16;
13–15 are permanently withdrawn constructor slots. Kind 0 is not a transmitted
business operation. `Unsupported`, Padding and API views are not constructors.

Surface operation numbers are 1=publish, 2=action, 3=result, 4=resync; Task numbers
are 1=start, 2=progress, 3=needs_input, 4=decision, 5=ack, 6=forward,
7=confirmation; Call numbers are 1=invite, 2=accept, 3=reject, 4=ice,
5=end, 6=lease_update; SelfSync numbers are 1=read, 2=draft, 3=pin, 4=mute.
Unknown numbers in these fields are Unsupported, not an inferred default action.
Surface.state.payload has exactly the SurfaceState descriptor. Task.event.payload
and decision_certificate.payload use TaskState plus the fixed decision-operation
validation; Call.signal.payload uses CallSignal. Their exact payload bytes are
signed under separate versioned surface/task/call domains. Native membership,
recovery, custody and group-state proofs keep the native canonical document
formats selected by the **known** ControlOperation; no JSON/schema guessing.
ContactControl.action is 1=request, 2=accept, 3=reject, 4=remove;
RecoveryControl.action is 1=guardian_invite, 2=guardian_accept. The known Control
operation selects exactly its corresponding generated payload (PairRecovery for
reset/ack, ContactControl for contact, GroupKeyDistribution for group key,
OwnContactSync for own contact, HistoryPage for own history, RecoveryControl for
recovery). Group state/home migration use their independently specified signed
native document; live presence uses epoch/subjects. Forbid unrelated payloads
and missing required payloads. A group seed is exactly 32 bytes, secret-bearing,
never a public update field. Unknown action/operation produces Unsupported.
All GroupSealedContent crypto fields retain the existing reviewed primitive's
validation and exact sizes; epoch/author fields bind the same native group
state. They do not create a second application schema. The pair/report AEAD
covers the generated wrapper; nested plaintext uses the same Message descriptor.
The generation tool emits this operation/domain/descriptor table and layer map.
MCP/tool canonical_arguments are application data, not a hidden transport codec.

## 4. Layers, selection and downgrade

### 4.1 Constructor and consumer registry

The final deployed header-encrypted profile has minimum layer 3. S10a initially
implements schema layers 1–2; S10b installs layer 3 and the new mandatory crypto
profile. These are development stages of one release wave, not supported legacy
account formats. S10b resets crypto state; it never falls back to clear headers.
Layer 4 is reserved here for S9 large-manifest fields. It is advertised only by
an implementation completing their semantics. The published message layer is a
wire/semantic contract, not merely proof that a generated struct can be parsed.

| KindId | Kind / body | First layer | Downgrade below first layer | Consumer contract |
|---:|---|---:|---|---|
| 1 | Message | 1 | No usable schema: local PeerUpgradeRequired | S9 media fields; S11 wake; S12 typed MessageUpdate |
| 2 | Service | 1 | No usable schema: local PeerUpgradeRequired | S11 generic wake; S12 typed service update |
| 3 | Edit | 2 | New Message stating an edit, with target reference and new text; never mutate an old row silently | S11 generic wake; S12 Edit request/update |
| 4 | Delete | 2 | Refuse a remote deletion with PeerUpgradeRequired; local deletion remains possible | S9 last-owner erase; S11 generic wake; S12 Delete |
| 5 | Reaction | 2 | New Message text describing the reaction and target; no fabricated reaction state | S11 generic wake; S12 Reaction |
| 6 | Receipt | 1 | Local PeerUpgradeRequired; never infer a receipt from transport ACK | S11 wake policy; S12 typed receipt |
| 7 | Typing | 2 | Suppress transmission; it must not become durable text | S6 ephemeral path; S11 no push; S12 transient update |
| 8 | Control | 1 | Local PeerUpgradeRequired; no text substitute for authenticated commands | S6 mode validation; S11 generic wake; S12 control update |
| 9 | Surface | 1 | Local PeerUpgradeRequired for the authenticated operation | S11 generic wake; S12 generated surface state |
| 10 | Task | 1 | Local PeerUpgradeRequired for the authenticated operation | S11 generic wake; S12 generated task state |
| 11 | Call | 1 | Refuse invite with PeerUpgradeRequired | S6 live ICE; S11 call_wake for invite; S12 Call |
| 12 | SelfSync | 1 | Local PeerUpgradeRequired; never apply a text surrogate to own state | S11 generic wake; S12 read/draft/pin/mute |

Layer 1 also contains Message.sealed_group (field 16). This replaces the SDK
sender-key JSON wrapper, not the reviewed group encryption primitive. Encode a
group Message without sealed_group as protobuf, encrypt it with the existing
authorized sender-key state, fill GroupSealedContent, then pair-seal that typed
Message for each recipient. A sealed_group Message cannot also carry text,
entities, reply, forward or media; its decrypted Message cannot recursively
contain sealed_group. Group metadata and the existing group crypto header thus
remain inside the pair AEAD. The current producer is
`crates/ramflux-sdk/src/client/group_session.rs:617`; its old struct is
`crates/ramflux-sdk/src/group.rs:55`. Canonical_crypto_header is the crypto-owned
canonical header, not an SDK JSON blob. Author/epoch/state hash and original
native evidence must verify against the current group access contract; pair
contact consent is not newly required for authorized non-contact group members.
Unknown nested group content retains both exact outer Inner and exact verified
decrypted group Message, registered and charged to the same raw-byte quota.
Reparse uses the retained verified bytes without retaining a sender-key secret.
A group report additionally needs the existing per-message group opening and
native author evidence to verify the rendered plaintext; never disclose a group
master key. A receipt over group ciphertext alone proves no claimed excerpt.

Entity offsets and lengths are **Unicode scalar values**. Validate UTF-8 once,
construct a scalar-to-byte index once, then validate at most 4,096 ranges in
linear work. Only Web/iOS adapters translate to UTF-16 code units. For example
`A😀é` has scalar offsets 0,1,2 and UTF-16 offsets 0,1,3. Entity.unknown or an
unrecognized kind makes the whole message Unsupported, preserving exact bytes.
No renderer interprets an unknown entity as a URL or command.

Layer 1 Message media uses MediaRef fields 1–6. Layer 2 adds inline_thumbnail
(field 7) and the scalar entity contract. Large_manifest (field 8), and its
network segmentation fields, require layer 4. For an older target, emit a text
caption plus a typed-visible upgrade notice and omit the large attachment; never
send a partial manifest or raw transfer token as text. Unknown newly added
Service/Control/Surface/Task/Call operations require the new layer and have the
same safe refusal/suppression rules as their containing kind. Field additions
require a new layer even when protobuf itself would permit ignoring them.

### 4.2 Signed negotiation state machine

| State / trigger | Required action | Persistent trust / recovery |
|---|---|---|
| Fresh native device | Build/sign LayerDeclaration and obtain endorsement in native Device record before message networking | Pin current native head, device epoch and declaration sequence |
| DM send | Read verified fresh declarations for source and every target device; select their minimum, bounded by compiled support | Missing/expired/foreign statement: LayerUnavailable; refresh outside local-read path |
| Own-device send/history | Take the minimum over source and all included own devices, including a newly admitted sibling | Same-root authorization remains mandatory; unknown raw history is preserved with provenance |
| Group send | Snapshot current signed membership/epochs plus all target device declarations; select one group minimum | Recheck the snapshot before seal/commit; never split semantics by selecting each device independently |
| Membership/declaration changes before submit | Discard unsubmitted prepared representation and rebuild at the new minimum | No previously accepted envelope is silently rewritten |
| Membership changes after accepted submission | Existing authorized packet remains a historical submission under its authenticated epoch; additions get later history/own-copy delivery | Existing history floors, removal and revocation fences still govern access |
| Incoming layer above effective receive maximum | Transactionally retain Unsupported and exact Inner, then ACK | UI shows “This message needs a newer version”; upgrade/re-publish then bounded local reparse |
| Legitimate application rollback | Current device signs a higher-sequence lower declaration and owner endorses a newer native head | Never accept lower sequence/head; code cannot claim a layer above its compiled support |
| Lost holder / expired declaration | Suspend new sends with LayerUnavailable; keep readable history local | Unlock signing holder or attended native recovery/enrollment, publish endorsed statement, refresh pins |
| Restore / own-history import | Treat saved declarations as historical evidence only | Fetch live native head and declaration floors anew; do not activate stale archive capability |

Structural controls never become vaguely equivalent text. The minimum can cause
suppression (Typing), a visible new text event (Reaction/Edit), or a local typed
refusal (Delete/authorization-bearing work). Nodes never inspect/downgrade Inner.
After S10b, a target below mandatory crypto layer 3 yields PeerUpgradeRequired;
message-layer downgrading is not permission to send clear ratchet headers.

## 5. Cryptographic framing, header encryption and padding

### 5.1 Exact plaintext and associated data

Encode one Inner once and preserve those bytes. The body plaintext is:

`u32_be(inner_length) || exact_inner || kf[32] || zero_padding`.

Let L = 4 + inner_length + 32. Pad to Padme(max(L,256)). This separates protobuf
varint lengths from padding calculations. PaddedInner is the generated logical
model used at the crypto boundary; it is never protobuf-encoded as the plaintext.
The receiver checks all lengths, zero padding and limits before exposing Inner.
S10a uses this length/Inner/kf framing without the Padme tail; S10b adds the
mandatory tail and encrypted header, with a development crypto-generation reset.
LP throughout this document is u32 big-endian byte length followed by exact
bytes. Qualified-device binding is LP(account_anchor), LP(device_id), u64_be(epoch).
Hash contexts concatenate LP(domain) and individually LP-framed variable fields;
u64 integers have eight big-endian bytes. Never concatenate ambiguous strings.
Media-manifest digest uses ascending tags, minimal varints, no duplicate fields,
no unknowns, omitted default scalars and original repeated order; encode once
and preserve exact bytes. Native signed RFS1 documents keep their own grammar.
Invalid crypto framing is not an unknown KindId; it uses the existing bounded
integrity/failure path. An authenticated well-framed unknown protobuf body follows
Decision 3 instead. Zeroizing buffers hold kf and plaintext on all exits.

A0 is the canonical sender field set defined in Decision 5. After inserting C,
A is canonical JCS of that sender field set including C. Exclude payload_hash,
signature, encrypted_payload and appended node metadata to avoid self-reference;
the sender signature separately binds the final payload_hash. Header AD binds A,
crypto format and any bootstrap capsule. Body AD binds A and the exact encrypted
header/capsule prefix. Receivers verify the outer signature/hash first and commit
no candidate ratchet state until the complete body and C verify.

### 5.2 Header state and key schedule

Follow the [Signal header-encryption state machine](https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption).
Each receive generation has current/next header keys HKr/NHKr; sending has
HKs/NHKs. A next-key hit drives a DH ratchet. Before that step, promote next header
keys to current; derive new next keys with the root KDF. Skipped-message lookup
is keyed by the authenticated header-key identity and message counter. No state
is mutated on an unauthenticated header or failed body.

The header-schedule domain strings are distinct (the two encrypted commitment
domains are defined below):

| Purpose | Exact info/domain |
|---|---|
| Initial directional header material | `ramflux.message.he.initial.v1` |
| Root/chain/next-header KDF | `ramflux.message.he.root.v1` |
| Header AEAD AD | `ramflux.message.he.header_ad.v1` |
| Bootstrap capsule KDF/AD | `ramflux.message.he.bootstrap.v1` |
| Body AEAD AD | `ramflux.message.he.body_ad.v1` |
| Header-key local index digest | `ramflux.message.he.key_index.v1` |

Use HKDF-SHA256, with length-prefixed context and verified pair binding. Initial
material is 64 bytes from the approved DM-FS-V3-02 X3DH secret SK, salt = its
prekey_bundle_hash, info = initial domain || transcript_hash. Split into
shared_hka (32) and shared_nhkb (32). Initialize directional keys as Signal
section 4.4: initiator HKs=shared_hka, NHKr=shared_nhkb; recipient
NHKr=shared_hka, NHKs=shared_nhkb, other current keys empty. Root steps produce
96 bytes (new RK, CK, NHK) from HKDF with salt=old RK, IKM=verified DH output,
info=root domain || pair_binding. Existing approved bootstrap E/R0 and initial
chain derivations remain authoritative; do not substitute E for R0 or retain
SPK/OPK private material as a new permanent actor secret.

Header encryption uses the already depended-on XChaCha20-Poly1305 primitive
(`crates/ramflux-crypto/Cargo.toml:21`), with a fresh 24-byte CSPRNG nonce and
16-byte tag. Reusing a 96-bit random nonce with a repeatedly used header key is
rejected. The 512-byte header plaintext is u32 length, the generated RatchetHeader
bytes, and zeros. Reject an encoded header above 508 bytes; identifiers are fixed
32-byte ids/digests here, not arbitrary outer strings. Body encryption retains
the reviewed per-message AEAD/MK and its one-use nonce rules. New-profile
session ids and hashes are 32 bytes. Header key_commitment is BLAKE3 of the
LP-framed domain `ramflux.message.he.mk_commit.v1`, MK and pair binding;
body_commitment is BLAKE3 of `ramflux.message.he.plain_commit.v1` and the exact
padded plaintext, with the same framing. These encrypted checks commit no
ciphertext/hash that depends on the header. Thus header construction precedes
body AEAD without a cycle. They replace old semantically different commitments,
not a silent reuse of their old domains.

For a verified claimed device pair: try current receive generation first, then
previous generations newest first, each current key then next key: at most
9 × 2 = **18 header AEAD attempts**. Never enumerate unrelated pairs. To keep
that bound, old header epochs needed for skipped messages consume slots in the
same eight-entry previous-receive ring as old session incarnations; there is no
hidden unbounded archive of extra header keys. A duplicate key is tried once.
Keep at most the existing 1,000 skipped message keys per generation, with their
own expiry. On eviction erase header/chain/skipped secrets and keep only the
existing bounded private tombstone. This can evict an old session incarnation
earlier during frequent DH rotation; it is an explicit bounded-recovery tradeoff.
An archive hit advances only that generation, never demotes the current sender.

No header key / excessive skip / evicted state uses existing bounded authenticated
pair recovery (one reset per minute, ten attempts per rolling day, seven-day
manual-recovery boundary), not UnsupportedSchema. Never generate a reset for an
unauthenticated claimed source. A locked required vault operation retains the
packet without ACK; operator recovery is unlock or attended recovery, not a
cached agreement-secret fallback.

### 5.3 Bootstrap capsule and circular-dependency resolution

A receiver cannot derive an X3DH root/header key until it can read E and select
its private prekey. Therefore claiming to hide the whole bootstrap under that
root is circular. The packet format explicitly distinguishes bootstrap from
established crypto frames; this is a residual bootstrap signal, not an inner
application kind. The bootstrap's public X3DH E is explicitly outer. R0, SPK/OPK
selection, lease binding, session id and all other bootstrap fields are encrypted.

For bootstrap only, derive a capsule key with HKDF-SHA256 from DH(E, recipient
native agreement key), salt = verified qualified pair binding, info = bootstrap
domain || A || E. Domain separation prevents reuse as an X3DH/body key. The
recipient obtains its agreement operation through the DM-FS private provider,
never a saved DB identity seed. Encrypt the exact DM-FS-V3-02 RFS1 bootstrap
header in an XChaCha capsule (24-byte nonce, at most 16 KiB plaintext). It provides
the signed base/selected OPK/SPK/lease inputs needed to verify the approved
transcript and derive SK. Then decrypt the ordinary encrypted header using the
newly initialized header state. Bootstrap needs one capsule AEAD plus one selected
header AEAD; regular blind trial remains bounded at eighteen. Never try bootstrap
DH as a nineteenth fallback on an established-format packet.

Physical CryptoBox framing is one byte format (0 established, 1 bootstrap), then
for format 1: E[32], u32 capsule_ciphertext_length, capsule_nonce[24], capsule
ciphertext (including tag). Both formats then carry header_nonce[24], exactly
528 bytes encrypted header, the existing body nonce[12], and body ciphertext/tag.
No plaintext session id/counter/R0 exists. The outer payload_hash covers this
entire box. Header AD binds the format and full capsule prefix, and body AD binds
that prefix plus encrypted header. Capsule/body/header swaps must fail.

The capsule is decryptable after compromise of the retained native agreement
key and recorded E; this exposes old bootstrap **metadata**, not an X3DH root
without the retired SPK/OPK. Do not claim metadata forward secrecy for the first
packet. Public E, the format byte and larger bootstrap size remain observable.

### 5.4 Header vector production recipe for S10b

These are exact implementation inputs and required output slots, **not fabricated
ciphertext golden values**. S10b must commit independently reproduced output bytes
and run them before activation:

1. Use the approved DM-FS-V3-02 OPK and SPK-only golden inputs/outputs verbatim:
   qualified refs, E secret/public, independent R0, base/OPK canonical bytes,
   SK, prekey_bundle_hash and transcript_hash. Include their canonical hashes in
   each vector manifest so no second bootstrap fixture quietly diverges.
2. Outer sender fields: envelope id = base64url(32 bytes 0x11), source/target refs
   from that vector; created_at=1762128000, ttl=300, message/normal/durable;
   collapse_tag=32 bytes 0x22. Inner: layer=3, kind=1, conversation="vector",
   device_sequence=1, hlc=1, text="A😀é" and bold scalar range [1,1]. Derive its
   logical id by Decision 10. kf=32 bytes 0x33. Use exact generated encoding bytes,
   not a JSON round-trip. Compute C and A in the specified order.
3. Header nonce = bytes 0x00..0x17; body nonce = bytes 0x20..0x2b; bootstrap capsule
   nonce = bytes 0x40..0x57. Nonces are fixed for vectors only. Use the approved
   initial ratchet state/counter with fixed clock; its RatchetHeader includes
   the verified native device epoch, pair hashes, bundle/transcript hashes.
4. Required expected-output slots (hex): inner_bytes, unpadded_frame, padded_frame,
   C, A0, A, initial 64-byte header material, each HK/NHK/RK/CK snapshot, encoded
   header, 512-byte header plaintext, header ciphertext/tag, body ciphertext/tag,
   capsule key/plaintext/ciphertext for both bootstrap modes, complete CryptoBox,
   payload_hash, and sender-signed bytes/signature. Record exact byte lengths.
5. Sequence vectors: first Alice packet; Bob reply/new DH; Alice second packet;
   skipped arrival; previous-session arrival; ring eviction; failed authentication
   preserving byte-identical state. Count attempts and prove <=18. Clock, RNG and
   vault provider are injected, with no public endpoint dependency.
6. An independent implementation verifies every successful decryption and KDF
   slot, not just round-trip through the same code. Negative vectors alter A,
   C, recipient, capsule E, nonce, counter, epoch, root commitment, ratchet key,
   skipped-key index and one tag bit. Each fails without advancing any state.
   Mutation cases are in section 12. Never derive an expected value from the
   production function under test and call it a fixed vector.

### 5.5 Padme definition and sizing

For n=max(L,256), E=floor(log2 n), S=floor(log2 E)+1,
z=max(0,E-S), round up to the next multiple of 2^z. Use integer arithmetic.
The separate no-floor reference results are 17→18, 100→104, 300→304,
1000→1024, 100000→100352. The 256-byte floor supersedes the first two.
No extra power-of-two bucket is applied above the floor.

For typical framed plaintext sizes L=100,300,1000,100000, padded sizes are
256,304,1024,100352: overhead over actual L is 156%, 1.333333%, 2.4%, 0.352%.
The very small floor cost is deliberately not advertised as <=12%. For every
integer L from 1 through 1 MiB, the maximum overhead over max(L,256) is
**6.2467576062742225%**, within the requested 12% budget. The 1 MiB vectors
exercise arithmetic; they do not raise the 512 KiB admitted body cap.

Normal CryptoBox overhead is 581 bytes above padded body: 1 format byte,
24+528 header bytes, 12-byte body nonce and 16-byte body tag. A short body padded
to 256 therefore makes 837 binary bytes, 1,116 base64 characters, before outer
JSON/signature/receipt. Bootstrap adds its bounded capsule and is wake-only for
S11. For a normal short text, S11 measures the **whole** HPKE/device-push-wrapped
provider payload against 3,072 bytes: cached short identity references may fit;
large authority proofs or identifiers may not. If it exceeds the bound, send a
generic wake and fetch by cursor. Never truncate a signed envelope, omit its
receipt or skip the padding floor to fit a push. Preview is off by default;
opt-in preview is produced locally after decryption.

The following table is generated during this round by Appendix A. An independent
JavaScript implementation uses logarithms/ceiling instead of bit masking; its
table is byte-identical and its exhaustive maximum is the same.
| L | Padded | Over max(L, 256) % | Over L % |
|---:|---:|---:|---:|
| 1 | 256 | 0.000000 | 25500.000000 |
| 2 | 256 | 0.000000 | 12700.000000 |
| 3 | 256 | 0.000000 | 8433.333333 |
| 4 | 256 | 0.000000 | 6300.000000 |
| 7 | 256 | 0.000000 | 3557.142857 |
| 8 | 256 | 0.000000 | 3100.000000 |
| 15 | 256 | 0.000000 | 1606.666667 |
| 16 | 256 | 0.000000 | 1500.000000 |
| 17 | 256 | 0.000000 | 1405.882353 |
| 31 | 256 | 0.000000 | 725.806452 |
| 32 | 256 | 0.000000 | 700.000000 |
| 63 | 256 | 0.000000 | 306.349206 |
| 64 | 256 | 0.000000 | 300.000000 |
| 100 | 256 | 0.000000 | 156.000000 |
| 127 | 256 | 0.000000 | 101.574803 |
| 128 | 256 | 0.000000 | 100.000000 |
| 255 | 256 | 0.000000 | 0.392157 |
| 256 | 256 | 0.000000 | 0.000000 |
| 257 | 272 | 5.836576 | 5.836576 |
| 300 | 304 | 1.333333 | 1.333333 |
| 511 | 512 | 0.195695 | 0.195695 |
| 512 | 512 | 0.000000 | 0.000000 |
| 513 | 544 | 6.042885 | 6.042885 |
| 1000 | 1024 | 2.400000 | 2.400000 |
| 1023 | 1024 | 0.097752 | 0.097752 |
| 1024 | 1024 | 0.000000 | 0.000000 |
| 1025 | 1088 | 6.146341 | 6.146341 |
| 2048 | 2048 | 0.000000 | 0.000000 |
| 4095 | 4096 | 0.024420 | 0.024420 |
| 4096 | 4096 | 0.000000 | 0.000000 |
| 4097 | 4352 | 6.224066 | 6.224066 |
| 8192 | 8192 | 0.000000 | 0.000000 |
| 16383 | 16384 | 0.006104 | 0.006104 |
| 16384 | 16384 | 0.000000 | 0.000000 |
| 16385 | 17408 | 6.243515 | 6.243515 |
| 32768 | 32768 | 0.000000 | 0.000000 |
| 65535 | 65536 | 0.001526 | 0.001526 |
| 65536 | 65536 | 0.000000 | 0.000000 |
| 65537 | 67584 | 3.123426 | 3.123426 |
| 100000 | 100352 | 0.352000 | 0.352000 |
| 262144 | 262144 | 0.000000 | 0.000000 |
| 524288 | 524288 | 0.000000 | 0.000000 |
| 1048575 | 1048576 | 0.000095 | 0.000095 |
| 1048576 | 1048576 | 0.000000 | 0.000000 |

## 6. Trimmed outer envelope and producer/consumer inventory

This is the final S10a/S10b envelope contract. JCS sender signatures remain;
protobuf is the inner source, not a replacement for node-visible canonical
routing signatures. All sender fields affecting routing, expiry, transient mode,
collapse and report commitment are signed and bound into AEAD AD. The accepting
node's appended receipt is independently signed.

| Current field | Disposition | Final meaning |
|---|---|---|
| schema / version / domain | Keep with explicit new envelope revision | Fixed client-envelope type, not inner kind dispatch |
| envelope_id | Keep | Per-recipient opaque id, separate from logical event id |
| source_principal_id / source_device_id | Keep | Authenticate and select only the claimed qualified device pair |
| signing_key_id / signature_alg / signature | Keep | Native branch envelope authentication; no anonymous-sender claim |
| target_delivery_id | Keep | Per-device routing |
| routing_set_id | Remove from client envelope | Current group sender already fans out to devices; future node fan-out is a separate design |
| delivery_class | Replace six values with exactly message / call_wake | User/control uniformity except VoIP wake |
| priority | Keep | normal for durable message, low for ephemeral, high for call_wake |
| ttl / created_at | Keep | Node expiry/replay and transient lifetime; no decrypted content needed |
| encrypted_payload / payload_hash | Keep | Opaque CryptoBox and its digest |
| ext.franking | Remove | Replaced by fixed 32-byte report_commitment on every envelope; openings/semantic hashes are encrypted |
| generic ext map | Replace with named bounded fields | source_authority evidence and forward-hop metadata preserve current authenticated routing; node_report_receipt is the sole report appendage |
| session_id, counter, ratchet_public_key, previous_chain_length | Move from readable DmCiphertext serialization into header AEAD | Not node routing inputs |
| device hashes, epoch, event id, key/header/franking semantic commitments | Move into encrypted header/body or remove redundant serialization | The uniform opaque reporting commitment is the explicit outer exception |
| collapse_tag | Add, always present | 32 bytes; per-recipient session/conversation HMAC or random cover value |
| delivery_mode | Add, always present | durable or generic ephemeral; transient classification is an admitted leak |
| node_report_receipt | Add, explicit null before acceptance / receipt after | Independently authenticated acceptance evidence; never alter the sender-signed source claim |

`source_authority` carries existing independently verified native evidence when
needed; it never becomes a new unsigned source identity. Its size/availability
can affect push embedding, but it is not selected by message kind. Existing
home migration forwarding hop fences remain authenticated by their service
frame; clients do not gain a mutable arbitrary ext channel.

### 6.1 Six current values: exhaustive disposition

| Current DeliveryClass | Production producer / consumer at baseline | Final disposition / push category |
|---|---|---|
| OpaqueEvent | `crates/ramflux-sdk/src/dm.rs:443` creates it for DM, receipt (`crates/ramflux-sdk/src/bus/delivery_receipts.rs:192`), group (`crates/ramflux-sdk/src/bus/dispatch/group.rs:930`), own fanout (`crates/ramflux-sdk/src/bus/own_device_copy.rs:249`); federation explicitly emits opaque_event at `crates/ramflux-sdk/src/client/federation.rs:212` | message; generic message wake. Home-migration forwarding also writes opaque_event at `crates/ramflux-node-core/src/home_node_migration.rs:62`. Actual incoming Call invite producers select call_wake explicitly. |
| SelfDeviceControl | Own history producer `crates/ramflux-sdk/src/client/surface/own_history.rs:252`; own-copy constructor overrides the initial class at `crates/ramflux-sdk/src/bus/own_device_copy.rs:250`; receiver class guard at `crates/ramflux-sdk/src/client/own_device_copy.rs:170`; special push mapping `apps/ramflux-gateway/src/clients.rs:467` | message; remove own-device-specific notification category. Routing uses verified recipient device sets, not this class. |
| NotificationWake | Push classifier `apps/ramflux-gateway/src/clients.rs:471`; no normal SDK Envelope producer found at baseline; route tests exercise it | call_wake, only validated invite production; replace legacy synthetic producers/fixtures. |
| ObjectManifest | No production Envelope constructor found; federated-envelope gate rejects it at `crates/ramflux-node-core/src/federation_delivery.rs:147` | Remove enum value. Message.media carries references/manifests. Relay manifest APIs remain their own signed service protocol. |
| ObjectChunk | No production Envelope constructor found; federated-envelope gate rejects it at `crates/ramflux-node-core/src/federation_delivery.rs:148` | Remove enum value. Bulk ciphertext travels via relay, never a third user-envelope class. |
| FederationControl | No client production Envelope constructor; gate rejects it at `crates/ramflux-node-core/src/federation_delivery.rs:149` | Remove from client enum. Node-to-node federation control remains in node service frames. |

The gateway producers sometimes cited at `apps/ramflux-gateway/src/clients.rs:1342`,
`apps/ramflux-gateway/src/serve.rs:637`,
`apps/ramflux-gateway/src/session.rs:2198` and
`apps/ramflux-gateway/src/submit_source.rs:111` are test fixtures, not additional
production message constructors. Update their expectations, not the inventory
of live production paths.

Every class flows through the common envelope serialization/router inbox/WAL
(`crates/ramflux-node-core/src/router_wal.rs:102`), the gateway push classifier
(`apps/ramflux-gateway/src/clients.rs:464`), federation capability gate
(`crates/ramflux-node-core/src/federation_delivery.rs:141`), notify queue/provider
payload (`crates/ramflux-node-core/src/notify.rs:121`) and provider label mapping
(`apps/ramflux-notify/src/main.rs:3232`). Notification policy also consumes the class for TTL at
`crates/ramflux-node-core/src/notify.rs:1841`, priority at
`crates/ramflux-node-core/src/notify.rs:1850`, collapse at
`crates/ramflux-node-core/src/notify.rs:1898` and provider hints at
`crates/ramflux-node-core/src/notify.rs:1927`; VoIP selection is at
`apps/ramflux-notify/src/main.rs:3215`. Replace these old category-specific
policies together. Federation string checks at
`crates/ramflux-node-core/src/federation_delivery.rs:78` and
`crates/ramflux-node-core/src/federation_delivery.rs:113` and the home-migration
forwarding constructor must use the new client/service class mapping. The old
own-copy receiver guard becomes native same-root/target authorization plus the
generated typed payload, never a class-based authority check.
No node decrypts Inner. The federation
gate accepts both new client classes under authenticated opaque-delivery authority;
it does not make FederationControl a valid client submission.

### 6.2 S11 push mapping

| Outer class/mode | Final provider behavior | TTL / collapse |
|---|---|---|
| message / durable | FCM data-only; APNs normal message notification/wake; Web Push generic wake | TTL <= remaining envelope lifetime and 604,800 s; use supplied collapse_tag, not a fixed device-wide key |
| call_wake / durable | High priority; APNs VoIP provider and CallKit handling for a valid incoming invitation | Sender TTL <= min(remaining invitation lifetime,60 s); provider TTL never extends it; call-scoped random collapse tag |
| message / ephemeral | Live session only, no provider request | 5 s, low priority; no notify persistence or offline push |

Typing never gets a call_wake or provider notification. A sender's class is not
proof of the encrypted business kind: the endpoint validates the invitation
before CallKit presentation, and S11 retains source/route/provider abuse budgets.
NotificationDeliveryClass's old task/surface/self/conference distinctions collapse
to generic message notification; call wake remains distinct. Native prekey,
custody, relay and federation service RPCs are outside this client-envelope enum.

## 7. Metadata leaks before and after

| Observable | Before (measured baseline) | After the final profile |
|---|---|---|
| Size | Exact serialized body size; no padding | Padme bucket plus 256-byte minimum; total size still reveals buckets, attachments and bootstrap capsule size |
| Session id | Readable DmCiphertext JSON | Header AEAD; no outer session selector |
| Counter / previous-chain length | Readable JSON integers | Header AEAD; header nonce is random, not an exposed counter |
| Ratchet public key | Readable ratchet_public_key | Header AEAD; bootstrap E is explicitly public, independent R0 is encrypted |
| Device hashes / epoch | Readable DmCiphertext metadata | Header AEAD; outer source/target identity remains visible |
| Inner kind | Prefix/schema guessing at endpoints; class/franking presence can expose coarse kind | Numeric kind stays encrypted; node cannot select a body decoder |
| Class | Six named classes, including own-device/object/control | Exactly message/call_wake; VoIP category and ephemeral mode remain visible |
| Franking | Optional rich ext.franking reveals event/hash fields and presence | Uniform opaque commitment plus acceptance receipt; report opening discloses one selected Inner only by consent |
| Group size | Per-device fan-out and shared timing | Residual: unchanged device fan-out; collapse tags are different per recipient |
| Timing | Observable sends/ACKs, calls and transport activity | Residual: no cover-traffic or mixnet guarantee; call_wake/ephemeral intentionally classify activity |

A representative baseline serialization, using the actual field names in
`crates/ramflux-crypto/src/double_ratchet.rs:141` (values are illustrative,
not a decryptable cryptographic vector):

```json
{"session_id":"pair-session","counter":7,"nonce":[0,0,0,0,0,0,0,0,0,0,0,0],"ciphertext":[1,2,3],"ratchet_public_key":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"previous_chain_length":4,"sender_device_id_hash":[],"recipient_device_id_hash":[],"device_epoch":2,"message_event_id":"event","canonical_header_bytes":[],"header_hash":"public","key_commitment":"public","franking_commitment":"public","commitment":"public","ciphertext_hash":"public"}
```

The empty hash arrays in that shape example abbreviate 32-byte fields; the
baseline Rust type, not this illustrative JSON, defines their accepted lengths.
The example demonstrates that base64 wrapping JSON is not header encryption.

## 8. Deletion and replacement inventory

### 8.1 Types and decoder paths

This inventory is a future implementation plan, not source deletion in this
round. Remove actual redundant message codecs; preserve independently owned
cryptographic domains and persistence labels instead of mistaking every string
for a wire constructor.

| Baseline item | Source | Replacement / responsible implementation |
|---|---|---|
| SDK Kind and Routing / Plaintext body_base64 | `crates/ramflux-sdk/src/client/routed/mod.rs:33`, `crates/ramflux-sdk/src/client/routed/mod.rs:44`, `crates/ramflux-sdk/src/client/routed/mod.rs:55` | Generated Inner/EventIdentity/KindId and the bounded descriptor dispatch; S10a |
| call byte prefix | `crates/ramflux-sdk/src/client/call/mod.rs:14` | Kind 11 Call with operation registry; S10a |
| surface byte prefix | `crates/ramflux-sdk/src/client/surface/carrier.rs:9` | Kind 9 Surface; S10a |
| task byte prefix | `crates/ramflux-sdk/src/client/task/carrier.rs:9` | Kind 10 Task; S10a |
| Own/surface/task try-parse chain and schema-switch controls | `crates/ramflux-sdk/src/client/routed/control.rs:36`, `crates/ramflux-sdk/src/client/routed/control.rs:52`, `crates/ramflux-sdk/src/client/routed/control.rs:136` | One numeric constructor dispatch plus its descriptor, never guess by JSON structure; S10a |
| Unknown control/project rejection and unknown-as-text path | `crates/ramflux-sdk/src/client/routed/project.rs:173`, `docs/client_read_model.md:295` | Transactional Unsupported/raw retention; S10a |
| MessageEventBody | `crates/ramflux-protocol/src/events.rs:347` | Remove unused parallel event family; Message/Edit/Delete/Reaction/Message.media/Forward map to generated kinds; S10a |
| ConversationEventBody | `crates/ramflux-protocol/src/events.rs:403` | Generated Service/Control and native authority proof; retain unrelated used identity/group types; S10a |
| BotEventBody | `crates/ramflux-protocol/src/surfaces.rs:403` | Generated Surface/Task, not another untagged wire family; S10a |
| ClientEvent<T> and its only sort helper | `crates/ramflux-protocol/src/core_types.rs:330`, `crates/ramflux-protocol/src/state.rs:51` | Generated MessageUpdate/EventIdentity ordering; remove unused generic wire facade; S10a |
| NackReason::UnsupportedSchema and its test | `crates/ramflux-protocol/src/core_types.rs:291`, `crates/ramflux-node-core/src/tests/server_retention_r2.rs:51` | Delete variant/fixture; unknown-kind ACK/raw-retention regression; S10a |
| DmCiphertext clear header metadata / old codec | `crates/ramflux-crypto/src/double_ratchet.rs:141`, `crates/ramflux-sdk/src/dm.rs:9` | CryptoBox and encrypted RatchetHeader; S10b |
| Optional franking production/tag/signature exclusions | `crates/ramflux-sdk/src/client/dm.rs:122`, `apps/ramflux-gateway/src/session.rs:1508`, `crates/ramflux-protocol/src/envelope_sender.rs:18` | Uniform C, encrypted opening and independently signed node receipt; S10a |
| Local-only DM delete dispatch | `crates/ramflux-sdk/src/bus/dispatch/message.rs:353` | Typed Delete with scoped replicated tombstone; S10a |
| Desktop string-key message decoder | `desktop/crates/ramflux-desktop-sdk/src/translate/messages.rs:54` | Generated MessageUpdate translation without schema-key parsing; S10c |
| Desktop parallel MomentKind wire classification | `desktop/crates/ramflux-desktop-core/src/model/moment.rs:380` | Presentation projection from generated Content/UnsupportedView; UI-only visual enums may remain, not another protocol source; S10c |
| Desktop surface prefix test | `desktop/crates/ramflux-desktop-sdk/src/translate/surfaces.rs:108` | Generated Surface variant; S10c |

### 8.2 Exhaustive SDK literal set, grouped by owner

Every distinct literal below has an explicit replacement or a stated retained
non-message responsibility. Test-only historical versions are removed with the
old decoder; they are not advertised as fallback compatibility. Locations include
all baseline occurrences, so duplicate fixtures do not inflate the distinct set.

#### Owner: `crates/ramflux-sdk/src`

| Literal | All baseline locations | Replacement / disposition |
|---|---|---|
| `ramflux.sdk.gateway.nonce.v1` | `crates/ramflux-sdk/src/constants.rs:9` | Retain gateway authentication nonce domain; node service protocol, not Inner. |
| `ramflux.sdk.group.route.device.v2` | `crates/ramflux-sdk/src/group.rs:193` | Retain/re-home group routing/crypto state domain with its existing preimage; hide its data inside pair-sealed typed group payload. |
| `ramflux.sdk.group.route.group.v2` | `crates/ramflux-sdk/src/group.rs:182` | Retain/re-home group routing/crypto state domain with its existing preimage; hide its data inside pair-sealed typed group payload. |
| `ramflux.sdk.group.sender.state.v2` | `crates/ramflux-sdk/src/group.rs:89` | Retain/re-home group routing/crypto state domain with its existing preimage; hide its data inside pair-sealed typed group payload. |
| `ramflux.sdk.object_key_slot.v1` | `crates/ramflux-sdk/src/object.rs:1385` | MediaKeySlot; remove legacy untyped slot wrapper after native cutover. |
| `ramflux.sdk.shared_group.sender.state.v1` | `crates/ramflux-sdk/src/group.rs:113` | Retain/re-home group routing/crypto state domain with its existing preimage; hide its data inside pair-sealed typed group payload. |

#### Owner: `crates/ramflux-sdk/src/bus`

| Literal | All baseline locations | Replacement / disposition |
|---|---|---|
| `ramflux.sdk.dm_x3dh_envelope.v1` | `crates/ramflux-sdk/src/bus/sync_driver.rs:401`, `crates/ramflux-sdk/src/client/routed/contact_recovery_tests.rs:277`, `crates/ramflux-sdk/src/client/routed/contact_recovery_tests.rs:353`, `crates/ramflux-sdk/src/client/routed/contact_recovery_tests.rs:402`, `crates/ramflux-sdk/src/client/routed/legacy.rs:37`, `crates/ramflux-sdk/src/client/routed/legacy_bootstrap_retry_tests.rs:99`, `crates/ramflux-sdk/src/client/routed/legacy_group_auth_tests.rs:121`, `crates/ramflux-sdk/src/client/routed/r4_tests.rs:354`, `crates/ramflux-sdk/src/client/routed/review_tests.rs:65`, `crates/ramflux-sdk/src/client/routed/tests.rs:430`, `crates/ramflux-sdk/src/dm.rs:224` | Remove legacy wrapper; native bootstrap capsule/CryptoBox replaces it. |
| `ramflux.sdk.group_sender_key.message.v1` | `crates/ramflux-sdk/src/bus/sync_driver.rs:401`, `crates/ramflux-sdk/src/bus/sync_driver.rs:406`, `crates/ramflux-sdk/src/client/group_quarantine.rs:81`, `crates/ramflux-sdk/src/client/group_session.rs:619`, `crates/ramflux-sdk/src/client/group_session.rs:670`, `crates/ramflux-sdk/src/client/inbox_failure.rs:64`, `crates/ramflux-sdk/src/client/own_device_sync.rs:1204`, `crates/ramflux-sdk/src/client/routed/r9_tests.rs:41`, `crates/ramflux-sdk/src/client/routed/review_tests.rs:117`, `crates/ramflux-sdk/src/client/routed/tests.rs:679`, `crates/ramflux-sdk/src/group.rs:145`, `crates/ramflux-sdk/src/group.rs:271` | Remove old sender-key packet wrapper; typed group crypto payload inside pair-sealed Message. |
| `ramflux.sdk.receipt_event.v1` | `crates/ramflux-sdk/src/bus/delivery_receipts.rs:154`, `crates/ramflux-sdk/src/bus/dispatch/message.rs:434`, `crates/ramflux-sdk/src/bus/dispatch/message.rs:494`, `crates/ramflux-sdk/src/bus/receipt_tests/bindings.rs:123`, `crates/ramflux-sdk/src/client/dm.rs:777`, `crates/ramflux-sdk/src/client/routed/participant_tests.rs:15`, `crates/ramflux-sdk/src/client/routed/participant_tests.rs:96`, `crates/ramflux-sdk/src/client/routed/r4_tests.rs:397`, `crates/ramflux-sdk/src/dm.rs:187` | Receipt kind; remove signed event JSON schema sniffing. |

#### Owner: `crates/ramflux-sdk/src/bus/dispatch`

| Literal | All baseline locations | Replacement / disposition |
|---|---|---|
| `ramflux.sdk.device.branch_authorized.v1` | `crates/ramflux-sdk/src/bus/dispatch/device.rs:337` | Service key/device change plus native proof; typed local update replaces string event payload. |
| `ramflux.sdk.group_control.delivery_id.v1` | `crates/ramflux-sdk/src/bus/dispatch/group.rs:630` | Retain routing-id derivation as a shared group primitive; not a body schema. |
| `ramflux.sdk.group_control.v1` | `crates/ramflux-sdk/src/bus/dispatch/group.rs:481`, `crates/ramflux-sdk/src/bus/dispatch/group.rs:561`, `crates/ramflux-sdk/src/client/group_delivery.rs:348` | Remove old group-control decoder; Control/GroupState with native proof. |
| `ramflux.sdk.group_sender_key.distribution_envelope.v1` | `crates/ramflux-sdk/src/bus/dispatch/group.rs:1113`, `crates/ramflux-sdk/src/bus/dispatch/task_group.rs:110`, `crates/ramflux-sdk/src/client/group_delivery.rs:93`, `crates/ramflux-sdk/src/client/group_delivery.rs:174`, `crates/ramflux-sdk/src/client/routed/legacy_bootstrap_retry_tests.rs:80`, `crates/ramflux-sdk/src/client/routed/legacy_group_auth_tests.rs:106`, `crates/ramflux-sdk/src/client/routed/r9_tests.rs:102`, `crates/ramflux-sdk/src/client/routed/tests.rs:360`, `crates/ramflux-sdk/src/client/routed/tests.rs:513`, `crates/ramflux-sdk/src/client/routed/tests.rs:757` | Control/GroupKey; remove SDK envelope wrapper around authenticated distribution. |

#### Owner: `crates/ramflux-sdk/src/client`

| Literal | All baseline locations | Replacement / disposition |
|---|---|---|
| `ramflux.sdk.contact.device_id_hash.v1` | `crates/ramflux-sdk/src/client/contact.rs:978`, `crates/ramflux-sdk/src/client/contact.rs:1136`, `crates/ramflux-sdk/src/client/contact.rs:1166` | Retain/re-home the existing identity/safety/group hash domain and unchanged preimage; not an Inner constructor. |
| `ramflux.sdk.contact.device_identity_key_hash.v1` | `crates/ramflux-sdk/src/client/contact.rs:983`, `crates/ramflux-sdk/src/client/contact.rs:1171` | Retain/re-home the existing identity/safety/group hash domain and unchanged preimage; not an Inner constructor. |
| `ramflux.sdk.contact.device_signing_key_hash.v1` | `crates/ramflux-sdk/src/client/contact.rs:988`, `crates/ramflux-sdk/src/client/contact.rs:1176` | Retain/re-home the existing identity/safety/group hash domain and unchanged preimage; not an Inner constructor. |
| `ramflux.sdk.contact.device_x25519_identity_key_hash.v1` | `crates/ramflux-sdk/src/client/contact.rs:993`, `crates/ramflux-sdk/src/client/contact.rs:1181` | Retain/re-home the existing identity/safety/group hash domain and unchanged preimage; not an Inner constructor. |
| `ramflux.sdk.contact.identity_key_hash.v1` | `crates/ramflux-sdk/src/client/contact.rs:967`, `crates/ramflux-sdk/src/client/contact.rs:1113` | Retain/re-home the existing identity/safety/group hash domain and unchanged preimage; not an Inner constructor. |
| `ramflux.sdk.contact.lineage_head.v1` | `crates/ramflux-sdk/src/client/contact.rs:972`, `crates/ramflux-sdk/src/client/contact.rs:1118` | Retain/re-home the existing identity/safety/group hash domain and unchanged preimage; not an Inner constructor. |
| `ramflux.sdk.dm_attachment_envelope.v1` | `crates/ramflux-sdk/src/client/dm.rs:213`, `crates/ramflux-sdk/src/client/dm.rs:944`, `crates/ramflux-sdk/src/client/routed/r4_tests.rs:451`, `crates/ramflux-sdk/src/client/routed/r4_tests.rs:520`, `crates/ramflux-sdk/src/client/routed/r4_tests.rs:613`, `crates/ramflux-sdk/src/client/routed/review_tests.rs:914` | Message.media plus typed MediaRef; remove attachment JSON sniffing. |
| `ramflux.sdk.dm_attachment_ref.v1` | `crates/ramflux-sdk/src/bus/backup_jobs/tests.rs:724`, `crates/ramflux-sdk/src/bus/dispatch/surface_history_import_tests.rs:61`, `crates/ramflux-sdk/src/bus/dispatch/tests/deferred_attachment.rs:24`, `crates/ramflux-sdk/src/client/deferred_attachment.rs:558`, `crates/ramflux-sdk/src/client/deferred_attachment/tests.rs:57`, `crates/ramflux-sdk/src/client/object.rs:237`, `crates/ramflux-sdk/src/client/object.rs:451`, `crates/ramflux-sdk/src/client/object.rs:641`, `crates/ramflux-sdk/src/client/object_cache_tests.rs:51`, `crates/ramflux-sdk/src/client/own_device_sync.rs:844`, `crates/ramflux-sdk/src/client/own_device_sync.rs:1003`, `crates/ramflux-sdk/src/client/routed/r4_tests.rs:413`, `crates/ramflux-sdk/src/object.rs:1370` | MediaRef; remove active old reference codec and historical live fixtures. |
| `ramflux.sdk.group.invite_record_root.v1` | `crates/ramflux-sdk/src/client/group_control_roots.rs:34`, `crates/ramflux-storage/src/account_db/groups.rs:885` | Retain/re-home the existing identity/safety/group hash domain and unchanged preimage; not an Inner constructor. |
| `ramflux.sdk.group.invite_root.v1` | `crates/ramflux-sdk/src/client/group_control_roots.rs:25` | Retain/re-home the existing identity/safety/group hash domain and unchanged preimage; not an Inner constructor. |
| `ramflux.sdk.group.key_change.v1` | `crates/ramflux-sdk/src/client/group_key_safety.rs:60` | Retain/re-home the existing identity/safety/group hash domain and unchanged preimage; not an Inner constructor. |
| `ramflux.sdk.group.sender.event.v2` | `crates/ramflux-sdk/src/client/group_session.rs:128` | Retain/re-home group routing/crypto state domain with its existing preimage; hide its data inside pair-sealed typed group payload. |
| `ramflux.sdk.group_sender_key.distribution.v1` | `crates/ramflux-sdk/src/client/group_session.rs:317`, `crates/ramflux-sdk/src/client/group_session.rs:790`, `crates/ramflux-sdk/src/client/own_device_sync.rs:544` | Control/GroupKey with typed native distribution proof; remove obsolete SDK schema version dispatch, preserving native authorization. |
| `ramflux.sdk.group_sender_key.distribution.v2` | `crates/ramflux-sdk/src/client/group_session.rs:318`, `crates/ramflux-sdk/src/client/routed/backup_tests.rs:219`, `crates/ramflux-sdk/src/client/routed/r9_tests.rs:28` | Control/GroupKey with typed native distribution proof; remove obsolete SDK schema version dispatch, preserving native authorization. |
| `ramflux.sdk.group_sender_key.distribution.v3` | `crates/ramflux-sdk/src/client/group_session.rs:319`, `crates/ramflux-sdk/src/client/own_device_sync.rs:542`, `crates/ramflux-sdk/src/client/shared_group/bootstrap.rs:175` | Control/GroupKey with typed native distribution proof; remove obsolete SDK schema version dispatch, preserving native authorization. |
| `ramflux.sdk.group_sender_key.distribution.v4` | `crates/ramflux-sdk/src/client/group_session.rs:320`, `crates/ramflux-sdk/src/client/shared_group/bootstrap.rs:176` | Control/GroupKey with typed native distribution proof; remove obsolete SDK schema version dispatch, preserving native authorization. |
| `ramflux.sdk.group_sender_key.message.v2` | `crates/ramflux-sdk/src/client/group_session.rs:617`, `crates/ramflux-sdk/src/client/group_session.rs:671`, `crates/ramflux-sdk/src/group.rs:145` | Typed group crypto payload inside pair-sealed Message; no readable group header in outer payload. |
| `ramflux.sdk.home_migration.intent.v1` | `crates/ramflux-sdk/src/client/home_migration.rs:28` | Retain native migration intent hash domain; Control carries the native signed proof. |
| `ramflux.sdk.object_key_slot.dm.v1` | `crates/ramflux-sdk/src/bus/backup_jobs/tests.rs:727`, `crates/ramflux-sdk/src/bus/dispatch/tests/deferred_attachment.rs:27`, `crates/ramflux-sdk/src/client/deferred_attachment/tests.rs:40`, `crates/ramflux-sdk/src/client/object.rs:364`, `crates/ramflux-sdk/src/client/object.rs:2913`, `crates/ramflux-sdk/src/client/object_cache_tests.rs:57`, `crates/ramflux-sdk/src/client/own_device_sync.rs:870`, `crates/ramflux-sdk/src/client/own_device_sync.rs:1018` | MediaKeySlot; remove active legacy slot codec and live legacy fixtures. |
| `ramflux.sdk.object_key_slot.dm.v2` | `crates/ramflux-sdk/src/client/own_device_copy.rs:50`, `crates/ramflux-sdk/src/client/routed/object_slot.rs:42`, `crates/ramflux-sdk/src/client/routed/object_slot.rs:107`, `crates/ramflux-sdk/src/client/routed/r4_tests.rs:428`, `crates/ramflux-sdk/src/client/routed/r5_tests.rs:289` | MediaKeySlot with native opaque encrypted key; no SDK schema-name dispatch. |
| `ramflux.sdk.object_share_package.v1` | `crates/ramflux-sdk/src/client/deferred_attachment/tests.rs:74`, `crates/ramflux-sdk/src/client/object.rs:148`, `crates/ramflux-sdk/src/client/object.rs:320` | Message.media with typed MediaRef/key slots; remove package JSON sniffing. |
| `ramflux.sdk.own_contact.copy.v3` | `crates/ramflux-sdk/src/client/own_contact.rs:165` | Retain authority-scoped copy-id hash domain; Control/OwnContact replaces body dispatch. |
| `ramflux.sdk.own_contact.roster.v1` | `crates/ramflux-sdk/src/client/own_contact.rs:214` | Retain verified roster hash domain; no own-device class. |
| `ramflux.sdk.own_device_history_bundle.v1` | `crates/ramflux-sdk/src/bus/dispatch/surface_history_import_tests.rs:16`, `crates/ramflux-sdk/src/client/own_contact/review_r9_tests.rs:170`, `crates/ramflux-sdk/src/client/own_device_sync.rs:764`, `crates/ramflux-sdk/src/client/own_device_sync.rs:1065` | Remove old live history format; Control/OwnHistory and HistoryPage are the new source. |
| `ramflux.sdk.own_device_history_bundle.v2` | `crates/ramflux-sdk/src/client/own_device_history_pages.rs:12`, `crates/ramflux-sdk/src/client/own_device_history_pages.rs:120`, `crates/ramflux-sdk/src/client/own_device_sync.rs:765`, `crates/ramflux-sdk/src/client/own_device_sync.rs:1491` | Control/OwnHistory HistoryPage; raw unsupported items preserve exact bytes. |
| `ramflux.sdk.own_device_history_bundle.v3` | `crates/ramflux-sdk/src/client/own_device_sync.rs:399`, `crates/ramflux-sdk/src/client/own_device_sync.rs:766` | Control/OwnHistory HistoryPage with authenticated origin and deletion fence. |
| `ramflux.sdk.own_device_message.v2` | `crates/ramflux-sdk/src/client/own_device_copy.rs:14` | Typed pair-sealed Inner; own-device routing is recipient selection, not a prefix/domain codec. |
| `ramflux.sdk.own_device_sync.v1` | `crates/ramflux-sdk/src/bus/dispatch/surface_history_import_tests.rs:50`, `crates/ramflux-sdk/src/client/dm.rs:120`, `crates/ramflux-sdk/src/client/own_device_sync.rs:158`, `crates/ramflux-sdk/src/client/own_device_sync.rs:588`, `crates/ramflux-sdk/src/client/own_device_sync.rs:992`, `crates/ramflux-sdk/src/client/routed/control.rs:53`, `crates/ramflux-sdk/src/client/routed/receive.rs:86` | Control/OwnHistory; replace schema check and historical-message suppression heuristic. |
| `ramflux.sdk.pending_group_payload.v2` | `crates/ramflux-sdk/src/client/group_pending.rs:14`, `crates/ramflux-sdk/src/client/group_pending.rs:23` | Replace private pending-body codec with bounded registered raw/copy handle; native group dependency stays. |
| `ramflux.sdk.private_prekey.v2` | `crates/ramflux-sdk/src/client/private_prekeys.rs:108` | DM-FS private-provider migration owns retirement of this actor format; never serialize it as Inner. |
| `ramflux.sdk.recovery.guardian_accept.v1` | `crates/ramflux-sdk/src/client/recovery.rs:683` | Control/Recovery with native signed guardian proof; remove private wire discriminator. |
| `ramflux.sdk.recovery.guardian_invite.v1` | `crates/ramflux-sdk/src/client/recovery.rs:633`, `crates/ramflux-sdk/src/client/recovery.rs:733` | Control/Recovery with native signed guardian proof; remove private wire discriminator. |
| `ramflux.sdk.safety.device.v1` | `crates/ramflux-sdk/src/client/group_key_safety.rs:41` | Retain/re-home the existing identity/safety/group hash domain and unchanged preimage; not an Inner constructor. |
| `ramflux.sdk.safety.member.v1` | `crates/ramflux-sdk/src/client/group_key_safety.rs:54` | Retain/re-home the existing identity/safety/group hash domain and unchanged preimage; not an Inner constructor. |
| `ramflux.sdk.x3dh.identity.v1` | `crates/ramflux-sdk/src/client/identity.rs:174`, `crates/ramflux-sdk/src/client/identity_authority/owned.rs:55` | DM-FS owns the native agreement commitment domain; no silent hash-preimage change. |
| `ramflux.sdk.x3dh.signed_prekey.v1` | `crates/ramflux-sdk/src/client/identity.rs:176` | DM-FS owns replacement by signed native prekey base; no live legacy prekey sender survives activation. |

#### Owner: `crates/ramflux-sdk/src/client/contact_requests`

| Literal | All baseline locations | Replacement / disposition |
|---|---|---|
| `ramflux.sdk.contact_request.envelope.v1` | `crates/ramflux-sdk/src/client/contact_requests/wire.rs:8` | Control/Contact with typed source/target and existing consent proof; remove string dispatch. |

#### Owner: `crates/ramflux-sdk/src/client/identity_authority`

| Literal | All baseline locations | Replacement / disposition |
|---|---|---|
| `ramflux.sdk.authority_rejection.v1` | `crates/ramflux-sdk/src/client/identity_authority/directory.rs:101` | Retain rejection-cache key domain; not a wire constructor. |
| `ramflux.sdk.profile_read_record.v1` | `crates/ramflux-sdk/src/client/identity_authority/profile_read.rs:160` | Retain exact-record verification-cache digest; local trust cache only. |
| `ramflux.sdk.verified_device_authority.v1` | `crates/ramflux-sdk/src/client/identity_authority/mod.rs:35` | Retire superseded authority record codec with native-only cleanup; current verified native authority is retained. |
| `ramflux.sdk.verified_device_authority.v3` | `crates/ramflux-sdk/src/client/identity_authority/custody_directory.rs:470` | Retain native verified-authority persistence record; add endorsed layer declaration, not a parallel message codec. |

#### Owner: `crates/ramflux-sdk/src/client/routed`

| Literal | All baseline locations | Replacement / disposition |
|---|---|---|
| `ramflux.sdk.bootstrap.hlc.v2` | `crates/ramflux-sdk/src/client/routed/bootstrap_sequence.rs:22` | S10b uses the native RFS1 transcript/sequence inside encrypted bootstrap capsule; remove old AAD dispatch. |
| `ramflux.sdk.bootstrap.owner.v2` | `crates/ramflux-sdk/src/client/routed/bootstrap_sequence.rs:89` | Retain private bootstrap-owner fence digest; never use it for constructor dispatch. |
| `ramflux.sdk.bootstrap.sequence.v1` | `crates/ramflux-sdk/src/client/routed/bootstrap_sequence.rs:24`, `crates/ramflux-sdk/src/client/routed/r9_tests.rs:245` | Remove legacy bootstrap AAD variant; native transcript and EventIdentity carry sequence. |
| `ramflux.sdk.dm_x3dh_envelope.v2` | `crates/ramflux-sdk/src/client/routed/contact_request_tests.rs:313`, `crates/ramflux-sdk/src/client/routed/mod.rs:245`, `crates/ramflux-sdk/src/client/routed/mod.rs:329`, `crates/ramflux-sdk/src/client/routed/object_slot.rs:117`, `crates/ramflux-sdk/src/client/routed/object_slot.rs:223`, `crates/ramflux-sdk/src/client/routed/review_tests.rs:516` | CryptoBox + generated Inner; remove SDK JSON wrapper. |
| `ramflux.sdk.envelope.aad.v2` | `crates/ramflux-sdk/src/client/routed/mod.rs:76` | Replace with section 5 sender AD and versioned HE/body domains; never reuse changed preimages silently. |
| `ramflux.sdk.object.slot.aad.v2` | `crates/ramflux-sdk/src/client/routed/object_slot.rs:261` | Retain object-slot authenticated-data domain; encrypted slot bytes are typed MediaKeySlot. |
| `ramflux.sdk.object.slot.receipt.v2` | `crates/ramflux-sdk/src/client/routed/object_slot.rs:279` | Retain private object-slot replay digest domain; not a message constructor. |
| `ramflux.sdk.receipt.v3` | `crates/ramflux-sdk/src/bus/receipt_tests/erasure_audit.rs:115`, `crates/ramflux-sdk/src/client/routed/committed.rs:30`, `crates/ramflux-storage/src/account_db/message_footprint/tests.rs:78` | Retain account-scoped committed-receipt digest domain; Receipt kind replaces the payload codec. |
| `ramflux.sdk.receive.watermark.v2` | `crates/ramflux-sdk/src/client/routed/committed.rs:168` | Retain private conversation watermark domain and sticky replay semantics. |
| `ramflux.sdk.root_bound_dm_pair.v1` | `crates/ramflux-sdk/src/client/routed/session.rs:285`, `crates/ramflux-storage/src/account_db/runtime/ratchet_retirement.rs:122` | Retain private pair-scope/retirement format; it is not message content. |
| `ramflux.sdk.slot.watermark.v2` | `crates/ramflux-sdk/src/client/routed/committed.rs:180` | Retain private object-slot watermark domain; no new application kind. |
| `ramflux.sdk.unverified_inbox.v1` | `crates/ramflux-sdk/src/client/routed/committed.rs:78` | Retain bounded unauthenticated quarantine/replay-key domain; never treat it as Unsupported authorization. |

#### Owner: `crates/ramflux-sdk/src/client/shared_group`

| Literal | All baseline locations | Replacement / disposition |
|---|---|---|
| `ramflux.sdk.group_control.v2` | `crates/ramflux-sdk/src/client/shared_group/controls.rs:8` | Control/GroupState; native signed group documents retain their own verifier. |
| `ramflux.sdk.group_state.v2` | `crates/ramflux-sdk/src/client/shared_group/bootstrap.rs:12` | Control/GroupState plus native authority snapshot; remove private message schema dispatch. |
| `ramflux.sdk.own_group_consent.v1` | `crates/ramflux-sdk/src/client/shared_group/own_consent.rs:9` | Control/GroupState/SelfSync typed update with existing consent proof; no schema dispatch. |

#### Owner: `crates/ramflux-sdk/src/custody`

| Literal | All baseline locations | Replacement / disposition |
|---|---|---|
| `ramflux.sdk.home_migration.proposal.v1` | `crates/ramflux-sdk/src/custody/home_authorization.rs:22` | Retain native migration authorization digest; not an application kind. |

## 9. Migration, persistence, readers and erasure

### 9.1 Activation is a development reset

There are no supported legacy accounts in this wave. S10a advances the local
storage/profile generation and requires a new native-v3 development account
store; S10b resets the cryptographic profile again at mandatory layer 3. Refuse
an old-generation database/archive with `SchemaResetRequired` and an explicit
create-fresh-store instruction. Do not silently destroy a user's selected path.
Preserve a separately retained old archive only as an explicitly unreadable
external artifact; do not import it into the active profile or use it as live
native authority. No dual reader, JSON/prefix fallback, legacy authority or
compatibility shim survives activation. Replacing test fixtures is part of the
implementation, not evidence that old data migrates.

Coordinated client/node activation installs the two classes, delivery_mode,
collapse_tag and uniform report receipt. An old node cannot accept the new
profile and is rejected during profile discovery; the SDK does not downgrade
outer fields to evade this. Nodes never interpret Inner. Ciphertext inbox/WAL
rows from the development profile are drained or reset by the operator before
activation, never reinterpreted as new crypto boxes. Rollback requires restoring
a complete matching development environment, not opening a new DB with old code.

Stored row families that remain in the new generation: current native account
identity and verified authority; native group membership/epoch records; consent
and contact state; current pair/ratchet/provider state; operation idempotency;
transport cursors/ACKs; projection/journal/outbox; object index and owner links;
message copy bindings, sticky tombstones and private replay/retirement floors.
They are **new-generation records**, not old content carried across a reset.
The existing native canonical signed documents and hash domains identified as
retained in section 8 keep their meanings. A same-generation backup may restore
history after deletion reconciliation; it never restores live authority pins,
leases, active layer declarations or publishable prekey private material.

### 9.2 Reader inventory before changing stored bytes

These are consumers, not merely writers. Inventory both the named keys and
physical table columns; search for `runtime_message_content`, `state_json`,
`body_json`, `response_json`, `runtime_unrouted`, `message_copy_binding`,
`own_device_history`, the three carrier prefixes and every section 8 literal.
The implementation's source audit must classify every hit before removing a
reader. The baseline ownership map is:

| Stored family | Readers / baseline ownership | New read and erase rule |
|---|---|---|
| Message content and projection | `crates/ramflux-storage/src/account_db/journal/mod.rs:57`; SDK routed/project and bus journal/project; local history/bus queries | Generated Content or UnsupportedView, exact raw loaded only by the bounded worker; delete removes raw/content and leaves a content-free tombstone |
| Journal events, unrouted and retry/dead-letter entries | `crates/ramflux-storage/src/account_db/journal/mod.rs:43`, `crates/ramflux-storage/src/account_db/journal/mod.rs:52`, `crates/ramflux-storage/src/account_db/journal/mod.rs:53`; routed receive/redrive and bus journal | Registered copy locators; ciphertext retry is not a second unregistered plaintext cache; Unsupported is never inserted in dead letter |
| Actor snapshots and prepared work | `crates/ramflux-storage/src/account_db/runtime/schema.rs:28`; routed session, group_session, own_device_copy, own_device_history_pages, surface/own_history and task/own_history | Generated state references raw rows by handle; any unavoidable inline body is a registered copy; erasure invalidates cached/prepared work before it can publish |
| Runtime outbox / operation results | `crates/ramflux-storage/src/account_db/runtime/schema.rs:14`, `crates/ramflux-storage/src/account_db/runtime/schema.rs:42`; runtime publication/idempotent replay and request adapters | Outbox pointers are not content copies; operation results containing content are registered and scrubbed, id-only results need no content locator |
| Copy linkage / privacy indexes | `crates/ramflux-storage/src/account_db/message_footprint/schema.rs:15`, `crates/ramflux-storage/src/account_db/message_footprint/schema.rs:20`; indexed erasure and late-write guard | Explicit ownership before publication, with binding propagation; no reliance on protobuf being discoverable by json_tree |
| Backup and retired snapshots | `crates/ramflux-storage/src/account_db/backup_message_footprint.rs:23`, `crates/ramflux-storage/src/account_db/backup_merge.rs:1`, `crates/ramflux-storage/src/account_db/backup_retirement.rs:1`, `crates/ramflux-storage/src/account_db/backup_object_erasure.rs:1`; backup exporter/merge, restore worker and archived actor readers | Archive namespace locators are copied with bytes; same-generation import rechecks live sticky fences before any body becomes readable |
| Media and object ownership | Storage object index/aliases and backup_object_erasure; object fetch, SDK MediaRef projection | Preserve multi-owner and standalone retention; remove key slots and raw message references under message erasure without deleting an object still owned elsewhere |
| Local consumers | Typed bus subscribers, C ABI/UniFFI/WASM adapters, CLI/TUI and desktop translate/messages/surfaces and moment model (section 8) | Emit tombstone/invalidation with journal cursor; consumers remove cached body and preview, then resync if their cursor is too old |

No FTS or separate persistent search index was found in the baseline SDK/storage
source audit. Current history queries read projections/content. S10 adds no new
index. Any future search tokenizer/index must register its owner edges and erase
hook before it can receive generated content; “not found” is not permission to
ignore an index discovered during implementation.

### 9.3 Registration by construction and ACK boundary

Use one storage writer API, conceptually `put_message_copy(transaction, owner,
copy_locator, bytes, provenance, expected_erasure_generation)`. It validates the
sticky fence, reserves applicable raw budget, writes bytes, binds logical/copy ids and
inserts footprint locators **within the same SQLite transaction**. No public
helper returns “persisted” before linkage is committed. Where the logical id is
not decodable, use the authenticated envelope-copy owner described in Decision 3
and bind both owners on reparse. Never turn an arbitrary embedded id into a
cross-account erasure target. For Unsupported owners, raw registry accounting includes duplicate copies,
verified nested group plaintext and serialized history containers: actual bytes,
not one charge per logical message. The 64-row limit counts Unsupported owners;
the 32 MiB limit counts all of their retained raw copies. Known content instead
stores exact Inner in runtime_message_content under the normal local-history
policy, with its report opening and provenance in registered private evidence.
It is not charged as an Unsupported row and never duplicated into an unbounded
second raw cache. These evidence bytes share the message's erase lifetime and
are not sent in ordinary bus updates.

| Copy / planned footprint kind and locator | Transaction and reader | Erase / late-write guard |
|---|---|---|
| New Unsupported message_raw_inner row: `raw_inner(account, copy_id, raw_digest)` | Receive transaction writes exact Inner, provenance, placeholder, projection/cursor and linkage; reparser reads by bounded handle | Delete row and nested group bytes, release quota, keep only content-free fence/digest needed for replay |
| Nested group bytes: `raw_group(account, copy_id, digest)` | Same receive transaction after native group verification; reparser reads already verified bytes | Same owner and byte quota as outer raw; never keep a group key solely to reparse |
| runtime_message_content: `content(message_id)` | Receive/reparse projection transaction; history reader | Explicit register for exact binary body and private report evidence; indexed erase deletes both; existing content trigger remains defense in depth |
| runtime_journal.body_json or generated binary successor: `event(seq)` | Event publish is in the same commit as body/linkage; subscriber replay | Scrub/remove content event and emit tombstone; retain only non-content cursor/replay data |
| runtime_actor_state.state_json: `actor(state_kind)` / copy binding | Session/group/dependency/own-copy writer transaction; actor restore | Register every contained raw/copy reference; invalidate pending/prepared content under the same sticky fence |
| runtime_operation.response_json: `operation(id)` | Idempotent request commit; retry reader | Remove body/result previews while preserving operation id and content-free outcome |
| Unrouted, retry and dead-letter payloads: `unrouted(envelope_id)`, `retry(key)`, `dead_letter(key)` | Each enqueue/redrive transaction binds authenticated source/copy; retry worker | Remove copied plaintext/origin and disarm retry; retain private replay fence; do not misclassify Unsupported as a retry failure |
| Prepared recipient envelopes and own-copy work: `prepared(copy_id)` | Seal/outbox transaction registers exact inner, origin and any encrypted content copy it persists; publisher | Recheck deletion generation under writer immediately before durable publication; erase cached envelope/body and stop its runnable work |
| Own-history serialized page: `history_container(transfer_id, page, digest)` linked to every included message | Page preparation/import transaction; history sender/receiver and backup worker | **Any-owner invalidation**: deleting any included message discards the entire cached/prepared page; regenerate surviving source messages under a new transfer id/hash chain. Never use shared-object last-owner retention for a container that still contains erased raw bytes |
| Backup bundle's active archive tables and retired actor/event snapshots: `archive(bundle_id, table, primary_key, column)` plus owner bindings | Consistent backup snapshot/export and retirement writer; merge/restore | Erase maintained local bundle copies and archive rows; import consumes the live deletion set first and rejects late erased copies |
| Temporary backup/restore file | Task-owned path plus bundle id, in a bounded job lifecycle; exporter/importer | Encrypt at rest, close/delete temporary artifact on cancellation/success; commit imported rows only through the registered API; do not claim unlink alone sanitizes an unencrypted filesystem |
| Object aliases/key slots: existing object/copy locator plus message owner edge | Media receive/share/restore transaction; object reader | Last-owner/standalone policy stays unchanged; deleted message's own slot/projection/raw metadata disappears |

ACK boundary for durable input: verify sender/native origin, decrypt and scan,
reserve quota, commit row + every copy binding + footprint + ratchet/replay/cursor,
then send the scoped transport ACK. Crash before COMMIT emits no ACK and retry
reconstructs the same logical id. Crash after COMMIT/before ACK permits idempotent
redelivery and ACK from durable state. Queueing an ACK is not evidence the remote
node durably confirmed it. Receipt kind is a separate user-level event. Ephemeral
transport has no inbox cursor/durable ACK; endpoint state admission follows its
own local transaction, and known Typing goes only to memory subscribers.

Reparse, own-copy import and restore compare expected erasure generation and
both logical/copy tombstones under the **same** writer transaction that installs
content. Deletion wins races; a decoded in-memory candidate is discarded if its
row vanished or generation changed. Reparse never republishes a previously
invalidated history page. Shared native group state still follows its existing
shared-state guard; per-message erasure cannot erase a live group's authority.
The new history-container rule is distinct from both shared group state and
attachment/object last-owner rules.

### 9.4 Artifact and threat boundary

An attacker can send bounded unknown authenticated content but cannot gain a
new authorization route. Wire admission precedes allocation, and raw quota
reservation precedes crypto/read-model commit. Expensive scans are O(input) with
a depth/field budget; reparse is one worker/account. A quota failure leaves prior
raw intact and gives actionable storage backpressure. Reparse does not execute
unverified task/call/control bytes just because a newer decoder recognizes them.
Own-history origin proofs remain required even on same-root transport.

Account DB plus `-wal` and `-shm` are one artifact set. Erasure transaction uses
existing secure-delete/checkpoint policy; before an export or absence assertion,
close stale readers, checkpoint/truncate WAL and verify all persistent columns
via the storage API. SHM is coordination metadata, never an application raw cache.
Encrypted transport/node WAL may still retain already delivered ciphertext until
normal ACK/TTL cleanup; erasure does not recall a peer's accepted ciphertext.
Retired/local maintained backup copies are scrubbed under their archive locators.
A restored backup imports current tombstones first and cannot roll back privacy
fences. An **already exported backup file**, remote recipient copy, OS snapshot,
clipboard or external consumer cache is outside device control; document that
residual instead of claiming global physical erasure. New exports must exclude
erased bodies and include the sticky fences needed by a later restore.

A generic absence test enumerates sqlite_schema and every table/column, not just
registered locators. It decodes known storage envelopes through storage APIs,
checks forbidden ids/raw digests/content across active and archive copies, runs
the WAL checkpoint, reopens and repeats after restore. It never scans raw database
bytes as a substitute for logical assertions. Deliberately persisting one copy
without registration must leave a detectable residual; the existing negative
probe is `crates/ramflux-storage/src/account_db/message_footprint/tests.rs:331`.
Crash and race schedules are mandatory, section 12.

## 10. Consumer field contracts

### 10.1 One registry for every constructor

This table is also the completeness checklist for generated consumer adapters.
All updates carry MessageUpdate.account_id, journal_sequence and EventIdentity;
UnsupportedView replaces Content without exposing secret/raw bytes by default.

| Kind | S6/S11 transport contract | S12 request/update and other consumer |
|---|---|---|
| Message | message, durable; optional measured embedded push | SendMessage.content.message; S9 Message.media, MediaRef and Thumbnail |
| Service | message, durable, generic wake | Content.service with verified native action; generated service renderer |
| Edit | message, durable | MessageRequest.edit / Content.edit; revision conflict and target authorization |
| Delete | message, durable, generic wake | MessageRequest.delete / tombstone; S9 owner edges and raw-copy erase |
| Reaction | message, durable | MessageRequest.reaction / Content.reaction; principal-scoped add/remove |
| Receipt | message, durable; notification policy suppresses noisy UI locally | Content.receipt; delivered/read never inferred from transport ACK |
| Typing | message, ephemeral, low, TTL 5 seconds, no push | MessageRequest.typing / transient Content.typing with expiry; never history |
| Control | message; durable except known live-presence operation | Content.control; exact generated payload plus fixed native proof codec |
| Surface | message, durable | Content.surface, SurfaceState/SurfaceAction; task/tool arguments remain application data |
| Task | message, durable | Content.task, TaskState and signed decision; existing approval/courier isolation |
| Call | invite=call_wake durable; ICE=message ephemeral; other signals=message | Content.call, CallSignal; native invite verification before showing a call |
| SelfSync | message, durable, same-root only | Content.selfSync; read/draft/pin/mute operation and revision |

### 10.2 S9 attachment fields

Message.media is ordered; each MediaRef has object_id, manifest_digest, mime_type,
size, key_slots, optional file_name, optional inline_thumbnail and large_manifest.
MediaKeySlot binds qualified recipient, crypto format and encrypted_key; no raw
object key is exposed in a generic UI update. Thumbnail carries mime_type, width,
height, encoded bytes and digest; maximum encoded bytes is 16 KiB, dimensions
1..512 each, decoded pixels at most 262,144, recognized image codecs only.
Validate before image decode; no URLs or executable image features. At layer 1
omit a thumbnail; layer 2 can carry it. Local previews never bypass content policy.

MediaManifest fields are the shared layer-4 contract: manifest_id and digest are
32 bytes, plaintext/ciphertext lengths are u64, encrypted_segment_bytes and
network_chunk_bytes are u32, segment_digests are ordered 32-byte ciphertext
segment hashes, key_slots are recipient-bound, relay_origin is an authenticated
relay origin, read_capability is an opaque secret, expires_at and retention_class
bind retention. Manifest bytes are deterministically encoded for manifest_digest;
its domain is `ramflux.message.media_manifest.v1`. Bound segment entries by the
Inner cap; a larger hash list uses a typed paged manifest under S9 with a reviewed
new layer before activation. S9 chooses numerical transfer segmentation policy;
these lengths must not be conflated with the existing 512 KiB transport chunk
cap or with end-to-end encrypted segment boundaries. Unknown future retention
classes are Unsupported, not permission for indefinite storage. No separate
object message class or private attachment envelope is added.

### 10.3 S11 push and S6 non-persisted delivery

S11 consumes the exact outer fields in section 6: delivery_class, delivery_mode,
priority, ttl_seconds, collapse_tag, envelope id, target device, ciphertext/hash,
sender/native authority and node receipt. collapse_tag is 32 opaque bytes on
every envelope, scoped per recipient/session; the provider collapse identifier
is its base64url form or a domain-separated fixed hash when provider syntax
requires it. A random-cover tag has the same length. No text/kind/group id enters
a push template. TTL is the remaining envelope life; never extend it at push.
call_wake is only the invite path; iOS PushKit/CallKit acceptance still requires
an authenticated incoming call. FCM high and APNs VoIP are not a delivery promise.
Whole provider payload <=3,072 bytes or use generic wake/cursor fetch. Default
preview remains off. Local device decryption produces opt-in preview.

S6 receives `delivery_mode = durable | ephemeral` on every client envelope. For
ephemeral, enforce low priority and TTL <=5 seconds, use a live-session queue of
at most 64 envelopes/256 KiB per target, and drop offline/expired/saturated input.
No inbox sequence, WAL, spool, persistence retry, dead letter or push record may
be created. Return a typed transient accepted/dropped outcome with no durability
claim; no scoped inbox ACK is allocated. Fields are sender signed/AEAD bound.
No plaintext typing bit, and no third class. Rate/admission limits still apply.
TTL validation occurs before any storage/enqueue decision. Receiver recognizes
Typing only after authentication/decryption; after expiry it emits a clear-state
transient update. Generic ephemeral mode leaks liveness urgency, not a claimed
application constructor. This node contract must be merged before S10a dispatch.

### 10.4 S12 API and native crypto

S12 depends on S3 plus complete S10. Consume MessageRequest, SendMessage,
MessageUpdate, Content and all typed nested descriptors directly. Preserve
request_id/account_id/operation_id and journal cursor across Rust, ProtoJSON,
UniFFI, C ABI and WASM adapters. Generated wrappers can add transport correlation,
not a second message schema or a stringly typed “payload” model. Business errors
remain typed codes (LayerUnavailable, PeerUpgradeRequired, StorageCapacity,
SchemaResetRequired, authorization and crypto errors), with exact adapter tests;
Unsupported is a successful typed row/update. Raw retrieval for local reparse is
privileged, bounded and off the ordinary update/bus path. Native proofs and
secret control bytes are not indiscriminately rendered into a desktop model.
DM-FS-V3-02 consumes no application KindIds; its bootstrap is the canonical input
to the encrypted capsule and header schedule described in sections 5 and 11.

## 11. Exact DM-FS-V3-02 adjustments

These are proposed edits for that interface owner's card after approval of this
commit. This document does not edit that card or implement its code. S0 changes
neither the signed prekey contract nor X3DH deadlines. “One application schema”
does not mean re-encoding native signed service documents as application events.

| Owned interface | Disposition | Exact card adjustment / lock-in |
|---|---|---|
| SignedNativePrekeyBase | Stays canonical RFS1, <=2 KiB | Keep every qualified branch, commitment, agreement key, generation, SPK id/serial/key, validity/counter and branch signature; add no Inner/layer capability bitset |
| SignedNativeOpk | Stays RFS1, <=512 bytes | Keep branch_binding, generation, serial/id/key and independent signature; never replace branch_binding with two variable strings |
| OwnerPrekeyUpdate | Stays RFS1, <=64 KiB | Keep additive <=64 OPKs, <=400 retirement refs and public-counter/idempotent-retirement separation |
| PrekeyPublicationSnapshot | Stays RFS1 public-only provider output | Keep current base/OPKs/counter/epoch/generation/retirement digest; registration consumes no credentials/private bytes |
| PublicPrekeyView | Stays RFS1 | Keep base and native authority only; layer declaration comes from the signed native device record, not an OPK/public-pool field |
| PrekeyLeaseIntent | Stays RFS1 | Keep requester/target/base/profile/times/nonce; operation id hashes all intent fields; 5-minute freshness and 10-minute selection upper bound unchanged |
| PrekeyLeaseResult | Stays RFS1 | Keep verified base, 0/1 signed OPK, operation binding/time/deadline or explicit bounded fallback; no owner ledger |
| OwnerPrekeyStatus | Stays RFS1 | Keep publication/floor/activation/retirement acknowledgement, unleased count and <=200 requested owner statuses; no requester/private data |
| NativePrekeyRequest | Stays signed RFS1 ordinary-session request | Keep every node-record/gateway/session/home-generation/source-authority/argument/nonce/time binding; request expiry <=5 minutes and nonce horizon 600 seconds |
| NativePrekeyLease frame | Stays ordinary-gateway service frame | JSON carries base64url RFS1 bytes; never an Inner Control or old unauthenticated PrekeyPublish |
| NativePrekeyPublish frame | Stays ordinary-gateway service frame | Same independent bounded canonical bytes; keep owner authorization and correlated response |
| NativePrekeyStatus frame | Stays ordinary-gateway service frame | Same owner-only query limits; not a generic CustodyRequest wrapper |
| Correlated bounded result frame | Stays service frame | Keep request correlation and payload ceilings; Busy carries S1 RetryHint as below |
| CustodyProofAction::PrekeyStatus / RegisterUpdate | Stay native custody carriers | Keep capability register, action-hash vectors and base64url canonical query/update; do not replace existing phased removal ownership |
| New OPK bootstrap header | Moves inside encrypted bootstrap capsule | Preserve exact RFS1 header and transcript; expose E and format only as section 5 requires; R0/SPK/OPK/lease/session/order/deadline stay encrypted |
| New SPK-only bootstrap header | Moves inside same capsule | Explicit OPK absence remains distinct from zero key; do not weaken SPK validity or deadline terms |
| Ratchet header / body handoff | Uses generated RatchetHeader and exact Inner framer at S10b | Add HE HK/NHK state adapter and encrypted capsule output; no SDK JSON DmCiphertext wrapper remains in outer payload |
| Typed refusals | Stay native typed refusal set | Keep exact distinctions below and exhaustive SDK maps; no UnsupportedSchema substitution |

Preserve all refusal names: native_publication_requires_custody,
native_account_required, prekey_profile_inactive, prekey_cross_home_unavailable,
prekey_clock_untrusted, prekey_capacity, prekey_repair_required,
prekey_refresh_required, prekey_lease_unavailable, bootstrap_key_unavailable,
update-required, Replay, Busy and PersistenceUnavailable. Keep distinct Capacity
vs Busy and no catch-all SDK mapping. Unknown native RFS1 fields are rejected
under their own security grammar; D3 fallback concerns application Inner, not a
lease request or signed prekey whose meaning cannot safely be guessed.

For Busy, reuse **S1-owned** `ramflux_protocol::custody::RetryHint { scope:
RetryScope, retry_after_ms: u32 }`, with RetryScope::{PreAuthSource, NodeCapacity}.
Do not introduce a second retry_hint type or a per-method/per-account scope with
no producer. The normal prekey node-capacity Busy uses NodeCapacity, includes
the hint in the authenticated node/session response, and clamps delay to
[1,000, 3,600,000] milliseconds. SDK honors the same hint and node-bound retry
state; it does not invent an independent fixed sleep. A producer that genuinely
runs under pre-auth source budget uses PreAuthSource. prekey_capacity retains its
own semantic code, not a fabricated admission Busy. Add shared-type/no-duplicate
and clamp/hint-binding tests to the card; S1 must land before the consuming retry
adapter, or that adapter waits explicitly for S1 rather than cloning the type.

Controller card edits to apply, in order:

1. Set Base to the approved S0 design commit SHA as a **design input**, keeping
   its own current-main implementation base. Do not merge the design branch.
2. Preserve r0's RFS1 field grammar, u16 ids/u32 lengths, strict ordering,
   canonical optional presence, hash/signature domains, ID byte limits, type
   ceilings and all canonical vectors. No prekey type is re-encoded as proto3.
3. Amend bootstrap visibility, header/transcript wording and adapters: canonical
   RFS1 bytes remain the transcript input, wrapped in the section 5 capsule by
   S10b; E is outer, R0 encrypted, and all capsule/envelope fields are AD bound.
   Existing 02 fixed header/transcript vectors remain valid inside the capsule.
4. Add explicit new-profile handoff outputs (SK and public transcript/bundle
   hashes, independently generated E/R0); only zeroizing temporary secret
   buffers cross the crypto adapter. S10b initializes HK/NHK using these values.
   Do not add a production client/bus caller to component-only card 02.
5. Add the S1 RetryHint dependency/reuse and exhaustive refusal surface tests.
6. Add capsule-swap, public-R0-negative, independent-E/R0, locked-provider and
   no-secret-snapshot integration tests to S10b's boundary. 02 owns pure vectors;
   03/04/05 retain their provider/node/activation and private-key-retirement work.

Keep OPK and SPK-only deadline helpers byte-for-byte in intent: exclusive now<D;
T=604800, skew=300 never extends D/SPK validity; OPK D is the minimum of
leased_at+T, SPK_expiry+T and envelope_expiry; SPK-only substitutes issued_at+T.
Reject all-zero DH, overlarge signed validity and future lease beyond skew.
Layer negotiation is not permission to fall back to a retired prekey profile.

## 12. Implementation cards and falsifiable acceptance

S0 has no runtime acceptance or code merge. Each future implementation card
names the approved design-branch commit SHA and copies this file exactly as its
first design-input commit where appropriate. Schema changes after approval
require interface-owner review; adapters cannot quietly redefine KindIds.

### 12.1 S10a — schema, complete message semantics and typed endpoint pipeline

**Dependencies and dispatch precondition:** approved S0 by design commit SHA;
S2 merged on main; **S6 non-persisted delivery merged on main before dispatch**.
The only alternative is a controller-approved revision that brings that node
capability into the same complete S10a scope, naming the node files and tests it
takes over. A design assertion is not evidence that the S6 node code exists.

Files/responsibilities:

- Protocol: new message/schema, message/generated, message/registry and
  message/validation modules; core_types delivery classes/outer fields;
  envelope_sender, custody/types and custody/network for endorsed declarations.
- Locked schema tool and descriptor/ProtoJSON generation/freshness checks;
  Cargo dependency wiring, license checks and real responsibility-based splits.
- SDK routed receive/project/control replaced by generated dispatch; client
  dm/group_session/own_device_copy/own_device_history, surface/task/call and
  object-slot adapters; bus dispatch/journal/receipts and runtime publication.
- Storage message_footprint, journal/content/operation state, raw-row APIs,
  backup_merge/retirement/message_footprint/object_erasure and restore/import.
- Gateway sender verification and all-frame report receipt; node franking/
  router_abuse verification; gateway clients/notify/federation class policy.
- CLI/TUI, C ABI, UniFFI and WASM typed adapters; remove every obsolete decoder
  in section 8. Desktop rendering itself belongs to S10c, using the same model.

Completion definition (every row required):

| Item | Required acceptance |
|---|---|
| Generation | Locked regen is deterministic and diff-free; Rust/ProtoJSON/binding round trips preserve presence, integers, Unicode and bytes; no private message schema or carrier remains |
| Negotiation | Signed native device max_layer with expiry/rollback/recovery; all-target group/DM/own minimum; membership recheck and safe kind/field downgrade |
| Semantics | All 12 kinds send/receive through generated dispatch; Edit/Delete/Reaction enforce authorization/revision/tombstone rules; same Message/Service identity/order; attachments, groups, receipts, calls, tasks and own history still work |
| Unknown input | Unknown kind, field, entity, nested signed payload or high layer commits Unsupported plus exact raw and provenance before ACK; bounded quota; no dead letter, NACK or action execution |
| Privacy | Every raw copy registers transactionally; crash/absence/race tests cover active, prepared, journal, nested group, archived and restored paths; history-container invalidation and object last-owner rules both pass |
| Typing acceptance | End-to-end typing send/receive uses S6 ephemeral mode, low priority and five-second expiry; offline/drop/expiry produce no inbox, WAL, spool, retry, dead-letter or push rows |
| Outer and reports | Exactly message/call_wake, uniform collapse_tag/report_commitment, updated producers and consumers; node receipt and opt-in accepted/tamper-refused report flow |
| Local surface | Generated requests/updates on bus, CLI/TUI and exported bindings; stale cursor resync and tombstone cache invalidation, typed errors, no JSON sniff fallback |

S10a cannot be READY or merge until every completion row passes. Its schema
layers 1–2 initially travel through the existing pair cipher; readable crypto
metadata remains until S10b. This explicitly staged crypto work does not remove
any S10a application semantics from its complete boundary. S10a does not claim
header privacy or Padme acceptance. The S10b reset installs mandatory layer 3.

Affected realnet slices: id02 (id02_custody), contact01
(contact01_contact_resolution), contact02, s41 (mvp_s41_dm_attachment), s43
(mvp_s43_receipt_network), s32 (mvp_s32_dm_receipt_delete), s48
(mvp_s48_own_device_sync), s73, s74, grpsync01 (grpsync01_membership_and_name),
s46 (mvp_s46_group_invite_accept), k2b (k2b_surface_round_trip), k3b
(k3b_task_needs_me_approval), k5a (k5a_agent_host), call01 (call01_voice).
Add end-to-end unknown/reparse and live/offline ephemeral cases to the relevant
slices. CI full suites and controller-run realnet prove their own boundaries;
focused unit tests are not substituted for those runs.

### 12.2 S10b — header encryption, bootstrap capsule and Padme

**Dependencies:** S10a merged on main **and** DM-FS-V3-02 merged on main.
Provider/node activation cards retain their own prerequisite contracts for a
real native bootstrap. A crypto test fixture is not production activation.
Files: crypto header-encryption state/KDF/framer/vector modules, DM session
snapshot/ring and zeroization; SDK dm/session/bootstrap/native-provider and
routed receive adapters; protocol crypto-box limits/domains/header validation;
storage crypto-generation reset and safe state commit. No new application kinds.

Completion: layer-3 mandatory crypto profile; no readable DmCiphertext header;
both bootstrap modes/capsule paths; max eighteen pair-local header trials;
skipped/current/next/old-state recovery; Padme floor/cap/overhead; full frame and
push sizing; independent fixed vectors; no state mutation on rejected packets;
secret-buffer erasure and locked-provider behavior. S10b cannot ship a clear
header fallback, R0=E or an unbounded old-key ring.

Affected realnet slices: s11 (mvp_s11_double_ratchet), id02, s35
(mvp_s35_multi_device), s48, s47 (mvp_s47_restore_device_rejoin). Include delayed,
reordered, duplicate, state-eviction and native OPK/SPK-only flows. No metadata
forward-secrecy claim for bootstrap capsules after agreement-key compromise.

### 12.3 S10c — typed desktop rendering

**Dependencies:** S10a merged on main and S5 merged on main.
Files: desktop-sdk translate/messages and translate/surfaces; desktop-core moment
model; native bridge/update adapters; conversation views/renderers and caches.
Remove MomentKind duplicates, hard-coded prefixes and string-key JSON parsing.
Consume generated MessageUpdate/Content; render entity scalars correctly, local
opt-in thumbnails, Unsupported placeholder, edits/reactions/deletes and transient
states. Do not expose secret control/group-key fields to generic UI models.

Acceptance: screenshots plus event/DB evidence for every visible constructor,
unknown placeholder before/after local upgrade, erased placeholder stays erased,
Unicode/UTF-16 boundary, same Message/Service ordering, typing expiry/reconnect,
and cache invalidation. No itest realnet slice is owned by this desktop-only card.

### 12.4 Dependency enforcement and order

Approved S0 design commit unblocks DM-FS-V3-02's amended component interface.
S2 + S6 on main unblock complete S10a; S10a + DM-FS-V3-02 on main unblock S10b;
S10a + S5 on main unblock S10c. S9/S11 consume this field contract without
inventing parallel descriptors. S12 requires S3 plus complete S10. S0 itself is
never merged. No implementation changes another card's owned native interface
without its owner's review.

`dispatch_s10b_requires_s10a_and_dm_fs_v3_02` rejects a dispatch manifest that
omits either merged prerequisite. Mutation: drop the S10a edge and dispatch
S10b; the dependency assertion must fail. `dispatch_s10a_requires_s6_merged`
rejects S10a before S6's non-persisted delivery is merged, unless the explicit
approved same-card node-scope revision is attached. Mutation: treat approved S0
as proof of S6 completion; the dispatch assertion must fail. These are controller
card/checker acceptance tests, not fictitious Rust runtime tests.

### 12.5 Required tests and compiling mutations

Names below are implementation acceptance specifications, **not tests executed
by this design round**. Every mutation must compile and fail the named semantic
assertion; a compile error or unrelated timeout is not a killed mutation. Keep
fresh target directories per mutation and restore the original source afterward.

| Decision / owner | Implementation test | Mutation that must fail it |
|---|---|---|
| D1/Q1, S10a | schema_regeneration_is_fresh; protojson_integer_presence_unicode_conformance; no_private_inner_wire_types | Change generated field without regeneration; encode u64 as float; introduce an SDK schema discriminator/carrier |
| D4/Q2, S10a | kind_registry_is_exhaustive_and_reserved; all_kind_binding_round_trip | Reuse a reserved KindId or remove one constructor/consumer arm |
| D2/Q6, S10a | group_layer_is_minimum_of_every_target; own_and_dm_layer_minimum; layer_update_rejects_rollback_and_expiry | Ignore one low-layer member; accept expired or older declaration; restore an archive declaration as live |
| D2/Q6, S10a | membership_change_rebuilds_unsubmitted_representation; downgrade_does_not_execute_structural_control | Skip membership recheck; turn Delete into executable text; send Reaction state to a layer-1 member |
| D3/Q9, S10a | unknown_kind_is_acked_and_kept_with_raw_bytes | Dead-letter an unknown kind instead of committing exact raw and ACKing |
| D3, S10a | unknown_field_entity_layer_and_signed_payload_keep_exact_bytes | Decode/re-encode through prost before retention; ignore unknown nested field/entity or execute a partially decoded control |
| D3/Q12, S10a | unsupported_quota_is_atomic_and_preserves_existing_rows | Exempt copied/nested raw from quota; evict an older row to ACK new input; advance ratchet on failed quota reservation |
| D3/Q12, S10a/storage | raw_inner_crash_commit_precedes_ack | Emit ACK after row insertion but before linkage COMMIT; inject crash at every write/commit/ACK boundary and observe acknowledged missing raw or locator |
| D3/Q12, S10a/storage | raw_inner_generic_absence_across_active_archive_and_restore | Omit explicit registration for exactly one of actor, operation, prepared page, journal, nested raw or archive copies; generic table/column audit must detect residual after erase/checkpoint/reopen/restore |
| D3/Q12, S10a/storage | raw_inner_reparse_restore_own_import_races_delete | Remove the late-write deletion-generation check in exactly one path; schedule decode before erase and commit after erase, then prove content reappears |
| D3/Q10, S10a/storage | history_container_any_owner_invalidates_without_erasing_shared_object | Treat multi-message history page as last-owner shared object; deleted raw remains even while surviving attachment and group state correctly remain |
| D3/Q9, S10a | reparse_is_idempotent_and_erased_raw_stays_tombstoned | Reparse twice into duplicate journal events or refetch erased raw from server |
| D4/Q10, S10a | message_service_share_sequence_and_order; edit_reaction_delete_authorization | Add a separate Service sequence; allow recipient's EVERYONE delete of peer DM; accept stale edit revision; recreate reaction after tombstone |
| D5/Q8, S10b | padme_floor_vectors_and_twelve_percent_bound | Replace Padme with power-of-two buckets; 257 rounds to 512 and violates the measured bound |
| D5/Q8, S10b | padding_caps_zeros_and_full_frame_budget | Omit the 256-byte floor; accept nonzero tail or length overflow; check plaintext cap instead of final encoded frame |
| D6/Q3, S10a | all_classes_producers_consumers_and_push_mapping | Retain SelfDeviceControl or object class at one production constructor; send ordinary Control as VoIP wake |
| D6/Q3, S10a | every_envelope_has_uniform_tag_and_commitment | Omit collapse_tag/report_commitment only for Receipt, SelfSync or group Control; fixed-shape assertion detects it |
| Q4, S10a | report_receipt_accepts_only_bound_opening_and_trusted_node | Skip C recomputation, change A0/target/payload hash, trust reporter's key or accept arbitrary redacted excerpt; tampered evidence must be refused |
| Q4, S10a | group_report_requires_message_opening_and_native_author | Show plaintext from group ciphertext receipt without a per-message opening/native author proof |
| D7/Q7, S10b | header_opacity_covers_every_ratchet_field | Serialize counter/session id/R0/device hash outside AEAD; parsed outer view assertion finds that field |
| D7/Q7, S10b | header_trial_bound_is_pair_local_eighteen | Search another pair, retain a nineteenth old key or permit unknown established format to trigger bootstrap DH |
| D7/Q7, S10b | he_current_next_skipped_and_evicted_states | Never promote NHK; key skipped messages by counter alone; preserve secret HK after ring eviction |
| D7/Q7, S10b | he_bootstrap_both_modes_and_capsule_ad_binding | Reuse E as R0, swap capsule/header/outer fields, omit a transcript binding or expose bootstrap header in plaintext |
| D7/Q7, S10b | he_vectors_cross_implementation_and_no_failed_commit | Reuse header nonce; change one KDF label; advance receiver after body tag failure; expected vectors/state snapshots differ |
| D9/Q5, S10a with S6 | typing_live_offline_expiry_has_no_persistent_artifacts | Route ephemeral through inbox/WAL or create push/retry row; query all relevant node tables after live/offline/saturated/expired cases |
| D9/Q5, S10a | typing_is_generated_transient_content_not_plaintext_kind | Add plaintext typing field or third class; persist known Typing in history or retain it after five-second expiry |
| Q8/S11, S10b consumer | push_embedding_measures_complete_padded_provider_payload | Exclude base64/authority/receipt/wrapper bytes from 3,072-byte measurement; oversized provider payload must fall back to wake |
| Q12/S10a | unknown_cannot_bypass_native_group_or_own_origin_authority | Retain a forged group/own-history message as authorized Unsupported; origin verifier must reject before fallback |
| S10c | typed_renderer_unknown_unicode_delete_and_transient | Parse hand-written keys, index emoji by bytes, render unknown entity as URL or retain a deleted cached preview |

D8 acceptance records target count/fan-out leakage as a residual; a test must
not claim traffic-analysis resistance merely because headers became encrypted.
D10's deletion audit must find zero active obsolete wire codecs after reset,
while retained cryptographic domains/native documents from section 8 still have
owners. Each card's report maps these rows to actual commands, mutation diffs,
compilation success and failing assertions, plus CI and realnet results where
required. This specification alone supplies none of that runtime evidence.

## 13. Residual risks and owner review points

The proposed defaults are concrete so implementation does not need another
schema-design round: floor 256, raw quota 64 rows/32 MiB, maximum Inner 524,252,
mandatory crypto layer 3, live queue 64/256 KiB, TTL 5 seconds and bounded receive
ring/trials. Owner approval accepts those protocol/resource choices; changing
them before implementation requires updating this design and vectors together.
No unresolved choice is hidden behind a schema string or a guessed decoder.

Residuals: source/recipient/signature key and timing stay outer; call_wake and
ephemeral mode reveal urgency/category; stable collapse tags link conversation
traffic within a pair session; per-device fan-out reveals group size; padding
reveals buckets and has a small-message floor cost. Bootstrap format/E/size are
observable; later agreement-key compromise reveals recorded capsule metadata.
Compromised endpoints, externally exported archives and remote recipients defeat
claims of global content erasure. Classical X25519/X3DH is not post-quantum.

Unknown authenticated content consumes local space and can cause explicit
backpressure, not unlimited storage or guaranteed ACK of unlimited input. Old
receive-key eviction bounds recovery; unlock/attended recovery remains necessary
when private providers or signed declarations are unavailable. Group raw copies
and history-page containers amplify the registration audit; their mutation
coverage is a prerequisite, not a reason to omit them. A new schema does not
repair current silent ACK-window overflow by itself; S6 owns typed gaps.

Owner review should confirm these bounded resource choices and the explicit
bootstrap metadata exception, uniform-report transcript and history-container
rule. None is claimed cryptographically audited here. Implementation must not
weaken native authority, deadline, consent, origin, replay, retirement or erasure
checks to make a conformance vector pass. Any discovered incompatible native
interface blocks that implementation and returns to its owner for a named fix.

## Appendix A. Reproducible Padme reference script

This Python program was executed outside the repository. L in the table is the
complete unpadded cryptographic plaintext, not text length. The exhaustive sweep
covers every integer length through 1 MiB, including the diagnostic range above
the production 512 KiB body cap. Maximum above-floor overhead is
6.2467576062742225%, below 12%; the floor cost for tiny messages is listed
separately. No production dependency or generated artifact is added by this check.

```python
FLOOR=256
LENGTHS=[1,2,3,4,7,8,15,16,17,31,32,63,64,100,127,128,255,256,257,300,511,512,513,1000,1023,1024,1025,2048,4095,4096,4097,8192,16383,16384,16385,32768,65535,65536,65537,100000,262144,524288,1048575,1048576]
def padded(length):
 n=max(length,FLOOR)
 exponent=n.bit_length()-1
 significant=exponent.bit_length()
 quantum=1<<max(0,exponent-significant)
 return (n+quantum-1)&~(quantum-1)
rows=[dict(length=n,padded=padded(n),over_floor_percent=100*(padded(n)-max(n,FLOOR))/max(n,FLOOR),over_input_percent=100*(padded(n)-n)/n) for n in LENGTHS]
print('| L | Padded | Over max(L, 256) % | Over L % |')
print('|---:|---:|---:|---:|')
for row in rows:print(f"| {row['length']} | {row['padded']} | {row['over_floor_percent']:.6f} | {row['over_input_percent']:.6f} |")
print('Maximum observed above-floor overhead (sample): '+str(max(x['over_floor_percent'] for x in rows)))
print('Maximum above-floor overhead (all lengths 1..1 MiB): '+str(max(100*(padded(n)-max(n,FLOOR))/max(n,FLOOR) for n in range(1,1048577))))
```

## Appendix B. Independent Padme calculation

This JavaScript implementation shares only the input length list and output
format; it rounds by logarithms and ceiling instead of bit masking. It also
sweeps every integer through 1 MiB.

```javascript
const inputs=[1,2,3,4,7,8,15,16,17,31,32,63,64,100,127,128,255,256,257,300,511,512,513,1000,1023,1024,1025,2048,4095,4096,4097,8192,16383,16384,16385,32768,65535,65536,65537,100000,262144,524288,1048575,1048576];
function rounded(length) {
 const n=Math.max(256,length);
 const exponent=Math.floor(Math.log2(n));
 const bits=Math.floor(Math.log2(exponent))+1;
 const step=2**Math.max(0,exponent-bits);
 return Math.ceil(n/step)*step;
}
console.log('| L | Padded | Over max(L, 256) % | Over L % |');
console.log('|---:|---:|---:|---:|');
for (const n of inputs) console.log(`| ${n} | ${rounded(n)} | ${(100*(rounded(n)-Math.max(n,256))/Math.max(n,256)).toFixed(6)} | ${(100*(rounded(n)-n)/n).toFixed(6)} |`);
let worst=0; for(let n=1;n<=1048576;n++) worst=Math.max(worst,100*(rounded(n)-Math.max(n,256))/Math.max(n,256));
console.error('Independent ceiling/logarithm implementation; exhaustive maximum='+worst+'%; <=12%: '+(worst<=12));
```

## Appendix C. External primary references

The unified design study supplies the product direction; it is not a runtime
acceptance source. The application schema and limits above are Ramflux choices.
These primary references support the specific construction/tooling facts:

- [Signal Double Ratchet, header encryption](https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption): current/next header-key state machine and skipped-key behavior; this proposal supplies its own domains, bounds and bootstrap wrapper.
- [Protocol Buffers ProtoJSON](https://protobuf.dev/programming-guides/json/): field-name, integer, bytes and unknown-input mapping used by the generated local API.
- [prost](https://docs.rs/prost/latest/prost/), [protox](https://docs.rs/protox/latest/protox/), [prost-build compile_fds](https://docs.rs/prost-build/latest/prost_build/struct.Config.html#method.compile_fds) and [pbjson-build](https://docs.rs/pbjson-build/latest/pbjson_build/): descriptor-driven Rust/ProtoJSON generation; this design requires locked regeneration and retained original peer bytes.
- [Telegram messageService](https://core.telegram.org/constructor/messageService): explicit service-message constructor as a modeling reference; no Telegram protocol or trust model is imported.
