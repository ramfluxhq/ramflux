# Message schema v1

## 1. Status, scope and hard system facts

**Proposal for review. No production implementation, security audit or runtime
acceptance is implied.** This document defines the application schema, its
cryptographic framing and the implementation boundaries. It adds no runtime
feature. The design branch is a review artifact; S10a imports this exact file by
its approved commit SHA rather than merging the design branch.

Round r3 continues the design artifact at
`e505565eb2e5c573ec10210125056b307b2143aa`, without rebasing its branch. All product `path:line` citations below
are pinned to `6b8e53106618aaee091989099ddb8dd5b1c9ad82`; `desktop/` denotes the
separate desktop repository at `08a9e63873a231a9a332c2274eeba7b819341feb`.
The intervening identity-verification/backup change does not change the schema
literal set. Counts are 182 occurrences, 70 distinct literals across the product,
and 179 occurrences, 70 distinct literals in SDK source. The live Surface/Call/Task wire definitions were also compared with main
`42cb140574aeca3b0e4f5cfcf2f840ae59d40832` in r2: the mapped definitions
are unchanged; a newer task historical-projection change adds local metadata,
not wire fields. All tables still cite the fixed product baseline. A literal inventory is
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
account**, plus 4 KiB bounded metadata per row. Within it, each authenticated
source account anchor has a **16-row / 8 MiB** sub-budget across all its devices,
groups, conversations and own-copy deliveries. Charge outer and nested raw copies
to the verified original author; same-root transport cannot reset that charge.
An undecodable identity is charged to the authenticated transport source anchor;
reparse can transfer a charge only atomically without exceeding either budget.
Reserve account and source budgets in the same transaction before ratchet/read-model
commit. No per-device identity or conversation churn bypasses the source budget.

Exhaustion is local storage backpressure: preserve existing rows, withhold ACK,
surface `StorageCapacity` identifying the bounded source, and continue servicing
other sources. Per-source admission queues and fair polling prevent one full
source queue from stopping other inbound processing. Recovery actions are
upgrade, delete selected Unsupported messages, block the source, or provision
storage. It is never UnsupportedSchema, an unsupported-kind NACK or FIFO eviction.
Withheld ACK is **not** a durable delivery promise: the node retains ciphertext
only until the earlier of envelope expiry and seven days after acceptance
(`docs/server-data.md:13`), then removes it. Its present ACK-window overflow can
also drop a delivery without recipient notification (`docs/server-data.md:192`).
Persist the local capacity diagnostic so retry/expiry is visible; do not invent a
node expiry receipt. S6 owns typed gaps. This does not promise unlimited delivery
from authenticated peers; native authorization and blocking continue to apply.
These budgets are new choices, not measured existing inbox quotas.

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
message. An unrecognized Entity.kind number makes the entire message
Unsupported; EntityUnknown exists only as a local projection, never on the wire. No partial action is
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

The final outer envelope has named `delivery_mode = durable | ephemeral`;
there is no plaintext typing flag. Until S10a introduces that named field, S6
uses the sender-signed `Envelope.ext.delivery_mode` bridge. In this bridge,
absent or `durable` selects durable delivery, `ephemeral` selects transient
delivery, and any unknown value is invalid at every hop. Mode is verified as
part of the sender signature before routing; it is not mutable hop metadata.
S10a replaces this bridge with the required named sender-signed/AEAD-bound
outer field under the envelope/profile reset in section 9.1. It removes bridge
emission and parsing; the new profile rejects ext.delivery_mode, including
dual-field input, instead of resolving precedence or retaining a second mode
transport. Both stages use the same signed-clock and no-persistence contract. S6 must support generic ephemeral transport before S10a
is dispatched. The leak is explicit: a node can distinguish transient traffic
and its short TTL. It cannot distinguish Typing from another permitted transient
control by decrypting it. Hiding this mode while requiring the node not to store
it is impossible without another private-delivery protocol; that alternative
is rejected here.

Ephemeral TTL has the explicit bound `1 <= ttl_seconds <= 5` (default 5),
in integer seconds, and priority low. The lifetime uses
sender-signed Unix-second `created_at` and `ttl_seconds`: compute the checked
sum D = created_at + ttl_seconds and checked expires_at_ms = D * 1000. Reject
overflow, TTL outside 1..5, created_at > node_now + 2 seconds, or now_ms >=
expires_at_ms. Every gateway, router, federation hop, live writer and receiver
enforces that same exclusive deadline; no grace, first-receipt renewal or
restart extension. Within the 2-second future tolerance acceptance can be
immediate, so remaining life at first receipt can reach ttl + 2 seconds.
S6 validates source/signature,
recipient, current authorization, TTL and frame size, then sends only to an
already live recipient session. It uses a bounded 64-envelope / 256 KiB live
queue per session, drops on saturation/offline/expiry, never allocates inbox_seq,
never writes router inbox, router WAL, federation durable spool or notify queue,
and never emits offline push. A sender gets a bounded transient accepted/dropped
result, not a durable inbox ACK. Live federation uses the same transient mode
and cannot convert it into a durable retry. Replay markers, if necessary, contain
only authenticated digests and expire at D. Router dedup keys bind authenticated
source root/device, envelope id and payload hash; receiver dedup binds source/id
and rejects conflicting payload hashes. A surviving receiver drops router
restart duplicates. Router and receiver restarts, including repeated restarts,
can expose duplicates within the remaining signed lifetime: there is no bound
of at most one duplicate. All copies are rejected at or after D. A sender clock
lagging the node by its TTL can lose transient delivery; never retry durably.

Endpoints accept Typing only in this mode. The typing indicator lifetime is
**at most 5 s**, bounded by the signed interval `[created_at, D)`: it is visible
only when created_at*1000 <= now_ms < expires_at_ms, and clears at D even
after restart or replay. The 2-second future tolerance permits early transport
acceptance, not early display or a longer indicator lifetime; any early input
stays only in bounded transient memory until its signed start, or is dropped.
Late arrival shortens the indicator lifetime; duplicate/reconnect never renews
the signed interval. Never create history, own-history, backup or journal body
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
endorses changes in a newer custody publication. An explicit lower max_layer
requires a higher sequence and may never be below the mandatory floor F. Pin
both native head/counter and declaration sequence; reject stale, foreign-epoch
or equal-sequence conflicting statements without lowering those pins. Wall-clock
expiry never rolls back authority, sequence or a declaration's historical record.

A statement may have at most 24 hours of validity **for above-floor selection**.
An expired or missing layer declaration NEVER blocks a send: use F for that
target, even after more than 24 hours offline. F=2 during the S10a development
stage and F=3 after S10b; S10a admits layers 1–2 together, never a layer-1-only
client. Every admitted client in a stage supports its floor. Delete and Edit
execute their typed semantics at every admitted floor; expiry never refuses
Delete or turns Edit into a new text message.
This floor is part of the deployed profile, not a guessed value of max_layer=0.
A foreign/replayed declaration is discarded and grants no above-floor support;
it also cannot erase the pinned sequence/head. Ordinary native device admission,
revocation and cryptographic-key availability still apply independently of layers.

For current verified declarations select the minimum over source compiled/active
support and every target's fresh max_layer (the fresh cohort). A target without a
fresh declaration receives a separately encoded F representation. It is excluded
from the fresh-cohort minimum: neither a group nor an own-device fan-out is
lowered wholesale for that member. Source capability is bounded by compiled
support. A sender whose own statement is missing/expired keeps sending at
max(F, the target's last valid declared max_layer), bounded by its compiled support
and the fresh-cohort minimum; a missing/expired target statement contributes F,
not historical above-floor authority. Own expiry does not lower fresh targets
or prevent sending. Republish the local statement on the next connection.
Every representation retains one logical event id, author sequence, authorization
and membership snapshot. Apply the downgrade table before per-device encryption.
For a group, distinct plaintext representations use distinct group sender-key
counters/ciphertexts under the same logical id, and only matching target devices
receive each pair-sealed wrapper. Never reuse a nonce/counter across variants.
S10b pads every per-device copy of this logical event to the same largest
ciphertext bucket by section 5.5, including fresh/floor and own/group variants.

There is **no mandatory daily custody publication** to keep messaging working.
Publish on capability change or to renew optional above-floor selection while
online; an offline/lost holder simply loses the above-floor optimization. Unlock
or attended native recovery/new-device enrollment restores publication authority,
not permission to send a floor message. Repair a stale lower declaration by a
higher-sequence signed update and endorsed head. Local history never waits for it.
Effective receive maximum is always the highest layer the receiver build
supports, regardless of its own declaration's presence, value or expiry. A
compiled maximum below F fails admission. Declaration expiry governs only
senders' above-floor selection; queued supported Delete/Edit execute immediately
without republication or an Unsupported round trip. Backup/restore preserves
statements only
as historical evidence and refreshes native pins; it cannot reactivate stale
capability. The existing native authority freshness/withholding model is unchanged.

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
Every signed payload has a concrete descriptor and an explicit signer/signature
field; there is no generic SignedPayload bytes model or schema-name dispatch.

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
enum EntityKind {
  ENTITY_UNSPECIFIED = 0;
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
  EntityKind kind = 3;
  optional string value = 4;
  reserved 5;
  reserved "unknown";
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
  CONTROL_A2I = 11;
  CONTROL_OBJECT_REVOKE = 12;
  CONTROL_OWN_CONTACT_TOMBSTONE = 13;
  CONTROL_OWN_GROUP_CONSENT = 14;
  CONTROL_OWN_MESSAGE_COPY = 15;
  CONTROL_FRIEND = 16;
}
message Control {
  ControlOperation operation = 1;
  reserved 2 to 15;
  reserved "target", "correlation_id", "native_signed_document", "history", "epoch",
           "subjects", "contact", "group_key", "pair_recovery", "recovery", "own_contact";
  oneof payload {
    PairReset reset = 16;
    PairResetAck reset_ack = 17;
    ContactControl contact_control = 18;
    GroupStateControl group_state = 19;
    GroupKeyControl group_key_control = 20;
    OwnContactSync own_contact_sync = 21;
    HistoryPage own_history = 22;
    HomeMigrationControl home_migration = 23;
    RecoveryControl recovery_control = 24;
    LivePresence live_presence = 25;
    A2iControlEvent a2i = 26;
    ObjectRevokeAccess object_revoke = 27;
    OwnContactTombstone own_contact_tombstone = 28;
    OwnGroupConsent own_group_consent = 29;
    OwnMessageCopy own_message_copy = 30;
    FriendControl friend = 31;
  }
}
message PairReset { uint64 rejected_bootstrap_floor = 1; }
message PairResetAck { uint64 rejected_bootstrap_floor = 1; }
message ContactControl { NativeContactConsent consent = 1; }
message HomeMigrationControl { NativeHomeAuthorization proposal = 1; }
message RecoveryControl {
  oneof payload { GuardianInvite invite = 1; GuardianAccept accept = 2; }
}
message LivePresence { uint64 epoch = 1; repeated QualifiedDevice subjects = 2; }
message ObjectRevokeAccess {
  string object_id = 1;
  string recipient_principal_id = 2;
  string link_id = 3;
  string reason = 4;
  int64 effective_at = 5;
}
message FriendControl {
  uint32 action = 1;
  string link_id = 2;
  string requester = 3;
  string target = 4;
  optional string remove_scope = 5;
  bool blocked = 6;
  optional int64 capability_revoked_at = 7;
}
message OwnMessageCopy {
  HistoryItem item = 1;
  QualifiedDevice source = 2;
  QualifiedDevice target = 3;
  int64 created_at = 4;
  int64 expires_at = 5;
}
message HistoryItem {
  bytes exact_inner = 1;
  reserved 2;
  reserved "origin_evidence";
  HistoryOriginEvidence source_evidence = 16;
  optional Delete tombstone = 3;
}
message HistoryOriginEvidence {
  bytes canonical_sender_envelope = 1;
  NativeCustodyManifest source_authority = 2;
  optional NativeGroupSnapshot group_membership = 3;
}
message HistoryPage {
  bytes transfer_id = 1;
  uint64 page = 2;
  bytes previous_page_digest = 3;
  repeated HistoryItem items = 4;
  bytes page_digest = 5;
}
message JsonNull {}
message JsonArray { repeated JsonValue values = 1; }
message JsonMember { string key = 1; JsonValue value = 2; }
message JsonObject { repeated JsonMember members = 1; }
message JsonValue {
  oneof value {
    JsonNull null = 1;
    bool boolean = 2;
    string number = 3;
    string text = 4;
    JsonArray array = 5;
    JsonObject object = 6;
  }
}
message NativeCustodyManifest { bytes canonical = 1; }
message NativeSignedDeviceSet { bytes canonical = 1; }
message NativePrekeyBundle { bytes canonical = 1; }
message NativeBranchProof { bytes canonical = 1; }
message NativeGroupActor { bytes canonical = 1; }
message NativeGroupSnapshot { bytes canonical = 1; }
message NativeGroupChangeRequest { bytes canonical = 1; }
message NativeGroupChangeResult { bytes canonical = 1; }
message NativeGroupTransferAcceptance { bytes canonical = 1; }
message NativeContactConsent { bytes canonical = 1; }
message NativeGroupEvent { bytes canonical = 1; }
message NativeHomeAuthorization { bytes canonical = 1; }
message CallEndpoint {
  string principal_id = 1;
  string root_public_key = 2;
  string device_id = 3;
}
message CallActionInvite {
  string base_key = 1;
}
message CallActionRinging {

}
message CallActionAnswer {
  string base_key = 1;
}
message CallActionAck {
  VoicePeerAllocation allocation = 1;
}
message CallActionReady {
  VoiceLeaseConsent consent = 1;
}
message CallActionReject {

}
message CallActionBusy {

}
message CallActionHangup {

}
message CallActionTimeout {

}
message CallActionFailed {

}
message CallActionAnsweredElsewhere {

}
message CallActionRekey {
  uint64 generation = 1;
  string base_key = 2;
}
message CallActionRekeyAck {
  uint64 generation = 1;
  string base_key = 2;
}
message CallAction {
  oneof value {
    CallActionInvite invite = 1;
    CallActionRinging ringing = 2;
    CallActionAnswer answer = 3;
    CallActionAck ack = 4;
    CallActionReady ready = 5;
    CallActionReject reject = 6;
    CallActionBusy busy = 7;
    CallActionHangup hangup = 8;
    CallActionTimeout timeout = 9;
    CallActionFailed failed = 10;
    CallActionAnsweredElsewhere answered_elsewhere = 11;
    CallActionRekey rekey = 12;
    CallActionRekeyAck rekey_ack = 13;
  }
}
message CallControl {
  string schema = 1;
  string call_id = 2;
  string conversation_id = 3;
  CallEndpoint caller = 4;
  CallEndpoint callee = 5;
  CallEndpoint sender = 6;
  uint64 seq = 7;
  int64 created_at = 8;
  CallAction body = 9;
  string signature = 10;
}
message VoiceAllocationRequest {
  string call_id = 1;
  CallEndpoint caller = 2;
  CallEndpoint callee = 3;
}
message VoicePeerAllocation {
  string lease_id = 1;
  string endpoint = 2;
  uint64 expires_at = 3;
  uint64 hard_expires_at = 4;
}
message VoiceLeaseConsent {
  VoiceAllocationRequest scope = 1;
  string lease_id = 2;
  uint64 expires_at = 3;
  string signature = 4;
}
message SurfaceEvent {
  string schema = 1;
  string conversation_id = 2;
  uint64 version = 3;
  SurfaceCommand command = 4;
}
message SurfaceAction {
  string schema = 1;
  string conversation_id = 2;
  string surface_id = 3;
  uint64 version = 4;
  string surface_hash = 5;
  string action_id = 6;
  JsonValue values = 7;
  string args_hash = 8;
  optional SurfaceTaskBinding task_binding = 9;
}
message SurfaceTaskBinding {
  string task_id = 1;
  string step_id = 2;
}
message SurfaceCommandCreateSurface {
  CreateSurfaceCommand value = 1;
}
message SurfaceCommandUpdateComponents {
  UpdateComponentsCommand value = 1;
}
message SurfaceCommandUpdateDataModel {
  UpdateDataModelCommand value = 1;
}
message SurfaceCommandDeleteSurface {
  DeleteSurfaceCommand value = 1;
}
message SurfaceCommandPatchSurface {
  PatchSurfaceCommand value = 1;
}
message SurfaceCommandStreamAppend {
  StreamAppendCommand value = 1;
}
message SurfaceCommand {
  oneof value {
    SurfaceCommandCreateSurface create_surface = 1;
    SurfaceCommandUpdateComponents update_components = 2;
    SurfaceCommandUpdateDataModel update_data_model = 3;
    SurfaceCommandDeleteSurface delete_surface = 4;
    SurfaceCommandPatchSurface patch_surface = 5;
    SurfaceCommandStreamAppend stream_append = 6;
  }
}
message PatchSurfaceCommand {
  string surface_id = 1;
  string base_surface_hash = 2;
  repeated SurfacePatchOp ops = 3;
  string new_surface_hash = 4;
}
message SurfacePatchOpReplaceBlock {
  JsonValue component = 1;
}
message SurfacePatchOpInsertBlock {
  uint64 index = 1;
  JsonValue component = 2;
}
message SurfacePatchOpRemoveBlock {
  string component_id = 1;
}
message SurfacePatchOpSetActions {
  repeated JsonValue actions = 1;
}
message SurfacePatchOpSetFallbackText {
  string fallback_text = 1;
}
message SurfacePatchOp {
  oneof value {
    SurfacePatchOpReplaceBlock replace_block = 1;
    SurfacePatchOpInsertBlock insert_block = 2;
    SurfacePatchOpRemoveBlock remove_block = 3;
    SurfacePatchOpSetActions set_actions = 4;
    SurfacePatchOpSetFallbackText set_fallback_text = 5;
  }
}
message StreamAppendCommand {
  string surface_id = 1;
  string component_id = 2;
  string text_delta = 3;
  bool final_ = 4;
}
message CreateSurfaceCommand {
  string surface_id = 1;
  SurfaceType surface_type = 2;
  string catalog = 3;
  string catalog_version = 4;
  string fallback_text = 5;
  optional string fallback_markdown = 6;
  repeated JsonValue components = 7;
  JsonObject data_model = 8;
  repeated JsonValue allowed_actions = 9;
}
message UpdateComponentsCommand {
  string surface_id = 1;
  string base_surface_hash = 2;
  repeated JsonValue components = 3;
  repeated string remove_component_ids = 4;
  string new_surface_hash = 5;
}
message UpdateDataModelCommand {
  string surface_id = 1;
  string base_surface_hash = 2;
  JsonObject data_patch = 3;
  string new_surface_hash = 4;
}
message DeleteSurfaceCommand {
  string surface_id = 1;
  optional DeleteSurfaceReason reason = 2;
}
message SurfaceTypeMessageCard {

}
message SurfaceTypeApprovalCard {

}
message SurfaceTypeFormCard {

}
message SurfaceTypeStatusPanel {

}
message SurfaceTypeTaskCard {

}
message SurfaceTypeFilePreview {

}
message SurfaceTypeCallCard {

}
message SurfaceTypeAgentResult {

}
message SurfaceTypeNotificationCard {

}
message SurfaceType {
  oneof value {
    SurfaceTypeMessageCard message_card = 1;
    SurfaceTypeApprovalCard approval_card = 2;
    SurfaceTypeFormCard form_card = 3;
    SurfaceTypeStatusPanel status_panel = 4;
    SurfaceTypeTaskCard task_card = 5;
    SurfaceTypeFilePreview file_preview = 6;
    SurfaceTypeCallCard call_card = 7;
    SurfaceTypeAgentResult agent_result = 8;
    SurfaceTypeNotificationCard notification_card = 9;
  }
}
message DeleteSurfaceReasonCompleted {

}
message DeleteSurfaceReasonCancelled {

}
message DeleteSurfaceReasonReplaced {

}
message DeleteSurfaceReasonExpired {

}
message DeleteSurfaceReasonError {

}
message DeleteSurfaceReason {
  oneof value {
    DeleteSurfaceReasonCompleted completed = 1;
    DeleteSurfaceReasonCancelled cancelled = 2;
    DeleteSurfaceReasonReplaced replaced = 3;
    DeleteSurfaceReasonExpired expired = 4;
    DeleteSurfaceReasonError error = 5;
  }
}
message A2iControlEvent {
  string schema = 1;
  uint32 version = 2;
  string domain = 3;
  Ext ext = 4;
  SignedFields signed = 5;
  A2iControlEventType event_type = 6;
  ControlDomain control_domain = 7;
  string action = 8;
  JsonValue subject = 9;
  string correlation_id = 10;
  string source_device_id = 11;
  string target_device_id = 12;
  optional string grant_id = 13;
  optional int64 expires_at = 14;
}
message ControlDomainMessage {

}
message ControlDomainConversation {

}
message ControlDomainA2ui {

}
message ControlDomainMcpTool {

}
message ControlDomain {
  oneof value {
    ControlDomainMessage message = 1;
    ControlDomainConversation conversation = 2;
    ControlDomainA2ui a2ui = 3;
    ControlDomainMcpTool mcp_tool = 4;
  }
}
message A2iControlEventTypeControl {

}
message A2iControlEventType {
  oneof value {
    A2iControlEventTypeControl control = 1;
  }
}
message TaskStatusProposed {

}
message TaskStatusRunning {

}
message TaskStatusNeedsMe {

}
message TaskStatusDone {

}
message TaskStatusFailed {

}
message TaskStatusCancelled {

}
message TaskStatus {
  oneof value {
    TaskStatusProposed proposed = 1;
    TaskStatusRunning running = 2;
    TaskStatusNeedsMe needs_me = 3;
    TaskStatusDone done = 4;
    TaskStatusFailed failed = 5;
    TaskStatusCancelled cancelled = 6;
  }
}
message NeedsMeApproval {
  string grant_id = 1;
}
message NeedsMeChoice {
  string surface_id = 1;
}
message NeedsMeInput {
  string surface_id = 1;
}
message NeedsMe {
  oneof value {
    NeedsMeApproval approval = 1;
    NeedsMeChoice choice = 2;
    NeedsMeInput input = 3;
  }
}
message TaskStep {
  string id = 1;
  string title = 2;
  TaskStatus state = 3;
  optional NeedsMe needs_me = 4;
}
message TaskStart {
  string task_id = 1;
  string conversation_id = 2;
  string requester = 3;
  string assignee = 4;
  string text = 5;
  optional string constraints = 6;
}
message TaskProposal {
  string task_id = 1;
  string conversation_id = 2;
  string proposer = 3;
  string assignee = 4;
  string title = 5;
  repeated TaskStep steps = 6;
}
message TaskAccept {
  string task_id = 1;
  uint64 version = 2;
}
message TaskDecline {
  string task_id = 1;
  uint64 version = 2;
}
message TaskUpdate {
  string task_id = 1;
  uint64 version = 2;
  TaskStatus state = 3;
  repeated TaskStep steps = 4;
  optional string result_ref = 5;
  optional string result_summary = 6;
}
message TaskCancel {
  string task_id = 1;
  uint64 base_revision = 2;
}
message TaskDecisionResume {

}
message TaskDecisionDeny {

}
message TaskDecision {
  oneof value {
    TaskDecisionResume resume = 1;
    TaskDecisionDeny deny = 2;
  }
}
message TaskResolve {
  string task_id = 1;
  uint64 base_revision = 2;
  string step_id = 3;
  NeedsMe target = 4;
  string decision_id = 5;
  TaskDecision decision = 6;
}
message TaskEventBodyStart {
  TaskStart value = 1;
}
message TaskEventBodyProposal {
  TaskProposal value = 1;
}
message TaskEventBodyAccept {
  TaskAccept value = 1;
}
message TaskEventBodyDecline {
  TaskDecline value = 1;
}
message TaskEventBodyUpdate {
  TaskUpdate value = 1;
}
message TaskEventBodyCancel {
  TaskCancel value = 1;
}
message TaskEventBodyResolve {
  TaskResolve value = 1;
}
message TaskEventBody {
  oneof value {
    TaskEventBodyStart start = 1;
    TaskEventBodyProposal proposal = 2;
    TaskEventBodyAccept accept = 3;
    TaskEventBodyDecline decline = 4;
    TaskEventBodyUpdate update = 5;
    TaskEventBodyCancel cancel = 6;
    TaskEventBodyResolve resolve = 7;
  }
}
message TaskEvent {
  string schema = 1;
  uint32 version = 2;
  string domain = 3;
  Ext ext = 4;
  SignedFields signed = 5;
  string conversation_id = 6;
  TaskEventBody event = 7;
}
message SignedFields {
  string signing_key_id = 1;
  SignatureAlg signature_alg = 2;
  string signature = 3;
}
message Ext {
  JsonObject ext = 1;
}
message SurfaceCarrier {
  string schema = 1;
  string content_type = 2;
  optional int64 posted_at = 3;
  optional int64 updated_at = 4;
  string conversation_id = 5;
  string surface_id = 6;
  string message_id = 7;
  string sender_principal_id = 8;
  string sender_device_id = 9;
  string author_principal_id = 10;
  string signature = 11;
  optional SurfaceSnapshotProof snapshot = 12;
  oneof payload {
    SurfaceEvent event = 16;
    SurfaceAction action = 17;
    SurfaceCarrier action_receipt = 18;
  }
  reserved 14, 15;
}
message SurfaceSnapshotProof {
  SurfaceEvent event = 1;
  SurfaceCheckpoint checkpoint = 2;
  optional string surface_hash = 3;
  SurfaceResyncMetadata metadata = 4;
  string author_device_id = 5;
}
message SurfaceDelivery {
  SurfaceControlKind kind = 1;
  SurfaceCarrier carrier = 2;
  optional uint64 group_epoch = 3;
  optional OwnContext context = 4;
  repeated NativeDeviceManifest manifests = 5;
}
message SurfaceControlKindPeer {

}
message SurfaceControlKindOwn {

}
message SurfaceControlKind {
  oneof value {
    SurfaceControlKindPeer peer = 1;
    SurfaceControlKindOwn own = 2;
  }
}
message OwnContext {
  string conversation_id = 1;
  repeated string participants = 2;
  optional SdkOwnDeviceGroupSnapshot group = 3;
  optional FriendLinkRecord friend = 4;
}
message TaskCarrier {
  string content_type = 1;
  string conversation_id = 2;
  string message_id = 3;
  string principal_id = 4;
  string device_id = 5;
  TaskEvent event = 6;
  string signature = 7;
  TaskCertificate decision_proof = 8;
}
message TaskApprovalRequest {
  TaskApprovalBinding binding = 1;
  LocalMcpApprovalRecord approval = 2;
  LocalMcpGrantSigningBody grant_body = 3;
}
message TaskApprovalPayloadRequest {
  TaskApprovalRequest request = 1;
}
message TaskApprovalPayloadDecision {
  TaskApprovalRequest request = 1;
  bool approved = 2;
  optional string grant_signature = 3;
}
message TaskApprovalPayload {
  oneof value {
    TaskApprovalPayloadRequest request = 1;
    TaskApprovalPayloadDecision decision = 2;
  }
}
message TaskApprovalPacket {
  TaskApprovalPayload payload = 1;
  string principal = 2;
  string device = 3;
  string signature = 4;
  reserved 5;
}
message TaskAck {
  TaskCarrier carrier = 1;
  TaskCertificate certificate = 2;
  repeated NativeDeviceManifest manifests = 3;
  string signer_principal = 4;
  string signer_device = 5;
  string signature = 6;
}
message TaskControlIntent {
  TaskCarrier carrier = 1;
}
message TaskControlAck {
  TaskAck value = 1;
}
message TaskControl {
  oneof value {
    TaskControlIntent intent = 1;
    TaskControlAck ack = 2;
  }
}
message TaskCertificate {
  string conversation_id = 1;
  TaskResolve resolution = 2;
  string assignee = 3;
  string issuer_device = 4;
  int64 issued_at = 5;
  TaskCertificatePhase phase = 6;
  optional uint64 committed_version = 7;
  optional string carrier_hash = 8;
  string decision_key = 9;
  string evidence_hash = 10;
  string signature = 11;
}
message TaskCertificatePhaseReserved {

}
message TaskCertificatePhaseCommitted {

}
message TaskCertificatePhase {
  oneof value {
    TaskCertificatePhaseReserved reserved = 1;
    TaskCertificatePhaseCommitted committed = 2;
  }
}
message TaskAcceptedEvent {
  TaskCarrier carrier = 1;
  string public_key = 2;
  bool actor_kind_verified = 3;
  int64 received_at = 4;
  optional TaskCertificate decision_certificate = 5;
  optional TaskMembership membership = 6;
}
message TaskHistory {
  repeated TaskAcceptedEvent events = 1;
  int64 created_at = 2;
  int64 updated_at = 3;
  reserved 4;
  reserved "checkpoint";
}
message TaskMembership {
  string conversation = 1;
  optional string group = 2;
  optional uint64 epoch = 3;
  int64 at = 4;
  repeated string members = 5;
}
message TaskOwnPacket {
  OwnContext context = 1;
  TaskHistory history = 2;
  repeated NativeDeviceManifest manifests = 3;
  repeated SdkOwnDeviceGroupMemberPin pins = 4;
  uint64 base = 5;
  string prefix_hash = 6;
}
message TaskApprovalBinding {
  string conversation_id = 1;
  string task_id = 2;
  string step_id = 3;
  uint64 opening_revision = 4;
  string requester = 5;
  string assignee = 6;
  string executor_device_id = 7;
}
message LocalMcpGrantSigningBody {
  optional TaskApprovalBinding task_binding = 1;
  string approval_id = 2;
  string grant_id = 3;
  string server_id = 4;
  string tool_name = 5;
  optional string tool_scope = 6;
  McpCapability capability = 7;
  string registry_hash = 8;
  string tool_manifest_set_hash = 9;
  bool full_delegation = 10;
  bool single_use = 11;
  optional string arguments_hash = 12;
  int64 expires_at = 13;
}
message LocalBusFederationRoute {
  string federation_url = 1;
  string source_node_id = 2;
  string target_node_id = 3;
  string required_capability = 4;
  optional string admin_token = 5;
  optional string recipient_prekey_url = 6;
}
message LocalMcpApprovalRecord {
  string approval_id = 1;
  string server_id = 2;
  string tool_name = 3;
  McpCapability capability = 4;
  RiskLevel risk_level = 5;
  optional string tool_scope = 6;
  string confirmation_mode = 7;
  int64 expires_at = 8;
  string status = 9;
  JsonValue details = 10;
}
message GroupStateControl {
  string schema = 1;
  GroupControlBody body = 2;
}
message GroupControlBodyRequest {
  NativeGroupChangeRequest request = 1;
  optional LocalBusFederationRoute federation = 2;
}
message GroupControlBodyResult {
  NativeGroupChangeResult result = 1;
}
message GroupControlBodyDeviceSet {
  string group_id = 1;
  NativeGroupActor actor = 2;
  uint64 device_set_epoch = 3;
}
message GroupControlBodyTransfer {
  TransferControl control = 1;
}
message GroupControlBody {
  oneof value {
    GroupControlBodyRequest request = 1;
    GroupControlBodyResult result = 2;
    GroupControlBodyDeviceSet device_set = 3;
    GroupControlBodyTransfer transfer = 4;
  }
}
message TransferDevice {
  string root = 1;
  string device = 2;
}
message TransferProbe {
  string id = 1;
  NativeGroupActor actor = 2;
  NativeGroupActor creator = 3;
  NativeGroupSnapshot base = 4;
  repeated TransferDevice required = 5;
  int64 issued_at = 6;
  int64 expires_at = 7;
}
message TransferHead {
  string proposal = 1;
  NativeGroupActor actor = 2;
  string requested_hash = 3;
  NativeGroupSnapshot head = 4;
  optional NativeGroupTransferAcceptance acceptance = 5;
  bool requires_sync = 6;
  TransferDevice target = 7;
  repeated TransferDevice additional_targets = 8;
  bool cancelled = 9;
  bool cancel_ack = 10;
  int64 issued_at = 11;
  int64 expires_at = 12;
}
message TransferBodyProbe {
  TransferProbe probe = 1;
}
message TransferBodyHead {
  TransferHead reply = 1;
}
message TransferBody {
  oneof value {
    TransferBodyProbe probe = 1;
    TransferBodyHead head = 2;
  }
}
message TransferControl {
  TransferBody body = 1;
  string signature = 2;
}
message OwnContactSync {
  NativeDeviceManifest manifest = 1;
  FriendLinkRecord link = 2;
}
message OwnContactTombstone {
  FriendLinkRecord link = 1;
  optional int64 decided_at = 2;
}
message OwnGroupConsent {
  string schema = 1;
  NativeGroupActor actor = 2;
  NativeGroupSnapshot snapshot = 3;
  bool accepted = 4;
  int64 issued_at = 5;
  int64 expires_at = 6;
  string signature = 7;
}
message SurfaceCheckpoint {
  string schema = 1;
  optional CreateSurfaceCommand content = 2;
  optional string conversation_id = 3;
  uint64 version = 4;
  bool closed = 5;
  repeated SurfaceFinalEntry final_text = 6;
}
message SurfaceFinalEntry {
  string id = 1;
  bool nested = 2;
  string text_hash = 3;
}
message SurfaceResyncMetadata {
  string schema = 1;
  string conversation_id = 2;
  uint64 version = 3;
  bool closed = 4;
  string finality_base64 = 5;
}
message SurfaceResyncRequest {
  string kind = 1;
  string conversation_id = 2;
  string surface_ref = 3;
  string author = 4;
  string surface_id = 5;
  optional string group = 6;
  optional uint64 epoch = 7;
}
message GuardianRecoveryShare {
  uint32 share_id = 1;
  uint32 threshold = 2;
  uint32 total = 3;
  RecoveryQuorumMemberKind member_kind = 4;
  string value_base64 = 5;
}
message GuardianInvite {
  string schema = 1;
  uint32 version = 2;
  string invite_id = 3;
  string inviter_principal_id = 4;
  string inviter_device_id = 5;
  uint64 inviter_device_epoch = 6;
  string inviter_device_public_key_base64url = 7;
  string guardian_principal_id = 8;
  string recovery_quorum_id = 9;
  GuardianRecoveryShare share = 10;
  int64 issued_at = 11;
  int64 expires_at = 12;
  SignedFields signed = 13;
}
message GuardianAccept {
  string schema = 1;
  uint32 version = 2;
  string accept_id = 3;
  string invite_id = 4;
  string owner_principal_id = 5;
  string guardian_principal_id = 6;
  string guardian_device_id = 7;
  uint64 guardian_device_epoch = 8;
  string guardian_device_public_key_base64url = 9;
  string recovery_quorum_id = 10;
  int64 accepted_at = 11;
  SignedFields signed = 12;
}
message SdkOwnDeviceGroupSnapshot {
  optional NativeGroupSnapshot shared_state = 1;
  string group_id = 2;
  uint64 group_epoch = 3;
  uint32 max_members = 4;
  string new_member_history = 5;
  string local_role = 6;
  uint64 local_joined_epoch = 7;
  repeated SdkOwnDeviceGroupMemberSnapshot members = 8;
  repeated LocalBusGroupMemberRoute routes = 9;
}
message SdkOwnDeviceGroupMemberPin {
  string group_id = 1;
  string device_id = 2;
  string signing_public_key = 3;
  optional string principal_id = 4;
  optional string principal_commitment = 5;
}
message SdkOwnDeviceGroupMemberSnapshot {
  string member_id = 1;
  string role = 2;
  uint64 joined_epoch = 3;
}
message LocalBusGroupMemberRoute {
  string member_id = 1;
  optional string member_principal_commitment = 2;
  optional string device_signing_public_key = 3;
  optional string target_delivery_id = 4;
  optional LocalBusFederationRoute federation = 5;
}
message GroupKeyDistribution {
  string schema = 1;
  uint32 version = 2;
  string group_id = 3;
  string sender_id = 4;
  uint64 group_key_epoch = 5;
  optional string group_state_hash = 6;
  bytes sender_key_seed = 7;
  optional string sender_key_signature = 8;
  optional string sender_device_signing_public_key = 9;
}
message GroupKeyControl {
  string schema = 1;
  uint32 version = 2;
  NativeGroupEvent membership_event = 3;
  optional string actor_manifest_url = 4;
  GroupKeyDistribution distribution = 5;
}
message SurfaceExportMetadata {
  bool truncated = 1;
  optional int64 next_before = 2;
  map<string, uint32> skipped = 3;
}
message SurfaceHistoryExport {
  repeated SurfaceDelivery controls = 1;
  repeated OwnedSurfaceCheckpoint checkpoints = 2;
  SurfaceExportMetadata metadata = 3;
}
message OwnedSurfaceCheckpoint {
  StoredSurface record = 1;
  SurfaceEvent snapshot_event = 2;
  uint64 version = 3;
  string surface_hash = 4;
  JsonValue conversation = 5;
  optional uint64 group_epoch = 6;
}
message StoredSurface {
  string surface_id = 1;
  string conversation_id = 2;
  string author_principal_id = 3;
  string author_device_id = 4;
  SurfaceCheckpoint checkpoint = 5;
  optional int64 created_at = 6;
  optional int64 updated_at = 7;
}
message TaskExportMetadata {
  bool truncated = 1;
  uint32 skipped_items = 2;
  optional string next_cursor = 3;
}
message NativeDeviceManifest {
  optional NativeCustodyManifest custody = 1;
  optional NativeSignedDeviceSet signed_device_set = 2;
  string principal_id = 3;
  string principal_commitment = 4;
  string root_public_key = 5;
  repeated ManifestDevice devices = 6;
}
message ManifestDevice {
  string principal_id = 1;
  string principal_commitment = 2;
  string device_id = 3;
  uint64 device_epoch = 4;
  string branch_public_key = 5;
  string target_delivery_id = 6;
  optional NativeBranchProof branch_proof = 7;
  NativePrekeyBundle prekey_bundle = 8;
  string branch_authorized_event_id = 9;
}
message SignatureAlgEd25519 {

}
message SignatureAlg {
  oneof value {
    SignatureAlgEd25519 ed25519 = 1;
  }
}
message FriendLinkRecord {
  string link_id = 1;
  string requester_id = 2;
  string target_id = 3;
  string state = 4;
  optional string remove_scope = 5;
  bool blocked = 6;
  optional int64 capability_revoked_at = 7;
}
message McpCapabilityReadConversation {

}
message McpCapabilityDraftMessage {

}
message McpCapabilitySendMessage {

}
message McpCapabilityReadLocalFiles {

}
message McpCapabilityWriteLocalFiles {

}
message McpCapabilityRunShell {

}
message McpCapabilityManageContacts {

}
message McpCapabilityManageGroup {

}
message McpCapabilityManageMedia {

}
message McpCapabilityManageNode {

}
message McpCapabilityExternalToolInvoke {

}
message McpCapability {
  oneof value {
    McpCapabilityReadConversation read_conversation = 1;
    McpCapabilityDraftMessage draft_message = 2;
    McpCapabilitySendMessage send_message = 3;
    McpCapabilityReadLocalFiles read_local_files = 4;
    McpCapabilityWriteLocalFiles write_local_files = 5;
    McpCapabilityRunShell run_shell = 6;
    McpCapabilityManageContacts manage_contacts = 7;
    McpCapabilityManageGroup manage_group = 8;
    McpCapabilityManageMedia manage_media = 9;
    McpCapabilityManageNode manage_node = 10;
    McpCapabilityExternalToolInvoke external_tool_invoke = 11;
  }
}
message RiskLevelLow {

}
message RiskLevelMedium {

}
message RiskLevelHigh {

}
message RiskLevelCritical {

}
message RiskLevel {
  oneof value {
    RiskLevelLow low = 1;
    RiskLevelMedium medium = 2;
    RiskLevelHigh high = 3;
    RiskLevelCritical critical = 4;
  }
}
message RecoveryQuorumMemberKindRootShare {

}
message RecoveryQuorumMemberKindDeviceShare {

}
message RecoveryQuorumMemberKindGuardianShare {

}
message RecoveryQuorumMemberKindHardwareTokenShare {

}
message RecoveryQuorumMemberKind {
  oneof value {
    RecoveryQuorumMemberKindRootShare root_share = 1;
    RecoveryQuorumMemberKindDeviceShare device_share = 2;
    RecoveryQuorumMemberKindGuardianShare guardian_share = 3;
    RecoveryQuorumMemberKindHardwareTokenShare hardware_token_share = 4;
  }
}
message Surface {
  reserved 1, 2;
  reserved "operation", "state";
  oneof payload {
    SurfaceDelivery delivery = 16;
    SurfaceResyncRequest resync_request = 17;
    SurfaceHistoryExport own_history = 18;
  }
}
message Task {
  reserved 1 to 4;
  reserved "operation", "event", "decision_certificate", "native_membership_witnesses";
  oneof payload {
    TaskCarrier carrier = 16;
    TaskApprovalPacket approval = 17;
    TaskControl control = 18;
    TaskHistoryExport own_history = 19;
  }
}
message TaskHistoryExport {
  repeated TaskOwnPacket packets = 1;
  TaskExportMetadata metadata = 2;
}
message Call {
  reserved 1, 2;
  reserved "operation", "signal";
  CallControl control = 16;
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

Kinds 9/10/11 now mirror the live Surface/Task/Call contracts field for field,
using the tables in section 3.1. Their removed r1 placeholder fields are reserved;
no r1 sketch has shipped. The nested oneof tags are the operation numbers; there
is no second integer op that can disagree with the payload. Every closed oneof
must have exactly one arm (unit variants have an explicit empty message).
Unknown arms are caught by the pre-decode scanner and retain the entire Inner.
Duplicate oneof/scalar fields are invalid input, never last-wins execution.

Control.operation must match exactly one typed oneof arm in section 3.2. Missing,
multiple or unrelated arms cannot execute. Unknown operation or arm follows
Unsupported, never a bytes payload interpreted by guessing a schema string.
Native* fields are the only external-codec exceptions: each has a single fixed
native type/validator, named in section 3.2; no Native wrapper accepts an
application event or changes its codec based on content. Cryptographic blobs,
proofs and exact Inner history bytes have their stated owners, not open payloads.
FriendControl.action is 1=requested, 2=accepted, 3=removed, 4=blocked,
5=unblocked. LivePresence is a planned typed ephemeral operation, not a newly
claimed existing wire producer. RecoveryControl is exactly invite or accept.
All GroupSealedContent crypto fields retain the existing reviewed primitive's
validation and exact sizes; epoch/author fields bind the same native group
state. They do not create a second application schema. The pair/report AEAD
covers the generated wrapper; nested plaintext uses the same Message descriptor.
The generation tool emits this operation/domain/descriptor table and layer map.
MCP/tool canonical_arguments are application data, not a hidden transport codec.

### 3.1 Live Surface, Task and Call field mapping

All sources below are at the fixed product SHA, also compared against main
`42cb140574aeca3b0e4f5cfcf2f840ae59d40832` for these wire declarations.
S10a re-encodes these contracts; it does not invent a new call state machine,
a component model, approval flow or task lifecycle. In each row the final column
is the protobuf type. Tags inside an inline variant message are shown explicitly;
all other nested types have their own rows. Optional scalar presence, signed
integer timestamps, ordered vectors and secret/public field boundaries survive.

Dynamic component trees, action values, data models, MCP subjects/details and
Ext remain **typed JsonValue/JsonObject data**, because live Rust uses Value.
JsonValue.number is a JSON numeric token validated as finite I-JSON (safe integer
range for integer values); no float round trip is permitted. Objects reject
duplicate keys, sort members by JCS key order for signing/hashing, and enforce
existing limits before use. The oneof covers JSON null/bool/number/string/array/
object exactly. It is never a constructor dispatch or a bytes escape hatch.
This preserves live model syntax and existing JCS surface/args hashes.

For signatures already defined by protocol types (CallControl, TaskEvent, A2iControlEvent,
VoiceLeaseConsent, native documents), reconstruct the exact current canonical
signing view from the typed fields, including fixed schema/domain and optional
omission rules. Existing signature/hash domains and validators remain owned by
those modules. No last-wins JSON map is an ingress adapter. For replaced SDK
transport carriers (SurfaceCarrier, TaskCarrier, TaskApprovalPacket, TaskAck,
TaskCertificate, TransferControl, OwnGroupConsent, GuardianInvite/Accept), sign
`LP("ramflux.message.typed.<TypeName>.v1") || LP(canonical_protobuf_without_signature)`
with the same authorized signing key. TypeName is the exact descriptor name in
this sketch. Canonical protobuf uses ascending tags, shortest varints, omitted
default scalars, preserved optional presence, original vector order and sorted
JsonObject members. Nested signatures remain included. Transcripts are fixed
here; old prefix/JSON carrier encoders are removed, never compatibility decoders.
Carrier/certificate hashes over the changed encoding get the same type-specific
v1 transcript domain and hash those canonical signed bytes including signature.
No old signature domain is silently reused for a changed transcript. Private
signing material, call base keys, grant signatures and proofs stay out of generic
UI projections and logs. Own history preserves the original signer and witnesses.

#### Mapping source: `crates/ramflux-protocol/src/call.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `CallEndpoint.principal_id` | `crates/ramflux-protocol/src/call.rs:11` | `CallEndpoint.principal_id = 1` | `string` |
| `CallEndpoint.root_public_key` | `crates/ramflux-protocol/src/call.rs:12` | `CallEndpoint.root_public_key = 2` | `string` |
| `CallEndpoint.device_id` | `crates/ramflux-protocol/src/call.rs:13` | `CallEndpoint.device_id = 3` | `string` |
| `CallAction::Invite{ base_key: String }` | `crates/ramflux-protocol/src/call.rs:31` | `CallAction.invite = 1` | `CallActionInvite (string base_key = 1;)` |
| `CallAction::Ringing` | `crates/ramflux-protocol/src/call.rs:32` | `CallAction.ringing = 2` | `CallActionRinging (empty)` |
| `CallAction::Answer{ base_key: String }` | `crates/ramflux-protocol/src/call.rs:33` | `CallAction.answer = 3` | `CallActionAnswer (string base_key = 1;)` |
| `CallAction::Ack{ allocation: Box<VoicePeerAllocation> }` | `crates/ramflux-protocol/src/call.rs:34` | `CallAction.ack = 4` | `CallActionAck (VoicePeerAllocation allocation = 1;)` |
| `CallAction::Ready{ consent: Box<VoiceLeaseConsent> }` | `crates/ramflux-protocol/src/call.rs:35` | `CallAction.ready = 5` | `CallActionReady (VoiceLeaseConsent consent = 1;)` |
| `CallAction::Reject` | `crates/ramflux-protocol/src/call.rs:36` | `CallAction.reject = 6` | `CallActionReject (empty)` |
| `CallAction::Busy` | `crates/ramflux-protocol/src/call.rs:37` | `CallAction.busy = 7` | `CallActionBusy (empty)` |
| `CallAction::Hangup` | `crates/ramflux-protocol/src/call.rs:38` | `CallAction.hangup = 8` | `CallActionHangup (empty)` |
| `CallAction::Timeout` | `crates/ramflux-protocol/src/call.rs:39` | `CallAction.timeout = 9` | `CallActionTimeout (empty)` |
| `CallAction::Failed` | `crates/ramflux-protocol/src/call.rs:40` | `CallAction.failed = 10` | `CallActionFailed (empty)` |
| `CallAction::AnsweredElsewhere` | `crates/ramflux-protocol/src/call.rs:41` | `CallAction.answered_elsewhere = 11` | `CallActionAnsweredElsewhere (empty)` |
| `CallAction::Rekey{ generation: u64, base_key: String }` | `crates/ramflux-protocol/src/call.rs:42` | `CallAction.rekey = 12` | `CallActionRekey (uint64 generation = 1;; string base_key = 2;)` |
| `CallAction::RekeyAck{ generation: u64, base_key: String }` | `crates/ramflux-protocol/src/call.rs:43` | `CallAction.rekey_ack = 13` | `CallActionRekeyAck (uint64 generation = 1;; string base_key = 2;)` |
| `CallControl.schema` | `crates/ramflux-protocol/src/call.rs:49` | `CallControl.schema = 1` | `string` |
| `CallControl.call_id` | `crates/ramflux-protocol/src/call.rs:50` | `CallControl.call_id = 2` | `string` |
| `CallControl.conversation_id` | `crates/ramflux-protocol/src/call.rs:51` | `CallControl.conversation_id = 3` | `string` |
| `CallControl.caller` | `crates/ramflux-protocol/src/call.rs:52` | `CallControl.caller = 4` | `CallEndpoint` |
| `CallControl.callee` | `crates/ramflux-protocol/src/call.rs:53` | `CallControl.callee = 5` | `CallEndpoint` |
| `CallControl.sender` | `crates/ramflux-protocol/src/call.rs:54` | `CallControl.sender = 6` | `CallEndpoint` |
| `CallControl.seq` | `crates/ramflux-protocol/src/call.rs:55` | `CallControl.seq = 7` | `uint64` |
| `CallControl.created_at` | `crates/ramflux-protocol/src/call.rs:56` | `CallControl.created_at = 8` | `int64` |
| `CallControl.body` | `crates/ramflux-protocol/src/call.rs:57` | `CallControl.body = 9` | `CallAction` |
| `CallControl.signature` | `crates/ramflux-protocol/src/call.rs:58` | `CallControl.signature = 10` | `string` |
| `VoiceAllocationRequest.call_id` | `crates/ramflux-protocol/src/call.rs:64` | `VoiceAllocationRequest.call_id = 1` | `string` |
| `VoiceAllocationRequest.caller` | `crates/ramflux-protocol/src/call.rs:65` | `VoiceAllocationRequest.caller = 2` | `CallEndpoint` |
| `VoiceAllocationRequest.callee` | `crates/ramflux-protocol/src/call.rs:66` | `VoiceAllocationRequest.callee = 3` | `CallEndpoint` |
| `VoicePeerAllocation.lease_id` | `crates/ramflux-protocol/src/call.rs:84` | `VoicePeerAllocation.lease_id = 1` | `string` |
| `VoicePeerAllocation.endpoint` | `crates/ramflux-protocol/src/call.rs:85` | `VoicePeerAllocation.endpoint = 2` | `string` |
| `VoicePeerAllocation.expires_at` | `crates/ramflux-protocol/src/call.rs:86` | `VoicePeerAllocation.expires_at = 3` | `uint64` |
| `VoicePeerAllocation.hard_expires_at` | `crates/ramflux-protocol/src/call.rs:87` | `VoicePeerAllocation.hard_expires_at = 4` | `uint64` |
| `VoiceLeaseConsent.scope` | `crates/ramflux-protocol/src/call.rs:93` | `VoiceLeaseConsent.scope = 1` | `VoiceAllocationRequest` |
| `VoiceLeaseConsent.lease_id` | `crates/ramflux-protocol/src/call.rs:94` | `VoiceLeaseConsent.lease_id = 2` | `string` |
| `VoiceLeaseConsent.expires_at` | `crates/ramflux-protocol/src/call.rs:95` | `VoiceLeaseConsent.expires_at = 3` | `uint64` |
| `VoiceLeaseConsent.signature` | `crates/ramflux-protocol/src/call.rs:96` | `VoiceLeaseConsent.signature = 4` | `string` |
#### Mapping source: `crates/ramflux-protocol/src/a2ui_state/types.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `EventFields.schema` | `crates/ramflux-protocol/src/a2ui_state/types.rs:67` | `SurfaceEvent.schema = 1` | `string` |
| `EventFields.conversation_id` | `crates/ramflux-protocol/src/a2ui_state/types.rs:68` | `SurfaceEvent.conversation_id = 2` | `string` |
| `EventFields.version` | `crates/ramflux-protocol/src/a2ui_state/types.rs:69` | `SurfaceEvent.version = 3` | `uint64` |
| `EventFields.command` | `crates/ramflux-protocol/src/a2ui_state/types.rs:70` | `SurfaceEvent.command = 4` | `SurfaceCommand` |
| `ActionFields.schema` | `crates/ramflux-protocol/src/a2ui_state/types.rs:117` | `SurfaceAction.schema = 1` | `string` |
| `ActionFields.conversation_id` | `crates/ramflux-protocol/src/a2ui_state/types.rs:118` | `SurfaceAction.conversation_id = 2` | `string` |
| `ActionFields.surface_id` | `crates/ramflux-protocol/src/a2ui_state/types.rs:119` | `SurfaceAction.surface_id = 3` | `string` |
| `ActionFields.version` | `crates/ramflux-protocol/src/a2ui_state/types.rs:120` | `SurfaceAction.version = 4` | `uint64` |
| `ActionFields.surface_hash` | `crates/ramflux-protocol/src/a2ui_state/types.rs:121` | `SurfaceAction.surface_hash = 5` | `string` |
| `ActionFields.action_id` | `crates/ramflux-protocol/src/a2ui_state/types.rs:122` | `SurfaceAction.action_id = 6` | `string` |
| `ActionFields.values` | `crates/ramflux-protocol/src/a2ui_state/types.rs:123` | `SurfaceAction.values = 7` | `JsonValue` |
| `ActionFields.args_hash` | `crates/ramflux-protocol/src/a2ui_state/types.rs:124` | `SurfaceAction.args_hash = 8` | `string` |
| `ActionFields.task_binding` | `crates/ramflux-protocol/src/a2ui_state/types.rs:126` | `SurfaceAction.task_binding = 9` | `optional SurfaceTaskBinding` |
| `SurfaceTaskBinding.task_id` | `crates/ramflux-protocol/src/a2ui_state/types.rs:111` | `SurfaceTaskBinding.task_id = 1` | `string` |
| `SurfaceTaskBinding.step_id` | `crates/ramflux-protocol/src/a2ui_state/types.rs:112` | `SurfaceTaskBinding.step_id = 2` | `string` |
| `A2uiConversationCommand::CreateSurface(CreateSurfaceCommand)` | `crates/ramflux-protocol/src/a2ui_state/types.rs:29` | `SurfaceCommand.create_surface = 1` | `SurfaceCommandCreateSurface (CreateSurfaceCommand value = 1;)` |
| `A2uiConversationCommand::UpdateComponents(UpdateComponentsCommand)` | `crates/ramflux-protocol/src/a2ui_state/types.rs:30` | `SurfaceCommand.update_components = 2` | `SurfaceCommandUpdateComponents (UpdateComponentsCommand value = 1;)` |
| `A2uiConversationCommand::UpdateDataModel(UpdateDataModelCommand)` | `crates/ramflux-protocol/src/a2ui_state/types.rs:31` | `SurfaceCommand.update_data_model = 3` | `SurfaceCommandUpdateDataModel (UpdateDataModelCommand value = 1;)` |
| `A2uiConversationCommand::DeleteSurface(DeleteSurfaceCommand)` | `crates/ramflux-protocol/src/a2ui_state/types.rs:32` | `SurfaceCommand.delete_surface = 4` | `SurfaceCommandDeleteSurface (DeleteSurfaceCommand value = 1;)` |
| `A2uiConversationCommand::PatchSurface(PatchSurfaceCommand)` | `crates/ramflux-protocol/src/a2ui_state/types.rs:33` | `SurfaceCommand.patch_surface = 5` | `SurfaceCommandPatchSurface (PatchSurfaceCommand value = 1;)` |
| `A2uiConversationCommand::StreamAppend(StreamAppendCommand)` | `crates/ramflux-protocol/src/a2ui_state/types.rs:34` | `SurfaceCommand.stream_append = 6` | `SurfaceCommandStreamAppend (StreamAppendCommand value = 1;)` |
| `PatchSurfaceCommand.surface_id` | `crates/ramflux-protocol/src/a2ui_state/types.rs:184` | `PatchSurfaceCommand.surface_id = 1` | `string` |
| `PatchSurfaceCommand.base_surface_hash` | `crates/ramflux-protocol/src/a2ui_state/types.rs:185` | `PatchSurfaceCommand.base_surface_hash = 2` | `string` |
| `PatchSurfaceCommand.ops` | `crates/ramflux-protocol/src/a2ui_state/types.rs:186` | `PatchSurfaceCommand.ops = 3` | `repeated SurfacePatchOp` |
| `PatchSurfaceCommand.new_surface_hash` | `crates/ramflux-protocol/src/a2ui_state/types.rs:187` | `PatchSurfaceCommand.new_surface_hash = 4` | `string` |
| `SurfacePatchOp::ReplaceBlock{ component: Value }` | `crates/ramflux-protocol/src/a2ui_state/types.rs:192` | `SurfacePatchOp.replace_block = 1` | `SurfacePatchOpReplaceBlock (JsonValue component = 1;)` |
| `SurfacePatchOp::InsertBlock{ index: usize, component: Value }` | `crates/ramflux-protocol/src/a2ui_state/types.rs:193` | `SurfacePatchOp.insert_block = 2` | `SurfacePatchOpInsertBlock (uint64 index = 1;; JsonValue component = 2;)` |
| `SurfacePatchOp::RemoveBlock{ component_id: String }` | `crates/ramflux-protocol/src/a2ui_state/types.rs:194` | `SurfacePatchOp.remove_block = 3` | `SurfacePatchOpRemoveBlock (string component_id = 1;)` |
| `SurfacePatchOp::SetActions{ actions: Vec<Value> }` | `crates/ramflux-protocol/src/a2ui_state/types.rs:195` | `SurfacePatchOp.set_actions = 4` | `SurfacePatchOpSetActions (repeated JsonValue actions = 1;)` |
| `SurfacePatchOp::SetFallbackText{ fallback_text: String }` | `crates/ramflux-protocol/src/a2ui_state/types.rs:196` | `SurfacePatchOp.set_fallback_text = 5` | `SurfacePatchOpSetFallbackText (string fallback_text = 1;)` |
| `StreamAppendCommand.surface_id` | `crates/ramflux-protocol/src/a2ui_state/types.rs:201` | `StreamAppendCommand.surface_id = 1` | `string` |
| `StreamAppendCommand.component_id` | `crates/ramflux-protocol/src/a2ui_state/types.rs:202` | `StreamAppendCommand.component_id = 2` | `string` |
| `StreamAppendCommand.text_delta` | `crates/ramflux-protocol/src/a2ui_state/types.rs:203` | `StreamAppendCommand.text_delta = 3` | `string` |
| `StreamAppendCommand.final_` | `crates/ramflux-protocol/src/a2ui_state/types.rs:205` | `StreamAppendCommand.final_ = 4` | `bool` |
#### Mapping source: `crates/ramflux-protocol/src/surfaces.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `CreateSurfaceCommand.surface_id` | `crates/ramflux-protocol/src/surfaces.rs:138` | `CreateSurfaceCommand.surface_id = 1` | `string` |
| `CreateSurfaceCommand.surface_type` | `crates/ramflux-protocol/src/surfaces.rs:139` | `CreateSurfaceCommand.surface_type = 2` | `SurfaceType` |
| `CreateSurfaceCommand.catalog` | `crates/ramflux-protocol/src/surfaces.rs:140` | `CreateSurfaceCommand.catalog = 3` | `string` |
| `CreateSurfaceCommand.catalog_version` | `crates/ramflux-protocol/src/surfaces.rs:141` | `CreateSurfaceCommand.catalog_version = 4` | `string` |
| `CreateSurfaceCommand.fallback_text` | `crates/ramflux-protocol/src/surfaces.rs:142` | `CreateSurfaceCommand.fallback_text = 5` | `string` |
| `CreateSurfaceCommand.fallback_markdown` | `crates/ramflux-protocol/src/surfaces.rs:144` | `CreateSurfaceCommand.fallback_markdown = 6` | `optional string` |
| `CreateSurfaceCommand.components` | `crates/ramflux-protocol/src/surfaces.rs:146` | `CreateSurfaceCommand.components = 7` | `repeated JsonValue` |
| `CreateSurfaceCommand.data_model` | `crates/ramflux-protocol/src/surfaces.rs:148` | `CreateSurfaceCommand.data_model = 8` | `JsonObject` |
| `CreateSurfaceCommand.allowed_actions` | `crates/ramflux-protocol/src/surfaces.rs:150` | `CreateSurfaceCommand.allowed_actions = 9` | `repeated JsonValue` |
| `UpdateComponentsCommand.surface_id` | `crates/ramflux-protocol/src/surfaces.rs:156` | `UpdateComponentsCommand.surface_id = 1` | `string` |
| `UpdateComponentsCommand.base_surface_hash` | `crates/ramflux-protocol/src/surfaces.rs:157` | `UpdateComponentsCommand.base_surface_hash = 2` | `string` |
| `UpdateComponentsCommand.components` | `crates/ramflux-protocol/src/surfaces.rs:159` | `UpdateComponentsCommand.components = 3` | `repeated JsonValue` |
| `UpdateComponentsCommand.remove_component_ids` | `crates/ramflux-protocol/src/surfaces.rs:161` | `UpdateComponentsCommand.remove_component_ids = 4` | `repeated string` |
| `UpdateComponentsCommand.new_surface_hash` | `crates/ramflux-protocol/src/surfaces.rs:162` | `UpdateComponentsCommand.new_surface_hash = 5` | `string` |
| `UpdateDataModelCommand.surface_id` | `crates/ramflux-protocol/src/surfaces.rs:168` | `UpdateDataModelCommand.surface_id = 1` | `string` |
| `UpdateDataModelCommand.base_surface_hash` | `crates/ramflux-protocol/src/surfaces.rs:169` | `UpdateDataModelCommand.base_surface_hash = 2` | `string` |
| `UpdateDataModelCommand.data_patch` | `crates/ramflux-protocol/src/surfaces.rs:170` | `UpdateDataModelCommand.data_patch = 3` | `JsonObject` |
| `UpdateDataModelCommand.new_surface_hash` | `crates/ramflux-protocol/src/surfaces.rs:171` | `UpdateDataModelCommand.new_surface_hash = 4` | `string` |
| `DeleteSurfaceCommand.surface_id` | `crates/ramflux-protocol/src/surfaces.rs:177` | `DeleteSurfaceCommand.surface_id = 1` | `string` |
| `DeleteSurfaceCommand.reason` | `crates/ramflux-protocol/src/surfaces.rs:179` | `DeleteSurfaceCommand.reason = 2` | `optional DeleteSurfaceReason` |
| `SurfaceType::MessageCard` | `crates/ramflux-protocol/src/surfaces.rs:185` | `SurfaceType.message_card = 1` | `SurfaceTypeMessageCard (empty)` |
| `SurfaceType::ApprovalCard` | `crates/ramflux-protocol/src/surfaces.rs:186` | `SurfaceType.approval_card = 2` | `SurfaceTypeApprovalCard (empty)` |
| `SurfaceType::FormCard` | `crates/ramflux-protocol/src/surfaces.rs:187` | `SurfaceType.form_card = 3` | `SurfaceTypeFormCard (empty)` |
| `SurfaceType::StatusPanel` | `crates/ramflux-protocol/src/surfaces.rs:188` | `SurfaceType.status_panel = 4` | `SurfaceTypeStatusPanel (empty)` |
| `SurfaceType::TaskCard` | `crates/ramflux-protocol/src/surfaces.rs:189` | `SurfaceType.task_card = 5` | `SurfaceTypeTaskCard (empty)` |
| `SurfaceType::FilePreview` | `crates/ramflux-protocol/src/surfaces.rs:190` | `SurfaceType.file_preview = 6` | `SurfaceTypeFilePreview (empty)` |
| `SurfaceType::CallCard` | `crates/ramflux-protocol/src/surfaces.rs:191` | `SurfaceType.call_card = 7` | `SurfaceTypeCallCard (empty)` |
| `SurfaceType::AgentResult` | `crates/ramflux-protocol/src/surfaces.rs:192` | `SurfaceType.agent_result = 8` | `SurfaceTypeAgentResult (empty)` |
| `SurfaceType::NotificationCard` | `crates/ramflux-protocol/src/surfaces.rs:193` | `SurfaceType.notification_card = 9` | `SurfaceTypeNotificationCard (empty)` |
| `DeleteSurfaceReason::Completed` | `crates/ramflux-protocol/src/surfaces.rs:199` | `DeleteSurfaceReason.completed = 1` | `DeleteSurfaceReasonCompleted (empty)` |
| `DeleteSurfaceReason::Cancelled` | `crates/ramflux-protocol/src/surfaces.rs:200` | `DeleteSurfaceReason.cancelled = 2` | `DeleteSurfaceReasonCancelled (empty)` |
| `DeleteSurfaceReason::Replaced` | `crates/ramflux-protocol/src/surfaces.rs:201` | `DeleteSurfaceReason.replaced = 3` | `DeleteSurfaceReasonReplaced (empty)` |
| `DeleteSurfaceReason::Expired` | `crates/ramflux-protocol/src/surfaces.rs:202` | `DeleteSurfaceReason.expired = 4` | `DeleteSurfaceReasonExpired (empty)` |
| `DeleteSurfaceReason::Error` | `crates/ramflux-protocol/src/surfaces.rs:203` | `DeleteSurfaceReason.error = 5` | `DeleteSurfaceReasonError (empty)` |
| `A2iControlEvent.schema` | `crates/ramflux-protocol/src/surfaces.rs:56` | `A2iControlEvent.schema = 1` | `string` |
| `A2iControlEvent.version` | `crates/ramflux-protocol/src/surfaces.rs:57` | `A2iControlEvent.version = 2` | `uint32` |
| `A2iControlEvent.domain` | `crates/ramflux-protocol/src/surfaces.rs:58` | `A2iControlEvent.domain = 3` | `string` |
| `A2iControlEvent.ext` | `crates/ramflux-protocol/src/surfaces.rs:60` | `A2iControlEvent.ext = 4` | `Ext` |
| `A2iControlEvent.signed` | `crates/ramflux-protocol/src/surfaces.rs:62` | `A2iControlEvent.signed = 5` | `SignedFields` |
| `A2iControlEvent.event_type` | `crates/ramflux-protocol/src/surfaces.rs:63` | `A2iControlEvent.event_type = 6` | `A2iControlEventType` |
| `A2iControlEvent.control_domain` | `crates/ramflux-protocol/src/surfaces.rs:64` | `A2iControlEvent.control_domain = 7` | `ControlDomain` |
| `A2iControlEvent.action` | `crates/ramflux-protocol/src/surfaces.rs:65` | `A2iControlEvent.action = 8` | `string` |
| `A2iControlEvent.subject` | `crates/ramflux-protocol/src/surfaces.rs:66` | `A2iControlEvent.subject = 9` | `JsonValue` |
| `A2iControlEvent.correlation_id` | `crates/ramflux-protocol/src/surfaces.rs:67` | `A2iControlEvent.correlation_id = 10` | `string` |
| `A2iControlEvent.source_device_id` | `crates/ramflux-protocol/src/surfaces.rs:68` | `A2iControlEvent.source_device_id = 11` | `string` |
| `A2iControlEvent.target_device_id` | `crates/ramflux-protocol/src/surfaces.rs:69` | `A2iControlEvent.target_device_id = 12` | `string` |
| `A2iControlEvent.grant_id` | `crates/ramflux-protocol/src/surfaces.rs:71` | `A2iControlEvent.grant_id = 13` | `optional string` |
| `A2iControlEvent.expires_at` | `crates/ramflux-protocol/src/surfaces.rs:73` | `A2iControlEvent.expires_at = 14` | `optional int64` |
| `ControlDomain::Message` | `crates/ramflux-protocol/src/surfaces.rs:85` | `ControlDomain.message = 1` | `ControlDomainMessage (empty)` |
| `ControlDomain::Conversation` | `crates/ramflux-protocol/src/surfaces.rs:86` | `ControlDomain.conversation = 2` | `ControlDomainConversation (empty)` |
| `ControlDomain::A2ui` | `crates/ramflux-protocol/src/surfaces.rs:87` | `ControlDomain.a2ui = 3` | `ControlDomainA2ui (empty)` |
| `ControlDomain::McpTool` | `crates/ramflux-protocol/src/surfaces.rs:88` | `ControlDomain.mcp_tool = 4` | `ControlDomainMcpTool (empty)` |
| `A2iControlEventType::Control` | `crates/ramflux-protocol/src/surfaces.rs:79` | `A2iControlEventType.control = 1` | `A2iControlEventTypeControl (empty)` |
#### Mapping source: `crates/ramflux-protocol/src/tasks/types.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `TaskStatus::Proposed` | `crates/ramflux-protocol/src/tasks/types.rs:11` | `TaskStatus.proposed = 1` | `TaskStatusProposed (empty)` |
| `TaskStatus::Running` | `crates/ramflux-protocol/src/tasks/types.rs:12` | `TaskStatus.running = 2` | `TaskStatusRunning (empty)` |
| `TaskStatus::NeedsMe` | `crates/ramflux-protocol/src/tasks/types.rs:13` | `TaskStatus.needs_me = 3` | `TaskStatusNeedsMe (empty)` |
| `TaskStatus::Done` | `crates/ramflux-protocol/src/tasks/types.rs:14` | `TaskStatus.done = 4` | `TaskStatusDone (empty)` |
| `TaskStatus::Failed` | `crates/ramflux-protocol/src/tasks/types.rs:15` | `TaskStatus.failed = 5` | `TaskStatusFailed (empty)` |
| `TaskStatus::Cancelled` | `crates/ramflux-protocol/src/tasks/types.rs:16` | `TaskStatus.cancelled = 6` | `TaskStatusCancelled (empty)` |
| `NeedsMe::Approval{ grant_id: String }` | `crates/ramflux-protocol/src/tasks/types.rs:30` | `NeedsMe.approval = 1` | `NeedsMeApproval (string grant_id = 1;)` |
| `NeedsMe::Choice{ surface_id: String }` | `crates/ramflux-protocol/src/tasks/types.rs:31` | `NeedsMe.choice = 2` | `NeedsMeChoice (string surface_id = 1;)` |
| `NeedsMe::Input{ surface_id: String }` | `crates/ramflux-protocol/src/tasks/types.rs:32` | `NeedsMe.input = 3` | `NeedsMeInput (string surface_id = 1;)` |
| `TaskStep.id` | `crates/ramflux-protocol/src/tasks/types.rs:48` | `TaskStep.id = 1` | `string` |
| `TaskStep.title` | `crates/ramflux-protocol/src/tasks/types.rs:49` | `TaskStep.title = 2` | `string` |
| `TaskStep.state` | `crates/ramflux-protocol/src/tasks/types.rs:50` | `TaskStep.state = 3` | `TaskStatus` |
| `TaskStep.needs_me` | `crates/ramflux-protocol/src/tasks/types.rs:52` | `TaskStep.needs_me = 4` | `optional NeedsMe` |
| `TaskStart.task_id` | `crates/ramflux-protocol/src/tasks/types.rs:57` | `TaskStart.task_id = 1` | `string` |
| `TaskStart.conversation_id` | `crates/ramflux-protocol/src/tasks/types.rs:58` | `TaskStart.conversation_id = 2` | `string` |
| `TaskStart.requester` | `crates/ramflux-protocol/src/tasks/types.rs:59` | `TaskStart.requester = 3` | `string` |
| `TaskStart.assignee` | `crates/ramflux-protocol/src/tasks/types.rs:60` | `TaskStart.assignee = 4` | `string` |
| `TaskStart.text` | `crates/ramflux-protocol/src/tasks/types.rs:61` | `TaskStart.text = 5` | `string` |
| `TaskStart.constraints` | `crates/ramflux-protocol/src/tasks/types.rs:63` | `TaskStart.constraints = 6` | `optional string` |
| `TaskProposal.task_id` | `crates/ramflux-protocol/src/tasks/types.rs:68` | `TaskProposal.task_id = 1` | `string` |
| `TaskProposal.conversation_id` | `crates/ramflux-protocol/src/tasks/types.rs:69` | `TaskProposal.conversation_id = 2` | `string` |
| `TaskProposal.proposer` | `crates/ramflux-protocol/src/tasks/types.rs:70` | `TaskProposal.proposer = 3` | `string` |
| `TaskProposal.assignee` | `crates/ramflux-protocol/src/tasks/types.rs:71` | `TaskProposal.assignee = 4` | `string` |
| `TaskProposal.title` | `crates/ramflux-protocol/src/tasks/types.rs:72` | `TaskProposal.title = 5` | `string` |
| `TaskProposal.steps` | `crates/ramflux-protocol/src/tasks/types.rs:73` | `TaskProposal.steps = 6` | `repeated TaskStep` |
| `TaskAccept.task_id` | `crates/ramflux-protocol/src/tasks/types.rs:78` | `TaskAccept.task_id = 1` | `string` |
| `TaskAccept.version` | `crates/ramflux-protocol/src/tasks/types.rs:79` | `TaskAccept.version = 2` | `uint64` |
| `TaskDecline.task_id` | `crates/ramflux-protocol/src/tasks/types.rs:84` | `TaskDecline.task_id = 1` | `string` |
| `TaskDecline.version` | `crates/ramflux-protocol/src/tasks/types.rs:85` | `TaskDecline.version = 2` | `uint64` |
| `TaskUpdate.task_id` | `crates/ramflux-protocol/src/tasks/types.rs:90` | `TaskUpdate.task_id = 1` | `string` |
| `TaskUpdate.version` | `crates/ramflux-protocol/src/tasks/types.rs:91` | `TaskUpdate.version = 2` | `uint64` |
| `TaskUpdate.state` | `crates/ramflux-protocol/src/tasks/types.rs:92` | `TaskUpdate.state = 3` | `TaskStatus` |
| `TaskUpdate.steps` | `crates/ramflux-protocol/src/tasks/types.rs:93` | `TaskUpdate.steps = 4` | `repeated TaskStep` |
| `TaskUpdate.result_ref` | `crates/ramflux-protocol/src/tasks/types.rs:95` | `TaskUpdate.result_ref = 5` | `optional string` |
| `TaskUpdate.result_summary` | `crates/ramflux-protocol/src/tasks/types.rs:97` | `TaskUpdate.result_summary = 6` | `optional string` |
| `TaskCancel.task_id` | `crates/ramflux-protocol/src/tasks/types.rs:102` | `TaskCancel.task_id = 1` | `string` |
| `TaskCancel.base_revision` | `crates/ramflux-protocol/src/tasks/types.rs:103` | `TaskCancel.base_revision = 2` | `uint64` |
| `TaskDecision::Resume` | `crates/ramflux-protocol/src/tasks/types.rs:110` | `TaskDecision.resume = 1` | `TaskDecisionResume (empty)` |
| `TaskDecision::Deny` | `crates/ramflux-protocol/src/tasks/types.rs:111` | `TaskDecision.deny = 2` | `TaskDecisionDeny (empty)` |
| `TaskResolve.task_id` | `crates/ramflux-protocol/src/tasks/types.rs:120` | `TaskResolve.task_id = 1` | `string` |
| `TaskResolve.base_revision` | `crates/ramflux-protocol/src/tasks/types.rs:121` | `TaskResolve.base_revision = 2` | `uint64` |
| `TaskResolve.step_id` | `crates/ramflux-protocol/src/tasks/types.rs:122` | `TaskResolve.step_id = 3` | `string` |
| `TaskResolve.target` | `crates/ramflux-protocol/src/tasks/types.rs:123` | `TaskResolve.target = 4` | `NeedsMe` |
| `TaskResolve.decision_id` | `crates/ramflux-protocol/src/tasks/types.rs:124` | `TaskResolve.decision_id = 5` | `string` |
| `TaskResolve.decision` | `crates/ramflux-protocol/src/tasks/types.rs:125` | `TaskResolve.decision = 6` | `TaskDecision` |
| `TaskEventBody::Start(TaskStart)` | `crates/ramflux-protocol/src/tasks/types.rs:131` | `TaskEventBody.start = 1` | `TaskEventBodyStart (TaskStart value = 1;)` |
| `TaskEventBody::Proposal(TaskProposal)` | `crates/ramflux-protocol/src/tasks/types.rs:132` | `TaskEventBody.proposal = 2` | `TaskEventBodyProposal (TaskProposal value = 1;)` |
| `TaskEventBody::Accept(TaskAccept)` | `crates/ramflux-protocol/src/tasks/types.rs:133` | `TaskEventBody.accept = 3` | `TaskEventBodyAccept (TaskAccept value = 1;)` |
| `TaskEventBody::Decline(TaskDecline)` | `crates/ramflux-protocol/src/tasks/types.rs:134` | `TaskEventBody.decline = 4` | `TaskEventBodyDecline (TaskDecline value = 1;)` |
| `TaskEventBody::Update(TaskUpdate)` | `crates/ramflux-protocol/src/tasks/types.rs:135` | `TaskEventBody.update = 5` | `TaskEventBodyUpdate (TaskUpdate value = 1;)` |
| `TaskEventBody::Cancel(TaskCancel)` | `crates/ramflux-protocol/src/tasks/types.rs:136` | `TaskEventBody.cancel = 6` | `TaskEventBodyCancel (TaskCancel value = 1;)` |
| `TaskEventBody::Resolve(TaskResolve)` | `crates/ramflux-protocol/src/tasks/types.rs:137` | `TaskEventBody.resolve = 7` | `TaskEventBodyResolve (TaskResolve value = 1;)` |
#### Mapping source: `crates/ramflux-protocol/src/tasks/event.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `EventFields.schema` | `crates/ramflux-protocol/src/tasks/event.rs:29` | `TaskEvent.schema = 1` | `string` |
| `EventFields.version` | `crates/ramflux-protocol/src/tasks/event.rs:30` | `TaskEvent.version = 2` | `uint32` |
| `EventFields.domain` | `crates/ramflux-protocol/src/tasks/event.rs:31` | `TaskEvent.domain = 3` | `string` |
| `EventFields.ext` | `crates/ramflux-protocol/src/tasks/event.rs:33` | `TaskEvent.ext = 4` | `Ext` |
| `EventFields.signed` | `crates/ramflux-protocol/src/tasks/event.rs:35` | `TaskEvent.signed = 5` | `SignedFields` |
| `EventFields.conversation_id` | `crates/ramflux-protocol/src/tasks/event.rs:36` | `TaskEvent.conversation_id = 6` | `string` |
| `EventFields.event` | `crates/ramflux-protocol/src/tasks/event.rs:37` | `TaskEvent.event = 7` | `TaskEventBody` |
#### Mapping source: `crates/ramflux-protocol/src/core_types.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `SignedFields.signing_key_id` | `crates/ramflux-protocol/src/core_types.rs:26` | `SignedFields.signing_key_id = 1` | `string` |
| `SignedFields.signature_alg` | `crates/ramflux-protocol/src/core_types.rs:27` | `SignedFields.signature_alg = 2` | `SignatureAlg` |
| `SignedFields.signature` | `crates/ramflux-protocol/src/core_types.rs:28` | `SignedFields.signature = 3` | `string` |
| `Ext.ext` | `crates/ramflux-protocol/src/core_types.rs:35` | `Ext.ext = 1` | `JsonObject` |
#### Mapping source: `crates/ramflux-sdk/src/client/surface/carrier.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `Carrier.schema` | `crates/ramflux-sdk/src/client/surface/carrier.rs:20` | `SurfaceCarrier.schema = 1` | `string` |
| `Carrier.content_type` | `crates/ramflux-sdk/src/client/surface/carrier.rs:21` | `SurfaceCarrier.content_type = 2` | `string` |
| `Carrier.posted_at` | `crates/ramflux-sdk/src/client/surface/carrier.rs:23` | `SurfaceCarrier.posted_at = 3` | `optional int64` |
| `Carrier.updated_at` | `crates/ramflux-sdk/src/client/surface/carrier.rs:25` | `SurfaceCarrier.updated_at = 4` | `optional int64` |
| `Carrier.conversation_id` | `crates/ramflux-sdk/src/client/surface/carrier.rs:27` | `SurfaceCarrier.conversation_id = 5` | `string` |
| `Carrier.surface_id` | `crates/ramflux-sdk/src/client/surface/carrier.rs:28` | `SurfaceCarrier.surface_id = 6` | `string` |
| `Carrier.message_id` | `crates/ramflux-sdk/src/client/surface/carrier.rs:29` | `SurfaceCarrier.message_id = 7` | `string` |
| `Carrier.sender_principal_id` | `crates/ramflux-sdk/src/client/surface/carrier.rs:30` | `SurfaceCarrier.sender_principal_id = 8` | `string` |
| `Carrier.sender_device_id` | `crates/ramflux-sdk/src/client/surface/carrier.rs:31` | `SurfaceCarrier.sender_device_id = 9` | `string` |
| `Carrier.author_principal_id` | `crates/ramflux-sdk/src/client/surface/carrier.rs:32` | `SurfaceCarrier.author_principal_id = 10` | `string` |
| `Carrier.signature` | `crates/ramflux-sdk/src/client/surface/carrier.rs:34` | `SurfaceCarrier.signature = 11` | `string` |
| `Carrier.snapshot` | `crates/ramflux-sdk/src/client/surface/carrier.rs:36` | `SurfaceCarrier.snapshot = 12` | `optional SurfaceSnapshotProof` |
| `PayloadKind::Event / wire_base64` | `crates/ramflux-sdk/src/client/surface/carrier.rs:26` | `SurfaceCarrier.event = 16` | `SurfaceEvent` |
| `PayloadKind::Action / wire_base64` | `crates/ramflux-sdk/src/client/surface/carrier.rs:26` | `SurfaceCarrier.action = 17` | `SurfaceAction` |
| `PayloadKind::ActionReceipt / wire_base64` | `crates/ramflux-sdk/src/client/surface/carrier.rs:26` | `SurfaceCarrier.action_receipt = 18` | `SurfaceCarrier` |
#### Mapping source: `crates/ramflux-sdk/src/client/surface/snapshot.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `SnapshotProof.wire_base64` | `crates/ramflux-sdk/src/client/surface/snapshot.rs:13` | `SurfaceSnapshotProof.event = 1` | `SurfaceEvent` |
| `SnapshotProof.checkpoint_base64` | `crates/ramflux-sdk/src/client/surface/snapshot.rs:15` | `SurfaceSnapshotProof.checkpoint = 2` | `SurfaceCheckpoint` |
| `SnapshotProof.surface_hash` | `crates/ramflux-sdk/src/client/surface/snapshot.rs:17` | `SurfaceSnapshotProof.surface_hash = 3` | `optional string` |
| `SnapshotProof.metadata` | `crates/ramflux-sdk/src/client/surface/snapshot.rs:19` | `SurfaceSnapshotProof.metadata = 4` | `SurfaceResyncMetadata` |
| `SnapshotProof.author_device_id` | `crates/ramflux-sdk/src/client/surface/snapshot.rs:20` | `SurfaceSnapshotProof.author_device_id = 5` | `string` |
#### Mapping source: `crates/ramflux-sdk/src/client/surface/control.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `SurfaceControl.kind` | `crates/ramflux-sdk/src/client/surface/control.rs:21` | `SurfaceDelivery.kind = 1` | `SurfaceControlKind` |
| `SurfaceControl.carrier_base64` | `crates/ramflux-sdk/src/client/surface/control.rs:22` | `SurfaceDelivery.carrier = 2` | `SurfaceCarrier` |
| `SurfaceControl.group_epoch` | `crates/ramflux-sdk/src/client/surface/control.rs:23` | `SurfaceDelivery.group_epoch = 3` | `optional uint64` |
| `SurfaceControl.context` | `crates/ramflux-sdk/src/client/surface/control.rs:24` | `SurfaceDelivery.context = 4` | `optional OwnContext` |
| `SurfaceControl.manifests` | `crates/ramflux-sdk/src/client/surface/control.rs:25` | `SurfaceDelivery.manifests = 5` | `repeated NativeDeviceManifest` |
| `ControlKind::Peer` | `crates/ramflux-sdk/src/client/surface/control.rs:15` | `SurfaceControlKind.peer = 1` | `SurfaceControlKindPeer (empty)` |
| `ControlKind::Own` | `crates/ramflux-sdk/src/client/surface/control.rs:16` | `SurfaceControlKind.own = 2` | `SurfaceControlKindOwn (empty)` |
| `OwnContext.conversation_id` | `crates/ramflux-sdk/src/client/surface/control.rs:30` | `OwnContext.conversation_id = 1` | `string` |
| `OwnContext.participants` | `crates/ramflux-sdk/src/client/surface/control.rs:31` | `OwnContext.participants = 2` | `repeated string` |
| `OwnContext.group` | `crates/ramflux-sdk/src/client/surface/control.rs:32` | `OwnContext.group = 3` | `optional SdkOwnDeviceGroupSnapshot` |
| `OwnContext.friend` | `crates/ramflux-sdk/src/client/surface/control.rs:33` | `OwnContext.friend = 4` | `optional FriendLinkRecord` |
#### Mapping source: `crates/ramflux-sdk/src/client/task/carrier.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `Carrier.content_type` | `crates/ramflux-sdk/src/client/task/carrier.rs:14` | `TaskCarrier.content_type = 1` | `string` |
| `Carrier.conversation_id` | `crates/ramflux-sdk/src/client/task/carrier.rs:15` | `TaskCarrier.conversation_id = 2` | `string` |
| `Carrier.message_id` | `crates/ramflux-sdk/src/client/task/carrier.rs:16` | `TaskCarrier.message_id = 3` | `string` |
| `Carrier.principal_id` | `crates/ramflux-sdk/src/client/task/carrier.rs:17` | `TaskCarrier.principal_id = 4` | `string` |
| `Carrier.device_id` | `crates/ramflux-sdk/src/client/task/carrier.rs:18` | `TaskCarrier.device_id = 5` | `string` |
| `Carrier.wire_base64` | `crates/ramflux-sdk/src/client/task/carrier.rs:19` | `TaskCarrier.event = 6` | `TaskEvent` |
| `Carrier.signature` | `crates/ramflux-sdk/src/client/task/carrier.rs:20` | `TaskCarrier.signature = 7` | `string` |
| `Carrier.decision_proof_base64` | `crates/ramflux-sdk/src/client/task/carrier.rs:22` | `TaskCarrier.decision_proof = 8` | `TaskCertificate` |
#### Mapping source: `crates/ramflux-sdk/src/client/task/approval.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `Request.binding` | `crates/ramflux-sdk/src/client/task/approval.rs:17` | `TaskApprovalRequest.binding = 1` | `TaskApprovalBinding` |
| `Request.approval` | `crates/ramflux-sdk/src/client/task/approval.rs:18` | `TaskApprovalRequest.approval = 2` | `LocalMcpApprovalRecord` |
| `Request.grant_body` | `crates/ramflux-sdk/src/client/task/approval.rs:19` | `TaskApprovalRequest.grant_body = 3` | `LocalMcpGrantSigningBody` |
| `Payload::Request{ request: Box<Request> }` | `crates/ramflux-sdk/src/client/task/approval.rs:24` | `TaskApprovalPayload.request = 1` | `TaskApprovalPayloadRequest (TaskApprovalRequest request = 1;)` |
| `Payload::Decision{ request: Box<Request>, approved: bool, grant_signature: Option<String> }` | `crates/ramflux-sdk/src/client/task/approval.rs:25` | `TaskApprovalPayload.decision = 2` | `TaskApprovalPayloadDecision (TaskApprovalRequest request = 1;; bool approved = 2;; optional string grant_signature = 3;)` |
| `Packet.payload` | `crates/ramflux-sdk/src/client/task/approval.rs:30` | `TaskApprovalPacket.payload = 1` | `TaskApprovalPayload` |
| `Packet.principal` | `crates/ramflux-sdk/src/client/task/approval.rs:31` | `TaskApprovalPacket.principal = 2` | `string` |
| `Packet.device` | `crates/ramflux-sdk/src/client/task/approval.rs:32` | `TaskApprovalPacket.device = 3` | `string` |
| `Packet.signature` | `crates/ramflux-sdk/src/client/task/approval.rs:33` | `TaskApprovalPacket.signature = 4` | `string` |
#### Mapping source: `crates/ramflux-sdk/src/client/task/control.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `Ack.carrier_base64` | `crates/ramflux-sdk/src/client/task/control.rs:14` | `TaskAck.carrier = 1` | `TaskCarrier` |
| `Ack.certificate` | `crates/ramflux-sdk/src/client/task/control.rs:15` | `TaskAck.certificate = 2` | `TaskCertificate` |
| `Ack.manifests` | `crates/ramflux-sdk/src/client/task/control.rs:16` | `TaskAck.manifests = 3` | `repeated NativeDeviceManifest` |
| `Ack.signer_principal` | `crates/ramflux-sdk/src/client/task/control.rs:17` | `TaskAck.signer_principal = 4` | `string` |
| `Ack.signer_device` | `crates/ramflux-sdk/src/client/task/control.rs:18` | `TaskAck.signer_device = 5` | `string` |
| `Ack.signature` | `crates/ramflux-sdk/src/client/task/control.rs:19` | `TaskAck.signature = 6` | `string` |
| `Control::Intent{ carrier_base64: String }` | `crates/ramflux-sdk/src/client/task/control.rs:24` | `TaskControl.intent = 1` | `TaskControlIntent (TaskCarrier carrier = 1;)` |
| `Control::Ack(Box<Ack>)` | `crates/ramflux-sdk/src/client/task/control.rs:25` | `TaskControl.ack = 2` | `TaskControlAck (TaskAck value = 1;)` |
#### Mapping source: `crates/ramflux-sdk/src/client/task/certificate.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `Certificate.conversation_id` | `crates/ramflux-sdk/src/client/task/certificate.rs:18` | `TaskCertificate.conversation_id = 1` | `string` |
| `Certificate.resolution` | `crates/ramflux-sdk/src/client/task/certificate.rs:19` | `TaskCertificate.resolution = 2` | `TaskResolve` |
| `Certificate.assignee` | `crates/ramflux-sdk/src/client/task/certificate.rs:20` | `TaskCertificate.assignee = 3` | `string` |
| `Certificate.issuer_device` | `crates/ramflux-sdk/src/client/task/certificate.rs:21` | `TaskCertificate.issuer_device = 4` | `string` |
| `Certificate.issued_at` | `crates/ramflux-sdk/src/client/task/certificate.rs:22` | `TaskCertificate.issued_at = 5` | `int64` |
| `Certificate.phase` | `crates/ramflux-sdk/src/client/task/certificate.rs:23` | `TaskCertificate.phase = 6` | `TaskCertificatePhase` |
| `Certificate.committed_version` | `crates/ramflux-sdk/src/client/task/certificate.rs:24` | `TaskCertificate.committed_version = 7` | `optional uint64` |
| `Certificate.carrier_hash` | `crates/ramflux-sdk/src/client/task/certificate.rs:25` | `TaskCertificate.carrier_hash = 8` | `optional string` |
| `Certificate.decision_key` | `crates/ramflux-sdk/src/client/task/certificate.rs:26` | `TaskCertificate.decision_key = 9` | `string` |
| `Certificate.evidence_hash` | `crates/ramflux-sdk/src/client/task/certificate.rs:27` | `TaskCertificate.evidence_hash = 10` | `string` |
| `Certificate.signature` | `crates/ramflux-sdk/src/client/task/certificate.rs:28` | `TaskCertificate.signature = 11` | `string` |
| `Phase::Reserved` | `crates/ramflux-sdk/src/client/task/certificate.rs:12` | `TaskCertificatePhase.reserved = 1` | `TaskCertificatePhaseReserved (empty)` |
| `Phase::Committed` | `crates/ramflux-sdk/src/client/task/certificate.rs:13` | `TaskCertificatePhase.committed = 2` | `TaskCertificatePhaseCommitted (empty)` |
#### Mapping source: `crates/ramflux-sdk/src/client/task/mod.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `AcceptedEvent.carrier` | `crates/ramflux-sdk/src/client/task/mod.rs:33` | `TaskAcceptedEvent.carrier = 1` | `TaskCarrier` |
| `AcceptedEvent.public_key` | `crates/ramflux-sdk/src/client/task/mod.rs:34` | `TaskAcceptedEvent.public_key = 2` | `string` |
| `AcceptedEvent.actor_kind_verified` | `crates/ramflux-sdk/src/client/task/mod.rs:36` | `TaskAcceptedEvent.actor_kind_verified = 3` | `bool` |
| `AcceptedEvent.received_at` | `crates/ramflux-sdk/src/client/task/mod.rs:38` | `TaskAcceptedEvent.received_at = 4` | `int64` |
| `AcceptedEvent.decision_certificate` | `crates/ramflux-sdk/src/client/task/mod.rs:40` | `TaskAcceptedEvent.decision_certificate = 5` | `optional TaskCertificate` |
| `AcceptedEvent.membership` | `crates/ramflux-sdk/src/client/task/mod.rs:42` | `TaskAcceptedEvent.membership = 6` | `optional TaskMembership` |
| `TaskHistory.events` | `crates/ramflux-sdk/src/client/task/mod.rs:46` | `TaskHistory.events = 1` | `repeated TaskAcceptedEvent` |
| `TaskHistory.created_at` | `crates/ramflux-sdk/src/client/task/mod.rs:47` | `TaskHistory.created_at = 2` | `int64` |
| `TaskHistory.updated_at` | `crates/ramflux-sdk/src/client/task/mod.rs:48` | `TaskHistory.updated_at = 3` | `int64` |
#### Mapping source: `crates/ramflux-sdk/src/client/task/historical.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `Membership.conversation` | `crates/ramflux-sdk/src/client/task/historical.rs:13` | `TaskMembership.conversation = 1` | `string` |
| `Membership.group` | `crates/ramflux-sdk/src/client/task/historical.rs:14` | `TaskMembership.group = 2` | `optional string` |
| `Membership.epoch` | `crates/ramflux-sdk/src/client/task/historical.rs:15` | `TaskMembership.epoch = 3` | `optional uint64` |
| `Membership.at` | `crates/ramflux-sdk/src/client/task/historical.rs:16` | `TaskMembership.at = 4` | `int64` |
| `Membership.members` | `crates/ramflux-sdk/src/client/task/historical.rs:17` | `TaskMembership.members = 5` | `repeated string` |
#### Mapping source: `crates/ramflux-sdk/src/client/task/own_history.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `TaskOwnPacket.context` | `crates/ramflux-sdk/src/client/task/own_history.rs:22` | `TaskOwnPacket.context = 1` | `OwnContext` |
| `TaskOwnPacket.history` | `crates/ramflux-sdk/src/client/task/own_history.rs:23` | `TaskOwnPacket.history = 2` | `TaskHistory` |
| `TaskOwnPacket.manifests` | `crates/ramflux-sdk/src/client/task/own_history.rs:24` | `TaskOwnPacket.manifests = 3` | `repeated NativeDeviceManifest` |
| `TaskOwnPacket.pins` | `crates/ramflux-sdk/src/client/task/own_history.rs:25` | `TaskOwnPacket.pins = 4` | `repeated SdkOwnDeviceGroupMemberPin` |
| `TaskOwnPacket.base` | `crates/ramflux-sdk/src/client/task/own_history.rs:26` | `TaskOwnPacket.base = 5` | `uint64` |
| `TaskOwnPacket.prefix_hash` | `crates/ramflux-sdk/src/client/task/own_history.rs:27` | `TaskOwnPacket.prefix_hash = 6` | `string` |
#### Mapping source: `crates/ramflux-sdk/src/bus/protocol.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `TaskApprovalBinding.conversation_id` | `crates/ramflux-sdk/src/bus/protocol.rs:1044` | `TaskApprovalBinding.conversation_id = 1` | `string` |
| `TaskApprovalBinding.task_id` | `crates/ramflux-sdk/src/bus/protocol.rs:1045` | `TaskApprovalBinding.task_id = 2` | `string` |
| `TaskApprovalBinding.step_id` | `crates/ramflux-sdk/src/bus/protocol.rs:1046` | `TaskApprovalBinding.step_id = 3` | `string` |
| `TaskApprovalBinding.opening_revision` | `crates/ramflux-sdk/src/bus/protocol.rs:1047` | `TaskApprovalBinding.opening_revision = 4` | `uint64` |
| `TaskApprovalBinding.requester` | `crates/ramflux-sdk/src/bus/protocol.rs:1048` | `TaskApprovalBinding.requester = 5` | `string` |
| `TaskApprovalBinding.assignee` | `crates/ramflux-sdk/src/bus/protocol.rs:1049` | `TaskApprovalBinding.assignee = 6` | `string` |
| `TaskApprovalBinding.executor_device_id` | `crates/ramflux-sdk/src/bus/protocol.rs:1050` | `TaskApprovalBinding.executor_device_id = 7` | `string` |
| `LocalMcpGrantSigningBody.task_binding` | `crates/ramflux-sdk/src/bus/protocol.rs:1056` | `LocalMcpGrantSigningBody.task_binding = 1` | `optional TaskApprovalBinding` |
| `LocalMcpGrantSigningBody.approval_id` | `crates/ramflux-sdk/src/bus/protocol.rs:1057` | `LocalMcpGrantSigningBody.approval_id = 2` | `string` |
| `LocalMcpGrantSigningBody.grant_id` | `crates/ramflux-sdk/src/bus/protocol.rs:1058` | `LocalMcpGrantSigningBody.grant_id = 3` | `string` |
| `LocalMcpGrantSigningBody.server_id` | `crates/ramflux-sdk/src/bus/protocol.rs:1059` | `LocalMcpGrantSigningBody.server_id = 4` | `string` |
| `LocalMcpGrantSigningBody.tool_name` | `crates/ramflux-sdk/src/bus/protocol.rs:1060` | `LocalMcpGrantSigningBody.tool_name = 5` | `string` |
| `LocalMcpGrantSigningBody.tool_scope` | `crates/ramflux-sdk/src/bus/protocol.rs:1062` | `LocalMcpGrantSigningBody.tool_scope = 6` | `optional string` |
| `LocalMcpGrantSigningBody.capability` | `crates/ramflux-sdk/src/bus/protocol.rs:1063` | `LocalMcpGrantSigningBody.capability = 7` | `McpCapability` |
| `LocalMcpGrantSigningBody.registry_hash` | `crates/ramflux-sdk/src/bus/protocol.rs:1064` | `LocalMcpGrantSigningBody.registry_hash = 8` | `string` |
| `LocalMcpGrantSigningBody.tool_manifest_set_hash` | `crates/ramflux-sdk/src/bus/protocol.rs:1065` | `LocalMcpGrantSigningBody.tool_manifest_set_hash = 9` | `string` |
| `LocalMcpGrantSigningBody.full_delegation` | `crates/ramflux-sdk/src/bus/protocol.rs:1066` | `LocalMcpGrantSigningBody.full_delegation = 10` | `bool` |
| `LocalMcpGrantSigningBody.single_use` | `crates/ramflux-sdk/src/bus/protocol.rs:1068` | `LocalMcpGrantSigningBody.single_use = 11` | `bool` |
| `LocalMcpGrantSigningBody.arguments_hash` | `crates/ramflux-sdk/src/bus/protocol.rs:1070` | `LocalMcpGrantSigningBody.arguments_hash = 12` | `optional string` |
| `LocalMcpGrantSigningBody.expires_at` | `crates/ramflux-sdk/src/bus/protocol.rs:1071` | `LocalMcpGrantSigningBody.expires_at = 13` | `int64` |
| `LocalBusFederationRoute.federation_url` | `crates/ramflux-sdk/src/bus/protocol.rs:395` | `LocalBusFederationRoute.federation_url = 1` | `string` |
| `LocalBusFederationRoute.source_node_id` | `crates/ramflux-sdk/src/bus/protocol.rs:396` | `LocalBusFederationRoute.source_node_id = 2` | `string` |
| `LocalBusFederationRoute.target_node_id` | `crates/ramflux-sdk/src/bus/protocol.rs:397` | `LocalBusFederationRoute.target_node_id = 3` | `string` |
| `LocalBusFederationRoute.required_capability` | `crates/ramflux-sdk/src/bus/protocol.rs:398` | `LocalBusFederationRoute.required_capability = 4` | `string` |
| `LocalBusFederationRoute.admin_token` | `crates/ramflux-sdk/src/bus/protocol.rs:400` | `LocalBusFederationRoute.admin_token = 5` | `optional string` |
| `LocalBusFederationRoute.recipient_prekey_url` | `crates/ramflux-sdk/src/bus/protocol.rs:402` | `LocalBusFederationRoute.recipient_prekey_url = 6` | `optional string` |
#### Mapping source: `crates/ramflux-sdk/src/records.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `LocalMcpApprovalRecord.approval_id` | `crates/ramflux-sdk/src/records.rs:80` | `LocalMcpApprovalRecord.approval_id = 1` | `string` |
| `LocalMcpApprovalRecord.server_id` | `crates/ramflux-sdk/src/records.rs:81` | `LocalMcpApprovalRecord.server_id = 2` | `string` |
| `LocalMcpApprovalRecord.tool_name` | `crates/ramflux-sdk/src/records.rs:82` | `LocalMcpApprovalRecord.tool_name = 3` | `string` |
| `LocalMcpApprovalRecord.capability` | `crates/ramflux-sdk/src/records.rs:83` | `LocalMcpApprovalRecord.capability = 4` | `McpCapability` |
| `LocalMcpApprovalRecord.risk_level` | `crates/ramflux-sdk/src/records.rs:84` | `LocalMcpApprovalRecord.risk_level = 5` | `RiskLevel` |
| `LocalMcpApprovalRecord.tool_scope` | `crates/ramflux-sdk/src/records.rs:85` | `LocalMcpApprovalRecord.tool_scope = 6` | `optional string` |
| `LocalMcpApprovalRecord.confirmation_mode` | `crates/ramflux-sdk/src/records.rs:86` | `LocalMcpApprovalRecord.confirmation_mode = 7` | `string` |
| `LocalMcpApprovalRecord.expires_at` | `crates/ramflux-sdk/src/records.rs:87` | `LocalMcpApprovalRecord.expires_at = 8` | `int64` |
| `LocalMcpApprovalRecord.status` | `crates/ramflux-sdk/src/records.rs:88` | `LocalMcpApprovalRecord.status = 9` | `string` |
| `LocalMcpApprovalRecord.details` | `crates/ramflux-sdk/src/records.rs:89` | `LocalMcpApprovalRecord.details = 10` | `JsonValue` |
#### Mapping source: `crates/ramflux-sdk/src/client/shared_group/controls.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `GroupControlPacket.schema` | `crates/ramflux-sdk/src/client/shared_group/controls.rs:12` | `GroupStateControl.schema = 1` | `string` |
| `GroupControlPacket.body` | `crates/ramflux-sdk/src/client/shared_group/controls.rs:13` | `GroupStateControl.body = 2` | `GroupControlBody` |
| `GroupControlBody::Request{ request: GroupChangeRequest, federation: Option<LocalBusFederationRoute> }` | `crates/ramflux-sdk/src/client/shared_group/controls.rs:18` | `GroupControlBody.request = 1` | `GroupControlBodyRequest (NativeGroupChangeRequest request = 1;; optional LocalBusFederationRoute federation = 2;)` |
| `GroupControlBody::Result{ result: GroupChangeResult }` | `crates/ramflux-sdk/src/client/shared_group/controls.rs:19` | `GroupControlBody.result = 2` | `GroupControlBodyResult (NativeGroupChangeResult result = 1;)` |
| `GroupControlBody::DeviceSet{ group_id: String, actor: GroupStateActor, device_set_epoch: u64 }` | `crates/ramflux-sdk/src/client/shared_group/controls.rs:20` | `GroupControlBody.device_set = 3` | `GroupControlBodyDeviceSet (string group_id = 1;; NativeGroupActor actor = 2;; uint64 device_set_epoch = 3;)` |
| `GroupControlBody::Transfer{ control: Box<super::TransferControl> }` | `crates/ramflux-sdk/src/client/shared_group/controls.rs:21` | `GroupControlBody.transfer = 4` | `GroupControlBodyTransfer (TransferControl control = 1;)` |
#### Mapping source: `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `TransferDevice.root` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:12` | `TransferDevice.root = 1` | `string` |
| `TransferDevice.device` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:13` | `TransferDevice.device = 2` | `string` |
| `TransferProbe.id` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:18` | `TransferProbe.id = 1` | `string` |
| `TransferProbe.actor` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:19` | `TransferProbe.actor = 2` | `NativeGroupActor` |
| `TransferProbe.creator` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:20` | `TransferProbe.creator = 3` | `NativeGroupActor` |
| `TransferProbe.base` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:21` | `TransferProbe.base = 4` | `NativeGroupSnapshot` |
| `TransferProbe.required` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:22` | `TransferProbe.required = 5` | `repeated TransferDevice` |
| `TransferProbe.issued_at` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:23` | `TransferProbe.issued_at = 6` | `int64` |
| `TransferProbe.expires_at` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:24` | `TransferProbe.expires_at = 7` | `int64` |
| `TransferHead.proposal` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:29` | `TransferHead.proposal = 1` | `string` |
| `TransferHead.actor` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:30` | `TransferHead.actor = 2` | `NativeGroupActor` |
| `TransferHead.requested_hash` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:31` | `TransferHead.requested_hash = 3` | `string` |
| `TransferHead.head` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:32` | `TransferHead.head = 4` | `NativeGroupSnapshot` |
| `TransferHead.acceptance` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:33` | `TransferHead.acceptance = 5` | `optional NativeGroupTransferAcceptance` |
| `TransferHead.requires_sync` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:34` | `TransferHead.requires_sync = 6` | `bool` |
| `TransferHead.target` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:35` | `TransferHead.target = 7` | `TransferDevice` |
| `TransferHead.additional_targets` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:37` | `TransferHead.additional_targets = 8` | `repeated TransferDevice` |
| `TransferHead.cancelled` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:39` | `TransferHead.cancelled = 9` | `bool` |
| `TransferHead.cancel_ack` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:41` | `TransferHead.cancel_ack = 10` | `bool` |
| `TransferHead.issued_at` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:42` | `TransferHead.issued_at = 11` | `int64` |
| `TransferHead.expires_at` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:43` | `TransferHead.expires_at = 12` | `int64` |
| `TransferBody::Probe{ probe: Box<TransferProbe> }` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:48` | `TransferBody.probe = 1` | `TransferBodyProbe (TransferProbe probe = 1;)` |
| `TransferBody::Head{ reply: Box<TransferHead> }` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:49` | `TransferBody.head = 2` | `TransferBodyHead (TransferHead reply = 1;)` |
| `TransferControl.body` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:54` | `TransferControl.body = 1` | `TransferBody` |
| `TransferControl.signature` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:55` | `TransferControl.signature = 2` | `string` |
#### Mapping source: `crates/ramflux-sdk/src/client/own_contact.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `Contact.manifest` | `crates/ramflux-sdk/src/client/own_contact.rs:20` | `OwnContactSync.manifest = 1` | `NativeDeviceManifest` |
| `Contact.link` | `crates/ramflux-sdk/src/client/own_contact.rs:21` | `OwnContactSync.link = 2` | `FriendLinkRecord` |
#### Mapping source: `crates/ramflux-sdk/src/client/own_contact/tombstone.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `Tombstone.link` | `crates/ramflux-sdk/src/client/own_contact/tombstone.rs:13` | `OwnContactTombstone.link = 1` | `FriendLinkRecord` |
| `Tombstone.decided_at` | `crates/ramflux-sdk/src/client/own_contact/tombstone.rs:15` | `OwnContactTombstone.decided_at = 2` | `optional int64` |
#### Mapping source: `crates/ramflux-sdk/src/client/shared_group/own_consent.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `Consent.schema` | `crates/ramflux-sdk/src/client/shared_group/own_consent.rs:15` | `OwnGroupConsent.schema = 1` | `string` |
| `Consent.actor` | `crates/ramflux-sdk/src/client/shared_group/own_consent.rs:16` | `OwnGroupConsent.actor = 2` | `NativeGroupActor` |
| `Consent.snapshot` | `crates/ramflux-sdk/src/client/shared_group/own_consent.rs:17` | `OwnGroupConsent.snapshot = 3` | `NativeGroupSnapshot` |
| `Consent.accepted` | `crates/ramflux-sdk/src/client/shared_group/own_consent.rs:18` | `OwnGroupConsent.accepted = 4` | `bool` |
| `Consent.issued_at` | `crates/ramflux-sdk/src/client/shared_group/own_consent.rs:19` | `OwnGroupConsent.issued_at = 5` | `int64` |
| `Consent.expires_at` | `crates/ramflux-sdk/src/client/shared_group/own_consent.rs:20` | `OwnGroupConsent.expires_at = 6` | `int64` |
| `Consent.signature` | `crates/ramflux-sdk/src/client/shared_group/own_consent.rs:21` | `OwnGroupConsent.signature = 7` | `string` |
#### Mapping source: `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `Checkpoint.schema` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:13` | `SurfaceCheckpoint.schema = 1` | `string` |
| `Checkpoint.content` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:14` | `SurfaceCheckpoint.content = 2` | `optional CreateSurfaceCommand` |
| `Checkpoint.conversation_id` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:15` | `SurfaceCheckpoint.conversation_id = 3` | `optional string` |
| `Checkpoint.version` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:16` | `SurfaceCheckpoint.version = 4` | `uint64` |
| `Checkpoint.closed` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:17` | `SurfaceCheckpoint.closed = 5` | `bool` |
| `Checkpoint.final_text` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:18` | `SurfaceCheckpoint.final_text = 6` | `repeated SurfaceFinalEntry` |
| `FinalEntry.id` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:23` | `SurfaceFinalEntry.id = 1` | `string` |
| `FinalEntry.nested` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:24` | `SurfaceFinalEntry.nested = 2` | `bool` |
| `FinalEntry.text_hash` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:25` | `SurfaceFinalEntry.text_hash = 3` | `string` |
| `ResyncMetadata.schema` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:31` | `SurfaceResyncMetadata.schema = 1` | `string` |
| `ResyncMetadata.conversation_id` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:32` | `SurfaceResyncMetadata.conversation_id = 2` | `string` |
| `ResyncMetadata.version` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:33` | `SurfaceResyncMetadata.version = 3` | `uint64` |
| `ResyncMetadata.closed` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:34` | `SurfaceResyncMetadata.closed = 4` | `bool` |
| `ResyncMetadata.finality_base64` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:35` | `SurfaceResyncMetadata.finality_base64 = 5` | `string` |
#### Mapping source: `crates/ramflux-sdk/src/client/surface/resync_request.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `ResyncRequest.kind` | `crates/ramflux-sdk/src/client/surface/resync_request.rs:16` | `SurfaceResyncRequest.kind = 1` | `string` |
| `ResyncRequest.conversation_id` | `crates/ramflux-sdk/src/client/surface/resync_request.rs:17` | `SurfaceResyncRequest.conversation_id = 2` | `string` |
| `ResyncRequest.surface_ref` | `crates/ramflux-sdk/src/client/surface/resync_request.rs:18` | `SurfaceResyncRequest.surface_ref = 3` | `string` |
| `ResyncRequest.author` | `crates/ramflux-sdk/src/client/surface/resync_request.rs:19` | `SurfaceResyncRequest.author = 4` | `string` |
| `ResyncRequest.surface_id` | `crates/ramflux-sdk/src/client/surface/resync_request.rs:20` | `SurfaceResyncRequest.surface_id = 5` | `string` |
| `ResyncRequest.group` | `crates/ramflux-sdk/src/client/surface/resync_request.rs:21` | `SurfaceResyncRequest.group = 6` | `optional string` |
| `ResyncRequest.epoch` | `crates/ramflux-sdk/src/client/surface/resync_request.rs:22` | `SurfaceResyncRequest.epoch = 7` | `optional uint64` |
#### Mapping source: `crates/ramflux-sdk/src/client/recovery.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `SdkGuardianRecoveryShare.share_id` | `crates/ramflux-sdk/src/client/recovery.rs:34` | `GuardianRecoveryShare.share_id = 1` | `uint32` |
| `SdkGuardianRecoveryShare.threshold` | `crates/ramflux-sdk/src/client/recovery.rs:35` | `GuardianRecoveryShare.threshold = 2` | `uint32` |
| `SdkGuardianRecoveryShare.total` | `crates/ramflux-sdk/src/client/recovery.rs:36` | `GuardianRecoveryShare.total = 3` | `uint32` |
| `SdkGuardianRecoveryShare.member_kind` | `crates/ramflux-sdk/src/client/recovery.rs:37` | `GuardianRecoveryShare.member_kind = 4` | `RecoveryQuorumMemberKind` |
| `SdkGuardianRecoveryShare.value_base64` | `crates/ramflux-sdk/src/client/recovery.rs:38` | `GuardianRecoveryShare.value_base64 = 5` | `string` |
| `SdkGuardianInviteMessage.schema` | `crates/ramflux-sdk/src/client/recovery.rs:44` | `GuardianInvite.schema = 1` | `string` |
| `SdkGuardianInviteMessage.version` | `crates/ramflux-sdk/src/client/recovery.rs:45` | `GuardianInvite.version = 2` | `uint32` |
| `SdkGuardianInviteMessage.invite_id` | `crates/ramflux-sdk/src/client/recovery.rs:46` | `GuardianInvite.invite_id = 3` | `string` |
| `SdkGuardianInviteMessage.inviter_principal_id` | `crates/ramflux-sdk/src/client/recovery.rs:47` | `GuardianInvite.inviter_principal_id = 4` | `string` |
| `SdkGuardianInviteMessage.inviter_device_id` | `crates/ramflux-sdk/src/client/recovery.rs:48` | `GuardianInvite.inviter_device_id = 5` | `string` |
| `SdkGuardianInviteMessage.inviter_device_epoch` | `crates/ramflux-sdk/src/client/recovery.rs:49` | `GuardianInvite.inviter_device_epoch = 6` | `uint64` |
| `SdkGuardianInviteMessage.inviter_device_public_key_base64url` | `crates/ramflux-sdk/src/client/recovery.rs:50` | `GuardianInvite.inviter_device_public_key_base64url = 7` | `string` |
| `SdkGuardianInviteMessage.guardian_principal_id` | `crates/ramflux-sdk/src/client/recovery.rs:51` | `GuardianInvite.guardian_principal_id = 8` | `string` |
| `SdkGuardianInviteMessage.recovery_quorum_id` | `crates/ramflux-sdk/src/client/recovery.rs:52` | `GuardianInvite.recovery_quorum_id = 9` | `string` |
| `SdkGuardianInviteMessage.share` | `crates/ramflux-sdk/src/client/recovery.rs:53` | `GuardianInvite.share = 10` | `GuardianRecoveryShare` |
| `SdkGuardianInviteMessage.issued_at` | `crates/ramflux-sdk/src/client/recovery.rs:54` | `GuardianInvite.issued_at = 11` | `int64` |
| `SdkGuardianInviteMessage.expires_at` | `crates/ramflux-sdk/src/client/recovery.rs:55` | `GuardianInvite.expires_at = 12` | `int64` |
| `SdkGuardianInviteMessage.signed` | `crates/ramflux-sdk/src/client/recovery.rs:57` | `GuardianInvite.signed = 13` | `SignedFields` |
| `SdkGuardianAcceptMessage.schema` | `crates/ramflux-sdk/src/client/recovery.rs:63` | `GuardianAccept.schema = 1` | `string` |
| `SdkGuardianAcceptMessage.version` | `crates/ramflux-sdk/src/client/recovery.rs:64` | `GuardianAccept.version = 2` | `uint32` |
| `SdkGuardianAcceptMessage.accept_id` | `crates/ramflux-sdk/src/client/recovery.rs:65` | `GuardianAccept.accept_id = 3` | `string` |
| `SdkGuardianAcceptMessage.invite_id` | `crates/ramflux-sdk/src/client/recovery.rs:66` | `GuardianAccept.invite_id = 4` | `string` |
| `SdkGuardianAcceptMessage.owner_principal_id` | `crates/ramflux-sdk/src/client/recovery.rs:67` | `GuardianAccept.owner_principal_id = 5` | `string` |
| `SdkGuardianAcceptMessage.guardian_principal_id` | `crates/ramflux-sdk/src/client/recovery.rs:68` | `GuardianAccept.guardian_principal_id = 6` | `string` |
| `SdkGuardianAcceptMessage.guardian_device_id` | `crates/ramflux-sdk/src/client/recovery.rs:69` | `GuardianAccept.guardian_device_id = 7` | `string` |
| `SdkGuardianAcceptMessage.guardian_device_epoch` | `crates/ramflux-sdk/src/client/recovery.rs:70` | `GuardianAccept.guardian_device_epoch = 8` | `uint64` |
| `SdkGuardianAcceptMessage.guardian_device_public_key_base64url` | `crates/ramflux-sdk/src/client/recovery.rs:71` | `GuardianAccept.guardian_device_public_key_base64url = 9` | `string` |
| `SdkGuardianAcceptMessage.recovery_quorum_id` | `crates/ramflux-sdk/src/client/recovery.rs:72` | `GuardianAccept.recovery_quorum_id = 10` | `string` |
| `SdkGuardianAcceptMessage.accepted_at` | `crates/ramflux-sdk/src/client/recovery.rs:73` | `GuardianAccept.accepted_at = 11` | `int64` |
| `SdkGuardianAcceptMessage.signed` | `crates/ramflux-sdk/src/client/recovery.rs:75` | `GuardianAccept.signed = 12` | `SignedFields` |
#### Mapping source: `crates/ramflux-sdk/src/own_device_sync.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `SdkOwnDeviceGroupSnapshot.shared_state` | `crates/ramflux-sdk/src/own_device_sync.rs:91` | `SdkOwnDeviceGroupSnapshot.shared_state = 1` | `optional NativeGroupSnapshot` |
| `SdkOwnDeviceGroupSnapshot.group_id` | `crates/ramflux-sdk/src/own_device_sync.rs:92` | `SdkOwnDeviceGroupSnapshot.group_id = 2` | `string` |
| `SdkOwnDeviceGroupSnapshot.group_epoch` | `crates/ramflux-sdk/src/own_device_sync.rs:93` | `SdkOwnDeviceGroupSnapshot.group_epoch = 3` | `uint64` |
| `SdkOwnDeviceGroupSnapshot.max_members` | `crates/ramflux-sdk/src/own_device_sync.rs:94` | `SdkOwnDeviceGroupSnapshot.max_members = 4` | `uint32` |
| `SdkOwnDeviceGroupSnapshot.new_member_history` | `crates/ramflux-sdk/src/own_device_sync.rs:95` | `SdkOwnDeviceGroupSnapshot.new_member_history = 5` | `string` |
| `SdkOwnDeviceGroupSnapshot.local_role` | `crates/ramflux-sdk/src/own_device_sync.rs:96` | `SdkOwnDeviceGroupSnapshot.local_role = 6` | `string` |
| `SdkOwnDeviceGroupSnapshot.local_joined_epoch` | `crates/ramflux-sdk/src/own_device_sync.rs:97` | `SdkOwnDeviceGroupSnapshot.local_joined_epoch = 7` | `uint64` |
| `SdkOwnDeviceGroupSnapshot.members` | `crates/ramflux-sdk/src/own_device_sync.rs:98` | `SdkOwnDeviceGroupSnapshot.members = 8` | `repeated SdkOwnDeviceGroupMemberSnapshot` |
| `SdkOwnDeviceGroupSnapshot.routes` | `crates/ramflux-sdk/src/own_device_sync.rs:99` | `SdkOwnDeviceGroupSnapshot.routes = 9` | `repeated LocalBusGroupMemberRoute` |
| `SdkOwnDeviceGroupMemberPin.group_id` | `crates/ramflux-sdk/src/own_device_sync.rs:106` | `SdkOwnDeviceGroupMemberPin.group_id = 1` | `string` |
| `SdkOwnDeviceGroupMemberPin.device_id` | `crates/ramflux-sdk/src/own_device_sync.rs:107` | `SdkOwnDeviceGroupMemberPin.device_id = 2` | `string` |
| `SdkOwnDeviceGroupMemberPin.signing_public_key` | `crates/ramflux-sdk/src/own_device_sync.rs:108` | `SdkOwnDeviceGroupMemberPin.signing_public_key = 3` | `string` |
| `SdkOwnDeviceGroupMemberPin.principal_id` | `crates/ramflux-sdk/src/own_device_sync.rs:109` | `SdkOwnDeviceGroupMemberPin.principal_id = 4` | `optional string` |
| `SdkOwnDeviceGroupMemberPin.principal_commitment` | `crates/ramflux-sdk/src/own_device_sync.rs:110` | `SdkOwnDeviceGroupMemberPin.principal_commitment = 5` | `optional string` |
| `SdkOwnDeviceGroupMemberSnapshot.member_id` | `crates/ramflux-sdk/src/own_device_sync.rs:115` | `SdkOwnDeviceGroupMemberSnapshot.member_id = 1` | `string` |
| `SdkOwnDeviceGroupMemberSnapshot.role` | `crates/ramflux-sdk/src/own_device_sync.rs:116` | `SdkOwnDeviceGroupMemberSnapshot.role = 2` | `string` |
| `SdkOwnDeviceGroupMemberSnapshot.joined_epoch` | `crates/ramflux-sdk/src/own_device_sync.rs:117` | `SdkOwnDeviceGroupMemberSnapshot.joined_epoch = 3` | `uint64` |
#### Mapping source: `crates/ramflux-sdk/src/bus/protocol.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `LocalBusGroupMemberRoute.member_id` | `crates/ramflux-sdk/src/bus/protocol.rs:647` | `LocalBusGroupMemberRoute.member_id = 1` | `string` |
| `LocalBusGroupMemberRoute.member_principal_commitment` | `crates/ramflux-sdk/src/bus/protocol.rs:649` | `LocalBusGroupMemberRoute.member_principal_commitment = 2` | `optional string` |
| `LocalBusGroupMemberRoute.device_signing_public_key` | `crates/ramflux-sdk/src/bus/protocol.rs:651` | `LocalBusGroupMemberRoute.device_signing_public_key = 3` | `optional string` |
| `LocalBusGroupMemberRoute.target_delivery_id` | `crates/ramflux-sdk/src/bus/protocol.rs:653` | `LocalBusGroupMemberRoute.target_delivery_id = 4` | `optional string` |
| `LocalBusGroupMemberRoute.federation` | `crates/ramflux-sdk/src/bus/protocol.rs:655` | `LocalBusGroupMemberRoute.federation = 5` | `optional LocalBusFederationRoute` |
#### Mapping source: `crates/ramflux-sdk/src/group.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `SdkGroupSenderKeyDistribution.schema` | `crates/ramflux-sdk/src/group.rs:10` | `GroupKeyDistribution.schema = 1` | `string` |
| `SdkGroupSenderKeyDistribution.version` | `crates/ramflux-sdk/src/group.rs:11` | `GroupKeyDistribution.version = 2` | `uint32` |
| `SdkGroupSenderKeyDistribution.group_id` | `crates/ramflux-sdk/src/group.rs:12` | `GroupKeyDistribution.group_id = 3` | `string` |
| `SdkGroupSenderKeyDistribution.sender_id` | `crates/ramflux-sdk/src/group.rs:13` | `GroupKeyDistribution.sender_id = 4` | `string` |
| `SdkGroupSenderKeyDistribution.group_key_epoch` | `crates/ramflux-sdk/src/group.rs:14` | `GroupKeyDistribution.group_key_epoch = 5` | `uint64` |
| `SdkGroupSenderKeyDistribution.group_state_hash` | `crates/ramflux-sdk/src/group.rs:16` | `GroupKeyDistribution.group_state_hash = 6` | `optional string` |
| `SdkGroupSenderKeyDistribution.sender_key_seed` | `crates/ramflux-sdk/src/group.rs:17` | `GroupKeyDistribution.sender_key_seed = 7` | `bytes` |
| `SdkGroupSenderKeyDistribution.sender_key_signature` | `crates/ramflux-sdk/src/group.rs:19` | `GroupKeyDistribution.sender_key_signature = 8` | `optional string` |
| `SdkGroupSenderKeyDistribution.sender_device_signing_public_key` | `crates/ramflux-sdk/src/group.rs:21` | `GroupKeyDistribution.sender_device_signing_public_key = 9` | `optional string` |
| `SdkGroupSenderKeyDistributionEnvelope.schema` | `crates/ramflux-sdk/src/group.rs:26` | `GroupKeyControl.schema = 1` | `string` |
| `SdkGroupSenderKeyDistributionEnvelope.version` | `crates/ramflux-sdk/src/group.rs:27` | `GroupKeyControl.version = 2` | `uint32` |
| `SdkGroupSenderKeyDistributionEnvelope.membership_event_base64` | `crates/ramflux-sdk/src/group.rs:29` | `GroupKeyControl.membership_event = 3` | `NativeGroupEvent` |
| `SdkGroupSenderKeyDistributionEnvelope.actor_manifest_url` | `crates/ramflux-sdk/src/group.rs:31` | `GroupKeyControl.actor_manifest_url = 4` | `optional string` |
| `SdkGroupSenderKeyDistributionEnvelope.distribution_base64` | `crates/ramflux-sdk/src/group.rs:32` | `GroupKeyControl.distribution = 5` | `GroupKeyDistribution` |
#### Mapping source: `crates/ramflux-sdk/src/client/surface/own_history.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `SurfaceExportMetadata.truncated` | `crates/ramflux-sdk/src/client/surface/own_history.rs:12` | `SurfaceExportMetadata.truncated = 1` | `bool` |
| `SurfaceExportMetadata.next_before` | `crates/ramflux-sdk/src/client/surface/own_history.rs:13` | `SurfaceExportMetadata.next_before = 2` | `optional int64` |
| `SurfaceExportMetadata.skipped` | `crates/ramflux-sdk/src/client/surface/own_history.rs:14` | `SurfaceExportMetadata.skipped = 3` | `map<string, uint32>` |
| `SurfaceHistoryExport.controls` | `crates/ramflux-sdk/src/client/surface/own_history.rs:18` | `SurfaceHistoryExport.controls = 1` | `repeated SurfaceDelivery` |
| `SurfaceHistoryExport.checkpoints` | `crates/ramflux-sdk/src/client/surface/own_history.rs:19` | `SurfaceHistoryExport.checkpoints = 2` | `repeated OwnedSurfaceCheckpoint` |
| `SurfaceHistoryExport.metadata` | `crates/ramflux-sdk/src/client/surface/own_history.rs:20` | `SurfaceHistoryExport.metadata = 3` | `SurfaceExportMetadata` |
#### Mapping source: `crates/ramflux-sdk/src/client/surface/own_checkpoint.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `OwnedSurfaceCheckpoint.record` | `crates/ramflux-sdk/src/client/surface/own_checkpoint.rs:13` | `OwnedSurfaceCheckpoint.record = 1` | `StoredSurface` |
| `OwnedSurfaceCheckpoint.snapshot_wire_base64` | `crates/ramflux-sdk/src/client/surface/own_checkpoint.rs:14` | `OwnedSurfaceCheckpoint.snapshot_event = 2` | `SurfaceEvent` |
| `OwnedSurfaceCheckpoint.version` | `crates/ramflux-sdk/src/client/surface/own_checkpoint.rs:15` | `OwnedSurfaceCheckpoint.version = 3` | `uint64` |
| `OwnedSurfaceCheckpoint.surface_hash` | `crates/ramflux-sdk/src/client/surface/own_checkpoint.rs:16` | `OwnedSurfaceCheckpoint.surface_hash = 4` | `string` |
| `OwnedSurfaceCheckpoint.conversation` | `crates/ramflux-sdk/src/client/surface/own_checkpoint.rs:17` | `OwnedSurfaceCheckpoint.conversation = 5` | `JsonValue` |
| `OwnedSurfaceCheckpoint.group_epoch` | `crates/ramflux-sdk/src/client/surface/own_checkpoint.rs:18` | `OwnedSurfaceCheckpoint.group_epoch = 6` | `optional uint64` |
#### Mapping source: `crates/ramflux-sdk/src/client/surface/mod.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `StoredSurface.surface_id` | `crates/ramflux-sdk/src/client/surface/mod.rs:39` | `StoredSurface.surface_id = 1` | `string` |
| `StoredSurface.conversation_id` | `crates/ramflux-sdk/src/client/surface/mod.rs:40` | `StoredSurface.conversation_id = 2` | `string` |
| `StoredSurface.author_principal_id` | `crates/ramflux-sdk/src/client/surface/mod.rs:41` | `StoredSurface.author_principal_id = 3` | `string` |
| `StoredSurface.author_device_id` | `crates/ramflux-sdk/src/client/surface/mod.rs:42` | `StoredSurface.author_device_id = 4` | `string` |
| `StoredSurface.checkpoint_base64` | `crates/ramflux-sdk/src/client/surface/mod.rs:43` | `StoredSurface.checkpoint = 5` | `SurfaceCheckpoint` |
| `StoredSurface.created_at` | `crates/ramflux-sdk/src/client/surface/mod.rs:45` | `StoredSurface.created_at = 6` | `optional int64` |
| `StoredSurface.updated_at` | `crates/ramflux-sdk/src/client/surface/mod.rs:47` | `StoredSurface.updated_at = 7` | `optional int64` |
#### Mapping source: `crates/ramflux-sdk/src/client/task/own_history.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `TaskExportMetadata.truncated` | `crates/ramflux-sdk/src/client/task/own_history.rs:14` | `TaskExportMetadata.truncated = 1` | `bool` |
| `TaskExportMetadata.skipped_items` | `crates/ramflux-sdk/src/client/task/own_history.rs:15` | `TaskExportMetadata.skipped_items = 2` | `uint32` |
| `TaskExportMetadata.next_cursor` | `crates/ramflux-sdk/src/client/task/own_history.rs:16` | `TaskExportMetadata.next_cursor = 3` | `optional string` |
#### Mapping source: `crates/ramflux-sdk/src/prekey/manifest.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `SdkDeviceManifestResponse.custody` | `crates/ramflux-sdk/src/prekey/manifest.rs:40` | `NativeDeviceManifest.custody = 1` | `optional NativeCustodyManifest` |
| `SdkDeviceManifestResponse.signed_device_set` | `crates/ramflux-sdk/src/prekey/manifest.rs:42` | `NativeDeviceManifest.signed_device_set = 2` | `optional NativeSignedDeviceSet` |
| `SdkDeviceManifestResponse.principal_id` | `crates/ramflux-sdk/src/prekey/manifest.rs:43` | `NativeDeviceManifest.principal_id = 3` | `string` |
| `SdkDeviceManifestResponse.principal_commitment` | `crates/ramflux-sdk/src/prekey/manifest.rs:44` | `NativeDeviceManifest.principal_commitment = 4` | `string` |
| `SdkDeviceManifestResponse.root_public_key` | `crates/ramflux-sdk/src/prekey/manifest.rs:45` | `NativeDeviceManifest.root_public_key = 5` | `string` |
| `SdkDeviceManifestResponse.devices` | `crates/ramflux-sdk/src/prekey/manifest.rs:46` | `NativeDeviceManifest.devices = 6` | `repeated ManifestDevice` |
| `SdkDeviceManifestEntry.principal_id` | `crates/ramflux-sdk/src/prekey/manifest.rs:13` | `ManifestDevice.principal_id = 1` | `string` |
| `SdkDeviceManifestEntry.principal_commitment` | `crates/ramflux-sdk/src/prekey/manifest.rs:14` | `ManifestDevice.principal_commitment = 2` | `string` |
| `SdkDeviceManifestEntry.device_id` | `crates/ramflux-sdk/src/prekey/manifest.rs:15` | `ManifestDevice.device_id = 3` | `string` |
| `SdkDeviceManifestEntry.device_epoch` | `crates/ramflux-sdk/src/prekey/manifest.rs:16` | `ManifestDevice.device_epoch = 4` | `uint64` |
| `SdkDeviceManifestEntry.branch_public_key` | `crates/ramflux-sdk/src/prekey/manifest.rs:17` | `ManifestDevice.branch_public_key = 5` | `string` |
| `SdkDeviceManifestEntry.target_delivery_id` | `crates/ramflux-sdk/src/prekey/manifest.rs:18` | `ManifestDevice.target_delivery_id = 6` | `string` |
| `SdkDeviceManifestEntry.branch_proof` | `crates/ramflux-sdk/src/prekey/manifest.rs:20` | `ManifestDevice.branch_proof = 7` | `optional NativeBranchProof` |
| `SdkDeviceManifestEntry.prekey_bundle` | `crates/ramflux-sdk/src/prekey/manifest.rs:21` | `ManifestDevice.prekey_bundle = 8` | `NativePrekeyBundle` |
| `SdkDeviceManifestEntry.branch_authorized_event_id` | `crates/ramflux-sdk/src/prekey/manifest.rs:22` | `ManifestDevice.branch_authorized_event_id = 9` | `string` |
#### Mapping source: `crates/ramflux-protocol/src/core_types.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `SignatureAlg::Ed25519` | `crates/ramflux-protocol/src/core_types.rs:20` | `SignatureAlg.ed25519 = 1` | `SignatureAlgEd25519 (empty)` |
#### Mapping source: `crates/ramflux-storage/src/records/friend.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `FriendLinkRecord.link_id` | `crates/ramflux-storage/src/records/friend.rs:8` | `FriendLinkRecord.link_id = 1` | `string` |
| `FriendLinkRecord.requester_id` | `crates/ramflux-storage/src/records/friend.rs:9` | `FriendLinkRecord.requester_id = 2` | `string` |
| `FriendLinkRecord.target_id` | `crates/ramflux-storage/src/records/friend.rs:10` | `FriendLinkRecord.target_id = 3` | `string` |
| `FriendLinkRecord.state` | `crates/ramflux-storage/src/records/friend.rs:11` | `FriendLinkRecord.state = 4` | `string` |
| `FriendLinkRecord.remove_scope` | `crates/ramflux-storage/src/records/friend.rs:13` | `FriendLinkRecord.remove_scope = 5` | `optional string` |
| `FriendLinkRecord.blocked` | `crates/ramflux-storage/src/records/friend.rs:15` | `FriendLinkRecord.blocked = 6` | `bool` |
| `FriendLinkRecord.capability_revoked_at` | `crates/ramflux-storage/src/records/friend.rs:17` | `FriendLinkRecord.capability_revoked_at = 7` | `optional int64` |
#### Mapping source: `crates/ramflux-protocol/src/surfaces.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `McpCapability::ReadConversation` | `crates/ramflux-protocol/src/surfaces.rs:297` | `McpCapability.read_conversation = 1` | `McpCapabilityReadConversation (empty)` |
| `McpCapability::DraftMessage` | `crates/ramflux-protocol/src/surfaces.rs:298` | `McpCapability.draft_message = 2` | `McpCapabilityDraftMessage (empty)` |
| `McpCapability::SendMessage` | `crates/ramflux-protocol/src/surfaces.rs:299` | `McpCapability.send_message = 3` | `McpCapabilitySendMessage (empty)` |
| `McpCapability::ReadLocalFiles` | `crates/ramflux-protocol/src/surfaces.rs:300` | `McpCapability.read_local_files = 4` | `McpCapabilityReadLocalFiles (empty)` |
| `McpCapability::WriteLocalFiles` | `crates/ramflux-protocol/src/surfaces.rs:301` | `McpCapability.write_local_files = 5` | `McpCapabilityWriteLocalFiles (empty)` |
| `McpCapability::RunShell` | `crates/ramflux-protocol/src/surfaces.rs:302` | `McpCapability.run_shell = 6` | `McpCapabilityRunShell (empty)` |
| `McpCapability::ManageContacts` | `crates/ramflux-protocol/src/surfaces.rs:303` | `McpCapability.manage_contacts = 7` | `McpCapabilityManageContacts (empty)` |
| `McpCapability::ManageGroup` | `crates/ramflux-protocol/src/surfaces.rs:304` | `McpCapability.manage_group = 8` | `McpCapabilityManageGroup (empty)` |
| `McpCapability::ManageMedia` | `crates/ramflux-protocol/src/surfaces.rs:305` | `McpCapability.manage_media = 9` | `McpCapabilityManageMedia (empty)` |
| `McpCapability::ManageNode` | `crates/ramflux-protocol/src/surfaces.rs:306` | `McpCapability.manage_node = 10` | `McpCapabilityManageNode (empty)` |
| `McpCapability::ExternalToolInvoke` | `crates/ramflux-protocol/src/surfaces.rs:307` | `McpCapability.external_tool_invoke = 11` | `McpCapabilityExternalToolInvoke (empty)` |
| `RiskLevel::Low` | `crates/ramflux-protocol/src/surfaces.rs:288` | `RiskLevel.low = 1` | `RiskLevelLow (empty)` |
| `RiskLevel::Medium` | `crates/ramflux-protocol/src/surfaces.rs:289` | `RiskLevel.medium = 2` | `RiskLevelMedium (empty)` |
| `RiskLevel::High` | `crates/ramflux-protocol/src/surfaces.rs:290` | `RiskLevel.high = 3` | `RiskLevelHigh (empty)` |
| `RiskLevel::Critical` | `crates/ramflux-protocol/src/surfaces.rs:291` | `RiskLevel.critical = 4` | `RiskLevelCritical (empty)` |
#### Mapping source: `crates/ramflux-protocol/src/events.rs`

| Live field / variant | Baseline source | Proto field / tag | Proto type / nested fields |
|---|---|---|---|
| `RecoveryQuorumMemberKind::RootShare` | `crates/ramflux-protocol/src/events.rs:12` | `RecoveryQuorumMemberKind.root_share = 1` | `RecoveryQuorumMemberKindRootShare (empty)` |
| `RecoveryQuorumMemberKind::DeviceShare` | `crates/ramflux-protocol/src/events.rs:13` | `RecoveryQuorumMemberKind.device_share = 2` | `RecoveryQuorumMemberKindDeviceShare (empty)` |
| `RecoveryQuorumMemberKind::GuardianShare` | `crates/ramflux-protocol/src/events.rs:14` | `RecoveryQuorumMemberKind.guardian_share = 3` | `RecoveryQuorumMemberKindGuardianShare (empty)` |
| `RecoveryQuorumMemberKind::HardwareTokenShare` | `crates/ramflux-protocol/src/events.rs:15` | `RecoveryQuorumMemberKind.hardware_token_share = 4` | `RecoveryQuorumMemberKindHardwareTokenShare (empty)` |

| Live carrier field | Baseline source | Proto selection | Typed replacement |
|---|---|---|---|
| `Carrier.payload_kind` | `crates/ramflux-sdk/src/client/surface/carrier.rs:26` | `SurfaceCarrier.payload: event=16 / action=17 / action_receipt=18` | Exactly one typed arm |
| `Carrier.wire_base64` | `crates/ramflux-sdk/src/client/surface/carrier.rs:33` | `SurfaceCarrier.event / action / action_receipt` | SurfaceEvent / SurfaceAction / original SurfaceCarrier; decoded from former base64 transport |

No live business field is declared obsolete. The following exclusions are
explicit local-only state, not silent wire deletions:

| Local field | Baseline source | Disposition |
|---|---|---|
| `Packet.local_expires_at` | `crates/ramflux-sdk/src/client/task/approval.rs:35` | Receiver-local retention deadline; bytes() always clears it. Reserve tag 5; never trust a peer deadline. |
| `TaskHistory.checkpoint` | `crates/ramflux-sdk/src/client/task/mod.rs:51` | Local-only #[serde(skip)] checkpoint; never exported in TaskOwnPacket. |

SurfaceCarrier's former payload_kind and wire_base64 are represented together
by event=16, action=17 or action_receipt=18. An action_receipt recursively holds
the original **action** carrier only; bound recursion to one receipt level and
verify the creator receipt plus original requester signature. Snapshot proof
checkpoint/finality and all six commands/five patch operations remain typed.
Surface.own_history=18
preserves SurfaceHistoryExport, OwnedSurfaceCheckpoint and export omission/cursor
metadata. Task.own_history=19 preserves TaskHistoryExport packets plus typed
TaskExportMetadata (truncated/skipped_items/next_cursor).
SurfaceResyncRequest.kind retains the fixed legacy discriminator as data to
validate, never a dispatch key. New wire dispatch is Surface.resync_request=17;
its reply is the author-signed Surface.delivery snapshot, not a seventh command.
TaskCarrier.decision_proof presence remains optional by message presence.
TaskHistory.checkpoint is local-only and TaskApprovalPacket.local_expires_at is
always cleared by the live egress builder; their reasons are listed above.
CallControl has all thirteen CallAction arms and exact native lease fields.
VoiceAllocation token/rebind_key/side never crossed peer CallControl: they stay
in the authenticated gateway VoiceLeaseResponse, outside this Inner schema.
There is no ICE or codec negotiation in the live relay call signaling contract.

### 3.2 Control constructor and native-codec registry

Every ControlOperation is layer 1 and has exactly the generated payload below.
The two additional live families A2I and object revocation are explicit, as are
all four group control variants. Native validation precedes side effects and
Unsupported storage; a wrapper never makes unverified native bytes authoritative.

| ControlOperation number/name | Control oneof field/tag/type | Live mapping / fixed validation |
|---|---|---|
| 1 CONTROL_PAIR_RESET | `reset = 16: PairReset` | pair.session.reset.v1; rejected_bootstrap_floor; routed/reset_work.rs |
| 2 CONTROL_PAIR_RESET_ACK | `reset_ack = 17: PairResetAck` | pair.session.reset.ack.v1; floor=0 in current sender |
| 3 CONTROL_CONTACT | `contact_control = 18: ContactControl` | NativeContactConsent = custody::Envelope<ContactConsentV2>; native first-contact path; legacy root JSON consent is retired on v3 reset |
| 4 CONTROL_GROUP_STATE | `group_state = 19: GroupStateControl` | GroupControlBody request=1/result=2/device_set=3/transfer=4; tables above include federation route, beacon epoch and Transfer Probe/Head |
| 5 CONTROL_GROUP_KEY | `group_key_control = 20: GroupKeyControl` | GroupKeyControl and GroupKeyDistribution mirror SDK v4 distribution, typed membership event, manifest URL and seed/signature bindings |
| 6 CONTROL_OWN_CONTACT | `own_contact_sync = 21: OwnContactSync` | Contact manifest + full FriendLinkRecord; same-root import |
| 7 CONTROL_OWN_HISTORY | `own_history = 22: HistoryPage` | Registered exact Inner pages plus origin evidence; old bundle fields mapped in section 8 |
| 8 CONTROL_HOME_MIGRATION | `home_migration = 23: HomeMigrationControl` | NativeHomeAuthorization = protocol::home_migration::Signed<Authorization>; reserved typed application handoff, no current Inner producer |
| 9 CONTROL_RECOVERY | `recovery_control = 24: RecoveryControl` | GuardianInvite/GuardianAccept, including secret share and all signer fields in section 3.1 |
| 10 CONTROL_LIVE_PRESENCE | `live_presence = 25: LivePresence` | Planned epoch/subjects; ephemeral only; not a live producer claim |
| 11 CONTROL_A2I | `a2i = 26: A2iControlEvent` | All fields plus Message/Conversation/A2ui/McpTool domain oneof; signed provenance retained |
| 12 CONTROL_OBJECT_REVOKE | `object_revoke = 27: ObjectRevokeAccess` | object.revoke_access object/recipient/link/reason/effective_at; verify sender owns received reference |
| 13 CONTROL_OWN_CONTACT_TOMBSTONE | `own_contact_tombstone = 28: OwnContactTombstone` | Sticky FriendLinkRecord restriction with decided_at |
| 14 CONTROL_OWN_GROUP_CONSENT | `own_group_consent = 29: OwnGroupConsent` | Same-root signed actor/snapshot/acceptance/issued_at/expires_at |
| 15 CONTROL_OWN_MESSAGE_COPY | `own_message_copy = 30: OwnMessageCopy` | Original exact Inner + source/target/times; authenticated same-root copy replaces private wrapper/key slots |
| 16 CONTROL_FRIEND | `friend = 31: FriendControl` | friend.requested/accepted/removed/blocked/unblocked; all link fields and scope preserved |

Native codecs are named, single-type adapters, not open application payloads:
NativeDeviceManifest mirrors every SDK manifest response field; its
CustodyManifest, SignedDeviceSetRecord, PrekeyBundle and BranchProofDocument
proof leaves use fixed Native* canonical codecs and native custody validation. NativeGroupActor, NativeGroupSnapshot,
NativeGroupChangeRequest, NativeGroupChangeResult and
NativeGroupTransferAcceptance keep their protocol group_state canonical JSON
and signature grammar. The typed GroupControlBody and TransferControl select
which adapter is used before inspecting those bytes. NativeContactConsent uses
its protocol canonical JSON codec. NativeGroupEvent is the existing signed
protocol GroupEvent; GroupKeyDistribution
is fully typed above, never a generic native blob. NativeHomeAuthorization is
Signed<home_migration::Authorization>, with the existing canonical signed codec;
its application handoff is planned, not a claimed live peer message producer.
All enforce their current native limits plus the aggregate envelope cap. No
schema string is used to choose a codec. A future independently owned native
revision requires a new named field/layer, never an in-place reinterpretation.
Section 8 lists sources and retirement of obsolete app wrappers around them.

The fixed proof codec authorities (all at the baseline SHA) are:

| Generated proof leaf | Fixed native type / source | Allowed codec |
|---|---|---|
| NativeCustodyManifest | CustodyManifest, `crates/ramflux-protocol/src/custody/network.rs:144` | Native custody canonical JSON + verified publication/authority |
| NativeSignedDeviceSet | SignedDeviceSetRecord, `crates/ramflux-protocol/src/identity_keys.rs:44` | Existing signed device-set canonical JSON; native admission rejects legacy authority |
| NativePrekeyBundle | PrekeyBundle, `crates/ramflux-crypto/src/prekey.rs:52` | Existing crypto prekey codec; DM-FS revision/retirement remains that owner's work |
| NativeBranchProof | BranchProofDocument, `crates/ramflux-crypto/src/identity.rs:80` | Existing signed branch-proof codec; no legacy-authority fallback |
| NativeGroupActor | GroupStateActor, `crates/ramflux-protocol/src/group_state.rs:90` | Native group canonical JSON/proof grammar |
| NativeGroupSnapshot | GroupStateSnapshot, `crates/ramflux-protocol/src/group_state.rs:149` | Native signed group snapshot codec |
| NativeGroupChangeRequest | GroupChangeRequest, `crates/ramflux-protocol/src/group_state.rs:166` | Native signed group request codec |
| NativeGroupChangeResult | GroupChangeResult, `crates/ramflux-protocol/src/group_state.rs:191` | Native signed group result codec |
| NativeGroupTransferAcceptance | GroupTransferAcceptance, `crates/ramflux-protocol/src/group_state.rs:122` | Native signed group transfer acceptance codec |
| NativeContactConsent | custody::Envelope<ContactConsentV2>, `crates/ramflux-protocol/src/custody/contact.rs:21` | Native custody envelope codec; exact type already selected |
| NativeGroupEvent | protocol::GroupEvent uses GroupEventBody, `crates/ramflux-protocol/src/events.rs:208` | Existing signed native membership event, not arbitrary application bytes |
| NativeHomeAuthorization | home_migration::Signed<Authorization>, `crates/ramflux-protocol/src/home_migration/messages.rs:184` | Existing home migration signed canonical codec; planned handoff |

These proof codecs are outside S0's application-field numbering. They never
contain an SDK application carrier; the owning native validator rejects a wrong
type/schema, unknown native field or bad signature before any application action.
HistoryItem.exact_inner is the explicit raw-retention exception. Its typed
source_evidence is HistoryOriginEvidence: canonical_sender_envelope is exactly
the independently sender-signed outer-envelope JCS codec in section 6; the other
fields select native custody/group proof codecs above. The importer verifies the
original source, membership and copy binding before retaining/reparsing Inner.
There is no arbitrary proof-bundle decoder or replacement application body.
All new application controls and their variant numbering are concrete above.

For every sub-operation listed in section 3.1/3.2: first layer=1, outer class is
message/durable except CallAction.Invite→call_wake, and LivePresence→ephemeral.
Below layer 1 refuse locally with PeerUpgradeRequired, never executable text.
All S10b clients support every one of these operations at mandatory floor 3.
Unknown future operations require a new layer and Unsupported/raw retention;
known operations keep current role, authorization, signature and size checks.
S12 uses these same generated fields; S10c renders only the public projection.
Section 4.1 and 10.1 incorporate this per-operation registry by reference.

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
| 3 | Edit | 2 | Below admitted F: require client upgrade at admission; never replace a typed Edit with text at an admitted floor | S11 generic wake; S12 Edit request/update |
| 4 | Delete | 2 | Below admitted F: require client upgrade at admission; never refuse a typed Delete because a declaration expired | S9 last-owner erase; S11 generic wake; S12 Delete |
| 5 | Reaction | 2 | New Message text describing the reaction and target; no fabricated reaction state | S11 generic wake; S12 Reaction |
| 6 | Receipt | 1 | Local PeerUpgradeRequired; never infer a receipt from transport ACK | S11 wake policy; S12 typed receipt |
| 7 | Typing | 2 | Suppress transmission; it must not become durable text | S6 ephemeral path; S11 no push; S12 transient update |
| 8 | Control | 1 | Local PeerUpgradeRequired; no text substitute for authenticated commands | S6 mode validation; S11 generic wake; S12 control update |
| 9 | Surface | 1 | Local PeerUpgradeRequired for the authenticated operation | S11 generic wake; S12 generated surface state |
| 10 | Task | 1 | Local PeerUpgradeRequired for the authenticated operation | S11 generic wake; S12 generated task state |
| 11 | Call | 1 | Refuse invite with PeerUpgradeRequired | S11 call_wake for Invite; S12 CallControl and all 13 actions |
| 12 | SelfSync | 1 | Local PeerUpgradeRequired; never apply a text surrogate to own state | S11 generic wake; S12 read/draft/pin/mute |

| Declaration / scope | Selected layer | Profile floor | Downgrade behavior | Isolation |
|---|---|---|---|---|
| Missing/expired declaration (all kinds) | Per-target F | F=2 in S10a, F=3 after S10b | Encode that target at F using the rows above; never LayerUnavailable, never lower a whole fan-out | Preserve every fresh-cohort target at its negotiated minimum; original logical identity is shared |

The per-operation registry in sections 3.1/3.2 is part of this downgrade/consumer
table: every Surface command/receipt/resync, Task event/approval/control/history,
Call action and Control payload has layer 1 and the stated refusal below it.

Layer 1 also contains Message.sealed_group (field 16). This replaces the SDK
sender-key JSON wrapper, not the reviewed group encryption primitive. Encode a
group Message without sealed_group as protobuf, encrypt it with the existing
authorized sender-key state, fill GroupSealedContent, then pair-seal that typed
Message for each recipient. A sealed_group Message cannot also carry text,
entities, reply, forward or media; its decrypted Message cannot recursively
contain sealed_group. Group metadata and the existing group crypto header thus
remain inside the pair AEAD. The current producer is
`crates/ramflux-sdk/src/client/group_session.rs:617`; its old struct is
`crates/ramflux-sdk/src/group.rs:50`. Canonical_crypto_header is the crypto-owned
canonical header, not an SDK JSON blob. Author/epoch/state hash and original
native evidence must verify against the current group access contract; pair
contact consent is not newly required for authorized non-contact group members.
Unknown nested group content retains both exact outer Inner and exact verified
decrypted group Message, registered and charged to the same raw-byte quota.
Reparse uses the retained verified bytes without retaining a sender-key secret.
A group report additionally needs the existing per-message group opening and
native author evidence to verify the rendered plaintext; never disclose a group
master key. A receipt over group ciphertext alone proves no claimed excerpt.

Reaction.token is exactly one extended grapheme cluster (Unicode UAX #29),
1..64 UTF-8 bytes, with no controls or whitespace-only value. Both add and remove
validate the same token without normalization; no unbounded multi-emoji string.

Entity offsets and lengths are **Unicode scalar values**. Validate UTF-8 once,
construct a scalar-to-byte index once, then validate at most 4,096 ranges in
linear work. Only Web/iOS adapters translate to UTF-16 code units. For example
`A😀é` has scalar offsets 0,1,2 and UTF-16 offsets 0,1,3. An unrecognized Entity.kind number makes the whole message Unsupported, preserving exact bytes.
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
| Fresh native device | Admit native identity and pin authority; publish signed max_layer when available | No declaration still permits F messaging; publication enables above-floor selection |
| DM send | Fresh cohort uses min(source support, all fresh target maxima); a missing/expired target independently uses F | Declaration absence/expiry NEVER yields LayerUnavailable; reject forged statements without resetting pins |
| Own-device send/history | Same fresh-cohort rule; each missing/expired sibling receives F only for itself | Same-root authorization, provenance and erasure fences remain mandatory |
| Group send | Snapshot signed membership/epochs; negotiate fresh-cohort minimum and separate F representations only for missing/expired members | Recheck membership; same logical event, separate sender-key counters/ciphertexts per representation; never downgrade the whole group for a stale member |
| Membership/declaration changes before submit | Discard affected unsubmitted representation and rebuild its target/cohort assignment | No accepted envelope is silently rewritten; never reuse variant ciphertext counters |
| Membership changes after accepted submission | Historical packet stays under its authenticated epoch; additions receive authorized later history/copies | Existing history floors, removal and revocation fences still govern access |
| Incoming layer above compiled receive maximum | Retain Unsupported and exact Inner transactionally, then ACK | UI placeholder; upgrade then bounded local reparse; own declaration expiry never lowers decoding |
| Own declaration absent/expired on send | Use target selection max(F, target last valid declaration), compiled/cohort bounded | Republish on next connection; own freshness never lowers all targets |
| Own declaration absent/expired on receive | Decode and execute through compiled maximum | Apply queued supported Delete/Edit immediately; no publication prerequisite |
| Legitimate application rollback | Higher-sequence signed lower maximum >=F, endorsed by newer native head | Reject older/equal-conflicting sequences/heads; compiled support bounds advertising |
| Lost holder / expired declaration | Continue floor sends; refresh only to restore above-floor selection | Unlock or attended recovery/enrollment restores signing/publication; layer freshness never blocks delivery |
| Restore / own-history import | Saved declarations are historical only; refresh native authority/floors | Never import stale archive capability as live; F remains available |

Structural controls never become vaguely equivalent text. All kinds defined
here execute at F=2 in S10a and F=3 after S10b, including Delete/Edit/Reaction
and ephemeral Typing. Missing declarations themselves never refuse a send.
Future above-floor kinds/fields need an explicit safe downgrade or refusal;
no admitted floor representation refuses Delete or replaces Edit with text.
A genuinely incompatible client below deployed F requires upgrade at admission;
this is distinct from a client whose declaration expired. No message-layer
fallback permits clear ratchet headers or revived revoked authority.

## 5. Cryptographic framing, header encryption and padding

### 5.1 Exact plaintext and associated data

Encode one Inner once and preserve those bytes. The body plaintext is:

`u32_be(inner_length) || exact_inner || kf[32] || zero_padding`.

Let L = 4 + inner_length + 32. The individual minimum is Padme(max(L,256));
fan-out uses the common ciphertext target defined in section 5.5. This separates
protobuf
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
packet. Public E and the format byte remain observable; standalone bootstrap size
is larger, while copies of one event share the section 5.5 ciphertext length.

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

For copies of one logical event, serialize every target representation before
sealing, including fresh-cohort, floor, group wrapper and own-device copies.
For copy i let L_i be its framed plaintext length, H_i its exact CryptoBox
overhead (including any bootstrap capsule), and P_i = Padme(max(L_i,256)).
Choose the largest total bucket B = max_i(H_i + P_i). Every copy appends
authenticated zero tail until its plaintext length is B - H_i, so every binary
encrypted_payload (and its base64 encoding) has the same length B. This applies
also across established/bootstrap formats; the public format/E remain visible.
A single copy retains the original Padme sizing and vectors. A receiver accepts
zero tails with length at least its individual P_i through the 512 KiB cap; it
cannot reconstruct the private fan-out and must not require its own minimal
bucket exactly. Recompute the common target when unsubmitted membership or
representations change. Do not expose real ciphertext until every copy passes
its plaintext, final-frame and transport cap; overflow rejects the whole event
with PayloadTooLarge, never sends a smaller stale-target copy or partially
commits ratchet state. Retries retain the accepted event's common size target.
The <=12% calculation below describes each individual Padme minimum, not cover
padding added to smaller representations; equalization can cost more than 12%
for those copies. S11 still measures the final padded provider payload.

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
| delivery_mode | S10a adds required named field, replacing the signed ext.delivery_mode bridge | durable or generic ephemeral; transient classification is an admitted leak; new profile rejects bridge/dual-field input |
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
`crates/ramflux-node-core/src/notify.rs:1851`, collapse at
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
NotificationDeliveryClass's old task/surface/self distinctions collapse
to generic message notification. A group-call/conference invitation that needs
VoIP wake MUST use call_wake too; mapping ConferenceWakeNotification to message
is forbidden. This class rule does not introduce a conference media protocol: the
live CallControl contract is one-to-one; later conference signaling must define
its own reviewed schema/layer before it can produce invites. Native prekey,
custody, relay and federation service RPCs are outside this client-envelope enum.

## 7. Metadata leaks before and after

| Observable | Before (measured baseline) | After the final profile |
|---|---|---|
| Size | Exact serialized body size; no padding | Padme bucket plus 256-byte minimum; total size still reveals buckets and attachments; bootstrap format/E remain visible |
| Per-device declaration freshness | S10a fresh/floor representations can differ in size, exposing stale or long-offline targets | From S10b every copy of one event uses the largest common ciphertext bucket, masking freshness by copy length; pre-S10b size signal is a residual |
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
| MessageEventBody | `crates/ramflux-protocol/src/events.rs:445` | Remove unused parallel event family; Message/Edit/Delete/Reaction/Message.media/Forward map to generated kinds; S10a |
| ConversationEventBody | `crates/ramflux-protocol/src/events.rs:347` | Generated Service/Control and native authority proof; retain unrelated used identity/group types; S10a |
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

### 8.3 Complete version-string audit, including non-SDK owners

The following table extends section 8.2 to the **entire product tree** at the
fixed base: all 397 distinct quoted `ramflux.*.vN` strings / 1,077 occurrences,
not just selected schema/type uses. Every baseline location is listed. The
70 SDK strings already in section 8.2 are not duplicated here. This strict
superset also accounts for hash domains, storage labels, service RPCs and test
fixtures: retention of a non-message domain is deliberate, not a new Inner
codec. Fixed schema strings inside native signature transcripts remain data to
validate, never a decoder-selection mechanism. Prefix literals with escaped
terminators are audited separately in section 8.4.

| Literal | All baseline locations | Replacement / retained-domain disposition |
|---|---|---|
| `ramflux.a2i.sender.v3` | `crates/ramflux-sdk/src/client/routed/control.rs:259` | Retain verified native A2I sender binding hash; Control.a2i, never a body decoder. |
| `ramflux.a2i_control.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/a2i_control/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/a2i_control/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/a2i_control/fixture.json:5`, `crates/ramflux-protocol/fixtures/protocol/v1/a2i_control/fixture.json:7`, `crates/ramflux-protocol/fixtures/protocol/v1/a2i_control/negative.invalid_signature.json:5`, `crates/ramflux-protocol/fixtures/protocol/v1/a2i_control/negative.invalid_signature.json:7`, `crates/ramflux-protocol/fixtures/protocol/v1/a2i_control/negative.replay.json:5`, `crates/ramflux-protocol/fixtures/protocol/v1/a2i_control/negative.replay.json:7`, `crates/ramflux-protocol/src/domain.rs:45` | Control.a2i: full A2iControlEvent; retain fixed signing schema/domain, remove JSON try-parse. |
| `ramflux.a2ui.action.v2` | `apps/ramflux-agent-host/tests/host/surface_bus.rs:48`, `crates/ramflux-protocol/src/a2ui_state/types.rs:13`, `crates/ramflux-protocol/src/a2ui_state/types.rs:21`, `crates/ramflux-sdk/src/client/surface/tests.rs:186`, `crates/ramflux-sdk/src/client/surface/tests/retention.rs:75`, `crates/ramflux-sdk/src/client/task/surface_tests.rs:89`, `crates/ramflux-sdk/src/surface.rs:70` | SurfaceAction (values, args_hash, task_binding); remove wire JSON decoder, keep native hash semantics. |
| `ramflux.a2ui.action_args.v1` | `crates/ramflux-protocol/src/domain.rs:50`, `crates/ramflux-protocol/src/domain.rs:254` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.a2ui.action_signing_body.v1` | `crates/ramflux-sync/src/a2ui.rs:9` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.a2ui.checkpoint.v2` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:43`, `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:124`, `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:147` | SurfaceCheckpoint: full typed content/finality proof; remove JSON wire checkpoint decoder. |
| `ramflux.a2ui.conversation.v2` | `crates/ramflux-protocol/src/a2ui_state/state.rs:360`, `crates/ramflux-protocol/src/a2ui_state/types.rs:12`, `crates/ramflux-protocol/src/a2ui_state/types.rs:16`, `crates/ramflux-sdk/src/client/surface/tests.rs:76`, `crates/ramflux-sdk/src/client/surface/tests.rs:428`, `crates/ramflux-sdk/src/client/surface/tests/security.rs:68`, `crates/ramflux-sdk/src/client/task/surface_tests.rs:206` | SurfaceEvent and all six SurfaceCommand arms; retain fixed native hash/signing value, remove old wire decoder. |
| `ramflux.a2ui.conversation.v3` | `crates/ramflux-protocol/tests/a2ui_state/wire.rs:74` | Remove negative unknown-schema fixture with old JSON decoder; new unknown-arm/raw-retention fixture replaces it. |
| `ramflux.a2ui.final_component.v1` | `crates/ramflux-protocol/src/domain.rs:48` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.a2ui.final_text.v1` | `crates/ramflux-protocol/src/domain.rs:49`, `crates/ramflux-protocol/tests/a2ui_state/checkpoint.rs:49` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.a2ui.resync_metadata.v1` | `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:77`, `crates/ramflux-protocol/src/a2ui_state/checkpoint.rs:101` | SurfaceResyncMetadata: typed finality proof; remove JSON wire metadata decoder. |
| `ramflux.a2ui.surface_hash.v1` | `crates/ramflux-protocol/src/domain.rs:47` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.a2ui.v1` | `crates/ramflux-crypto/tests/generate_protocol_fixtures.rs:368`, `crates/ramflux-crypto/tests/generate_protocol_fixtures.rs:404`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/fixture.json:2`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/negative.invalid_signature.json:2`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/negative.replay.json:2`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_manifest/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_manifest/fixture.json:3`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_manifest/negative.invalid_signature.json:3`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_manifest/negative.replay.json:3`, `crates/ramflux-sdk/src/bus/dispatch/call_bot.rs:362`, `crates/ramflux-sync/src/bot.rs:318` | Retire old application surface body/fixtures; SurfaceEvent v2 semantics only; no legacy compatibility shim. |
| `ramflux.a2ui_surface.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/fixture.json:7`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/fixture.json:10`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/negative.invalid_signature.json:7`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/negative.invalid_signature.json:10`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/negative.replay.json:7`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/negative.replay.json:10`, `crates/ramflux-protocol/src/domain.rs:46` | Retire parallel A2uiSurfaceEvent wire family; generated Kind 9 Surface. |
| `ramflux.account.backup.stream.v2` | `crates/ramflux-crypto/src/backup_stream/mod.rs:72`, `crates/ramflux-crypto/src/backup_stream/mod.rs:87` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.account_db_kek.v2` | `crates/ramflux-sdk/src/client/account.rs:314` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.account_db_key.v1` | `crates/ramflux-storage/src/encryption.rs:53` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.account_db_key.wrap.v1` | `crates/ramflux-storage/src/encryption.rs:232`, `crates/ramflux-storage/src/encryption.rs:249` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.ack.v1` | `apps/ramflux-gateway/src/submit_ack_tests.rs:238`, `apps/ramflux-gateway/src/submit_ack_tests.rs:238`, `apps/ramflux-gateway/src/submit_ack_tests.rs:359`, `apps/ramflux-gateway/src/submit_ack_tests.rs:359`, `apps/ramflux-router/src/router_runtime.rs:1034`, `apps/ramflux-router/src/router_runtime.rs:1036`, `crates/ramflux-node-core/src/tests/helpers.rs:442`, `crates/ramflux-node-core/src/tests/helpers.rs:444`, `crates/ramflux-protocol/fixtures/protocol/v1/ack/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/ack/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/ack/fixture.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/ack/fixture.json:8`, `crates/ramflux-protocol/fixtures/protocol/v1/ack/negative.invalid_signature.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/ack/negative.invalid_signature.json:8`, `crates/ramflux-protocol/fixtures/protocol/v1/ack/negative.replay.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/ack/negative.replay.json:8`, `crates/ramflux-protocol/src/domain.rs:25`, `crates/ramflux-sdk/src/dm.rs:426`, `crates/ramflux-sdk/src/dm.rs:428` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.agent.deferred_surface.v1` | `apps/ramflux-agent-host/src/runner_deferred.rs:33`, `apps/ramflux-agent-host/tests/host/deferred_fairness.rs:127` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.agent.handled_action.v1` | `apps/ramflux-agent-host/src/runner_output.rs:198` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.agent.prx.operation.v1` | `apps/ramflux-agent-host/src/runner_approval.rs:49` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.agent.prx.task.operation.v1` | `apps/ramflux-agent-host/src/runner_approval.rs:549` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.agent.prx.task.v1` | `apps/ramflux-agent-host/src/runner_approval.rs:42` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.agent.reply.device.v1` | `apps/ramflux-agent-host/src/participant.rs:304` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.agent.reply.v1` | `apps/ramflux-agent-host/src/participant.rs:252` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.agent.rule.v1` | `apps/ramflux-agent-host/src/engine.rs:245`, `apps/ramflux-agent-host/src/engine.rs:283` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.attachment.ack.progress.v1` | `crates/ramflux-sdk/src/client/deferred_attachment.rs:541` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.attachment.reference.v1` | `crates/ramflux-sdk/src/bus/backup_jobs/tests.rs:195`, `crates/ramflux-sdk/src/client/deferred_attachment.rs:114`, `crates/ramflux-sdk/src/client/deferred_attachment.rs:192`, `crates/ramflux-sdk/src/client/deferred_attachment.rs:635`, `crates/ramflux-storage/src/account_db/backup_missing_tests.rs:84`, `crates/ramflux-storage/src/account_db/object_retention/actors.rs:28`, `crates/ramflux-storage/src/account_db/object_retention/legacy.rs:164`, `crates/ramflux-storage/src/account_db/object_retention/legacy.rs:174` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.backup.fetch.v1` | `crates/ramflux-sdk/src/bus/backup_jobs/attachments.rs:42`, `crates/ramflux-sdk/src/bus/backup_jobs/tests.rs:749` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.backup.native_data.v1` | `crates/ramflux-sdk/src/bus/backup_jobs/native.rs:62`, `crates/ramflux-sdk/src/bus/backup_jobs/native.rs:84`, `crates/ramflux-sdk/src/bus/backup_jobs/native.rs:284`, `crates/ramflux-sdk/src/bus/backup_jobs/native_tests.rs:332`, `crates/ramflux-sdk/src/bus/backup_jobs/native_writer_tests.rs:25` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.backup.staging.database.v1` | `crates/ramflux-sdk/src/bus/backup_jobs/workers.rs:559` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.backup.staging.metadata.v1` | `crates/ramflux-sdk/src/bus/backup_jobs/format.rs:181`, `crates/ramflux-sdk/src/bus/backup_jobs/format.rs:200` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.basic.v1` | `apps/rf/src/cli/a2i_a2ui.rs:73`, `crates/ramflux-crypto/tests/generate_protocol_fixtures.rs:371`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/fixture.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/negative.invalid_signature.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface/negative.replay.json:4`, `crates/ramflux-protocol/tests/a2ui_state/goldens.json:12`, `crates/ramflux-protocol/tests/a2ui_state/goldens.json:36`, `crates/ramflux-protocol/tests/a2ui_state/support.rs:9`, `crates/ramflux-protocol/tests/m1_2_protocol.rs:205`, `crates/ramflux-sdk/src/bus/dispatch/a2i_a2ui.rs:276`, `crates/ramflux-sync/src/a2ui.rs:230` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.bot_event.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/bot_event/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_event/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_event/fixture.json:11`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_event/fixture.json:15`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_event/negative.invalid_signature.json:11`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_event/negative.invalid_signature.json:15`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_event/negative.replay.json:11`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_event/negative.replay.json:15`, `crates/ramflux-protocol/src/domain.rs:43` | Remove unused BotEvent family; generated Surface/Task. |
| `ramflux.bot_install_grant.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/bot_install_grant/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_install_grant/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_install_grant/fixture.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_install_grant/fixture.json:10`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_install_grant/negative.invalid_signature.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_install_grant/negative.invalid_signature.json:10`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_install_grant/negative.replay.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_install_grant/negative.replay.json:10`, `crates/ramflux-protocol/src/domain.rs:44` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.bot_manifest.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/bot_manifest/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_manifest/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_manifest/fixture.json:14`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_manifest/fixture.json:34`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_manifest/negative.invalid_signature.json:14`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_manifest/negative.invalid_signature.json:34`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_manifest/negative.replay.json:14`, `crates/ramflux-protocol/fixtures/protocol/v1/bot_manifest/negative.replay.json:34`, `crates/ramflux-protocol/src/domain.rs:42` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.branch_proof.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/branch_proof/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/branch_proof/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/branch_proof/fixture.json:8`, `crates/ramflux-protocol/fixtures/protocol/v1/branch_proof/fixture.json:14`, `crates/ramflux-protocol/fixtures/protocol/v1/branch_proof/negative.invalid_signature.json:8`, `crates/ramflux-protocol/fixtures/protocol/v1/branch_proof/negative.invalid_signature.json:14`, `crates/ramflux-protocol/fixtures/protocol/v1/branch_proof/negative.replay.json:8`, `crates/ramflux-protocol/fixtures/protocol/v1/branch_proof/negative.replay.json:14`, `crates/ramflux-protocol/src/domain.rs:35` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.branch_proof.v2` | `crates/ramflux-protocol/src/domain.rs:29`, `docs/root_bound_device_keys.md:21` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.call.control.signature.v1` | `crates/ramflux-sdk/src/client/call/mod.rs:19` | Retain protocol CallControl signature transcript/domain over mirrored fields; never a kind discriminator. |
| `ramflux.call.control.v1` | `crates/ramflux-sdk/src/client/call/mod.rs:49`, `crates/ramflux-sdk/src/client/call/state.rs:177` | Call.control: full CallControl/all 13 actions; retain fixed native signing schema; remove prefix/JSON body dispatch. |
| `ramflux.call.sequence.v1` | `crates/ramflux-sdk/src/client/call/mod.rs:244` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.call.transition.v1` | `crates/ramflux-sdk/src/client/call/mod.rs:311` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.chunk.cipher.v1` | `crates/ramflux-protocol/src/domain.rs:8` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.chunk.plain.v1` | `crates/ramflux-protocol/src/domain.rs:7` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.client_discovery.v1` | `crates/ramflux-protocol/src/client_discovery.rs:10` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.client_event.v1` | `crates/ramflux-protocol/src/group_device_roots.rs:23`, `crates/ramflux-protocol/src/group_device_roots.rs:143`, `crates/ramflux-sdk/src/client/group.rs:712`, `crates/ramflux-sdk/src/client/identity_authority/group_review_r3_tests.rs:11` | Remove unused parallel ClientEvent body codec; generated Inner/MessageUpdate. |
| `ramflux.client_event.v2` | `crates/ramflux-protocol/src/group_device_roots.rs:26`, `crates/ramflux-protocol/src/group_device_roots.rs:89`, `crates/ramflux-sdk/src/client/group_control_roots.rs:79` | Remove old body/fixture facade; generated Inner/MessageUpdate. |
| `ramflux.committing_aead.ad.v1` | `crates/ramflux-protocol/src/domain.rs:66` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.committing_aead.header.v1` | `crates/ramflux-protocol/src/domain.rs:65` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.committing_aead.v1` | `crates/ramflux-protocol/src/domain.rs:64` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.contact.card.v1` | `crates/ramflux-sdk/src/client/routed/contact_locator_tests.rs:100`, `crates/ramflux-sdk/src/contact_card.rs:8`, `docs/contact_cards.md:86` | Retain cited ownership/idempotency/storage hash in its current module; peer data uses typed Control/Receipt/HistoryItem instead of string dispatch. |
| `ramflux.contact.card.v3` | `crates/ramflux-protocol/src/custody/contact_card.rs:8`, `docs/contact_cards.md:54` | Retain cited ownership/idempotency/storage hash in its current module; peer data uses typed Control/Receipt/HistoryItem instead of string dispatch. |
| `ramflux.contact.decision_event.v1` | `crates/ramflux-sdk/src/client/contact.rs:702` | Retain cited ownership/idempotency/storage hash in its current module; peer data uses typed Control/Receipt/HistoryItem instead of string dispatch. |
| `ramflux.contact.link.v2` | `crates/ramflux-sdk/src/client/contact_roots.rs:178` | Retain cited ownership/idempotency/storage hash in its current module; peer data uses typed Control/Receipt/HistoryItem instead of string dispatch. |
| `ramflux.contact_request.authority_floor.v1` | `crates/ramflux-sdk/src/client/contact_requests/retention.rs:13` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.contact_request.conversation.v1` | `crates/ramflux-sdk/src/client/contact_requests/wire.rs:53` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.contact_request.delivery.v1` | `crates/ramflux-sdk/src/client/contact_requests/delivery.rs:32`, `crates/ramflux-sdk/src/client/routed/contact_request_r2_tests.rs:153`, `crates/ramflux-sdk/src/client/routed/contact_request_r2_tests.rs:188`, `crates/ramflux-sdk/src/client/routed/contact_request_r2_tests.rs:362`, `crates/ramflux-sdk/src/client/routed/contact_request_r2_tests.rs:381` | Retain contact-delivery idempotency hash; native consent mapped to Control.contact_control; not a body schema. |
| `ramflux.contact_request.id.v1` | `crates/ramflux-crypto/src/custody/contact.rs:89`, `crates/ramflux-crypto/tests/fixtures/contact_consent_v2_reference.py:22`, `crates/ramflux-protocol/src/custody/contact.rs:78`, `crates/ramflux-sdk/src/client/contact_requests/wire.rs:60` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.contact_request.recipient_material.v1` | `crates/ramflux-sdk/src/client/contact_requests/delivery.rs:84` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.contact_request.v1` | `crates/ramflux-sdk/src/client/contact_requests/wire.rs:7`, `crates/ramflux-sdk/src/client/routed/contact_request_r2_tests.rs:66`, `crates/ramflux-sdk/src/client/routed/contact_request_r3_tests.rs:204` | Retire legacy root JSON contact codec on v3 reset; Control.contact_control carries native custody Envelope<ContactConsentV2>. |
| `ramflux.conversation_event.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/conversation_event/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/conversation_event/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/conversation_event/fixture.json:12`, `crates/ramflux-protocol/fixtures/protocol/v1/conversation_event/fixture.json:16`, `crates/ramflux-protocol/fixtures/protocol/v1/conversation_event/negative.invalid_signature.json:12`, `crates/ramflux-protocol/fixtures/protocol/v1/conversation_event/negative.invalid_signature.json:16`, `crates/ramflux-protocol/fixtures/protocol/v1/conversation_event/negative.replay.json:12`, `crates/ramflux-protocol/fixtures/protocol/v1/conversation_event/negative.replay.json:16`, `crates/ramflux-protocol/src/domain.rs:38` | Remove unused ConversationEvent body family; generated Service/Control. |
| `ramflux.cursor.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/cursor/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/cursor/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/cursor/fixture.json:7`, `crates/ramflux-protocol/fixtures/protocol/v1/cursor/fixture.json:13`, `crates/ramflux-protocol/fixtures/protocol/v1/cursor/negative.invalid_signature.json:7`, `crates/ramflux-protocol/fixtures/protocol/v1/cursor/negative.invalid_signature.json:13`, `crates/ramflux-protocol/fixtures/protocol/v1/cursor/negative.replay.json:7`, `crates/ramflux-protocol/fixtures/protocol/v1/cursor/negative.replay.json:13`, `crates/ramflux-protocol/src/domain.rs:27` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.device_proof.v1` | `apps/ramflux-gateway/src/session.rs:1874`, `apps/ramflux-gateway/src/session.rs:1874`, `apps/ramflux-gateway/src/session_resilience_tests.rs:209`, `apps/ramflux-gateway/src/session_resilience_tests.rs:209`, `crates/ramflux-node-core/src/tests/helpers.rs:766`, `crates/ramflux-node-core/src/tests/helpers.rs:768`, `crates/ramflux-protocol/fixtures/protocol/v1/device_proof/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/device_proof/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/device_proof/fixture.json:8`, `crates/ramflux-protocol/fixtures/protocol/v1/device_proof/fixture.json:12`, `crates/ramflux-protocol/fixtures/protocol/v1/device_proof/negative.invalid_signature.json:8`, `crates/ramflux-protocol/fixtures/protocol/v1/device_proof/negative.invalid_signature.json:12`, `crates/ramflux-protocol/fixtures/protocol/v1/device_proof/negative.replay.json:8`, `crates/ramflux-protocol/fixtures/protocol/v1/device_proof/negative.replay.json:12`, `crates/ramflux-protocol/src/domain.rs:13`, `crates/ramflux-sdk/src/gateway/helpers.rs:72`, `crates/ramflux-sdk/src/gateway/helpers.rs:74` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.device_set.v1` | `crates/ramflux-protocol/src/domain.rs:70` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.dm_ratchet.chain.v1` | `crates/ramflux-protocol/src/domain.rs:57` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.dm_ratchet.header.v1` | `crates/ramflux-protocol/src/domain.rs:59` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.dm_ratchet.message.v1` | `crates/ramflux-protocol/src/domain.rs:58` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.dm_ratchet.root.v1` | `crates/ramflux-protocol/src/domain.rs:56` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.dm_ratchet.skipped_key.v1` | `crates/ramflux-protocol/src/domain.rs:60` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.dm_session.snapshot.v1` | `crates/ramflux-crypto/src/double_ratchet.rs:647`, `crates/ramflux-crypto/src/double_ratchet.rs:694` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.envelope.v1` | `apps/ramflux-federation/src/flow.rs:676`, `apps/ramflux-federation/src/flow.rs:676`, `apps/ramflux-federation/src/flow.rs:783`, `apps/ramflux-federation/src/flow.rs:785`, `apps/ramflux-federation/src/http_listener_tests.rs:314`, `apps/ramflux-federation/src/http_listener_tests.rs:314`, `apps/ramflux-gateway/src/session.rs:2184`, `apps/ramflux-gateway/src/session.rs:2186`, `apps/ramflux-gateway/src/submit_ack_tests.rs:289`, `apps/ramflux-gateway/src/submit_ack_tests.rs:289`, `apps/ramflux-gateway/src/submit_source.rs:97`, `apps/ramflux-router/src/router_runtime.rs:1013`, `apps/ramflux-router/src/router_runtime.rs:1015`, `crates/ramflux-node-core/src/custody_delivery.rs:32`, `crates/ramflux-node-core/src/tests/helpers.rs:421`, `crates/ramflux-node-core/src/tests/helpers.rs:423`, `crates/ramflux-protocol/fixtures/protocol/v1/envelope/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/envelope/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/envelope/fixture.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/envelope/fixture.json:10`, `crates/ramflux-protocol/fixtures/protocol/v1/envelope/negative.invalid_signature.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/envelope/negative.invalid_signature.json:10`, `crates/ramflux-protocol/fixtures/protocol/v1/envelope/negative.replay.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/envelope/negative.replay.json:10`, `crates/ramflux-protocol/src/domain.rs:5`, `crates/ramflux-protocol/tests/envelope_forward_canon.rs:12`, `crates/ramflux-protocol/tests/envelope_forward_canon.rs:12`, `crates/ramflux-sdk/src/bus/dispatch/message.rs:962`, `crates/ramflux-sdk/src/bus/dispatch/message.rs:962`, `crates/ramflux-sdk/src/bus/task_delivery.rs:143`, `crates/ramflux-sdk/src/bus/task_delivery.rs:143`, `crates/ramflux-sdk/src/client/federation.rs:353`, `crates/ramflux-sdk/src/client/surface/own_history.rs:242`, `crates/ramflux-sdk/src/client/task/control_tests.rs:12`, `crates/ramflux-sdk/src/dm.rs:454`, `crates/ramflux-sdk/src/dm.rs:456`, `crates/ramflux-sdk/src/gateway/submit_tests.rs:116`, `crates/ramflux-sdk/src/gateway/submit_tests.rs:116` | Replace client-envelope revision/class policy per section 6; native notify/service messages retain their separately validated transport contract. |
| `ramflux.event.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/event_id/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/event_id/fixture.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/event_id/negative.invalid_signature.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/event_id/negative.replay.json:4`, `crates/ramflux-protocol/src/domain.rs:4` | Retain native signed authority/event proof where used; Inner Service/Control selects its fixed proof type; no generic application dispatch. |
| `ramflux.federated_issuer_trust_snapshot.v3` | `crates/ramflux-node-core/src/relay/trust.rs:15` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.federated_issuer_trust_snapshot_envelope.v3` | `crates/ramflux-node-core/src/relay/trust.rs:19` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.federated_issuer_trust_snapshot_envelope.v4` | `crates/ramflux-node-core/src/relay/provider.rs:21` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.federated_trust_snapshot_envelope.v3` | `crates/ramflux-node-core/src/relay/trust.rs:67` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.federation.test_seed.v1` | `apps/ramflux-federation/src/discovery.rs:136` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.federation_handshake.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/federation_handshake/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/federation_handshake/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/federation_handshake/fixture.json:3`, `crates/ramflux-protocol/fixtures/protocol/v1/federation_handshake/fixture.json:9`, `crates/ramflux-protocol/fixtures/protocol/v1/federation_handshake/negative.invalid_signature.json:3`, `crates/ramflux-protocol/fixtures/protocol/v1/federation_handshake/negative.invalid_signature.json:9`, `crates/ramflux-protocol/fixtures/protocol/v1/federation_handshake/negative.replay.json:3`, `crates/ramflux-protocol/fixtures/protocol/v1/federation_handshake/negative.replay.json:9`, `crates/ramflux-protocol/src/domain.rs:53` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.federation_provider_keyring.fingerprint.v1` | `crates/ramflux-node-core/src/relay/provider.rs:16` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.federation_provider_keyring.v1` | `crates/ramflux-node-core/src/relay/provider.rs:13`, `deploy/secrets/federation/README.md:24` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.franking.node_tag.v1` | `crates/ramflux-protocol/src/domain.rs:68` | Retire after node receipt v2 in Decision 5; independent verifier updated in S10a. |
| `ramflux.franking_opening.v1` | `crates/ramflux-protocol/src/domain.rs:67` | Retire after uniform report-opening transcript in Decision 5; do not reuse for different inputs. |
| `ramflux.friend_event.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/friend_event/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/friend_event/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/friend_event/fixture.json:13`, `crates/ramflux-protocol/fixtures/protocol/v1/friend_event/fixture.json:17`, `crates/ramflux-protocol/fixtures/protocol/v1/friend_event/negative.invalid_signature.json:13`, `crates/ramflux-protocol/fixtures/protocol/v1/friend_event/negative.invalid_signature.json:17`, `crates/ramflux-protocol/fixtures/protocol/v1/friend_event/negative.replay.json:13`, `crates/ramflux-protocol/fixtures/protocol/v1/friend_event/negative.replay.json:17`, `crates/ramflux-protocol/src/domain.rs:36` | Generated Control.friend with fixed action registry; remove parallel unused event wrapper. |
| `ramflux.gateway.device_proof.v1` | `crates/ramflux-node-core/src/gateway_frames.rs:79`, `crates/ramflux-sdk/src/constants.rs:8` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.gateway.open.v1` | `crates/ramflux-node-core/src/gateway_frames.rs:78`, `crates/ramflux-sdk/src/constants.rs:7` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.gateway.resume_token.v1` | `crates/ramflux-node-core/src/gateway_state.rs:381`, `crates/ramflux-node-core/src/gateway_state.rs:396`, `crates/ramflux-sdk/src/gateway/helpers.rs:48` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.gateway_certificate_request.v3` | `crates/ramflux-node-core/src/relay/certificates.rs:46` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.gateway_issuer_certificate.binding.v3` | `crates/ramflux-node-core/src/relay/certificates.rs:55` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.gateway_issuer_certificate.v3` | `crates/ramflux-node-core/src/relay/certificates.rs:45`, `crates/ramflux-protocol/src/object_relay_v3.rs:29` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.gateway_session.v1` | `crates/ramflux-node-core/src/gateway_frames.rs:77`, `crates/ramflux-sdk/src/constants.rs:6` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group.change.record.v1` | `crates/ramflux-sdk/src/client/shared_group/requests.rs:38` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group.courier.attempt.v1` | `crates/ramflux-sdk/src/bus/shared_group_sync/requests.rs:13` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group.courier.cursor.v1` | `crates/ramflux-sdk/src/bus/shared_group_sync/requests.rs:164` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group.delivery.subject.v1` | `crates/ramflux-sdk/src/bus/shared_group_sync/outbox/delivery.rs:223` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group.device_roots.v2` | `crates/ramflux-protocol/src/group_device_roots.rs:31`, `crates/ramflux-protocol/src/group_device_roots.rs:124`, `crates/ramflux-sdk/src/client/group_control_roots.rs:84` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group.distribution.content.v3` | `crates/ramflux-sdk/src/bus/dispatch/group.rs:1176` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group.distribution_envelope.v2` | `crates/ramflux-sdk/src/group.rs:307` | GroupKeyControl typed distribution/membership proof/manifest URL; remove SDK JSON wrapper. |
| `ramflux.group.sender.chain.v3` | `crates/ramflux-sdk/src/client/group_session.rs:751` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group.sender_key.distribution.v4` | `crates/ramflux-sdk/src/client/group_distribution_auth.rs:12` | GroupKeyDistribution exact SDK fields and existing signature/seed binding; no SDK JSON body decoder. |
| `ramflux.group.transfer.delivery.v1` | `crates/ramflux-sdk/src/client/shared_group/transfer.rs:223` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group.transfer.device.v1` | `crates/ramflux-sdk/src/client/shared_group/transfer.rs:44` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group.transfer_sync.v1` | `crates/ramflux-sdk/src/client/shared_group/transfer_wire.rs:8` | Typed TransferControl/Probe/Head under Control.group_state; replace changed signature transcript per section 3.1. |
| `ramflux.group_event.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/group_event/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/group_event/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/group_event/fixture.json:15`, `crates/ramflux-protocol/fixtures/protocol/v1/group_event/fixture.json:19`, `crates/ramflux-protocol/fixtures/protocol/v1/group_event/negative.invalid_signature.json:15`, `crates/ramflux-protocol/fixtures/protocol/v1/group_event/negative.invalid_signature.json:19`, `crates/ramflux-protocol/fixtures/protocol/v1/group_event/negative.replay.json:15`, `crates/ramflux-protocol/fixtures/protocol/v1/group_event/negative.replay.json:19`, `crates/ramflux-protocol/src/domain.rs:37` | Retain native signed authority/event proof where used; Inner Service/Control selects its fixed proof type; no generic application dispatch. |
| `ramflux.group_sender_key.chain.v1` | `crates/ramflux-protocol/src/domain.rs:62` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group_sender_key.distribution.v1` | `crates/ramflux-protocol/src/domain.rs:61` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group_sender_key.message.v1` | `crates/ramflux-protocol/src/domain.rs:63` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group_state.actor.v1` | `crates/ramflux-protocol/src/group_state.rs:9` | Retain fixed native GroupStateActor proof codec; never guessed by Inner decoder. |
| `ramflux.group_state.content.v2` | `crates/ramflux-crypto/src/group_state/snapshot.rs:146`, `crates/ramflux-crypto/src/group_state/snapshot.rs:319` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group_state.creator_signature.v2` | `crates/ramflux-crypto/src/group_state/snapshot.rs:61` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group_state.creator_transfer.v2` | `crates/ramflux-crypto/src/group_state/snapshot.rs:16` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group_state.delivery.v1` | `crates/ramflux-sdk/src/bus/shared_group_sync/outbox/delivery.rs:157` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group_state.federation_route.v1` | `crates/ramflux-sdk/src/client/shared_group/federation.rs:10` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group_state.genesis.v2` | `crates/ramflux-crypto/src/group_state/snapshot.rs:15` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.group_state.request.v1` | `crates/ramflux-protocol/src/group_state.rs:7` | Retain fixed native GroupChangeRequest proof codec in NativeGroupChangeRequest; typed GroupControlBody.request selects it. |
| `ramflux.group_state.result.v1` | `crates/ramflux-protocol/src/group_state.rs:8` | Retain fixed native GroupChangeResult proof codec in NativeGroupChangeResult; typed GroupControlBody.result selects it. |
| `ramflux.group_state.snapshot.v2` | `crates/ramflux-protocol/src/group_state.rs:6` | Retain fixed native GroupStateSnapshot proof codec; typed snapshot fields select it. |
| `ramflux.group_state.transfer_acceptance.v1` | `crates/ramflux-crypto/src/group_state/transfer.rs:10` | Retain fixed native GroupTransferAcceptance proof codec in typed TransferHead.acceptance. |
| `ramflux.home_node_migration_proof.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/home_node_migration_proof/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/home_node_migration_proof/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/home_node_migration_proof/fixture.json:5`, `crates/ramflux-protocol/fixtures/protocol/v1/home_node_migration_proof/fixture.json:18`, `crates/ramflux-protocol/fixtures/protocol/v1/home_node_migration_proof/negative.invalid_signature.json:5`, `crates/ramflux-protocol/fixtures/protocol/v1/home_node_migration_proof/negative.invalid_signature.json:18`, `crates/ramflux-protocol/fixtures/protocol/v1/home_node_migration_proof/negative.replay.json:5`, `crates/ramflux-protocol/fixtures/protocol/v1/home_node_migration_proof/negative.replay.json:18`, `crates/ramflux-protocol/src/domain.rs:14`, `crates/ramflux-protocol/src/home_node_migration.rs:111` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.home_node_route_record.v1` | `crates/ramflux-node-core/src/home_node_migration.rs:7` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.home_node_route_update_proof.v1` | `crates/ramflux-node-core/src/home_node_migration.rs:8` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.branch_certificate.v1` | `crates/ramflux-crypto/tests/fixtures/custody_v3.json:40`, `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:63`, `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:64`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:23`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:58`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:312`, `crates/ramflux-protocol/src/domain.rs:79` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.branch_proof.v3` | `crates/ramflux-protocol/src/domain.rs:80` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.contact_request.v2` | `crates/ramflux-crypto/tests/fixtures/contact_consent_v2.json:15`, `crates/ramflux-crypto/tests/fixtures/contact_consent_v2_reference.py:21`, `crates/ramflux-crypto/tests/fixtures/contact_consent_v2_reference.py:30`, `crates/ramflux-protocol/src/domain.rs:85` | Retain custody Envelope<ContactConsentV2> canonical proof/signature codec; selected only by typed NativeContactConsent. |
| `ramflux.identity.custody.object_hash.v1` | `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:37`, `crates/ramflux-protocol/src/domain.rs:92`, `docs/root_key_custody_wire.md:44` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.custody.section_hash.v1` | `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:84`, `crates/ramflux-protocol/src/domain.rs:93`, `docs/root_key_custody_wire.md:279` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.custody_action.v1` | `crates/ramflux-protocol/src/custody/network.rs:243` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.custody_session_action.v1` | `crates/ramflux-protocol/src/custody/network.rs:251` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.custody_signed_prekey.v1` | `crates/ramflux-sdk/src/custody/vault.rs:279` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.delegation.v1` | `crates/ramflux-protocol/src/domain.rs:81` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.device_agreement_key.v1` | `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:75`, `crates/ramflux-protocol/src/domain.rs:34`, `docs/root_key_custody_wire.md:112` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.device_signing_key.v1` | `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:74`, `crates/ramflux-protocol/src/domain.rs:33`, `docs/root_key_custody_wire.md:111` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.erasure_ack.v1` | `crates/ramflux-protocol/src/domain.rs:83` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.group_delegation.v1` | `crates/ramflux-protocol/src/domain.rs:82` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_admission_attestation.v1` | `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:787`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:802`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:803`, `crates/ramflux-protocol/src/domain.rs:120` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_attest_request.v1` | `crates/ramflux-protocol/src/domain.rs:126` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_authorization.v1` | `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:208`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:209`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:531`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:559`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:560`, `crates/ramflux-protocol/src/domain.rs:114` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_backlog_manifest.v1` | `crates/ramflux-protocol/src/domain.rs:125` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_commit.v1` | `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:259`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:260`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:711`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:732`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:733`, `crates/ramflux-protocol/src/domain.rs:118` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_commit_delivery.v1` | `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:751`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:768`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:769`, `crates/ramflux-protocol/src/domain.rs:119` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_control.v1` | `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:625`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:644`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:645`, `crates/ramflux-protocol/src/domain.rs:116` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_delivery_map.v1` | `crates/ramflux-protocol/src/domain.rs:123` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_genesis.v1` | `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:415`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:416`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:594`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:606`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:607`, `crates/ramflux-protocol/src/domain.rs:115` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_noncommit_fence.v1` | `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:821`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:831`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:832`, `crates/ramflux-protocol/src/domain.rs:121` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_peer_status.v1` | `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:850`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:864`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:865`, `crates/ramflux-protocol/src/domain.rs:127` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_prepare.v1` | `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:437`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:462`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:463`, `crates/ramflux-protocol/src/domain.rs:112` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_receipt.v1` | `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:668`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:692`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:693`, `crates/ramflux-protocol/src/domain.rs:117` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_record_hash.v1` | `crates/ramflux-protocol/src/domain.rs:122` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.home_route_offer.v1` | `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:486`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:512`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:513`, `crates/ramflux-protocol/src/domain.rs:113` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.legacy_binding.v1` | `crates/ramflux-protocol/src/domain.rs:84` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.master.v1` | `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:47`, `crates/ramflux-protocol/src/domain.rs:91`, `docs/root_key_custody.md:164` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.master_certificate.v1` | `crates/ramflux-crypto/tests/fixtures/custody_v3.json:72`, `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:54`, `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:55`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:90`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:147`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:344`, `crates/ramflux-protocol/src/domain.rs:77` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.node_pin_path.v1` | `crates/ramflux-sdk/src/custody/node_pins.rs:51` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.node_record.v1` | `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:176`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:399`, `crates/ramflux-protocol/src/domain.rs:89` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.pairing.channel.initiator.v1` | `crates/ramflux-protocol/src/domain.rs:100`, `docs/root_key_custody_wire.md:842` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.pairing.channel.responder.v1` | `crates/ramflux-protocol/src/domain.rs:101`, `docs/root_key_custody_wire.md:843` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.pairing.commitment.v1` | `crates/ramflux-protocol/src/domain.rs:96`, `docs/root_key_custody_wire.md:827` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.pairing.confirm.initiator.v1` | `crates/ramflux-protocol/src/domain.rs:98`, `docs/root_key_custody_wire.md:838` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.pairing.confirm.responder.v1` | `crates/ramflux-protocol/src/domain.rs:99`, `docs/root_key_custody_wire.md:839` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.pairing.sas.v1` | `crates/ramflux-protocol/src/domain.rs:97`, `docs/root_key_custody_wire.md:835` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.pairing.sas_emoji.v1` | `crates/ramflux-protocol/src/domain.rs:102`, `docs/root_key_custody_wire.md:821` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.pairing_transcript.v1` | `crates/ramflux-protocol/src/domain.rs:95`, `crates/ramflux-protocol/src/domain.rs:276`, `docs/root_key_custody_wire.md:812`, `docs/root_key_custody_wire.md:824` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.profile.v1` | `crates/ramflux-protocol/src/domain.rs:30` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.relay_acceptance.v1` | `crates/ramflux-protocol/src/domain.rs:86` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.revoked_devices.checkpoint.v1` | `crates/ramflux-protocol/src/domain.rs:88` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.revoked_devices.list.v1` | `crates/ramflux-protocol/src/domain.rs:109`, `docs/root_key_custody_wire.md:346` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.root_public_key.commitment.v1` | `apps/ramflux-router/src/router_runtime.rs:1156`, `crates/ramflux-crypto/src/signed_device_set.rs:23`, `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:52`, `crates/ramflux-node-core/src/mvp1_registry.rs:324`, `crates/ramflux-node-core/src/tests/helpers.rs:236`, `crates/ramflux-node-core/src/tests/helpers.rs:840`, `crates/ramflux-sdk/src/prekey.rs:61`, `crates/ramflux-sdk/src/prekey.rs:73`, `docs/root_key_custody_wire.md:136` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.safety_number.v2` | `crates/ramflux-protocol/src/domain.rs:94`, `docs/root_key_custody_wire.md:151` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.signed_device_set.v1` | `crates/ramflux-protocol/src/domain.rs:32` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.signed_device_set.v2` | `crates/ramflux-protocol/src/domain.rs:31` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.signed_device_set.v3` | `crates/ramflux-crypto/tests/fixtures/custody_v3.json:97`, `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:79`, `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:87`, `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:94`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:115`, `crates/ramflux-crypto/tests/fixtures/home_migration_v1.json:369`, `crates/ramflux-protocol/src/domain.rs:78` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.time_attestation.v1` | `crates/ramflux-protocol/src/domain.rs:90` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.time_probe.v1` | `crates/ramflux-protocol/src/domain.rs:110`, `docs/root_key_custody_wire.md:666` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.transfer.aad.v1` | `crates/ramflux-protocol/src/domain.rs:104`, `docs/root_key_custody_wire.md:861` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.transfer.hpke.v1` | `crates/ramflux-protocol/src/domain.rs:105`, `docs/root_key_custody_wire.md:868` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.transfer.hpke_info.v1` | `crates/ramflux-protocol/src/domain.rs:103`, `docs/root_key_custody_wire.md:859` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.transfer.hpke_suite.v1` | `crates/ramflux-protocol/src/domain.rs:107`, `docs/root_key_custody_wire.md:822` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.transfer.payload.v1` | `crates/ramflux-protocol/src/domain.rs:106`, `docs/root_key_custody_wire.md:887` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity.transfer_binding.v1` | `crates/ramflux-protocol/src/domain.rs:87` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity_admission.base_snapshot.v1` | `apps/ramflux-router/src/operator.rs:89`, `crates/ramflux-node-core/src/router_store/identity_registry.rs:24` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity_admission.missing_snapshot.v1` | `crates/ramflux-node-core/src/router_store/identity_registry.rs:25` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity_deletion_proof.deleted_metadata_empty.v1` | `crates/ramflux-protocol/src/domain.rs:21` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity_deletion_proof.deleted_metadata_leaf.v1` | `crates/ramflux-protocol/src/domain.rs:17` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity_deletion_proof.deleted_metadata_parent.v1` | `crates/ramflux-protocol/src/domain.rs:19` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity_deletion_proof.retained_summary.v1` | `crates/ramflux-protocol/src/domain.rs:23` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity_deletion_proof.tombstone.v1` | `crates/ramflux-protocol/src/domain.rs:24` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity_deletion_proof.v1` | `crates/ramflux-node-core/src/lifecycle.rs:267`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_deletion_proof/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_deletion_proof/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_deletion_proof/fixture.json:9`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_deletion_proof/fixture.json:22`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_deletion_proof/identity_deletion_proof.bad_tombstone.reject.json:9`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_deletion_proof/identity_deletion_proof.bad_tombstone.reject.json:22`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_deletion_proof/negative.invalid_signature.json:9`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_deletion_proof/negative.invalid_signature.json:22`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_deletion_proof/negative.replay.json:9`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_deletion_proof/negative.replay.json:22`, `crates/ramflux-protocol/src/domain.rs:15` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity_event.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/identity_event/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_event/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_event/fixture.json:13`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_event/fixture.json:17`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_event/negative.invalid_signature.json:13`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_event/negative.invalid_signature.json:17`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_event/negative.replay.json:13`, `crates/ramflux-protocol/fixtures/protocol/v1/identity_event/negative.replay.json:17`, `crates/ramflux-protocol/src/domain.rs:28` | Retain native signed authority/event proof where used; Inner Service/Control selects its fixed proof type; no generic application dispatch. |
| `ramflux.identity_lifecycle_tombstone.v1` | `crates/ramflux-node-core/src/lifecycle.rs:154` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.identity_lineage.event_head.v1` | `crates/ramflux-node-core/src/router_lifecycle.rs:535` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.itest.http.v1` | `crates/ramflux-node-core/src/gateway_frames.rs:30` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.itest.quic_fault.body.v1` | `apps/ramflux-relay/src/itest_quic_fault.rs:10` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.kt.empty.v1` | `crates/ramflux-crypto/src/key_verification.rs:248` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.kt.leaf.v1` | `crates/ramflux-crypto/src/key_verification.rs:183` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.kt.node.v1` | `crates/ramflux-crypto/src/key_verification.rs:242` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.kt_leaf.v1` | `crates/ramflux-crypto/src/key_verification.rs:196`, `crates/ramflux-crypto/src/key_verification.rs:429` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.legacy.inbox.v1` | `crates/ramflux-sdk/src/client/group_quarantine.rs:24` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.local.custody_account.v1` | `crates/ramflux-sdk/src/custody/store.rs:309`, `crates/ramflux-sdk/src/custody/store.rs:343`, `crates/ramflux-sdk/src/custody/store.rs:449`, `crates/ramflux-sdk/src/custody/store/recovery.rs:453` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.local.custody_vault_reference.v1` | `crates/ramflux-sdk/src/custody/store.rs:412` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.local.native_data_generation.v1` | `crates/ramflux-sdk/src/bus/backup_jobs/native.rs:234` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.local.recovery_intent.v1` | `crates/ramflux-sdk/src/custody/store/recovery.rs:49`, `crates/ramflux-sdk/src/custody/store/recovery.rs:354` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.local.recovery_snapshot.v1` | `crates/ramflux-sdk/src/custody/store/recovery.rs:35` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.local.restore_install.v1` | `crates/ramflux-sdk/src/bus/backup_jobs/workers.rs:461` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.local_bus.account.v1` | `crates/ramflux-sdk/src/client/routed/contact_card_tests.rs:104` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.local_bus.account_backup.v1` | `crates/ramflux-sdk/src/bus/dispatch/account.rs:11` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.local_bus.account_manifest.v1` | `crates/ramflux-sdk/src/bus/backup_jobs/tests.rs:155`, `crates/ramflux-sdk/src/bus/dispatch/account.rs:460`, `crates/ramflux-sdk/src/bus/dispatch/tests/fixtures/legacy_created_account_manifest.json:6`, `crates/ramflux-sdk/src/bus/dispatch/tests/key_backup_restore.rs:21`, `crates/ramflux-sdk/src/bus/protocol.rs:323`, `crates/ramflux-sdk/src/bus/runtime_tests.rs:204`, `crates/ramflux-sdk/src/node/tests.rs:118`, `crates/ramflux-sdk/src/storage_failure_fixture.rs:46` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.local_bus.custody.v1` | `crates/ramflux-sdk/src/bus/custody_setup.rs:97`, `crates/ramflux-sdk/src/custody/bus.rs:145` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.local_bus.v1` | `crates/ramflux-sdk/src/bus/creation_client.rs:273`, `crates/ramflux-sdk/src/bus/creation_client.rs:297`, `crates/ramflux-sdk/src/bus/custody_response.rs:29`, `crates/ramflux-sdk/src/bus/custody_setup.rs:370`, `crates/ramflux-sdk/src/bus/dispatch/account.rs:556`, `crates/ramflux-sdk/src/bus/io.rs:28`, `crates/ramflux-sdk/src/bus/io.rs:48`, `crates/ramflux-sdk/src/bus/io.rs:262`, `crates/ramflux-sdk/src/bus/io.rs:381`, `crates/ramflux-sdk/src/bus/protocol.rs:1130`, `crates/ramflux-sdk/src/client/routed/contact_resolution_tests.rs:312`, `crates/ramflux-sdk/src/custody/bus.rs:119` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.mcp_grant.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/mcp_grant/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/mcp_grant/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/mcp_grant/fixture.json:3`, `crates/ramflux-protocol/fixtures/protocol/v1/mcp_grant/fixture.json:8`, `crates/ramflux-protocol/fixtures/protocol/v1/mcp_grant/negative.invalid_signature.json:3`, `crates/ramflux-protocol/fixtures/protocol/v1/mcp_grant/negative.invalid_signature.json:8`, `crates/ramflux-protocol/fixtures/protocol/v1/mcp_grant/negative.replay.json:3`, `crates/ramflux-protocol/fixtures/protocol/v1/mcp_grant/negative.replay.json:8`, `crates/ramflux-protocol/src/domain.rs:41` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.message_event.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/message_event/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/message_event/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/message_event/fixture.json:23`, `crates/ramflux-protocol/fixtures/protocol/v1/message_event/fixture.json:27`, `crates/ramflux-protocol/fixtures/protocol/v1/message_event/negative.invalid_signature.json:23`, `crates/ramflux-protocol/fixtures/protocol/v1/message_event/negative.invalid_signature.json:27`, `crates/ramflux-protocol/fixtures/protocol/v1/message_event/negative.replay.json:23`, `crates/ramflux-protocol/fixtures/protocol/v1/message_event/negative.replay.json:27`, `crates/ramflux-protocol/src/domain.rs:39` | Remove unused MessageEvent family; generated Message/Edit/Delete/Reaction/Receipt. |
| `ramflux.nack.v1` | `apps/ramflux-router/src/router_runtime.rs:1049`, `apps/ramflux-router/src/router_runtime.rs:1051`, `crates/ramflux-node-core/src/router.rs:1780`, `crates/ramflux-node-core/src/router.rs:1782`, `crates/ramflux-node-core/src/tests/helpers.rs:457`, `crates/ramflux-node-core/src/tests/helpers.rs:459`, `crates/ramflux-protocol/fixtures/protocol/v1/nack/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/nack/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/nack/fixture.json:2`, `crates/ramflux-protocol/fixtures/protocol/v1/nack/fixture.json:8`, `crates/ramflux-protocol/fixtures/protocol/v1/nack/negative.invalid_signature.json:2`, `crates/ramflux-protocol/fixtures/protocol/v1/nack/negative.invalid_signature.json:8`, `crates/ramflux-protocol/fixtures/protocol/v1/nack/negative.replay.json:2`, `crates/ramflux-protocol/fixtures/protocol/v1/nack/negative.replay.json:8`, `crates/ramflux-protocol/src/domain.rs:26` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.node.foreign_device_set.v1` | `crates/ramflux-node-core/src/foreign_device_heads.rs:22` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.node.registration_proof.v2` | `crates/ramflux-node-core/src/mvp1_registry.rs:421`, `crates/ramflux-node-core/tests/root_bound_identity.rs:455` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.notification.collapse_key_hash.v1` | `crates/ramflux-node-core/src/tests/server_retention_r2.rs:196` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.notification.collapse_key_hash.v2` | `crates/ramflux-node-core/src/notify.rs:1483` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.notification.encrypted_bucket.v1` | `crates/ramflux-node-core/src/notify.rs:1970` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.notification.push_alias_hash.v1` | `crates/ramflux-node-core/src/notify.rs:1121`, `crates/ramflux-node-core/src/notify.rs:1224`, `crates/ramflux-node-core/src/notify.rs:1262`, `crates/ramflux-node-core/src/notify.rs:1439` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.notification_wake.v1` | `crates/ramflux-node-core/src/notify_wal.rs:1447`, `crates/ramflux-node-core/src/notify_wal.rs:1449`, `crates/ramflux-node-core/src/tests/helpers.rs:531`, `crates/ramflux-node-core/src/tests/helpers.rs:533`, `crates/ramflux-protocol/fixtures/protocol/v1/notification_wake/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/notification_wake/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/notification_wake/fixture.json:3`, `crates/ramflux-protocol/fixtures/protocol/v1/notification_wake/fixture.json:6`, `crates/ramflux-protocol/fixtures/protocol/v1/notification_wake/negative.invalid_signature.json:3`, `crates/ramflux-protocol/fixtures/protocol/v1/notification_wake/negative.invalid_signature.json:6`, `crates/ramflux-protocol/fixtures/protocol/v1/notification_wake/negative.replay.json:3`, `crates/ramflux-protocol/fixtures/protocol/v1/notification_wake/negative.replay.json:6`, `crates/ramflux-protocol/src/domain.rs:40` | Replace client-envelope revision/class policy per section 6; native notify/service messages retain their separately validated transport contract. |
| `ramflux.notify.provider_attempt_key.v1` | `crates/ramflux-node-core/src/notify.rs:2039` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.notify.provider_h2_pool_ca.v1` | `apps/ramflux-notify/src/main.rs:2653` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object.erasure.fence.v1` | `crates/ramflux-crypto/src/object_erasure.rs:11` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object.erasure.lookup.v1` | `crates/ramflux-crypto/src/object_erasure.rs:17` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object.transport.owner.v1` | `crates/ramflux-sdk/src/client/object.rs:1049` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object.v1` | `crates/ramflux-crypto/src/kdf.rs:226`, `crates/ramflux-crypto/src/kdf.rs:227`, `crates/ramflux-crypto/src/kdf.rs:234`, `crates/ramflux-crypto/src/kdf.rs:235`, `crates/ramflux-protocol/src/domain.rs:6` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_access_grant.binding.v3` | `crates/ramflux-node-core/src/relay/authorization.rs:47`, `crates/ramflux-sdk/src/object.rs:769`, `crates/ramflux-sdk/src/object.rs:989` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_access_grant.v3` | `crates/ramflux-node-core/src/relay/authorization.rs:42`, `crates/ramflux-protocol/src/object_relay_v3.rs:26` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_chunk_frame.v1` | `crates/ramflux-node-core/src/relay/legacy.rs:211`, `crates/ramflux-node-core/src/tests/stores.rs:2536`, `crates/ramflux-node-core/src/tests/stores.rs:2602`, `crates/ramflux-sdk/src/client/object.rs:1964` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_chunk_id.v1` | `crates/ramflux-protocol/src/domain.rs:9` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_chunk_request.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/object_chunk_request/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/object_chunk_request/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/object_chunk_request/fixture.json:2`, `crates/ramflux-protocol/fixtures/protocol/v1/object_chunk_request/fixture.json:9`, `crates/ramflux-protocol/fixtures/protocol/v1/object_chunk_request/negative.invalid_signature.json:2`, `crates/ramflux-protocol/fixtures/protocol/v1/object_chunk_request/negative.invalid_signature.json:9`, `crates/ramflux-protocol/fixtures/protocol/v1/object_chunk_request/negative.replay.json:2`, `crates/ramflux-protocol/fixtures/protocol/v1/object_chunk_request/negative.replay.json:9`, `crates/ramflux-protocol/src/domain.rs:11` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_get.operation_id.v1` | `apps/rf/src/handlers/object.rs:349`, `apps/rf/src/handlers/object.rs:356` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_get_spool.v1` | `crates/ramflux-sdk/src/bus/dispatch/object.rs:1141` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_lan_announce.v1` | `crates/ramflux-sync/src/object_store.rs:1092`, `crates/ramflux-sync/src/object_store.rs:1479` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_manifest.v1` | `crates/ramflux-protocol/fixtures/protocol/v1/object_manifest/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/object_manifest/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/object_manifest/fixture.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/object_manifest/fixture.json:11`, `crates/ramflux-protocol/fixtures/protocol/v1/object_manifest/negative.invalid_signature.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/object_manifest/negative.invalid_signature.json:11`, `crates/ramflux-protocol/fixtures/protocol/v1/object_manifest/negative.replay.json:4`, `crates/ramflux-protocol/fixtures/protocol/v1/object_manifest/negative.replay.json:11`, `crates/ramflux-protocol/src/domain.rs:10` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_put.operation_id.v1` | `apps/rf/src/handlers/object.rs:702`, `apps/rf/src/handlers/object.rs:711` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_put.request.v1` | `crates/ramflux-sdk/src/object.rs:215` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_put_journal.prefix.v1` | `crates/ramflux-sdk/src/bus/dispatch/object.rs:763` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_put_spool.account.v1` | `crates/ramflux-sdk/src/bus/dispatch/object.rs:791` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_put_spool.v1` | `crates/ramflux-sdk/src/bus/dispatch/object.rs:801` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_relay.recipient_device.v1` | `apps/ramflux-gateway/src/session.rs:1219`, `apps/ramflux-relay/src/test_support.rs:55`, `apps/ramflux-relay/src/test_support.rs:378`, `crates/ramflux-node-core/src/relay/test_support.rs:98`, `crates/ramflux-node-core/src/relay/test_support.rs:217`, `crates/ramflux-sdk/src/client/object.rs:2799`, `crates/ramflux-sdk/src/object.rs:574`, `crates/ramflux-sdk/src/object.rs:607` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_relay.recipient_device.v2` | `crates/ramflux-crypto/src/device_reference.rs:114` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_relay.retention_metadata.v1` | `crates/ramflux-node-core/src/relay/chunk.rs:308` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_relay.tombstone.v3` | `crates/ramflux-sdk/src/client/object.rs:1304` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.object_relay_tombstone.test.v1` | `crates/ramflux-node-core/src/tests/stores.rs:1030`, `crates/ramflux-node-core/src/tests/stores.rs:1182`, `crates/ramflux-node-core/src/tests/stores.rs:1415`, `crates/ramflux-node-core/src/tests/stores.rs:1464` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.object_transfer_error.v1` | `crates/ramflux-sync/src/object_store.rs:655` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.operation.v1` | `crates/ramflux-sdk/src/bus/mutations.rs:54` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.own_contact.parked.v1` | `crates/ramflux-sdk/src/client/own_contact/backfill_retry.rs:10` | Retain cited ownership/idempotency/storage hash in its current module; peer data uses typed Control/Receipt/HistoryItem instead of string dispatch. |
| `ramflux.own_device.history.v1` | `crates/ramflux-sdk/src/client/identity_authority/custody_lifecycle_tests.rs:192` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.own_device.import_receipt.v1` | `crates/ramflux-sdk/src/client/own_device_sync.rs:338` | Retain cited ownership/idempotency/storage hash in its current module; peer data uses typed Control/Receipt/HistoryItem instead of string dispatch. |
| `ramflux.own_device.restore_skip.v1` | `crates/ramflux-storage/src/account_db/group_snapshot.rs:58` | Retain cited ownership/idempotency/storage hash in its current module; peer data uses typed Control/Receipt/HistoryItem instead of string dispatch. |
| `ramflux.own_group.lazy_group.v1` | `crates/ramflux-sdk/src/client/own_group_lazy_authority.rs:17` | Retain cited ownership/idempotency/storage hash in its current module; peer data uses typed Control/Receipt/HistoryItem instead of string dispatch. |
| `ramflux.owner_authorization_proof.binding.v3` | `crates/ramflux-node-core/src/relay/authorization.rs:49`, `crates/ramflux-sdk/src/client/object.rs:1325`, `crates/ramflux-sdk/src/client/object.rs:2684` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.owner_authorization_proof.v3` | `crates/ramflux-node-core/src/relay/authorization.rs:43`, `crates/ramflux-protocol/src/object_relay_v3.rs:27` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.perf.d1.microbench.v1` | `crates/ramflux-transport/examples/relay_quic_bench.rs:751` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.perf.d1.payload.v1` | `crates/ramflux-transport/examples/relay_quic_bench.rs:37` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.pre_auth_cookie.v1` | `crates/ramflux-node-core/src/gateway_state.rs:471` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.push_alias.v1` | `crates/ramflux-protocol/src/domain.rs:52` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.receipt.actor.v3` | `crates/ramflux-storage/src/account_db/conversation_projection.rs:85` | Retain cited ownership/idempotency/storage hash in its current module; peer data uses typed Control/Receipt/HistoryItem instead of string dispatch. |
| `ramflux.receipt.visible_id.v1` | `crates/ramflux-sdk/src/bus/dispatch/message.rs:614` | Retain cited ownership/idempotency/storage hash in its current module; peer data uses typed Control/Receipt/HistoryItem instead of string dispatch. |
| `ramflux.received.object.sender.v2` | `crates/ramflux-sdk/src/client/deferred_attachment.rs:597` | Retain cited ownership/idempotency/storage hash in its current module; peer data uses typed Control/Receipt/HistoryItem instead of string dispatch. |
| `ramflux.received.slot.selector.v2` | `crates/ramflux-sdk/src/client/deferred_attachment.rs:646` | Retain cited ownership/idempotency/storage hash in its current module; peer data uses typed Control/Receipt/HistoryItem instead of string dispatch. |
| `ramflux.recovery_quorum_proof.v1` | `crates/ramflux-node-core/src/lifecycle.rs:249`, `crates/ramflux-sdk/src/client/recovery.rs:601` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.registration_pow.v1` | `crates/ramflux-protocol/src/domain.rs:71` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.registration_trust_tier.v1` | `crates/ramflux-protocol/src/domain.rs:72` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.requester_proof_of_possession.v3` | `crates/ramflux-node-core/src/relay/authorization.rs:44`, `crates/ramflux-protocol/src/object_relay_v3.rs:28` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.retention.dev_node_signing_seed.v1` | `crates/ramflux-node-core/src/retention.rs:623` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.safety_number.group.v1` | `crates/ramflux-crypto/src/key_verification.rs:137`, `docs/root_key_custody_wire.md:153` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.safety_number.v1` | `crates/ramflux-protocol/src/domain.rs:69` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.sdk.v1` | `crates/ramflux-sdk/src/bus/dispatch/group/native_contract_tests.rs:28`, `crates/ramflux-sdk/src/bus/dispatch/group/native_selector_tests.rs:93`, `crates/ramflux-sdk/src/bus/dispatch/shared_group_sibling_tests.rs:117`, `crates/ramflux-sdk/src/bus/dispatch/surface_transport.rs:41`, `crates/ramflux-sdk/src/bus/group_conversation/tests.rs:125`, `crates/ramflux-sdk/src/bus/group_conversation/tests.rs:240`, `crates/ramflux-sdk/src/bus/shared_group_sync/native_tests.rs:31`, `crates/ramflux-sdk/src/bus/shared_group_sync/native_tests.rs:53` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.selected_evidence.v1` | `crates/ramflux-node-core/src/franking.rs:89` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.shared_group.sender_key.v1` | `crates/ramflux-sdk/src/group.rs:134` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.signed_request.replay.v2` | `crates/ramflux-protocol/src/core_types.rs:122` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.signed_request.v1` | `apps/ramflux-gateway/src/push_registration_tests.rs:12`, `apps/ramflux-gateway/src/push_registration_tests.rs:12`, `apps/ramflux-gateway/src/session.rs:1868`, `apps/ramflux-gateway/src/session.rs:1868`, `apps/ramflux-gateway/src/session.rs:2209`, `apps/ramflux-gateway/src/session.rs:2211`, `apps/ramflux-gateway/src/session.rs:2295`, `apps/ramflux-gateway/src/session.rs:2297`, `apps/ramflux-gateway/src/session_resilience_tests.rs:208`, `apps/ramflux-gateway/src/session_resilience_tests.rs:208`, `apps/ramflux-gateway/src/submit_ack_tests.rs:461`, `apps/ramflux-gateway/src/submit_ack_tests.rs:461`, `crates/ramflux-node-core/src/custody_service/admission.rs:260`, `crates/ramflux-node-core/src/tests/helpers.rs:485`, `crates/ramflux-node-core/src/tests/helpers.rs:487`, `crates/ramflux-node-core/src/tests/helpers.rs:789`, `crates/ramflux-node-core/src/tests/helpers.rs:791`, `crates/ramflux-protocol/fixtures/protocol/v1/signed_request/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/signed_request/fixture.canonical:1`, `crates/ramflux-protocol/fixtures/protocol/v1/signed_request/fixture.json:5`, `crates/ramflux-protocol/fixtures/protocol/v1/signed_request/fixture.json:11`, `crates/ramflux-protocol/fixtures/protocol/v1/signed_request/negative.invalid_signature.json:5`, `crates/ramflux-protocol/fixtures/protocol/v1/signed_request/negative.invalid_signature.json:11`, `crates/ramflux-protocol/fixtures/protocol/v1/signed_request/negative.replay.json:5`, `crates/ramflux-protocol/fixtures/protocol/v1/signed_request/negative.replay.json:11`, `crates/ramflux-protocol/src/domain.rs:12`, `crates/ramflux-sdk/src/custody/network.rs:428`, `crates/ramflux-sdk/src/gateway/engine.rs:116`, `crates/ramflux-sdk/src/gateway/engine.rs:118`, `crates/ramflux-sdk/src/gateway/helpers.rs:101`, `crates/ramflux-sdk/src/gateway/helpers.rs:103` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.source_ip_hash.v1` | `crates/ramflux-node-core/src/source_privacy.rs:62` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.source_ip_hash.v2` | `crates/ramflux-node-core/src/source_privacy.rs:38` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.storage.test.pin.v1` | `crates/ramflux-storage/src/account_db/journal/tests.rs:407` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.stream.a2ui.v1` | `crates/ramflux-sdk/src/bus/journal/mod.rs:73` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.supervisor.operation.v1` | `crates/ramflux-sdk/src/bus/lifecycle.rs:64` | Retain cited local API/persistence/idempotency owner; local messaging fields switch to generated MessageRequest/Update, no peer Inner sniffing. |
| `ramflux.surface.action_delivery.v1` | `crates/ramflux-sdk/src/client/surface/decision.rs:92`, `crates/ramflux-sdk/src/client/surface/decision.rs:125`, `crates/ramflux-sdk/src/client/surface/task_action_read.rs:38`, `crates/ramflux-sdk/src/client/surface/task_decision.rs:101` | Retain surface action delivery-id hash/idempotency responsibility; generated SurfaceCarrier.action, no wire discriminator. |
| `ramflux.surface.authored.v1` | `crates/ramflux-sdk/src/client/surface/authored.rs:10` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.surface.carrier.v2` | `crates/ramflux-protocol/src/domain.rs:51`, `crates/ramflux-sdk/src/client/surface/carrier.rs:99` | SurfaceCarrier event/action/original-action receipt; remove prefix/JSON codec; new typed signature domain in section 3.1. |
| `ramflux.surface.decision.v1` | `crates/ramflux-sdk/src/client/surface/decision.rs:17` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.surface.delivery.v1` | `crates/ramflux-sdk/src/client/surface/delivery.rs:63`, `crates/ramflux-sdk/src/client/surface/delivery.rs:162`, `crates/ramflux-sdk/src/client/surface/projection.rs:198` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.surface.error.v1` | `crates/ramflux-sdk/src/client/surface/projection.rs:218` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.surface.history_page.v1` | `crates/ramflux-sdk/src/client/surface/own_history.rs:213` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.surface.identity.v1` | `crates/ramflux-sdk/src/client/surface/scope.rs:15` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.surface.pending_author.v1` | `crates/ramflux-sdk/src/client/surface/pending.rs:29`, `crates/ramflux-sdk/src/client/surface/pending.rs:50` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.surface.pending_delivery.v1` | `crates/ramflux-sdk/src/client/surface/pending.rs:33` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.surface.storage_key.v1` | `crates/ramflux-sdk/src/client/surface/mod.rs:104` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.surface.timeline.v1` | `crates/ramflux-sdk/src/client/surface/control.rs:334` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.sync.attachment.v1` | `crates/ramflux-sdk/src/bus/attachment_scheduler.rs:48` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.sync_batch.v1` | `crates/ramflux-sync/src/object_store.rs:1061`, `crates/ramflux-sync/src/object_store.rs:1635` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.task.approval.decision.v1` | `crates/ramflux-sdk/src/client/task/approval.rs:184`, `crates/ramflux-sdk/src/client/task/approval.rs:282`, `crates/ramflux-sdk/src/client/task/approval_retention.rs:131` | Retain approval decision-id derivation; TaskApprovalPayload.decision, not an alternate wire message. |
| `ramflux.task.approval.request.v1` | `crates/ramflux-sdk/src/client/task/approval.rs:67` | Retain approval request-id derivation; TaskApprovalPayload.request, not an alternate wire message. |
| `ramflux.task.approval.v1` | `crates/ramflux-sdk/src/client/task/approval.rs:51` | TaskApprovalPacket with Request/Decision typed payload; remove prefix/JSON packet/signature transcript. |
| `ramflux.task.archived_certificate.v1` | `crates/ramflux-sdk/src/client/task/checkpoint.rs:26` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.task.carrier.v1` | `crates/ramflux-sdk/src/client/task/carrier.rs:27` | TaskCarrier typed fields and new signature domain; remove prefix/JSON carrier. |
| `ramflux.task.committed_intent.v1` | `crates/ramflux-sdk/src/client/task/certificate.rs:54` | Replaced carrier digest transcript specified in section 3.1; no prefix bytes hashed on new wire. |
| `ramflux.task.courier.dead.v1` | `crates/ramflux-sdk/src/bus/task_courier_queue.rs:79` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.task.courier.failure.v1` | `crates/ramflux-sdk/src/bus/task_courier_apply.rs:144` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.task.courier.row.v1` | `crates/ramflux-sdk/src/bus/task_courier_queue.rs:55` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.task.decision_ack.v1` | `crates/ramflux-sdk/src/client/task/control.rs:47` | TaskAck with original typed TaskCarrier, TaskCertificate and manifests; replace changed signature transcript per section 3.1. |
| `ramflux.task.decision_certificate.v1` | `crates/ramflux-sdk/src/client/task/certificate.rs:37` | TaskCertificate all eleven fields; replace changed signature transcript per section 3.1. |
| `ramflux.task.delivery.v1` | `crates/ramflux-sdk/src/client/task/projection.rs:145`, `crates/ramflux-sdk/src/client/task/projection.rs:219` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.task.external_decision.v1` | `crates/ramflux-sdk/src/client/task/decision.rs:32` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.task.history_prefix.v1` | `crates/ramflux-sdk/src/client/task/own_history.rs:380` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.task.private_evidence.v1` | `crates/ramflux-sdk/src/client/task/decision.rs:122` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.task.storage.v1` | `crates/ramflux-sdk/src/client/task/mod.rs:56` | Retain cited surface/task owner hash, storage or courier idempotency domain (not a wire constructor); typed Kind 9/10 owns its application data. |
| `ramflux.task_event.v1` | `crates/ramflux-protocol/src/domain.rs:74`, `crates/ramflux-protocol/src/tasks/event.rs:11`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:7`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:7`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:13`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:13`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:19`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:19`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:25`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:25`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:31`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:31`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:37`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:37`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:43`, `crates/ramflux-protocol/tests/snapshots/task_goldens__task_events_v1.snap:43` | TaskCarrier.event / TaskEventBody (all seven arms); retain native signature rules/limits, remove wire JSON ingress. |
| `ramflux.test.account.root.v1` | `crates/ramflux-sdk/src/bus/own_contact_backfill/tests.rs:30`, `crates/ramflux-sdk/src/bus/runtime_tests.rs:170`, `crates/ramflux-sdk/src/bus/runtime_tests/group_actor.rs:15` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.test.foreign.root.v1` | `crates/ramflux-node-core/src/tests/federation.rs:943` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.test.grantee_root.v1` | `crates/ramflux-sdk/src/object.rs:1067` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.test.group.identity.v1` | `crates/ramflux-sdk/src/client/group_tests.rs:58` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.test.group.member.v1` | `crates/ramflux-sdk/src/bus/dispatch/group.rs:1636` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.test.group.prekey.v1` | `crates/ramflux-sdk/src/client/group_tests.rs:62` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.test.group.root.v1` | `crates/ramflux-sdk/src/client/group_tests.rs:31` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.test.read_model.root.v1` | `crates/ramflux-sdk/src/bus/read_model/tests.rs:10` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.test.registration_root.v1` | `apps/ramflux-router/src/router_runtime.rs:960`, `apps/ramflux-router/src/router_runtime.rs:1100`, `crates/ramflux-node-core/src/tests/helpers.rs:26`, `crates/ramflux-node-core/src/tests/helpers.rs:189`, `crates/ramflux-node-core/src/tests/server_retention_r3.rs:39`, `crates/ramflux-node-core/src/tests/session_authority_refresh.rs:39` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.test.remote.identity.v1` | `crates/ramflux-sdk/src/client/identity_authority/test_support.rs:135` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.test.remote.prekey.v1` | `crates/ramflux-sdk/src/client/identity_authority/test_support.rs:139` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.test.remote.root.v1` | `crates/ramflux-sdk/src/client/identity_authority/test_support.rs:131`, `crates/ramflux-sdk/src/client/own_device_sync/tests/stale_group_snapshot_tests.rs:68`, `crates/ramflux-sdk/src/client/own_device_sync/tests/stale_group_snapshot_tests.rs:652` | Retain cited test/benchmark domain only; any fixture of a retired codec is rewritten to its generated constructor; no production Inner dispatch. |
| `ramflux.test.runtime.agreement.v1` | `apps/ramflux-router/src/router_runtime.rs:1110` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.test.runtime.device.v1` | `apps/ramflux-router/src/router_runtime.rs:970`, `apps/ramflux-router/src/router_runtime.rs:1104`, `apps/ramflux-router/src/router_runtime.rs:1202` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.voice.rebind.v1` | `crates/ramflux-crypto/src/voice_rebind.rs:22`, `docs/voice-calls.md:133` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.well_known_client.v1` | `crates/ramflux-protocol/src/client_discovery.rs:9` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.well_known_server.v1` | `apps/ramflux-federation/src/discovery.rs:104`, `crates/ramflux-node-core/src/federation_crypto.rs:166`, `crates/ramflux-node-core/src/tests/helpers.rs:640` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.x3dh.initial_secret.v1` | `crates/ramflux-protocol/src/domain.rs:55` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |
| `ramflux.x3dh.prekey_bundle.v1` | `crates/ramflux-protocol/src/domain.rs:54` | Retain cited native service, crypto, storage or identity domain in its current owner; outside application Inner numbering, never a new body discriminator. |

### 8.4 Every byte-prefix match and its decode path

Reproduce the reviewer audit with
`git grep -n -E 'b"ramflux\.[a-z_.]+v[0-9]+' <base>`.
Classify the complete output, including non-carrier crypto/storage/service/test
domains, instead of silently filtering them out. The table has one row per exact
byte literal, with every occurrence and the corresponding application decoder
when one exists. All twelve application prefixes (including the v1 legacy
refusal) lose their wire encoders/decoders at reset.

| Exact byte literal (escaped terminator) | All baseline locations | Replacement / disposition | Decoder replaced / retained owner |
|---|---|---|---|
| `ramflux.account_db_kek.v2` | `crates/ramflux-sdk/src/client/account.rs:314` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.account_db_key.v1` | `crates/ramflux-storage/src/encryption.rs:53` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.account_db_key.wrap.v1` | `crates/ramflux-storage/src/encryption.rs:232`, `crates/ramflux-storage/src/encryption.rs:249` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.backup.staging.database.v1` | `crates/ramflux-sdk/src/bus/backup_jobs/workers.rs:559` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.backup.staging.metadata.v1` | `crates/ramflux-sdk/src/bus/backup_jobs/format.rs:181`, `crates/ramflux-sdk/src/bus/backup_jobs/format.rs:200` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.call.control.v1\n` | `crates/ramflux-sdk/src/client/call/mod.rs:14` | Kind 11 Call.control (13 CallAction variants) | `crates/ramflux-sdk/src/client/call/mod.rs:40` |
| `ramflux.contact_request.id.v1` | `crates/ramflux-crypto/tests/fixtures/contact_consent_v2_reference.py:22` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.crypto.batch_test.v1:` | `crates/ramflux-crypto/tests/ed25519_batch.rs:51` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.gateway.resume_token.v1` | `crates/ramflux-node-core/src/gateway_state.rs:396` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.identity.custody_signed_prekey.v1` | `crates/ramflux-sdk/src/custody/vault.rs:279` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.identity.device_agreement_key.v1` | `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:75` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.identity.device_signing_key.v1` | `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:74` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.identity.master.v1` | `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:47` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.identity.root_public_key.commitment.v1` | `crates/ramflux-crypto/tests/fixtures/custody_v3_reference.py:52` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.identity.safety_number.v2\0` | `crates/ramflux-crypto/src/custody/safety.rs:45` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.mesh.postcard.v1\0` | `crates/ramflux-transport/src/compio_mesh.rs:17`, `crates/ramflux-transport/src/mesh_quic.rs:50` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.notify.route_control.v1\0` | `crates/ramflux-node-core/src/service_signing.rs:64`, `crates/ramflux-node-core/src/service_signing.rs:96` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.notify.route_delete.v1\0` | `crates/ramflux-node-core/src/service_signing.rs:71`, `crates/ramflux-node-core/src/service_signing.rs:83` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.notify.routes.v1\0` | `crates/ramflux-node-core/src/notify/routes.rs:15` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.notify.verify_bench.v1:` | `crates/ramflux-crypto/tests/ed25519_verify_bench.rs:72` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |
| `ramflux.own_contact.v1\n` | `crates/ramflux-sdk/src/client/identity_authority/custody_lifecycle_tests.rs:186`, `crates/ramflux-sdk/src/client/own_contact.rs:16`, `crates/ramflux-sdk/src/client/routed/contact_request_tests.rs:421`, `crates/ramflux-sdk/src/client/routed/recipient_context_tests.rs:45` | Control.own_contact_sync (6); all ingress/backfill/restore paths | `crates/ramflux-sdk/src/client/own_contact.rs:72`, `crates/ramflux-sdk/src/client/own_contact.rs:416` |
| `ramflux.own_contact_tombstone.v1\n` | `crates/ramflux-sdk/src/client/contact_event_id_tests.rs:94`, `crates/ramflux-sdk/src/client/identity_authority/tests.rs:553`, `crates/ramflux-sdk/src/client/own_contact/tombstone.rs:9` | Control.own_contact_tombstone (13), sticky same-root restrictions | `crates/ramflux-sdk/src/client/own_contact/tombstone.rs:18`, `crates/ramflux-sdk/src/client/own_contact/tombstone.rs:51` |
| `ramflux.own_device_message.v1\n` | `crates/ramflux-sdk/src/client/own_device_copy.rs:315` | Remove legacy refusal/decoder branch on v3 reset; no v1 compatibility | `crates/ramflux-sdk/src/client/own_device_copy.rs:315` |
| `ramflux.own_device_message.v2\n` | `crates/ramflux-sdk/src/client/own_device_copy.rs:15` | Control.own_message_copy (15), verified original exact Inner; no extra SDK body/key-slot codec | `crates/ramflux-sdk/src/client/own_device_copy.rs:318` |
| `ramflux.own_group_consent.v1\n` | `crates/ramflux-sdk/src/client/shared_group/own_consent.rs:10` | Control.own_group_consent (14) with typed signed snapshot/decision | `crates/ramflux-sdk/src/client/shared_group/own_consent.rs:142` |
| `ramflux.surface.control.v1\n` | `crates/ramflux-sdk/src/client/surface/control.rs:11` | Kind 9 Surface.delivery; typed peer/own, epoch, context, manifests | `crates/ramflux-sdk/src/client/surface/control.rs:164`, `crates/ramflux-sdk/src/client/surface/control.rs:178` |
| `ramflux.surface.v2\n` | `crates/ramflux-sdk/src/client/surface/carrier.rs:9` | Kind 9 Surface.delivery.carrier (event/action/action_receipt) | `crates/ramflux-sdk/src/client/surface/carrier.rs:140` |
| `ramflux.task.approval.v1\n` | `crates/ramflux-sdk/src/client/task/approval.rs:13` | Kind 10 Task.approval; typed Request/Decision, grant signature | `crates/ramflux-sdk/src/client/task/approval.rs:160` |
| `ramflux.task.control.v1\n` | `crates/ramflux-sdk/src/client/task/control.rs:10` | Kind 10 Task.control; typed Intent/Ack, certificates/manifests | `crates/ramflux-sdk/src/client/task/control.rs:130` |
| `ramflux.task.own.v1\n` | `crates/ramflux-sdk/src/client/task/own_history.rs:11` | Kind 10 Task.own_history; complete witnessed history/context/pins/base/prefix | `crates/ramflux-sdk/src/client/task/own_history.rs:152`, `crates/ramflux-sdk/src/client/task/own_history.rs:307` |
| `ramflux.task.v1\n` | `crates/ramflux-sdk/src/client/task/carrier.rs:9` | Kind 10 Task.carrier (7 TaskEventBody variants) | `crates/ramflux-sdk/src/client/task/carrier.rs:75` |
| `ramflux.voice.rebind.v1` | `crates/ramflux-crypto/src/voice_rebind.rs:22` | Retain independently owned crypto/storage/service/test domain; not an application byte-prefix carrier. | Cited owner; no Inner decode path. |

The broad string-form grep also finds these version-labelled domain suffixes;
none is an application carrier. Escaped JSON fixture text refers back to the
corresponding base literal in section 8.3, not a new wire constructor.

| Remaining string form | Baseline source | Retained disposition |
|---|---|---|
| `ramflux.notify.route_owner.v1\0{target}` | `crates/ramflux-node-core/src/notify/route_authority.rs:32` | Notify route-owner hash input; native node owner |
| `ramflux.object_relay.v3.get.body` | `crates/ramflux-sdk/src/client/object.rs:2221`, `crates/ramflux-sdk/src/client/object.rs:2510` | Relay request-body hash domain; native object service |
| `ramflux.object_relay.v3.ack.body` | `crates/ramflux-sdk/src/client/object.rs:2298`, `crates/ramflux-sdk/src/client/object.rs:2608` | Relay ACK-body hash domain; native object service |
| `ramflux.group.sender_key.v1\|{group_id}\|{sender_id}\|{epoch}` | `crates/ramflux-sdk/src/group.rs:295` | Legacy group associated-data derivation; primitive adapter owns retirement, never Inner dispatch |
| `ramflux.object_key_slot.v1\|{object_id}\|{conversation_id}\|{recipient_device_id}` | `crates/ramflux-sdk/src/object.rs:234` | Legacy slot associated-data derivation; MediaKeySlot/native crypto adapter owns retirement |

### 8.5 Remaining decoder, projection and history entry points

These are additional guards/readers beyond the defining decode function. The
first table accounts for the PREFIX-recognition grep over all crates/ and apps/,
including retained non-message prefixes, so a retained guard
cannot silently route a new protobuf packet back to a removed decoder. Test
recognizers are removed/replaced with their constructor fixtures too.

| Baseline recognition site | Replacement |
|---|---|
| `apps/ramflux-gateway/src/itest_http.rs:257` | Retain native custody history HTTP path routing; not an application Inner decoder. |
| `apps/ramflux-gateway/src/quic_dispatch.rs:71` | Retain native custody history path routing; not an application Inner decoder. |
| `apps/ramflux-router/src/handlers.rs:129` | Retain native custody history path dispatch/parsing; not an application Inner decoder. |
| `apps/ramflux-router/src/handlers.rs:544` | Retain native custody history path dispatch/parsing; not an application Inner decoder. |
| `apps/ramflux-router/src/handlers.rs:1062` | Retain native custody history path dispatch/parsing; not an application Inner decoder. |
| `crates/ramflux-node-core/src/router_wal.rs:1339` | Retain WAL shard-directory name parser; not an application Inner decoder. |
| `crates/ramflux-sdk/src/bus/delivery_receipts.rs:111` | Retain local receipt-work key parsing; generated Receipt replaces wire content, not this storage key. |
| `crates/ramflux-sdk/src/bus/delivery_receipts.rs:204` | Retain local receipt-work key parsing; generated Receipt replaces wire content, not this storage key. |
| `crates/ramflux-sdk/src/bus/dispatch/surface_own_tests.rs:236` | Replace old own-copy prefix fixture recognition with generated Control.own_message_copy validation; S10a. |
| `crates/ramflux-sdk/src/bus/dispatch/surface_own_tests.rs:442` | Replace old own-copy prefix fixture recognition with generated Control.own_message_copy validation; S10a. |
| `crates/ramflux-sdk/src/bus/dispatch/surface_own_tests.rs:524` | Replace old own-copy prefix fixture recognition with generated Control.own_message_copy validation; S10a. |
| `crates/ramflux-sdk/src/bus/dispatch/surface_text_fixture.rs:32` | Replace own-copy fixture with generated Control.own_message_copy; S10a. |
| `crates/ramflux-sdk/src/bus/readers.rs:224` | Generated Content/UnsupportedView projection; never lossy UTF-8 of stored bytes; S10a. |
| `crates/ramflux-sdk/src/bus/tests/task_courier_fixture.rs:298` | Replace own-copy fixture with generated Control.own_message_copy; S10a. |
| `crates/ramflux-sdk/src/contact_card.rs:204` | Retain portable signed contact-card/link input codec; not an application Inner decoder. |
| `crates/ramflux-sdk/src/contact_card.rs:205` | Retain portable signed contact-card/link input codec; not an application Inner decoder. |
| `crates/ramflux-sdk/src/contact_card.rs:347` | Retain portable signed contact-card/link input codec; not an application Inner decoder. |
| `crates/ramflux-sdk/src/prekey.rs:199` | Retain native custody history request-path validation; not an application Inner decoder. |
| `crates/ramflux-sdk/src/client/call/mod.rs:40` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/identity_authority/tests.rs:592` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/own_contact.rs:72` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/own_contact.rs:416` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/own_contact/tombstone.rs:18` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/own_contact/tombstone.rs:51` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/own_device_copy.rs:315` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/own_device_copy.rs:318` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/routed/control.rs:231` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/routed/control.rs:232` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/routed/control.rs:233` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/routed/control.rs:238` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/routed/mod.rs:316` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/routed/receive.rs:26` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/routed/receive.rs:608` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/shared_group/own_consent.rs:142` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/surface/backfill.rs:18` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/surface/carrier.rs:140` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/surface/control.rs:164` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/surface/control.rs:178` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/surface/delivery.rs:17` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/task/approval.rs:160` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/task/carrier.rs:75` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/task/control.rs:130` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/task/own_history.rs:152` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/task/own_history.rs:307` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |
| `crates/ramflux-sdk/src/client/task/projection.rs:189` | Generated kind/typed-payload validation and original provenance; remove prefix gate (S10a). |

| Other baseline decoder / reader | Replacement / responsible implementation |
|---|---|
| `crates/ramflux-sdk/src/client/routed/control.rs:64` A2iControlEvent try-parse | Control.a2i=26; exact generated fields and native source binding; S10a |
| `crates/ramflux-sdk/src/client/routed/control.rs:93`, `crates/ramflux-sdk/src/client/routed/reset_work.rs:73` pair reset type strings | Control.reset/reset_ack, including rejected_bootstrap_floor; S10a |
| `crates/ramflux-sdk/src/client/routed/control.rs:119`, `crates/ramflux-sdk/src/client/routed/control.rs:143`, `crates/ramflux-sdk/src/client/contact.rs:666`, `crates/ramflux-sdk/src/client/contact.rs:754` friend.* / object.revoke_access | Control.friend (all five actions/full link fields) and Control.object_revoke (all five fields); preserve ownership checks; S10a |
| `crates/ramflux-sdk/src/client/contact_requests/native.rs:16`, `crates/ramflux-sdk/src/client/contact_requests/wire.rs:88` contact schema sniff | Control.contact_control selects custody Envelope<ContactConsentV2> directly; retire legacy consent v1 on v3 reset; S10a |
| `crates/ramflux-sdk/src/client/shared_group/controls.rs:17` group four-arm body JSON decode | Control.group_state → GroupControlBody Request/Result/DeviceSet/Transfer; typed federation route and transfer Probe/Head; S10a |
| `crates/ramflux-sdk/src/client/group_delivery.rs:62`, `crates/ramflux-sdk/src/client/group_delivery.rs:92`, `crates/ramflux-sdk/src/client/group_delivery.rs:408` group message/control/distribution try-parse | Message.sealed_group; Control.group_state/group_key_control with full distribution fields; S10a |
| `crates/ramflux-sdk/src/client/surface/resync_request.rs:10`, `crates/ramflux-sdk/src/client/surface/resync_request.rs:129` surface.resync.request.v1 | Surface.resync_request; every existing field mapped in section 3.1; author replies with typed snapshot; S10a |
| `crates/ramflux-sdk/src/client/own_device_sync.rs:9`, `crates/ramflux-sdk/src/client/own_device_sync.rs:42`, `crates/ramflux-sdk/src/client/own_device_history_pages.rs:12` sync/bundle/version switch | Control.own_history / HistoryPage and typed Task.own_history/Surface.delivery; details below; S10a |
| `desktop/crates/ramflux-desktop-sdk/src/translate/calls.rs:65` string-key call decoder | Generated CallControl/CallAction and public CallRow adapter; all 13 signals, S10c |
| `desktop/crates/ramflux-desktop-sdk/src/translate/tasks.rs:79` string-key task decoder | Generated TaskEvent/TaskEventBody/TaskCertificate public projection; S10c |
| `desktop/crates/ramflux-desktop-sdk/src/translate/task_events.rs:73` parse(text) recovery | Remove rendered-text recovery; generated Task typed update; S10c |
| `desktop/crates/ramflux-desktop-sdk/src/translate/surface_answers.rs:59` surface answer keys | Generated SurfaceAction/ActionReceipt projection with original requester binding; S10c |

History replacement is a reset, not a legacy bundle decoder. The old envelope's
principal/source/target/snapshot/times/nonce/signature become authenticated page
transfer id, qualified endpoints, expiry, previous digest and sender envelope
signature; history_ref/key-slot data becomes typed Message.media when an object
is needed. Old bundle messages/contents become exact Inner HistoryItems with
source evidence and explicit footprint bindings. task_packets and task export
cursor/truncation remain typed TaskOwnPacket pages; surface_pages/controls/
checkpoints and export cursor/truncation become typed Surface deliveries and
snapshot proofs. surface_message_epochs bind EventIdentity.group_epoch.
Groups/manifests/member pins/accepted contacts become their typed Control
operations and OwnContext proofs, with the same-root and current revocation
fences. next_page becomes page sequencing/cursor; authority_only becomes a
control-only page with no items. Saved dm_sessions and raw sender-key distribution
strings are retired from history: fresh pair sessions and typed authorized group
key controls establish crypto state. No archive may restore old live keys or
capability floors. This preserves messages, approvals and original authority
while removing the old wire codecs rather than carrying them as untyped bytes.

The mechanical checks compare all string and byte sets with `comm -3`, verify
every occurrence location and require every PREFIX recognition site above.
Section 12's removal audit repeats this inventory against the implementation:
zero active obsolete app decoders; retained domains still have their cited owner.

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

S10a also replaces S6's signed `Envelope.ext.delivery_mode` bridge with the
named outer delivery_mode field. Update SDK producers, gateway signature/AD
validation, router/federation/live writers and receiver ingress together under
the profile reset; remove bridge parsing/emission, reject old/dual-field input
on the new profile, and retain no compatibility or field-precedence shim.
Do not migrate queued ephemeral content into an inbox or durable retry.

### 9.2 Reader inventory before changing stored bytes

These are consumers, not merely writers. Inventory both the named keys and
physical table columns; search for `runtime_message_content`, `state_json`,
`body_json`, `response_json`, `runtime_unrouted`, `message_copy_binding`,
`own_device_history`, all section 8.4 carrier prefixes and every section 8 literal.
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
| Control | message; durable except known live-presence operation | Content.control; all 16 operation/typed-payload mappings in section 3.2, including A2I and object revoke |
| Surface | message, durable | Content.surface; SurfaceDelivery/ResyncRequest and every section 3.1 command/action/receipt; generated JsonValue data |
| Task | message, durable | Content.task; every TaskEventBody, approval Request/Decision, Intent/Ack and own-history field in section 3.1 |
| Call | Invite=call_wake durable; remaining 12 CallAction signals=message durable | Content.call.control; exact CallControl, allocation and consent; no ICE; verify invite before presentation |
| SelfSync | message, durable, same-root only | Content.selfSync; read/draft/pin/mute operation and revision |

### 10.2 S9 attachment fields

Message.media is ordered; each MediaRef has object_id, manifest_digest, mime_type,
size, key_slots, optional file_name, optional inline_thumbnail and large_manifest.
MediaKeySlot binds qualified recipient, crypto format and encrypted_key; no raw
object key is exposed in a generic UI update. Thumbnail carries mime_type, width,
height and encoded bytes; maximum encoded bytes is 16 KiB, dimensions
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

S6 initially receives the signed `Envelope.ext.delivery_mode` bridge defined
in Decision 6 (absent/durable -> durable; ephemeral -> transient; unknown ->
invalid). S10a replaces it with the required named signed/AEAD-bound outer
`delivery_mode = durable | ephemeral` field and removes the bridge at its
profile reset (section 9.1); no dual-field precedence or parallel transport.
For ephemeral, enforce low priority and the explicit signed bound
`1 <= ttl_seconds <= 5` integer seconds (default 5).
Decision 6 defines D = checked(created_at + ttl_seconds), exclusive deadline
D*1000, 2-second future tolerance and no grace; every hop/receiver verifies the
unchanged deadline before enqueue and again before delivery. Restarts never
renew it. Use a live-session queue of
at most 64 envelopes/256 KiB per target, and drop offline/expired/saturated input.
No inbox sequence, WAL, spool, persistence retry, dead letter or push record may
be created. Return a typed transient accepted/dropped outcome with no durability
claim; no scoped inbox ACK is allocated. Fields are sender signed/AEAD bound.
No plaintext typing bit, and no third class. Rate/admission limits still apply.
TTL validation occurs before any storage/enqueue decision. Receiver recognizes
Typing only after authentication/decryption. Its indicator lifetime is at most
5 s inside `[created_at, D)`; early transport acceptance within future tolerance
never starts display before created_at. At now_ms >= D*1000 emit a clear-state
transient update. Generic ephemeral mode leaks liveness urgency, not a claimed
application constructor. This node contract must be merged before S10a dispatch.

### 10.4 S12 API and native crypto

S12 depends on S3 plus complete S10. Consume MessageRequest, SendMessage,
MessageUpdate, Content and all typed nested descriptors directly. Preserve
request_id/account_id/operation_id and journal cursor across Rust, ProtoJSON,
UniFFI, C ABI and WASM adapters. Generated wrappers can add transport correlation,
not a second message schema or a stringly typed “payload” model. Business errors
remain typed codes (PeerUpgradeRequired, StorageCapacity,
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
| Negotiation | Signed native device max_layer with expiry/rollback/recovery; fresh-cohort minimum plus per-target F fallback on missing/expired declarations; membership recheck and safe kind/field downgrade |
| Semantics | All 12 kinds send/receive through generated dispatch; Edit/Delete/Reaction enforce authorization/revision/tombstone rules; same Message/Service identity/order; attachments, groups, receipts, calls, tasks and own history still work |
| Unknown input | Unknown kind, field, entity, nested signed payload or high layer commits Unsupported plus exact raw and provenance before ACK; bounded quota; no dead letter, NACK or action execution |
| Privacy | Every raw copy registers transactionally; crash/absence/race tests cover active, prepared, journal, nested group, archived and restored paths; history-container invalidation and object last-owner rules both pass |
| Typing acceptance | End-to-end typing send/receive uses S6 ephemeral mode, low priority, signed TTL bound 1..5 s and indicator lifetime at most 5 s inside the signed interval; offline/drop/expiry produce no inbox, WAL, spool, retry, dead-letter or push rows |
| Outer and reports | Exactly message/call_wake, uniform collapse_tag/report_commitment, named signed/AEAD-bound delivery_mode replaces the signed ext.delivery_mode bridge at reset; new profile rejects bridge/dual-field input; updated producers/consumers and node report flow |
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
push sizing; equal ciphertext lengths across every per-device copy of one
logical event, including differing layer representations and bootstrap overhead;
independent fixed vectors; no state mutation on rejected packets;
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
| D2/Q6, S10a | group_fresh_cohort_minimum; own_and_dm_fresh_minimum; layer_update_rejects_rollback | Ignore one fresh low-layer target; accept an older/equal-conflicting declaration; restore archive capability as live |
| D2/Q6, S10a | membership_change_rebuilds_unsubmitted_representation; downgrade_does_not_execute_structural_control | Skip membership recheck; turn Delete into executable text; admit a layer-1-only client below F=2 |
| H1/D2, S10a | offline_over_24h_still_receives_floor_in_dm_group_and_own_copy | Treat expired or missing declaration as LayerUnavailable; lower every fresh group/own target to F instead of only the stale member; assert stale member receives F, fresh members retain negotiated layer and logical id is shared |
| r3-M1/D2, S10a | stale_declaration_target_receives_and_executes_delete_and_edit | Set F=1 in S10a so Delete refuses or Edit becomes text; tie receive maximum to own declaration expiry so queued layer-2 Delete/Edit become Unsupported; each mutation separately fails across DM/group/own-copy, including stale sender with fresh target |
| r3-L1/D1, S10a | message_page_projects_generated_content_and_unsupported | Keep readers.rs prefix sniff/lossy UTF-8 of stored protobuf; known text and UnsupportedView projection assertions fail |
| H2, S10a | every_surface_command_patch_action_receipt_and_resync_round_trips | Drop any component/data-model/finality field or one of 6 commands/5 patches; remove original action signer binding; k2b must fail |
| H2, S10a | all_thirteen_call_actions_and_native_lease_fields_round_trip | Drop base_key, generation, allocation, consent signature or one action; call01 key agreement/rekey and state assertions fail |
| H2, S10a | every_task_event_approval_control_and_history_round_trips | Drop Proposal/Resolve, grant_signature, Intent/Ack certificate, history prefix or membership witness; k3b/k5a assertions fail |
| M2, S10a | every_control_operation_has_exactly_one_typed_payload | Substitute a different operation arm; drop A2I subject/domain, group Request federation route, DeviceSet epoch, Transfer arm or object revoke; exhaustive per-arm assertions fail |
| L2/D3, S10a | unsupported_source_budget_is_fair_and_node_expiry_is_visible | Charge by rotating device/conversation instead of root, let one source exceed 16 rows/8 MiB, stop other peers after source exhaustion or promise persistence after node TTL; fair-admission/expiry assertions fail |
| L3/Q3, S10a/S11 | conference_invite_maps_to_call_wake | Map ConferenceWakeNotification or a group-call wake invite to message; VoIP mapping assertion fails |
| L4, S10a | entity_unknown_is_projection_only_and_reaction_token_is_bounded | Accept removed Entity tag 5 for execution, render unknown numeric kind, accept 65-byte or two-grapheme reaction token; raw-retention and validation assertions fail |
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
| r3-L2/D5, S10b | per_device_copies_of_one_message_have_equal_ciphertext_lengths | Pad fresh/floor DM/group/own copies independently or omit bootstrap overhead compensation; unequal binary/base64 lengths fail; test exact caps and whole-event refusal on overflow |
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
| r3-L6/D9/Q5, S10a with S6 | typing_lifetime_at_most_five_seconds_and_ttl_is_bounded | Accept TTL 0 or 6, display future-dated input early, keep visible past D, or reset its interval on duplicate; ttl=1/5, ttl=0/6 refusal, future-tolerance and late-arrival assertions fail |
| r3-L6/Q5, S10a | named_delivery_mode_replaces_signed_ext_bridge_at_reset | Ignore the bridge signature, route unknown bridge value durably, retain bridge parsing after reset, or accept both fields with precedence; pre-reset absent/durable/ephemeral/invalid and post-reset bridge/dual-field rejection assertions fail |
| r3-S6/D9/Q5, S10a with S6 | ephemeral_signed_deadline_is_exclusive_across_hops_and_restarts | Renew TTL at a hop/restart, add grace at D, allow created_at > now+2, wrap deadline arithmetic, or promise at most one duplicate across repeated router/receiver restarts; boundary, skew and restart traces fail |
| D9/Q5, S10a | typing_is_generated_transient_content_not_plaintext_kind | Add plaintext typing field or third class; persist known Typing in history or retain it at/after the signed deadline |
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
schema-design round: floor 256, raw quota 64 rows/32 MiB with 16 rows/8 MiB per source anchor, maximum Inner 524,252,
mandatory crypto layer 3, live queue 64/256 KiB, TTL 5 seconds and bounded receive
ring/trials. Owner approval accepts those protocol/resource choices; changing
them before implementation requires updating this design and vectors together.
No unresolved choice is hidden behind a schema string or a guessed decoder.

Residuals: source/recipient/signature key and timing stay outer; call_wake and
ephemeral mode reveal urgency/category; stable collapse tags link conversation
traffic within a pair session; per-device fan-out reveals group size; padding
reveals buckets and has a small-message floor cost. Per-event fan-out cover
padding can exceed the individual Padme overhead bound. Bootstrap format/E are
observable; later agreement-key compromise reveals recorded capsule metadata.
Compromised endpoints, externally exported archives and remote recipients defeat
claims of global content erasure. Classical X25519/X3DH is not post-quantum.

| Residual | Boundary / consequence |
|---|---|
| Pre-S10b per-device size signal | S10a has no mandatory padding: different fresh/floor representations can reveal stale declarations or long-offline devices. S10b common-bucket padding closes this length signal; target count, timing and public bootstrap format remain observable. |
| Sender clock behind node | If lag is at least ttl, the exclusive signed deadline may already have passed and transient delivery (for example Typing) is lost. No grace or durable fallback repairs it. |
| Transient duplicates on restart | Router and receiver restarts can expose repeated duplicates within the remaining sender-signed lifetime; there is no at-most-one-duplicate guarantee. At/after D every hop rejects all copies; no transient history is created. |

Unknown authenticated content consumes local space and can cause explicit
backpressure, not unlimited storage or guaranteed ACK of unlimited input. Old
receive-key eviction bounds recovery; unlock/attended recovery remains necessary
when private providers are unavailable. A missing/expired layer declaration
only selects the per-target floor; it never blocks messaging. Group raw copies
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
