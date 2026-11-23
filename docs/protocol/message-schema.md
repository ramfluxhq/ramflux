<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026 Span Brain -->

# Message schema

This specification defines message identity, transient admission, Unsupported
views, private revision entropy and native group snapshot rules. The complete
wire grammar is [message.proto](../../crates/ramflux-protocol/src/message/schema/message.proto).
Storage profile requirements are described in [storage profile reset](../schema_profile_reset.md).

## Direct-message identity and transient delivery

An ordinary two-root DM uses `dm:` followed by unpadded base64url of the raw
32-byte BLAKE3 digest of `LP(domain) || LP(A) || LP(B)`, where the domain is
`ramflux.message.dm_conversation.v1`, LP is u32 big endian byte length followed
by exact bytes, and A/B are distinct verified canonical unpadded base64url
32-byte root anchors sorted by their encoded ASCII bytes. The transcript is
132 bytes (lengths 34/43/43). Neither principal names, device identities,
primary devices nor home/federation locations enter the transcript. The
shared protocol implementation and independent golden vector are in
`message::dm_scope`. Existing directional contact-request IDs are unchanged.

The entire `dm:` namespace is reserved, including malformed suffixes. Groups
cannot create, link, import, restore or repair into it. Known reserved direct
IDs must equal the derived pair ID and still satisfy their existing immutable
kind, group and participant-root bindings. New ordinary direct scopes require
the canonical ID. Creation and binding are transactional and preserve existing
erasure state. Same-root own controls and SelfSync may reference scopes;
they grant no permission to rebind them. Native CONTACT/GROUP_STATE bootstraps
retain their separate authority checks and cannot allocate conflicting
reserved scopes. The DM ID is public and offline matchable: it is neither a
clear routing field nor a replacement for keyed collapse tags.

The transport no-client-database-write guarantee ends at authenticated ciphertext
handoff. Endpoint admission permits pair-ratchet and incarnation-wide allowance writes, and
bounded unknown-content retention with original channel and authority. Known
Typing content remains volatile. Typing operation IDs are validated at 16–64
bytes, used only for correlation and bounded generation-owned duplicate
and cadence control, and bypass persistent operation reservation, response
capture and journal capture. Restart forgets them; duplicates never renew
signed lifetime. No ephemeral ACK, receipt ledger, durable retry or fallback
is permitted. Unknown retention charges all copies and metadata atomically
with ratchet/provenance state against the account and source quotas.

Signed lifetime D is measured in seconds; transport wrapper times are
milliseconds. Every Typing effect, including inactive clears, is gated by the
signed start and deadline. The whole pair-incarnation seal allowance never
refills through durable traffic, receive, submit, ACK, reconnect or elapsed
time; restore must not combine an older allowance with a newer ratchet.
`message.transient` uses sequence zero and no journal cursor or replay.

D ends delivery/display; it does not promise cryptographic erasure. Skipped
keys, backups and retained unknown plaintext can outlive D. Signed outer
identities, timestamps, mode, TTL and collapse correlation remain visible.

Reparse reapplies the authenticated original channel policy inside the installing
writer transaction. Recognizing a retained ephemeral kind cannot authorize a
Delete, Edit, Reaction, Receipt, SelfSync or native operation. Recognized Typing
is discarded without reconstructing durable content. Durable author Deletes
use verified original source evidence; LOCAL and moderator effects additionally
require current Sync or group permission. Both owner fences, provenance and the
erasure generation are checked before installation. Historical Message/Service
projection is cosmetic; Control/Call/Task/Surface never execute retroactively.
A Service does not execute a pin action. The v1 native pin action is unavailable
until a separate native authority and state contract exists; same-root SelfSync
pins remain separate.

The ratchet/allowance exception does not permit generic change-outbox rows.
Endpoint ephemeral admission commits crypto state and any bounded raw/provenance
retention together before returning a result. A quota or commit failure retains
neither partial raw evidence nor an advanced ratchet. Recognized non-Typing
input advances only the authenticated receive ratchet and creates no projection,
receipt, ACK or retry state. Retained future Edit/Reaction raw copies and native
opening evidence share the referenced target's erase fence. Endpoint origin
retention uses the shared strict v2 signature/evidence transcript; a legacy
ciphertext-bearing signature is never reinterpreted as body-free origin proof.

The native local `message.submit` Typing branch consumes generated
`MessageRequest.send.content.typing` before durable operation lookup/reservation
and response/event capture. `request_id` remains correlation-only. Within an
unlocked account generation a committed seal's operation id never creates a
fresh signed lifetime; an identical request returns its remembered transient
result, and a conflicting body is refused. Reopening the account forgets this
memory while retaining the persisted pair-incarnation allowance.

Native local `message.focus { conversation_id: string | null }` declares frontend
focus without writing storage or starting a connection. Switching/clearing focus
attempts one volatile clear for the old conversation. The account preference
`share_typing` defaults on and gates sending. Sender state uses the existing
64-scope/256-KiB transient resource bounds; cadence and rate use the adopted
4,000-ms and 20-per-60-second limits. A dropped/offline result suppresses that
target for 60 seconds or until authenticated peer progress; neither event resets
the pair allowance. Typing never triggers generic command network preparation,
courier wake, outbox publication, gateway-resume persistence or response capture.

The SDK account owns volatile receive state. Its live-source owner resets held,
visible, deduplication and queued updates on source-generation loss; unlock also
starts empty. A successfully committed durable Message clears the verified
original author's visible indicators in its conversation. A failed writer
transaction cannot clear them or count as received peer progress.

The shared transient binding codec accepts only Typing content, a 32-byte opaque
nonce, zero device sequence/HLC and no group fields. Both `MessageUpdate` and the
`message.transient` event carry sequence zero. Live stream subscriptions register
this topic only after the subscribe acknowledgement; it has no journal replay.
The journal's central insertion path refuses this topic. Transient queue overflow
is lossy, preserves its subscriber and never changes the client's durable cursor.

Ordinary group-history
`group_opening` is exactly 64 raw bytes, opening_key[32] || commitment_key[32].
One shared native verifier recomputes every native franking hash/commitment over
the exact nested Message, signed sealed-group ciphertext/header and native AAD.
It wipes the supplied temporary opening on success and every refusal; no master
key or new author authority is conveyed. Edited original evidence still contains
no group opening or plaintext. Verification requires native header byte equality and the native session-id:counter event id; AAD is reconstructed from the authenticated wrapper, never supplied by the caller. These checks apply to signed history, import, report and restore.

Group receipt captures both native per-message keys on the successful decrypt;
re-decryption is a replay, not an evidence-recovery operation. The original
v2 signature, custody authority, signed group snapshot, outer C and native
opening are checked together. Reparse uses that retained proof and exact nested
Message, without keeping a sender chain merely for reparse. It rechecks current
local/author group roles and the immutable conversation binding inside its writer.

Known content keeps private origin evidence under ordinary local-history policy;
Unsupported copies include it in their existing raw quota. Both use registered
message owners. Edit retirement removes the original origin, nested content,
prepared copies and whole cached pages in the same writer; a late original
opening cannot pass the retired-opening fence. Delete remains a sticky fence.
Original signed evidence may be selected only through explicit history/report
APIs; ordinary updates carry no report or group opening.

## Unsupported diagnostics and native control admission

Unsupported diagnostics use the first matching reason in this order:
`layer_above_supported`, `unknown_kind`, `unknown_field`, `unknown_enum`,
`unknown_entity`, `body_undecodable`, `identity_undecodable`.
These labels describe the decoder result and grant no authority. Malformed
wire, lifetime, consent, identity and native-operation checks remain admission
requirements. These diagnostics do not admit an otherwise refused input.

An Unsupported view backed by retained raw bytes exports a random 16-byte
`raw_handle`. Its source-qualified copy id remains in the local private mapping.
The mapping and view join the receive transaction and message erasure footprint.
Redelivery keeps the same handle. A successful reparse retires the handle with
its Unsupported view in the installing transaction. If channel policy instead
retires the raw bytes and keeps a non-actionable historical diagnostic, that
view's handle is empty and its private mapping is removed. Neither form contains
native execution authority or claims that an erased body remains available.

An Edit targeting an existing Unsupported placeholder waits for its Message
content just as an Edit targeting absent content does. Early-Edit registers are
qualified by the original author root as well as target id; an accepted peer in
another conversation cannot replace that author's register by naming its id.
When the verified original identity becomes available, foreign pending claims
are retired. Upgrade installation resolves the legitimate parked Edit in the
same writer transaction and publishes the resulting content in force, with the
original immutable identity and the actual journal cursor. It never publishes
an original preview that the winning Edit has just retired.

Generated native Controls finish their post-commit cache handling through the
typed decoder, including Unsupported controls that have no cache effect. They
never enter the retired application JSON cache parser. A generated Call refresh
uses the exact Inner's staged native transition after commit.

Friend action 1/3/4/5 requires the authenticated requester root; action 2 requires
the authenticated target root. The other root is local. Existing link endpoints
are immutable, and an acceptance requires an existing live local request or an
already accepted link. Actions call the existing native contact primitives.
Friend exact-repeat receipts use raw BLAKE3 over LP(domain) || LP(source device
storage key) || LP(exact Inner), with domain `ramflux.message.friend.applied.v1`;
the receipt contains no Message content. Other native Control executors require their own authority checks before execution.

## Private revision entropy

Layer 3 / profile floor 3 adds Message tag 17, `bytes erasure_nonce`: exactly 32
cryptographically random bytes on every plaintext Message and Edit replacement.
The SDK prepares this once per logical revision before recipient fan-out. Reuse
that prepared content or its exact encoded Inner for all recipients; each new
revision receives independent entropy. The sealed group wrapper carries no
nonce: it is inside the encrypted nested Message. Admission scans exact canonical wire before prost. Every committed plaintext
Message requires one `8a 01 20 || nonce[32]` field; duplicate, absent, empty,
wrong-length, wrong-wire-type and nonminimal encodings are refused. SelfSync
drafts forbid tag 17; draft validation is separate from committed content.
Public send/edit input cannot select the nonce. Nonce-free plaintext is refused
after activation; there is no older-profile fallback.

The exact previous-content digest transcript is unchanged. Its final LP field
contains the exact previous plaintext Message bytes including this nonce. This
prevents the retained digest from confirming guesses for erased short text
without the erased 256-bit entropy. Possession of the old nonce and public target
metadata still permits confirmation; a retained recipient copy or external old
backup cannot be recalled.

The nonce belongs to private body storage and encrypted peer/history transport.
Private Debug output is redacted. Ordinary renderer updates, journal/live/snapshot/replay/reparse updates, operation responses, public
bindings and body-free original headers omit
it. Edit retires every replaced body, nonce, opening and registered container in
one writer transaction. Delete and restore fences cover it exactly as the body.
A later replacement nonce must not be reused for an earlier revision.

Protobuf wire vector: text "yes", then tag17 varint `8a 01`, length `20`, then
bytes `00 01 ... 1f`. Nonce hashing, public sanitization, stale-copy retirement,
private history/reparse/restore, sibling digest agreement, competing edits and
transactional retirement/rollback follow the same revision and erasure rules.

## Native group snapshots

```proto
message GroupControlBodySnapshot {
  NativeGroupSnapshot snapshot = 1;
  optional GroupKeyDistribution distribution = 2;
}
// GroupControlBody.value: GroupControlBodySnapshot snapshot = 5;
```

The selected arm invokes the existing canonical GroupStateSnapshot codec and native verification/state machine. Its schema field is checked against the native fixed value; it never selects a different codec. Native issuer/transport, current directory and membership, state continuity/removal floors and invitation-consent checks remain mandatory. A sender omits the distribution for recipients outside the signed membership. A present distribution must match the authenticated issuer, group, snapshot epoch and state hash, and pass the existing native key authentication before installation. Required consent precedes membership, route, joined-floor and key installation. Working seed copies are zeroized; private retained native invitation/key material follows the existing lifecycle. A typed control that is Unsupported never applies its native action.

The snapshot is required, nonempty and exactly canonical native JSON (duplicate/unknown native keys refuse), verified before installation. Raw generated scanning enforces minimal encoding, ordered singleton fields and oneof presence before decoding. Unknown generated fields remain Unsupported and never execute. Every NativeGroupSnapshot canonical leaf, including Transfer, OwnContext, OwnGroupConsent and original/history evidence, has the native 98,304-byte bound; other native leaves retain 8,192 bytes. Encoded GroupKeyDistribution is bounded to 4,096 bytes before parsing. Inner aggregate/depth/frame limits still apply.

Typed distribution maps explicitly to native v3/v4 schema/version, with exactly32 seed bytes, transport sender equal to snapshot issuer, pinned signing key, group/epoch/state-head equality, native v4 seed-bound signature and native v3 same-head seed fence. Identical replay cannot rewind a receiver; a valid v4 fresh chain remains permitted. State reconciliation and eligible key import form one transaction, and import requires that snapshot hash remain the installed head and local membership be effective. Production sealing derives eligibility from the selected root/device plus verified directory and snapshot; terminal/nonmember recipients receive no seed. Removed previously joined recipients may install terminal state without keys. History evidence never installs live state; reparsing Control never executes it.
