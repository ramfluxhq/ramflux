# S10a activation amendments: ordinary DM identity and ephemeral boundary

Adopts the final controller dispatches dated 2026-11-11 and their audit addenda.

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

S6c's no-client-database-write guarantee ends at authenticated ciphertext
handoff. S10a permits pair-ratchet and incarnation-wide allowance writes, and
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
pins remain separate. This policy follows sweep-2 audit H2/M7.

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

Controller OV-GROUP-OPENING (FINAL, audit r1 PASS 0/0/0, 2026-11-12) pins ordinary group-history
`group_opening` to exactly 64 raw bytes, opening_key[32] || commitment_key[32].
One shared native verifier recomputes every native franking hash/commitment over
the exact nested Message, signed sealed-group ciphertext/header and native AAD.
It wipes the supplied temporary opening on success and every refusal; no master
key or new author authority is conveyed. Edited original evidence still contains
no group opening or plaintext. The final audit requires native header byte equality and the native session-id:counter event id; AAD is reconstructed from the authenticated wrapper, never supplied by the caller. Its full signed-history/import/report/restore acceptance matrix remains mandatory.

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
