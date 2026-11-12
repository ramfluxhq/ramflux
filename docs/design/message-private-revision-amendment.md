# Private revision entropy (S10a activation amendment)

Controller OV-EDIT-DIGEST-ERASURE, adopted 2026-11-12, final with EDIT-DIGEST-NONCE-AUDIT-r1 corrections.

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
bytes `00 01 ... 1f`. Tests pin this independent grammar and wrong lengths, public
redaction/header independence, fan-out identity, fresh entropy and calibrated
{no,yes,maybe} guessing behavior. Break-the-fix removes nonce bytes from the real
production digest and must make the guessing-resistance assertion fail.

Acceptance includes nonce hashing, public sanitization and stale-copy production
break-the-fix checks, private history/reparse/restore round trips, sibling digest
agreement, competing edits and transactional retirement/rollback.
