# Automatic delivery receipts

An unlocked receiving daemon creates a private delivered receipt for each authenticated
peer DM or group message once its message projection is durably stored. No recipient UI
or explicit receipt request is required. The receipt intent, attribution and message
projection commit in the same SQLCipher account transaction before the inbox ACK.
Undecryptable, held or rejected messages do not claim delivery.

The receipt uses the existing encrypted device-pair envelope and receipt event format.
It targets only the authenticated sending device using its verified directory route.
Group receipts are not broadcast to other members or the sender's sibling devices.
Own messages and own-device copies never generate peer receipts. Read receipts retain
their existing explicit privacy/opt-in behavior; this mechanism never sends a read event.

## Durable retries

The durable key is `(conversation_id, message_id, receiving_device_id)`. A completed or
terminally failed key never schedules another automatic send on inbox replay or restart.
The prepared ciphertext is persisted before submission and reused after an uncertain ACK.
The peer's existing receipt replay guard deduplicates accepted retransmissions.
A receipt carries the authenticated transport envelope ID, even when the receiver's
local projection ID is scoped to avoid a collision. Before sending a DM/group packet,
the sender durably binds `(sending device, recipient device, envelope ID)` to its own
logical conversation/message. Incoming receipts resolve only through that binding or
an exact existing outbound message; unknown or inbound-only targets are refused before
receipt insertion. This handles per-recipient group wire IDs without suffix parsing.
The encrypted routing header, associated data and wire receipt format are unchanged.
Bindings are recorded for newly sent SDK-managed DM/group packets. Older packets whose wire and logical
IDs are identical retain exact-ID compatibility; an older unbound fan-out alias is
refused rather than guessed or retroactively bound.
The courier rechecks sender trust and the receiving device even for prepared packets;
revocation or root replacement retires that work without sending it.

Each sync pass scans at most 256 intents and attempts at most 16 due receipts,
checking a 250 ms work budget between jobs. Task retries/confirmations run first. A durable
round-robin key cursor prevents one page of backed-off entries hiding later work.
Intents may remain on disk with their messages; a receipt backlog never refuses or drops
an incoming message. Working memory and network attempts remain bounded.

A job has at most eight attempts and a ten-minute send lifetime. Failures back off for
2, 4, 8, 16, 32, then at most 60 seconds, measured after the failed attempt. A conservative
next-at timestamp is committed before I/O, so interruption/restart also respects backoff.
Connection acquisition, preparation and submission share a three-second I/O deadline. Expired/exhausted or trust-invalid
work is retired with a durable `message.delivery_receipt.failed` metadata event containing
conversation, message and receiving device. Failure never claims Delivered on the sender.
A deadline explicitly retires the uncertain session. A persisted thirty-second cooldown
prevents receipt-driven reconnects for other queued jobs; it does not delay ordinary sync.
A timestamp more than thirty seconds in the future is discarded, so a backwards wall-clock
step cannot extend the cooldown indefinitely.

Receipt statuses, outbound wire bindings and failed-receipt journal entries expire after
thirty days in bounded batches (at most 128 metadata rows and 128 failure events per sync
pass). Untimestamped legacy metadata gets thirty days from first observation. Failure to
sweep is logged and never aborts synchronization. Journal pruning preserves gap detection.
Message origin attribution is never swept: it survives with the message and is removed
through message deletion/tombstones, independently of receipt status. Origins enrolled
by older receipt retention ledgers are also protected.

Deleting a message prevents any new receipt work and erases its message-origin record.
Receipt work that was already pending may temporarily retain the peer routing address
needed to finish the authenticated receipt. The courier removes that work after it is
sent, terminally fails, or expires under the bounds above; it is never a message-history
or export surface.

## Client compatibility and attribution

`message.receipt.delivered` remains accepted. It is an idempotent no-op for `pending`
and `sent` automatic work. For `failed` work, an explicit request by the owned receiving
device re-stages the stored authenticated intent with a fresh eight-attempt/ten-minute
budget; the courier still rechecks sender trust and root before sending. Replaying the
inbox does not automatically re-stage failures. The response adds `delivery_receipt_state`
(`pending`, `sent`, `failed`) and `already_sent`; its scope is `network_e2ee` after
submission and `daemon_queue` otherwise. Client-supplied routing never replaces the saved
intent. Once retention removes a status, the existing legacy explicit path is available
again, using retained attribution and current authenticated routing.

`message.read` / `message.list` rows and received-message journal rows add:

- `sender_device_id`: the authenticated sending device identifier.
- `sender_root_commitment`: its verified root commitment.
- `sender_device_display`: `<device label or device id>@<full root commitment>`.

The display is only a label, never a routing address. Clients should use the separate
identity fields for per-device state. Older/unattributed rows use null rather than a
guessed device or root. Received peer attribution is retained from the original commit,
independent of later directory labels or routing updates.
