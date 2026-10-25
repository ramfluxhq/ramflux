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

## Client compatibility and attribution

`message.receipt.delivered` remains accepted. Once an automatic intent exists, this
method is an idempotent no-op, including while that intent is pending. The response adds
`delivery_receipt_state` (`pending`, `sent`, `failed`) and `already_sent`; its scope is
`network_e2ee` after submission and `daemon_queue` otherwise. It does not bypass the retry
budget or replace the prepared packet with client-supplied routing. The legacy explicit
path remains available for messages without an automatic intent.

`message.read` / `message.list` rows and received-message journal rows add:

- `sender_device_id`: the authenticated sending device identifier.
- `sender_root_commitment`: its verified root commitment.
- `sender_device_display`: `<device label or device id>@<full root commitment>`.

The display is only a label, never a routing address. Clients should use the separate
identity fields for per-device state. Older/unattributed rows use null rather than a
guessed device or root. Received peer attribution is retained from the original commit,
independent of later directory labels or routing updates.
