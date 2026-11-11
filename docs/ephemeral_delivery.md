<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Ephemeral delivery

Ephemeral envelopes carry short-lived encrypted events to an already live
recipient on the same node. They use the signed `ext.delivery_mode="ephemeral"`
bridge, the existing opaque-event class, low priority and a TTL of 1–5 seconds.
The SDK signs both `gateway.session_push.v1` and `gateway.ephemeral.v1` in the
capability scope. Authenticated router discovery controls the gateway echo and
per-registration capability. The gateway intersects both signed client claims
with router readiness; a client claim alone cannot enable the channel, and a
session-push-only client never receives an ephemeral echo.
The public SDK send and receive APIs are unchanged. Activation applies to fresh
sessions; restart or reconnect to renegotiate existing sessions.

## Session ownership and ciphertext consumer

`GatewaySessionAccess::submit_ephemeral` submits once through the account's resident
session host and its generation fence. The internal `ExpectedReply::EphemeralSubmit`
wait carries incoming events and correlates the result envelope ID. A foreign
result retires the session; no ephemeral failure enters the durable retry path.
The existing synchronous `send_ephemeral` / `EphemeralWire` codec API is unchanged.

Take `GatewaySessionAccess::take_ephemeral_consumer` for the account generation.
Only one consumer may exist at a time; dropping it releases the lease and pending
work while retaining live dedup, so cancellation permits safe reattachment.
Its `EphemeralConsumer::next` resolves active signing authority through the caller's
root/device lookup, authenticates original frame bytes and returns ciphertext plus
the signed deadline. The resolver must enforce authenticated membership and
revocation before supplying `EphemeralSource`; the consumer independently checks
that the source root and literal device match the envelope. Call `complete` after
the handoff. Pending raw frames, Holds, queued and in-flight ciphertext share one
64-frame / 262,144-byte budget; ephemeral frames bypass generic subscriptions and
the durable delivery buffer. The consumer polls Holds on a timer even when no new
packet arrives. Disconnect clears pending work and preserves live same-generation
dedup; account lock/stop or generation replacement clears all state and closes the
old consumer.

## Results and compatibility

The sender validates mode and lifetime, then checks both echoed capabilities
before writing a frame. Missing echo produces local unsupported. A new router
refuses a recipient registered by an old gateway with `recipient_unsupported`.
A new gateway connected to an old router cannot negotiate ephemeral delivery.
There is no durable fallback, cross-node federation, offline wake or own-device
fan-out for these events.

Exactly one `ephemeral_result` is returned. `accepted` means the recipient's
bounded volatile queue accepted the frame; it does not promise delivery before
expiry. Dropped results name `invalid`, `unsupported`, `recipient_unsupported`,
`offline`, `not_local`, `expired`, `rate_limited`, `queue_full` or `replayed`.
No later durable ACK is emitted for an ephemeral envelope.

## Lifetime and bounds

The signed exclusive deadline is `D = (created_at + ttl) * 1000`, checked for
overflow and carried unchanged on every hop. A sender up to two seconds ahead
may be accepted; the receiver independently checks its own clock and holds early
ciphertext in memory for at most two monotonic seconds. It never displays before
the signed start or at/after D. An event's visible interval is at most five seconds.
D ends delivery and display; it does not establish cryptographic erasure.

A complete frame is at most 32 KiB. Gateway admission uses a per-session 20/s
bucket with burst 40. Queue and receiver occupancy are each at most 64 frames or
256 KiB, including a frame in flight. Saturation drops new events. The router
retains at most 65,536 volatile authenticated replay markers (8 MiB measured heap
budget); the receiver retains at most 4,096 live digests. Neither evicts a live
marker to admit a duplicate.

## Persistence and restart

Ephemeral routing has read-only access to source authority and live routing.
It does not append inbox content, allocate an inbox sequence, persist replay
markers, create retries, write client history or journal entries, or notify an
offline recipient. The ordinary durable route rejects marked envelopes before
persistent effects. The S6c persistence
guarantee covers transport through authenticated ciphertext handoff to the SDK
consumer. Its persistence test uses presealed known ciphertext and checks client
tables, database files and journal together with node artifacts across live,
offline, full, expired and refused outcomes, including reopen.

Pair decryption is stateful. Typing ratchet/allowance state and Unsupported
unknown-content retention are S10a endpoint exceptions, verified in the message
module; they are outside this transport-only unchanged-database guarantee.
Neither exception permits an ephemeral ACK, ledger entry or durable delivery
fallback. Nodes observe mode, TTL, outer identities, timing and pair-session tag
correlation; encrypted event content remains opaque to them.

Restart empties transient queues and volatile dedup state. A surviving receiver
still rejects duplicates; restarting both router and receiver can expose another
copy only within the original signed lifetime. Resume returns no ephemeral
history and the durable issued sequence remains unchanged. Router boot changes
trigger idempotent capability reassertion for live registrations. A partially
applied batch stays eligible for retry in the same boot.

Activation is isolated in the final capability-listing/advertisement commit.
Reverting that commit stops negotiation without changing any persistent schema
or requiring a migration. Existing negotiated sessions retain their frozen flag
until they retire; restart or reconnect renegotiates against the dormant router.

## Verification

`ephemeral_activation_end_to_end` and `ephemeral_persistence_absence` use a
same-tree router process, the production gateway ingress/writer, separate stores,
and the SDK codec/receiver. They cover live delivery, legacy recipient refusal,
offline drop, client database/WAL and journal stability, and empty Resume with
unchanged issued after router restart. The dormant-parent row runs with
`RAMFLUX_EXPECT_EPHEMERAL_DORMANT=1`; normal activation rows require the listing.
`e2e_push_restart` separately runs real node and `rf` processes, observes live DM
ACKs before reads, kills the recipient process, sends three offline DMs and checks
exact resumed content and node ACKs for every message. The CLI currently has no
ephemeral or typing command.
