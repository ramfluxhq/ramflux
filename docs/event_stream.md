# Account event stream

The daemon owns one sync driver and durable sequence journal per unlocked account.
Clients subscribe with `bus.subscribe` (alias `subscription.open`), an account id,
a set of `topics`, and an optional `since_seq`. `*` selects all topics. A missing
cursor starts at the current head; a supplied cursor replays events strictly after
that sequence, followed by live changes. The response acknowledgement precedes
replay on the same connection. Events carry `seq` and `at`.

## Resume and recovery

A fresh journal accepts `since_seq: 0`. A cursor equal to the last pruned sequence
also resumes: it has already consumed that sequence. A cursor below the durable
pruning watermark or above the current head receives `resync_required`, with
`floor_seq` and `head_seq` in the response body. Existing Rust SDK `request` and `request_frame` methods retain
`SdkError::LocalBus("<code>: <message>")`, including the `resync_required` prefix
used by existing clients. To inspect the bounds, opt into
`request_frame_structured(frame)`: daemon refusals become
`SdkError::LocalBusRefused { code, message, body }`. Alternatively,
`request_frame_response(frame)` returns the complete error frame without
normalizing it. Transport/deadline errors and secret-body erasure remain unchanged. `floor_seq` is the oldest retained sequence (or the head when no events
remain), not a requirement that the cursor itself still be retained. Separate
status retention and sticky protection can leave earlier events below the
pruning watermark.

On refusal, reload the account's read models and subscribe from the returned
head, retaining subsequent events while reconciling the snapshot. The ordinary
read-model/snapshot APIs and the subscription cursor must both participate in
this reconciliation; an old cached view alone cannot fill a journal gap.
A slow client receives `stream.lagged` with `last_delivered_seq` and reconnects
from that cursor. Replay is bounded and the account writer never waits for a
slow subscriber. Account lock or daemon stop closes the stream.

## Status transitions and retention

`sync.status` and `node.health` are durable state transitions. The first sample
is emitted, then an event is emitted only when semantic fields change. The
`last_run` timestamp alone does not create an event. The latest sample and the
last emitted semantic state are persisted in the same account transaction, so
idle polling and daemon restart do not manufacture transitions. `last_run` on
an event describes that transition's sample, rather than a periodic heartbeat.

`sync.status` compares `state` and `unrouted`. `node.health` compares `state`,
`transport`, and `node_id`. The node id comes from the account's persisted node
binding; legacy or manually configured endpoints without a binding emit null.
Endpoint addresses are never guessed to be node identities. A missing or
unparsable optional account manifest is logged and yields a null node id; it
does not prevent account readers from starting.

`sync.status.get` is an account-scoped reader-pool method. Its response, also
included in every successful `bus.subscribe` acknowledgement, has:

```json
{
  "last_run": 2000,
  "sync_status": {"seq": 1, "at": 1000, "body": {"state": "idle", "unrouted": 0, "last_run": 2000}},
  "node_health": {"seq": 2, "at": 1000, "body": {"node_id": null, "state": "connected", "transport": "quic", "last_run": 2000}}
}
```

Each body has exactly the corresponding event payload shape, with the latest
poll's `last_run`. `seq` and `at` identify its last semantic transition, while
`last_run` can advance without an event. Those coordinates persist even after
the journal transition is pruned. A subscriber at the head therefore gets the
current status without waiting for a transition. Clients displaying “last synced”
can refresh `sync.status.get`; event timestamps are not heartbeats. Both samples
and `last_run` are null before the first completed sync. Older persisted samples
recover coordinates from retained journal rows; if that historical row was
already pruned before upgrade, only its coordinates are null until a transition.
Subscription samples and replay bounds share one database snapshot.

Ordinary journal events default to a 10,000-event count budget and seven-day
age limit (`RAMFLUX_EVENT_MAX_COUNT`, `RAMFLUX_EVENT_MAX_AGE_SECONDS`). Status and
health transitions never consume that count budget. They have their own combined
128-transition budget and the same age limit. Unacknowledged sticky safety or
approval events remain protected. Removing any actual event, including an old
status transition, advances the durable pruning watermark: a client that missed
it may still need resynchronization even if its message events remain retained.
Repeated unchanged idle samples neither allocate journal sequences nor evict
messages. Real state flapping remains observable and bounded.

The stream is account scoped. Daemon-wide account/node directory subscriptions
are a separate API concern.
