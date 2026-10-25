# One-to-one voice calls

An attended human account starts a call from an existing direct conversation:

```sh
rf call invite --account alice --conversation thread
rf call list --account bob
rf call answer --account bob --call CALL_ID
rf call reject --account bob --call CALL_ID
rf call hangup --account alice --call CALL_ID
```

The daemon generates a fresh 128-bit call ID. Offer strings, user-selected call IDs,
and SRTP keys from the former local-only call stub are no longer accepted. The
signaling payload is device-signed and carried inside the existing device-pair AEAD
channel. It binds the call ID, conversation, both root-qualified endpoints, sequence,
time and action. A fresh receiver learns the direct context from the authenticated
control. Existing contexts must name the same two principals. Current contact and
manifest checks apply to call controls and relay authorization renewal.

The first answering callee device wins. Each invited device receives a distinct
caller key; losing devices get `answered_elsewhere`. Ringing expires after 45 seconds.
The caller becomes active after authenticating the answer and obtaining a relay
lease; the callee becomes active after authenticating the caller's acknowledgment.
Call state and timeline records contain no media keys or relay bearer credentials.
`call.list {}` returns at most 128 public records and runs on the account reader pool.
`message.list` includes rows of `kind: "call"`, with duration and missed status.

Subscribe to `call.changed` for whole public rows with `call_id`, `conversation_id`,
`peer_id`, `direction`, `state`, `end_reason`, `seq`, `created_at`, `answered_at`,
`ended_at`, and additive `media_generation`. Times are Unix seconds. State values are
`outgoing_ringing`, `incoming_ringing`, `connecting`, `active`, and `ended`. End reasons
are `completed`, `cancelled`, `declined`, `busy`, `timeout`, `answered_elsewhere`,
`failed`, and `missed`.

## Media engine handoff

Only `call.media.session {call_id}` returns media secrets. Pass the response directly
to the local media engine; never log or journal it. The shape is:

```text
relay: {endpoint: "host:port", token: base64url(opaque bytes)}
sframe: {cipher_suite: 5,
         send: {kid, base_key},
         receive: {kid, base_key}}
```

The fixed media profile is Opus, 48 kHz, mono, 20 ms, RTP payload type 111.
SFrame RFC 9605 suite 5 (`AES_256_GCM_SHA512_128`) authenticates the RTP header as
metadata. Caller-to-callee uses KID 0; the opposite direction uses KID 1. Initial
counters start at zero. The receiver enforces a per-key 128-counter replay window.

A media engine may obtain its keys only once per call. Generic operation IDs do not
cache or replay media replies. An engine restart requires ending the call and starting
a fresh call, protecting both nonce uniqueness and the receiver's replay window. A
daemon restart ends unfinished calls as `failed`; old media keys are never reconstructed
from public records or control redelivery.

UDP framing is `u32be(token byte length) || decoded token || RTP/SFrame packet`.
The relay forwards only the RTP/SFrame packet. Send an empty framed payload every
5 seconds to maintain the NAT binding. UDP keepalives do not renew authorization.

## Node configuration

The production relay requires all three endpoints together:

- `RAMFLUX_RELAY_VOICE_UDP_ADDR`: listening UDP address.
- `RAMFLUX_RELAY_VOICE_CONTROL_ADDR`: internal mTLS lease-control address.
- `RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT`: client-reachable public `host:port`.

Set `RAMFLUX_RELAY_VOICE_CONTROL_ENDPOINT` on the caller's home gateway. Use the
`deploy/docker-compose.voice.yml` overlay with `deploy/docker-compose.yml`, supplying
the public endpoint. The control listener is not published. Without the overlay or
these settings, voice allocation is unavailable and a call cannot become active.

Only the local node's gateway mTLS identity may mutate leases. The gateway checks the
live signed session and current registry branch on every allocation, renewal and
release. Tokens bind a call and both root-qualified device endpoints. Leases last
60 seconds; the caller renews after 20 seconds and sends authenticated lease updates
to the callee. Expired media authorization ends the call. Concurrent limits are two
allocations per root-qualified account (caller charged on allocation, callee only on its
first credential use), 4096 globally, and 128 KiB/s per endpoint. Renewal cannot extend
the original lease beyond four hours. Clock rollback starts a fresh bandwidth window.
Payloads are bounded to 1400 bytes. The relay learns destinations from authenticated
UDP sources; an allocation cannot supply an arbitrary forwarding address. Private
and special-use destinations remain refused by default. Development fixtures use the
existing explicit private-target opt-in.

## Acceptance

The dedicated realnet mode additionally requires `RAMFLUX_ITEST_VOICE=1`, selecting
`docker-compose.itest.voice.yml`. It is disabled for other acceptance stacks. The
voice fixture uses named stacks and dedicated ports, two daemon processes, real
signed signaling and production mTLS allocation; synthetic Opus frames travel both
ways through the opaque UDP relay. Run it on the container QA host.

## Source pinning and NAT changes

The relay pins each side's UDP source on its first token-authenticated datagram. Media
or keepalives from another source cannot replace that pin. A new source receives a
36-byte raw challenge, `RFVC || random_cookie[32]`, from the relay. Within five seconds,
it must echo `RFVE || cookie` as the payload of a normal datagram framed with its own
token. The cookie is bound to that source and side. Until the echo succeeds, media
continues to the previous address. The echo is consumed, never forwarded as media.
One challenge per side can be outstanding; new sources cannot churn it before expiry.
Challenge replies are no larger than the smallest authenticated request, and share
the endpoint bandwidth budget. Clients accept challenges only from their configured
relay. The caller's credential is never sent to the callee.

Generated call IDs never begin with `-`. Use `--call=CALL_ID` and `--conversation=ID`
when scripting with opaque selectors; the CLI also accepts hyphen-prefixed IDs as
separate argument values. Call controls do not create unrelated conversations on an
established pair. Each media key starts exactly once at counter zero; live endpoint
handoff/rekey is deferred. Device or key change ends a call with `end_reason: failed`.

Committed call receipts retain routing attribution and the original payload hash but
omit the encrypted call payload. The local event log likewise stores only commitment
metadata for those controls. Consumed ratchet message keys are removed before the
post-decrypt snapshot is persisted. This ciphertext omission also matters because
reusable private X3DH prekeys can otherwise reconstruct bootstrap decryption. It is
not a claim of post-compromise secrecy for ciphertext independently captured on the
wire together with the reusable private bootstrap keys. Terminal calls delete their
control-sequence receipts; retained public call rows continue to prevent resurrection.
