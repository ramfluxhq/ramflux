# One-to-one voice calls

An attended human account starts a call from an existing direct conversation:

```sh
rf call invite --account alice --conversation=thread
rf call list --account bob
rf call answer --account bob --call=CALL_ID
rf call reject --account bob --call=CALL_ID
rf call hangup --account alice --call=CALL_ID
```

The daemon generates a fresh 128-bit call ID, redrawing IDs beginning with `-`.
The CLI also accepts hyphen-prefixed opaque selectors as split argument values.
The former local-only offer/SRTP echo API is removed.

Controls are device-signed inside the existing device-pair AEAD channel. They bind
call ID, conversation, both root-qualified endpoints, sequence, timestamp and action.
The fresh receiver can establish its direct context; later call controls cannot
create unrelated conversations on an established pair. Existing contexts must bind
the same two participants. Current root-signed device authority and accepted contact
checks apply. The first answering device wins; each invited device has a separate
caller key, and losing devices receive `answered_elsewhere`. Ringing expires at 45 s.

The caller becomes active after authenticating the answer and allocating its lease.
It sends only a public lease offer to the callee. The callee signs consent binding
call ID, both root-qualified endpoints, lease ID and the hard expiry. It claims its
own credentials over its own authenticated gateway session, after authenticating the
caller's offer, then becomes active and returns the public signed consent. Neither
participant receives the other's token or rebind key. Renewal includes the consent.
The gateway verifies current root-signed device sets, active key commitments, device
epoch, live session root/actor and callee signature. The node charges only the caller
before consent, and the callee once after verified consent. Repeated claims are
idempotent. A changed/expired consent or revoked key fails closed.

This version claims both participants' leases through gateways of the same home
node. Federated-home credential claiming/routing is not added here; a missing local
lease or authority fails the call rather than forwarding a claim to an arbitrary
peer-supplied endpoint.

## Public client contract

Methods are `call.invite {conversation_id}`, `call.answer|reject|hangup {call_id}`,
`call.list {}`, and `call.media.session {call_id}`. Mutation replies and `call.changed`
events use whole public rows: `call_id`, `conversation_id`, `peer_id`, `direction`,
`state`, `end_reason`, `seq`, `created_at`, `answered_at`, `ended_at`, and reserved
`media_generation: 0`. Times are Unix seconds. Direction is `outgoing` or `incoming`.
States are `outgoing_ringing`, `incoming_ringing`, `connecting`, `active`, `ended`.
End reasons are `completed`, `cancelled`, `declined`, `busy`, `timeout`,
`answered_elsewhere`, `failed`, `missed`.

`call.list` uses the account reader pool and returns at most 128 public records.
`message.list` contains `kind: "call"` records with duration and missed status.
Public rows, timeline entries and journal bodies never contain media keys, tokens,
rebind keys or private allocations. Terminal calls delete their control-sequence
receipts; retained public terminal records prevent resurrection.

## Private media-engine handoff

Only `call.media.session` returns these fields. Pass them directly to the media
engine; do not log, journal or persist them:

```text
relay: {endpoint: "host:port", token: base64url(32 bytes),
        lease_id: base64url(16 bytes), side: 0|1, rebind_key: base64url(32 bytes)}
sframe: {cipher_suite: 5,
         send: {kid, base_key: base64url(32 bytes)},
         receive: {kid, base_key: base64url(32 bytes)}}
```

The relay fields `lease_id`, `side`, `rebind_key` are additive desktop media fields.
Side 0 is caller; side 1 is callee. Each engine receives only its own fields.
The media profile is Opus 48 kHz mono, 20 ms, minimal RTP with payload type 111.
[SFrame RFC 9605](https://www.rfc-editor.org/rfc/rfc9605.html) suite 5 is
`AES_256_GCM_SHA512_128`; the RTP header is authenticated metadata. KIDs are 0 for
caller-to-callee and 1 for the reverse direction; counters begin at zero per fresh
key and the receive replay window has 128 counters.

Key handoff is once per call, excluded from generic operation-response caching.
Each SFrame key starts exactly once at counter zero. An engine restart or lost
handoff requires a new call, protecting both nonce uniqueness and receive replay
state. Daemon restart retires unfinished calls as `failed` and never reconstructs
old keys. Device/key change also ends the call as `failed`; fresh-call keys satisfy
v1 rekeying. Live handoff and KID increments are deferred.

The daemon call commit omits encrypted control payloads from replay receipts and
stores commitment metadata instead of raw call envelopes in its local event log.
Consumed ratchet message keys are removed before saving the advanced snapshot.
Ciphertext omission also matters because reusable private X3DH prekeys can otherwise
reconstruct bootstrap decryption. This is not post-compromise secrecy for independent
wire captures plus those reusable private keys, or explicit raw SDK archival.

## UDP source binding and HMAC rebinding

Ordinary datagrams are `u32be(token byte length) || decoded token || RTP/SFrame`.
The relay forwards only RTP/SFrame bytes. Empty framed payloads every 5 s maintain
NAT, but do not renew authorization. The first authenticated source is pinned.
Ordinary packets from another source cannot move the pin.

The connected media socket accepts challenges only from its configured relay.
On an address change the relay sends this raw challenge to the new source:

```text
"RFVC" || cookie[32] || new_addr_bytes
new_addr_bytes = family_byte || IP_octets || UDP_port_u16be
family_byte = 4 with 4 IPv4 octets, or 6 with 16 IPv6 octets
```

The challenge is 43 bytes for IPv4 or 55 for IPv6. It supplies the public NAT-mapped
address seen by the relay; do not substitute the engine's local socket address.
Compute:

```text
tag = HMAC-SHA256(decoded_rebind_key,
  ASCII("ramflux.voice.rebind.v1") || decoded_lease_id[16] || side_u8 ||
  cookie[32] || new_addr_bytes)[0..16]
response_payload = ASCII("RFVE") || cookie[32] || tag[16]
```

Send the 52-byte response payload in the normal token framing from that new socket
within five seconds. Only a valid, address/lease/side-bound HMAC echo moves the pin;
a copied token and cookie alone cannot. The response is consumed, never forwarded.
Each side has one outstanding challenge until expiry, and all such requests share
the endpoint bandwidth budget. Challenge replies are bounded to 55 bytes, once per
five-second outstanding challenge. Ordinary media needs no per-packet HMAC.
Changing only the socket preserves the existing SFrame counters and replay window.

## Node configuration and acceptance

Configure all relay endpoints together: `RAMFLUX_RELAY_VOICE_UDP_ADDR`,
`RAMFLUX_RELAY_VOICE_CONTROL_ADDR`, `RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT`.
The gateway uses `RAMFLUX_RELAY_VOICE_CONTROL_ENDPOINT`. The production
`deploy/docker-compose.voice.yml` overlay keeps the gateway-only mTLS control
listener internal. Without configuration, voice allocation is unavailable.

Leases last 60 s, renewed every 20 s, with an immutable four-hour hard deadline.
Limits are two concurrent allocations per root-qualified account, 4096 globally,
128 KiB/s per side, and a 1400-byte media payload. Clock rollback starts a new
bandwidth window. Expiry/release remove credentials and quota charges. Private and
special-use forwarding targets remain refused by default; QA explicitly opts in.

QA uses `RAMFLUX_ITEST_VOICE=1` and `docker-compose.itest.voice.yml`, named stacks,
two daemons, CLI signaling, bidirectional synthetic Opus/RTP/SFrame, replay refusal,
failed stolen-token rebinding and successful HMAC NAT rebinding. The realnet fixture
requires `RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1` too.
