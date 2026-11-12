<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Client connection policy

How a native client (desktop, iOS, Android) reaches its gateway. The policy
lives in `crates/ramflux-transport/src/connection_policy.rs` (pure rules),
`gateway_dial.rs` (the race) and `crates/ramflux-sdk/src/gateway/auto_dial.rs`
(the SDK entry). The browser client is out of scope here.

## Carriers

| Carrier | Wire | Status |
|---|---|---|
| QUIC | UDP, one bidirectional stream of length-prefixed frames | in use |
| TCP + TLS | TCP, length-prefixed frames | in use |
| WebSocket + TLS | TCP, TLS 1.3, one binary message per frame | client carrier implemented, not dialed by the SDK |

Every carrier ends in TLS 1.3 at the gateway, is verified against the same
pinned CA, and exposes that TLS session's exporter. The channel-bound device
handoff is therefore identical on all of them. There is no plaintext carrier,
no option to skip certificate verification, and no binding-free mode to fall
back to: a fallback changes the carrier and nothing else.

The native WebSocket carrier sends no `Origin` header, no cookie and no
extension offer, and it uses the native binding, not the browser binding. The
SDK does not dial it yet, because no gateway listener accepts the native
binding over WebSocket and no `Open.transport_kind` value is defined for it.

## `Auto`

`GatewaySessionTransportKind::Auto` has two orderings, selected by
`GatewaySessionConfig::with_connection_race`:

- `ConnectionRace::Serial` (default): QUIC for `quic_fallback_timeout`, then
  TCP + TLS. This is the existing desktop behaviour.
- `ConnectionRace::Raced`: start QUIC, start TCP + TLS 300 ms later, keep the
  first that completes its TLS handshake, and close the other before the first
  frame is written. Phones use this ordering and never use `Quic` alone.

After a raced dial the winner is remembered for the current network for ten
minutes:

| Remembered | Next dial |
|---|---|
| nothing, or expired | QUIC at 0 ms, TCP + TLS at 300 ms |
| QUIC | the same race; `Auto` never dials QUIC alone |
| TCP + TLS | TCP + TLS only, until the memory expires |

The expiry is the QUIC re-probe: ten minutes after a TCP + TLS win, the next
dial races QUIC again. A failed dial, or a failed probe after a network
change, forgets the network at once. The memory is in process only and is
keyed by a hash of a host-supplied label, never by the label itself.

## Session budgets

| | Value |
|---|---|
| Client QUIC idle timeout (raced dial) | 90 s |
| Client QUIC keep-alive (raced dial) | 25 s |
| Stream-carrier heartbeat (constants; the resident connection manager keeps its own keep-alive timer for now) | 25 s, dead after 2 missed replies |
| Probe deadline after a network change | 3 s |

The effective QUIC idle timeout is the smaller of the two peers' values. The
25 s keep-alive is below both the 90 s client value and the 30 s transport
default, so a session holds against a gateway that has not raised its own
value yet.

## Network changes

The host forwards the operating system's default-network callback to
`NetworkMonitor::on_network_changed(kind)`:

- `NetworkChangeKind::Changed(key)` or `Available(key)`: the session owner
  calls `GatewaySessionEngine::on_network_changed(kind, last_seen_inbox_seq)`.
  It sends one heartbeat with a 3 s deadline. `Survived` means the connection
  absorbed the change (for QUIC, by path validation on the gateway side): it
  is kept and no second session is opened. Otherwise the connection is
  replaced by a new one that resumes, and `Reconnected` is returned.
  `probe_after_network_change` is the probe alone, for an owner that
  reconnects by itself; it returns `Survived` or `Reconnect`.
- `NetworkChangeKind::Lost`: nothing is sent. The owner drops the connection
  and waits for `Available`.

The client never depends on connection migration and never rebinds its UDP
socket itself. Leaving the foreground on a phone is not a network change; the
host lifecycle closes the session.

## Blocked networks

A captive portal or an intercepting middlebox fails the pinned-CA check.
`ramflux_sdk::is_network_blocked(&error)` identifies that case so the host can
show "network blocked". A host must not offer to trust the presented
certificate and must not install an additional root.

## Proxies

- An HTTP proxy is used only when the host configures one explicitly
  (`GatewaySessionConfig::with_http_proxy`). There is no environment or system
  lookup.
- With a proxy configured, QUIC is never dialed. TCP + TLS runs inside an HTTP
  `CONNECT` tunnel; TLS to the gateway stays end to end, so the proxy sees the
  gateway host name and ciphertext only.
- The code is behind the default-off `http-connect-proxy` feature and is not
  compiled for Windows targets.
- Proxy credentials (`Basic`) are redacted from `Debug` output and never
  appear in an error or a log line. They travel to the proxy without TLS, as
  the `Basic` scheme over a plain proxy connection always does.
- There is no SOCKS support and no traffic obfuscation.
