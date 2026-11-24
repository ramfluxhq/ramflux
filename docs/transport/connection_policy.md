<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Native connection policy

Native clients use the same pinned gateway CA and TLS 1.3 custody exporter
on QUIC and TCP+TLS. The gateway needs no change for these carriers or an
HTTP CONNECT tunnel. WebSocket is not implemented: there is no native WebSocket ingress.

`GatewaySessionConfig::with_connection_race(ConnectionRace::Raced)` opts into
QUIC at 0 ms and TCP+TLS at 300 ms. The first completed handshake wins;
the dialer cancels and drains losing tasks before returning. Desktop keeps
`ConnectionRace::Serial` by default. The winning carrier is remembered for
ten minutes per host-supplied network key, with at most 32 entries. A TCP
win skips QUIC until expiry; a failed dial clears that network's memory.
Keys are hashed in memory and never persisted. QUIC remains a racing leg
when QUIC is remembered, because UDP reachability can change.

The public host callback is:

```rust
pub fn NetworkMonitor::on_network_changed(&self, kind: NetworkChangeKind)
```

Keep a clone of `GatewaySessionConfig::network_monitor`, or set
`LocalBusConfig::network_monitor` before starting the embedded daemon.
For the daemon, `LocalBusConfig::connection_race` selects the ordering for
all its account sessions. Forward Android NetworkCallback / iOS NWPathMonitor
notifications using `Available(NetworkKey)`, `Changed(NetworkKey)` or `Lost`.
`NetworkKey::from_host_label(&[u8])` hashes an interface/network handle without
retaining its label. Reports require no Tokio runtime and can come from any
host thread. They coalesce to the latest generation via a watch channel.

The resident connection manager retires its current session on a new report,
cancels session children and any active exchange, and redials using its
existing admission/resume and durable receive checkpoints. Immediate retirement
fits the single-owner session model and does not rely on QUIC migration or
probe a socket whose interface has changed. While `Lost`, it sends nothing and
waits for `Available` or `Changed`; stop remains interruptible. Direct users of
GatewaySessionEngine own that engine and must react to monitor reports themselves.

Enable `http-connect-proxy` in the SDK and transport to configure
`GatewaySessionConfig::with_http_proxy(HttpConnectProxy)`, or set
`LocalBusConfig::http_proxy`. As in the reference implementation this feature
is default-off and is not exposed on Windows. There is no environment or
system proxy lookup. A configured proxy always takes precedence over Auto
ordering: only CONNECT to the configured TCP gateway address is attempted,
then TLS runs end to end inside the tunnel. Explicit QUIC is refused. Proxy
refusal or failure never triggers a direct UDP or TCP fallback. Even an
inconsistent dial plan containing QUIC is refused before opening its socket.
Basic credentials are sent only to the configured proxy, over its plain TCP
connection, and Debug/errors redact them. Response headers are bounded to
8192 bytes; the complete dial leg has a handshake deadline.

Client constraints declare no compiled-in central service, required vendor
push, or required app store. The source/manifest guard checks those constraints.
Each client integrates its platform callbacks and verifies its supported targets;
loopback tests do not establish behavior on a phone or a deployed node.
