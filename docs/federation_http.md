# Federation HTTP listeners

There is no combined listener. `RAMFLUX_FEDERATION_PUBLIC_ADDR` defaults to
`127.0.0.1:18082`; `RAMFLUX_FEDERATION_ADMIN_ADDR` defaults to `127.0.0.1:18089`.
Both listeners start independently. Binding them to the same address fails startup.
The public handler has no admin token or federation trust-store reference.

Production Compose binds both inside the container, publishes only public port
18082 (`RAMFLUX_FEDERATION_PUBLIC_PORT`), and sends the router's
`RAMFLUX_ROUTER_FEDERATION_FORWARD_URL` to
`http://ramflux-federation:18084/internal/home-node-migration/forward`.
Admin port 18084 has no host mapping. Only trusted services should join this
Compose network; container-network access is not a substitute for the admin token.
A host installation keeps admin on loopback unless explicitly configured otherwise.
Expose the public listener through the deployment's HTTPS termination when needed;
never route public ingress to the admin listener. Public requests to admin paths
return 404 even with a valid token. Admin does not alias public client routes.

`demo-node.sh` retains `DEMO_HTTP_PORT` (default 59482) as its client HTTP origin;
it writes `RAMFLUX_FEDERATION_PUBLIC_PORT`; administration is unpublished unless
the operator explicitly selects the loopback-only overlay below.
The old `RAMFLUX_FEDERATION_ADMIN_PORT` host mapping is removed. Operators and
fixtures must configure separate public and admin addresses, rather than expect
an old combined endpoint to work.

## Production route inventory and readers

| Listener | Method and path | Reader / caller |
| --- | --- | --- |
| Public | GET `/healthz` | Operator/demo HTTP readiness |
| Public | GET `/.well-known/ramflux/client` | SDK node discovery, demo status and node fingerprint verification |
| Public | GET `/.well-known/ramflux/server` | Peer signed node discovery, `rf admin federation peer` well-known URLs |
| Public | GET `/mvp1/prekey/{selector}` | SDK/CLI prekey consumers using `RAMFLUX_CLIENT_PREKEY_HTTP_URL` or recipient prekey URL; proxies authenticated router mesh |
| Public | GET `/mvp1/device-manifest/{selector}` | SDK device authority consumers on the same client HTTP origin; proxies router mesh |
| Admin | GET `/healthz` | Private operator / production peering fixture readiness |
| Admin | POST `/admin/federation/peer` | `rf admin federation peer`, private operator tooling; token required |
| Admin | POST `/admin/federation/discover` | Private discovery/pinning tooling; token required |
| Admin | POST `/s8/federation/forward` | Explicit privileged cross-node CLI forwarding; token required |
| Admin | POST `/internal/home-node-migration/forward` | Router local home-node migration forwarding; token required |
| Admin | POST `/s8/federation/mesh-observability` | Private operator / production peering fixture transport diagnostics; token required |

All other HTTP routes/methods return 404. Existing mesh mTLS/QUIC routes, including
peer envelope delivery and retention GC, retain their separate authenticated mesh
listener and are not exposed by either HTTP handler. Prekey selection and response
payloads are unchanged; the public proxy allows only the two GET read prefixes above. POST
`/mvp1/prekey/fetch` is unsupported and returns 404; no router handler or client
consumer exists for that route.

## Authenticated mesh route inventory

TCP mTLS and QUIC expose the same four routes, on the independently configured
mesh listener (Compose port 7443). Neither HTTP listener forwards these paths.

| Method and path | Reader / caller |
| --- | --- |
| GET `/healthz` | Authenticated mesh health probes |
| GET `/mvp9/federation/trust-snapshot` | Relay trust consumers over authenticated mesh |
| POST `/s8/federation/envelope` | Admitted federation peers delivering signed envelopes |
| POST `/internal/retention/gc_sweep` | Retention service only; peer service identity enforced |

## Integration fixture control plane

The `itest-http` feature plus `RAMFLUX_ITEST_HTTP=1` enables an additional
**test-only** control listener. Its default is loopback port 18086; itest Compose
binds container port 18086 and publishes it using the existing
`RAMFLUX_ITEST_FEDERATION_HTTP_PORT`. It is not the production public or admin
handler. Production builds do not enable this feature. Legacy fixture
`federation_url` variables refer to this control plane, not a client origin.

| Test-control method and path | Reader / caller |
| --- | --- |
| GET `/healthz` | Fixture readiness |
| GET `/s8/federation/mesh-observability` | S8 transport assertions |
| GET `/.well-known/ramflux/server` | S8 test discovery fixture |
| POST `/s12/federation/discovery/resolve` | S12 pin/discovery fixture |
| GET `/s12/federation/discovery/pin/{node}` | S12 pin assertions |
| POST `/mvp4/federation/route` | Route setup fixtures |
| POST `/mvp4/federation/trust-status` | Trust-state fixtures |
| GET `/mvp4/federation/can-deliver/{node}` | Trust assertions |
| POST `/mvp8/federation/handshake` | Admission fixtures |
| GET `/mvp8/federation/capabilities/{node}` | Capability assertions |
| POST `/mvp8/federation/friend-request` | Cross-node friend-request fixtures |
| POST `/s8/federation/forward` | Test forwarding fixtures |
| POST `/mvp7/federation/tombstone` | Federation deletion fixtures |
| GET `/mvp7/federation/tombstone/{node}` | Tombstone assertions |

Production peering fixtures use `docker-compose.itest.admin.yml` only when they
explicitly supply `RAMFLUX_ITEST_FEDERATION_ADMIN_PORT`. This publishes admin on
host loopback for the test CLI; their public discovery/prekey port is independent.
The override is never included by demo-node.sh or normal production Compose.

## Public bounds, errors and host configuration

`RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS` and
`RAMFLUX_FEDERATION_ADMIN_MAX_CONNECTIONS` each default to 64 concurrent connections;
valid values are 1..4096 and invalid configuration fails startup. Excess connections
receive a generic 503 without spawning another worker on either listener. Slots are released after
success, request failure or normal worker return. Production uses `panic = "abort"`,
so a worker panic terminates the process rather than unwinding and releasing only
that slot. The existing request read timeout still applies. Public 500 responses
contain only `internal server error`; causes are logged privately.

With `RAMFLUX_FEDERATION_PER_SOURCE_LIMITS=on` (the default), the public listener
also limits each source independently. Concurrent connections default to 8 per
source and 16 per IPv4 `/24` or IPv6 `/48`. A connection-open token bucket and a
request token bucket both default to 20 per second with a burst of 40. Connection
rate and slot refusals receive a generic 503; request-rate refusals receive a
generic 429.

Source accounting is derived only from the accepted socket address.
`X-Forwarded-For`, `Forwarded`, and similar HTTP headers are not trusted. A reverse
proxy therefore appears as one source unless it preserves addresses at a trusted
transport boundary. Set `RAMFLUX_FEDERATION_PER_SOURCE_LIMITS=off` when a trusted
proxy or port forward cannot preserve them; the global connection and HTTP framing
limits remain enforced. The service emits a one-time warning when more than 90%
of a 100-connection observation window comes from one private or loopback address.

IPv4 addresses have independent buckets and an additional `/24` connection cap.
IPv6 addresses aggregate per `/64`, with an additional `/48` connection cap, so
privacy addresses from one routed prefix cannot consume the global slots. The
source table defaults to 4096 entries and inactive entries expire after 300
seconds. At capacity, an O(1) LRU index evicts an idle entry, preferring a fully
refilled bucket; active entries are never evicted. Capacity must be greater than
the global connection cap or startup fails. Configure the service with:

| Runtime setting | Default | Valid range |
| --- | ---: | ---: |
| `RAMFLUX_FEDERATION_PER_SOURCE_LIMITS` | `on` | `on`, `off` |
| `RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS_PER_SOURCE` | 8 | 1..4096 |
| `RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS_PER_PREFIX` | 16 | 1..4096 |
| `RAMFLUX_FEDERATION_PUBLIC_CONNECTION_RATE_PER_SECOND` | 20 | 1..1000000 |
| `RAMFLUX_FEDERATION_PUBLIC_CONNECTION_BURST` | 40 | 1..1000000 |
| `RAMFLUX_FEDERATION_PUBLIC_REQUEST_RATE_PER_SECOND` | 20 | 1..1000000 |
| `RAMFLUX_FEDERATION_PUBLIC_REQUEST_BURST` | 40 | 1..1000000 |
| `RAMFLUX_FEDERATION_PUBLIC_SOURCE_TABLE_CAPACITY` | 4096 | 1..65536 |
| `RAMFLUX_FEDERATION_PUBLIC_SOURCE_IDLE_SECONDS` | 300 | 1..86400 |

Compose uses the corresponding `RF_COMPOSE_` aliases. Invalid values fail service
startup. The global connection cap remains an independent upper bound.

Published ports into the demo's bridge network preserve client source addresses
only with a rootful Linux Podman or Docker engine. Rootless bridge publishing uses
a port proxy even when Podman's default rootless network command is `pasta`, and a
Podman machine uses a host proxy; both collapse clients onto a private source. The
demo wrapper therefore defaults the switch to `off` for rootless, machine/remote,
and unknown topologies, with a warning, and to `on` only for detected rootful Linux.
An explicit operator `on` or `off` is never overwritten; `on` in a collapsing or
unknown topology emits a warning. Operators must verify the address observed by the
federation container before forcing `on`. A source-preserving rootless topology is
tracked separately and is not provided by the bridge-network demo.

For host runs, set `RAMFLUX_FEDERATION_PUBLIC_ADDR` and
`RAMFLUX_FEDERATION_ADMIN_ADDR` to distinct available addresses, for example
`127.0.0.1:19082` and `127.0.0.1:19087`. The native admin default 18089 avoids
the itest relay (18084) and retention (18087) default host ports. Occupied public/admin binds fail startup
with the listener name and attempted address; they never silently share a socket.
Compose explicitly retains internal admin 18084 and router forwarding on that port.

## Operator administration over SSH

Production opt-in (supply the normal production secret/config inputs as usual):

```sh
export RAMFLUX_FEDERATION_ADMIN_LOOPBACK_PORT=59487
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.admin.yml up -d
ssh -L 59487:127.0.0.1:59487 operator@node.example
```

Use the existing private admin token with `rf admin federation` and an admin URL
of `http://127.0.0.1:59487` through the tunnel. In a demo operator env file, set
`DEMO_ADMIN_LOOPBACK_PORT=59487`, then run `demo-node.sh up ENV_FILE`. Retain that
selection for maintenance commands. The script writes a concrete port input and
includes the saved `compose.admin.yml`. An empty/unset selection on the next `up`
removes the host mapping. Only a numeric port is accepted, never a bind address;
the overlay hard-codes `127.0.0.1` independently of `DEMO_BIND_ADDR`. No public
firewall opening is needed. Production operators likewise omit the overlay from
the next `up` to remove access.

The router-to-federation admin hop carries its token in the JSON body over plain
HTTP on the trusted Compose network. It is not mTLS-protected. Restrict network
membership; mTLS for this hop is a separate hardening card.

## Request resource limits

Both HTTP listeners cap headers and bodies before allocation. Bodies are read in
fixed-size chunks rather than reserving the declared Content-Length. Invalid or
duplicate lengths and unsupported Transfer-Encoding return 400; oversized headers
or bodies return 413; timeouts return 408. The public response bodies are generic.
An absent body length means zero bytes; huge declarations never drive an allocation.

Public defaults: 8 KiB headers, 64 KiB body, 10 seconds from accept for headers and
body together. Admin defaults: 64 KiB headers, 1 MiB body, 30 seconds. Each socket
read is also bounded to five seconds or the remaining whole-request budget,
whichever is smaller. Slow trickle traffic cannot renew that budget. Configure
`RAMFLUX_FEDERATION_{PUBLIC,ADMIN}_{MAX_HEADER_BYTES,MAX_BODY_BYTES,REQUEST_TIMEOUT_SECONDS}`.
Allowed maxima are 64 KiB headers, 64 MiB body and 3600 seconds; all values must be
positive integers. Compose uses the corresponding `RF_COMPOSE_` input aliases;
demo writes concrete inputs from its operator env file. The shared reader's default
body cap is 1 MiB. Parsing rejection is fail-closed and never shares admin routes.

Over-cap 503 is best-effort: unread queued bytes can make the kernel close with a
reset instead. Either result refuses the excess connection without a worker.

## Response delivery and bounded shutdown

Federation responses are serialized before socket writes. Every write uses the
remaining request budget, with at most five seconds for response delivery; partial
progress never renews either deadline, including on kernels whose socket timeout can
restart within one large write call, because each syscall is capped at 64 KiB.
Mesh/router work retains its own transport timeouts, but cannot restart the response
budget. A read which exhausts its budget may send only the 408 rejection using a
separate 100 ms allowance. If admin handler work completes after the response budget,
the server sends a bounded 504 stating that the operation outcome is unknown; callers
must reconcile state before retrying a non-idempotent request. Failed partial writes
are logged and closed; no second response is appended to a partial response.

After a complete response the server shuts down its write half, then drains unread
request bytes with a fixed buffer until EOF or 100 ms, capped by the remaining
request budget. Small oversized headers which finish arriving within that drain
window receive a complete 413 rather than a truncated status line. A larger or slow
finite header, or a peer which streams indefinitely beyond the drain budget, may
still see a reset after the response; it cannot prolong a worker slot.
The over-cap 503 remains best-effort, with no drain on the accept thread.

The demo validates all six header/body/deadline inputs and both connection caps
before creating state, invoking tools or recreating containers. Explicit empty,
unresolved, malformed, zero and out-of-range values fail; unset values use the
listener defaults. Production and itest Compose accept the corresponding
`RF_COMPOSE_FEDERATION_ADMIN_MAX_CONNECTIONS` input, as for the public cap.

The admin hop still uses a bearer token over plaintext HTTP inside the Compose
network. Thread caps and timeouts do not provide transport confidentiality or peer
authentication. Keep network membership restricted; authenticated TLS for this hop
remains separate follow-up work and is not implemented by these limits.
