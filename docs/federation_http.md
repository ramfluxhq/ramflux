# Federation HTTP listeners

There is no combined listener. `RAMFLUX_FEDERATION_PUBLIC_ADDR` defaults to
`127.0.0.1:18082`; `RAMFLUX_FEDERATION_ADMIN_ADDR` defaults to `127.0.0.1:18087`.
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

`RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS` defaults to 64 concurrent connections;
valid values are 1..4096 and invalid configuration fails startup. Excess connections
receive a generic 503 without spawning another worker. Slots are released after
success, request failure or worker termination. The existing request read timeout
still applies. Public 500 responses contain only `internal server error`; causes
are logged privately. Per-source-IP rate limiting is separate follow-up work.

For host runs, set `RAMFLUX_FEDERATION_PUBLIC_ADDR` and
`RAMFLUX_FEDERATION_ADMIN_ADDR` to distinct available addresses, for example
`127.0.0.1:19082` and `127.0.0.1:19087`. The native admin default 18087 avoids
the itest relay default host port 18084. Occupied public/admin binds fail startup
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
