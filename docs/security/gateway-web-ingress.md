# Gateway web ingress (operators)

Status: implemented behind the `web-ingress` cargo feature and **off by default**. Do not
enable it on a node that serves real accounts until the protocol audit of the
`web_origin_bound` binding mode has passed. Release images are built without the feature.

## What it is

A separate listener of `ramflux-gateway` for linked web devices:

- its own TCP socket and port, never the native QUIC or TCP+TLS listener;
- TLS 1.3 only, terminated by the gateway process, with a Web PKI certificate whose key
  is not the mesh service key (the gateway refuses to start if the two keys are equal);
- ALPN `http/1.1` only, then an HTTP/1.1 upgrade to WebSocket on `/v1/session` with the
  subprotocol `ramflux.gateway_session.v1`;
- one binary WebSocket message carries exactly one gateway frame body (the same JSON
  frames the native transports carry, without the length prefix).

A web device is a linked secondary device. It authenticates with a branch proof in the
`web_origin_bound` binding mode and can only open a session and manage its own prekeys.

## What it does not protect against

The `Origin` allow-list protects browser users from other web pages. It is not
authentication: a non-browser client can send any `Origin`. Authentication is the signed
branch proof. The mode has no TLS channel binding, so a party that terminates TLS between
the browser and the gateway can relay a proof; the reduced role of a web device is the
compensating control. The node that serves the web application can read what that
application handles. Users who need protection from the node operator use a native build.

## Settings

All are read from the gateway's environment. The listener starts only when
`RAMFLUX_GATEWAY_WEB_LISTEN` is set and the binary was built with `--features web-ingress`.
A binary without the feature refuses to start if the variable is set.

| Variable | Meaning |
|---|---|
| `RAMFLUX_GATEWAY_WEB_LISTEN` | Socket address of the web listener. Unset or empty: no web listener. |
| `RAMFLUX_GATEWAY_WEB_TLS_CERT` | PEM certificate chain (Web PKI) for the web listener. |
| `RAMFLUX_GATEWAY_WEB_TLS_KEY` | PEM private key for that chain. Must differ from the mesh service key. |
| `RAMFLUX_GATEWAY_WEB_URL` | The exact URL clients dial, in canonical form: `wss://<lowercase host>[:port]/v1/session`, port omitted when 443, no trailing slash, query, fragment or userinfo. This string is signed in every proof. |
| `RAMFLUX_GATEWAY_WEB_ORIGINS` | Comma-separated exact origins of this node's own web application, 1 to 8 entries, for example `https://app.example.org`. No wildcard, no `null`, no `http:`, no trailing slash, no default port. |
| `RAMFLUX_GATEWAY_WEB_DEV_ORIGINS` | `1` additionally allows `http://localhost:<port>` and `http://127.0.0.1:<port>` and logs a warning. Development only; never set it in a deployment file. |
| `RAMFLUX_CUSTODY_PROXY_SIGNING_SEED` | Existing setting. The web listener signs a proxy receipt for every proof and refuses to start without it. |
| `RAMFLUX_CUSTODY_WEB_PROXY_IDS` (router) | Comma-separated proxy ids whose receipts may vouch for web proofs. Unset or empty: the authority refuses every `web_origin_bound` proof. |

The node identity record must advertise the mode and the listener: `channel_binding_modes`
contains `web_origin_bound`, and `web_listeners` contains the configured URL with the
configured origins. A connection is refused when the record does not list them.

With Docker Compose the same settings are supplied through their `RF_COMPOSE_*` aliases
(`deploy/compose-inputs.json`). They default to empty, and `deploy/docker-compose.yml`
publishes no web port; an operator who enables the listener adds the port mapping and
mounts the certificate.

## Proxies and source addresses

The gateway terminates TLS itself. Rate limits use the accepted TCP peer address (IPv6
aggregated per /64) and the gateway's own clock. `X-Forwarded-For`, `Forwarded`,
`X-Real-IP`, `Via`, cookies and `Authorization` are never read. Placing an HTTP reverse
proxy or a CDN in front of this listener makes every client share the proxy's address and
its limits, and puts a TLS-terminating party on the path; it is not a supported setup.

## Limits

Before the upgrade: at most 8 unauthenticated and 32 total connections per source, 30
upgrade attempts per source per minute, a 10 s TLS deadline, a 5 s and 8192-byte request
head. After 10 refused proofs in 10 minutes a source is refused for 10 minutes. Upgrades
per origin are counted for alerting only and never refuse a client. These counters live in
memory; an unauthenticated connection causes no durable write.

After the upgrade: messages are limited to 65 536 bytes until the session is established
and 1 048 576 bytes afterwards, measured on the running total of fragments before
anything is buffered. Text messages, any reserved bit (compression is never negotiated),
unmasked frames and oversized control frames close the connection. The gateway pings every
30 s and closes when no pong arrives within 20 s or when no application frame arrives for
90 s. The downstream window is 16 entries.

## Close codes

`1002` protocol error, `1003` text message, `1008` control-frame abuse, `1009` message too
big, `1011` internal error, `4400` bad frame, `4401` a fresh proof is required, `4403`
authentication or authorisation refused (the reason never says which check failed), `4408`
timeout, `4429` rate limited, `4503` node unavailable.

## Consequences for the operator

Running this listener makes the node the code origin and the transport endpoint of its web
users. This document describes the software's behaviour; which duties follow from operating
such a service depends on where and for whom it is operated.
