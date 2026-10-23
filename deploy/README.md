# Persistent LAN demo node

`./deploy/scripts/demo-node.sh {up|down|status|logs} ENV_FILE` runs the production
seven-service compose as an isolated, persistent demo project. Use a Linux host
with Docker Compose v2 (`--wait` support), the pinned Rust toolchain, native build
dependencies, OpenSSL, Python 3, and sufficient disk space. No test service images
or relay HMAC key are used. The operator env file is required and is trusted shell
configuration: keep it outside the repository and restrict it to its owner.

Build the trust/discovery helper from the matching `ramflux-itest` checkout once:

```sh
cd /path/to/ramflux-itest
cargo build --locked --release --bin demo-node-tool
```

Create an operator-only env file (replace the paths and advertised DNS name):

```sh
DEMO_HOST=demo.example.org
DEMO_PROJECT=ramflux-demo
DEMO_DATA_DIR=/srv/ramflux-demo
DEMO_TOOL=/path/to/ramflux-itest/target/release/demo-node-tool
# Optional defaults:
DEMO_NODE_ID=demo.invalid
DEMO_GATEWAY_PORT=58443
DEMO_RELAY_PORT=58447
DEMO_HTTP_PORT=58482
DEMO_TURN_PORT=58478
DEMO_MESH_PORT=58453
DEMO_BIND_ADDR=0.0.0.0
# Image tag defaults to DEMO_PROJECT, isolating demo image tags across projects.
DEMO_VERSION=ramflux-demo
```

`DEMO_HOST` accepts a DNS name or IPv4 address, without a URL scheme or port.
`DEMO_NODE_ID` is the stable logical identity, independent of the host name.
The data directory must initially be empty and dedicated to this project. Once
initialized, settings and its canonical path are frozen: restore the original env
file if they change. Use another project and directory for a separate deployment.
Use distinct ports for separate projects. `DEMO_MESH_PORT` binds only to loopback;
other published ports bind to `DEMO_BIND_ADDR`. Allow the configured gateway
TCP/UDP, relay UDP, discovery/prekey HTTP TCP, and TURN TCP/UDP ports through the
host firewall as appropriate for the demo LAN. DNS must resolve from the desktop.
IPv6 advertisement is not supported by this wrapper.

```sh
cd /path/to/ramflux
chmod 600 /path/to/demo.env
# Build dependencies must be installed; use the workspace's default target directory.
unset CARGO_TARGET_DIR
sh deploy/scripts/demo-node.sh up /path/to/demo.env
sh deploy/scripts/demo-node.sh status /path/to/demo.env
sh deploy/scripts/demo-node.sh logs /path/to/demo.env
sh deploy/scripts/demo-node.sh down /path/to/demo.env
# Explicitly destroy only this project's named volumes and private trust directory:
sh deploy/scripts/demo-node.sh down /path/to/demo.env --purge
```

`up` reuses the existing CA, service certificates, random identity seeds, gateway
v3 issuer certificate, offline-root-signed provider keyring and provider-signed
snapshot. Signing code is shared with the s71/s72 production acceptance fixtures.
It prebuilds the production binaries with `build-prod-images.sh`, builds the thin
runtime images, starts compose with `restart: unless-stopped`, and waits for all
service health checks. Normal `down` preserves named volumes and all trust files.
Initialization recovers missing generated trust files using the same saved keys.
Demo trust lasts one year; the helper refuses identities within an hour of expiry.
There is no automatic key rotation. Preserve the private data directory and named
volumes together when backing up; never commit or distribute `identity.json`,
`identity.env`, `runtime.env`, or CA private keys. Only service TLS private keys
are mounted into their respective services; provider/offline signing seeds stay
outside containers.

The desktop adds the printed `http://DEMO_HOST:DEMO_HTTP_PORT` URL, then confirms
the node using the expected public key over a trusted channel. Discovery and
prekey HTTP use the same explicit LAN HTTP origin as the s72 fixture; gateway and
relay use server-authenticated QUIC with the CA from the signed discovery record.
This wrapper does not provide public HTTPS termination. Use it on a controlled
demo LAN: HTTP metadata and prekey traffic are visible there. The SDK's TLS-only
prekey probe currently reports failure for this HTTP origin, as expected in s72.
The federation HTTP listener also exposes token-protected administration routes;
keep its port limited to the demo LAN and keep the generated admin token private.

`status` checks all seven container health states, then fetches the client record,
verifies freshness, signature and the saved operator public key, and probes both
gateway and relay QUIC `/healthz` using that record's CA and advertised endpoints.
It exits nonzero on any failure. Health probes do not prove account creation, DM,
attachments, or TURN behavior; those require the desktop/controller acceptance.

For a LAN check on another machine, build the same helper natively there and use
a local env file with the settings above, a local `DEMO_TOOL` path and only this
additional public value copied over a trusted channel from the host's
`identity.env`:

```sh
DEMO_EXPECTED_NODE_PUBLIC_KEY=replace_with_public_pin
```

```sh
sh deploy/scripts/demo-node.sh status /path/to/local-demo.env --remote
```

Remote status needs no Docker or host data directory. It verifies the signed
record and both QUIC application health endpoints over the LAN; it cannot inspect
container health. Neither status mode confirms or changes desktop trust pins.

Every managed container, volume and network has a random ownership label. The
wrapper refuses operations when any resource under the requested compose project
has a different/missing owner label. It never prunes, removes images, removes
orphans, or manages other compose projects. A sibling `<data-directory>.lock`
serializes operations; after an interrupted process, check that no wrapper is
running before manually removing a stale empty lock directory. Invoke the wrapper
as the same host user and Docker context each time; it ignores inherited Docker
and compose environment overrides and uses that user's default Docker context.
