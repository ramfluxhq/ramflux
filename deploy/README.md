# Persistent LAN demo node

`./deploy/scripts/demo-node.sh {up|down|status|logs} ENV_FILE` runs the production
seven-service compose as an isolated, persistent demo project. Use a Linux host
with Docker Compose v2 or Podman with podman-compose 1.3.0 (or a compatible
compose provider), the pinned Rust toolchain, native build dependencies, OpenSSL,
Python 3, and sufficient disk space. No test service images
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
DEMO_GATEWAY_PORT=59443
DEMO_RELAY_PORT=59447
DEMO_HTTP_PORT=59482
DEMO_TURN_PORT=59478
DEMO_MESH_PORT=59453
DEMO_BIND_ADDR=0.0.0.0
# Image tag defaults to DEMO_PROJECT, isolating demo image tags across projects.
DEMO_VERSION=ramflux-demo
# Health wait controls can change without changing the project identity/settings:
DEMO_HEALTH_TIMEOUT_SECONDS=180
DEMO_HEALTH_POLL_SECONDS=2
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
IPv6 advertisement is not supported by this wrapper. The default 594xx ports
leave the integration fixtures' 584xx ports available. Existing project settings
remain frozen: if a project was initialized with other ports, specify those ports
explicitly in its env file rather than editing its ownership marker or purging data.

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
runtime images, starts compose with `restart: unless-stopped`, and polls all seven
services until each is running and healthy. The wait defaults to 180 seconds with
a two-second poll interval, configurable from 1 to 3600 seconds. A detected exited,
unhealthy, unchecked or duplicate service fails immediately; a missing or starting
service is retried until the deadline. Failure prints project status and recent
logs, exits nonzero, and retains the project for diagnosis. Compose runs from the
state directory with absolute file paths; neither `--project-directory` nor
`--wait` is used. Normal `down` preserves named volumes and all trust files.
Initialization recovers missing generated trust files using the same saved keys.
`runtime.env` explicitly sets every relay environment variable, including its
30-second refresh interval and internal listener address, plus gateway/federation
path and mode defaults. Required keyring-provider inputs include
`RAMFLUX_FEDERATION_PROVIDER_KEYRING_FILE=/etc/ramflux/federation/provider-keyring.json`
and `RAMFLUX_RELAY_TRUST_SNAPSHOT_CACHE_FILE=/var/lib/ramflux/relay/trust-snapshot.json`.
Concrete values avoid unresolved self-referential defaults in podman-compose 1.3.0.
The actual-provider regression renders the complete generated project and rejects
unresolved `${...}` expressions anywhere in the result. Run it without a container
runtime, using an installed `podman-compose` (with its Python dependencies):

```sh
DEMO_TEST_PODMAN_COMPOSE=podman-compose \
  python3 -m unittest discover -s deploy/scripts/tests -v
```

For a standalone provider script, set `DEMO_TEST_PODMAN_COMPOSE` to its Python
command instead. The config test uses a stub Podman executable that permits only
`--version`; it cannot start containers. It is explicitly skipped if no provider
is installed or configured. Other lifecycle tests always use fake CLIs.

The keyring and signed snapshot use the read-only `secrets/federation` mount; the
relay creates and persists its verified snapshot cache and anti-rollback state in
`relay-redb`. The wrapper never seeds or resets that cache. To repair an existing
project, run `up` with the original env file: it regenerates `runtime.env` while
preserving identity, signed trust and named volumes; no purge is needed.
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
as the same host user and container engine each time. Provider detection prefers
native Docker with Compose v2, then Podman with standalone `podman-compose`, then
Podman's compose wrapper or the Docker-compatible Podman wrapper. It prints the
selected provider and uses that engine for ownership and health inspection.
Service lookup uses project/service labels rather than `compose ps -q SERVICE`,
which podman-compose 1.3.0 does not filter by service. Inherited remote-engine and
compose overrides are ignored; `XDG_RUNTIME_DIR` is preserved for rootless Podman.
Use the same user's default engine context for every operation.
