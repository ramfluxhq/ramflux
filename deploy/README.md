# Persistent LAN demo node

`./deploy/scripts/demo-node.sh {up|down|status|logs} ENV_FILE` runs the production
seven-service compose as an isolated, persistent demo project. Use a Linux host
with Docker Compose v2 or Podman with podman-compose 1.3.0 (or a compatible
compose provider), the pinned Rust toolchain, native build dependencies, OpenSSL,
Python 3, and sufficient disk space. No test service images
or relay HMAC key are used. The operator env file is required and is trusted shell
configuration: keep it outside the repository and restrict it to its owner.

## Compose interpolation inputs

The checked-in Compose files support Docker Compose v2 and podman-compose 1.3.0.
Service environment names remain `RAMFLUX_*`. Inputs that previously used their own
service name as an interpolation default now use a separate `RF_COMPOSE_*` name;
[compose-inputs.json](compose-inputs.json) lists every old service key and its new
Compose input. For example:

```dotenv
RF_COMPOSE_FEDERATION_NODE_ID=demo.example.org
RF_COMPOSE_CLIENT_GATEWAY_QUIC_ADDR=demo.example.org:443
RF_COMPOSE_NOTIFY_PROVIDER_CREDENTIALS_FILE=/run/secrets/providers.json
```

Migrate the mapped names in operator Compose env files or exported Compose inputs.
Names absent from the map, including published-port variables and the required
federation offline-root pin, retain their existing spelling. **Breaking operator
migration:** production security/identity inputs must now be explicitly configured;
unset or empty required inputs fail closed. Only optional inputs retain `:-`
defaults. Explicit migrated values and shared references retain their values.
Run the [mandatory preflight](#mandatory-compose-input-preflight-breaking-operator-migration)
with the same env files before every Compose command.
Production voice still requires a public endpoint, now supplied by
`RF_COMPOSE_RELAY_VOICE_PUBLIC_ENDPOINT`. Direct service launches continue to use
the original `RAMFLUX_*` runtime environment names.

The demo wrapper keeps `identity.env` unchanged and appends matching Compose aliases
to its private generated `runtime.env`. Existing demo data needs no identity,
certificate or volume migration: the next `up` regenerates that file. The integration
harness passes the mapped input aliases, preserving fixture-over-process
precedence and bootstrap inputs, generates admin tokens, runs preflight, and lints
against reintroduced self-defaults and missing aliases.

Services ignore literal `${…}` values only for the explicit non-security tuning
allowlist, with a key-only warning. Other unresolved inputs, including optional
security file paths, fail startup. Malformed relay budgets remain fatal. Other
optional numeric/runtime inputs retain their defaults; explicit empty settings
keep their existing meaning. Concrete secrets and trust files still undergo
normal validation; unresolved paths cannot select replacement signing material.

The following tests render all Compose variants without contacting a container
engine. `DEMO_TEST_PODMAN_COMPOSE` selects the installed provider; optionally set
`COMPOSE_TEST_DOCKER_COMPOSE` to a Docker Compose v2 command or standalone binary.
The Podman stub refuses every operation except `--version`.

```sh
DEMO_TEST_PODMAN_COMPOSE=podman-compose \
COMPOSE_TEST_DOCKER_COMPOSE='docker compose' \
  python3 -m unittest discover -s deploy/scripts/tests -v
```

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
# Opt in only after loading all seven matching images into this host's engine.
# DEMO_PREBUILT_IMAGES=1
# Health wait controls can change without changing the project identity/settings:
DEMO_HEALTH_TIMEOUT_SECONDS=180
DEMO_HEALTH_POLL_SECONDS=2
```

Node secrets are mode 0640 and the capability-dropped services read them through
the operator's group (`RAMFLUX_SECRET_GID`, set to `id -g` by the wrapper). See
`docs/server-data.md` for rootful Docker and rootless Podman.

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

### Prebuilt images for hosts that cannot compile

The default `up` path remains a local Rust build followed by Compose `--build`.
For a small target host, build and export the seven images on a separate Linux
host with the same CPU architecture. Choose one immutable `DEMO_VERSION` tag and
use it for every image:

```sh
cd /path/to/ramflux
DEMO_VERSION=release-2026-10-27
sh deploy/scripts/build-prod-images.sh
for service in gateway router notify federation relay signaling retention; do
  docker build -f deploy/Dockerfile --build-arg "BIN=ramflux-$service" \
    -t "ghcr.io/ramfluxhq/ramflux-$service:$DEMO_VERSION" .
done
docker save \
  $(for service in gateway router notify federation relay signaling retention; do
      printf 'ghcr.io/ramfluxhq/ramflux-%s:%s ' "$service" "$DEMO_VERSION"
    done) \
  -o ramflux-demo-images.tar
```

Use `podman build` and `podman save` instead when Podman is the selected engine.
Copy the archive to the target, load it into the same engine/user context used by
the demo wrapper, and add the matching values to the operator env file:

```sh
docker load -i ramflux-demo-images.tar  # or: podman load -i ...
DEMO_VERSION=release-2026-10-27
DEMO_PREBUILT_IMAGES=1
```

With this explicit opt-in, `up` still runs configuration preflight but skips the
local Cargo build and invokes Compose with `--no-build`. Before Compose starts,
the wrapper inspects all seven exact `ghcr.io/ramfluxhq/ramflux-<service>:TAG`
images in the detected engine. It lists every missing image and exits without
starting the project if any image is absent. It never pulls or substitutes tags.

`DEMO_TOOL` remains required for initialization, local `status`, and remote
verification. A `demo-node-tool` binary may be copied from a build host only when
it is statically compatible with the target: use the same CPU architecture and a
compatible glibc (or an intentionally static build). Keep the tool executable and
set its absolute target-host path as `DEMO_TOOL`.

### Optional voice UDP overlay

Set `RAMFLUX_DEMO_VOICE_UDP_PORT=59449` in the operator env file, or append
`--voice-udp-port 59449` to a command; the flag overrides the env value. The port
must be 1024..65535 and distinct from the gateway, relay-client, TURN and loopback mesh UDP ports.
With this option unset, the existing base Compose invocation is unchanged.

The wrapper freezes `deploy/docker-compose.voice.yml` as `compose.voice.yml` in
its state directory and includes it between the base and ownership override.
It writes concrete runtime values for `RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT`
(`DEMO_HOST:PORT`) and `RAMFLUX_RELAY_VOICE_UDP_PORT` (`DEMO_BIND_ADDR:PORT`),
plus the relay UDP/control listeners and gateway control endpoint. Only voice UDP
17449 is published at the selected host port; control TCP 17450 stays on the mesh.
Allow the chosen UDP port through the host/LAN firewall separately.

Voice is an optional overlay outside the frozen base identity settings: enabling,
changing or removing it with `up` preserves this project's existing data and keys.
Use the same selection for every invocation (prefer the operator env file).
Repeat `up` after changing it, before any other local command; clearing it and
repeating `up` removes the voice mapping. If the selected voice endpoint/port was
not applied by the last `up`, `status`, `logs`, `down` and `down --purge` stop
before Compose with a clear "run up first" message. Restore the last applied
selection to use those commands without applying the change. A frozen overlay file left behind is ignored when unset.
Local `status` checks the actual gateway/relay voice env and published UDP mapping
alongside service health. This checks configuration, not end-to-end audio delivery;
`status --remote` retains its existing discovery/QUIC checks and does not probe voice.

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
The wrapper also supplies the matching `RF_COMPOSE_*` inputs for these concrete runtime values.
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
The public federation HTTP listener exposes only client reads. Administration uses
a separate unpublished listener on the Compose network (port 18084). The demo HTTP
port remains the public origin. See [the route inventory](../docs/federation_http.md).

`status` checks all seven container health states, then fetches the client record,
verifies freshness, signature and the saved operator public key, and prints the
node key fingerprint using the same discovery domain as `node.add`/`node.list`.
It calls the SDK's pre-account gateway probe: verified QUIC first, then verified
TCP-TLS fallback if needed, using the signed record's CA and server name. The
first application frame is Heartbeat; only the protocol-constant
`first gateway frame must be open` Nack counts as success. No Open or Auth frame
is sent, and gateway session status remains `requires_account`. The relay check
continues to use client-facing QUIC `/healthz` and requires status 200. The helper
prints the selected gateway transport results and relay health; it exits nonzero
on any failure. Health probes do not prove account creation, DM,
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

### Mandatory Compose input preflight (breaking operator migration)

Before **every** Compose invocation (including config, logs and down), run:

```sh
python3 deploy/scripts/compose-preflight.py --env-file /path/to/operator.env
# Use exactly the same env files, in the same order, and the same process environment:
docker compose --env-file /path/to/operator.env -f deploy/docker-compose.yml config
```

With no explicit env file, preflight reads `.env` in the current directory. Repeated
`--env-file` arguments apply in order; process environment wins. Run both commands
from the same directory. If Compose's project directory has another implicit env
file, pass it explicitly to both commands; do not rely on implicit project lookup.
Use the same explicit files for Podman Compose. The demo wrapper and itest harness
invoke preflight automatically; existing frozen demo projects must be regenerated
through their normal `up` workflow before maintenance commands can pass migration.

Rename the outer inputs according to `deploy/compose-inputs.json` (service
variables **inside containers** retain `RAMFLUX_*`). Legacy names without an equal
new name, conflicting pairs, unresolved expressions and public default admin
secrets are refused with key names only. Equal dual names support generated env
files consumed by other tools. Remove stale exported legacy names too. Production
Compose now requires explicit federation/router admin tokens, signing and issuer
material, trust/cache paths, node identity, and all advertised client endpoints;
there is no public admin-token fallback. Generate independent random secrets,
provision the matching certificates/trust files, and set every required input
before rendering. Intentional unset/empty production inputs fail closed; this is
an operator-visible security change, not backward-compatible unset behaviour.

Only the explicitly enumerated non-security runtime/tuning keys in
`ramflux_core::environment::OPTIONAL_EXPRESSION_KEYS` may ignore a literal `${…}`
with a key-only warning. Security inputs, including optional credential, privacy,
trust and certificate file paths, fail startup rather than select another key.
Malformed relay metadata budgets fail startup; absence (or an unresolved optional
expression) selects the bounded default. Empty credential paths retain their
existing explicitly-disabled semantics where supported.

### Upgrading an existing demo and private admin access

Run the new `demo-node.sh up ENV_FILE` against the existing owned state directory.
`up` atomically refreshes changed shipped base/voice Compose copies and prints one
refresh notice. Ownership, identity, certificates and named data volumes survive;
operator ports still come from the env file. Maintenance commands use the saved
copies and do not refresh them. No manual deletion of `compose.yml`, identity
files or volumes is needed. Public discovery/prekeys remain on `DEMO_HTTP_PORT`
(default 59482); neither admin 18084 nor an unintended default host 18082 is published.

For temporary administration, set `DEMO_ADMIN_LOOPBACK_PORT=59487` in the operator
env and run `up`. This opt-in binds only `127.0.0.1`, even with a public
`DEMO_BIND_ADDR`, and can be reached through an SSH tunnel. Unset it and run `up`
to remove the mapping. Production installs can use `docker-compose.admin.yml`
with `RAMFLUX_FEDERATION_ADMIN_LOOPBACK_PORT`. See
[listener configuration, bounds and SSH commands](../docs/federation_http.md).

Before upgrading, save the private state's frozen definitions for rollback:
`cp -p STATE/compose.yml STATE/compose.yml.pre-split` and likewise save runtime.env
and compose.voice.yml when present, keeping the state directory private. To roll
back, stop the new project without `--purge`, restore the old checkout/images,
restore **compose.yml** (and the saved voice copy) from those backups, then run the
old `up` with the original operator env. Restoring compose.yml is mandatory:
otherwise the old script mixes a new definition with old port inputs and can
publish default host 18082 while breaking 59482. Never remove identity or volumes.
The new script validates the public connection limit before state or engine changes.
