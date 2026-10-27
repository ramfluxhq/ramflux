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

```

Use `podman build` instead when Podman is the selected engine. Follow the
one-image-per-archive transfer procedure and image identity checklist in
[Upgrading or rolling back](#upgrading-or-rolling-back-an-existing-demo-and-private-admin-access).
Load all seven archives into the same engine/user context used by the wrapper,
then set `DEMO_VERSION=release-2026-10-27` and `DEMO_PREBUILT_IMAGES=1` in the
operator env file.

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

Federation header, body, timeout and connection limits are validated before every
local command. An invalid value therefore also blocks `status`, `logs`, `down` and
`down --purge`; correct the operator env before retrying the maintenance command.

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

### Upgrading or rolling back an existing demo and private admin access

Change only `DEMO_VERSION` in the operator env, then run the explicit upgrade path:

```sh
deploy/scripts/demo-node.sh upgrade /absolute/path/to/demo.env
```

The command builds all seven images, or with `DEMO_PREBUILT_IMAGES=1` first verifies
that all seven versioned images are loaded, have distinct image IDs, and each declares
`RAMFLUX_BIN=ramflux-<service>` in its image environment or label. If both are present,
both must match. Missing, malformed, aliased, or mismatched images are refused with the
offending service names before snapshot/config changes or container recreation. It uses
`--no-build` after validation. The first successful
`up` starts the version history. Every successful `up` or `upgrade` creates a private,
read-only snapshot under `version-snapshots/` containing `owner.json`, `runtime.env`,
`demo-override.json`, the deploy-tree digest, the exact frozen base/voice/admin Compose
files, and every managed input the operation can rewrite: `config/`, `certs/`,
`secrets/`, `.env`, `identity.env`, and `owner.token`. These snapshots therefore contain
private keys, signing seeds, and admin tokens. The state and snapshot directories remain
mode 0700 and snapshot files mode 0400; back up and grant access to the whole tree as
secret material. Publication fsyncs every file and containing directory before the
transaction marker can refer to it. The tool retains the current snapshot plus its
three predecessors and removes older snapshots and abandoned partial captures. It
retains the node identity, CA, seeds, volumes, ports and all other ownership settings,
and prints the canonical rollback command. A plain `up` still refuses a version change.
An upgrade also refuses a missing or newly selected voice/admin overlay, reporting only
the relevant configuration key.

Without custody inputs the node still runs and serves public probes, but accounts
remain `networking_pending` and cannot use contacts, messaging, groups, or calls.
Each `up` prints one `WARNING: custody is not configured; accounts remain networking_pending`
line when custody is absent. To enable custody, provide all three inputs:
`RAMFLUX_CUSTODY_NODE_PUBLIC_KEY` (the independently trusted receiving-node public
key), `RAMFLUX_CUSTODY_NODE_RECORD_FILE` (an absolute host path to its signed
record), and `RAMFLUX_CUSTODY_PROXY_SIGNING_SEED` (the matching node-authorized
gateway proxy seed). Once any is set, a partial configuration refuses before
creating the data directory or performing any transaction or engine action with
`DEMO_CUSTODY_INPUT_MISSING: <key>`; an
unreadable, empty, oversized, or symlinked record reports
`DEMO_CUSTODY_INPUT_INVALID: RAMFLUX_CUSTODY_NODE_RECORD_FILE`. The same checks
apply to first install and an upgrade from a version without custody inputs.
No receiving-node key, record, or proxy signing seed is generated or inferred.
`RAMFLUX_CUSTODY_PROXY_SIGNING_SEED` is forwarded only to the gateway;
receipt mode requires the dedicated node-authorized seed described in
[custody configuration](../docs/custody_networking.md#receiving-node-configuration).

The wrapper keeps a private managed copy of the signed record, mounts it read-only
into the router, and retains the custody public key, configured proxy seed and
`RAMFLUX_CUSTODY_{HANDSHAKE_POOL,AUTHENTICATED_POOL,AUTH_TIMEOUT_MS}` inputs in
`runtime.env` with their Compose aliases. A version-only upgrade reuses these
retained inputs when the operator env omits them. Replacing or clearing a retained
custody public key or proxy seed refuses with `DEMO_CUSTODY_INPUT_CHANGED: <key>`;
an image upgrade cannot silently replace the receiving-node pin or signing identity.
Rollback and recovery restore
the exact snapshot inputs and record bytes, without consulting the operator's
current custody settings or the original record path. Service startup still
performs signed-record and pool validation; wrapper validation is not a signature
or authorization check.

A same-version `up` accepts a renewed signed record under the retained node pin
and proxy seed. When its bytes change, the wrapper prints
`custody record changed; restarting ramflux-router` and restarts only that service
before health and public probes. Unchanged record bytes do not trigger this restart.
If the restart or probes fail, the pending marker remains for explicit recovery.
Proxy-seed rotation still requires a separately supported transaction; ordinary
`up` and `upgrade` keep refusing a changed seed.

Rollback restores record and configuration files, but does not restore the
router custody state in `router-redb`. A previously applied record epoch or pin
cannot be undone by restoring older files. A rollback across record versions may
therefore fail router validation; it retains the pending marker, and `recover`
restores the last-good snapshot and reruns health and public probes before
clearing it. Recovery preserves the router's monotonic custody checks and never
resets its volume or bypasses record validation.

When transferring prebuilt images, use one image per archive, especially with Podman.
On the source host, set the selected engine and exact version, then save each image:

```sh
engine=podman  # Or docker; use the engine that holds the built images.
version=demo-v2
for service in gateway router notify federation relay signaling retention; do
  image="ghcr.io/ramfluxhq/ramflux-$service:$version"
  "$engine" image inspect "$image" > "ramflux-$service-$version.inspect.json"
  "$engine" save -o "ramflux-$service-$version.tar" "$image"
done
```

Transfer the seven archives and inspection records through a trusted channel. On the
destination host, use its selected engine to load each archive separately:

```sh
engine=podman  # Or docker on the destination.
version=demo-v2
for service in gateway router notify federation relay signaling retention; do
  "$engine" load -i "ramflux-$service-$version.tar"
  "$engine" image inspect "ghcr.io/ramfluxhq/ramflux-$service:$version" \
    > "loaded-ramflux-$service-$version.inspect.json"
done
```

Transfer checklist before changing `DEMO_VERSION` or running `upgrade`:

- Verify seven distinct image IDs on the source host and seven on the destination.
- Compare each service's full image ID between its source and loaded inspection records
  (`Id` or `ID`; ignore an optional `sha256:` prefix). Each pair must match.
- Verify each record's `Config.Env` or `Config.Labels` declares the expected
  `RAMFLUX_BIN=ramflux-<service>`. All declarations must agree with the service name.
- Keep the prior version's images available for rollback/recovery and check them too.
  Do not use a single multi-name `podman save` invocation for these seven archives.

Run the printed `demo-node.sh rollback ENV_FILE` command while retaining the current
env file. Rollback selects the preceding immutable snapshot, restores every managed
file byte-for-byte without consulting the current checkout, verifies that all seven
old images remain available, and recreates the services with `--no-build`. Container
health alone is insufficient: `up`, `upgrade`, `rollback`, and recovery also run the
signed public discovery and application probes through the published origin before
committing their state. After rollback succeeds, restore `DEMO_VERSION` in the operator
env to the printed version; later maintenance commands fail closed while the env and
recorded version differ. Keep previously deployed images and the private snapshot tree
until the upgrade has been accepted. Public discovery/prekeys remain on
`DEMO_HTTP_PORT` (default 59482); neither admin 18084 nor an unintended default host
18082 is published.

If the target snapshot used a different voice or private-admin overlay selection,
first update the operator env to that target selection: set or unset
`RAMFLUX_DEMO_VOICE_UDP_PORT` and `DEMO_ADMIN_LOOPBACK_PORT` exactly as they were for
the target version, then run `rollback`. Rollback validates that explicit selection
against the target snapshot before writing anything and derives its Compose files from
the restored snapshot. If rollback itself fails, explicit recovery derives the source
selection from the restored last-good runtime state.

For a state without snapshot metadata, `up` or `upgrade` first captures and fsyncs the
complete current state and only then publishes `transaction.pending`. For an already
adopted state, the last-good snapshot already exists before the marker is written. If image
recreation, container health, or the public probes fail, the wrapper retains the pending
transaction for explicit recovery. While it exists, all commands other than `recover`
and `rollback` refuse with exit 3 and the transaction ID, without restoring files or
calling Compose. This includes `status --remote`, `down`, `logs`, `up`, and `upgrade`.
Correct the engine or restore the retained old images, keep the same
operator settings (the failed target `DEMO_VERSION` may remain), then run:

```sh
deploy/scripts/demo-node.sh recover /absolute/path/to/demo.env
```

Recovery restores the marker's last-good snapshot, recreates containers with
`--no-build`, verifies container health and the public endpoints, and removes the marker
only after success. Failed recovery keeps the marker for another explicit attempt.
`rollback` with a pending transaction performs this same recovery to the last-good
snapshot; without a pending transaction it selects the preceding version as usual. Never delete the
marker or edit a snapshot to force progress. If the named snapshot is missing or
partial, recovery refuses with the manual path: restore the complete demo data
directory from the operator backup, verify `owner.json`, and only then remove
`transaction.pending`. The adjacent `.lock` is always released on ordinary failures.
After SIGKILL, first verify that no demo operation remains and remove only that stale
adjacent lock.

A failed first `up` has no previous version to restore. Its exit-3 diagnostic instead
says ``initial setup failed: run `demo-node.sh recover` to undo it``. Keep the original
operator settings and run `recover` (or `rollback`): the tool stops and removes only
this project's containers and networks after checking their project labels and owner
token. It also removes the project's owned volumes created by that first setup:
retaining their old owner token would prevent a fresh `up`. It then removes the files
created by the failed setup and clears the marker last. Other projects are preserved.
No images or complete
Compose files are needed for this cleanup. A removal failure retains the marker so
the operation can be retried. Successful cleanup prints
``initial setup rolled back; run `up` again`` and leaves the originally empty data
directory ready for another `up`. Resource conflicts are checked before a new
transaction is published; a refused adoption leaves no pending marker.

For temporary administration, set `DEMO_ADMIN_LOOPBACK_PORT=59487` in the operator
env and run `up`. This opt-in binds only `127.0.0.1`, even with a public
`DEMO_BIND_ADDR`, and can be reached through an SSH tunnel. Unset it and run `up`
to remove the mapping. Production installs can use `docker-compose.admin.yml`
with `RAMFLUX_FEDERATION_ADMIN_LOOPBACK_PORT`. See
[listener configuration, bounds and SSH commands](../docs/federation_http.md).

For upgrades from tooling older than this snapshot workflow, first save the complete
private state and retain the original checkout and images. Never remove identity or
volumes. The first new-tooling `up` or `upgrade` takes the old state as its first durable
snapshot before publishing a transaction marker.

For the sd001 deployment specifically, retain the existing manual-backup directory
`B`, stage this deploy tree, and run `demo-node.sh up ENV_FILE` with the existing env
unchanged (`DEMO_VERSION=sd001-9a8961a9` and `DEMO_PREBUILT_IMAGES=1`). Confirm that
`owner.json` now has `current_snapshot`, then run local `status` and `status --remote`
with the trusted `qxoGmWD1…` node pin. That adopted snapshot is the rollback target for
the next upgrade. The tooling cannot roll back to the older `sd001-2da4a6d2` state,
which predates snapshot metadata; the retained manual backup `B` is the only rollback
path to that version. The script validates the public connection limit before state or
engine changes.

## Demo custody provisioning

Native accounts need custody to leave `networking_pending`. Public discovery and
health probes alone do not establish account networking. The included
`deploy/scripts/demo-node.sh` consumes the provisioning fragment directly. First
create the demo state and discovery identity with the normal `up` procedure above;
without custody it prints the warning above and leaves accounts pending. Then
provision custody and run `up` again with the same operator settings.
`rf node custody-init` and `rf node custody-renew` are local operator
commands: they do not connect to a daemon or a remote node.

Custody records use the **existing pinned discovery identity**, not a separate
custody root. Its signing seed is already online because federation signs live
discovery with it. Prefer running the tool on that server so the key needs no
second copy. An operator machine holding an explicitly protected copy can also
run it; securely transfer the generated record and env fragment to the server
and adapt only a separate deployment copy of the fragment for that host's record path.
Never edit an original prepared fragment or its signed record. Never transfer the
node seed to clients, print it, generate a replacement, or claim it is offline-only.
The proxy key is a distinct software Ed25519 credential, not an HSM claim.

Build `rf` with `cargo build -p ramflux-rf --bin rf`. On the server, load the
trusted operator env and the already created private `identity.env`, then run:

```sh
set -a
. /absolute/path/demo.env
. "$DEMO_DATA_DIR/identity.env"
set +a
DEMO_NODE_ID=${DEMO_NODE_ID:-demo.invalid}
rf node custody-init \
  --node-id "$DEMO_NODE_ID" \
  --node-signing-seed "$DEMO_DATA_DIR/certs/node-identity/node-signing.key" \
  --expected-public-key "$DEMO_EXPECTED_NODE_PUBLIC_KEY" \
  --output-dir "$DEMO_DATA_DIR/custody-provisioning" \
  --validity-days 30
cp "$DEMO_DATA_DIR/custody-provisioning/custody-epoch-1.env" "$DEMO_DATA_DIR/custody.active.env"
chmod 600 "$DEMO_DATA_DIR/custody.active.env"
```

The seed path is explicit and must already exist, with the same canonical
base64url seed used by federation. The expected public key must equal its
public key and the independently retained discovery pin. The command refuses
a wrong pin or missing seed. Validity is **1–30 days**, default 30, bounded by
the existing protocol limit; stdout reports the expiry as Unix UTC seconds and
never prints a private seed. Output directories must be owned by the invoking
user with mode 0700; records and env
fragments are 0600. Protect their backups as credentials.

The fragment has exactly `RAMFLUX_CUSTODY_NODE_PUBLIC_KEY`,
`RAMFLUX_CUSTODY_NODE_RECORD_FILE` and `RAMFLUX_CUSTODY_PROXY_SIGNING_SEED`.
Add this line to `/absolute/path/demo.env`, after its `DEMO_DATA_DIR` setting:

```sh
. "$DEMO_DATA_DIR/custody.active.env"
```

Then apply the initial credentials with the included wrapper:

```sh
deploy/scripts/demo-node.sh up /absolute/path/demo.env
```

The wrapper copies the signed record to
`$DEMO_DATA_DIR/secrets/custody/node-record.json` and mounts it read-only at
`/etc/ramflux/custody/node-record.json` inside the router. It sends the matching
proxy seed only to the gateway. Use the generated record together with its
matching seed. The record authorizes `ramflux-gateway`
for this node's audience in `HomeRelayReceipt` mode. No unbound mode is enabled.

Give demo users the published discovery origin, exact `DEMO_NODE_ID` and existing
`DEMO_EXPECTED_NODE_PUBLIC_KEY` through an authenticated operator channel. On each
client, set `DISCOVERY_ORIGIN`, `NODE_ID` and `NODE_PUBLIC_KEY` to those supplied
values, then confirm that same identity with its running local daemon:

```sh
rf node add "$DISCOVERY_ORIGIN"
rf node confirm "$NODE_ID" --pin-source operator --expected-public-key "$NODE_PUBLIC_KEY"
rf node set-default "$NODE_ID"
```

The SDK/desktop node profile uses this discovery pin for custody too; no second
pin or trust channel is introduced.

Prepare renewal **before the deployed proxy's printed signing deadline**. Every
renewal requires the signed record **currently installed on the node**, not a
record from a previous preparation. On the server, use the demo wrapper's managed
copy:

```sh
rf node custody-renew \
  --node-id "$DEMO_NODE_ID" \
  --node-signing-seed "$DEMO_DATA_DIR/certs/node-identity/node-signing.key" \
  --expected-public-key "$DEMO_EXPECTED_NODE_PUBLIC_KEY" \
  --output-dir "$DEMO_DATA_DIR/custody-provisioning" \
  --deployed-record "$DEMO_DATA_DIR/secrets/custody/node-record.json" \
  --validity-days 30
```

On an operator machine, retrieve an authenticated copy of that installed record
from the server and name the local copy with `--deployed-record`. The tool checks
its signature against the retained node pin; it does not contact the server to
attest which record is installed. Keep the node seed protected and avoid another
copy by provisioning on the server when possible.

A deployed epoch N produces epoch N+1, linked to that exact deployed record's hash.
Output is an **immutable** `custody-epoch-<N+1>.env` plus its hash-named record in
`records/`. Initial install also retains `custody.env` for compatibility; renewal
never rewrites it. No prepared fragment is ever overwritten or edited. Keep the
provisioning directory at its original path and retain the whole private tree,
including every prepared seed and signed predecessor. Only a separate deployment
copy, such as `custody.active.env`, may be adapted for another host's absolute
record path. Do not move or edit the original provisioning fragments.

Preparing again from the same deployed head refuses with
`DEMO_CUSTODY_ALREADY_PREPARED`. Deploy the existing preparation before preparing
its successor. If an alternative preparation is intentional, add
`--force-new-proxy`: the tool writes another immutable
`custody-epoch-<N+1>-<record-hash>.env`, keeps the original fragment/seed, and still
builds on deployed epoch N. It never silently advances to N+2. Select exactly one
alternative for deployment. After coordinated rotation installs that selected
record, the managed deployed copy permits preparing the next epoch. Forced
`custody-init` on existing output also requires an explicit `--deployed-record`
and follows these same rules; it cannot reset the epoch or infer deployment.

Renewal generates a fresh proxy seed/key id, retains cumulative revocations and
required retiring descriptors, and never extends an old key's signing interval.
Publication fsyncs the record before atomically linking its complete fragment
into place without replacement. The protocol permits at most 16 concurrent/overlap
descriptors; excess retained descriptors are refused rather than discarded.

On Unix hosts (Linux and macOS), inputs are opened without following their final
symlink and type/mode checks use the opened descriptor. Output operations are
relative to held directory descriptors. Keep the output directory and its ancestry
under operator control and stable while running the tool; an absolute path in an
immutable fragment cannot track later directory renames. Platforms without this
Unix filesystem support refuse provisioning rather than use a weaker fallback.

The persistent 0600 `.lock` inode records the owning pid and operation start time
while a kernel advisory lock is held. An idle lock has `pid: null` and is retained
to avoid replacement races. A live owner refuses with
`DEMO_CUSTODY_OPERATION_RUNNING`; a dead owner is reclaimed with
`DEMO_CUSTODY_STALE_LOCK_RECLAIMED`. No process is signalled. A malformed or legacy
lock without readable ownership refuses with `DEMO_CUSTODY_LOCK_INVALID`: only
after independently verifying that no custody operation is running may an operator
remove that exact stale `.lock`. Never remove a live lock. Temporary files are
removed on ordinary error paths; after a killed process, the next exclusive
operation removes abandoned temporary files in this tool's private namespace.

The wrapper can apply changed record bytes under the same retained pin and proxy
seed with a same-version `up`; it restarts the router as described above. This
tool's `custody-renew` also generates a new proxy seed, so that record-only path
does not apply its output.

**Applying a changed proxy seed through the demo wrapper is pending the dedicated
DEMO-UPGRADE-FU-02 coordinated rotation operation.** Preparing renewal does not
deploy it or extend the deployed credential's deadline. Keep deployed `custody.active.env` unchanged
until that operation is available; ordinary `up`/`upgrade` deliberately refuse
proxy-seed replacement. Do not bypass this by editing `runtime.env`, copying a
prepared record over the installed record to simulate deployment, deleting state,
or resetting the node identity. Arrange supported rotation before the deployed
credential expires. Router custody epochs and key pins persist in the data
volume; restoring an older record file does not roll those pins back.
