# Ramflux

Ramflux is a self-hostable, end-to-end encrypted messaging core for private
nodes, federation, and local-first clients.

This repository is the BSD-3-Clause Ramflux core. It contains the seven node
services, the Rust SDK, the reference `rf` CLI, and the shared protocol,
cryptography, storage, transport, sync, and core libraries.

## What is in this workspace

- `apps/ramflux-gateway` — client entrypoint for GatewayFrame sessions.
- `apps/ramflux-router` — online routing, offline inbox, replay protection,
  and delivery fanout.
- `apps/ramflux-notify` — coarse wake dispatch and notification provider
  integration.
- `apps/ramflux-federation` — node discovery, trust pinning, and cross-node
  delivery.
- `apps/ramflux-relay` — encrypted object and media relay.
- `apps/ramflux-signaling` — call signaling and TURN credential support.
- `apps/ramflux-retention` — retention policy and deletion enforcement.
- `apps/rf` — reference CLI over the SDK local bus.
- `crates/ramflux-sdk` — Rust SDK facade and C ABI substrate.
- `crates/ramflux-{core,protocol,crypto,storage,transport,sync,node-core}` —
  shared libraries used by the services, SDK, and CLI.

## Quick Start

Build the workspace:

```sh
cargo build --workspace
```

Run tests:

```sh
cargo test --workspace
```

Prebuilt `v0.1.0` release binaries are published for Linux x64 and macOS
arm64:

- `x86_64-unknown-linux-gnu`
- `aarch64-apple-darwin`

Linux arm64, Intel Mac, and Windows binaries are not part of the `v0.1.0`
release target set.

Start a local self-hosted node with Docker Compose:

```sh
cargo build --workspace --release
./deploy/scripts/bootstrap-ca.sh
./deploy/scripts/issue-certs.sh
docker compose -f deploy/docker-compose.yml up --build
```

The compose file starts all seven services and exposes the gateway on TCP and
QUIC port `443` by default. For local development without privileged ports:

```sh
RAMFLUX_GATEWAY_TCP_PORT=8443 \
RAMFLUX_GATEWAY_QUIC_PORT=8443 \
docker compose -f deploy/docker-compose.yml up --build
```

Stop the node and remove local volumes:

```sh
docker compose -f deploy/docker-compose.yml down -v
```

## Security

Do not file public issues for vulnerabilities. See `SECURITY.md` and
https://ramflux.org/security for coordinated disclosure.

## Licensing

Ramflux is open-core:

- This core workspace is licensed under BSD-3-Clause.
- Official interactive client repositories, including the terminal UI client,
  are licensed under AGPL-3.0-or-later with the project exception described in
  their repositories.
- The Ramflux name and logo are trademarks of Span Brain; see `TRADEMARKS.md`.

Ramflux is part of Span Brain.
