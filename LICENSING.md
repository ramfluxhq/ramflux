# Licensing

Ramflux is an **open-core** project. Different components carry different
licenses, chosen so that the parts users must be able to audit are permissively
open, while the installed clients — the real trust boundary for an
end-to-end-encrypted system — stay copyleft.

| Component | Repository / path | License | Why |
|-----------|-------------------|---------|-----|
| Core: node services (gateway, router, notify, federation, relay, signaling, retention), SDK, `rf` CLI, protocol, crypto, storage, transport | `ramflux` (this workspace) | **BSD-3-Clause** | An open, auditable core is a *trust* asset. Anyone can read, verify, fork, and self-host it. |
| GUI / terminal clients (`rf-tui`, future desktop/mobile) | `ramflux-tui`, `ramflux-desktop`, `ramflux-app` | **AGPL-3.0-or-later** (with an App-Store Exception, AGPL §7) | The installed client is where the no-logs / E2EE claim actually lives; copyleft keeps modified clients honest and auditable. |
| Managed / commercial control plane (hosted console, billing) | private | Proprietary | Funds the project; never required to self-host. |
| Name and logo | — | Trademark — see `TRADEMARKS.md` | The code license does not grant brand rights. |

## Per-file SPDX headers

Every source file carries an SPDX identifier on the first lines:

```rust
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
```

Client repositories use `AGPL-3.0-or-later` instead. CI and the PR checklist
enforce the presence of an SPDX header.

## Contributions

- **Core (BSD-3-Clause)** uses an inbound = outbound model: by submitting a
  contribution you agree it is licensed under BSD-3-Clause. A DCO sign-off
  (`git commit -s`) is required — see `CONTRIBUTING.md`.
- **Clients (AGPL-3.0)** additionally require signing the individual `CLA.md`,
  whose relicensing clause permits the project to ship a commercial edition.

## Third-party code

See `NOTICE` for attributions of third-party and derived code.
