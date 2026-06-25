# Security Policy

Ramflux is an end-to-end-encrypted messaging and federation system. We take
security reports seriously and practice coordinated disclosure.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Report privately through either:

- **GitHub Security Advisories** — "Report a vulnerability" on the repository's
  Security tab (preferred), or
- **Email** — security@spanbrain.org (PGP key published at
  `/.well-known/security.txt` — TODO: publish key).

Please include:

- the affected component and version (or commit),
- the impact and a realistic attack scenario,
- reproduction steps or a proof of concept,
- any suggested remediation.

## Our commitment

- **Acknowledgement within 72 hours.**
- An initial assessment and severity rating within one week.
- For critical issues, a coordinated fix target of two weeks; we will keep you
  updated if a fix needs longer.
- **Coordinated disclosure**: we agree a public disclosure date with you and
  credit you by name (unless you prefer to remain anonymous).

## Supported versions

| Version | Supported |
|---------|-----------|
| latest `0.x` release | ✅ |
| older `0.x` | ❌ (please upgrade) |

Until 1.0, only the latest minor release receives security fixes. The support
table will be updated when a stable line is established.

## Scope

In scope: the core node services, SDK, CLI, protocol, and cryptography in this
repository; the official clients in the `ramflux-tui` / `ramflux-desktop` /
`ramflux-app` repositories.

Out of scope: third-party forks and modified clients (see `TRADEMARKS.md`),
self-hosting misconfiguration, and issues requiring a compromised host or a
malicious local operator with root.

## Dependency advisories

Supply-chain advisories are tracked in CI (`cargo audit` + `cargo deny`). Any
advisory we deliberately suppress in `deny.toml` is listed below with a
justification.

| Advisory | Crate | Status | Justification |
|----------|-------|--------|---------------|
| RUSTSEC-2023-0089 | `atomic-polyfill` | suppressed | Transitive through `postcard` / `heapless`; tracked for migration while P3 preserves the dependency graph. |
| RUSTSEC-2024-0384 | `instant` | suppressed | Transitive through `glommio`; tracked for gateway runtime dependency migration. |
| RUSTSEC-2025-0134 | `rustls-pemfile` | suppressed | Direct PEM loader dependency; tracked for migration to `rustls-pki-types` PEM APIs. |
