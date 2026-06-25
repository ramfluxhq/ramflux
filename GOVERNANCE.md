# Governance

This document describes how the Ramflux project is run and how decisions are
made. It is intentionally lightweight; it will grow as the community does.

## Roles

- **Maintainers** — have commit and release rights, review and merge PRs, and
  are responsible for the project's direction, security, and releases.
- **Contributors** — anyone who submits issues, PRs, docs, or reviews.

The current maintainers are listed in `MAINTAINERS.md` / `CODEOWNERS`.

## Decision making

- Day-to-day changes are decided by maintainer review: a PR may merge once it
  has at least one maintainer approval and CI is green. Security-, crypto-, and
  protocol-sensitive paths (see `CODEOWNERS`) require approval from a maintainer
  who owns that area.
- Larger or breaking changes (wire protocol, security model, licensing,
  governance) are proposed as a written issue/RFC and decided by **lazy
  consensus** among maintainers: if no maintainer objects within a reasonable
  window, the proposal is accepted. If there is disagreement, the maintainers
  seek consensus; a simple majority decides when consensus cannot be reached.

## Adding maintainers

Contributors who have a sustained track record of high-quality contributions and
good judgment may be invited to become maintainers by consensus of the existing
maintainers.

## Security and releases

- Security reports follow `SECURITY.md` (coordinated disclosure).
- Releases follow Semantic Versioning; the release process and supply-chain
  gates are described in `CONTRIBUTING.md` and enforced in CI.

## Code of Conduct

All participation is governed by `CODE_OF_CONDUCT.md`.
