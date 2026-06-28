#!/usr/bin/env sh
# Host pre-build of the 7 production node binaries for docker-compose.yml.
#
# Open-repo layout: the Cargo workspace IS the `ramflux` repo root (one level
# above this deploy dir); the service binaries live in apps/ramflux-*. We
# compile them (release) on the host's incremental cargo cache into the
# workspace target/release/, where deploy/Dockerfile (`COPY target/release/
# ${BIN}`) picks them up when `docker compose -f docker-compose.yml up --build`
# builds the thin runtime images. This keeps node bring-up fast while still
# exercising the real production compose without RAMFLUX_ITEST_* shims.
#
# Invoked by the realnet harness production-node flows (S10/S22) and runnable
# directly for a manual production bring-up.
set -eu

export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEPLOY_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
WORKSPACE_DIR=$(CDPATH= cd -- "$DEPLOY_DIR/.." && pwd)   # ramflux repo root (Cargo workspace)

TC=""
if command -v rustup >/dev/null 2>&1 && rustup toolchain list 2>/dev/null | grep -q '^1\.96\.0'; then
  TC="+1.96.0"
fi

printf '>> production host pre-build: compiling 7 node binaries (release)\n'
( cd "$WORKSPACE_DIR" && cargo $TC build --locked --release \
    --bin ramflux-gateway --bin ramflux-router --bin ramflux-notify \
    --bin ramflux-federation --bin ramflux-relay --bin ramflux-signaling \
    --bin ramflux-retention )

printf 'build-prod-images complete: %s/target/release\n' "$WORKSPACE_DIR"
