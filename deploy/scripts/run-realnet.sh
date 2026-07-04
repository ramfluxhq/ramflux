#!/usr/bin/env sh
# Run the Ramflux realnet itest acceptance suite against the real 7-service
# compose stack.
#
# Usage:
#   ramflux/deploy/scripts/run-realnet.sh [TEST_FILTER]
#     TEST_FILTER  cargo test name filter; default "realnet" (all realnet tests).
#                  e.g. mvp01_realnet | mvp_s01_gateway_session
#
# Clone layout (the runner checks out two sibling repos under one parent dir):
#   <parent>/ramflux/         the open monorepo (this deploy dir is ramflux/deploy)
#   <parent>/ramflux-itest/   the realnet integration-test harness
# The itest harness resolves the deploy dir as code_root/ramflux/deploy where
# code_root = <parent> (CARGO_MANIFEST_DIR of ramflux-itest, then parent).
#
# Requirements (the realnet tests self-orchestrate `docker compose up --build`):
#   - docker OR podman (with a `docker compose` provider) on PATH
#   - the two sibling checkouts above
#   - Rust toolchain >= 1.96.0 (uses +1.96.0 if rustup has it)
#
# Realnet execution is Linux-only in practice: the compose-backed services and
# optional runtime probes are Linux-only.
set -eu

# Non-login ssh shells don't source the cargo env, so cargo/rustup can be off
# PATH. Prepend the standard rustup bin dir so the script self-heals.
export PATH="$HOME/.cargo/bin:$PATH"

FILTER="${1:-realnet}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEPLOY_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)       # ramflux/deploy
WORKSPACE_DIR=$(CDPATH= cd -- "$DEPLOY_DIR/.." && pwd)    # ramflux (Cargo workspace)
PARENT_DIR=$(CDPATH= cd -- "$WORKSPACE_DIR/.." && pwd)    # realnet-clone parent
ITEST_DIR="$PARENT_DIR/ramflux-itest"

if [ ! -d "$ITEST_DIR" ]; then
  echo "ERROR: ramflux-itest not found at $ITEST_DIR (need a sibling checkout of ramflux + ramflux-itest)" >&2
  exit 2
fi

if command -v docker >/dev/null 2>&1; then
  RT=docker
elif command -v podman >/dev/null 2>&1; then
  RT=podman
else
  echo "ERROR: need docker or podman on PATH (realnet tests run a compose up)" >&2
  exit 2
fi
printf '>> container runtime: %s (%s)\n' "$RT" "$($RT --version 2>/dev/null | head -1)"

TC=""
if command -v rustup >/dev/null 2>&1 && rustup toolchain list 2>/dev/null | grep -q '^1\.96\.0'; then
  TC="+1.96.0"
fi

# --- Host pre-build (Option B): compile the 7 node binaries OUTSIDE Docker on
# the host's persistent incremental cargo cache, then stage them for the thin
# runtime images (Dockerfile.itest just COPYs them in). A persistent host
# target/ cache survives across runs and only changed crates recompile -- vs an
# in-Docker `COPY . . && cargo build --bin X` which recompiles the full dep
# graph from scratch inside 7 separate image builds every run. NB: the binaries
# link the HOST glibc, so Dockerfile.itest runs them on debian:trixie-slim
# (matching the reference host glibc). Default acceptance uses debug for fast
# edit/test cycles; perf runs can opt into release with RAMFLUX_PERF_RELEASE=1.
WORKSPACE="$WORKSPACE_DIR"
BUILD_PROFILE_FLAG=""
BUILD_TARGET_DIR="debug"
BUILD_PROFILE_LABEL="debug"
if [ "${RAMFLUX_PERF_RELEASE:-0}" = "1" ]; then
  BUILD_PROFILE_FLAG="--release"
  BUILD_TARGET_DIR="release"
  BUILD_PROFILE_LABEL="release"
fi
printf '>> host pre-build: compiling 7 node binaries (%s; incremental host cargo cache)\n' "$BUILD_PROFILE_LABEL"

DEFAULT_BIN_ARGS=""
if [ "${RAMFLUX_GATEWAY_COMPIO:-0}" = "1" ]; then
  printf '>> host pre-build: compiling ramflux-gateway with compio-gateway feature\n'
  ( cd "$WORKSPACE" && cargo $TC build --locked $BUILD_PROFILE_FLAG \
      --features itest-http,compio-gateway --bin ramflux-gateway )
else
  DEFAULT_BIN_ARGS="$DEFAULT_BIN_ARGS --bin ramflux-gateway"
fi
if [ "${RAMFLUX_ROUTER_COMPIO:-0}" = "1" ]; then
  printf '>> host pre-build: compiling ramflux-router with compio-mesh feature\n'
  ( cd "$WORKSPACE" && cargo $TC build --locked $BUILD_PROFILE_FLAG \
      --features itest-http,compio-mesh --bin ramflux-router )
else
  DEFAULT_BIN_ARGS="$DEFAULT_BIN_ARGS --bin ramflux-router"
fi
if [ "${RAMFLUX_FEDERATION_COMPIO:-0}" = "1" ]; then
  printf '>> host pre-build: compiling ramflux-federation with compio-mesh feature\n'
  ( cd "$WORKSPACE" && cargo $TC build --locked $BUILD_PROFILE_FLAG \
      --features itest-http,compio-mesh --bin ramflux-federation )
else
  DEFAULT_BIN_ARGS="$DEFAULT_BIN_ARGS --bin ramflux-federation"
fi
if [ "${RAMFLUX_NOTIFY_COMPIO:-0}" = "1" ]; then
  printf '>> host pre-build: compiling ramflux-notify with compio-notify feature\n'
  ( cd "$WORKSPACE" && cargo $TC build --locked $BUILD_PROFILE_FLAG \
      --features itest-http,compio-notify --bin ramflux-notify )
else
  DEFAULT_BIN_ARGS="$DEFAULT_BIN_ARGS --bin ramflux-notify"
fi
DEFAULT_BIN_ARGS="$DEFAULT_BIN_ARGS --bin ramflux-relay --bin ramflux-signaling --bin ramflux-retention"
if [ -n "$DEFAULT_BIN_ARGS" ]; then
  ( cd "$WORKSPACE" && cargo $TC build --locked $BUILD_PROFILE_FLAG --features itest-http \
      $DEFAULT_BIN_ARGS )
fi
mkdir -p "$DEPLOY_DIR/itest-bin"
for b in gateway router notify federation relay signaling retention; do
  cp -f "$WORKSPACE/target/$BUILD_TARGET_DIR/ramflux-$b" "$DEPLOY_DIR/itest-bin/ramflux-$b"
  # strip debug symbols so the build context stays small.
  strip "$DEPLOY_DIR/itest-bin/ramflux-$b" 2>/dev/null || true
done

# Pre-clean: a previously KILLED run can leave stale ramflux-* containers
# (runc residue blocks normal teardown), and the next run silently REUSES them
# instead of recreating from fresh images -> validation runs against stale code
# and the test hangs. Force-remove any leftovers so each run is a clean slate.
printf '>> pre-clean: removing any stale ramflux-* containers/volumes\n'
$RT compose -f "$DEPLOY_DIR/docker-compose.itest.yml" down --volumes --remove-orphans >/dev/null 2>&1 || true
$RT compose -p ramflux-s10-private-node -f "$DEPLOY_DIR/docker-compose.yml" down --volumes --remove-orphans >/dev/null 2>&1 || true
# Federation (S8/S9) and production (S10/S22) tests use DIFFERENT compose project
# names, so a name=ramflux- filter (not just ramflux-deploy) is needed to avoid
# leaving their containers behind for the next run to wrongly reuse.
for c in $($RT ps -aq --filter name=ramflux- 2>/dev/null); do
  $RT rm -f --depend --time 0 "$c" >/dev/null 2>&1 || true
done
for v in $($RT volume ls -q 2>/dev/null | grep -i 'ramflux-' 2>/dev/null); do
  $RT volume rm -f "$v" >/dev/null 2>&1 || true
done
# Reclaim dangling image layers orphaned by prior `compose up --build` runs;
# rootless podman accumulates these and can fill the disk. Dangling-only prune
# keeps the active tagged images + builder cache intact.
$RT image prune -f >/dev/null 2>&1 || true

# Self-bounding timeout: a normal filtered realnet run is ~20s single-mesh,
# ~50s two-stack. If it runs much longer it is almost certainly HUNG (stale
# container reuse, or an unreachable node). Cap it so a hang dies fast
# (exit 124). Override via RAMFLUX_REALNET_TIMEOUT for a genuine full-suite run.
REALNET_TIMEOUT="${RAMFLUX_REALNET_TIMEOUT:-600}"
printf '>> realnet itest: filter=%s  (timeout=%ss; builds images, runs, tears down)\n' "$FILTER" "$REALNET_TIMEOUT"
cd "$ITEST_DIR"
if RAMFLUX_ITEST_REALNET=1 timeout "$REALNET_TIMEOUT" cargo $TC test --features realnet "$FILTER" -- --nocapture --test-threads=1; then
  printf '>> realnet itest PASSED (filter=%s)\n' "$FILTER"
else
  rc=$?
  if [ "$rc" -eq 124 ]; then
    printf '>> realnet itest TIMED OUT after %ss (filter=%s) -- likely HUNG, NOT slow. Check stale ramflux-* containers / node reachability before re-running.\n' "$REALNET_TIMEOUT" "$FILTER" >&2
  fi
  exit "$rc"
fi
