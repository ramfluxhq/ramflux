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
BUILD_TARGET_FLAG=""
BUILD_WITH_ZIG=0
BUILD_PROFILE_LABEL="debug"
if [ "${RAMFLUX_PERF_RELEASE:-0}" = "1" ]; then
  BUILD_PROFILE_FLAG="--release"
  BUILD_TARGET_DIR="release"
  BUILD_PROFILE_LABEL="release"
fi
HOST_TRIPLE=$(rustc -vV | sed -n 's/^host: //p')
case "$HOST_TRIPLE" in
  *-unknown-linux-*) ;;
  *)
    if ! command -v cargo-zigbuild >/dev/null 2>&1; then
      echo "ERROR: host target $HOST_TRIPLE cannot stage Linux containers; install cargo-zigbuild" >&2
      exit 2
    fi
    if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then
      LINUX_TARGET="aarch64-unknown-linux-gnu"
    else
      LINUX_TARGET="x86_64-unknown-linux-gnu"
    fi
    BUILD_WITH_ZIG=1
    BUILD_TARGET_FLAG="--target $LINUX_TARGET"
    BUILD_TARGET_DIR="$LINUX_TARGET/$BUILD_TARGET_DIR"
    printf '>> host pre-build: cross-compiling Linux binaries with cargo-zigbuild target=%s\n' "$LINUX_TARGET"
    ;;
esac
build_rust() {
  if [ "$BUILD_WITH_ZIG" -eq 1 ]; then
    cargo $TC zigbuild "$@"
  else
    cargo $TC build "$@"
  fi
}
printf '>> host pre-build: compiling 7 node binaries (%s; incremental host cargo cache)\n' "$BUILD_PROFILE_LABEL"

DEFAULT_BIN_ARGS=""
if [ "${RAMFLUX_GATEWAY_COMPIO:-0}" = "1" ]; then
  printf '>> host pre-build: compiling ramflux-gateway with compio-gateway feature\n'
  ( cd "$WORKSPACE" && build_rust --locked $BUILD_PROFILE_FLAG $BUILD_TARGET_FLAG \
      --features itest-http,compio-gateway --bin ramflux-gateway )
else
  DEFAULT_BIN_ARGS="$DEFAULT_BIN_ARGS --bin ramflux-gateway"
fi
if [ "${RAMFLUX_ROUTER_COMPIO:-0}" = "1" ]; then
  printf '>> host pre-build: compiling ramflux-router with compio-mesh feature\n'
  ( cd "$WORKSPACE" && build_rust --locked $BUILD_PROFILE_FLAG $BUILD_TARGET_FLAG \
      --features itest-http,compio-mesh --bin ramflux-router )
else
  DEFAULT_BIN_ARGS="$DEFAULT_BIN_ARGS --bin ramflux-router"
fi
if [ "${RAMFLUX_FEDERATION_COMPIO:-0}" = "1" ]; then
  printf '>> host pre-build: compiling ramflux-federation with compio-mesh feature\n'
  ( cd "$WORKSPACE" && build_rust --locked $BUILD_PROFILE_FLAG $BUILD_TARGET_FLAG \
      --features itest-http,compio-mesh --bin ramflux-federation )
else
  DEFAULT_BIN_ARGS="$DEFAULT_BIN_ARGS --bin ramflux-federation"
fi
if [ "${RAMFLUX_NOTIFY_COMPIO:-0}" = "1" ]; then
  printf '>> host pre-build: compiling ramflux-notify with compio-notify feature\n'
  ( cd "$WORKSPACE" && build_rust --locked $BUILD_PROFILE_FLAG $BUILD_TARGET_FLAG \
      --features itest-http,compio-notify --bin ramflux-notify )
else
  DEFAULT_BIN_ARGS="$DEFAULT_BIN_ARGS --bin ramflux-notify"
fi
# relay is built on its own so the itest-only surfaces can be enabled explicitly
# (itest-media-udp / itest-object-v2 / itest-quic-fault are all default-off and must
# not be pulled via itest-http). The T24-A3 post-commit QUIC fault seam
# (itest-quic-fault) stays inert unless a test sets RAMFLUX_RELAY_ITEST_DROP_AFTER_COMMIT,
# so enabling it here does not affect any other realnet test.
RELAY_FEATURES="itest-http,itest-media-udp,itest-object-v2,itest-quic-fault"
RELAY_LOCKED="--locked"
# CTRL-089 RELAY-MEM-02-A1 DIAGNOSTIC/profiler-only passthrough (default-off). When
# RAMFLUX_RELAY_ALLOC_PROF=1, additionally compile the relay with the default-off itest-alloc-prof
# feature (dhat global allocator + process-lifetime heap profiler with a SIGTERM graceful dump). This
# adds the dhat/libc deps which are absent from Cargo.lock, so --locked is dropped for the profile
# build ONLY. Never set for a normal acceptance run → the relay is built exactly as before and the
# production default allocator is untouched.
if [ "${RAMFLUX_RELAY_ALLOC_PROF:-0}" = "1" ]; then
  RELAY_FEATURES="$RELAY_FEATURES,itest-alloc-prof"
  RELAY_LOCKED=""
  printf '>> host pre-build: RAMFLUX_RELAY_ALLOC_PROF=1 → relay built with itest-alloc-prof (dhat heap profiler; DIAGNOSTIC)\n'
fi
printf '>> host pre-build: compiling ramflux-relay with features %s\n' "$RELAY_FEATURES"
( cd "$WORKSPACE" && build_rust $RELAY_LOCKED $BUILD_PROFILE_FLAG $BUILD_TARGET_FLAG \
    --features "$RELAY_FEATURES" --bin ramflux-relay )
DEFAULT_BIN_ARGS="$DEFAULT_BIN_ARGS --bin ramflux-signaling --bin ramflux-retention"
if [ -n "$DEFAULT_BIN_ARGS" ]; then
  ( cd "$WORKSPACE" && build_rust --locked $BUILD_PROFILE_FLAG $BUILD_TARGET_FLAG --features itest-http \
      $DEFAULT_BIN_ARGS )
fi
mkdir -p "$DEPLOY_DIR/itest-bin"
for b in gateway router notify federation relay signaling retention; do
  cp -f "$WORKSPACE/target/$BUILD_TARGET_DIR/ramflux-$b" "$DEPLOY_DIR/itest-bin/ramflux-$b"
  # CTRL-089 DIAGNOSTIC: keep the relay UNSTRIPPED under the dhat profiler so dhat can resolve
  # backtraces to function/type names at dump time (stripping would leave raw-address stacks).
  if [ "$b" = "relay" ] && [ "${RAMFLUX_RELAY_ALLOC_PROF:-0}" = "1" ]; then
    printf '>> host pre-build: keeping ramflux-relay UNSTRIPPED (dhat symbolization)\n'
    continue
  fi
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
run_with_timeout() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "$REALNET_TIMEOUT" "$@"
    return $?
  fi
  # macOS does not ship GNU coreutils timeout. Keep the same bounded behavior without
  # adding a host package prerequisite; the child receives TERM before the hard kill.
  "$@" &
  child_pid=$!
  (
    sleep "$REALNET_TIMEOUT"
    kill -TERM "$child_pid" 2>/dev/null || exit 0
    sleep 5
    kill -KILL "$child_pid" 2>/dev/null || true
  ) &
  timer_pid=$!
  if wait "$child_pid"; then
    child_rc=0
  else
    child_rc=$?
  fi
  kill "$timer_pid" 2>/dev/null || true
  wait "$timer_pid" 2>/dev/null || true
  return "$child_rc"
}
if RAMFLUX_ITEST_REALNET=1 run_with_timeout cargo $TC test --features realnet "$FILTER" -- --nocapture --test-threads=1; then
  printf '>> realnet itest PASSED (filter=%s)\n' "$FILTER"
else
  rc=$?
  if [ "$rc" -eq 124 ]; then
    printf '>> realnet itest TIMED OUT after %ss (filter=%s) -- likely HUNG, NOT slow. Check stale ramflux-* containers / node reachability before re-running.\n' "$REALNET_TIMEOUT" "$FILTER" >&2
  fi
  exit "$rc"
fi
