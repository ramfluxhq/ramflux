#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
#
# M3 acceptance on the iOS simulator. Not a pull-request gate: a manual or nightly run.
#
#   1. create-send  create an account and send a direct message through a local gateway
#   2. kill         SIGKILL the app process while it holds the store
#   3. restart      start again, prove the message survived, send over the resumed session
#   4. suspend      the core suspends; the process is stopped (SIGSTOP) and the data-root
#                   lock is taken from OUTSIDE the process, which only works when no lock is
#                   held at suspension; then continue, resume and send again
#   5. background   (optional, --with-background) the real didEnterBackground notification
#
# Usage:
#   run-m3-acceptance.sh --scenario <scenario.json> [--device <udid|booted>] [--with-background]
#
# The scenario names the local gateway (reachable from the simulator as a host address) and
# the peer account. Preparing the gateway and the peer is the caller's job (for example with
# the `rf` CLI on this Mac against the same gateway); see scenario.example.json.
set -euo pipefail

bundle_id="org.ramflux.harness"
device="booted"
scenario=""
with_background=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario) scenario="$2"; shift 2 ;;
    --device) device="$2"; shift 2 ;;
    --with-background) with_background=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$scenario" && -f "$scenario" ]] || { echo "--scenario <file> is required" >&2; exit 2; }

harness_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="$harness_dir/../build/harness/RamfluxHarness.app"
[[ -d "$app" ]] || { echo "build the harness first: build-harness.sh" >&2; exit 1; }

sim() { xcrun simctl "$@"; }

fail() { echo "M3-ACCEPTANCE FAIL: $*" >&2; exit 1; }

# The simulator runs app processes as processes of this Mac, so they can be signalled and
# their files can be locked from here.
harness_pid() { pgrep -f "RamfluxHarness.app/RamfluxHarness" | head -n 1 || true; }

wait_for_file() {
  local file="$1" seconds="$2" waited=0
  until [[ -e "$file" ]]; do
    sleep 0.2
    waited=$((waited + 1))
    [[ $waited -lt $((seconds * 5)) ]] || return 1
  done
}

wait_for_exit() {
  local seconds="$1" waited=0
  while [[ -n "$(harness_pid)" ]]; do
    sleep 0.2
    waited=$((waited + 1))
    [[ $waited -lt $((seconds * 5)) ]] || return 1
  done
}

result_ok() {
  local file="$1"
  [[ -f "$file" ]] || return 1
  python3 -I - "$file" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
for failure in result.get("failures", []):
    print("  failure:", failure, file=sys.stderr)
sys.exit(0 if result.get("ok") is True else 1)
PY
}

# Take and release an exclusive, non-blocking flock on the lock file from this process.
# Exit 0: nobody holds it. Exit 3: it is held. Anything else: error.
probe_lock() {
  python3 -I - "$1" <<'PY'
import errno, fcntl, os, sys
descriptor = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError as error:
    sys.exit(3 if error.errno in (errno.EWOULDBLOCK, errno.EAGAIN) else 4)
fcntl.flock(descriptor, fcntl.LOCK_UN)
os.close(descriptor)
PY
}

launch() {
  local phase="$1"
  rm -f "$documents/ready-to-kill" "$documents/suspended" "$documents/continue" \
    "$documents/result-$phase.json"
  sim launch "$device" "$bundle_id" --phase "$phase" >/dev/null
}

echo "== install"
sim terminate "$device" "$bundle_id" >/dev/null 2>&1 || true
sim uninstall "$device" "$bundle_id" >/dev/null 2>&1 || true
sim install "$device" "$app"
container="$(sim get_app_container "$device" "$bundle_id" data)"
documents="$container/Documents"
data_root="$container/Library/Application Support/ramflux"
lock_file="$data_root/daemon.lock"
mkdir -p "$documents"
cp "$scenario" "$documents/scenario.json"

echo "== 1. create an account and send a direct message"
launch create-send
wait_for_file "$documents/ready-to-kill" 180 || fail "create-send never reached its durable point"
result_ok "$documents/result-create-send.json" || fail "create-send reported failures"
set +e; probe_lock "$lock_file"; held=$?; set -e
[[ $held -eq 3 ]] || fail "the running core does not hold the data-root lock (probe exit $held)"

echo "== 2. kill the process while it holds the store"
pid="$(harness_pid)"
[[ -n "$pid" ]] || fail "harness process not found"
kill -KILL "$pid"
wait_for_exit 10 || fail "harness did not die"
probe_lock "$lock_file" || fail "the lock outlived the killed process"

echo "== 3. restart and resume"
launch restart
wait_for_exit 180 || fail "restart phase did not finish"
result_ok "$documents/result-restart.json" || fail "restart reported failures"

echo "== 4. suspend: no lock may be held while the process is stopped"
launch suspend
wait_for_file "$documents/suspended" 180 || fail "the core never reported suspension"
pid="$(harness_pid)"
[[ -n "$pid" ]] || fail "harness process not found"
kill -STOP "$pid"
# The process cannot run now. If any descriptor of it still held the lock, this would
# report "held" and stay that way.
set +e; probe_lock "$lock_file"; state=$?; set -e
kill -CONT "$pid"
[[ $state -eq 0 ]] || fail "data-root lock is not free while the process is suspended (probe exit $state)"
wal="$(find "$data_root" -name '*-wal' -size +0c -print 2>/dev/null || true)"
[[ -z "$wal" ]] || fail "write-ahead data left at suspension: $wal"
touch "$documents/continue"
wait_for_exit 180 || fail "suspend phase did not finish"
result_ok "$documents/result-suspend.json" || fail "suspend reported failures"

if [[ $with_background -eq 1 ]]; then
  echo "== 5. real application lifecycle"
  launch background
  sleep 5
  # Bringing another app to the front sends didEnterBackground to the harness.
  sim launch "$device" com.apple.Preferences >/dev/null
  wait_for_file "$documents/suspended" 60 || fail "the core did not suspend in the background"
  probe_lock "$lock_file" || fail "data-root lock held while the app is in the background"
  # Launching a running app again brings it to the foreground without restarting it.
  sim launch "$device" "$bundle_id" --phase background >/dev/null
  sleep 5
  touch "$documents/continue"
  wait_for_exit 180 || fail "background phase did not finish"
  result_ok "$documents/result-background.json" || fail "background reported failures"
fi

echo "M3-ACCEPTANCE PASS"
