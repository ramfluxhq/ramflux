#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
#
# Demo B B9 approval leg (DEMO-B-message-structure-acceptance, owner ruling 2026-11-13).
# Runs the approval command from the checklist against an unlocked account. The required outcome is
# a typed Authority refusal: exit 1, stderr names generated_authority, no grant is created, and the
# daemon stays usable for account status. Every rf child has a 15s deadline and its own process
# group. The scenario itself stops after 90s. This driver never creates grant authority.
#
# Usage: b9-approval-refusal.sh --rf BIN --socket SOCK --account ID --device DEVICE_ID
set -euo pipefail

RF=rf
SOCK=""
ACCOUNT=""
DEVICE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --rf) RF="${2:?--rf needs a value}"; shift 2 ;;
    --socket) SOCK="${2:?--socket needs a value}"; shift 2 ;;
    --account) ACCOUNT="${2:?--account needs a value}"; shift 2 ;;
    --device) DEVICE="${2:?--device needs a value}"; shift 2 ;;
    --help|-h) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "b9-approval-refusal: unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$SOCK" ] && [ -n "$ACCOUNT" ] && [ -n "$DEVICE" ] || {
  echo "b9-approval-refusal: --socket, --account and --device are required" >&2
  exit 2
}

WORK=$(mktemp -d "${TMPDIR:-/private/tmp}/b9-approval.XXXXXX")
CHILD_DEADLINE=15
SCENARIO_DEADLINE=90
START=$(date +%s)
(
  sleep "$SCENARIO_DEADLINE"
  echo "B9 FAILED: scenario deadline ${SCENARIO_DEADLINE}s exceeded" >&2
  kill -TERM -$$ 2>/dev/null || true
) &
WATCHDOG=$!
trap 'status=$?; kill "$WATCHDOG" 2>/dev/null || true; rm -rf "$WORK"; exit "$status"' EXIT
EVENT="demo-b-b9-authority-$(date -u +%s)-$$"

# Runs rf in its own process group. GNU timeout on Linux; perl alarm elsewhere.
# Exit 124 means the deadline fired and the group was killed.
run_bounded() {
  local now=$(( $(date +%s) - START ))
  if [ "$now" -ge "$SCENARIO_DEADLINE" ]; then
    echo "B9 FAILED: scenario deadline ${SCENARIO_DEADLINE}s exceeded before: $*" >&2
    exit 1
  fi
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 2 "$CHILD_DEADLINE" "$@"
    return $?
  fi
  perl - "$CHILD_DEADLINE" "$@" <<'PERL'
use strict;
use warnings;
my $seconds = shift @ARGV;
my $pid = fork();
die "fork failed: $!" unless defined $pid;
if ($pid == 0) {
    setpgrp(0, 0) or die "setpgrp failed: $!";
    exec @ARGV or die "exec failed: $!";
}
my $stop = sub {
    kill 'TERM', -$pid;
    sleep 1;
    kill 'KILL', -$pid;
};
$SIG{ALRM} = sub { $stop->(); exit 124; };
$SIG{TERM} = sub { $stop->(); exit 143; };
$SIG{INT} = sub { $stop->(); exit 130; };
alarm $seconds;
my $waited = waitpid($pid, 0);
alarm 0;
exit 124 if $waited < 0;
exit 128 + ($? & 127) if $? & 127;
exit($? >> 8);
PERL
}

# expect_refusal LABEL ARGS...: the call must exit 1 and name generated_authority on stderr.
expect_refusal() {
  label=$1; shift
  rc=0
  run_bounded "$RF" --socket "$SOCK" "$@" >"$WORK/$label.out" 2>"$WORK/$label.err" || rc=$?
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] || [ "$rc" -eq 143 ]; then
    echo "B9 FAILED: $label exceeded the ${CHILD_DEADLINE}s deadline" >&2
    exit 1
  fi
  if [ "$rc" -ne 1 ]; then
    echo "B9 FAILED: $label exited $rc, expected 1 (typed refusal)" >&2
    exit 1
  fi
  if ! grep -q 'generated_authority' "$WORK/$label.err"; then
    echo "B9 FAILED: $label refusal lacks the typed generated_authority reason" >&2
    exit 1
  fi
  echo "B9 $label: exit 1, typed reason generated_authority"
}

expect_refusal append a2i append --account "$ACCOUNT" --event "$EVENT" --type a2i.control \
  --source-device "$DEVICE" --target-device "$DEVICE" \
  --control-domain mcp.approval --action grant --subject demo-b-no-grant
expect_refusal list a2i list --account "$ACCOUNT"
expect_refusal ack a2i ack --account "$ACCOUNT" --event "$EVENT"

# The daemon must survive the refusals and still answer an account status call.
rc=0
run_bounded "$RF" --socket "$SOCK" account status --account "$ACCOUNT" >"$WORK/status.json" || rc=$?
if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] || [ "$rc" -eq 143 ]; then
  echo "B9 FAILED: account status exceeded the ${CHILD_DEADLINE}s deadline" >&2
  exit 1
fi
if [ "$rc" -ne 0 ]; then
  echo "B9 FAILED: account status exited $rc" >&2
  exit 1
fi
echo "B9 PASS: approval refused with typed Authority reason; daemon usable; no grant created"
