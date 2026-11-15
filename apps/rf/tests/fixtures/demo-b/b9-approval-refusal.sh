#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
#
# Demo B B9 approval leg (DEMO-B-message-structure-acceptance, owner ruling 2026-11-13).
# Runs the approval command from the checklist against an unlocked account. The required outcome is
# a typed Authority refusal: exit 1, stderr names generated_authority, no grant is created, and the
# daemon stays usable for account status. This driver never creates grant authority.
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
trap 'rm -rf "$WORK"' EXIT
EVENT="demo-b-b9-authority-$(date -u +%s)-$$"

# expect_refusal LABEL ARGS...: the call must exit 1 and name generated_authority on stderr.
expect_refusal() {
  label=$1; shift
  rc=0
  "$RF" --socket "$SOCK" "$@" >"$WORK/$label.out" 2>"$WORK/$label.err" || rc=$?
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
"$RF" --socket "$SOCK" account status --account "$ACCOUNT" >"$WORK/status.json"
echo "B9 PASS: approval refused with typed Authority reason; daemon usable; no grant created"
