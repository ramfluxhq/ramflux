#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
#
# Host driver of the Android core acceptance (emulator or device attached to adb):
#
#   1. install the harness and clear its data;
#   2. phase `first`: create an account, send a direct message through the local gateway;
#      the harness process then kills itself with its stores open;
#   3. check that the process is gone and that its journal reached the send;
#   4. phase `resume`: a new process finds the account and the message, repeats the send
#      under its operation id without a duplicate, sends again, and proves that suspension
#      releases the data root;
#   5. optionally, phase `vault`: a production build on a device without a hardware-backed
#      Keystore refuses to create an account.
#
# The driver does not start the node. Start a local gateway and a peer identity first and
# pass what the device needs:
#
#   RAMFLUX_NODE_URL                 node URL as the device sees it (emulator: host alias)
#   RAMFLUX_ACCOUNT_CREATE_BODY      JSON body of account.create
#   RAMFLUX_ACCOUNT_UNLOCK_BODY      JSON body of account.unlock (optional)
#   RAMFLUX_PEER_CARD_IMPORT_BODY    JSON body of contact.card.import with the peer's card
#   RAMFLUX_CONVERSATION_ID          conversation of the direct message
#   RAMFLUX_TARGET_DELIVERY_ID       delivery id of the peer
#   RAMFLUX_RECIPIENT_DEVICE_ID      (optional)
#   RAMFLUX_RECIPIENT_COMMITMENT     (optional)
#   RAMFLUX_EXPECT_VAULT_REFUSAL=1   run only the vault phase (production build)
#   RAMFLUX_GRADLE_ARGS              extra Gradle arguments, e.g. the emulator fixture build
#                                    of the native library documented in gradle.properties
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project="$(cd "$script_dir/.." && pwd)"
package="org.ramflux.harness"
runner="$package.test/androidx.test.runner.AndroidJUnitRunner"
journal="no_backup/m4-harness/journal.json"

: "${RAMFLUX_NODE_URL:?set RAMFLUX_NODE_URL to the local gateway as the device sees it}"

fail() { echo "m4-harness: FAIL: $*" >&2; exit 1; }

# %q quoting keeps a JSON value one argument through `adb shell`.
arg() { [ -n "${2:-}" ] && printf ' -e %s %q' "$1" "$2" || true; }
instrument_args="$(arg nodeUrl "$RAMFLUX_NODE_URL")\
$(arg accountCreateBody "${RAMFLUX_ACCOUNT_CREATE_BODY:-}")\
$(arg accountUnlockBody "${RAMFLUX_ACCOUNT_UNLOCK_BODY:-}")\
$(arg peerCardImportBody "${RAMFLUX_PEER_CARD_IMPORT_BODY:-}")\
$(arg conversationId "${RAMFLUX_CONVERSATION_ID:-}")\
$(arg targetDeliveryId "${RAMFLUX_TARGET_DELIVERY_ID:-}")\
$(arg recipientDeviceId "${RAMFLUX_RECIPIENT_DEVICE_ID:-}")\
$(arg recipientPrincipalCommitment "${RAMFLUX_RECIPIENT_COMMITMENT:-}")"

instrument() { # <phase> [extra args]
  # shellcheck disable=SC2086
  adb shell "am instrument -w -e phase $1 ${2:-} $instrument_args $runner" 2>&1
}

(
  cd "$project"
  # shellcheck disable=SC2086
  ./gradlew ${RAMFLUX_GRADLE_ARGS:-} :harness:installRelease :harness:installReleaseAndroidTest
)
adb shell pm clear "$package" >/dev/null

if [ "${RAMFLUX_EXPECT_VAULT_REFUSAL:-0}" = "1" ]; then
  out="$(instrument vault '-e expectVaultRefusal true')"
  echo "$out"
  grep -q '^OK (' <<<"$out" || fail "vault phase did not pass"
  grep -q 'FAILURES!!!' <<<"$out" && fail "vault phase reported failures"
  echo "m4-harness: PASS (production refuses account creation without a hardware-backed key)"
  exit 0
fi

echo "m4-harness: phase first"
out="$(instrument first || true)"
echo "$out"
grep -q 'FAILURES!!!' <<<"$out" && fail "first phase failed before the kill"
grep -qi 'Process crashed' <<<"$out" || fail "the harness process was expected to be killed"
[ -z "$(adb shell pidof "$package" | tr -d '\r')" ] || fail "the harness process is still alive"
first="$(adb shell run-as "$package" cat "$journal" 2>/dev/null || true)"
grep -q '"ready_to_die":"true"' <<<"$first" || fail "the first run did not reach its send: $first"

echo "m4-harness: phase resume"
out="$(instrument resume)"
echo "$out"
grep -q 'FAILURES!!!' <<<"$out" && fail "resume phase reported failures"
grep -q '^OK (' <<<"$out" || fail "resume phase did not pass"
final="$(adb shell run-as "$package" cat "$journal")"
grep -q '"resumed":"true"' <<<"$final" || fail "the resumed run did not finish: $final"
grep -q '"second_send"' <<<"$final" || fail "no second send after the kill"
echo "m4-harness: PASS"
