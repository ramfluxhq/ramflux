#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Disposable fixture only. No production provider is activated here.
set -euo pipefail
[ "$(uname -s)" = Linux ]
[ "$(id -u)" -eq 0 ] || { echo 'run fixture as root on a disposable test host' >&2; exit 1; }
checkout="$(pwd)"
workspace="$checkout"
created_workspace=''
created_target_alias=''
test_binary=''
fixture_env=()
run_bounded() {
  local seconds="$1" label="$2" status command
  shift 2
  printf -v command '%q ' "$@"
  if timeout --signal=TERM --kill-after=10s "${seconds}s" "$@"; then
    return 0
  else
    status=$?
  fi
  if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
    echo "::error::Timed out after ${seconds}s waiting for ${label}: ${command% }" >&2
    local -a user_dump
    user_dump=(env PATH="/usr/bin:/bin")
    if [ -n "${fixture_user:-}" ] && [ -n "${fixture:-}" ]; then
      user_dump=(runuser -u "$fixture_user" -- env PATH="/usr/bin:/bin"
        XDG_RUNTIME_DIR="$fixture/runtime"
        DBUS_SESSION_BUS_ADDRESS="unix:path=$fixture/runtime/bus")
    fi
    echo '--- systemctl --user status ---' >&2
    timeout 10s "${user_dump[@]}" systemctl --user status --no-pager >&2 || true
    echo '--- busctl --user list ---' >&2
    timeout 10s "${user_dump[@]}" busctl --user list >&2 || true
    echo '--- recent system journal ---' >&2
    timeout 10s journalctl -n 100 --no-pager >&2 || true
    echo '--- systemd fixture unit ---' >&2
    if [ -n "${unit:-}" ]; then
      timeout 10s systemctl status "$unit.service" --no-pager >&2 || true
    fi
    echo '--- longest-running processes ---' >&2
    timeout 10s ps -eo pid,ppid,user,stat,etime,args --sort=-etime | head -n 80 >&2 || true
    echo '--- active systemd jobs ---' >&2
    timeout 10s systemctl list-jobs --no-pager >&2 || true
  fi
  return "$status"
}
if [ "${1:-}" = --test-binary ]; then
  # Scoped inner loop: use the just-built integration test, without an archive build.
  test_binary="$(realpath "$2")"
else
  archive="$(realpath "${1:-rest.tar.zst}")"
  nextest="$(command -v cargo-nextest)"
fi
for tool in systemd-creds systemd-run systemctl busctl dbus-run-session dbus-send useradd runuser timeout; do
  command -v "$tool" >/dev/null
done
run_bounded 30 'systemd manager readiness query' systemctl show --property=Version --value >/dev/null
fixture="$(mktemp -d /tmp/rf-linux-vault.XXXXXXXX)"
fixture_user="rfv${fixture##*.}"
fixture_user="${fixture_user,,}"
unit="${fixture_user}-probe"
created_user=0
cleanup() {
  # Record failures, finish every remaining step, then exit non-zero if anything failed.
  local script_status=$? cleanup_failed=0
  run_bounded 30 'systemd fixture cleanup' systemctl stop "$unit.service" || true
  if [ "$created_user" -eq 1 ]; then
    pkill -u "$fixture_user" >/dev/null 2>&1 || true
  fi
  if [ -s "$fixture/ancestor-acls" ]; then
    setfacl --restore="$fixture/ancestor-acls" || {
      echo 'cleanup: setfacl --restore failed' >&2; cleanup_failed=1;
    }
  fi
  if [ "$created_user" -eq 1 ]; then
    userdel "$fixture_user" >/dev/null 2>&1 || {
      echo 'cleanup: userdel failed' >&2; cleanup_failed=1;
    }
  fi
  rm -rf -- "$fixture" || { echo 'cleanup: fixture removal failed' >&2; cleanup_failed=1; }
  if [ -n "$created_target_alias" ]; then
    rm -f -- "$created_target_alias" || {
      echo 'cleanup: target alias removal failed' >&2; cleanup_failed=1;
    }
  fi
  if [ -n "$created_workspace" ]; then
    rm -rf -- "$created_workspace" || {
      echo 'cleanup: workspace removal failed' >&2; cleanup_failed=1;
    }
  fi
  if [ "$script_status" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
    exit 1
  fi
  exit "$script_status"
}
trap cleanup EXIT
run_bounded 30 'private fixture user creation' useradd --no-create-home --home-dir "$fixture/home" --shell /bin/sh "$fixture_user"
created_user=1
fixture_group="$(id -gn "$fixture_user")"
chmod 0700 "$fixture"
chown "$fixture_user:$fixture_group" "$fixture"
for dir in home config data state runtime tmp; do
  install -d -m 0700 -o "$fixture_user" -g "$fixture_group" "$fixture/$dir"
done
# Synthetic nonsecret input: systemd itself must actually inject the credential.
printf 'fixture-ok\n' > "$fixture/probe-input"
chmod 0600 "$fixture/probe-input"
# The directory is expanded by the child after systemd injects its credentials.
# shellcheck disable=SC2016
run_bounded 90 'systemd credential probe' systemd-run --unit="$unit" --wait --pipe --collect \
  --property="User=$fixture_user" --property=UMask=0077 \
  --property=TimeoutStartSec=30s --property=RuntimeMaxSec=30s \
  --property="LoadCredential=rf-fixture:$fixture/probe-input" \
  /bin/sh -ec 'cat "$CREDENTIALS_DIRECTORY/rf-fixture"' > "$fixture/systemd-credential-probe"
chown "$fixture_user:$fixture_group" "$fixture/systemd-credential-probe"
chmod 0600 "$fixture/systemd-credential-probe"
if [ -n "$test_binary" ]; then
  "$test_binary" --list | python3 -c 'import sys; assert "linux_vault_platform_fixture_is_private: test" in sys.stdin.read().splitlines()'
  # Shared build ancestors can be private. Copy only the freshly built binaries;
  # never relax host permissions or substitute an installed rf executable.
  cp "$test_binary" "$fixture/platform-test"
  cp "$(dirname "$(dirname "$test_binary")")/rf" "$fixture/rf"
  cmp "$test_binary" "$fixture/platform-test"
  cmp "$(dirname "$(dirname "$test_binary")")/rf" "$fixture/rf"
  chown "$fixture_user:$fixture_group" "$fixture/platform-test" "$fixture/rf"
  chmod 0500 "$fixture/platform-test" "$fixture/rf"
  fixture_env=("RF_LINUX_VAULT_FIXTURE_RF=$fixture/rf")
  RF_LINUX_VAULT_FIXTURE_ROOT="$fixture" "$fixture/platform-test" --ignored --exact linux_vault_systemd_credential_roundtrip_and_mode_refusal
  test_command=("$fixture/platform-test" --ignored --exact linux_vault_platform_fixture_is_private)
else
  command -v getfacl >/dev/null
  command -v setfacl >/dev/null
  # Nextest remaps metadata but cannot rewrite env!(CARGO_BIN_EXE_rf).
  # Recreate the compile-time workspace on the disposable hosted CI runner.
  workspace="$(tar --zstd -xOf "$archive" target/nextest/cargo-metadata.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["workspace_root"])')"
  case "$workspace" in /*) ;; *) echo 'archive workspace must be absolute' >&2; exit 1 ;; esac
  [ "$workspace" != / ]
  if [ "$workspace" != "$checkout" ]; then
    [ ! -e "$workspace" ] || { echo 'archive workspace exists; refusing to modify it' >&2; exit 1; }
    mkdir -p "$workspace"
    created_workspace="$workspace"
    tar -C "$checkout" --exclude=./target --exclude=./.git --exclude=./rest.tar.zst -cf - . |
      tar -C "$workspace" -xf -
  fi
  cd "$workspace"
  cp "$archive" "$fixture/rest.tar.zst"
  cp "$nextest" "$fixture/cargo-nextest"
  chown "$fixture_user:$fixture_group" "$fixture/rest.tar.zst" "$fixture/cargo-nextest"
  archive="$fixture/rest.tar.zst"
  nextest="$fixture/cargo-nextest"
  filter='binary(linux_vault_platform) & not test(linux_vault_systemd_credential_roundtrip_and_mode_refusal) & not test(linux_vault_secret_service_has_no_headless_fallback)'
  run_bounded 300 'rest archive test listing and extraction' "$nextest" nextest list --archive-file "$archive" --workspace-remap . \
    --extract-to . --extract-overwrite --message-format json > "$fixture/list.json"
  python3 - "$fixture/list.json" <<'PY'
import json, sys
listing = json.load(open(sys.argv[1]))
names = [name for suite in listing['rust-suites'].values()
         if suite['binary-id'].endswith('linux_vault_platform')
         for name in suite['testcases']]
assert 'linux_vault_platform_fixture_is_private' in names, names
PY
  original_target="$(tar --zstd -xOf "$archive" target/nextest/binaries-metadata.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["rust-build-meta"]["target-directory"])')"
  case "$original_target" in /*) ;; *) echo 'archive target must be absolute' >&2; exit 1 ;; esac
  [ "$original_target" != / ]
  if [ "$original_target" != "$workspace/target" ]; then
    [ ! -e "$original_target" ] && [ ! -L "$original_target" ] || {
      echo 'archive target exists; refusing to modify it' >&2; exit 1;
    }
    mkdir -p "$(dirname "$original_target")"
    ln -s "$workspace/target" "$original_target"
    created_target_alias="$original_target"
  fi
  # nextest canonicalizes the compile-time workspace as the fixture user.
  # Hosted runners may have private ancestors (notably /home/runner). Grant
  # only traversal where needed and restore the exact ACLs before user removal.
  ancestor="$(dirname "$workspace")"
  while :; do
    if run_bounded 10 'private-user workspace traversal check' runuser -u "$fixture_user" -- test -x "$ancestor"; then
      :
    else
      status=$?
      if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
        exit "$status"
      fi
      getfacl -p "$ancestor" >> "$fixture/ancestor-acls"
      setfacl -m "u:$fixture_user:x" "$ancestor"
    fi
    [ "$ancestor" != / ] || break
    ancestor="$(dirname "$ancestor")"
  done
  RF_LINUX_VAULT_FIXTURE_ROOT="$fixture" run_bounded 300 'systemd credential archive test' "$nextest" nextest run --archive-file "$archive" --workspace-remap . \
    --extract-to . --extract-overwrite --run-ignored ignored-only --no-tests=fail \
    -E 'binary(linux_vault_platform) & test(linux_vault_systemd_credential_roundtrip_and_mode_refusal)'
  # Only disposable archive output is transferred, never a shared build target.
  chown -R "$fixture_user:$fixture_group" "$workspace/target"
  test_command=("$nextest" nextest run --archive-file "$archive" --workspace-remap .
    --extract-to . --extract-overwrite --run-ignored ignored-only --no-tests=fail -E "$filter")
fi
cat > "$fixture/bus.conf" <<BUS
<busconfig>
  <type>session</type>
  <listen>unix:path=$fixture/runtime/bus</listen>
  <auth>EXTERNAL</auth>
  <policy context="default"><allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/></policy>
</busconfig>
BUS
chmod 0644 "$fixture/bus.conf"
# SDK tests never mutate global environment; only this child gets private paths.
run_bounded 480 'private-user D-Bus session and vault fixture tests' runuser -u "$fixture_user" -- env -i PATH="/usr/bin:/bin" \
  HOME="$fixture/home" XDG_CONFIG_HOME="$fixture/config" XDG_DATA_HOME="$fixture/data" \
  XDG_STATE_HOME="$fixture/state" XDG_RUNTIME_DIR="$fixture/runtime" TMPDIR="$fixture/tmp" \
  RF_LINUX_VAULT_FIXTURE_ROOT="$fixture" "${fixture_env[@]}" \
  dbus-run-session --dbus-daemon=/usr/bin/dbus-daemon --config-file="$fixture/bus.conf" -- \
  "${test_command[@]}"
