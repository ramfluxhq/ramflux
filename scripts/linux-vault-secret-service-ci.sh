#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Real local Secret Service fixture, isolated from the host login collection.
set -euo pipefail
[ "$(id -u)" -eq 0 ]
fixture="$(mktemp -d /tmp/rf-ss.XXXXXXXX)"
user="rfss${fixture##*.}"; user="${user,,}"
created=0
cleanup() {
  if [ "$created" -eq 1 ]; then
    pkill -u "$user" >/dev/null 2>&1 || true
    userdel "$user" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$fixture"
}
trap cleanup EXIT
useradd --no-create-home --home-dir "$fixture/home" --shell /bin/sh "$user"
created=1
group="$(id -gn "$user")"
for dir in home config data state runtime tmp; do install -d -m 0700 "$fixture/$dir"; done
"$1" --list | python3 -c 'import sys; names=sys.stdin.read(); assert "custody::vault::linux::secret_service::tests::linux_vault_installation_init_is_serial_and_crash_safe: test" in names; assert "custody::vault::linux::secret_service::tests::linux_vault_owned_buffers_clear_on_all_exits: test" in names'
"$2" --list | python3 -c 'import sys; assert "linux_vault_secret_service_has_no_headless_fallback: test" in sys.stdin.read()'
cp "$1" "$fixture/sdk-test"
cp "$2" "$fixture/platform-test"
cp "$3" "$fixture/rf"
cat > "$fixture/run" <<'RUN'
#!/bin/bash
set -euo pipefail
# Synthetic fixture password only. No product key on stdin/argv/stdout.
printf '%s' 'rf-disposable-fixture-only' | gnome-keyring-daemon --unlock --components=secrets > /dev/null
cd "$RF_LINUX_VAULT_FIXTURE_ROOT"
if [ "${RF_SS_CLEANUP_ONLY:-0}" = 1 ]; then
  exec ./sdk-test --ignored --exact custody::vault::linux::secret_service::tests::linux_vault_owned_buffers_clear_on_all_exits
fi
./sdk-test --ignored 'custody::vault::linux::secret_service::tests::linux_vault_' --test-threads=1
./platform-test --ignored --exact linux_vault_secret_service_has_no_headless_fallback
./sdk-test --ignored --exact custody::vault::linux::secret_service::tests::locked_collection_refuses_without_prompt
RUN
chmod 0500 "$fixture/run" "$fixture/sdk-test" "$fixture/platform-test" "$fixture/rf"
chmod 0700 "$fixture"
chown -R "$user:$group" "$fixture"
runuser -u "$user" -- env -i PATH=/usr/bin:/bin HOME="$fixture/home" \
  XDG_CONFIG_HOME="$fixture/config" XDG_DATA_HOME="$fixture/data" \
  XDG_STATE_HOME="$fixture/state" XDG_RUNTIME_DIR="$fixture/runtime" TMPDIR="$fixture/tmp" \
  RF_LINUX_VAULT_FIXTURE_ROOT="$fixture" RF_LINUX_VAULT_FIXTURE_RF="$fixture/rf" RF_SS_CLEANUP_ONLY="${4:-0}" \
  dbus-run-session -- "$fixture/run"
