#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Runtime dependencies for the ubuntu-24.04 vault fixture; no desktop session.
set -euo pipefail

# apt's downloader runs as _apt, independently of the runner agent. Diagnose
# that exact resolver path and recover a stale local resolver once, boundedly.
if ! sudo timeout 10s runuser -u _apt -- getent ahostsv4 archive.ubuntu.com; then
  echo 'apt DNS preflight failed; inspecting and restarting the local resolver'
  ls -l /etc/resolv.conf
  sudo timeout 10s resolvectl status || true
  sudo timeout 20s systemctl restart systemd-resolved
  sudo timeout 10s runuser -u _apt -- getent ahostsv4 archive.ubuntu.com
fi

sources_dir=$(mktemp -d)
trap 'rm -rf "$sources_dir"' EXIT
# Hosted runners route their default mirrorlist through Azure. Use the signed
# Ubuntu archives directly so an Azure mirror DNS outage cannot stall this job.
cat > "$sources_dir/ubuntu.sources" <<'SOURCES'
Types: deb
URIs: https://archive.ubuntu.com/ubuntu
Suites: noble noble-updates
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: https://security.ubuntu.com/ubuntu
Suites: noble-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SOURCES

apt_options=(
  -o "Dir::Etc::sourcelist=$sources_dir/ubuntu.sources"
  -o Dir::Etc::sourceparts=-
  -o Acquire::Retries=3
  -o Acquire::http::Timeout=15
  -o Acquire::https::Timeout=15
  -o Dpkg::Use-Pty=0
)
# Fail if any index is unavailable instead of proceeding with stale metadata.
sudo env DEBIAN_FRONTEND=noninteractive apt-get "${apt_options[@]}" -o APT::Update::Error-Mode=any update
# dbus supplies dbus-run-session; gnome-keyring supplies the headless secrets
# daemon. X11 launchers, libsecret development files and GUI recommends are unused.
sudo env DEBIAN_FRONTEND=noninteractive apt-get "${apt_options[@]}" install -y --no-install-recommends \
  systemd dbus gnome-keyring zstd acl strace
