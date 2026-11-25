#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Username centre container entrypoint (witness and centre roles only). Role-only copy of the
# witness and centre arms of deploy/scripts/demo-username-start.sh, plus `prepare`, which
# provisions the three volumes once (copy of demo-username-init.sh for these roles).
# Restart never authorizes store reconstruction: a marker is consumed on first start.
set -eu
umask 077
root=/var/lib/ramflux/username
case "${1:-}" in
  prepare)
    prepare() {
      name=$1 uid=$2 gid=$3 mode=$4
      directory=$root/$name
      if [ ! -e "$directory/.provisioned" ]; then
        [ -z "$(ls -A "$directory")" ] || { echo 'refusing unowned username volume' >&2; exit 1; }
        chown "$uid:$gid" "$directory"
        chmod "$mode" "$directory"
        touch "$directory/.provisioned"
        case "$name" in center|witness) touch "$directory/.initialize" ;; esac
        chown "$uid:$gid" "$directory"/.*[a-z]
      fi
      [ "$(stat -c '%u:%g:%a' "$directory")" = "$uid:$gid:$mode" ] || {
        echo 'username volume ownership/mode mismatch' >&2; exit 1;
      }
    }
    prepare center 10001 10003 700
    prepare witness 10002 10003 700
    prepare socket 10002 10003 750
    # Secrets are copied from the read-only source mount on every prepare run, owned by the role
    # UID and mode 0600 (the source files are owned by the host user, not by the role UIDs).
    stage() {
      role=$1 uid=$2 gid=10003
      install -d -m 700 -o "$uid" -g "$gid" "$root/$role/etc"
      for f in /run/username-secrets/"$role"/*; do
        install -m 600 -o "$uid" -g "$gid" "$f" "$root/$role/etc/$(basename "$f")"
      done
    }
    stage witness 10002
    stage center 10001
    exit 0 ;;
  witness)
    shift
    marker=$root/witness/.initialize
    if [ -f "$marker" ]; then rm "$marker"; set -- "$@" --username-initialize; fi
    set -- --config "$root/witness/etc/federation.toml" "$@"
    exec /usr/local/bin/ramflux-federation "$@" ;;
  center)
    shift
    remaining=30
    until [ -S "$root/socket/witness.sock" ]; do
      [ "$remaining" -gt 0 ] || { echo 'witness socket deadline' >&2; exit 1; }
      remaining=$((remaining - 1))
      sleep 1
    done
    marker=$root/center/.initialize
    if [ -f "$marker" ]; then rm "$marker"; set -- "$@" --username-rebuild; fi
    set -- --config "$root/center/etc/federation.toml" "$@"
    exec /usr/local/bin/ramflux-federation "$@" ;;
  *) echo 'usage: username-start.sh prepare|witness|center [args]' >&2; exit 1 ;;
esac
