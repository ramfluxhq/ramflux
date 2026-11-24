#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# One provisioning marker per volume. Missing DBs are never recreated on restart.
set -eu
umask 077
root=/var/lib/ramflux/username
prepare() {
  name=$1 uid=$2 gid=$3 mode=$4
  directory=$root/$name
  if [ ! -e "$directory/.provisioned" ]; then
    [ -z "$(ls -A "$directory")" ] || { echo 'refusing unowned username volume' >&2; exit 1; }
    chown "$uid:$gid" "$directory"
    chmod "$mode" "$directory"
    touch "$directory/.provisioned"
    case "$name" in center|witness|home) touch "$directory/.initialize" ;; esac
    chown "$uid:$gid" "$directory"/.*[a-z]
  fi
  [ "$(stat -c '%u:%g:%a' "$directory")" = "$uid:$gid:$mode" ] || {
    echo 'username volume ownership/mode mismatch' >&2; exit 1;
  }
}
prepare center 10001 10003 700
prepare witness 10002 10003 700
prepare socket 10002 10003 750
prepare home 0 0 700
prepare center-privacy 10001 10003 700
prepare witness-privacy 10002 10003 700
