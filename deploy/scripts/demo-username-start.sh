#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Consume initial provisioning once. Restart never authorizes store reconstruction.
set -eu
umask 077
role=$1
shift
root=/var/lib/ramflux/username
case "$role" in
  router)
    RAMFLUX_NODE_SERVICE_SIGNING_SEED_B64URL=$(cat /etc/ramflux/pairing/node-signing.key)
    export RAMFLUX_NODE_SERVICE_SIGNING_SEED_B64URL
    exec /usr/local/bin/ramflux-router "$@" ;;
  federation)
    RAMFLUX_NODE_SERVICE_SIGNING_SEED_B64URL=$(cat /etc/ramflux/node-identity/node-signing.key)
    export RAMFLUX_NODE_SERVICE_SIGNING_SEED_B64URL
    marker=$root/home/.initialize
    if [ -f "$marker" ]; then rm "$marker"; set -- "$@" --username-home-initialize; fi ;;
  witness)
    # Demo only: the registered-node list holds this demo node's own key and is rewritten hourly
    # so it never expires (a real centre produces the list; see deploy/central/README.md).
    list=$RAMFLUX_USERNAME_REGISTERED_NODES_FILE
    write_list() {
      printf '{"v":1,"generated_at":%s,"nodes":[{"node_key":"%s","state":"active"}]}\n' \
        "$(date +%s)" "${DEMO_REGISTERED_NODE_KEY:?}" > "$list.tmp"
      mv "$list.tmp" "$list"
    }
    write_list
    ( while sleep 3600; do write_list; done ) &
    marker=$root/witness/.initialize
    if [ -f "$marker" ]; then rm "$marker"; set -- "$@" --username-initialize; fi ;;
  center)
    remaining=30
    until [ -S "$root/socket/witness.sock" ]; do
      [ "$remaining" -gt 0 ] || { echo 'witness socket deadline' >&2; exit 1; }
      remaining=$((remaining - 1))
      sleep 1
    done
    marker=$root/center/.initialize
    if [ -f "$marker" ]; then rm "$marker"; set -- "$@" --username-rebuild; fi ;;
  *) echo 'unknown username service role' >&2; exit 1 ;;
esac
exec /usr/local/bin/ramflux-federation "$@"
