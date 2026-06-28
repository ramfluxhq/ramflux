#!/usr/bin/env sh
# Bootstrap the local mesh CA + per-service certs + node config for itests.
# Resolves sibling scripts via this script's own directory so it works no
# matter what the caller's cwd is (the harness runs it with cwd = the
# realnet-clone parent, passing "ramflux/deploy/scripts/bootstrap-itest.sh").
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

"$SCRIPT_DIR/bootstrap-ca.sh"
"$SCRIPT_DIR/issue-certs.sh"
"$SCRIPT_DIR/provision-node.sh"
printf 'bootstrap-itest complete\n'
