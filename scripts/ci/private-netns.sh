#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain

# CI test execution only: fetch dependencies and build before calling this.
# A fresh network namespace has loopback, but no interface or route to the host.
set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo 'private-netns: expected a command' >&2
    exit 2
fi
if [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ]; then
    exec "$@"
fi
if [ "$(uname -s)" != Linux ]; then
    echo 'private-netns: self-hosted tests require Linux user/network namespaces' >&2
    exit 2
fi
for tool in unshare ip; do
    if ! command -v "$tool" >/dev/null; then
        echo "private-netns: missing required tool: $tool" >&2
        exit 2
    fi
done

test_uid="$(id -u)"
test_gid="$(id -g)"
namespace=(unshare --user --map-user="$test_uid" --map-group="$test_gid" --net --keep-caps)
# Retaining capabilities across exec lets a nonzero mapped uid configure lo.
if "${namespace[@]}" -- bash -c 'ip link set lo up' 2>/dev/null; then
    exec "${namespace[@]}" -- bash -euo pipefail -c 'ip link set lo up; exec "$@"' bash "$@"
fi

# Older util-linux may lack --keep-caps. Configure lo as namespace root,
# then enter a nested user namespace mapped back to the original uid/gid.
namespace=(unshare --user --map-root-user --net)
if "${namespace[@]}" -- bash -euo pipefail -c '
    ip link set lo up
    unshare --user --map-user="$1" --map-group="$2" -- true
' bash "$test_uid" "$test_gid" 2>/dev/null; then
    exec "${namespace[@]}" -- bash -euo pipefail -c '
        ip link set lo up
        test_uid="$1"; test_gid="$2"; shift 2
        exec unshare --user --map-user="$test_uid" --map-group="$test_gid" -- "$@"
    ' bash "$test_uid" "$test_gid" "$@"
fi

echo 'private-netns: cannot create a private network namespace with loopback; refusing to run tests' >&2
exit 2
