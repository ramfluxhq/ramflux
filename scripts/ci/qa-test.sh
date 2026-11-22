#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain

# Fetch/build with the runner's public egress, then run the unchanged test
# selection with private loopback and no route to QA or its other workloads.
set -euo pipefail
if [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ]; then
    exec "$@"
fi
if [ "${RUNNER_ENVIRONMENT:-}" != self-hosted ]; then
    echo 'qa-test: unknown runner environment' >&2
    exit 2
fi
if [ "$#" -lt 2 ] || [ "$1" != cargo ]; then
    echo 'qa-test: expected cargo test or cargo nextest run' >&2
    exit 2
fi
case "$2" in
    test) ;;
    nextest)
        if [ "${3:-}" != run ]; then
            echo 'qa-test: expected cargo nextest run' >&2
            exit 2
        fi
        ;;
    *) echo 'qa-test: expected cargo test or cargo nextest run' >&2; exit 2 ;;
esac
build=()
for argument in "$@"; do
    if [ "$argument" = -- ]; then break; fi
    build+=("$argument")
done
"${build[@]}" --no-run
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec env CARGO_NET_OFFLINE=true bash "$script_dir/private-netns.sh" "$@"
