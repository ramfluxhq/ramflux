#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain

# Custom Actions shell for jobs eligible for the three sandboxed QA runners.
set -euo pipefail
if [ "$#" -ne 1 ]; then
    echo 'qa-job: expected the Actions step script' >&2
    exit 2
fi
if [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ]; then
    exec bash --noprofile --norc -e -o pipefail "$1"
fi
if [ "${RUNNER_ENVIRONMENT:-}" != self-hosted ] || [ "$(uname -s)" != Linux ]; then
    echo 'qa-job: expected a hosted runner or sandboxed Linux runner' >&2
    exit 2
fi

# The service's PrivateTmp mount may not provide /tmp. Keep compilers and
# test fixtures in the Actions-owned directory, without changing host mounts.
export RF_CI_TMPBASE="${RUNNER_TEMP:?qa-job: RUNNER_TEMP is required}"
export TMPDIR="${RF_TEST_TMPDIR:-$RF_CI_TMPBASE}"
export TMP="$TMPDIR"
export TEMP="$TMPDIR"
if [ ! -d "$TMPDIR" ] || [ ! -w "$TMPDIR" ]; then
    echo 'qa-job: Actions temporary directory is unavailable' >&2
    exit 2
fi

# At most six compiler/test workers across the three runners. These are
# concurrency bounds, not CPU reservations; lane cargo uses normal priority.
export CARGO_BUILD_JOBS=2
export CMAKE_BUILD_PARALLEL_LEVEL=2
export NEXTEST_TEST_THREADS=2
export RUST_TEST_THREADS=2
exec nice -n 10 bash --noprofile --norc -e -o pipefail "$1"
