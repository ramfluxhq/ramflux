#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
: "${CARGO_TARGET_DIR:?CARGO_TARGET_DIR is required}"
s10a_header_dir="$CARGO_TARGET_DIR/include"
test -s "$s10a_header_dir/ramflux_sdk.h"
s10a_source=$(mktemp)
trap 'rm -f "$s10a_source"' EXIT
cat >"$s10a_source" <<'HEADER'
#include "ramflux_sdk.h"
int main(void) { return ramflux_sdk_abi_version_major() == 0; }
HEADER
cc -std=c11 -Werror -x c -I"$s10a_header_dir" -fsyntax-only "$s10a_source"
c++ -std=c++17 -Werror -x c++ -I"$s10a_header_dir" -fsyntax-only "$s10a_source"
echo C_ABI_HEADER_SMOKE_OK
