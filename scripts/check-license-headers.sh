#!/usr/bin/env bash
# Provenance gate: every Rust source must carry an SPDX header, and every member
# crate must inherit the workspace license instead of hardcoding one. Pure
# bash + git, no toolchain required. Runs in CI and as a local pre-commit check.
set -euo pipefail

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

fail=0

# 1. SPDX-License-Identifier header on every tracked .rs under crates/ and apps/.
missing_spdx=$(git ls-files crates apps | grep '\.rs$' | while read -r f; do
  if ! head -n 5 "$f" | grep -q 'SPDX-License-Identifier:'; then
    printf '%s\n' "$f"
  fi
done)
if [ -n "$missing_spdx" ]; then
  printf '::error::missing SPDX-License-Identifier header in:\n%s\n' "$missing_spdx"
  fail=1
fi

# 2. Member crates must declare `license.workspace = true`; a hardcoded
#    `license = "..."` (e.g. a stale Apache-2.0) silently contradicts the
#    open-core boundary in LICENSING.md, the SPDX headers, and NOTICE.
hardcoded_license=$(git ls-files crates apps | grep '/Cargo.toml$' | while read -r f; do
  if grep -qE '^[[:space:]]*license[[:space:]]*=[[:space:]]*"' "$f"; then
    printf '%s\n' "$f"
  fi
done)
if [ -n "$hardcoded_license" ]; then
  printf "::error::crate must use 'license.workspace = true', found hardcoded license in:\n%s\n" "$hardcoded_license"
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  printf 'provenance gate: OK\n'
fi
exit "$fail"
