#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-sdk/src/client/self_sync/delivery.rs
named=native_contacts_backfill_once_after_enrollment_without_private_branch_loaded
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import re, sys
p = Path(sys.argv[1]); s = p.read_text()
pattern = r'if !self\.self_sync_target_admitted\(&target, repair\.target_epoch\)\?\s*\|\|\s*self\.self_sync_target_certificate\(&target\)\? != repair\.target_certificate'
s, count = re.subn(pattern, 'if false', s)
assert count == 1
p.write_text(s)
PY
if timeout 300 cargo test -p ramflux-sdk --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'self_sync_target_retirement mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo SELF_SYNC_TARGET_RETIREMENT_BTF_OK
