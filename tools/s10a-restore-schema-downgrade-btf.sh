#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-storage/src/account_db/restore_floor.rs
named=restore_refuses_archive_from_newer_schema_in_same_generation
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]); s = p.read_text()
old = 'if newest > supported {'
assert s.count(old) == 1
p.write_text(s.replace(old, 'if newest > supported && newest < 0 {'))
PY
if timeout 300 cargo test -p ramflux-storage --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'restore-schema-downgrade mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo RESTORE_SCHEMA_DOWNGRADE_BTF_OK
