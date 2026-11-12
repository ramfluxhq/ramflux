#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-storage/src/account_db/backup_edit_register.rs
named=restored_equal_revision_edit_takes_greater_event_id_in_both_directions
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]); s = p.read_text()
old = '=> match first.cmp(second) {'
assert s.count(old) == 1
p.write_text(s.replace(old, '=> match first.as_ref().map(|pair| pair.revision).cmp(&second.as_ref().map(|pair| pair.revision)) {'))
PY
if timeout 300 cargo test -p ramflux-storage --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'restore-edit-winner mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo RESTORE_EDIT_WINNER_BTF_OK
