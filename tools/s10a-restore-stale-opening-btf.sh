#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-storage/src/account_db/backup_edit_register.rs
named=restored_older_edit_never_replaces_local_winner_or_revives_its_openings
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]); s = p.read_text()
old = 'exclude_incoming_content(db, &target, &lost)?;'
assert s.count(old) == 1
p.write_text(s.replace(old, 'let _ = &lost;'))
PY
if timeout 300 cargo test -p ramflux-storage --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'restore-stale-opening mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo RESTORE_STALE_OPENING_BTF_OK
