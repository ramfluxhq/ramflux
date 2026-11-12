#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-storage/src/account_db/backup_self_sync.rs
named=self_sync_restore_erases_local_repair_fingerprints_and_outbox_copies
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]); s = p.read_text()
old = 'super::self_sync_retirement::retire_actor(&self.db, &key)?;'
assert s.count(old) == 1
p.write_text(s.replace(old, 'self.db.execute("DELETE FROM runtime_actor_state WHERE state_kind=?1", [&key])?;'))
PY
if timeout 300 cargo test -p ramflux-storage --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'self_sync_restore_retirement mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo SELF_SYNC_RESTORE_RETIREMENT_BTF_OK
