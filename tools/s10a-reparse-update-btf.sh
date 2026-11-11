#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-storage/src/account_db/journal/generated.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='update.journal_sequence = event.seq;'
assert s.count(needle)==1;p.write_text(s.replace(needle,'update.journal_sequence = event.seq.saturating_sub(event.seq);'))
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib reparse_is_idempotent_and_erased_raw_stays_tombstoned -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*reparse_is_idempotent_and_erased_raw_stays_tombstoned .*FAILED' "$log"; then
    cat "$log"; echo 'Reparse cursor BtF did not reach assertion' >&2; exit 1
fi
printf 'REPARSE_UPDATE_CURSOR_BTF_OK\n'
