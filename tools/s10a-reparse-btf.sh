#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
reparse=crates/ramflux-storage/src/account_db/raw_inner/reparse.rs
quota=crates/ramflux-storage/src/account_db/raw_inner/quota.rs
saved_reparse=$(mktemp)
saved_quota=$(mktemp)
log=$(mktemp)
cp "$reparse" "$saved_reparse"
cp "$quota" "$saved_quota"
restore() { cp "$saved_reparse" "$reparse"; cp "$saved_quota" "$quota"; rm -f "$saved_reparse" "$saved_quota" "$log"; }
trap restore EXIT
expect_failure() {
    local named="$1" rc=0
    timeout 300 cargo test -p ramflux-storage --lib "$named" -- --nocapture >"$log" 2>&1 || rc=$?
    if [ "$rc" != 101 ] || ! rg -q "test .*${named} .*FAILED" "$log"; then
        cat "$log"; echo "Reparse BtF did not reach named assertion: $named" >&2; exit 1
    fi
    printf 'BTF_KILLED ramflux-storage %s\n' "$named"
}
python3 - "$reparse" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='WHERE c.attempted_decoder<>?1'
assert s.count(needle)==1;p.write_text(s.replace(needle,'WHERE c.attempted_decoder<>?1 OR c.attempted_decoder=?1'))
PY
expect_failure reparse_attempts_survive_reopen_and_progress_past_sixty_four_copies
cp "$saved_reparse" "$reparse"
python3 - "$quota" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='length(c.raw_bytes)+length(c.copy_metadata)'
assert s.count(needle)==2;p.write_text(s.replace(needle,'length(c.raw_bytes)'))
PY
expect_failure unsupported_quota_is_atomic_and_preserves_existing_rows
printf 'REPARSE_ATTEMPT_QUOTA_BTF_OK\n'
