#!/usr/bin/env bash
# Production generated error namespace checks, on QA only.
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/bindings/errors.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
expect_failure() {
    local named="$1" rc=0
    timeout 300 cargo test -p ramflux-sdk --lib "$named" -- --nocapture >"$log" 2>&1 || rc=$?
    if [ "$rc" != 101 ] || ! rg -q "test .*${named} .*FAILED" "$log"; then
        cat "$log"; echo "BtF did not reach named assertion: $named" >&2; exit 1
    fi
    printf 'BTF_KILLED ramflux-sdk %s\n' "$named"
    cp "$saved" "$source_file"
}
python3 - "$source_file" <<'PYCODE'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='Self::EditConflict => "edit_conflict"'
assert s.count(needle)==1;p.write_text(s.replace(needle,'Self::EditConflict => "invalid_argument"'))
PYCODE
expect_failure generated_requests_updates_share_core_across_product_adapters
printf 'GENERATED_ERRORS_BTF_OK\n'
