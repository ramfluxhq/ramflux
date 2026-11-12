#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/client/generated_pending_edit.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='format!("routed/pending-edit/{target}/{root}")'
assert s.count(needle)==1
s=s.replace(needle,'format!("routed/pending-edit/{target}")').replace('fn key(target: &str, root: &str)', 'fn key(target: &str, _root: &str)')
p.write_text(s)
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib early_edit_register_is_qualified_by_original_author_root -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*early_edit_register_is_qualified_by_original_author_root .*FAILED' "$log" \
    || ! rg -q 'foreign root replaced the legitimate pending Edit' "$log"; then
    cat "$log"; echo 'Pending Edit author BtF did not reach assertion' >&2; exit 1
fi
printf 'PENDING_EDIT_AUTHOR_BTF_OK\n'
