#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/client/unsupported_view.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='raw_handle: handle.clone(),'
assert s.count(needle)==1
p.write_text(s.replace(needle,'raw_handle: copy_id.as_bytes().to_vec(),'))
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib unknown_kind_is_acked_and_kept_with_raw_bytes -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*unknown_kind_is_acked_and_kept_with_raw_bytes .*FAILED' "$log" \
    || ! rg -q 'Unsupported view leaked private raw locator' "$log"; then
    cat "$log"; echo 'Unsupported handle BtF did not reach assertion' >&2; exit 1
fi
printf 'UNSUPPORTED_HANDLE_BTF_OK\n'
