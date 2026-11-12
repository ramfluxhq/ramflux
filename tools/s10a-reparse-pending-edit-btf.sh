#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/client/raw_inner_reparse.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import re,sys
p=Path(sys.argv[1]);s=p.read_text()
s,count=re.subn(r'self\.resolve_generated_pending_edit\(\s*&provenance\.conversation,\s*&provenance\.message\s*,?\s*\)\?;', '// BtF: omit pending Edit resolution at upgrade install', s)
assert count==1
p.write_text(s)
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib reparse_message_resolves_parked_edit_before_publishing_content_in_force -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*reparse_message_resolves_parked_edit_before_publishing_content_in_force .*FAILED' "$log" \
    || ! rg -q 'reparse published original instead of parked Edit' "$log"; then
    cat "$log"; echo 'Reparse pending Edit BtF did not reach assertion' >&2; exit 1
fi
printf 'REPARSE_PENDING_EDIT_BTF_OK\n'
