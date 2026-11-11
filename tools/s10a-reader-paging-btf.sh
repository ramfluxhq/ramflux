#!/usr/bin/env bash
# Production typed paging byte cap and per-row sequence checks, on QA only.
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/client/typed_messages.rs
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
import sys,re
p=Path(sys.argv[1]);s=p.read_text();s,n=re.subn(r'> 768\s*\*\s*1024', '> 1536 * 1024',s);assert n==1;p.write_text(s)
PYCODE
expect_failure message_page_respects_encoded_byte_cap_and_continuation
python3 - "$source_file" <<'PYCODE'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='journal_sequence: sequence';assert s.count(needle)==1;p.write_text(s.replace(needle,'journal_sequence: sequence.max(db.journal_bounds()?.head_seq)'))
PYCODE
expect_failure message_page_projects_generated_content_and_unsupported
printf 'READER_PAGING_BTF_OK\n'
