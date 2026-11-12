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
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='if prepared.provenance.original_mode == "ephemeral" {'
assert s.count(needle)==1;p.write_text(s.replace(needle,'if false {'))
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib reparse_preserves_original_channel_and_authority -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*reparse_preserves_original_channel_and_authority .*FAILED' "$log"; then
    cat "$log"; echo 'Reparse channel BtF did not reach assertion' >&2; exit 1
fi
printf 'REPARSE_ORIGINAL_CHANNEL_BTF_OK\n'
