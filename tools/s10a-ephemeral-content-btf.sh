#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/client/routed/ephemeral_content.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='if scanned.outcome == ScanOutcome::Unsupported {'
assert s.count(needle)==1;p.write_text(s.replace(needle,'if scanned.outcome == ScanOutcome::Unsupported || scanned.kind != 7 {'))
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib ephemeral_unknown_is_retained_and_known_non_typing_is_dropped -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*ephemeral_unknown_is_retained_and_known_non_typing_is_dropped .*FAILED' "$log"; then
    cat "$log"; echo 'Ephemeral content BtF did not reach assertion' >&2; exit 1
fi
printf 'EPHEMERAL_CONTENT_BTF_OK\n'
