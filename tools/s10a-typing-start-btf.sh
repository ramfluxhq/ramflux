#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/client/typing.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='if future_clear {'
assert s.count(needle)==2
# Keep quota accounting; break only the production deferred-clear admission branch.
a=s.index('        if future_clear {');s=s[:a]+s[a:].replace(needle,'if future_clear && false {',1)
p.write_text(s)
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib future_typing_clear_cannot_remove_visible_indicator_before_signed_start -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*future_typing_clear_cannot_remove_visible_indicator_before_signed_start .*FAILED' "$log"; then
    cat "$log"; echo 'Typing signed-start BtF did not reach assertion' >&2; exit 1
fi
printf 'TYPING_SIGNED_START_BTF_OK\n'
