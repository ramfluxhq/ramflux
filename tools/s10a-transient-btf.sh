#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/bus/client.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text()
needle='if super::events::is_transient(&frame) && !events.is_closed() {'
assert s.count(needle)==1
p.write_text(s.replace(needle,needle+'\n            *last_seq = 0;'))
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib transient_events_never_advance_cursor_or_disconnect_on_overflow -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*transient_events_never_advance_cursor_or_disconnect_on_overflow .*FAILED' "$log" \
    || ! rg -q 'transient event changed the durable cursor' "$log"; then
    cat "$log"; echo 'Transient cursor BtF did not reach assertion' >&2; exit 1
fi
printf 'TRANSIENT_CURSOR_BTF_OK\n'
