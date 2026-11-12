#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/client/routed/control.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();base=s.index('pub(super) fn refresh_routed_control_cache(')
start=s.index('        if self.refresh_generated_control_cache(body)?',base)
end=s.index('        if self.refresh_call_control(body)?',start)
p.write_text(s[:start]+s[end:])
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib generated_unknown_control_retention_never_parses_legacy_cache_json -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*generated_unknown_control_retention_never_parses_legacy_cache_json .*FAILED' "$log" \
    || ! rg -q 'generated Control fell back to legacy cache' "$log"; then
    cat "$log"; echo 'Generated control cache BtF did not reach assertion' >&2; exit 1
fi
printf 'GENERATED_CONTROL_CACHE_BTF_OK\n'
