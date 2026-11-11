#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-crypto/src/group_state/transition.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text()
a=s.index('    ramflux_protocol::message::dm_scope::validate_group(')
b=s.index('    let max_members',a)
p.write_text(s[:a]+s[b:])
PY
rc=0
timeout 300 cargo test -p ramflux-crypto --lib group_genesis_cannot_squat_reserved_dm_namespace -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*group_genesis_cannot_squat_reserved_dm_namespace .*FAILED' "$log"; then
    cat "$log"; echo 'DM reservation BtF did not reach assertion' >&2; exit 1
fi
printf 'DM_SCOPE_BTF_OK\n'
