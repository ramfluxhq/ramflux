#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/client/generated_control/receive.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text()
needle='if sender != source.root_commitment() || local != &own || sender == local {'
assert s.count(needle)==1
p.write_text(s.replace(needle,'if sender == local || own.is_empty() {'))
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib generated_friend_wrong_actor_is_refused_before_unsupported_retention -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*generated_friend_wrong_actor_is_refused_before_unsupported_retention .*FAILED' "$log" \
    || ! rg -q 'wrong Friend endpoint role reached retention/execution' "$log"; then
    cat "$log"; echo 'Friend authority BtF did not reach assertion' >&2; exit 1
fi
printf 'FRIEND_AUTHORITY_BTF_OK\n'
