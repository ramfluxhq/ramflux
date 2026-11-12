#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/client/raw_inner_origin.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();start=s.index('        ramflux_crypto::verify_report_opening(');end=s.index(';',start)+1
assert 'map_err' in s[start:end]
piece=s[start+8:end];assert piece.count('?')==1
s=s[:start]+'        let _ = '+piece.replace('?','')+s[end:];p.write_text(s)
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib retained_origin_uses_first_hand_native_proof_and_rejects_body_identity_and_route_forgery -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*retained_origin_uses_first_hand_native_proof_and_rejects_body_identity_and_route_forgery .*FAILED' "$log"; then
    cat "$log"; echo 'Retained origin BtF did not reach assertion' >&2; exit 1
fi
printf 'RETAINED_ORIGIN_BTF_OK\n'
