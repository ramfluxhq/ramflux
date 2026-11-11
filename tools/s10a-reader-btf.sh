#!/usr/bin/env bash
# Production tombstone identity and closed metadata retention checks, on QA only.
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-storage/src/account_db/message_footprint/erasure.rs
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
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle="WHEN state_kind='routed/generated-identity/'||NEW.message_id"
assert s.count(needle)==1;p.write_text(s.replace(needle,"WHEN 0 AND state_kind='routed/generated-identity/'||NEW.message_id"))
PY
expect_failure typed_tombstones_preserve_raw_identity_recorded_scope_and_invalidate_actual_cache
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle="AND NOT EXISTS(SELECT 1 FROM json_each(CAST(state_json AS TEXT)) WHERE key NOT IN ('id','conversationId','author','deviceSequence','hlc','groupId','groupEpoch'))"
assert s.count(needle)==1;p.write_text(s.replace(needle,'AND 1'))
PY
expect_failure typed_identity_retention_never_preserves_payload_shadows_or_unbound_headers
printf 'READER_BTF_OK\n'
