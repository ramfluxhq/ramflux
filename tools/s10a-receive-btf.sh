#!/usr/bin/env bash
# Audited receive regressions; mutate the production functions on the QA copy only.
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
receive=crates/ramflux-sdk/src/client/routed/receive.rs
send=crates/ramflux-sdk/src/client/routed/mod.rs
saved_receive=$(mktemp)
saved_send=$(mktemp)
log=$(mktemp)
cp "$receive" "$saved_receive"
cp "$send" "$saved_send"
restore() { cp "$saved_receive" "$receive"; cp "$saved_send" "$send"; rm -f "$saved_receive" "$saved_send" "$log"; }
trap restore EXIT
expect_assertion_failure() {
    local test_name="$1" rc=0
    timeout 300 cargo test -p ramflux-sdk --lib "$test_name" -- --nocapture >"$log" 2>&1 || rc=$?
    if [ "$rc" != 101 ] || ! rg -q "test .*${test_name} .*FAILED" "$log"; then
        cat "$log"
        echo "BtF did not reach the named failing assertion: $test_name" >&2
        exit 1
    fi
    printf 'BTF_KILLED ramflux-sdk %s\n' "$test_name"
}
python3 - "$receive" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1])
s=path.read_text()
needle='self.commit_routed_pair_context(&opened, entry, &opened.body)'
assert s.count(needle)==1
path.write_text(s.replace(needle,'let _ = opened; Ok(())'))
PY
expect_assertion_failure generated_refusals_settle_and_never_stage_locally
cp "$saved_receive" "$receive"
python3 - "$send" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1])
s=path.read_text()
needle='let sizes = measure_wire_sealed_send(client, persist)?;'
assert s.count(needle)==1
path.write_text(s.replace(needle, 'client.account_db()?.persist_actor_state(&format!("dm-pair/ephemeral-seals/{}", persist.session.session_id), &0_u16)?;\n    '+needle))
PY
expect_assertion_failure typing_cannot_exhaust_skipped_keys_or_bootstrap
cp "$saved_send" "$send"
printf 'RECEIVE_BTF_OK\n'
