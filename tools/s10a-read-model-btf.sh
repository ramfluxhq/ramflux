#!/usr/bin/env bash
# Production break-the-fix probes for the unified read model and the bus lag notice, on QA only.
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
model=crates/ramflux-sdk/src/client/typed_read_model.rs
events=crates/ramflux-sdk/src/bus/events.rs
saved_model=$(mktemp)
saved_events=$(mktemp)
log=$(mktemp)
cp "$model" "$saved_model"
cp "$events" "$saved_events"
restore() {
    cp "$saved_model" "$model"
    cp "$saved_events" "$events"
}
cleanup() { restore; rm -f "$saved_model" "$saved_events" "$log"; }
trap cleanup EXIT
mutate() {
    python3 - "$1" "$2" "$3" <<'PYCODE'
from pathlib import Path
import sys
path, needle, replacement = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
source = path.read_text()
assert source.count(needle) == 1, f"needle count {source.count(needle)}: {needle}"
path.write_text(source.replace(needle, replacement))
PYCODE
}
expect_failure() {
    local named="$1" rc=0
    timeout 600 cargo test -p ramflux-sdk --lib "$named" -- --nocapture >"$log" 2>&1 || rc=$?
    if [ "$rc" != 101 ] || ! rg -q "test .*${named} .*FAILED" "$log"; then
        cat "$log"; echo "BtF did not reach named assertion: $named" >&2; exit 1
    fi
    printf 'BTF_KILLED ramflux-sdk %s\n' "$named"
    restore
}
expect_pass() {
    timeout 600 cargo test -p ramflux-sdk --lib "$1" -- --nocapture >"$log" 2>&1 \
        || { cat "$log"; echo "restored test failed: $1" >&2; exit 1; }
    rg -q "test result: ok. [1-9]" "$log" || { echo "restored filter matched no test: $1" >&2; exit 1; }
}

# 1. A change cursor that re-serves the row at the cursor.
mutate "$model" 'after_sequence != 0 && sequence <= after_sequence' \
    'after_sequence != 0 && sequence < after_sequence'
expect_failure read_model_serves_page_changes_and_detail_from_the_durable_store

# 2. A truncated batch that claims to be complete: the delivery-page loss, reintroduced.
mutate "$model" '(updates, total > cut)' '(updates, false)'
expect_failure durable_changes_serve_a_backlog_larger_than_the_delivery_page

# 3. Media key slots left in rendered content.
mutate "$model" '        media.key_slots.clear();' '        let _ = &media.key_slots;'
expect_failure read_model_content_carries_no_media_key_or_read_capability

# 4. An overflowing unified subscriber dropped without a lag notice.
mutate "$events" 'fn signals_lag() -> bool {
    crate::client::target_selection::schema_v1_selected()' 'fn signals_lag() -> bool {
    false'
expect_failure unified_overflow_ends_with_a_lag_notice_instead_of_a_silent_drop

for named in \
    read_model_serves_page_changes_and_detail_from_the_durable_store \
    durable_changes_serve_a_backlog_larger_than_the_delivery_page \
    tampered_committed_binding_is_refused_and_never_served \
    read_model_content_carries_no_media_key_or_read_capability \
    unified_overflow_ends_with_a_lag_notice_instead_of_a_silent_drop \
    dormant_generation_keeps_the_existing_overflow_behaviour; do
    expect_pass "$named"
done
printf 'READ_MODEL_BTF_OK\n'
