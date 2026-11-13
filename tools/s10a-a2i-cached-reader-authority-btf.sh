#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
: "${CARGO_TARGET_DIR:?persistent lane target required}"
: "${S10A_BTF_DIR:?persistent evidence directory required}"
mkdir -p "$S10A_BTF_DIR"
s10a_test=client::routed::tests::r4::retained_a2i_rows_cannot_be_exposed_or_acknowledged_after_reopen
s10a_source=crates/ramflux-sdk/src/bus/readers/local.rs
s10a_backup=$(mktemp)
cp "$s10a_source" "$s10a_backup"
restore() {
    if ! cmp -s "$s10a_backup" "$s10a_source"; then cp "$s10a_backup" "$s10a_source"; fi
    rm -f "$s10a_backup"
}
trap restore EXIT
run_test() {
    timeout 300 cargo test -p ramflux-sdk --lib "$s10a_test" -- --exact --nocapture > "$1" 2>&1
}
run_test "$S10A_BTF_DIR/baseline.log"
grep -q 'test result: ok. 1 passed' "$S10A_BTF_DIR/baseline.log"
python3 - <<'PY'
from pathlib import Path
p = Path('crates/ramflux-sdk/src/bus/readers/local.rs')
s = p.read_text()
start = 'fn a2i(_client: &RamfluxClient, _pending: bool) -> Result<Value, SdkError> {'
assert s.count(start) == 1
left = s.index(start)
right = s.index('\n}', left) + 2
# Restore the former cached projection, which lacked native grant admission.
old_reader = '''fn a2i(client: &RamfluxClient, pending: bool) -> Result<Value, SdkError> {
    let mut events = Vec::new();
    for event in client.account_db()?.list_actor_states::<ramflux_sync::A2iControlEvent>("a2i/scoped/")? {
        if event.source_principal_commitment.is_none()
            || event.source_principal_id.is_none()
            || (pending && event.acknowledged)
        { continue; }
        let source = client.a2i_event_identity(&event)?;
        let mut row = serde_json::to_value(&event)?;
        row["acknowledge_id"] = json!(crate::client::routed::control::a2i_key(&source, &event.event_id)?);
        events.push(row);
    }
    Ok(json!({"events":events}))
}'''
p.write_text(s[:left] + old_reader + s[right:])
PY
set +e
run_test "$S10A_BTF_DIR/mutant.log"
s10a_rc=$?
set -e
cp "$s10a_backup" "$s10a_source"
test "$s10a_rc" != 0
grep -q 'test result: FAILED. 0 passed; 1 failed;' "$S10A_BTF_DIR/mutant.log"
grep -q 'A2I authority refusal missing: None' "$S10A_BTF_DIR/mutant.log"
if grep -q '^error: could not compile' "$S10A_BTF_DIR/mutant.log"; then exit 1; fi
run_test "$S10A_BTF_DIR/restored.log"
grep -q 'test result: ok. 1 passed' "$S10A_BTF_DIR/restored.log"
echo A2I_CACHED_READER_AUTHORITY_BTF_OK
