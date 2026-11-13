#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
: "${CARGO_TARGET_DIR:?persistent lane target required}"
: "${S10A_BTF_DIR:?persistent evidence directory required}"
mkdir -p "$S10A_BTF_DIR"
s10a_test=client::target_selection::tests::bad_cached_authority_isolates_that_member_as_stale
s10a_source=crates/ramflux-sdk/src/client/target_selection.rs
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
p = Path('crates/ramflux-sdk/src/client/target_selection.rs')
s = p.read_text()
start = s.index('    fn shared_group_selection_request(')
left = s.index('        let selected =', start)
right = s.index(';', left) + 1
assert 'select_layer_devices' in s[left:right]
# Reintroduce the old strict routing dependency into a format-only plan.
s = s[:right] + '\n        let selected = { drop(selected); self.shared_group_selected_devices(state)? };' + s[right:]
p.write_text(s)
PY
set +e
run_test "$S10A_BTF_DIR/mutant.log"
s10a_rc=$?
set -e
cp "$s10a_backup" "$s10a_source"
test "$s10a_rc" != 0
grep -q 'test result: FAILED. 0 passed; 1 failed;' "$S10A_BTF_DIR/mutant.log"
grep -q 'custody publication absent' "$S10A_BTF_DIR/mutant.log"
if grep -q '^error: could not compile' "$S10A_BTF_DIR/mutant.log"; then exit 1; fi
run_test "$S10A_BTF_DIR/restored.log"
grep -q 'test result: ok. 1 passed' "$S10A_BTF_DIR/restored.log"
echo TARGET_PLAN_MEMBER_ISOLATION_BTF_OK
