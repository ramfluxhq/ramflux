#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
: "${CARGO_TARGET_DIR:?persistent lane target required}"
: "${S10A_BTF_DIR:?persistent evidence directory required}"
mkdir -p "$S10A_BTF_DIR"
s10a_test=bus::backup_jobs::native_tests::recovery_tests::native_backup_fresh_restore_completes_offline_and_lists_pending_account
s10a_source=crates/ramflux-sdk/src/client/shared_group/mod.rs
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
p = Path('crates/ramflux-sdk/src/client/shared_group/mod.rs')
s = p.read_text()
start = '        let selected = match self.shared_group_selected_devices(&verified) {'
end = '        for (root, names) in selected {'
assert s.count(start) == 1 and s.count(end) == 1
left = s.index(start)
right = s.index(end, left)
p.write_text(s[:left] + '        let selected = self.shared_group_selected_devices(&verified)?;\n' + s[right:])
PY
set +e
run_test "$S10A_BTF_DIR/mutant.log"
s10a_rc=$?
set -e
cp "$s10a_backup" "$s10a_source"
test "$s10a_rc" != 0
grep -q 'test result: FAILED. 0 passed; 1 failed;' "$S10A_BTF_DIR/mutant.log"
grep -q 'read restored group:.*native group roster authority unavailable' "$S10A_BTF_DIR/mutant.log"
if grep -q '^error: could not compile' "$S10A_BTF_DIR/mutant.log"; then exit 1; fi
run_test "$S10A_BTF_DIR/restored.log"
grep -q 'test result: ok. 1 passed' "$S10A_BTF_DIR/restored.log"
echo NATIVE_GROUP_DISPLAY_RESTORE_BTF_OK
