#!/usr/bin/env bash
# Real production-path edits only; execute on the lane QA host.
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
saved=$(mktemp -d)
log=$(mktemp)
files=(crates/ramflux-sdk/src/client/generated_history/producer.rs)
for i in "${!files[@]}"; do cp "${files[$i]}" "$saved/$i"; done
restore_files() { for i in "${!files[@]}"; do cp "$saved/$i" "${files[$i]}"; done; }
cleanup() { restore_files; rm -rf "$saved"; rm -f "$log"; }
trap cleanup EXIT
expect_failure() {
    local crate="$1" named="$2" rc=0
    timeout 300 cargo test --locked --offline -p "$crate" --lib "$named" -- --nocapture >"$log" 2>&1 || rc=$?
    if [ "$rc" != 101 ] || ! rg -q "test .*${named} .*FAILED" "$log"; then cat "$log"; echo "BtF did not reach named assertion: $named" >&2; exit 1; fi
    printf 'BTF_KILLED %s %s\n' "$crate" "$named"
}
# 1. Forward a row that has no retained first-hand origin evidence.
python3 - "${files[0]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='Err(SdkError::HistoryEvidence(_) | SdkError::GeneratedRefused { .. }) => Ok(None),';assert s.count(needle)==1;p.write_text(s.replace(needle,'Err(SdkError::HistoryEvidence(_) | SdkError::GeneratedRefused { .. }) => Ok(Some(g::HistoryItem::default())),'))
PY
expect_failure ramflux-sdk history_producer_skips_rows_without_first_hand_evidence
restore_files
# 2. Let a transfer leave the account root.
python3 - "${files[0]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='if target == &local || target.root_commitment() != local.root_commitment() {';assert s.count(needle)==1;p.write_text(s.replace(needle,'if target == &local {'))
PY
expect_failure ramflux-sdk history_staging_refuses_the_local_device_and_a_foreign_root
restore_files
# 3. Keep the old transfer id when the chain restarts.
python3 - "${files[0]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='        self.transfer_id = random_transfer_id()?;\n        self.next_page = 0;';assert s.count(needle)==1;p.write_text(s.replace(needle,'        self.next_page = 0;'))
PY
expect_failure ramflux-sdk history_chain_restart_keeps_item_cursor_and_starts_at_page_zero
restore_files
# 4. Re-export the cursor row after a resume.
python3 - "${files[0]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='cursor.is_none_or(|cursor| position > cursor)';assert s.count(needle)==1;p.write_text(s.replace(needle,'cursor.is_none_or(|cursor| position >= cursor)'))
PY
expect_failure ramflux-sdk history_producer_pages_first_hand_items_in_cursor_order_with_exact_bytes
restore_files
# 5. Drop the exact-item digest from the produced page.
python3 - "${files[0]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='                page_digest: digest.to_vec(),';assert s.count(needle)==1;p.write_text(s.replace(needle,'                page_digest: vec![0; 32],'))
PY
expect_failure ramflux-sdk history_producer_pages_first_hand_items_in_cursor_order_with_exact_bytes
restore_files
echo HISTORY_PRODUCER_BTF_OK
