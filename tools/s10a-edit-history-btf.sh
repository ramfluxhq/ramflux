#!/usr/bin/env bash
# Real production-path edits only; execute on the lane QA host.
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
saved=$(mktemp -d)
log=$(mktemp)
files=(crates/ramflux-sdk/src/client/routed/generated_receive.rs crates/ramflux-sdk/src/client/generated_history.rs crates/ramflux-storage/src/account_db/message_edit_retirement.rs crates/ramflux-protocol/src/message/original_header.rs crates/ramflux-protocol/src/sender_transcript.rs crates/ramflux-storage/src/account_db/message_footprint/erasure.rs)
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
python3 - "${files[0]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='Self::verify_generated_message_header(entry, bytes)?;';assert s.count(needle)==1;p.write_text(s.replace(needle,'let _ = Self::verify_generated_message_header(entry, bytes);'))
PY
expect_failure ramflux-sdk message_receipt_requires_matching_metadata_commitment
restore_files
python3 - "${files[1]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='if original.root != edit_author.root';assert s.count(needle)==1;p.write_text(s.replace(needle,'if false && original.root != edit_author.root'))
PY
expect_failure ramflux-sdk edited_import_refuses_cross_author_edit
restore_files
python3 - "${files[2]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='fn retire_actor(db: &Connection, key: &str) -> rusqlite::Result<()> {';assert s.count(needle)==1;p.write_text(s.replace(needle,needle+'\n    if !key.is_empty() { return Ok(()); }'))
PY
expect_failure ramflux-storage edit_retires_original_opening_everywhere
restore_files
python3 - "${files[3]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();start=s.index('    if validation::scan_message("EventIdentity"');end=s.index('    super::identity::verify(&identity)',start);s=s[:start]+'    let _ = validation::scan_message("EventIdentity", bytes, registry::COMPILED_LAYER);\n    let identity = EventIdentity::decode(bytes).map_err(|_| bad)?;\n'+s[end:];p.write_text(s)
PY
expect_failure ramflux-protocol retained_identity_refuses_unknown_alternate_and_oversized_bytes
restore_files
python3 - "${files[4]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='remove_node_fields(&mut value);';assert s.count(needle)==2;s=s.replace(needle,needle+'\n    if let Some(ext) = value.get_mut("ext").and_then(Value::as_object_mut) { ext.remove("message_metadata_commitment"); }',1);p.write_text(s)
PY
expect_failure ramflux-protocol sender_transcript_golden_vectors
restore_files
python3 - "${files[3]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();start=s.index('pub fn for_inner(')
s=s[:start]+s[start:].replace('        expires_at,','        expires_at: expires_at + message.reply_to.as_ref().map_or(0, |value| value.encode_to_vec().len() as u64),',1);p.write_text(s)
PY
expect_failure ramflux-protocol original_header_never_commits_body_fields
restore_files
python3 - "${files[3]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='group_state_hash: group.group_state_hash.clone(),';assert s.count(needle)==1;s=s.replace(needle,'group_state_hash: [group.group_state_hash.clone(), group.content_commitment.clone()].concat(),');p.write_text(s)
PY
expect_failure ramflux-protocol edited_group_history_item_drops_wrapper_commitments
restore_files
python3 - "${files[5]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle="AND state_kind<>'directory/message/'||NEW.message_id";assert s.count(needle)==1;s=s.replace(needle,needle+" AND state_kind NOT LIKE 'routed/original-header/%'");p.write_text(s)
PY
expect_failure ramflux-sdk delete_after_edit_erases_original_evidence_and_fences_reimport
restore_files
python3 - "${files[0]}" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='if kind == 1';assert s.count(needle)==2;p.write_text(s.replace(needle,'if false && kind == 1',1))
PY
expect_failure ramflux-sdk retired_original_redelivery_never_replaces_current_edit
restore_files
printf 'EDIT_HISTORY_BTF_OK\n'
