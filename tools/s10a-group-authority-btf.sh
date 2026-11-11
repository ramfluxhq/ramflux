#!/usr/bin/env bash
# Exercise each production authority guard as well as the complete routed receive chain.
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/client/generated_group.rs
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
p=Path(sys.argv[1]);s=p.read_text();needle='if author.account_anchor != source.root_commitment()'
assert s.count(needle)==1;p.write_text(s.replace(needle,'if false && author.account_anchor != source.root_commitment()'))
PY
expect_failure generated_group_author_must_equal_pair_peer
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='if !group.native_authority_proof.is_empty()'
assert s.count(needle)==1;p.write_text(s.replace(needle,'if false && !group.native_authority_proof.is_empty()'))
PY
expect_failure generated_group_refuses_nonempty_authority_proof
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();a=s.index('pub(crate) fn require_generated_group_epoch(');prefix=s[:a];tail=s[a:]
needle='if let Some(current) = db.shared_group_state(group)? {'
assert tail.count(needle)==1;tail=tail.replace(needle,'if let Some(current) = db.shared_group_state_at_epoch(group, epoch)? {');p.write_text(prefix+tail)
PY
expect_failure generated_group_author_must_be_current_member
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();a=s.index('pub(crate) fn require_generated_group_epoch(');prefix=s[:a];tail=s[a:]
needle='db.shared_group_state_at_epoch(group, epoch)?'
assert tail.count(needle)==1;p.write_text(prefix+tail.replace(needle,'db.shared_group_state(group)?'))
PY
expect_failure generated_group_requires_pinned_key_epoch
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();a=s.index('pub(crate) fn require_generated_group_epoch(');prefix=s[:a];tail=s[a:]
needle='if let Some(current) = db.shared_group_state(group)? {'
assert tail.count(needle)==1;tail=tail.replace(needle,'if let Some(current) = db.shared_group_state_at_epoch(group, epoch)? {');p.write_text(prefix+tail)
PY
expect_failure pending_moderator_delete_is_ignored_after_demotion_without_poisoning_target
printf 'GROUP_AUTHORITY_BTF_OK\n'
