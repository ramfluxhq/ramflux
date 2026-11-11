#!/usr/bin/env bash
# Audited receive regressions; mutate the production functions on the QA copy only.
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
receive=crates/ramflux-sdk/src/client/routed/receive.rs
send=crates/ramflux-sdk/src/client/routed/mod.rs
reaction=crates/ramflux-sdk/src/client/message_mutations/reactions.rs
saved_reaction=$(mktemp)
saved_receive=$(mktemp)
saved_send=$(mktemp)
log=$(mktemp)
extra_files=(crates/ramflux-sdk/src/client/self_sync/fence.rs crates/ramflux-sdk/src/client/self_sync/publication.rs)
saved_extra=$(mktemp -d)
for i in "${!extra_files[@]}"; do cp "${extra_files[$i]}" "$saved_extra/$i"; done
cp "$reaction" "$saved_reaction"
cp "$receive" "$saved_receive"
cp "$send" "$saved_send"
restore() { for i in "${!extra_files[@]}"; do cp "$saved_extra/$i" "${extra_files[$i]}"; done; rm -rf "$saved_extra"; cp "$saved_reaction" "$reaction"; cp "$saved_receive" "$receive"; cp "$saved_send" "$send"; rm -f "$saved_reaction" "$saved_receive" "$saved_send" "$log"; }
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
python3 - "$receive" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]); s=path.read_text()
needle='if matches!(code, "authentication_failed" | "schema_invalid" | "routing_rejected") {'
assert s.count(needle)==1
path.write_text(s.replace(needle, 'if code == "authentication_failed" { return Ok(()); }\n        '+needle))
PY
expect_assertion_failure refused_first_c_does_not_strand_pair_successor
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
expect_assertion_failure typing_budget_survives_interleaved_durable_sends_and_restart
cp "$saved_send" "$send"
python3 - "$reaction" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]);s=path.read_text()
needle='if order <= previous_order {'
assert s.count(needle)==1
path.write_text(s.replace(needle,'if previous.reaction.remove && reaction.remove { return Ok(false); }\n                '+needle))
PY
expect_assertion_failure reaction_signed_order_advances_absent_noops_and_bounds_visible_tokens
cp "$saved_reaction" "$reaction"
python3 - "${extra_files[0]}" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]);s=path.read_text()
needle='db.remove_actor_state(&key)?;'
assert s.count(needle)==2
path.write_text(s.replace(needle,needle+'\n                db.remove_actor_state(&floor_key(&key))?;',1))
PY
expect_assertion_failure self_sync_read_draft_pin_mute_revision_authority_and_erasure
cp "$saved_extra/0" "${extra_files[0]}"
python3 - "${extra_files[1]}" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]);s=path.read_text()
needle='if !reuse {'
assert s.count(needle)==1
path.write_text(s.replace(needle,'if true || !reuse {'))
PY
expect_assertion_failure self_sync_publication_allocates_once_across_fanout_and_restart
cp "$saved_extra/1" "${extra_files[1]}"
printf 'RECEIVE_BTF_OK\n'
