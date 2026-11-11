#!/usr/bin/env bash
# Named production-path break-the-fix proof. Run only via the lane QA wrapper.
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-protocol/src/sender_transcript.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
expect_assertion_failure() {
    local crate="$1" test_name="$2" rc=0
    timeout 300 cargo test -p "$crate" --lib "$test_name" -- --nocapture >"$log" 2>&1 || rc=$?
    if [ "$rc" != 101 ] || ! rg -q "test .*${test_name} .*FAILED" "$log"; then
        cat "$log"
        echo "BtF did not reach the named failing assertion: $crate $test_name" >&2
        exit 1
    fi
    printf 'BTF_KILLED %s %s\n' "$crate" "$test_name"
}
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
s = path.read_text()
needle = 'if value.get("payload_hash").and_then(Value::as_str) != Some(expected.as_str())'
assert s.count(needle) == 1
path.write_text(s.replace(needle, 'if false && value.get("payload_hash").and_then(Value::as_str) != Some(expected.as_str())'))
PY
expect_assertion_failure ramflux-node-core sender_signature_requires_ciphertext_hash_on_every_node_verifier
expect_assertion_failure ramflux-sdk sender_signature_requires_ciphertext_hash_on_sdk_ephemeral_verifier
cp "$saved" "$source_file"
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
s = path.read_text()
needle = 'value.remove("signature");'
assert s.count(needle) == 1
path.write_text(s.replace(needle, 'value.remove("routing_set_id");\n    ' + needle))
PY
expect_assertion_failure ramflux-protocol sender_transcript_golden_vectors
cp "$saved" "$source_file"
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
s = path.read_text()
needle = 'crate::verify_canonical_signature(&transcript.bytes, signature, public_key)?;'
assert s.count(needle) == 1
path.write_text(s.replace(needle, 'crate::verify_canonical_signature(&transcript.bytes, signature, public_key).or_else(|_| crate::verify_canonical_signature(&crate::signed_bytes(envelope)?, signature, public_key))?;'))
PY
expect_assertion_failure ramflux-protocol v1_signature_not_accepted_as_v2_and_vice_versa
cp "$saved" "$source_file"
printf 'ORIGIN_SIGNATURE_BTF_OK\n'
