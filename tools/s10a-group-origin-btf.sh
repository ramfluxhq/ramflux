#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-crypto/src/group_opening.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text()
start=s.index('        let computed = franking_commitment(')
end=s.index('        for (actual, expected)',start)
chunk=s[start:end]
argument=chunk[chunk.index('&FrankingCommitmentInput')+1:chunk.rfind(')')]
replacement='        let _ = franking_commitment;\n        let _ = '+argument+';\n'
replacement+='''        let computed = crate::FrankingCommitment {
            plaintext_hash: String::new(), associated_data_hash: String::new(),
            ciphertext_hash: ramflux_protocol::encode_base64url(&sealed.ciphertext_hash), header_hash: ramflux_protocol::encode_base64url(&sealed.header_hash),
            key_commitment: ramflux_protocol::encode_base64url(&sealed.key_commitment), franking_commitment: ramflux_protocol::encode_base64url(&sealed.franking_commitment),
            commitment: ramflux_protocol::encode_base64url(&sealed.commitment),
        };
'''
p.write_text(s[:start]+replacement+s[end:])
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib group_origin_signed_wrapper_rejects_altered_plaintext_and_missing_evidence -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*group_origin_signed_wrapper_rejects_altered_plaintext_and_missing_evidence .*FAILED' "$log" \
    || ! rg -q 'signed group origin accepted plaintext' "$log"; then
    cat "$log"; echo 'Group opening BtF did not reach assertion' >&2; exit 1
fi
printf 'GROUP_ORIGIN_RECOMPUTATION_BTF_OK\n'
