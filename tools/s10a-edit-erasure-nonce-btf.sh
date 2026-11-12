#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-sdk/src/client/message_mutations.rs
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
needle = '    if target.id.is_empty() || target.conversation_id.is_empty() || target.author_anchor.is_empty()'
assert s.count(needle) == 1
s = s.replace(needle, '''    // Break the production digest: omit the private entropy from the exact Message.
    let mut broken = ramflux_protocol::message::Message::decode(exact)
        .map_err(|_| refused("BtF Message invalid"))?;
    broken.erasure_nonce.clear();
    let broken_bytes = broken.encode_to_vec();
    let exact = broken_bytes.as_slice();
''' + needle)
p.write_text(s)
PY
if timeout 300 cargo test -p ramflux-sdk --lib private_revision_nonce_blocks_erased_text_guessing_and_preserves_fanout >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'nonce erasure mutant survived' >&2
    exit 1
fi
if ! rg -q 'private_revision_nonce_blocks_erased_text_guessing_and_preserves_fanout .*FAILED|private_revision_nonce_blocks_erased_text_guessing_and_preserves_fanout --- FAILED' "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo EDIT_ERASURE_NONCE_BTF_OK
