#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-sdk/src/client/own_sent_message/attestation.rs
named=native_live_own_copy_uses_generated_outer_and_retains_the_enclosing_control_proof
snapshot=$(mktemp)
log_file=$(mktemp)
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
timeout 300 cargo test -p ramflux-sdk --lib "$named" >"$log_file" 2>&1 || { cat "$log_file"; rm -f "$snapshot" "$log_file"; exit 1; }
cp "$source_file" "$snapshot"
trap restore EXIT
python3 - "$source_file" <<'PYM'
from pathlib import Path
import sys
p = Path(sys.argv[1]); s = p.read_text()
old = 'db.load_actor_state::<OwnSentAttestation>(&key)? {'
assert s.count(old) == 1
p.write_text(s.replace(old, 'db.load_actor_state::<OwnSentAttestation>(&key)?.filter(|_| false) {'))
PYM
if timeout 300 cargo test -p ramflux-sdk --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'duplicate attestation mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach named regression' >&2
    exit 1
fi
echo OWN_ATTESTATION_DUPLICATE_BTF_OK
