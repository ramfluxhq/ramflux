#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-sdk/src/client/routed/generated_transport.rs
named=shared_generated_sealer_refuses_closed_a2i_and_floorless_self_sync_before_framing
snapshot=$(mktemp)
log_file=$(mktemp)
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
timeout 300 cargo test -p ramflux-sdk --all-features --lib "$named" >"$log_file" 2>&1 || { cat "$log_file"; rm -f "$snapshot" "$log_file"; exit 1; }
cp "$source_file" "$snapshot"
trap restore EXIT
python3 - "$source_file" <<'PYM'
from pathlib import Path
import sys
p = Path(sys.argv[1]); s = p.read_text()
old = 'if closed_a2i {'
assert s.count(old) == 1
p.write_text(s.replace(old, 'if closed_a2i && false {'))
PYM
if timeout 300 cargo test -p ramflux-sdk --all-features --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'shared generated producer authority mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach named regression' >&2
    exit 1
fi
echo SHARED_PRODUCER_AUTHORITY_BTF_OK
