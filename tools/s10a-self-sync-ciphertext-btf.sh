#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-sdk/src/client/routed/receive.rs
named=stale_self_sync_draft_retains_only_content_free_delivery_receipt
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]); s = p.read_text()
old = '|| self_sync'
assert s.count(old) == 1
p.write_text(s.replace(old, '|| (self_sync && false)'))
PY
if timeout 300 cargo test -p ramflux-sdk --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'self_sync_ciphertext mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo SELF_SYNC_CIPHERTEXT_BTF_OK
