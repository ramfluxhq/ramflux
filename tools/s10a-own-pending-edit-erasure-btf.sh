#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-sdk/src/client/message_mutations.rs
named=own_authored_current_edit_for_later_third_sibling_stays_pending_without_original_metadata
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
old = 'self.retire_pending_generated_edit_for_delete(target)?;'
assert s.count(old) == 1
p.write_text(s.replace(old, 'if false { '+old+' }'))
PYM
if timeout 300 cargo test -p ramflux-sdk --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'pending Edit erasure mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach named assertion' >&2
    exit 1
fi
echo OWN_PENDING_EDIT_ERASURE_BTF_OK
