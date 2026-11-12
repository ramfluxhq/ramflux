#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-sdk/src/client/routed/native_control/guardian.rs
named=guardian_pending_decisions_bind_source_fingerprint_and_transaction
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
import re
p = Path(sys.argv[1]); s = p.read_text()
old = 'invite_fingerprint(&invite)? != handle.fingerprint'
pattern = r'\s*'.join(re.escape(c) for c in old if not c.isspace())
matches = list(re.finditer(pattern, s))
assert len(matches) == 1, len(matches)
match = matches[0]
new = '(invite_fingerprint(&invite)? != handle.fingerprint && false)'
p.write_text(s[:match.start()] + new + s[match.end():])
PY
if timeout 300 cargo test -p ramflux-sdk --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 's10a-guardian-pending-selection-btf.sh mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo GUARDIAN_PENDING_SELECTION_BTF_OK
