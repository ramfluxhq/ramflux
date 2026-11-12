#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-storage/src/account_db/backup_original_header.rs
named=restore_header_agreement_verifies_origins_and_fences_conflicting_dependents
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
old = 'ours != theirs'
pattern = r'\s*'.join(re.escape(c) for c in old if not c.isspace())
matches = list(re.finditer(pattern, s))
assert len(matches) == 1, len(matches)
match = matches[0]
new = '(ours != theirs && false)'
p.write_text(s[:match.start()] + new + s[match.end():])
PY
if timeout 300 cargo test -p ramflux-sdk --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 's10a-restore-header-agreement-btf.sh mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo RESTORE_HEADER_AGREEMENT_BTF_OK
