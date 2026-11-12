#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-sdk/src/client/own_contact.rs
named=generated_own_contact_import_and_tombstone_use_native_sticky_rules
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]); s = p.read_text()
start = s.index('fn validate_own_contact(')
end = s.index('fn apply_own_contact(', start)
part = s[start:end]
old = 'existing.requester_id != link.requester_id || existing.target_id != link.target_id'
assert part.count(old) == 1
part = part.replace(old, old.replace(' || ', ' && '))
p.write_text(s[:start] + part + s[end:])
PY
if timeout 300 cargo test -p ramflux-sdk --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'own-contact root-binding mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo OWN_CONTACT_ROOT_BINDING_BTF_OK
