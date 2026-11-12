#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-sdk/src/client/routed/native_control/guardian.rs
named=generated_recovery_accept_is_bound_to_a_locally_issued_invite
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]); s = p.read_text()
old = '.ok_or_else(|| authority("guardian accept has no locally issued invite"))?;'
assert s.count(old) == 1
p.write_text(s.replace(old, '.unwrap_or_else(|| IssuedGuardianInvite { guardian_principal_id: native.guardian_principal_id.clone(), recovery_quorum_id: native.recovery_quorum_id.clone(), expires_at: i64::MAX });'))
PY
if timeout 300 cargo test -p ramflux-sdk --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'recovery_accept_issued mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo RECOVERY_ACCEPT_ISSUED_BTF_OK
