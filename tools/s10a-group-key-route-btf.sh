#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-sdk/src/client/routed/native_control/group_key.rs
named=generated_group_key_off_its_group_route_is_refused_without_retention
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]); s = p.read_text()
old = '        if opened.routing.kind != Kind::GroupControl\n            || opened.routing.group_id.as_deref() != Some(value.group_id.as_str())\n        {\n            return Err(authority("group key route differs from its group"));\n        }'
assert s.count(old) == 1
p.write_text(s.replace(old, '        let _ = Kind::GroupControl;'))
PY
if timeout 300 cargo test -p ramflux-sdk --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'group_key_route mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo GROUP_KEY_ROUTE_BTF_OK
