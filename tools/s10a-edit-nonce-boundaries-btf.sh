#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
mode=${1:?public or stale}
case "$mode" in
 public) source_file=crates/ramflux-protocol/src/message/private_revision.rs; crate=ramflux-sdk; named=public_bindings_strip_private_revision_nonce_and_refuse_selected_input ;;
 stale) source_file=crates/ramflux-storage/src/account_db/message_edit_retirement.rs; crate=ramflux-storage; named=edit_delete_retire_private_revision_nonce_copies_and_rollback ;;
 *) exit 2 ;;
esac
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" "$mode" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]); s = p.read_text()
if sys.argv[2] == "public":
    start = s.index("pub fn redact_content(")
    end = s.index("/// Public send/edit/draft", start)
    s = s[:start] + "pub fn redact_content(content: &mut Content) { let _ = content; }\n\n" + s[end:]
else:
    old = 'for (kind, locator) in copies { retire_copy(db, &kind, &locator, &keep)?; }'
    assert s.count(old) == 1
    s = s.replace(old, 'for (kind, locator) in copies { if locator == "history/page/nonce" { continue; } retire_copy(db, &kind, &locator, &keep)?; }')
p.write_text(s)
PY
if timeout 300 cargo test -p "$crate" --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo "nonce $mode mutant survived" >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach the named assertion' >&2
    exit 1
fi
echo "EDIT_NONCE_${mode^^}_BTF_OK"
