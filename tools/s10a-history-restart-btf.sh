#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
set -euo pipefail
cd "$(dirname "$0")/.."
source_file=crates/ramflux-sdk/src/client/generated_history/page.rs
named=history_chain_replays_do_not_refresh_and_gaps_forks_interleaving_refuse
snapshot=$(mktemp)
log_file=$(mktemp)
cp "$source_file" "$snapshot"
restore() { cp "$snapshot" "$source_file"; rm -f "$snapshot" "$log_file"; }
trap restore EXIT
python3 - "$source_file" <<'PYM'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text()
old='        self.retired.retain(|row| row.until > now);'
assert s.count(old)==1
p.write_text(s.replace(old, '        if now.saturating_sub(self.accepted_at) >= 60 { *self = Self::default(); }\n'+old))
PYM
if timeout 300 cargo test -p ramflux-sdk --lib "$named" >"$log_file" 2>&1; then
    cat "$log_file"
    echo 'history idle reset mutant survived' >&2
    exit 1
fi
if ! rg -q "$named .*FAILED|$named --- FAILED" "$log_file"; then
    cat "$log_file"
    echo 'mutant did not reach named assertion' >&2
    exit 1
fi
echo HISTORY_IDLE_CONTINUATION_BTF_OK
