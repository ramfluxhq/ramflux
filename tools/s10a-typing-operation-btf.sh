#!/usr/bin/env bash
set -euo pipefail
: "${RF_LANE_BASE:?run through qa-cargo}"
source_file=crates/ramflux-sdk/src/bus/generated_typing.rs
saved=$(mktemp)
log=$(mktemp)
cp "$source_file" "$saved"
restore() { cp "$saved" "$source_file"; rm -f "$saved" "$log"; }
trap restore EXIT
python3 - "$source_file" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();needle='let update = account.client.send_generated_typing_request(engine, &request).await?;'
assert s.count(needle)==1;p.write_text(s.replace(needle,'let _ = account.client.account_db()?.reserve_operation("typing-btf", "typing-btf", "message.submit")?;\n    '+needle))
PY
rc=0
timeout 300 cargo test -p ramflux-sdk --lib typing_generated_send_bypasses_durable_operation_capture -- --nocapture >"$log" 2>&1 || rc=$?
if [ "$rc" != 101 ] || ! rg -q 'test .*typing_generated_send_bypasses_durable_operation_capture .*FAILED' "$log" \
    || ! rg -q 'Typing touched persistent artifacts' "$log" || ! rg -q 'runtime_operation' "$log"; then
    cat "$log"; echo 'Typing operation BtF did not reach assertion' >&2; exit 1
fi
printf 'TYPING_OPERATION_CAPTURE_BTF_OK\n'
