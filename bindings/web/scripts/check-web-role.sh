#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
#
# Link-time proof that the browser module is a linked secondary device only.
# Fails when the linked module or its generated declarations expose anything that accepts,
# derives or stores a primary seed or a recovery secret, or that creates, recovers, migrates or
# approves.
#   sh scripts/check-web-role.sh <module.wasm> <module.d.ts>
set -eu

wasm=${1:?path to the linked .wasm}
dts=${2:?path to the generated .d.ts}
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)

forbidden='primary_seed|primaryseed|recovery_secret|recoverysecret|mnemonic|account_create|accountcreate|create_account|recovery_initiate|recover_account|home_migration|device_approve|approve_device|pair_approve|guardian|export_agent_credentials|passphrase_rotate'

fail=0

# 1. The public surface: generated declarations name every export.
if grep -Eiq "$forbidden" "$dts"; then
    echo "check-web-role: forbidden name in the generated declarations:" >&2
    grep -Ein "$forbidden" "$dts" >&2
    fail=1
fi

# 2. The export section of the linked module.
if command -v wasm-tools >/dev/null 2>&1; then
    exports=$(wasm-tools print "$wasm" | grep -E '^\s*\(export ' || true)
elif command -v wasm-objdump >/dev/null 2>&1; then
    exports=$(wasm-objdump -x -j Export "$wasm")
else
    echo "check-web-role: need wasm-tools or wasm-objdump to read the export section" >&2
    exit 2
fi
if printf '%s\n' "$exports" | grep -Eiq "$forbidden"; then
    echo "check-web-role: forbidden export in the linked module:" >&2
    printf '%s\n' "$exports" | grep -Ei "$forbidden" >&2
    fail=1
fi

# 2b. Function names kept in the module (when the name section is present): no linked function
#     may come from the account ceremonies either.
if command -v wasm-tools >/dev/null 2>&1; then
    if wasm-tools print "$wasm" | grep -E '^\s*\(func \$' | grep -Eiq "$forbidden"; then
        echo "check-web-role: forbidden function linked into the module:" >&2
        wasm-tools print "$wasm" | grep -E '^\s*\(func \$' | grep -Ei "$forbidden" | head -20 >&2
        fail=1
    fi
fi

# 3. The dependency graph: the daemon SDK, which holds the account ceremonies, and the marker
#    features must be absent from the browser build.
tree=$(cd "$root" && cargo tree --locked -p ramflux-web --target wasm32-unknown-unknown -e normal,features --prefix none)
if printf '%s\n' "$tree" | grep -Eq '^ramflux-sdk |^ramflux-node-core |primary-authority|account-recovery|itest-legacy-accounts|itest-memory-vault'; then
    echo "check-web-role: the browser build links primary-authority code:" >&2
    printf '%s\n' "$tree" | grep -E '^ramflux-sdk |^ramflux-node-core |primary-authority|account-recovery|itest-legacy-accounts|itest-memory-vault' >&2
    fail=1
fi

# 4. The marker features really are a compile error on the wasm target.
for feature in primary-authority account-recovery; do
    if (cd "$root" && cargo check --locked -q -p ramflux-web --target wasm32-unknown-unknown --features "$feature") >/dev/null 2>&1; then
        echo "check-web-role: feature $feature compiled for wasm32; it must be a compile error" >&2
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "check-web-role: ok"
