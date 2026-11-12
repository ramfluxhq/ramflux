#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
#
# Build the browser package from source. Nothing is published.
#   sh scripts/build.sh        wasm + generated TypeScript declarations + role check + worker scripts
#   sh scripts/build.sh wasm   wasm and declarations only
#
# Needs: the wasm32-unknown-unknown target, wasm-bindgen-cli of the same version as the
# wasm-bindgen crate in Cargo.lock, and (for the worker scripts) the TypeScript compiler.
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)
target_dir=${CARGO_TARGET_DIR:-$root/target}
wasm="$target_dir/wasm32-unknown-unknown/release/ramflux_web.wasm"

locked=$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' "$root/Cargo.lock")
have=$(wasm-bindgen --version 2>/dev/null | awk '{ print $2 }' || true)
if [ "$have" != "$locked" ]; then
    echo "build: wasm-bindgen-cli $locked is required (found '${have:-none}')." >&2
    echo "build: cargo install wasm-bindgen-cli --version $locked --locked" >&2
    exit 2
fi

# No default features and no feature flags: a browser build is a linked secondary device.
(cd "$root" && cargo build --locked --release -p ramflux-web --target wasm32-unknown-unknown)

rm -rf "$here/pkg"
# `--target web` emits an ES module and the generated `.d.ts`; there is no hand-written
# declaration file in this package.
wasm-bindgen --target web --typescript --out-dir "$here/pkg" --out-name ramflux_web "$wasm"

sh "$here/scripts/check-web-role.sh" "$here/pkg/ramflux_web_bg.wasm" "$here/pkg/ramflux_web.d.ts"

if [ "${1:-all}" = "wasm" ]; then
    exit 0
fi

if command -v tsc >/dev/null 2>&1; then
    (cd "$here" && tsc -p tsconfig.json)
else
    echo "build: tsc not found; worker scripts were not compiled (npm install, then npm run build:ts)." >&2
    exit 3
fi

# Release identity shown in the client so an operator and a user can compare builds.
(cd "$here" && sha256sum pkg/ramflux_web_bg.wasm dist/*.js 2>/dev/null || shasum -a 256 pkg/ramflux_web_bg.wasm dist/*.js) > "$here/dist/SHA256SUMS"
echo "build: done; hashes in dist/SHA256SUMS"
