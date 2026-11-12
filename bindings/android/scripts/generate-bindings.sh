#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
#
# Generate the Kotlin bindings of crates/ramflux-ffi from a built library (UniFFI library
# mode: the interface is read from the metadata inside the library, there is no UDL file).
#
#   generate-bindings.sh <libramflux_ffi.so> <out-dir>
#
# The generator is the `uniffi-bindgen` binary of the same crate, so its version always
# equals the scaffolding version the library was built with.
set -euo pipefail

library="${1:?usage: generate-bindings.sh <libramflux_ffi.so> <out-dir>}"
out_dir="${2:?usage: generate-bindings.sh <libramflux_ffi.so> <out-dir>}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace="$(cd "$script_dir/../../.." && pwd)"
config="$script_dir/../uniffi.toml"

[ -f "$library" ] || { echo "generate-bindings: $library does not exist" >&2; exit 1; }
library="$(cd "$(dirname "$library")" && pwd)/$(basename "$library")"
mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"
# Stale files of a renamed type must not survive a regeneration.
find "$out_dir" -name '*.kt' -type f -delete

(
  cd "$workspace"
  cargo run --locked -p ramflux-ffi --features bindgen-cli --bin uniffi-bindgen -- \
    generate --library "$library" --language kotlin --config "$config" --out-dir "$out_dir"
)

generated="$(find "$out_dir" -name '*.kt' -type f | wc -l | tr -d ' ')"
if [ "$generated" -eq 0 ]; then
  echo "generate-bindings: the generator wrote no Kotlin file" >&2
  exit 1
fi
# The wrapper calls `shutdown()`; a generator that ignored the rename would instead emit a
# second `close()` that collides with AutoCloseable.
if ! grep -rq 'fun `\?shutdown`\?(' "$out_dir"; then
  echo "generate-bindings: RamfluxCore.close was not renamed to shutdown; check uniffi.toml" >&2
  exit 1
fi

# Record what these bindings were generated from. The handshake sends this stamp, so a
# library of another binding API version or descriptor is detected when the core opens.
stamp_dir="$out_dir/org/ramflux/sdk/ffi"
mkdir -p "$stamp_dir"
(
  cd "$workspace"
  cargo run --locked -p ramflux-ffi --features bindgen-cli --bin ramflux-ffi-stamp -- kotlin
) | sed 's/^package .*/package org.ramflux.sdk.ffi/' >"$stamp_dir/HostBindingStamp.kt"
grep -q 'DESCRIPTOR_FINGERPRINT' "$stamp_dir/HostBindingStamp.kt" || {
  echo "generate-bindings: the binding stamp was not generated" >&2
  exit 1
}
echo "generate-bindings: $generated Kotlin file(s) and the binding stamp in $out_dir"
