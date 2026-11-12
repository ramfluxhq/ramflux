#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
#
# Build ramflux_ffi.xcframework (iOS device + iOS simulator slices) and generate the Swift
# bindings the Swift package compiles.
#
# Runs on macOS with Xcode and the pinned Rust toolchain. It is not part of any default
# build and nothing calls it from the workspace.
#
#   bindings/apple/scripts/build-xcframework.sh [--debug] [--no-embedded]
#
# Outputs (all under bindings/apple/):
#   build/ramflux_ffi.xcframework          static library slices + C header + module map
#   Sources/Ramflux/Generated/ramflux_ffi.swift   generated Swift API
set -euo pipefail

profile="release"
features="embedded"
for arg in "$@"; do
  case "$arg" in
    --debug) profile="debug" ;;
    --no-embedded) features="" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

apple_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$apple_dir/../.." && pwd)"
build_dir="$apple_dir/build"
generated_dir="$apple_dir/Sources/Ramflux/Generated"
lib_name="libramflux_ffi.a"
ffi_module="ramflux_ffiFFI"
xcframework="$build_dir/ramflux_ffi.xcframework"

# The design fixes the slices: arm64 device and arm64 simulator. No Intel simulator slice.
device_target="aarch64-apple-ios"
simulator_target="aarch64-apple-ios-sim"

# Lowest iOS the static library is compiled for. Keep in step with Package.swift.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "build-xcframework.sh needs macOS with Xcode (xcodebuild, the iOS SDKs)" >&2
  exit 1
fi
command -v xcodebuild >/dev/null || { echo "xcodebuild not found" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 1; }

cd "$repo_root"

# A missing target fails the build; it is never skipped.
for target in "$device_target" "$simulator_target"; do
  if ! rustup target list --installed | grep -qx "$target"; then
    echo "Rust target $target is not installed: rustup target add $target" >&2
    exit 1
  fi
done

cargo_profile_args=()
if [[ "$profile" == "release" ]]; then
  cargo_profile_args+=(--release)
fi
feature_args=()
if [[ -n "$features" ]]; then
  feature_args+=(--features "$features")
fi

echo "== building static libraries ($profile, features: ${features:-none})"
for target in "$device_target" "$simulator_target"; do
  cargo build --locked -p ramflux-ffi --lib --target "$target" \
    ${cargo_profile_args[@]+"${cargo_profile_args[@]}"} ${feature_args[@]+"${feature_args[@]}"}
done

device_lib="$repo_root/target/$device_target/$profile/$lib_name"
simulator_lib="$repo_root/target/$simulator_target/$profile/$lib_name"
for lib in "$device_lib" "$simulator_lib"; do
  [[ -f "$lib" ]] || { echo "missing $lib" >&2; exit 1; }
done

echo "== generating Swift bindings (library mode, generator pinned to the scaffolding)"
rm -rf "$build_dir/headers" "$build_dir/swift" "$xcframework"
# The module map sits in a directory named after the module, so that two XCFrameworks that
# both ship a module.modulemap do not collide in the consumer's header search path.
headers_dir="$build_dir/headers/$ffi_module"
mkdir -p "$headers_dir" "$build_dir/swift" "$generated_dir"

bindgen=(cargo run --locked --quiet -p ramflux-ffi --features bindgen-cli
  --bin uniffi-bindgen-swift --)
"${bindgen[@]}" "$simulator_lib" "$build_dir/swift" --swift-sources
"${bindgen[@]}" "$simulator_lib" "$headers_dir" --headers
"${bindgen[@]}" "$simulator_lib" "$headers_dir" --xcframework --modulemap \
  --modulemap-filename module.modulemap

[[ -f "$build_dir/swift/ramflux_ffi.swift" ]] || { echo "no generated Swift" >&2; exit 1; }
[[ -f "$headers_dir/${ffi_module}.h" ]] || { echo "no generated header" >&2; exit 1; }
[[ -f "$headers_dir/module.modulemap" ]] || { echo "no generated module map" >&2; exit 1; }
cp "$build_dir/swift/ramflux_ffi.swift" "$generated_dir/ramflux_ffi.swift"

# Stamp the binding API version and descriptor fingerprint the Swift sources are generated
# from. The host sends them in the handshake; the core refuses an incompatible pair.
cargo run --locked --quiet -p ramflux-ffi --features bindgen-cli --bin ramflux-ffi-stamp -- swift \
  > "$generated_dir/HostBindingStamp.swift"

echo "== assembling $xcframework"
xcodebuild -create-xcframework \
  -library "$device_lib" -headers "$build_dir/headers" \
  -library "$simulator_lib" -headers "$build_dir/headers" \
  -output "$xcframework"

# A shipped library must not carry the test-only vault or legacy-account code paths.
if nm -gU "$device_lib" 2>/dev/null | grep -Eq 'itest_memory_vault|itest_legacy'; then
  echo "test-only symbols found in the device library" >&2
  exit 1
fi

echo "== sizes"
du -sh "$device_lib" "$simulator_lib" "$xcframework"
echo "done: $xcframework"
