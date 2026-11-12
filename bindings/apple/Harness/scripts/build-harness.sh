#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
#
# Build the M3 acceptance harness as an iOS-simulator app bundle.
#
# The harness is compiled as ONE Swift module from the generated bindings, the hand-written
# helpers of the Swift package and the driver sources, and linked against the simulator slice
# of the static library. It is a test driver, not a product target, and is never shipped.
#
#   bindings/apple/Harness/scripts/build-harness.sh
#
# Requires: macOS, Xcode with an iOS simulator SDK, and a previous run of
# bindings/apple/scripts/build-xcframework.sh (it produces the library, the header, the
# module map and the generated Swift).
set -euo pipefail

harness_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
apple_dir="$(cd "$harness_dir/.." && pwd)"
repo_root="$(cd "$apple_dir/../.." && pwd)"
build_dir="$apple_dir/build"
out_dir="$build_dir/harness"
app="$out_dir/RamfluxHarness.app"
profile="${RAMFLUX_HARNESS_PROFILE:-release}"
deployment="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"
simulator_lib_dir="$repo_root/target/aarch64-apple-ios-sim/$profile"

[[ "$(uname -s)" == "Darwin" ]] || { echo "needs macOS with Xcode" >&2; exit 1; }
[[ -f "$simulator_lib_dir/libramflux_ffi.a" ]] \
  || { echo "run bindings/apple/scripts/build-xcframework.sh first" >&2; exit 1; }
[[ -f "$apple_dir/Sources/Ramflux/Generated/ramflux_ffi.swift" ]] \
  || { echo "generated Swift is missing; run build-xcframework.sh" >&2; exit 1; }

sdk="$(xcrun --sdk iphonesimulator --show-sdk-path)"
rm -rf "$out_dir"
mkdir -p "$app"

sources=()
while IFS= read -r file; do
  sources+=("$file")
done < <(find "$apple_dir/Sources/Ramflux" "$harness_dir/Sources" -name '*.swift' | sort)

echo "== compiling ${#sources[@]} Swift files for the simulator"
xcrun --sdk iphonesimulator swiftc \
  -target "arm64-apple-ios${deployment}-simulator" \
  -sdk "$sdk" \
  -swift-version 5 \
  -O \
  -module-name RamfluxHarness \
  -parse-as-library \
  -I "$build_dir/headers/ramflux_ffiFFI" \
  -L "$simulator_lib_dir" \
  -lramflux_ffi \
  -framework Security -framework CoreFoundation -framework Network -framework UIKit \
  -o "$app/RamfluxHarness" \
  "${sources[@]}"

cp "$harness_dir/Info.plist" "$app/Info.plist"

# Ad-hoc signature with the keychain entitlements. Simulator only: nothing here is a
# distribution identity, and no debug entitlement of the harness reaches a product build.
codesign --force --sign - --entitlements "$harness_dir/Harness.entitlements" \
  --timestamp=none "$app"

echo "done: $app"
