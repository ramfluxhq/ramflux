#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
#
# Cross-compile crates/ramflux-ffi for Android with cargo-ndk and lay the libraries out as
# jniLibs/<abi>/libramflux_ffi.so.
#
#   build-native.sh <out-dir> [abi,abi,...] [release|dev]
#
# Needs: the Rust toolchain of rust-toolchain.toml with the Android targets installed,
# cargo-ndk, and an Android NDK r28 or newer (ANDROID_NDK_HOME, or the default Android
# Studio location that cargo-ndk detects). A missing target or NDK fails the build; it is
# never skipped.
#
# Environment:
#   RAMFLUX_ANDROID_API     minimum API level to link against (default 28, the module minSdk)
#   RAMFLUX_FFI_FEATURES    cargo features of ramflux-ffi (default "embedded")
#   RAMFLUX_MAX_SO_BYTES    size budget per library (default 20 MiB, the design budget)
set -euo pipefail

out_dir="${1:?usage: build-native.sh <out-dir> [abis] [release|dev]}"
abis="${2:-arm64-v8a,armeabi-v7a,x86_64}"
profile="${3:-release}"
api="${RAMFLUX_ANDROID_API:-28}"
features="${RAMFLUX_FFI_FEATURES:-embedded}"
max_bytes="${RAMFLUX_MAX_SO_BYTES:-20971520}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace="$(cd "$script_dir/../../.." && pwd)"

command -v cargo-ndk >/dev/null 2>&1 || {
  echo "build-native: cargo-ndk is not installed (cargo install cargo-ndk --locked)" >&2
  exit 1
}

triple_of() {
  case "$1" in
    arm64-v8a) echo aarch64-linux-android ;;
    armeabi-v7a) echo armv7-linux-androideabi ;;
    x86_64) echo x86_64-linux-android ;;
    *) echo "build-native: unsupported ABI '$1'" >&2; return 1 ;;
  esac
}

installed_targets="$(cd "$workspace" && rustup target list --installed)"
target_args=()
IFS=',' read -r -a abi_list <<<"$abis"
for abi in "${abi_list[@]}"; do
  triple="$(triple_of "$abi")"
  if ! grep -qx "$triple" <<<"$installed_targets"; then
    echo "build-native: Rust target $triple is not installed (rustup target add $triple)" >&2
    exit 1
  fi
  target_args+=(-t "$abi")
done

profile_args=()
case "$profile" in
  release) profile_args+=(--release) ;;
  dev) ;;
  *) echo "build-native: profile must be release or dev" >&2; exit 1 ;;
esac

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

# CARGO_NDK_PLATFORM is cargo-ndk's documented way to set the API level.
(
  cd "$workspace"
  CARGO_NDK_PLATFORM="$api" cargo ndk "${target_args[@]}" -o "$out_dir" \
    build -p ramflux-ffi --lib --features "$features" --locked "${profile_args[@]}"
)

# Post-conditions: one library per requested ABI, inside the size budget, and with every
# LOAD segment aligned to 16 KB on the 64-bit ABIs (required by Google Play for apps that
# target API 35 or higher; NDK r28 and newer do this by default).
objdump=""
if [ -n "${ANDROID_NDK_HOME:-}" ]; then
  objdump="$(find "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" -name llvm-objdump -type f 2>/dev/null | head -n 1)"
fi
status=0
for abi in "${abi_list[@]}"; do
  lib="$out_dir/$abi/libramflux_ffi.so"
  if [ ! -f "$lib" ]; then
    echo "build-native: $lib was not produced" >&2
    status=1
    continue
  fi
  bytes="$(wc -c <"$lib" | tr -d ' ')"
  if [ "$bytes" -gt "$max_bytes" ]; then
    echo "build-native: $lib is $bytes bytes, over the $max_bytes byte budget" >&2
    status=1
  fi
  case "$abi" in
    arm64-v8a | x86_64)
      if [ -n "$objdump" ]; then
        if "$objdump" -p "$lib" | awk '$1 == "LOAD" { print $NF }' | grep -qvE '^2\*\*(1[4-9]|[2-9][0-9])$'; then
          echo "build-native: $lib has a LOAD segment aligned below 16 KB" >&2
          status=1
        fi
      else
        echo "build-native: llvm-objdump not found; 16 KB alignment of $lib was NOT checked" >&2
      fi
      ;;
  esac
  echo "build-native: $abi $bytes bytes"
done
exit "$status"
