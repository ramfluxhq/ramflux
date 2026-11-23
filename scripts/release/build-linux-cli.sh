#!/usr/bin/env bash
# Build the native production CLI bundle. No services are started.
set -euo pipefail
tui="${1:?usage: build-linux-cli.sh TUI_DIR TARGET DIST_DIR}"
target="${2:?missing target}"
dist="${3:?missing dist directory}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
tui="$(cd "$tui" && pwd)"
cd "$root"
case "$(uname -s):$(uname -m):$target" in
  Linux:x86_64:x86_64-unknown-linux-gnu|Linux:aarch64:aarch64-unknown-linux-gnu) ;;
  *) echo 'The Linux CLI bundle requires a matching native Linux host.' >&2; exit 1 ;;
esac
version="$(python3 - "$tui" <<'PY'
import pathlib, sys, tomllib
product = tomllib.loads(pathlib.Path('Cargo.toml').read_text())['workspace']['package']['version']
tui = tomllib.loads((pathlib.Path(sys.argv[1]) / 'Cargo.toml').read_text())['package']['version']
if product != tui:
    sys.exit(f'Version mismatch: rf={product}, rf-tui={tui}')
print(product)
PY
)"
product_sha="${RAMFLUX_GIT_SHA:-$(git rev-parse HEAD)}"
tui_sha="${RAMFLUX_TUI_SHA:-$(git -C "$tui" rev-parse HEAD)}"
export RAMFLUX_PRODUCTION_BUILD=1
unset RAMFLUX_ITEST_BUILD
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
mkdir -p "$CARGO_TARGET_DIR" "$dist"
CARGO_TARGET_DIR="$(cd "$CARGO_TARGET_DIR" && pwd)"
dist="$(cd "$dist" && pwd)"
RAMFLUX_GIT_SHA="$product_sha" cargo build --locked --release --target "$target" -p ramflux-rf --bin rf
rf="$CARGO_TARGET_DIR/$target/release/rf"
env -u RAMFLUX_GIT_SHA GIT_CEILING_DIRECTORIES="$root" cargo build --locked --release --target "$target" --manifest-path "$tui/Cargo.toml" --bin rf-tui
rf_tui="$CARGO_TARGET_DIR/$target/release/rf-tui"
"$rf" --version
"$rf_tui" --version
bundle="ramflux-cli-v$version-$target"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$bundle/bin" "$stage/$bundle/licenses/ramflux" "$stage/$bundle/licenses/ramflux-tui"
install -m755 "$rf" "$stage/$bundle/bin/rf"
install -m755 "$rf_tui" "$stage/$bundle/bin/rf-tui"
install -m644 LICENSE NOTICE "$stage/$bundle/licenses/ramflux/"
install -m644 "$tui/LICENSE" "$stage/$bundle/licenses/ramflux-tui/"
install -m644 docs/install-linux-cli.md "$stage/$bundle/README.md"
{
  printf 'version=%s\ntarget=%s\nramflux=%s\nramflux-tui=%s\n' "$version" "$target" "$product_sha" "$tui_sha"
  python3 - "$tui/Cargo.toml" <<'PY'
import pathlib, sys, tomllib
print('ramflux-tui-sdk=' + tomllib.loads(pathlib.Path(sys.argv[1]).read_text())['dependencies']['ramflux-sdk']['rev'])
PY
  printf '\nRuntime libraries (GNU/Linux; system glibc is required):\n'
  ldd "$rf"
  ldd "$rf_tui"
} > "$stage/$bundle/BUILD-INFO.txt"
tar -C "$stage" -czf "$dist/$bundle.tar.gz" "$bundle"
(cd "$dist" && sha256sum "$bundle.tar.gz" > "$bundle.tar.gz.sha256")
(cd "$dist" && sha256sum --check "$bundle.tar.gz.sha256")
printf 'Packaged %s\n' "$dist/$bundle.tar.gz"
