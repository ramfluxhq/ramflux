# Linux CLI and TUI installation

`rf` includes the daemon (`rf daemon`); there is no separate `rfd` executable.
Linux release bundles contain `rf`, `rf-tui`, both license texts, and build
metadata. Both programs have the same product version. They are built natively
on Ubuntu 24.04 for x86_64 and aarch64, using GNU libc, not fully static musl.
SQLite/SQLCipher, OpenSSL and D-Bus client libraries use the SDK's vendored
builds where configured. `BUILD-INFO.txt` records the actual runtime libraries.

## Release archive

Choose an existing release that has Linux CLI assets. For example, after
that version's release workflow has completed:

```sh
version=0.2.5  # replace with the release you selected
case "$(uname -m)" in
  x86_64) target=x86_64-unknown-linux-gnu ;;
  aarch64) target=aarch64-unknown-linux-gnu ;;
  *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
archive="ramflux-cli-v${version}-${target}.tar.gz"
base="https://github.com/ramfluxhq/ramflux/releases/download/v${version}"
curl -fLO "$base/$archive"
curl -fLO "$base/$archive.sha256"
sha256sum --check "$archive.sha256"
tar -xzf "$archive"
mkdir -p "$HOME/.local/bin"
install -m755 "${archive%.tar.gz}/bin/"* "$HOME/.local/bin/"
rf --version
rf-tui --version
```

Keep `~/.local/bin` on your `PATH`. Checksums detect corruption; they are not
an independent signature or proof of publisher identity.

## Arch Linux / Omarchy

The in-tree `packaging/arch/ramflux-cli/PKGBUILD` builds both binaries from
matching version tags with pinned source checksums. It is not an AUR upload.
Review the recipe and `.SRCINFO` before installing; run `makepkg` as your
ordinary user:

```sh
sudo pacman -S --needed base-devel rust git pkgconf perl
git clone https://github.com/ramfluxhq/ramflux.git
cd ramflux/packaging/arch/ramflux-cli
makepkg --verifysource
makepkg -si
```

The recipe's `pkgver` selects the version, independently of the clone's branch.
Maintainers update both source hashes and the two commit IDs, then regenerate `.SRCINFO` with
`makepkg --printsrcinfo > .SRCINFO` when changing `pkgver`. Rust must satisfy
that tag's pinned toolchain. aarch64 packages require Arch Linux ARM; official
Arch Linux / Omarchy targets x86_64. No service is enabled during installation.

For account custody, run inside your normal logged-in desktop session with a
user D-Bus session and an unlocked default Secret Service collection. On
Omarchy, gnome-keyring is normally supplied by the desktop; otherwise install
and configure a provider such as `gnome-keyring` (or KWallet's Secret Service).
`libsecret` supplies diagnostic client tools, not the keyring service itself.
Without a provider custody operations refuse; there is no device-secret file
fallback. `rf vault init` is a separate operator vault setup, not a prerequisite
for ordinary account creation in the default collection.

## Paths and connection

With the Linux-host support included in the selected release, `rf` uses
`$XDG_RUNTIME_DIR/ramflux/rfd.sock`, data under `$XDG_DATA_HOME/ramflux`
(`~/.local/share/ramflux` by default), and logs/state under
`$XDG_STATE_HOME/ramflux` (`~/.local/state/ramflux` by default).
`XDG_RUNTIME_DIR` must be an absolute, private directory owned by your user;
do not run the daemon as root. The package installs no state under `/tmp`.
For TUI tags that still have an older socket default, pass the socket explicitly:

```sh
rf daemon
# In another terminal in the same desktop session:
rf-tui --socket "$XDG_RUNTIME_DIR/ramflux/rfd.sock" --account YOUR_ACCOUNT_ID
```

## Release maintainers

Create matching `vX.Y.Z` tags in `ramflux` and `ramflux-tui` after aligning
their versions and checking the TUI's SDK pin. The **Linux CLI release**
workflow builds each architecture natively and attaches both archives and
checksums to the product GitHub release only after both builds succeed.
Manual dispatch requires an existing matching tag; `publish=false` (default)
keeps downloadable workflow artifacts without changing the release.
Pull requests touching the workflow, release script or package also build both
architectures without publishing. This workflow does not deploy any service.
