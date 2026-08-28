#!/usr/bin/env bash
# Builds Attaché from source (attache-gate, attache-mount-helper,
# attache-import) and installs them plus the repo root's `att` script into
# ~/.local/bin. Safe to re-run - e.g. after pulling new source, just rebuilds
# and reinstalls everything in place.
#
# Doesn't touch anything privileged itself: installing a freshly built
# attache-mount-helper always strips any existing cap_sys_admin (the kernel
# does this on any write to the file, by design), so the one privileged step
# (install-mount-helper.sh) always needs a run after this, printed at the
# end for you to run yourself - same as every other privileged step in this
# project, never run automatically.
set -euo pipefail

# This script lives at the repo root, so SELF_DIR is REPO_ROOT.
SELF_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_ROOT="$SELF_DIR"
TARGET_TRIPLE="x86_64-unknown-linux-musl"
BIN_DIR="$HOME/.local/bin"

missing=()
check() {
    command -v "$1" >/dev/null 2>&1 || missing+=("$1${2:+ - $2}")
}

echo "install: checking required tools..."
check cargo "Rust toolchain, https://rustup.rs"
check gocryptfs "distro package, e.g. 'dnf install gocryptfs' / 'apt install gocryptfs'"
check fusermount3 "fuse3 package"
check socat "control socket client for att allow/denied/reset-whitelist"
check zenity "GUI access-approval dialogs"
check gdbus "glib2, used for suspend/logout detection via logind"
check lsof "activity detection for the idle-timeout"
check setcap "libcap, needed once for install-mount-helper.sh below"
[[ -e /dev/fuse ]] || missing+=("/dev/fuse - fuse-common package plus a kernel with FUSE support")

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "install: missing required tools:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    echo "install: install these first, then re-run." >&2
    exit 1
fi

optional_missing=()
check_optional() {
    command -v "$1" >/dev/null 2>&1 || optional_missing+=("$1${2:+ - $2}")
}
check_optional xorriso "needed only for 'att export'"
check_optional growisofs "needed only to burn 'att export's ISO to disc"
if [[ ${#optional_missing[@]} -gt 0 ]]; then
    echo "install: missing optional tools (only affects 'att export'):"
    printf '  - %s\n' "${optional_missing[@]}"
fi

if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET_TRIPLE"; then
    if command -v rustup >/dev/null 2>&1; then
        echo "install: adding rustup target $TARGET_TRIPLE..."
        rustup target add "$TARGET_TRIPLE"
    else
        echo "install: no rustup, and no $TARGET_TRIPLE target found for cargo." >&2
        echo "         install a musl-capable Rust toolchain for your distro and re-run." >&2
        exit 1
    fi
fi

echo "install: building attache-gate + attache-mount-helper + attache-import..."
(cd "$REPO_ROOT" && cargo build --release --target "$TARGET_TRIPLE")

REL_DIR="$REPO_ROOT/target/$TARGET_TRIPLE/release"
mkdir -p "$BIN_DIR"
install -m 755 "$REL_DIR/attache-gate" "$BIN_DIR/attache-gate"
install -m 755 "$REL_DIR/attache-mount-helper" "$BIN_DIR/attache-mount-helper"
install -m 755 "$REL_DIR/attache-import" "$BIN_DIR/attache-import"
install -m 755 "$SELF_DIR/att" "$BIN_DIR/att"

echo "install: installed to $BIN_DIR:"
ls -la "$BIN_DIR/att" "$BIN_DIR/attache-gate" "$BIN_DIR/attache-mount-helper" "$BIN_DIR/attache-import"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        echo
        echo "install: $BIN_DIR is not on your PATH - add this to your shell profile:"
        echo "    export PATH=\"$BIN_DIR:\$PATH\""
        ;;
esac

echo
echo "install: one privileged step is left - installing a fresh binary always"
echo "         strips any capability it had, so this always needs (re-)running:"
echo "    sudo $SELF_DIR/install-mount-helper.sh"
echo
echo "Then: 'att init' to create a new vault (or attache-import to restore one"
echo "from an exported disc), then 'att open'."
