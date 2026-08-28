#!/usr/bin/env bash
# One-line bootstrap for Attaché.
#
#   curl -fsSL https://raw.githubusercontent.com/giobinda/attache/main/bootstrap.sh | bash
#
# Default (ATTACHE_BUILD=prebuilt): downloads the static musl binaries from a
# GitHub release, verifies them against the release's SHA256SUMS, and installs
# them into ~/.local/bin. No toolchain needed.
#
# ATTACHE_BUILD=source: clones the repo to ~/.local/share/attache/src and runs
# install.sh from it (needs the Rust musl toolchain plus the deps install.sh
# checks for).
#
# Either way this does nothing privileged: the one `sudo` command is printed at
# the end for you to run yourself, never invoked here.
#
# Environment overrides:
#   ATTACHE_BUILD      prebuilt | source            (default: prebuilt)
#   ATTACHE_REF        release tag or 'latest';      (default: latest)
#                      a branch/tag in source mode   (default there: main)
#   ATTACHE_REPO_SLUG  owner/repo                    (default: giobinda/attache)
#   ATTACHE_BIN_DIR    where binaries go             (default: ~/.local/bin)
#   ATTACHE_SRC        source-mode checkout dir      (default: ~/.local/share/attache/src)
set -euo pipefail

BUILD="${ATTACHE_BUILD:-prebuilt}"
SLUG="${ATTACHE_REPO_SLUG:-giobinda/attache}"
BIN_DIR="${ATTACHE_BIN_DIR:-$HOME/.local/bin}"
SHARE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/attache"
BINS=(attache-gate attache-mount-helper attache-import)

die()  { echo "bootstrap: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

path_hint() {
    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *) printf '\n  %s is not on your PATH - add this to your shell profile:\n    export PATH="%s:$PATH"\n' "$BIN_DIR" "$BIN_DIR" ;;
    esac
}

final_steps() {
    local helper="$1"
    cat <<EOF

bootstrap: installed to $BIN_DIR
$(path_hint)
One privileged step is left - it grants attache-mount-helper the single
capability it needs, and must be re-run after every update (the kernel drops
the capability whenever the file's contents change):

    sudo $helper

Then create or restore a vault and open it:

    att init          # new vault   (or:  attache-import <disc>   to restore one)
    att open
EOF
}

install_prebuilt() {
    have curl      || die "need 'curl' on PATH (or use ATTACHE_BUILD=source)"
    have sha256sum || die "need 'sha256sum' on PATH"

    local ref="${ATTACHE_REF:-latest}" tag
    if [[ "$ref" == "latest" ]]; then
        tag="$(curl -fsSL "https://api.github.com/repos/$SLUG/releases/latest" \
                 | grep -m1 '"tag_name"' | cut -d'"' -f4)"
        [[ -n "$tag" ]] || die "could not resolve the latest release of $SLUG (try ATTACHE_REF=v0.1.0)"
    else
        tag="$ref"
    fi

    local base="https://github.com/$SLUG/releases/download/$tag"
    local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

    echo "bootstrap: downloading $tag from $SLUG (prebuilt static musl)..."
    local f
    for f in "${BINS[@]}" att install-mount-helper.sh SHA256SUMS; do
        curl -fsSL "$base/$f" -o "$tmp/$f" \
            || die "could not download $f from release $tag - does that release exist? (try ATTACHE_BUILD=source)"
    done

    echo "bootstrap: verifying checksums..."
    ( cd "$tmp" && sha256sum -c SHA256SUMS ) || die "checksum verification FAILED - aborting"

    mkdir -p "$BIN_DIR" "$SHARE_DIR"
    for f in "${BINS[@]}" att; do install -m 755 "$tmp/$f" "$BIN_DIR/$f"; done
    install -m 755 "$tmp/install-mount-helper.sh" "$SHARE_DIR/install-mount-helper.sh"

    final_steps "$SHARE_DIR/install-mount-helper.sh"
}

install_from_source() {
    have git || die "need 'git' on PATH to build from source"
    local repo="https://github.com/$SLUG.git"
    local ref="${ATTACHE_REF:-main}"
    local src="${ATTACHE_SRC:-$SHARE_DIR/src}"

    if [[ -d "$src/.git" ]]; then
        echo "bootstrap: updating $src"
        git -C "$src" fetch --depth 1 origin "$ref"
        git -C "$src" reset --hard FETCH_HEAD
    else
        echo "bootstrap: cloning $repo -> $src"
        mkdir -p "$(dirname "$src")"
        git clone --depth 1 --branch "$ref" "$repo" "$src"
    fi

    echo "bootstrap: running install.sh"
    echo
    exec bash "$src/install.sh"
}

case "$BUILD" in
    prebuilt) install_prebuilt ;;
    source)   install_from_source ;;
    *)        die "ATTACHE_BUILD must be 'prebuilt' or 'source', got '$BUILD'" ;;
esac
