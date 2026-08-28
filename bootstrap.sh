#!/usr/bin/env bash
# One-line bootstrap for Attaché. Fetches the source, then hands off to
# install.sh:
#
#   curl -fsSL https://raw.githubusercontent.com/giobinda/attache/main/bootstrap.sh | bash
#
# Clones (or updates) the source under ~/.local/share/attache/src and runs
# install.sh from it. Keeps the checkout around because the one privileged
# step - install-mount-helper.sh - has to be re-run from it after every
# rebuild.
#
# Like install.sh, this does nothing privileged itself: the single sudo
# command is printed at the end for you to run yourself, never invoked here.
#
# Overridable via environment:
#   ATTACHE_REPO   git URL to clone            (default: this repo on github)
#   ATTACHE_REF    branch or tag to check out  (default: main)
#   ATTACHE_SRC    where to put the checkout   (default: ~/.local/share/attache/src)
set -euo pipefail

REPO="${ATTACHE_REPO:-https://github.com/giobinda/attache.git}"
REF="${ATTACHE_REF:-main}"
SRC_DIR="${ATTACHE_SRC:-${XDG_DATA_HOME:-$HOME/.local/share}/attache/src}"

if ! command -v git >/dev/null 2>&1; then
    echo "bootstrap: 'git' is required to fetch the source - install it and re-run." >&2
    exit 1
fi

if [[ -d "$SRC_DIR/.git" ]]; then
    echo "bootstrap: updating existing checkout at $SRC_DIR"
    git -C "$SRC_DIR" fetch --depth 1 origin "$REF"
    git -C "$SRC_DIR" reset --hard FETCH_HEAD
else
    echo "bootstrap: cloning $REPO -> $SRC_DIR"
    mkdir -p "$(dirname "$SRC_DIR")"
    git clone --depth 1 --branch "$REF" "$REPO" "$SRC_DIR"
fi

echo "bootstrap: running install.sh"
echo
exec bash "$SRC_DIR/install.sh"
