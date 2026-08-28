#!/usr/bin/env bash
# One-time privileged install step for attache-mount-helper. Must be run
# with sudo. Does exactly three things to the one file at
# ~/.local/bin/attache-mount-helper:
#   - own it root:root, not writable by the invoking user (defense in
#     depth on top of the kernel already stripping file capabilities on
#     any write to the file)
#   - world-executable: safe, since the helper resolves every path from
#     the *caller's own* real uid, so any user who runs it can only ever
#     affect their own home directory
#   - grant it CAP_SYS_ADMIN via a file capability (not setuid-root) -
#     the narrowest privilege that lets it create a real mount namespace
#     and mark specific mountpoints shared/private; see the doc comment
#     at the top of attache-gate/src/bin/attache-mount-helper.rs for why this
#     needs real privilege at all.
#
# Re-run this after every `cargo build`/reinstall of attache-mount-helper -
# replacing the file's contents (even via `install`/`cp`) drops the
# capability, by kernel design, so it never silently survives a binary
# swap.
set -euo pipefail

if [[ -z "${SUDO_USER:-}" ]]; then
    echo "install-mount-helper: run this via sudo (need \$SUDO_USER to find the real home dir)" >&2
    exit 1
fi
REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
HELPER="$REAL_HOME/.local/bin/attache-mount-helper"
if [[ ! -f "$HELPER" ]]; then
    echo "install-mount-helper: $HELPER not found - build/install it first" >&2
    exit 1
fi

chown root:root "$HELPER"
chmod 755 "$HELPER"
setcap cap_sys_admin+ep "$HELPER"

echo "install-mount-helper: done. Verifying:"
getcap "$HELPER"
stat -c '%U:%G %a %n' "$HELPER"
