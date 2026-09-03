# Changelog

All notable changes are recorded here. Every bug fix ships as a new release.

## v0.1.5

### Fixed
- **The vault auto-closed while it was still in use** — e.g. a music
  player working through a playlist. The idle check ran every 5 minutes
  and looked for a file modified since the last check (`find -newer`) or
  one held open right then (`lsof +D`). A player that opens a track,
  buffers it, and closes the descriptor changes no mtime and holds
  nothing open at the instant the check fires, so a 5-minute window could
  catch a gap and tear the mount down mid-song. The gate now timestamps
  every `open`/`create`/`read`/`write` and exposes it, plus the live
  open-handle count, over the control socket (`STATUS`); `att` asks the
  gate instead of sampling from outside the mount. The old `find`/`lsof`
  heuristic stays as a fallback for when the socket can't be reached.

## v0.1.4

### Fixed
- **Copying a folder into the vault from a file manager failed with "not
  enough space".** The gate never implemented `statfs`, so the mount fell
  back to `fuser`'s default reply of zero blocks total and zero free. KDE's
  KIO copy job sums the source size and checks it against the destination's
  free space before writing anything, so every folder drag into `~/attache`
  in Dolphin was refused up front (a plain `cp`, which does no such check,
  worked). `statfs` now forwards the backing filesystem's real numbers.
- **Symlinks in the vault were unreadable and uncreatable.** The gate
  implemented neither `readlink`, `symlink`, nor `link`, so resolving a
  symlink returned `ENOSYS`, and creating a symlink or hard link failed
  with `EPERM`. This broke recursive copies of any tree containing a
  symlink, `git` checkouts, tarball extraction, and editors that
  canonicalize paths. `readlink` is ungated (metadata read, like
  `getattr`); `symlink`/`link` are gated on the new name's path like
  `create`/`mkdir`.

## v0.1.3

### Added
- `att allow --list` — show the "always allow" whitelist: each approved
  binary's content hash, approval time, name, and path. Works whether the
  vault is open (over the control socket) or closed (brief bootstrap mount,
  same as `att allow --always`). Read-only, so it isn't gated behind a
  confirmation dialog.

## v0.1.2

### Fixed
- **Sandboxed apps (Flatpak / Snap / AppImage) could never be whitelisted** —
  clicking *Always Allow* did nothing and the same file re-prompted forever.
  The gate identified a caller by the resolved path of `/proc/<pid>/exe`
  (`/app/freecad/bin/FreeCAD`), which only exists inside the app's own
  namespace, so persisting or matching an approval failed with `ENOENT`.
  Callers are now identified by the **SHA-256 of the binary's bytes**, read
  through the `/proc/<pid>/exe` magic symlink (works across namespaces).

### Changed
- Whitelist and session cache match on the binary's content hash, not its
  path. A byte-identical binary at another path is now also allowed; swapping
  a binary's bytes still revokes its approval. The prompt still shows the
  program name and path (plus a short hash) — you approve a name, not a hash.
- `att allow --always <path>` hashes the file at that path; for a sandboxed
  app you'd point it at the real host path, but the GUI *Always Allow* now
  works without that.

## v0.1.1

### Fixed
- **Critical:** the whole vault froze on the first file access from any app
  (FreeCAD, a preview/thumbnail worker, an indexer): the FUSE session ran on a
  single dispatch thread, so a gated `open`/`create`/`setattr` blocked in the
  access prompt stalled every other request — including un-gated
  `readdir`/`getattr`. If `zenity` couldn't reach the session bus it hung
  there permanently with no dialog shown.
  - FUSE dispatch is now multi-threaded (`n_threads` = CPUs, clamped 4–16).
  - `zenity` fails closed immediately when there's no display / session bus,
    instead of hanging in GTK's D-Bus autolaunch.
  - Access prompts auto-deny after `ATTACHE_PROMPT_TIMEOUT` seconds
    (default 120) so an unanswered dialog can't pin a worker.
  - `read`/`write` no longer hold the open-handle lock across backing I/O;
    the whitelist lock is released before hashing the calling binary.
- `att open` now warns when no graphical session is detected.

## v0.1.0

- Initial public release: `attache-gate` (per-binary FUSE access gate),
  `attache-mount-helper` (privileged mount-namespace setup), `attache-import`
  (verified restore from an exported disc), and the `att` CLI.
