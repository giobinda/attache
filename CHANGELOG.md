# Changelog

All notable changes are recorded here. Every bug fix ships as a new release.

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
