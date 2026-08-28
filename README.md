# Attaché

An encrypted folder for Linux that asks **which program** may open your files.

Attaché keeps a [gocryptfs](https://github.com/rfjakob/gocryptfs)-encrypted vault at
`~/.attache` and exposes the decrypted contents at `~/attache`. Every time a
process tries to open a file in the vault, a GUI dialog asks **Allow Once /
Always Allow / Deny**, keyed on the calling program's binary. Decisions are
cached per binary for the session; "Always Allow" is persisted to a per-vault
whitelist so that program is not asked again. Where there is no GUI to show the
prompt (over SSH, headless), unapproved access is denied by default.

The vault auto-closes after 5 minutes idle, at logout or shutdown, and before
suspend.

## The name

An *attaché case* is the slim, locked briefcase a diplomatic attaché uses to
carry sensitive papers between postings: the documents are protected in transit
and only opened by the right hands. That is the whole idea here — a small locked
case for your private files that travels with you and checks who is reaching
inside.

## What it's for: portable privacy

The vault is one self-contained encrypted directory. It does not depend on the
host machine — no system configuration, no database, no service to register:

- `att export` burns the encrypted vault **plus the tools to open it** to a disc,
  with a `MANIFEST.sha256` over every file. `attache-import` restores it,
  verified, onto any Linux machine with nothing preinstalled.
- The access policy — the per-binary prompts and the SHA-256 whitelist — lives
  *inside* the vault's own backing directory, so it travels with the data. Your
  rules about which programs may read your files are enforced on the new machine
  too, not left behind on the old one.

So your private working set — notes, keys, documents — moves with you: encrypted
at rest, gated per application, on machines you did not have to set up or trust
in advance.

> **Status:** early, single-author project. It performs privileged mount
> operations — read the code and the [threat model](#threat-model) before
> trusting it with anything that matters.

## Components

| Path | What it is |
| --- | --- |
| `att` | Bash CLI — `init`, `open`, `close`, `status`, `note`, `export`, `allow`, `reset-whitelist`, `denied`, `oblivion`. Owns the background manager process that holds the mounts open and tears them down on idle/logout/suspend. |
| `attache-gate/` | Rust crate. Builds **`attache-gate`** (the FUSE passthrough that does the per-binary gating) and **`attache-mount-helper`** (the one privileged helper, `cap_sys_admin`, that sets up the mount namespace). |
| `attache-import/` | Rust crate. **`attache-import`** — restores a vault from an exported disc onto a fresh machine, verifying every file against a burned-in `MANIFEST.sha256` first. |

`attache-gate` and `attache-import` are members of one Cargo workspace
(`Cargo.toml` at the repo root).

## How it layers

```
~/attache                     ← ordinary symlink (display name; rename freely)
   │
~/.attache-mnt                ← attache-gate FUSE mount: gates every open()
   │
~/.local/state/attache/decrypted   ← gocryptfs plaintext, inside a PRIVATE mount
   │                                  namespace only the gate's processes join
~/.attache                    ← gocryptfs ciphertext (this is what's at rest)
```

`att open` collects the gocryptfs password on a real terminal, then hands off to
a single background manager process that owns both mounts (gocryptfs and
`attache-gate`) for as long as the vault is open.

## Secure notes: `att note`

```sh
att note                 # new note named for the current time: 20260828-153000.vnote
att note ideas.md        # or a name you choose (relative path, no '..')
```

`att note` opens `$VISUAL` / `$EDITOR` (default `vim`) on a file **inside the
vault**. If the vault is closed it opens it first and closes it again when you
are done. The note's contents go straight into gocryptfs — encrypted at rest
like everything else in the vault — and nothing about it is written anywhere
outside.

**No history, no backups, no leakage:**

- The editor runs with `HOME` and every `XDG_*` directory redirected to a
  throwaway sandbox under `/dev/shm` (RAM, never written to disk), which is
  deleted the moment the editor exits. Your real home never sees the editor's
  swap files, undo history, `.viminfo`, recent-files list, or config.
- Attaché keeps no versioning, no snapshots, and no trash. Overwrite a note and
  the previous contents are gone.
- The encrypted vault is the **only** copy of your notes unless you make one
  yourself with `att export`. `att oblivion` — which shreds the key material and
  deletes the payload — is genuinely irreversible.

## Threat model

A plain directory's permission bits cannot tell "attache-gate" apart from any
other program you run, so the decrypted plaintext must not be reachable by a
second, ungated path. `attache-mount-helper` (installed root-owned with
`cap_sys_admin`, **not** setuid) puts the gocryptfs plaintext in a mount
namespace nothing outside the gate can see, while keeping `~/.attache-mnt`
visible everywhere apps expect it. It resolves every path from the caller's own
real uid (via `getpwuid`, never `$HOME`/argv), so any user who runs it can only
affect their own home directory. It drops the capability by `exec()`ing into
`attache-gate`, which has no capabilities of its own — nothing downstream ever
runs with `cap_sys_admin`.

The vault's whitelist lives inside the vault's own backing directory and is
matched on the binary's SHA-256, not just its path: a trusted executable swapped
out at the same path loses its approval instead of inheriting it. The FUSE layer
refuses all access to the whitelist file through the mount — it can only be
touched by the gate operating on the backing directory directly.

## Install

Requires a musl-capable Rust toolchain plus these on `PATH`:
`gocryptfs`, `fusermount3`, `socat`, `zenity`, `gdbus` (glib2), `lsof`,
`setcap` (libcap), and `/dev/fuse`. `xorriso` / `growisofs` are optional, only
for `att export`.

### One-liner

```sh
curl -fsSL https://raw.githubusercontent.com/giobinda/attache/main/bootstrap.sh | bash
```

`bootstrap.sh` clones the source to `~/.local/share/attache/src`, then runs
`install.sh` from it (builds the workspace, installs `att` +
`attache-gate` / `attache-mount-helper` / `attache-import` into `~/.local/bin`).
It does **nothing privileged** — it finishes by printing the one `sudo` command
for you to run yourself:

```sh
sudo ~/.local/share/attache/src/install-mount-helper.sh
```

Piping a script into a shell is the kind of thing this project exists to make you
think twice about — read [`bootstrap.sh`](bootstrap.sh) and
[`install.sh`](install.sh) first, or take the manual path.

### Manual

```sh
git clone https://github.com/giobinda/attache.git && cd attache
./install.sh                        # builds the workspace, installs to ~/.local/bin
sudo ./install-mount-helper.sh      # the one privileged step — never run automatically
```

### Then

```sh
att init                            # create a new vault (or: attache-import <disc> to restore one)
att open
```

`install-mount-helper.sh` must be re-run from the checkout after every rebuild —
replacing the binary's contents drops the file capability by kernel design.
Re-running the one-liner updates the source and rebuilds in place.

## Portable restore

`att export <dir>` writes a bootable-restore ISO: the encrypted vault, static
`gocryptfs` / `attache-gate` / `attache-mount-helper` / `att` builds, and a
`MANIFEST.sha256`. On a fresh machine, `attache-import` verifies the manifest
(catching disc rot or tampering) and installs everything into `~/.local/bin`.

## Development

```sh
cargo build --release --target x86_64-unknown-linux-musl
cargo test          # unit tests + the passthrough / import integration tests
```

## License

GPLv3. See [LICENSE](LICENSE).
