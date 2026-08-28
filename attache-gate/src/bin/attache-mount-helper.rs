//! Meant to be installed with `setcap cap_sys_admin+ep` (see
//! `attache-cli/install-mount-helper.sh`), root-owned, world-executable -
//! safe to be world-executable because every path this touches is
//! resolved from the *caller's own* real uid (via getpwuid, never from
//! `$HOME`/argv), so anyone invoking it can only ever affect their own
//! home directory, never another user's.
//!
//! Exists to close a specific gap: `attache-gate` gates access to
//! `~/.attache-mnt`, but the gocryptfs-decrypted plaintext it passes
//! through also lives at `~/.local/state/attache/decrypted` - a second,
//! completely ungated path to the same data, reachable by any process
//! running as the same user (see the security review that motivated
//! this). Fixing that means the decrypted backing directory has to live
//! in a mount namespace that nothing outside attache-gate can see, while
//! `~/.attache-mnt` itself stays visible everywhere apps expect it (the
//! `att` CLI in turn symlinks a user-facing name - default `~/attache`,
//! configurable - onto this fixed path; that symlink is ordinary and
//! unprivileged, since tampering with it can only break the friendly
//! name, never bypass the gate). Getting a mount performed inside an
//! otherwise-private namespace to still show up in the ordinary session
//! namespace requires two things only real CAP_SYS_ADMIN can do (verified
//! empirically - an unprivileged `unshare --user --mount` cannot manage
//! this, the kernel deliberately downgrades `shared` to `slave` across a
//! less-privileged user namespace boundary specifically to prevent this
//! exact trick from being a privilege escalation):
//!
//!   1. mark `~/.attache-mnt` as a `shared`-propagation mountpoint, and
//!      `~/.local/state/attache` as `private`, in the real session
//!      namespace, once, ahead of time (the `setup` subcommand);
//!   2. create a *real* (non-userns) mount namespace at `att open` time,
//!      so a mount performed under the now-private state dir stays
//!      confined to it, while a mount performed under the now-shared
//!      `~/.attache-mnt` still propagates out (the `run` subcommand).
//!
//! `run` drops its elevated capability the normal way, by exec()ing into
//! a binary (`attache-gate`) that has no file capabilities of its own -
//! nothing downstream of this ever runs with CAP_SYS_ADMIN.

use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const PWFIFO_NAME: &str = "open.pwfifo";

fn real_home_dir() -> PathBuf {
    unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            eprintln!("attache-mount-helper: no passwd entry for uid {uid}");
            std::process::exit(1);
        }
        let dir = CStr::from_ptr((*pw).pw_dir);
        PathBuf::from(OsStr::from_bytes(dir.to_bytes()))
    }
}

/// True if `path` is exactly a mount target right now, per
/// `/proc/self/mountinfo`. Deliberately not a `st_dev` comparison against
/// the parent directory - that misses a bind mount of a directory onto
/// itself, since bind-mounting doesn't change the device number, only
/// adds a mount-table entry. (Doesn't unescape mountinfo's octal escapes
/// for space/tab/backslash/newline in paths - fine here, every path this
/// binary ever checks is a fixed, plain, space-free path under `$HOME`.)
fn is_mountpoint(path: &Path) -> bool {
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    let Some(canonical) = canonical.to_str() else {
        return false;
    };
    let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    mountinfo
        .lines()
        .any(|line| line.split_whitespace().nth(4) == Some(canonical))
}

fn mount_raw(source: Option<&Path>, target: &Path, flags: libc::c_ulong) -> std::io::Result<()> {
    let target_c = CString::new(target.as_os_str().as_bytes()).unwrap();
    let source_c = source.map(|s| CString::new(s.as_os_str().as_bytes()).unwrap());
    let source_ptr = source_c.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
    let ret = unsafe {
        libc::mount(
            source_ptr,
            target_c.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Bind-mounts `path` onto itself (turning it into its own distinct
/// mountpoint, needed since propagation flags apply per-mountpoint) unless
/// it already is one, then sets the given propagation type. Idempotent.
fn make_standalone_mount(path: &Path, propagation: libc::c_ulong) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    if !is_mountpoint(path) {
        mount_raw(Some(path), path, libc::MS_BIND)?;
    }
    mount_raw(None, path, propagation)
}

fn cmd_setup() -> std::process::ExitCode {
    let home = real_home_dir();
    // The *real* FUSE-gated mount - always this exact hardcoded, hidden
    // path, never influenced by any config/argv/env var. `att` creates an
    // ordinary, unprivileged symlink from whatever name the user wants
    // displayed (default ~/attache, configurable) to this path; tampering
    // with that symlink can only break the friendly name, never bypass
    // the gate, since the actual protected mount never moves. Keeping
    // this fixed is what lets the mountpoint be "configurable" at all
    // without reopening the exact "caller-controlled path reaches a
    // CAP_SYS_ADMIN operation" risk this design has avoided from the
    // start - see the crate-level discussion this went through.
    let real_mountpoint = home.join(".attache-mnt");
    let state_dir = home.join(".local/state/attache");

    if let Err(e) = make_standalone_mount(&real_mountpoint, libc::MS_SHARED) {
        eprintln!(
            "attache-mount-helper: setup: sharing {}: {e}",
            real_mountpoint.display()
        );
        return std::process::ExitCode::FAILURE;
    }
    if let Err(e) = make_standalone_mount(&state_dir, libc::MS_PRIVATE) {
        eprintln!(
            "attache-mount-helper: setup: privatizing {}: {e}",
            state_dir.display()
        );
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

/// Enters a real mount namespace and mounts gocryptfs's decrypted view
/// into the (now namespace-private) backing directory, using the
/// password waiting in `open.pwfifo`. Shared by `run` (which then execs
/// into attache-gate to serve it) and `reset-whitelist` (which touches one
/// file in it directly and unmounts again) - both need the exact same
/// isolation, since the backing dir must never be mounted anywhere the
/// host namespace can see it, not even briefly for a one-off maintenance
/// operation.
fn enter_namespace_and_mount_backing() -> Result<PathBuf, ()> {
    let home = real_home_dir();
    // Also always this exact hardcoded path - same reasoning as
    // real_mountpoint in cmd_setup above.
    let cipherdir = home.join(".attache");
    let state_dir = home.join(".local/state/attache");
    let backing = state_dir.join("decrypted");
    let pwfifo = state_dir.join(PWFIFO_NAME);

    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        eprintln!(
            "attache-mount-helper: unshare(CLONE_NEWNS): {}",
            std::io::Error::last_os_error()
        );
        return Err(());
    }

    if let Err(e) = std::fs::create_dir_all(&backing) {
        eprintln!("attache-mount-helper: mkdir {}: {e}", backing.display());
        return Err(());
    }
    // Defense in depth only - the mount namespace above is what actually
    // keeps this dir unreachable from outside, not this permission bit -
    // but it's free and this is the one process that ever touches it.
    if let Err(e) = std::fs::set_permissions(&backing, std::fs::Permissions::from_mode(0o700)) {
        eprintln!("attache-mount-helper: chmod 700 {}: {e}", backing.display());
        return Err(());
    }

    let status = Command::new("gocryptfs")
        .arg("-passfile")
        .arg(&pwfifo)
        .arg(&cipherdir)
        .arg(&backing)
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!("attache-mount-helper: gocryptfs exited with {s}");
            return Err(());
        }
        Err(e) => {
            eprintln!("attache-mount-helper: failed to run gocryptfs: {e}");
            return Err(());
        }
    }

    if !is_mountpoint(&backing) {
        eprintln!(
            "attache-mount-helper: gocryptfs reported success but {} isn't mounted",
            backing.display()
        );
        return Err(());
    }

    Ok(backing)
}

/// Execs into `attache-gate` to serve the just-mounted backing dir - which
/// inherits the namespace (so it can see the backing dir) but not the
/// CAP_SYS_ADMIN this process was holding (attache-gate has no file
/// capabilities of its own, so exec drops it the normal way).
fn cmd_run() -> std::process::ExitCode {
    let Ok(backing) = enter_namespace_and_mount_backing() else {
        return std::process::ExitCode::FAILURE;
    };
    let mountpoint = real_home_dir().join(".attache-mnt");

    let err = Command::new("attache-gate")
        .arg(&backing)
        .arg(&mountpoint)
        .exec();
    eprintln!("attache-mount-helper: exec attache-gate: {err}");
    std::process::ExitCode::FAILURE
}

/// Removes Attache's whitelist of always-allowed binaries. Needs the
/// same isolated mount as `run` - the whitelist file lives inside the
/// backing dir, which must never be reachable outside this namespace,
/// even for this one-off delete-and-unmount.
fn cmd_reset_whitelist() -> std::process::ExitCode {
    let Ok(backing) = enter_namespace_and_mount_backing() else {
        return std::process::ExitCode::FAILURE;
    };

    let whitelist_path = backing.join(attache_gate::whitelist::WHITELIST_FILENAME);
    let result = match std::fs::remove_file(&whitelist_path) {
        Ok(()) => {
            println!("attache-mount-helper: removed {}", whitelist_path.display());
            std::process::ExitCode::SUCCESS
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("attache-mount-helper: no whitelist to reset, already empty");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "attache-mount-helper: failed to remove {}: {e}",
                whitelist_path.display()
            );
            std::process::ExitCode::FAILURE
        }
    };

    unmount_backing(&backing);
    result
}

/// Pre-approves a binary for "always allow" without needing a live
/// prompt - the same persistent whitelist entry the GUI dialog's "Always
/// Allow" button writes, just added proactively instead of in response to
/// a live access attempt. Needs the same isolated mount as `run`, for the
/// same reason as `reset-whitelist`.
fn cmd_allow_always(target: &Path) -> std::process::ExitCode {
    let Ok(backing) = enter_namespace_and_mount_backing() else {
        return std::process::ExitCode::FAILURE;
    };

    // Canonicalize for a stable label, then match on a hash of the binary's
    // bytes - the same value ProcResolver computes from /proc/<pid>/exe at
    // runtime. (The whitelist no longer keys on the path.)
    let result = match std::fs::canonicalize(target) {
        Ok(canonical) => {
            let comm = canonical
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let sha256 = match attache_gate::whitelist::hash_file(&canonical) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!(
                        "attache-mount-helper: {}: {e}",
                        canonical.display()
                    );
                    unmount_backing(&backing);
                    return std::process::ExitCode::FAILURE;
                }
            };
            let identity = attache_gate::process_info::ProcessIdentity {
                path: canonical.clone(),
                comm,
                sha256,
            };
            match attache_gate::whitelist::Whitelist::load(&backing).add(&identity) {
                Ok(()) => {
                    println!("attache-mount-helper: whitelisted {}", canonical.display());
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!(
                        "attache-mount-helper: failed to whitelist {}: {e}",
                        canonical.display()
                    );
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("attache-mount-helper: {}: {e}", target.display());
            std::process::ExitCode::FAILURE
        }
    };

    unmount_backing(&backing);
    result
}

/// Nothing else runs in this namespace once the caller exits for
/// `reset-whitelist`/`allow-always` (there was never an attache-gate here to
/// inherit it), so it's this process's job to unmount cleanly rather than
/// leaving it for the namespace's own teardown - same reasoning as
/// attache-gate's own backing-dir cleanup in main.rs.
fn unmount_backing(backing: &Path) {
    match Command::new("fusermount").arg("-u").arg(backing).status() {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("attache-mount-helper: fusermount -u {} exited with {s}", backing.display()),
        Err(e) => eprintln!("attache-mount-helper: failed to run fusermount -u {}: {e}", backing.display()),
    }
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("setup") if args.len() == 2 => cmd_setup(),
        Some("run") if args.len() == 2 => cmd_run(),
        Some("reset-whitelist") if args.len() == 2 => cmd_reset_whitelist(),
        Some("allow-always") if args.len() == 3 => cmd_allow_always(Path::new(&args[2])),
        _ => {
            eprintln!(
                "usage: {} setup|run|reset-whitelist|allow-always <path>",
                args.first().map(String::as_str).unwrap_or("attache-mount-helper")
            );
            std::process::ExitCode::FAILURE
        }
    }
}
