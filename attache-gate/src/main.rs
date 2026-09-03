use std::path::PathBuf;
use std::process::ExitCode;

use fuser::{Config, MountOption};
use attache_gate::passthrough_fs::PassthroughFs;
use attache_gate::policy::{ZenityConfirm, ZenityPrompter};
use attache_gate::process_info::ProcResolver;

fn main() -> ExitCode {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let Some((backing, mountpoint)) = parse_args(&args) else {
        eprintln!(
            "Usage: {} <backing-dir> <mountpoint>",
            args.first().map(String::as_str).unwrap_or("attache-gate")
        );
        return ExitCode::FAILURE;
    };

    if !backing.is_dir() {
        eprintln!(
            "error: backing dir does not exist or is not a directory: {}",
            backing.display()
        );
        return ExitCode::FAILURE;
    }
    if !mountpoint.is_dir() {
        eprintln!(
            "error: mountpoint does not exist or is not a directory: {}",
            mountpoint.display()
        );
        return ExitCode::FAILURE;
    }

    let fs = PassthroughFs::new(backing.clone(), ZenityPrompter, ProcResolver);

    // Lets `att allow`/`att reset-whitelist` reach this already-running
    // mount while it's open, instead of requiring `att close` first -
    // see control.rs's doc comment for why this still needs a live human
    // confirmation and can't just comply with whatever's asked. state_dir
    // (backing's parent) is host-visible even though backing itself isn't
    // - only the mount *under* state_dir is namespace-confined, not the
    // directory itself - so the socket file lands somewhere `attache`'s
    // client side can actually find it.
    match backing.parent() {
        Some(state_dir) => {
            let whitelist = fs.whitelist_handle();
            let activity = fs.activity_monitor();
            attache_gate::control::spawn(
                state_dir.to_path_buf(),
                whitelist,
                activity,
                ZenityConfirm,
            );
        }
        None => eprintln!(
            "warning: could not determine state dir from {}; control socket not started",
            backing.display()
        ),
    }

    let mut config = Config::default();
    config
        .mount_options
        .push(MountOption::FSName("attache-gate".to_string()));

    // Dispatch FUSE requests across several worker threads rather than the
    // single one `fuser` defaults to. An access prompt (see policy.rs)
    // blocks the thread that serves the gated `open`/`create`/`setattr`
    // until a human answers the dialog; with one dispatch thread that
    // freezes the *entire* mount - including un-gated `readdir`/`getattr`,
    // so a file manager listing the vault hangs behind an unrelated
    // prompt. With N threads a pending prompt only ties up one of them.
    // The kernel still enforces per-inode/per-fh ordering, so this doesn't
    // reorder dependent operations.
    let n_threads = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
        .clamp(4, 16);
    config.n_threads = Some(n_threads);
    // Give each worker its own /dev/fuse fd (Linux 4.5+); avoids all
    // workers contending on one fd's read lock.
    config.clone_fd = true;

    if let Err(e) = fuser::mount(fs, &mountpoint, &config) {
        eprintln!("error: failed to mount: {e}");
        return ExitCode::FAILURE;
    }

    if let Some(state_dir) = backing.parent() {
        let _ = std::fs::remove_file(state_dir.join(attache_gate::control::SOCKET_NAME));
    }

    // `backing` is typically only reachable from inside this process's own
    // (private) mount namespace - nothing else can unmount it once we're
    // gone, so we do it ourselves now that our own FUSE loop has ended.
    // Best-effort: if this process gets killed outright instead of
    // reaching here, the backing mount is orphaned until the whole
    // namespace is torn down (i.e. until nothing is left running inside
    // it), which is a resource leak but not a security issue - the
    // backing dir is invisible outside this namespace either way.
    match std::process::Command::new("fusermount")
        .arg("-u")
        .arg(&backing)
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!("warning: fusermount -u {} exited with {status}", backing.display()),
        Err(e) => eprintln!("warning: failed to run fusermount -u {}: {e}", backing.display()),
    }
    ExitCode::SUCCESS
}

fn parse_args(args: &[String]) -> Option<(PathBuf, PathBuf)> {
    match args {
        [_, backing, mountpoint] => Some((PathBuf::from(backing), PathBuf::from(mountpoint))),
        _ => None,
    }
}
