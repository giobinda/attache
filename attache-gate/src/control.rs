//! A small Unix-domain-socket control channel that lets `att allow`/
//! `att reset-whitelist` reach an *already-running* attache-gate while
//! the mount is open, instead of requiring it to be closed first (closing
//! it would disrupt anything else that currently has a file open in the
//! vault).
//!
//! Every request is confirmed via [`crate::policy::ControlConfirm`] - the
//! same kind of GUI dialog used for live file-access prompts - before
//! being applied. The socket file is owner-only (0600), but that only
//! restricts *which user* can connect, not *which process* running as
//! that user does; without this confirmation step, any locally-running
//! process could silently whitelist itself over the socket with no human
//! involved at all, which is exactly what the rest of this project exists
//! to prevent.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::passthrough_fs::ActivityMonitor;
use crate::policy::ControlConfirm;
use crate::process_info::ProcessIdentity;
use crate::whitelist::Whitelist;

/// Kept in sync with `CONTROL_SOCKET` in `attache-cli/attache`.
pub const SOCKET_NAME: &str = "control.sock";

/// Binds the control socket at `<state_dir>/control.sock` and serves it
/// on a background thread for as long as the process lives. Binding
/// failure is logged, not fatal - the mount still works fine without this,
/// just without the open-vault fast path for `att allow`/`reset-whitelist`.
pub fn spawn<C>(
    state_dir: PathBuf,
    whitelist: Arc<Mutex<Whitelist>>,
    activity: ActivityMonitor,
    confirm: C,
) where
    C: ControlConfirm + Send + Sync + 'static,
{
    let socket_path = state_dir.join(SOCKET_NAME);
    // Stale socket from a crashed previous run - bind fails over a
    // leftover file otherwise.
    let _ = std::fs::remove_file(&socket_path);

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "warning: control socket bind failed at {}: {e}",
                socket_path.display()
            );
            return;
        }
    };
    if let Err(e) = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!("warning: chmod 600 {}: {e}", socket_path.display());
    }

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_connection(stream, &whitelist, &activity, &confirm);
        }
    });
}

fn handle_connection<C: ControlConfirm>(
    stream: UnixStream,
    whitelist: &Arc<Mutex<Whitelist>>,
    activity: &ActivityMonitor,
    confirm: &C,
) {
    let Ok(cloned) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(cloned);
    let mut writer = stream;

    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let line = line.trim();

    let response = if let Some(path) = line.strip_prefix("ALLOW-ALWAYS ") {
        allow_always(whitelist, confirm, Path::new(path))
    } else if line == "RESET-WHITELIST" {
        reset_whitelist(whitelist, confirm)
    } else if line == "LIST-WHITELIST" {
        list_whitelist(whitelist)
    } else if line == "STATUS" {
        status(activity)
    } else {
        "ERROR unknown command".to_string()
    };

    let _ = writeln!(writer, "{response}");
}

fn allow_always<C: ControlConfirm>(
    whitelist: &Arc<Mutex<Whitelist>>,
    confirm: &C,
    target: &Path,
) -> String {
    // A real filesystem path is required here (there's no pid to read
    // `/proc/<pid>/exe` from). Canonicalize it for a stable label, then
    // hash its contents - that hash is what the whitelist matches on, the
    // same value `ProcResolver::resolve` would compute for this binary.
    let canonical = match std::fs::canonicalize(target) {
        Ok(p) => p,
        Err(e) => return format!("ERROR {}: {e}", target.display()),
    };

    let action = format!("`att allow` wants to always allow:\n{}", canonical.display());
    if !confirm.confirm(&action) {
        return "DENIED not confirmed".to_string();
    }

    let sha256 = match crate::whitelist::hash_file(&canonical) {
        Ok(h) => h,
        Err(e) => return format!("ERROR {}: {e}", canonical.display()),
    };
    let comm = canonical
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let identity = ProcessIdentity {
        path: canonical.clone(),
        comm,
        sha256,
    };
    match whitelist.lock().unwrap().add(&identity) {
        Ok(()) => format!("OK whitelisted {}", canonical.display()),
        Err(e) => format!("ERROR {e}"),
    }
}

/// Returns the current whitelist as TSV (see `Whitelist::tsv`). Read-only,
/// so - unlike `ALLOW-ALWAYS` / `RESET-WHITELIST` - it isn't gated behind a
/// `ControlConfirm` dialog: it grants no capability and changes no state,
/// and the 0600 socket already restricts it to the vault's own user.
fn list_whitelist(whitelist: &Arc<Mutex<Whitelist>>) -> String {
    let tsv = whitelist.lock().unwrap().tsv();
    if tsv.is_empty() {
        "OK empty".to_string()
    } else {
        format!("OK\n{}", tsv.trim_end())
    }
}

/// `OK <seconds-since-last-vault-I/O> <open-handle-count>` - consumed by
/// `att`'s idle-timeout manager instead of it sampling `lsof +D` / mtime
/// from outside the mount (which misses a media player streaming a track
/// it opened, buffered, and closed between two 5-minutely checks). A
/// non-zero handle count, or an idle time under the manager's window,
/// means "keep the vault open". Read-only, so - like `LIST-WHITELIST` -
/// it isn't gated behind a `ControlConfirm` dialog.
fn status(activity: &ActivityMonitor) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let idle = now.saturating_sub(activity.last_activity_secs());
    format!("OK {idle} {}", activity.open_handles())
}

fn reset_whitelist<C: ControlConfirm>(whitelist: &Arc<Mutex<Whitelist>>, confirm: &C) -> String {
    let action = "`att reset-whitelist` wants to remove every always-allowed app.\n\
                   Every app will need to be re-approved."
        .to_string();
    if !confirm.confirm(&action) {
        return "DENIED not confirmed".to_string();
    }
    match whitelist.lock().unwrap().clear() {
        Ok(()) => "OK whitelist reset".to_string(),
        Err(e) => format!("ERROR {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeConfirm {
        answer: bool,
        calls: AtomicUsize,
    }

    impl FakeConfirm {
        fn new(answer: bool) -> Self {
            Self {
                answer,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl ControlConfirm for FakeConfirm {
        fn confirm(&self, _action: &str) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.answer
        }
    }

    /// The identity `allow_always` builds internally: canonical path + a
    /// hash of the binary's bytes.
    fn identity_for(bin: &Path) -> ProcessIdentity {
        let path = std::fs::canonicalize(bin).unwrap();
        let sha256 = crate::whitelist::hash_file(&path).unwrap();
        let comm = path.file_name().unwrap().to_string_lossy().into_owned();
        ProcessIdentity { path, comm, sha256 }
    }

    #[test]
    fn allow_always_confirmed_whitelists_the_binary() {
        let backing = tempfile::tempdir().unwrap();
        let bin = backing.path().join("trusted-tool");
        std::fs::write(&bin, b"a real binary").unwrap();
        let whitelist = Arc::new(Mutex::new(Whitelist::load(backing.path())));
        let confirm = FakeConfirm::new(true);

        let response = allow_always(&whitelist, &confirm, &bin);

        assert!(response.starts_with("OK"), "unexpected response: {response}");
        let identity = identity_for(&bin);
        assert!(whitelist.lock().unwrap().is_allowed(&identity));
    }

    #[test]
    fn allow_always_not_confirmed_does_not_whitelist() {
        let backing = tempfile::tempdir().unwrap();
        let bin = backing.path().join("shady-tool");
        std::fs::write(&bin, b"a real binary").unwrap();
        let whitelist = Arc::new(Mutex::new(Whitelist::load(backing.path())));
        let confirm = FakeConfirm::new(false);

        let response = allow_always(&whitelist, &confirm, &bin);

        assert_eq!(response, "DENIED not confirmed");
        let identity = identity_for(&bin);
        assert!(!whitelist.lock().unwrap().is_allowed(&identity));
    }

    #[test]
    fn allow_always_nonexistent_path_never_prompts() {
        let backing = tempfile::tempdir().unwrap();
        let whitelist = Arc::new(Mutex::new(Whitelist::load(backing.path())));
        let confirm = FakeConfirm::new(true);

        let response = allow_always(&whitelist, &confirm, Path::new("/nonexistent/binary"));

        assert!(response.starts_with("ERROR"), "unexpected response: {response}");
        assert_eq!(
            confirm.calls.load(Ordering::SeqCst),
            0,
            "should validate the path before ever bothering the user with a confirmation"
        );
    }

    #[test]
    fn list_whitelist_returns_entries_without_a_confirmation() {
        let backing = tempfile::tempdir().unwrap();
        let bin = backing.path().join("trusted-tool");
        std::fs::write(&bin, b"a real binary").unwrap();

        let whitelist = Arc::new(Mutex::new(Whitelist::load(backing.path())));
        assert_eq!(list_whitelist(&whitelist), "OK empty");

        whitelist.lock().unwrap().add(&identity_for(&bin)).unwrap();
        let response = list_whitelist(&whitelist);
        assert!(response.starts_with("OK\n"), "unexpected: {response}");
        assert!(response.contains("\ttrusted-tool\t"), "unexpected: {response}");
    }

    #[test]
    fn reset_whitelist_confirmed_clears_it() {
        let backing = tempfile::tempdir().unwrap();
        let bin = backing.path().join("trusted-tool");
        std::fs::write(&bin, b"a real binary").unwrap();
        let identity = identity_for(&bin);
        let mut w = Whitelist::load(backing.path());
        w.add(&identity).unwrap();
        let whitelist = Arc::new(Mutex::new(w));

        let response = reset_whitelist(&whitelist, &FakeConfirm::new(true));

        assert_eq!(response, "OK whitelist reset");
        assert!(!whitelist.lock().unwrap().is_allowed(&identity));
    }

    #[test]
    fn reset_whitelist_not_confirmed_leaves_it_untouched() {
        let backing = tempfile::tempdir().unwrap();
        let bin = backing.path().join("trusted-tool");
        std::fs::write(&bin, b"a real binary").unwrap();
        let identity = identity_for(&bin);
        let mut w = Whitelist::load(backing.path());
        w.add(&identity).unwrap();
        let whitelist = Arc::new(Mutex::new(w));

        let response = reset_whitelist(&whitelist, &FakeConfirm::new(false));

        assert_eq!(response, "DENIED not confirmed");
        assert!(whitelist.lock().unwrap().is_allowed(&identity));
    }
}
