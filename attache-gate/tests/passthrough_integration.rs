//! Integration tests that actually mount `PassthroughFs` via FUSE and drive
//! it through `std::fs`, verifying real passthrough behavior end to end.
//! Only the `Prompter` is faked (to avoid popping a real GUI dialog); the
//! `ProcessResolver` is real, since these tests run as an ordinary process
//! with a resolvable PID.
//!
//! Run serially: concurrent FUSE mount/unmount on the same machine can be
//! flaky, and `cargo test` runs tests in a binary on separate threads by
//! default, so each test takes out `MOUNT_LOCK` for its duration.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

use fuser::{Config, Session};
use attache_gate::passthrough_fs::PassthroughFs;
use attache_gate::policy::{Prompter, PromptResponse};
use attache_gate::process_info::{ProcessIdentity, ProcResolver};

static MOUNT_LOCK: Mutex<()> = Mutex::new(());

struct AlwaysAllow;
impl Prompter for AlwaysAllow {
    fn ask(&self, _identity: &ProcessIdentity, _target: &Path) -> PromptResponse {
        PromptResponse::AllowOnce
    }
}

struct AlwaysDeny;
impl Prompter for AlwaysDeny {
    fn ask(&self, _identity: &ProcessIdentity, _target: &Path) -> PromptResponse {
        PromptResponse::Deny
    }
}

/// Answers `AllowAlways` exactly once, then panics if asked again - used to
/// prove a whitelisted binary is auto-allowed on a later mount without a
/// second prompt.
struct AllowAlwaysOnce {
    used: std::sync::atomic::AtomicBool,
}
impl AllowAlwaysOnce {
    fn new() -> Self {
        Self {
            used: std::sync::atomic::AtomicBool::new(false),
        }
    }
}
impl Prompter for AllowAlwaysOnce {
    fn ask(&self, _identity: &ProcessIdentity, _target: &Path) -> PromptResponse {
        if self.used.swap(true, std::sync::atomic::Ordering::SeqCst) {
            panic!("prompted a second time - whitelist should have short-circuited this");
        }
        PromptResponse::AllowAlways
    }
}

struct PanicIfAsked;
impl Prompter for PanicIfAsked {
    fn ask(&self, _identity: &ProcessIdentity, _target: &Path) -> PromptResponse {
        panic!("prompted despite the binary being on the vault's whitelist");
    }
}

/// Signals when `ask()` has been entered, then blocks there until the test
/// sends a response - so the test can hold one access prompt open
/// indefinitely and observe what happens to *other* requests meanwhile.
struct BlockUntilReleased {
    entered: Mutex<mpsc::Sender<()>>,
    release: Mutex<mpsc::Receiver<PromptResponse>>,
}
impl Prompter for BlockUntilReleased {
    fn ask(&self, _identity: &ProcessIdentity, _target: &Path) -> PromptResponse {
        let _ = self.entered.lock().unwrap().send(());
        self.release
            .lock()
            .unwrap()
            .recv()
            .unwrap_or(PromptResponse::Deny)
    }
}

/// Waits briefly for the mount to become visible before the test starts
/// exercising it, to absorb the small window between the mount syscall
/// completing and the background dispatch thread being ready.
fn settle() {
    std::thread::sleep(Duration::from_millis(100));
}

#[test]
fn always_allow_round_trips_files_through_the_real_backing_directory() {
    let _guard = MOUNT_LOCK.lock().unwrap();
    let backing = tempfile::tempdir().unwrap();
    let mountpoint = tempfile::tempdir().unwrap();

    let fs = PassthroughFs::new(backing.path().to_path_buf(), AlwaysAllow, ProcResolver);
    let session = Session::new(fs, mountpoint.path(), &Config::default()).unwrap();
    let _bg = session.spawn().unwrap();
    settle();

    // write + read back through the mount
    let file_path = mountpoint.path().join("hello.txt");
    std::fs::write(&file_path, b"hello vault").unwrap();
    let content = std::fs::read_to_string(&file_path).unwrap();
    assert_eq!(content, "hello vault");

    // the backing directory actually received the real file
    let backing_file = backing.path().join("hello.txt");
    assert_eq!(std::fs::read_to_string(&backing_file).unwrap(), "hello vault");

    // directory listing
    let names: Vec<_> = std::fs::read_dir(mountpoint.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(names.contains(&std::ffi::OsString::from("hello.txt")));

    // mkdir + rmdir
    let subdir = mountpoint.path().join("sub");
    std::fs::create_dir(&subdir).unwrap();
    assert!(backing.path().join("sub").is_dir());
    std::fs::remove_dir(&subdir).unwrap();
    assert!(!backing.path().join("sub").exists());

    // rename
    let renamed = mountpoint.path().join("renamed.txt");
    std::fs::rename(&file_path, &renamed).unwrap();
    assert!(backing.path().join("renamed.txt").exists());
    assert!(!backing.path().join("hello.txt").exists());

    // dropping `_bg` here unmounts (BackgroundSession's Drop impl)
}

#[test]
fn always_allow_supports_truncate_chmod_and_touch() {
    let _guard = MOUNT_LOCK.lock().unwrap();
    let backing = tempfile::tempdir().unwrap();
    let mountpoint = tempfile::tempdir().unwrap();

    let fs = PassthroughFs::new(backing.path().to_path_buf(), AlwaysAllow, ProcResolver);
    let session = Session::new(fs, mountpoint.path(), &Config::default()).unwrap();
    let _bg = session.spawn().unwrap();
    settle();

    let file_path = mountpoint.path().join("note.txt");
    std::fs::write(&file_path, b"hello vault").unwrap();

    // truncate: what an editor's save-in-place does, and what regressed
    // before setattr existed at all (every save through the gate failed
    // with ENOSYS)
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file_path)
        .unwrap()
        .set_len(5)
        .unwrap();
    assert_eq!(std::fs::read_to_string(&file_path).unwrap(), "hello");
    assert_eq!(
        std::fs::read_to_string(backing.path().join("note.txt")).unwrap(),
        "hello"
    );

    // chmod
    std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let backing_mode = std::fs::metadata(backing.path().join("note.txt"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(backing_mode & 0o777, 0o600);

    // touch (utimens) without ever opening the file first - this is the
    // case that would bypass the auth gate if setattr weren't gated too
    let new_mtime = filetime::FileTime::from_unix_time(1_700_000_000, 0);
    filetime::set_file_times(&file_path, new_mtime, new_mtime).unwrap();
    let backing_mtime =
        filetime::FileTime::from_last_modification_time(&std::fs::metadata(backing.path().join("note.txt")).unwrap());
    assert_eq!(backing_mtime, new_mtime);
}

#[test]
fn always_deny_blocks_open_with_permission_denied() {
    let _guard = MOUNT_LOCK.lock().unwrap();
    let backing = tempfile::tempdir().unwrap();
    let mountpoint = tempfile::tempdir().unwrap();

    // seed a file directly in the backing dir (bypassing the gate) so we
    // are testing open-for-read being denied, not creation.
    std::fs::write(backing.path().join("secret.txt"), b"top secret").unwrap();

    let fs = PassthroughFs::new(backing.path().to_path_buf(), AlwaysDeny, ProcResolver);
    let session = Session::new(fs, mountpoint.path(), &Config::default()).unwrap();
    let _bg = session.spawn().unwrap();
    settle();

    let err = std::fs::read_to_string(mountpoint.path().join("secret.txt")).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn always_deny_blocks_mutating_operations_with_permission_denied() {
    let _guard = MOUNT_LOCK.lock().unwrap();
    let backing = tempfile::tempdir().unwrap();
    let mountpoint = tempfile::tempdir().unwrap();

    // seed content directly in the backing dir, bypassing the gate, so each
    // assertion below is testing the operation itself, not a missing file.
    std::fs::write(backing.path().join("existing.txt"), b"data").unwrap();
    std::fs::create_dir(backing.path().join("existing_dir")).unwrap();

    let fs = PassthroughFs::new(backing.path().to_path_buf(), AlwaysDeny, ProcResolver);
    let session = Session::new(fs, mountpoint.path(), &Config::default()).unwrap();
    let _bg = session.spawn().unwrap();
    settle();

    let denied = |r: std::io::Result<()>| {
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
    };

    denied(std::fs::create_dir(mountpoint.path().join("new_dir")));
    denied(std::fs::remove_file(mountpoint.path().join("existing.txt")));
    denied(std::fs::remove_dir(mountpoint.path().join("existing_dir")));
    denied(std::fs::rename(
        mountpoint.path().join("existing.txt"),
        mountpoint.path().join("renamed.txt"),
    ));
    // setattr reached directly by path, with no preceding open() - the
    // case that would bypass the gate entirely if setattr weren't
    // authorized on its own
    denied(std::fs::set_permissions(
        mountpoint.path().join("existing.txt"),
        std::fs::Permissions::from_mode(0o600),
    ));
    denied(filetime::set_file_times(
        mountpoint.path().join("existing.txt"),
        filetime::FileTime::now(),
        filetime::FileTime::now(),
    ));

    // nothing actually changed in the backing dir
    assert!(backing.path().join("existing.txt").exists());
    assert!(backing.path().join("existing_dir").exists());
    assert!(!backing.path().join("new_dir").exists());
    assert!(!backing.path().join("renamed.txt").exists());
}

#[test]
fn allow_always_whitelists_the_binary_across_mounts() {
    let _guard = MOUNT_LOCK.lock().unwrap();
    let backing = tempfile::tempdir().unwrap();

    {
        let mountpoint = tempfile::tempdir().unwrap();
        let fs = PassthroughFs::new(backing.path().to_path_buf(), AllowAlwaysOnce::new(), ProcResolver);
        let session = Session::new(fs, mountpoint.path(), &Config::default()).unwrap();
        let _bg = session.spawn().unwrap();
        settle();

        // first access prompts (and is answered AllowAlways), which should
        // persist an approval for this test binary into the vault.
        std::fs::write(mountpoint.path().join("a.txt"), b"one").unwrap();
    }

    // a brand new mount, with a prompter that panics if ever asked, proves
    // the approval was picked up from the persisted whitelist rather than
    // any in-memory cache (which wouldn't have survived the drop above).
    let mountpoint = tempfile::tempdir().unwrap();
    let fs = PassthroughFs::new(backing.path().to_path_buf(), PanicIfAsked, ProcResolver);
    let session = Session::new(fs, mountpoint.path(), &Config::default()).unwrap();
    let _bg = session.spawn().unwrap();
    settle();

    std::fs::write(mountpoint.path().join("b.txt"), b"two").unwrap();
    assert_eq!(
        std::fs::read_to_string(backing.path().join("b.txt")).unwrap(),
        "two"
    );
}

#[test]
fn a_pending_access_prompt_does_not_freeze_the_rest_of_the_vault() {
    // Regression test: the FUSE session must dispatch on more than one
    // thread. With a single dispatch thread, a gated open() blocked in the
    // (human-answered, indefinitely-long) access prompt froze *every*
    // other request for the whole mount - including un-gated readdir /
    // getattr - so e.g. a file manager listing the vault hung behind an
    // unrelated prompt. See attache-gate/src/main.rs (n_threads).
    let _guard = MOUNT_LOCK.lock().unwrap();
    let backing = tempfile::tempdir().unwrap();
    let mountpoint = tempfile::tempdir().unwrap();

    // seeded straight into the backing dir so opening them goes through the
    // gate as a first access, not a create.
    std::fs::write(backing.path().join("gated.txt"), b"secret").unwrap();
    std::fs::write(backing.path().join("probe.txt"), b"x").unwrap();

    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let prompter = BlockUntilReleased {
        entered: Mutex::new(entered_tx),
        release: Mutex::new(release_rx),
    };

    let mut config = Config::default();
    config.n_threads = Some(4);
    config.clone_fd = true;
    let fs = PassthroughFs::new(backing.path().to_path_buf(), prompter, ProcResolver);
    let session = Session::new(fs, mountpoint.path(), &config).unwrap();
    let _bg = session.spawn().unwrap();
    settle();

    // Safety valve: release the prompt unconditionally after a while, so a
    // failed assertion below can't leave a worker parked in ask() forever
    // and deadlock the unmount during cleanup.
    let release_guard = release_tx.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(10));
        let _ = release_guard.send(PromptResponse::Deny);
    });

    // Thread A: open a file -> parks in the prompt, occupying one worker.
    let mp = mountpoint.path().to_path_buf();
    let opener = std::thread::spawn(move || std::fs::read(mp.join("gated.txt")));
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the gated open never reached the prompt");

    // While that prompt is still unanswered, an unrelated readdir + getattr
    // must still complete promptly.
    let (done_tx, done_rx) = mpsc::channel();
    let mp2 = mountpoint.path().to_path_buf();
    std::thread::spawn(move || {
        let names: Vec<_> = std::fs::read_dir(&mp2)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        std::fs::metadata(mp2.join("probe.txt")).unwrap();
        let _ = done_tx.send(names);
    });
    let names = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("readdir/getattr blocked behind an unrelated pending access prompt");
    assert!(names.contains(&std::ffi::OsString::from("probe.txt")));

    // release the prompt so the opener thread and the unmount can finish
    release_tx.send(PromptResponse::AllowOnce).unwrap();
    assert_eq!(opener.join().unwrap().unwrap(), b"secret");
}

#[test]
fn whitelist_file_is_hidden_and_unwritable_through_the_mount() {
    let _guard = MOUNT_LOCK.lock().unwrap();
    let backing = tempfile::tempdir().unwrap();
    let mountpoint = tempfile::tempdir().unwrap();

    // seed a whitelist file directly in the backing dir, as the gate itself
    // would after an "always allow" approval.
    let whitelist_path = backing.path().join(".attache-gate-whitelist.json");
    std::fs::write(&whitelist_path, b"[]").unwrap();

    let fs = PassthroughFs::new(backing.path().to_path_buf(), AlwaysAllow, ProcResolver);
    let session = Session::new(fs, mountpoint.path(), &Config::default()).unwrap();
    let _bg = session.spawn().unwrap();
    settle();

    // invisible in directory listings, even though the caller is fully
    // authorized for everything else in the vault
    let names: Vec<_> = std::fs::read_dir(mountpoint.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(!names.contains(&std::ffi::OsString::from(".attache-gate-whitelist.json")));

    // not readable, writable, or removable through the mount
    let mounted_path = mountpoint.path().join(".attache-gate-whitelist.json");
    assert!(std::fs::read_to_string(&mounted_path).is_err());
    assert!(std::fs::write(&mounted_path, b"tampered").is_err());
    assert!(std::fs::remove_file(&mounted_path).is_err());

    // an attempt to rename another file *onto* the whitelist's name is
    // blocked too, so it can't be clobbered that way either
    std::fs::write(mountpoint.path().join("innocent.txt"), b"data").unwrap();
    assert!(std::fs::rename(mountpoint.path().join("innocent.txt"), &mounted_path).is_err());

    // the real file on the backing filesystem is untouched
    assert_eq!(std::fs::read_to_string(&whitelist_path).unwrap(), "[]");
}
