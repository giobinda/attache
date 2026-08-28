use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::process_info::ProcessIdentity;
use crate::whitelist::Whitelist;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// A user's answer to an access prompt. `AllowAlways` is distinct from
/// `AllowOnce` in that it gets persisted to the vault's [`Whitelist`], so
/// the same binary is auto-allowed on future accesses without prompting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptResponse {
    AllowOnce,
    AllowAlways,
    Deny,
}

/// Asks the user (or a test double) whether a process should be allowed access.
pub trait Prompter {
    fn ask(&self, identity: &ProcessIdentity, target: &Path) -> PromptResponse;
}

/// Caches per-binary allow/deny decisions for the lifetime of the mount, so
/// the same process isn't re-prompted on every file access. Also consults
/// (and, on an "always allow" response, updates) the vault's persistent
/// [`Whitelist`], so approvals survive across mounts too.
pub struct AuthPolicy<P: Prompter> {
    prompter: P,
    /// Keyed on the binary's content hash (`ProcessIdentity::sha256`), same
    /// as the persistent whitelist - so a swapped binary misses the cache
    /// too, and two distinct binaries can't collide on a shared
    /// namespace-local path like `/app/bin/foo`.
    cache: Mutex<HashMap<String, Decision>>,
    whitelist: Arc<Mutex<Whitelist>>,
}

impl<P: Prompter> AuthPolicy<P> {
    pub fn new(prompter: P, whitelist: Whitelist) -> Self {
        Self {
            prompter,
            cache: Mutex::new(HashMap::new()),
            whitelist: Arc::new(Mutex::new(whitelist)),
        }
    }

    /// A shared handle to the same whitelist this policy consults, so
    /// something outside the normal FUSE authorize() path (the control
    /// socket in `control.rs`) can add to or clear it from an
    /// already-running mount, with changes visible to this policy
    /// immediately - no separate reload needed.
    pub fn whitelist_handle(&self) -> Arc<Mutex<Whitelist>> {
        Arc::clone(&self.whitelist)
    }

    pub fn decide(&self, identity: &ProcessIdentity, target: &Path) -> Decision {
        // Consulted on *every* call, never served from the session cache
        // below: `identity.sha256` is a fresh hash of the caller's binary
        // (recomputed by `ProcResolver::resolve` from `/proc/<pid>/exe` on
        // every request), so a binary swapped out under an approved hash
        // simply stops matching here - it can't inherit the old decision.
        // The check itself is a cheap in-memory string compare now, so
        // there's nothing expensive to hold the lock across.
        if self.whitelist.lock().unwrap().is_allowed(identity) {
            return Decision::Allow;
        }

        // Non-whitelisted binaries: prompt once per mount session and
        // cache that answer, same as before - this cache never carries
        // the hash-pinning guarantee (an "Allow Once"/"Always Allow" here
        // are answers to a live GUI prompt the user just saw, not a
        // persisted trust decision), so there's nothing it can silently
        // downgrade.
        if let Some(decision) = self.cache.lock().unwrap().get(&identity.sha256) {
            return *decision;
        }

        // Not held across `ask()` below: `cache` is one mutex shared by
        // every access this mount ever authorizes, and the prompt blocks
        // on a human indefinitely - holding the lock across it would
        // freeze every *other* process's vault access too, including ones
        // already decided, for as long as this one dialog sits unanswered
        // (a trivial local DoS: one process opens an unfamiliar binary and
        // never dismisses the dialog). The cost of not holding it is a
        // possible duplicate prompt if two threads race on the very first
        // access to the same never-before-seen binary - one extra dialog,
        // not a frozen vault.
        let response = self.prompter.ask(identity, target);

        match response {
            PromptResponse::AllowOnce => {
                let decision = Decision::Allow;
                self.cache.lock().unwrap().insert(identity.sha256.clone(), decision);
                decision
            }
            PromptResponse::AllowAlways => {
                // Deliberately never inserted into `cache`: the whitelist
                // check at the top of this function is the source of truth,
                // and it keys on the same content hash the cache would.
                // Persisting is what makes "Always" outlast the session;
                // the cache only exists to skip re-prompting within it.
                if let Err(e) = self.whitelist.lock().unwrap().add(identity) {
                    log::warn!(
                        "failed to persist whitelist entry for {}: {e}",
                        identity.path.display()
                    );
                }
                Decision::Allow
            }
            PromptResponse::Deny => {
                // {:?} rather than {}: comm/path/target are all
                // attacker-influenced (a process picks its own comm
                // string, and can name a vault file anything it likes),
                // and Debug-formatting a str/Path quotes and escapes
                // control characters/quotes automatically - plain display
                // formatting here would let a crafted name inject fake
                // log lines (CWE-117). Grepped by `att denied`.
                log::warn!(
                    "ATTACHE-DENIED comm={:?} path={:?} target={:?}",
                    identity.comm,
                    identity.path,
                    target
                );
                let decision = Decision::Deny;
                self.cache.lock().unwrap().insert(identity.sha256.clone(), decision);
                decision
            }
        }
    }
}

/// Escapes the five characters Pango/GLib markup treats specially.
/// `identity.comm` and `target` are both attacker-influenced (a process
/// picks its own comm string, and can name a file inside the vault
/// anything it likes before triggering access to it) and zenity's
/// `--text` renders Pango markup - without this, a crafted filename could
/// inject formatting into the dialog to misrepresent what's actually
/// being requested (CWE-451, UI misrepresentation of critical
/// information), e.g. hiding the real path or forging misleading text.
fn escape_markup(s: &str) -> String {
    s.chars().fold(String::with_capacity(s.len()), |mut acc, c| {
        match c {
            '&' => acc.push_str("&amp;"),
            '<' => acc.push_str("&lt;"),
            '>' => acc.push_str("&gt;"),
            '\'' => acc.push_str("&apos;"),
            '"' => acc.push_str("&quot;"),
            _ => acc.push(c),
        }
        acc
    })
}

fn dialog_text(identity: &ProcessIdentity, target: &Path) -> String {
    // The user decides on a recognisable name + path; the short hash makes
    // it clear *which exact binary* an "Always Allow" will pin (the match
    // is on the full hash, never the path).
    let short_hash: String = identity.sha256.chars().take(12).collect();
    format!(
        "{} ({})\nsha256: {}…\n\nwants to access:\n{}\n\nAllow?",
        escape_markup(&identity.comm),
        escape_markup(&identity.path.display().to_string()),
        escape_markup(&short_hash),
        escape_markup(&target.display().to_string())
    )
}

/// Whether there's any plausible way to show a GUI dialog right now.
/// zenity is a GTK app: with no session bus *and* no display it doesn't
/// fail fast, it can block indefinitely in D-Bus autolaunch - which, on a
/// single call path feeding a security gate, is worse than a clean denial.
/// So if none of these are set we skip zenity entirely and fail closed.
fn gui_env_available(var: impl Fn(&str) -> Option<String>) -> bool {
    let set = |k: &str| var(k).map(|v| !v.is_empty()).unwrap_or(false);
    set("DBUS_SESSION_BUS_ADDRESS") || set("DISPLAY") || set("WAYLAND_DISPLAY")
}

/// Seconds a prompt may sit unanswered before it auto-denies. Keeps a
/// worker thread from being pinned forever by a dialog nobody sees or
/// answers. Override with `ATTACHE_PROMPT_TIMEOUT`.
fn prompt_timeout_secs() -> u32 {
    std::env::var("ATTACHE_PROMPT_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120)
}

/// Prompts the user via a `zenity` GUI dialog. Fails closed (Deny) if there's
/// no GUI session, if zenity is missing or errors, or if the dialog goes
/// unanswered past the timeout — since this is a security gate. The GUI
/// launch itself isn't unit-tested here (it opens a real dialog), but
/// `gui_env_available` and the dialog text (`dialog_text`/`escape_markup`)
/// are tested below, and the caching/decision logic it feeds is covered by
/// the `AuthPolicy` tests above.
pub struct ZenityPrompter;

impl Prompter for ZenityPrompter {
    fn ask(&self, identity: &ProcessIdentity, target: &Path) -> PromptResponse {
        if !gui_env_available(|k| std::env::var(k).ok()) {
            // No dialog can be shown - and trying anyway risks hanging this
            // worker in GTK's D-Bus autolaunch. This is the case
            // `att allow --always <path>` exists to work around.
            log::warn!(
                "no GUI session (DBUS_SESSION_BUS_ADDRESS/DISPLAY/WAYLAND_DISPLAY all unset) \
                 - denying {:?} by default; use `att allow --always <path>` to pre-approve \
                 binaries where there's no dialog to show",
                identity.path
            );
            return PromptResponse::Deny;
        }

        let timeout_secs = prompt_timeout_secs();
        let text = dialog_text(identity, target);
        // zenity only reports a distinct exit status for its two built-in
        // buttons (0 = ok, 1 = cancel), so the extra "Always Allow" button
        // is told apart by capturing stdout: pressing it prints its own
        // label there (still with exit status 1, same as Cancel).
        // `--timeout` makes zenity exit 5 if left unanswered.
        let output = std::process::Command::new("zenity")
            .arg("--question")
            .arg("--title=Attache Access Request")
            .arg(format!("--text={text}"))
            .arg("--ok-label=Allow Once")
            .arg("--cancel-label=Deny")
            .arg("--extra-button=Always Allow")
            .arg(format!("--timeout={timeout_secs}"))
            .output();

        match output {
            Ok(output) if output.status.success() => PromptResponse::AllowOnce,
            Ok(output) if String::from_utf8_lossy(&output.stdout).trim() == "Always Allow" => {
                PromptResponse::AllowAlways
            }
            Ok(output) if output.status.code() == Some(5) => {
                // zenity's timeout exit status: the dialog was shown but
                // nobody answered in time. Logged distinctly from an
                // explicit Deny so `att denied` readers can tell "ignored"
                // from "refused".
                log::warn!(
                    "access prompt for {:?} went unanswered for {timeout_secs}s - denying",
                    identity.path
                );
                PromptResponse::Deny
            }
            Ok(_) => PromptResponse::Deny, // explicit Cancel/Deny click
            Err(e) => {
                log::warn!(
                    "zenity unavailable ({e}) - denying by default; \
                     use `att allow --always <path>` to pre-approve binaries \
                     where there's no GUI to prompt on"
                );
                PromptResponse::Deny
            }
        }
    }
}

/// Confirms an out-of-band admin action from `control.rs` (e.g. "`attache
/// allow` wants to whitelist X") - conceptually similar to `Prompter` but
/// for a request that isn't tied to a live file-access attempt by a
/// specific process, so it doesn't fit that trait's (identity, target)
/// shape. Deliberately its own trait rather than an overload: a socket
/// connection being owner-only (0600) restricts *which user* can reach
/// it, not *which process* running as that user does, so without a real
/// human confirming every such request the same way they confirm a live
/// one, any locally-running process could silently whitelist itself with
/// no human involved at all.
pub trait ControlConfirm {
    fn confirm(&self, action: &str) -> bool;
}

pub struct ZenityConfirm;

impl ControlConfirm for ZenityConfirm {
    fn confirm(&self, action: &str) -> bool {
        let text = escape_markup(action);
        matches!(
            std::process::Command::new("zenity")
                .arg("--question")
                .arg("--title=Attache Control Request")
                .arg(format!("--text={text}"))
                .arg("--ok-label=Confirm")
                .arg("--cancel-label=Deny")
                .status(),
            Ok(status) if status.success()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    struct CountingPrompter {
        calls: AtomicUsize,
        answer: PromptResponse,
    }

    impl CountingPrompter {
        fn new(answer: PromptResponse) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                answer,
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Prompter for CountingPrompter {
        fn ask(&self, _identity: &ProcessIdentity, _target: &Path) -> PromptResponse {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.answer
        }
    }

    /// A no-vault whitelist backed by an empty temp dir, for tests that
    /// only care about the in-memory cache, not persistence.
    fn empty_whitelist() -> Whitelist {
        Whitelist::load(tempfile::tempdir().unwrap().path())
    }

    /// A synthetic identity for cache/prompt tests that don't care about a
    /// real binary: the hash is derived from the string so it's stable and
    /// unique per `bin`.
    fn identity(bin: &str) -> ProcessIdentity {
        ProcessIdentity {
            path: PathBuf::from(bin),
            comm: bin.to_string(),
            sha256: format!("hash-of::{bin}"),
        }
    }

    /// An identity built the way `ProcResolver::resolve` would: the hash is
    /// of the file's real, current contents. Use this when a test swaps the
    /// binary and needs the swap to be visible.
    fn identity_at(path: &Path) -> ProcessIdentity {
        ProcessIdentity {
            path: path.to_path_buf(),
            comm: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            sha256: crate::whitelist::hash_file(path).expect("hash the test binary"),
        }
    }

    #[test]
    fn first_access_asks_the_prompter() {
        let policy = AuthPolicy::new(CountingPrompter::new(PromptResponse::AllowOnce), empty_whitelist());

        let decision = policy.decide(&identity("/usr/bin/cat"), Path::new("/vault/a.txt"));

        assert_eq!(decision, Decision::Allow);
        assert_eq!(policy.prompter.call_count(), 1);
    }

    #[test]
    fn second_access_from_same_binary_uses_cache() {
        let policy = AuthPolicy::new(CountingPrompter::new(PromptResponse::AllowOnce), empty_whitelist());
        let bin = identity("/usr/bin/cat");

        policy.decide(&bin, Path::new("/vault/a.txt"));
        let decision = policy.decide(&bin, Path::new("/vault/b.txt"));

        assert_eq!(decision, Decision::Allow);
        assert_eq!(policy.prompter.call_count(), 1);
    }

    #[test]
    fn denial_is_also_cached() {
        let policy = AuthPolicy::new(CountingPrompter::new(PromptResponse::Deny), empty_whitelist());
        let bin = identity("/usr/bin/evil");

        let first = policy.decide(&bin, Path::new("/vault/a.txt"));
        let second = policy.decide(&bin, Path::new("/vault/a.txt"));

        assert_eq!(first, Decision::Deny);
        assert_eq!(second, Decision::Deny);
        assert_eq!(policy.prompter.call_count(), 1);
    }

    #[test]
    fn different_binaries_are_prompted_independently() {
        let policy = AuthPolicy::new(CountingPrompter::new(PromptResponse::AllowOnce), empty_whitelist());

        policy.decide(&identity("/usr/bin/cat"), Path::new("/vault/a.txt"));
        policy.decide(&identity("/usr/bin/vim"), Path::new("/vault/a.txt"));

        assert_eq!(policy.prompter.call_count(), 2);
    }

    #[test]
    fn allow_always_persists_to_the_whitelist_and_is_not_reprompted() {
        let backing = tempfile::tempdir().unwrap();
        let bin_path = backing.path().join("trusted-tool");
        std::fs::write(&bin_path, b"a real binary").unwrap();
        let bin = identity_at(&bin_path);

        let policy = AuthPolicy::new(
            CountingPrompter::new(PromptResponse::AllowAlways),
            Whitelist::load(backing.path()),
        );
        let first = policy.decide(&bin, Path::new("/vault/a.txt"));
        assert_eq!(first, Decision::Allow);
        assert_eq!(policy.prompter.call_count(), 1);

        // a fresh policy over the same vault (as if the gate restarted)
        // must not need to prompt again — it picks the approval up from
        // the persisted whitelist.
        let restarted = AuthPolicy::new(
            CountingPrompter::new(PromptResponse::Deny),
            Whitelist::load(backing.path()),
        );
        let second = restarted.decide(&bin, Path::new("/vault/b.txt"));
        assert_eq!(second, Decision::Allow);
        assert_eq!(restarted.prompter.call_count(), 0);
    }

    /// Returns each answer in `answers` in turn (one per call), so a test
    /// can tell "re-prompted with a new answer" apart from "served a
    /// stale cached one".
    struct SequencedPrompter {
        answers: Mutex<std::collections::VecDeque<PromptResponse>>,
        calls: AtomicUsize,
    }

    impl SequencedPrompter {
        fn new(answers: impl IntoIterator<Item = PromptResponse>) -> Self {
            Self {
                answers: Mutex::new(answers.into_iter().collect()),
                calls: AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Prompter for SequencedPrompter {
        fn ask(&self, _identity: &ProcessIdentity, _target: &Path) -> PromptResponse {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.answers
                .lock()
                .unwrap()
                .pop_front()
                .expect("prompter called more times than answers were queued")
        }
    }

    #[test]
    fn binary_swapped_after_allow_always_is_reprompted_not_served_from_cache() {
        let backing = tempfile::tempdir().unwrap();
        let bin_path = backing.path().join("trusted-tool");
        std::fs::write(&bin_path, b"the real binary").unwrap();

        let policy = AuthPolicy::new(
            SequencedPrompter::new([PromptResponse::AllowAlways, PromptResponse::Deny]),
            Whitelist::load(backing.path()),
        );

        let first = policy.decide(&identity_at(&bin_path), Path::new("/vault/a.txt"));
        assert_eq!(first, Decision::Allow);
        assert_eq!(policy.prompter.call_count(), 1);

        // attacker (or anything else able to write to this path) swaps
        // the trusted binary's content out from under its own approval,
        // still within the same mount session. `resolve` re-hashes
        // /proc/<pid>/exe every request, so the identity changes with it.
        std::fs::write(&bin_path, b"a malicious payload").unwrap();

        // must be re-prompted (not served the earlier session-cached
        // Allow) precisely because the hash no longer matches - and this
        // time the user says Deny.
        let second = policy.decide(&identity_at(&bin_path), Path::new("/vault/b.txt"));
        assert_eq!(second, Decision::Deny);
        assert_eq!(policy.prompter.call_count(), 2);
    }

    /// Blocks `ask()` for one specific binary path until the test releases
    /// it, so the test can hold a prompt open indefinitely on purpose;
    /// answers instantly (`AllowOnce`) for any other binary.
    struct SelectivelyBlockingPrompter {
        block_path: PathBuf,
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<PromptResponse>>,
    }

    impl Prompter for SelectivelyBlockingPrompter {
        fn ask(&self, identity: &ProcessIdentity, _target: &Path) -> PromptResponse {
            if identity.path == self.block_path {
                self.entered.send(()).unwrap();
                self.release.lock().unwrap().recv().unwrap()
            } else {
                PromptResponse::AllowOnce
            }
        }
    }

    #[test]
    fn cached_binary_is_not_blocked_by_a_concurrent_prompt_for_another_binary() {
        let block_path = PathBuf::from("/usr/bin/unknown");
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<PromptResponse>();
        let prompter = SelectivelyBlockingPrompter {
            block_path: block_path.clone(),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        };
        let policy = Arc::new(AuthPolicy::new(prompter, empty_whitelist()));

        // warm the cache for a different, unrelated, already-decided binary
        let cached_bin = identity("/usr/bin/cat");
        assert_eq!(
            policy.decide(&cached_bin, Path::new("/vault/a.txt")),
            Decision::Allow
        );

        // occupy the prompter with a dialog for a *different* binary that
        // this test controls when (if ever) it gets answered
        let blocked_policy = Arc::clone(&policy);
        let blocking_identity = identity("/usr/bin/unknown");
        let handle = thread::spawn(move || {
            blocked_policy.decide(&blocking_identity, Path::new("/vault/b.txt"))
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the blocking prompt never started");

        // a concurrent access for the already-cached binary must not be
        // stuck behind that unrelated, still-unanswered prompt - bounded
        // wait rather than a plain call, so a regression fails this test
        // instead of hanging it
        let (done_tx, done_rx) = mpsc::channel();
        let check_policy = Arc::clone(&policy);
        let cached_bin_2 = cached_bin.clone();
        thread::spawn(move || {
            let decision = check_policy.decide(&cached_bin_2, Path::new("/vault/c.txt"));
            let _ = done_tx.send(decision);
        });
        let decision = done_rx
            .recv_timeout(Duration::from_millis(500))
            .expect("cached access was blocked behind an unrelated pending prompt");
        assert_eq!(decision, Decision::Allow);

        // let the blocked thread finish cleanly
        release_tx.send(PromptResponse::Deny).unwrap();
        assert_eq!(handle.join().unwrap(), Decision::Deny);
    }

    #[test]
    fn gui_env_unavailable_when_display_and_bus_all_unset() {
        let env: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        assert!(!gui_env_available(|k| env.get(k).map(|s| s.to_string())));
    }

    #[test]
    fn gui_env_unavailable_when_vars_present_but_empty() {
        let env: std::collections::HashMap<&str, &str> =
            [("DISPLAY", ""), ("WAYLAND_DISPLAY", ""), ("DBUS_SESSION_BUS_ADDRESS", "")]
                .into_iter()
                .collect();
        assert!(!gui_env_available(|k| env.get(k).map(|s| s.to_string())));
    }

    #[test]
    fn gui_env_available_with_any_one_of_display_wayland_or_bus() {
        for key in ["DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS"] {
            let env: std::collections::HashMap<&str, &str> = [(key, "something")].into_iter().collect();
            assert!(
                gui_env_available(|k| env.get(k).map(|s| s.to_string())),
                "expected available when {key} is set"
            );
        }
    }

    #[test]
    fn escape_markup_neutralizes_pango_special_characters() {
        assert_eq!(
            escape_markup("<b>fake system dialog</b> & \"quoted\" 'text'"),
            "&lt;b&gt;fake system dialog&lt;/b&gt; &amp; &quot;quoted&quot; &apos;text&apos;"
        );
    }

    #[test]
    fn escape_markup_leaves_plain_text_unchanged() {
        assert_eq!(escape_markup("cat (/usr/bin/cat)"), "cat (/usr/bin/cat)");
    }

    #[test]
    fn dialog_text_escapes_an_attacker_chosen_filename() {
        let identity = ProcessIdentity {
            path: PathBuf::from("/usr/bin/cat"),
            comm: "cat".to_string(),
            sha256: "0".repeat(64),
        };
        // a malicious process can name a vault file (or itself) whatever
        // it likes before triggering access to it
        let target = Path::new("/vault/<b>Security Update Required</b>.txt");

        let text = dialog_text(&identity, target);

        assert!(!text.contains('<'), "raw markup leaked into the dialog text: {text}");
        assert!(!text.contains('>'), "raw markup leaked into the dialog text: {text}");
        assert!(text.contains("&lt;b&gt;Security Update Required&lt;/b&gt;.txt"));
    }
}
