use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
    cache: Mutex<HashMap<PathBuf, Decision>>,
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
        // Checked - and its hash re-verified - on *every* call, never
        // served from the session cache below: caching this would let a
        // binary swapped out at an already-approved path silently inherit
        // the old decision for the rest of the mount's lifetime, which is
        // exactly what the hash-pinning in Whitelist::is_allowed exists to
        // catch. The cache still helps for the common case (repeated
        // access from the same already-verified whitelisted binary isn't
        // actually free - it re-hashes the file - but it's the only way
        // this guarantee holds every time, not just on first use).
        if self.whitelist.lock().unwrap().is_allowed(identity) {
            return Decision::Allow;
        }

        // Non-whitelisted binaries: prompt once per mount session and
        // cache that answer, same as before - this cache never carries
        // the hash-pinning guarantee (an "Allow Once"/"Always Allow" here
        // are answers to a live GUI prompt the user just saw, not a
        // persisted trust decision), so there's nothing it can silently
        // downgrade.
        if let Some(decision) = self.cache.lock().unwrap().get(&identity.path) {
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
                self.cache.lock().unwrap().insert(identity.path.clone(), decision);
                decision
            }
            PromptResponse::AllowAlways => {
                // Deliberately never inserted into `cache`: the whitelist
                // check at the top of this function is now the source of
                // truth for this path, re-verified (hash included) on
                // every call. Caching a plain Allow here under the same
                // key would let a binary later swapped out at this path
                // fall through to a stale cache hit instead of being
                // re-checked - exactly the bug this function's first
                // check exists to prevent.
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
                self.cache.lock().unwrap().insert(identity.path.clone(), decision);
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
    format!(
        "{} ({}) wants to access:\n{}\n\nAllow?",
        escape_markup(&identity.comm),
        escape_markup(&identity.path.display().to_string()),
        escape_markup(&target.display().to_string())
    )
}

/// Prompts the user via a `zenity` GUI dialog. Fails closed (Deny) if zenity
/// is missing or errors, since this is a security gate — the GUI launch
/// itself isn't unit-tested here (it opens a real dialog), but the dialog
/// text is built by `dialog_text`/`escape_markup`, which are tested below;
/// the caching/decision logic it all feeds into is covered by the
/// `AuthPolicy` tests above.
pub struct ZenityPrompter;

impl Prompter for ZenityPrompter {
    fn ask(&self, identity: &ProcessIdentity, target: &Path) -> PromptResponse {
        let text = dialog_text(identity, target);
        // zenity only reports a distinct exit status for its two built-in
        // buttons (0 = ok, 1 = cancel), so the extra "Always Allow" button
        // is told apart by capturing stdout: pressing it prints its own
        // label there (still with exit status 1, same as Cancel).
        let output = std::process::Command::new("zenity")
            .arg("--question")
            .arg("--title=Attache Access Request")
            .arg(format!("--text={text}"))
            .arg("--ok-label=Allow Once")
            .arg("--cancel-label=Deny")
            .arg("--extra-button=Always Allow")
            .output();

        match output {
            Ok(output) if output.status.success() => PromptResponse::AllowOnce,
            Ok(output) if String::from_utf8_lossy(&output.stdout).trim() == "Always Allow" => {
                PromptResponse::AllowAlways
            }
            Ok(_) => PromptResponse::Deny, // explicit Cancel/Deny click
            Err(e) => {
                // zenity itself couldn't even run (missing, no DISPLAY, ...)
                // - distinct from a user's explicit Deny click, and the
                // one case `att allow --always <path>` exists to work
                // around: in a CLI-only environment, this fires for every
                // not-yet-whitelisted binary, since there's no dialog to
                // show at all.
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

    fn identity(bin: &str) -> ProcessIdentity {
        ProcessIdentity {
            path: PathBuf::from(bin),
            comm: bin.to_string(),
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
        let bin = ProcessIdentity {
            path: bin_path,
            comm: "trusted-tool".to_string(),
        };

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
        let bin = ProcessIdentity {
            path: bin_path.clone(),
            comm: "trusted-tool".to_string(),
        };

        let policy = AuthPolicy::new(
            SequencedPrompter::new([PromptResponse::AllowAlways, PromptResponse::Deny]),
            Whitelist::load(backing.path()),
        );

        let first = policy.decide(&bin, Path::new("/vault/a.txt"));
        assert_eq!(first, Decision::Allow);
        assert_eq!(policy.prompter.call_count(), 1);

        // attacker (or anything else able to write to this path) swaps
        // the trusted binary's content out from under its own approval,
        // still within the same mount session.
        std::fs::write(&bin_path, b"a malicious payload").unwrap();

        // must be re-prompted (not served the earlier session-cached
        // Allow) precisely because the hash no longer matches - and this
        // time the user says Deny.
        let second = policy.decide(&bin, Path::new("/vault/b.txt"));
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
        let blocking_identity = ProcessIdentity {
            path: block_path,
            comm: "unknown".to_string(),
        };
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
