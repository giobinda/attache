use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::process_info::ProcessIdentity;

/// Name of the whitelist file inside the vault's backing directory.
/// `PassthroughFs` refuses all FUSE access to any path with this file name
/// (see `passthrough_fs::is_protected`), so it can't be read, overwritten,
/// or deleted by a process operating through the mounted vault - only by
/// this gate process itself, which touches the backing directory directly.
pub const WHITELIST_FILENAME: &str = ".attache-gate-whitelist.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WhitelistEntry {
    path: PathBuf,
    comm: String,
    /// Hex-encoded SHA-256 of the binary's contents at approval time. This
    /// is the *only* field matched on: a binary later swapped out (same
    /// path or not) no longer matches and loses its approval.
    sha256: String,
    added_at: u64,
}

/// Persistent record of binaries the user has approved for "always allow"
/// access to this vault. Lives inside the vault's own backing directory
/// (rather than e.g. the user's home config) so the whitelist travels with
/// the vault and can't be tampered with from outside it.
pub struct Whitelist {
    file: PathBuf,
    entries: Vec<WhitelistEntry>,
}

impl Whitelist {
    /// Loads the whitelist from `<backing_root>/.attache-gate-whitelist.json`.
    /// A missing or unreadable/corrupt file is treated as an empty
    /// whitelist rather than an error, since a fresh vault has none yet.
    pub fn load(backing_root: &Path) -> Self {
        let file = backing_root.join(WHITELIST_FILENAME);
        let entries = fs::read(&file)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self { file, entries }
    }

    /// True if any entry records this exact hex SHA-256. Cheap: in-memory
    /// string compare, no file I/O.
    pub fn contains_sha256(&self, sha256: &str) -> bool {
        self.entries.iter().any(|e| e.sha256 == sha256)
    }

    /// True if `identity`'s binary contents were previously approved.
    ///
    /// Matches on the content hash alone, not the path: the hash is computed
    /// once by `ProcResolver::resolve` from `/proc/<pid>/exe` (which works
    /// across mount namespaces), so this holds for sandboxed callers -
    /// Flatpak/Snap/AppImage - whose reported path (`/app/...`) doesn't
    /// exist outside their own namespace. Swapping the binary's bytes
    /// changes the hash and revokes the approval; the stored `path`/`comm`
    /// are advisory labels only.
    pub fn is_allowed(&self, identity: &ProcessIdentity) -> bool {
        self.contains_sha256(&identity.sha256)
    }

    /// Records `identity`'s binary as always-allowed (keyed on its content
    /// hash) and persists the whitelist. Trusts `identity.sha256` - the
    /// caller computed it, either from `/proc/<pid>/exe` (`resolve`) or by
    /// hashing a real path (`att allow --always`).
    pub fn add(&mut self, identity: &ProcessIdentity) -> io::Result<()> {
        let added_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.entries.retain(|e| e.sha256 != identity.sha256);
        self.entries.push(WhitelistEntry {
            path: identity.path.clone(),
            comm: identity.comm.clone(),
            sha256: identity.sha256.clone(),
            added_at,
        });
        self.persist()
    }

    /// Removes every entry and persists the (now empty) whitelist to disk
    /// - used by the control socket's RESET-WHITELIST, where (unlike the
    /// closed-vault `att reset-whitelist` path) there's a live
    /// `Whitelist` in memory that must stay in sync with whatever's on
    /// disk, not just a file to delete.
    pub fn clear(&mut self) -> io::Result<()> {
        self.entries.clear();
        self.persist()
    }

    fn persist(&self) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(&self.entries)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        // Write to a temp file and rename (atomic on the same filesystem),
        // so a crash mid-write can't leave a truncated/corrupt whitelist.
        let tmp = self.file.with_extension("json.tmp");
        fs::write(&tmp, json)?;
        fs::rename(&tmp, &self.file)
    }
}

/// Hex-encoded SHA-256 of everything `r` yields. Streamed, so it's fine on
/// a large binary; used to hash `/proc/<pid>/exe` (an openable magic
/// symlink) as well as plain files.
pub fn hash_reader<R: io::Read>(mut r: R) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Hex-encoded SHA-256 of the file at `path`.
pub fn hash_file(path: &Path) -> io::Result<String> {
    hash_reader(fs::File::open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_bin(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    /// Mirrors what `ProcResolver::resolve` builds: the hash is of the
    /// file's current contents. Falls back to a path-derived placeholder if
    /// the path doesn't exist, so tests can model a sandboxed binary.
    fn identity(path: PathBuf) -> ProcessIdentity {
        let sha256 = hash_file(&path).unwrap_or_else(|_| format!("no-file::{}", path.display()));
        ProcessIdentity {
            path,
            comm: "test".to_string(),
            sha256,
        }
    }

    #[test]
    fn unknown_binary_is_not_allowed() {
        let backing = tempfile::tempdir().unwrap();
        let bin = write_bin(backing.path(), "cat", b"binary-a");

        let whitelist = Whitelist::load(backing.path());

        assert!(!whitelist.is_allowed(&identity(bin)));
    }

    #[test]
    fn approved_binary_is_allowed() {
        let backing = tempfile::tempdir().unwrap();
        let bin = write_bin(backing.path(), "cat", b"binary-a");
        let mut whitelist = Whitelist::load(backing.path());

        whitelist.add(&identity(bin.clone())).unwrap();

        assert!(whitelist.is_allowed(&identity(bin)));
    }

    #[test]
    fn approval_survives_reload_from_disk() {
        let backing = tempfile::tempdir().unwrap();
        let bin = write_bin(backing.path(), "cat", b"binary-a");
        let mut whitelist = Whitelist::load(backing.path());
        whitelist.add(&identity(bin.clone())).unwrap();

        let reloaded = Whitelist::load(backing.path());

        assert!(reloaded.is_allowed(&identity(bin)));
    }

    #[test]
    fn swapped_binary_at_the_same_path_loses_approval() {
        let backing = tempfile::tempdir().unwrap();
        let bin = write_bin(backing.path(), "cat", b"binary-a");
        let mut whitelist = Whitelist::load(backing.path());
        whitelist.add(&identity(bin.clone())).unwrap();

        // attacker replaces the trusted binary in place
        fs::write(&bin, b"malicious-payload").unwrap();

        assert!(!whitelist.is_allowed(&identity(bin)));
    }

    #[test]
    fn same_contents_different_path_is_allowed() {
        // Deliberate model change (v0.1.2): approval is keyed on the
        // binary's *bytes*, not its path - a path can't be a boundary for
        // sandboxed callers whose /proc/<pid>/exe is namespace-local. A
        // byte-identical binary elsewhere is the same program, so it's
        // allowed; different bytes are not (see below).
        let backing = tempfile::tempdir().unwrap();
        let trusted = write_bin(backing.path(), "cat", b"binary-a");
        let mut whitelist = Whitelist::load(backing.path());
        whitelist.add(&identity(trusted)).unwrap();

        let elsewhere = tempfile::tempdir().unwrap();
        let same_bytes = write_bin(elsewhere.path(), "cat", b"binary-a");
        assert!(whitelist.is_allowed(&identity(same_bytes)));

        let different_bytes = write_bin(elsewhere.path(), "dog", b"binary-b");
        assert!(!whitelist.is_allowed(&identity(different_bytes)));
    }

    #[test]
    fn approval_matches_by_hash_even_when_the_path_no_longer_resolves() {
        // The Flatpak/Snap case: /proc/<pid>/exe reads `/app/.../FreeCAD`,
        // which doesn't exist in the gate's namespace. `add` must not need
        // to touch that path, and `is_allowed` must still match it later.
        let backing = tempfile::tempdir().unwrap();
        let sandboxed = ProcessIdentity {
            path: PathBuf::from("/app/freecad/bin/FreeCAD"),
            comm: "FreeCAD".to_string(),
            sha256: "a".repeat(64),
        };

        let mut whitelist = Whitelist::load(backing.path());
        whitelist.add(&sandboxed).unwrap();
        assert!(whitelist.is_allowed(&sandboxed));
        assert!(Whitelist::load(backing.path()).is_allowed(&sandboxed));
    }

    #[test]
    fn clear_removes_entries_in_memory_and_on_disk() {
        let backing = tempfile::tempdir().unwrap();
        let bin = write_bin(backing.path(), "cat", b"binary-a");
        let mut whitelist = Whitelist::load(backing.path());
        whitelist.add(&identity(bin.clone())).unwrap();
        assert!(whitelist.is_allowed(&identity(bin.clone())));

        whitelist.clear().unwrap();

        assert!(!whitelist.is_allowed(&identity(bin.clone())));
        let reloaded = Whitelist::load(backing.path());
        assert!(!reloaded.is_allowed(&identity(bin)));
    }
}
