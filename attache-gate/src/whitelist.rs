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
    /// Hex-encoded SHA-256 of the binary's contents at the time it was
    /// approved. Matching on this (not just `path`) means a binary later
    /// swapped out at the same path - e.g. an attacker overwriting a
    /// previously-trusted executable - loses its approval instead of
    /// silently inheriting it.
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

    /// True if `identity`'s binary was previously approved *and* its
    /// current on-disk contents still match the hash recorded at approval
    /// time.
    pub fn is_allowed(&self, identity: &ProcessIdentity) -> bool {
        let Some(entry) = self.entries.iter().find(|e| e.path == identity.path) else {
            return false;
        };
        matches!(hash_file(&identity.path), Ok(hash) if hash == entry.sha256)
    }

    /// Records `identity` as always-allowed and persists the whitelist to
    /// disk. Hashes the binary fresh (rather than trusting a caller-supplied
    /// hash) so the stored value always reflects what was actually approved.
    pub fn add(&mut self, identity: &ProcessIdentity) -> io::Result<()> {
        let sha256 = hash_file(&identity.path)?;
        let added_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.entries.retain(|e| e.path != identity.path);
        self.entries.push(WhitelistEntry {
            path: identity.path.clone(),
            comm: identity.comm.clone(),
            sha256,
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

fn hash_file(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_bin(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    fn identity(path: PathBuf) -> ProcessIdentity {
        ProcessIdentity {
            path,
            comm: "test".to_string(),
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
    fn same_name_different_path_is_not_allowed() {
        let backing = tempfile::tempdir().unwrap();
        let trusted = write_bin(backing.path(), "cat", b"binary-a");
        let mut whitelist = Whitelist::load(backing.path());
        whitelist.add(&identity(trusted)).unwrap();

        let impostor_dir = tempfile::tempdir().unwrap();
        let impostor = write_bin(impostor_dir.path(), "cat", b"binary-a");

        assert!(!whitelist.is_allowed(&identity(impostor)));
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
