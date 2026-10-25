//! Duress-password hashing for `att`. The hash file lives *outside* the
//! cipherdir (`att` keeps it in its state dir): gocryptfs journals every
//! unrecognised name in the cipherdir root, which would leave a permanent
//! record that a duress password exists.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};

/// Deliberately heavier than argon2's defaults (19 MiB, t=2): the hash sits
/// in plaintext on disk, so anyone holding a copy of it can try to guess
/// the duress password offline. Recovering it doesn't decrypt anything, but
/// it does tell a coercer which password to avoid. Costs ~0.15s, and only
/// on an `att open` whose password already failed.
const M_COST_KIB: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

fn hasher() -> Argon2<'static> {
    let params = Params::new(M_COST_KIB, T_COST, P_COST, None)
        .expect("argon2 parameters are compile-time constants and valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hashes `password` with a fresh random salt and writes the PHC string to
/// `file` (mode 0600, replacing whatever was there).
pub fn set(file: &Path, password: &[u8]) -> io::Result<()> {
    let hash = hasher()
        .hash_password(password)
        .map_err(|e| io::Error::other(format!("argon2: {e}")))?;
    let tmp = file.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    writeln!(f, "{hash}")?;
    f.sync_all()?;
    fs::rename(&tmp, file)
}

/// True only if `file` holds a valid hash *and* `password` matches it.
/// Every failure mode (no file, unreadable, corrupt) is "no match": a
/// broken duress file must never be able to destroy the vault, it just
/// falls through to an ordinary open.
pub fn matches(file: &Path, password: &[u8]) -> bool {
    let Ok(contents) = fs::read_to_string(file) else {
        return false;
    };
    hasher()
        .verify_password(password, contents.trim())
        .is_ok()
}

/// Reads one line from stdin with its trailing newline stripped - the
/// same "first line is the password" convention gocryptfs's `-passfile`
/// uses, so `att` can feed both the same way and the password never
/// touches argv or the environment.
pub fn read_password_line() -> io::Result<Vec<u8>> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    if line.ends_with('\n') {
        line.pop();
    }
    Ok(line.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_only_the_password_that_was_set() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("duress");
        set(&file, b"run").unwrap();
        assert!(matches(&file, b"run"));
        assert!(!matches(&file, b"real-password"));
        assert!(!matches(&file, b""));
    }

    #[test]
    fn missing_or_corrupt_file_never_matches() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("duress");
        assert!(!matches(&file, b"anything"));
        fs::write(&file, "not a phc string\n").unwrap();
        assert!(!matches(&file, b"anything"));
    }

    #[test]
    fn hash_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("duress");
        set(&file, b"run").unwrap();
        let mode = fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
