use std::path::PathBuf;

use crate::whitelist::hash_reader;

/// Identity of the process making a filesystem request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// The `/proc/<pid>/exe` target. For a sandboxed caller (Flatpak/Snap/
    /// AppImage) this is namespace-local and may not exist in our own view
    /// - it's a human-readable label only, never the thing we match on.
    pub path: PathBuf,
    /// `/proc/<pid>/comm` - the short program name shown in the prompt.
    pub comm: String,
    /// Hex SHA-256 of the binary's actual bytes, read through the openable
    /// `/proc/<pid>/exe` magic symlink (works across mount namespaces).
    /// This is the whitelist's match key.
    pub sha256: String,
}

/// Resolves a PID to the identity of the process running it.
pub trait ProcessResolver {
    fn resolve(&self, pid: u32) -> Option<ProcessIdentity>;
}

/// Resolves process identity via `/proc/<pid>/exe` and `/proc/<pid>/comm`.
pub struct ProcResolver;

impl ProcessResolver for ProcResolver {
    fn resolve(&self, pid: u32) -> Option<ProcessIdentity> {
        let exe = format!("/proc/{pid}/exe");
        // `read_link` gives a display label; opening the same magic symlink
        // gives the real executable inode even when that path is only valid
        // inside the caller's mount namespace. If we can't hash the binary
        // we can't safely identify it - return None, which `authorize`
        // treats as a denial.
        let path = std::fs::read_link(&exe).ok()?;
        let sha256 = hash_reader(std::fs::File::open(&exe).ok()?).ok()?;
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        Some(ProcessIdentity { path, comm, sha256 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn canonical(p: &Path) -> PathBuf {
        std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
    }

    #[test]
    fn resolves_current_process_to_its_own_executable() {
        let resolver = ProcResolver;
        let pid = std::process::id();

        let identity = resolver.resolve(pid).expect("should resolve own pid");

        let expected = canonical(&std::env::current_exe().unwrap());
        assert_eq!(canonical(&identity.path), expected);
    }

    #[test]
    fn resolve_hashes_the_running_binary() {
        let identity = ProcResolver
            .resolve(std::process::id())
            .expect("should resolve own pid");

        let via_path = crate::whitelist::hash_file(&std::env::current_exe().unwrap()).unwrap();
        assert_eq!(identity.sha256, via_path);
        assert_eq!(identity.sha256.len(), 64);
    }
}
