use std::path::PathBuf;

/// Identity of the process making a filesystem request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub path: PathBuf,
    pub comm: String,
}

/// Resolves a PID to the identity of the process running it.
pub trait ProcessResolver {
    fn resolve(&self, pid: u32) -> Option<ProcessIdentity>;
}

/// Resolves process identity via `/proc/<pid>/exe` and `/proc/<pid>/comm`.
pub struct ProcResolver;

impl ProcessResolver for ProcResolver {
    fn resolve(&self, pid: u32) -> Option<ProcessIdentity> {
        let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        Some(ProcessIdentity { path, comm })
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
}
