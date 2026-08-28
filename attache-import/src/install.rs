//! Guards against silently clobbering an existing Attache install on the target
//! machine when importing a new one.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationStatus {
    /// Absent or empty: safe to write into regardless of `--force`.
    Clear,
    /// Non-empty and `--force` was not given: refuse.
    NonEmptyRefused,
    /// Non-empty but `--force` was given: proceed anyway.
    NonEmptyForced,
}

impl DestinationStatus {
    pub fn is_safe(self) -> bool {
        !matches!(self, DestinationStatus::NonEmptyRefused)
    }
}

pub fn check_destination(cipherdir: &Path, force: bool) -> DestinationStatus {
    let has_entries = std::fs::read_dir(cipherdir)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);

    if !has_entries {
        DestinationStatus::Clear
    } else if force {
        DestinationStatus::NonEmptyForced
    } else {
        DestinationStatus::NonEmptyRefused
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonexistent_destination_is_clear() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");

        assert_eq!(check_destination(&missing, false), DestinationStatus::Clear);
        assert!(check_destination(&missing, false).is_safe());
    }

    #[test]
    fn empty_destination_is_clear() {
        let dir = tempfile::tempdir().unwrap();

        assert_eq!(check_destination(dir.path(), false), DestinationStatus::Clear);
        assert!(check_destination(dir.path(), false).is_safe());
    }

    #[test]
    fn non_empty_destination_without_force_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("existing.txt"), b"data").unwrap();

        let status = check_destination(dir.path(), false);

        assert_eq!(status, DestinationStatus::NonEmptyRefused);
        assert!(!status.is_safe());
    }

    #[test]
    fn non_empty_destination_with_force_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("existing.txt"), b"data").unwrap();

        let status = check_destination(dir.path(), true);

        assert_eq!(status, DestinationStatus::NonEmptyForced);
        assert!(status.is_safe());
    }
}
