//! Parsing and verification of the `MANIFEST.sha256` file burned alongside
//! the attache: a standard `sha256sum`-format manifest (`<hex>  <path>` per
//! line) used to detect disc rot or tampering before importing anything.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub hash: String,
    pub path: std::path::PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError {
    pub line_number: usize,
    pub line: String,
}

pub fn parse(text: &str) -> Result<Vec<ManifestEntry>, ParseError> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(i, line)| parse_line(line).ok_or_else(|| ParseError {
            line_number: i + 1,
            line: line.to_string(),
        }))
        .collect()
}

fn parse_line(line: &str) -> Option<ManifestEntry> {
    let (hash, path) = line.split_once("  ")?;
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if path.is_empty() {
        return None;
    }
    Some(ManifestEntry {
        hash: hash.to_lowercase(),
        path: std::path::PathBuf::from(path),
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub ok: Vec<std::path::PathBuf>,
    pub missing: Vec<std::path::PathBuf>,
    pub mismatched: Vec<std::path::PathBuf>,
}

impl VerifyReport {
    pub fn all_ok(&self) -> bool {
        self.missing.is_empty() && self.mismatched.is_empty()
    }
}

/// Verifies every manifest entry's file exists under `attache_dir` and its
/// SHA-256 matches. A file present on disk but *not* listed in the manifest
/// is not reported at all: the manifest asserts what it covers, and saying
/// nothing about extra files keeps this a content-integrity check rather
/// than a stricter "the disc must contain exactly this set" check, which
/// isn't the property we're protecting against disc rot / tampering.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn verify(attache_dir: &std::path::Path, entries: &[ManifestEntry]) -> VerifyReport {
    let mut report = VerifyReport::default();
    for entry in entries {
        let full_path = attache_dir.join(&entry.path);
        match std::fs::read(&full_path) {
            Ok(bytes) => {
                let digest = sha256_hex(&bytes);
                if digest == entry.hash {
                    report.ok.push(entry.path.clone());
                } else {
                    report.mismatched.push(entry.path.clone());
                }
            }
            Err(_) => report.missing.push(entry.path.clone()),
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_single_valid_line() {
        let hash = "a".repeat(64);
        let text = format!("{hash}  hello.txt");

        let entries = parse(&text).unwrap();

        assert_eq!(
            entries,
            vec![ManifestEntry {
                hash,
                path: std::path::PathBuf::from("hello.txt"),
            }]
        );
    }

    #[test]
    fn parses_multiple_lines_and_skips_blank_lines() {
        let hash_a = "a".repeat(64);
        let hash_b = "b".repeat(64);
        let text = format!("{hash_a}  a.txt\n\n{hash_b}  sub/b.txt\n");

        let entries = parse(&text).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].path, std::path::PathBuf::from("sub/b.txt"));
    }

    #[test]
    fn rejects_a_malformed_line() {
        let err = parse("not-a-valid-manifest-line").unwrap_err();

        assert_eq!(err.line_number, 1);
    }

    fn write_and_hash(dir: &std::path::Path, name: &str, content: &[u8]) -> ManifestEntry {
        std::fs::write(dir.join(name), content).unwrap();
        ManifestEntry {
            hash: sha256_hex(content),
            path: std::path::PathBuf::from(name),
        }
    }

    #[test]
    fn verify_reports_all_ok_when_files_match() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![
            write_and_hash(dir.path(), "a.txt", b"hello"),
            write_and_hash(dir.path(), "b.txt", b"world"),
        ];

        let report = verify(dir.path(), &entries);

        assert!(report.all_ok());
        assert_eq!(report.ok.len(), 2);
    }

    #[test]
    fn verify_reports_a_tampered_file_as_mismatched_others_still_ok() {
        let dir = tempfile::tempdir().unwrap();
        let good = write_and_hash(dir.path(), "good.txt", b"unchanged");
        let tampered = write_and_hash(dir.path(), "tampered.txt", b"original");
        // mutate the file after the manifest entry was computed
        std::fs::write(dir.path().join("tampered.txt"), b"tampered!").unwrap();

        let report = verify(dir.path(), &[good.clone(), tampered.clone()]);

        assert!(!report.all_ok());
        assert_eq!(report.ok, vec![good.path]);
        assert_eq!(report.mismatched, vec![tampered.path]);
        assert!(report.missing.is_empty());
    }

    #[test]
    fn verify_reports_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![ManifestEntry {
            hash: "a".repeat(64),
            path: std::path::PathBuf::from("never-written.txt"),
        }];

        let report = verify(dir.path(), &entries);

        assert!(!report.all_ok());
        assert_eq!(report.missing, vec![std::path::PathBuf::from("never-written.txt")]);
    }

    #[test]
    fn verify_ignores_extra_files_not_in_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let listed = write_and_hash(dir.path(), "listed.txt", b"content");
        std::fs::write(dir.path().join("unlisted.txt"), b"not in manifest").unwrap();

        let report = verify(dir.path(), &[listed]);

        assert!(report.all_ok());
    }
}
