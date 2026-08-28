pub mod install;
pub mod manifest;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Binaries bundled on the disc under `bin/`, installed into
/// `<dest-home>/.local/bin`. `attache-import` itself is deliberately not in
/// this list: there is no reason to install the installer.
const BUNDLED_BINARIES: &[&str] = &[
    "gocryptfs",
    "attache-gate",
    "attache-mount-helper",
    "att",
    "install-mount-helper.sh",
];

pub struct ImportOptions<'a> {
    pub source_dir: &'a Path,
    pub dest_home: &'a Path,
    pub force: bool,
}

#[derive(Debug)]
pub struct ImportSummary {
    pub verified_files: usize,
    pub cipherdir: PathBuf,
    pub bin_dir: PathBuf,
}

#[derive(Debug)]
pub enum ImportError {
    ManifestParse(manifest::ParseError),
    IntegrityFailed(manifest::VerifyReport),
    DestinationRefused,
    Io(std::io::Error),
}

impl From<std::io::Error> for ImportError {
    fn from(e: std::io::Error) -> Self {
        ImportError::Io(e)
    }
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::ManifestParse(e) => {
                write!(f, "malformed MANIFEST.sha256 at line {}: {}", e.line_number, e.line)
            }
            ImportError::IntegrityFailed(report) => {
                writeln!(f, "attache integrity check failed:")?;
                for path in &report.missing {
                    writeln!(f, "  missing: {}", path.display())?;
                }
                for path in &report.mismatched {
                    writeln!(f, "  mismatched checksum: {}", path.display())?;
                }
                Ok(())
            }
            ImportError::DestinationRefused => write!(
                f,
                "destination already has an Attache installed; pass --force to overwrite, or choose a different --dest-home"
            ),
            ImportError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ImportError {}

pub fn run(opts: &ImportOptions) -> Result<ImportSummary, ImportError> {
    let manifest_text = std::fs::read_to_string(opts.source_dir.join("MANIFEST.sha256"))?;
    let entries = manifest::parse(&manifest_text).map_err(ImportError::ManifestParse)?;

    let attache_src = opts.source_dir.join("attache");
    let report = manifest::verify(&attache_src, &entries);
    if !report.all_ok() {
        return Err(ImportError::IntegrityFailed(report));
    }

    let cipherdir = opts.dest_home.join(".attache");
    if !install::check_destination(&cipherdir, opts.force).is_safe() {
        return Err(ImportError::DestinationRefused);
    }

    copy_dir_recursive(&attache_src, &cipherdir)?;

    let bin_dir = opts.dest_home.join(".local").join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    for name in BUNDLED_BINARIES {
        let dest_path = bin_dir.join(name);
        std::fs::copy(opts.source_dir.join("bin").join(name), &dest_path)?;
        std::fs::set_permissions(&dest_path, std::fs::Permissions::from_mode(0o755))?;
    }

    Ok(ImportSummary {
        verified_files: report.ok.len(),
        cipherdir,
        bin_dir,
    })
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let dest_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            std::fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}
