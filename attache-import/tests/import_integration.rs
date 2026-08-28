//! Integration tests for the top-level `run` orchestration: build a fake
//! staging dir (what a mounted disc would look like) and a fake dest-home,
//! call the library function directly (no subprocess), and assert on the
//! resulting filesystem state.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use attache_import::{run, ImportError, ImportOptions};

fn write_manifest(staging: &Path, entries: &[(&str, &[u8])]) {
    let attache_dir = staging.join("attache");
    std::fs::create_dir_all(&attache_dir).unwrap();
    let mut manifest = String::new();
    for (rel_path, content) in entries {
        let full = attache_dir.join(rel_path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&full, content).unwrap();
        let hash = attache_import::manifest::sha256_hex(content);
        manifest.push_str(&format!("{hash}  {rel_path}\n"));
    }
    std::fs::write(staging.join("MANIFEST.sha256"), manifest).unwrap();
}

fn write_fake_binaries(staging: &Path) {
    let bin_dir = staging.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    for name in [
        "gocryptfs",
        "attache-gate",
        "attache-mount-helper",
        "att",
        "install-mount-helper.sh",
        "attache-import",
    ] {
        let path = bin_dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n# fake {name}\n")).unwrap();
        // deliberately non-executable on the source, to prove the
        // destination sets 0755 regardless of source permissions.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
}

#[test]
fn happy_path_verifies_copies_attache_and_installs_binaries() {
    let staging = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    write_manifest(staging.path(), &[("a.txt", b"hello"), ("sub/b.txt", b"world")]);
    write_fake_binaries(staging.path());

    let summary = run(&ImportOptions {
        source_dir: staging.path(),
        dest_home: dest.path(),
        force: false,
    })
    .unwrap();

    assert_eq!(summary.verified_files, 2);
    assert_eq!(summary.cipherdir, dest.path().join(".attache"));
    assert_eq!(summary.bin_dir, dest.path().join(".local").join("bin"));

    assert_eq!(
        std::fs::read_to_string(dest.path().join(".attache/a.txt")).unwrap(),
        "hello"
    );
    assert_eq!(
        std::fs::read_to_string(dest.path().join(".attache/sub/b.txt")).unwrap(),
        "world"
    );

    for name in [
        "gocryptfs",
        "attache-gate",
        "attache-mount-helper",
        "att",
        "install-mount-helper.sh",
    ] {
        let installed = dest.path().join(".local/bin").join(name);
        let mode = std::fs::metadata(&installed).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "{name} should be installed as 0755");
    }
    assert!(
        !dest.path().join(".local/bin/attache-import").exists(),
        "the installer itself should not be installed"
    );
}

#[test]
fn refuses_to_clobber_an_existing_non_empty_attache_without_force() {
    let staging = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    write_manifest(staging.path(), &[("a.txt", b"hello")]);
    write_fake_binaries(staging.path());

    let cipherdir = dest.path().join(".attache");
    std::fs::create_dir_all(&cipherdir).unwrap();
    std::fs::write(cipherdir.join("preexisting.bin"), b"do not touch me").unwrap();

    let err = run(&ImportOptions {
        source_dir: staging.path(),
        dest_home: dest.path(),
        force: false,
    })
    .unwrap_err();

    assert!(matches!(err, ImportError::DestinationRefused));
    // nothing changed: the pre-existing file is untouched, nothing from
    // staging was copied in, and the bin dir was never created.
    assert_eq!(
        std::fs::read_to_string(cipherdir.join("preexisting.bin")).unwrap(),
        "do not touch me"
    );
    assert!(!cipherdir.join("a.txt").exists());
    assert!(!dest.path().join(".local/bin").exists());

    let summary = run(&ImportOptions {
        source_dir: staging.path(),
        dest_home: dest.path(),
        force: true,
    })
    .unwrap();
    assert_eq!(summary.verified_files, 1);
    assert!(cipherdir.join("a.txt").exists());
}
