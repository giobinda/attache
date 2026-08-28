use std::path::PathBuf;
use std::process::ExitCode;

use attache_import::{run, ImportOptions};

struct Args {
    source_dir: PathBuf,
    dest_home: Option<PathBuf>,
    force: bool,
}

fn parse_args(args: &[String]) -> Option<Args> {
    let mut iter = args.iter().skip(1);
    let source_dir = PathBuf::from(iter.next()?);
    let mut dest_home = None;
    let mut force = false;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--dest-home" => dest_home = Some(PathBuf::from(iter.next()?)),
            "--force" => force = true,
            _ => return None,
        }
    }
    Some(Args { source_dir, dest_home, force })
}

fn main() -> ExitCode {
    let raw_args: Vec<String> = std::env::args().collect();
    let Some(args) = parse_args(&raw_args) else {
        eprintln!(
            "Usage: {} <source-dir> [--dest-home <path>] [--force]",
            raw_args.first().map(String::as_str).unwrap_or("attache-import")
        );
        return ExitCode::FAILURE;
    };

    let dest_home = match args.dest_home.or_else(|| std::env::var_os("HOME").map(PathBuf::from)) {
        Some(h) => h,
        None => {
            eprintln!("error: --dest-home not given and $HOME is not set");
            return ExitCode::FAILURE;
        }
    };

    if !args.source_dir.is_dir() {
        eprintln!(
            "error: source dir does not exist or is not a directory: {}",
            args.source_dir.display()
        );
        return ExitCode::FAILURE;
    }

    let opts = ImportOptions {
        source_dir: &args.source_dir,
        dest_home: &dest_home,
        force: args.force,
    };

    match run(&opts) {
        Ok(summary) => {
            println!("verified {} file(s) against MANIFEST.sha256", summary.verified_files);
            println!("Attache installed at {}", summary.cipherdir.display());
            println!("binaries installed at {}", summary.bin_dir.display());
            println!();
            println!(
                "next: make sure {} is on PATH, then run `att open`",
                summary.bin_dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
