//! The paths bound gives a program (`BOUND_ROOT`, a bundled `PATH` entry,
//! its working directory) are spelled as the system reports paths inside
//! them, however the caller spells the cache and temporary directories:
//! canonical on Unix, in `GetFullPathNameW`'s form on Windows (where a
//! caller such as Git Bash writes `C:/Users/...`).

use std::fs;
use std::path::{Path, PathBuf};

use bound_tests::{Harness, Report, bins, os, run, same_path};

fn harness() -> Harness {
    Harness::new(bins!())
}

/// `dir` as a caller may spell it: with forward slashes on Windows, with a
/// `.` component on Unix.
fn unusual(dir: &Path) -> PathBuf {
    if cfg!(windows) { PathBuf::from(dir.to_string_lossy().replace('\\', "/")) } else { dir.join(".") }
}

/// Asserts that a path the program saw is spelled natively.
fn assert_native(what: &str, path: &str) {
    let native = if cfg!(windows) { !path.contains('/') } else { !path.split('/').any(|part| part == ".") };
    assert!(native, "{what}: {path}");
}

/// The paths a bundle's program saw: its bundle directory, the first entry
/// of its `PATH` and its working directory.
fn assert_paths_native(report: &Report) {
    assert_native("BOUND_ROOT", &report.env("BOUND_ROOT").unwrap());
    let path = report.env("PATH").unwrap();
    assert_native("PATH", path.split(if cfg!(windows) { ';' } else { ':' }).next().unwrap());
    assert_native("cwd", &report.cwd().to_string_lossy());
}

#[test]
fn a_shared_bundle_reaches_the_program_natively_spelled() {
    let h = harness();
    h.write("app/tools/x", "");
    let artifact = h.bind(
        "shared",
        os![
            "--bundle",
            "shared",
            "--include",
            "app",
            "--cwd",
            "@bundle:app",
            "--env-prepend",
            "PATH=@bundle:app/tools",
            "--",
            h.bins.fixture,
            "report"
        ],
    );
    let mut cmd = h.command(&artifact);
    cmd.env("BOUND_CACHE_DIR", unusual(&h.cache_dir()));
    let report = Report::parse(&run(&mut cmd));
    assert_paths_native(&report);
    // The bundle is in the cache the caller named.
    let root = PathBuf::from(report.env("BOUND_ROOT").unwrap());
    assert!(root.ancestors().any(|dir| same_path(dir, &h.cache_dir())), "{}", root.display());
}

#[test]
fn a_private_bundle_reaches_the_program_natively_spelled() {
    let h = harness();
    h.write("app/tools/x", "");
    let artifact = h.bind(
        "private",
        os![
            "--bundle",
            "private",
            "--include",
            "app",
            "--cwd",
            "@bundle:app",
            "--env-prepend",
            "PATH=@bundle:app/tools",
            "--",
            h.bins.fixture,
            "report"
        ],
    );
    let temp = h.path("temp");
    fs::create_dir(&temp).unwrap();
    let mut cmd = h.command(&artifact);
    // The temporary directory as the caller names it (`GetTempPath2W` reads
    // TMP first).
    cmd.env(if cfg!(windows) { "TMP" } else { "TMPDIR" }, unusual(&temp));
    let report = Report::parse(&run(&mut cmd));
    assert_paths_native(&report);
    let root = PathBuf::from(report.env("BOUND_ROOT").unwrap());
    assert!(same_path(root.parent().unwrap(), &temp), "{}", root.display());
}
