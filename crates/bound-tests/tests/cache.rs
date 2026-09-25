//! The per-user cache: large contents taken from it, shared bundles, and
//! `bound cache`.

use std::fs;
use std::path::{Path, PathBuf};

use bound_tests::{Harness, Report, assert_removed, assert_success, bins, os, run, stdout};

fn harness() -> Harness {
    Harness::new(bins!())
}

/// Deterministic, compressible content of `len` bytes.
fn content(len: usize) -> Vec<u8> {
    (0..len).map(|i| b"bound cache test line\n"[i % 22]).collect()
}

fn cache_listing(h: &Harness) -> String {
    let out = h.bound_output(os!["cache", "list"]);
    assert_success(&out, "bound cache list");
    stdout(&out)
}

#[test]
fn large_contents_are_stored_once_and_reused() {
    let h = harness();
    let big = content(3 << 20);
    h.write("data/big.bin", &big);
    h.write("data/small.txt", "small");
    let artifact = h.bind(
        "reader",
        os!["--include", "data", "--cwd", "bundle", "--", h.bins.fixture, "read", "data/big.bin", "data/small.txt"],
    );
    for _ in 0..3 {
        let out = h.run(&artifact, os![]);
        assert_success(&out, "reader");
        assert!(out.stdout.len() == big.len() + 5 && out.stdout[..big.len()] == big[..], "wrong content");
    }
    let listing = cache_listing(&h);
    assert!(listing.contains("Large contents: 1 "), "only the large file is cached:\n{listing}");
    assert!(listing.contains("Shared bundles: 0"), "{listing}");
}

#[test]
fn programs_cannot_change_cached_contents() {
    let h = harness();
    h.write("big.bin", content(2 << 20));
    let artifact =
        h.bind("mutate", os!["--include", "big.bin", "--cwd", "bundle", "--", h.bins.fixture, "mutate", "big.bin"]);
    for _ in 0..3 {
        // Each run sees the original content, then overwrites its own copy.
        let out = h.run(&artifact, os![]);
        assert_success(&out, "mutate");
        assert_eq!(out.stdout.len(), 2 << 20);
        assert!(out.stdout.starts_with(b"bound cache test line\n"));
    }
}

#[test]
fn caching_can_be_turned_off() {
    let h = harness();
    h.write("big.bin", content(2 << 20));
    let artifact = h.bind("off", os!["--include", "big.bin", "--", h.bins.fixture, "exit", "0"]);
    let out = run(h.command(&artifact).env("BOUND_CACHE", "0"));
    assert_success(&out, "off");
    assert!(cache_listing(&h).contains("empty"), "nothing may be cached");
    let out = run(h.bound().args(["cache", "dir"]).env("BOUND_CACHE", "off"));
    assert!(stdout(&out).contains("turned off"), "{}", stdout(&out));
}

fn shared(h: &Harness) -> PathBuf {
    h.write("app/config.toml", "setting = 1\n");
    h.write("app/tool.sh", "#!/bin/sh\n");
    h.bind(
        "shared",
        os!["--bundle", "shared", "--include", "app", "--cwd", "bundle", "--", h.bins.fixture, "report", "@args"],
    )
}

#[test]
fn shared_bundles_are_extracted_once_and_reused() {
    let h = harness();
    let artifact = shared(&h);
    let first = h.report(&artifact, os![]);
    let root = PathBuf::from(first.env("BOUND_ROOT").unwrap());
    assert!(root.starts_with(h.cache_dir()), "{} is not in the cache", root.display());
    assert_eq!(fs::read_to_string(root.join("app").join("config.toml")).unwrap(), "setting = 1\n");
    for _ in 0..3 {
        let again = h.report(&artifact, os![]);
        assert_eq!(PathBuf::from(again.env("BOUND_ROOT").unwrap()), root, "every run uses the same directory");
        assert_eq!(again.cwd(), root);
    }
    // The bundle stays after the runs and is read-only. (Permissions are
    // checked rather than tried: root, which runs these tests in
    // containers, may write regardless.)
    let config = root.join("app").join("config.toml");
    assert!(config.is_file());
    assert!(fs::metadata(&config).unwrap().permissions().readonly(), "shared bundles must be read-only");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [&root, &root.join("app")] {
            assert_eq!(fs::metadata(dir).unwrap().permissions().mode() & 0o777, 0o555, "{}", dir.display());
        }
    }
    let listing = cache_listing(&h);
    assert!(listing.contains("Shared bundles: 1 "), "{listing}");

    let out = h.bound_output(os!["inspect", &artifact]);
    assert!(stdout(&out).contains("shared by every run"), "{}", stdout(&out));
}

#[test]
fn shared_bundles_need_no_cleanup() {
    // Nothing is removed after a run of a shared bundle, so nothing waits
    // to: the program replaces the launcher at once (Unix), and the
    // launcher that supervises it starts no reaper (Windows).
    let h = harness();
    #[cfg(unix)]
    {
        let artifact = shared(&h);
        h.report(&artifact, os![]);
        let child = h.command(&artifact).stdout(std::process::Stdio::piped()).spawn().unwrap();
        let pid = child.id();
        let report = Report::parse(&child.wait_with_output().unwrap());
        assert_eq!(report.pid(), pid);
    }
    #[cfg(windows)]
    {
        use std::io::BufRead;
        use std::time::{Duration, Instant};
        h.write("app/config.toml", "setting = 1\n");
        // How many processes run the artifact's image while the program runs:
        // the launcher, and a reaper for a private bundle.
        let running = |bundle: &str, expected: usize| {
            let artifact = h.bind(
                &format!("hold-{bundle}"),
                os!["--bundle", bundle, "--include", "app", "--", h.bins.fixture, "hold"],
            );
            let mut child = h.command(&artifact).stdout(std::process::Stdio::piped()).spawn().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
            let name = artifact.file_name().unwrap().to_string_lossy().to_lowercase();
            let count =
                || bound_tests::processes().into_iter().filter(|(_, _, exe)| exe.to_lowercase() == name).count();
            // The reaper starts just after the program: give it time.
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut seen = count();
            while seen < expected && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
                seen = count();
            }
            std::thread::sleep(Duration::from_millis(500));
            seen = seen.max(count());
            let _ = child.kill();
            let _ = child.wait();
            seen
        };
        assert_eq!(running("private", 2), 2, "a private bundle has a reaper");
        assert_eq!(running("shared", 1), 1, "a shared bundle needs none");
    }
}

#[test]
fn shared_bundles_fall_back_to_private_ones_without_a_cache() {
    let h = harness();
    let artifact = shared(&h);
    let report = Report::parse(&run(h.command(&artifact).env("BOUND_CACHE", "no")));
    let root = PathBuf::from(report.env("BOUND_ROOT").unwrap());
    assert!(!root.starts_with(h.cache_dir()));
    assert!(root.file_name().unwrap().to_string_lossy().starts_with("bound-"));
    assert_removed(&root);
}

/// Makes a sealed entry writable again, as someone about to change it would.
fn make_writable(path: &Path) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(if path.is_dir() { 0o755 } else { 0o644 });
    }
    // Windows: clears the read-only attribute.
    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).unwrap();
}

#[test]
fn a_modified_shared_bundle_is_replaced() {
    let h = harness();
    let artifact = shared(&h);
    let root = PathBuf::from(h.report(&artifact, os![]).env("BOUND_ROOT").unwrap());
    // Someone makes it writable and changes it: it is no longer sealed.
    let config = root.join("app").join("config.toml");
    for path in [&root, &root.join("app"), &config] {
        make_writable(path);
    }
    fs::write(&config, "tampered").unwrap();
    let again = h.report(&artifact, os![]);
    assert_eq!(PathBuf::from(again.env("BOUND_ROOT").unwrap()), root);
    assert_eq!(fs::read_to_string(&config).unwrap(), "setting = 1\n", "the bundle was extracted again");
}

#[test]
fn cache_clean_removes_entries() {
    let h = harness();
    let artifact = shared(&h);
    let root = PathBuf::from(h.report(&artifact, os![]).env("BOUND_ROOT").unwrap());
    h.write("big.bin", content(2 << 20));
    let big = h.bind("big", os!["--include", "big.bin", "--", h.bins.fixture, "exit", "0"]);
    assert_success(&h.run(&big, os![]), "big");

    let out = h.bound_output(os!["cache", "dir"]);
    assert_eq!(Path::new(stdout(&out).trim()), h.cache_dir());
    // Recently used entries survive a clean of unused ones.
    let out = h.bound_output(os!["cache", "clean", "--unused", "30"]);
    assert!(stdout(&out).contains("Removed 0 cache entries"), "{}", stdout(&out));
    let out = h.bound_output(os!["cache", "clean"]);
    assert_success(&out, "bound cache clean");
    assert!(stdout(&out).contains("Removed 2 cache entries"), "{}", stdout(&out));
    assert!(!root.exists());
    let listing = cache_listing(&h);
    assert!(listing.contains("Shared bundles: 0") && listing.contains("Large contents: 0"), "{listing}");
    // The artifact still runs, and re-creates its bundle.
    h.report(&artifact, os![]);
    assert!(root.exists());
}

#[test]
fn corrupted_contents_are_never_cached() {
    let h = harness();
    h.write("big.bin", content(2 << 20));
    let artifact = h.bind("corrupt", os!["--include", "big.bin", "--", h.bins.fixture, "exit", "0"]);
    let mut bytes = fs::read(&artifact).unwrap();
    let (footer, _) = bound_format::footer::read_footer(&mut std::io::Cursor::new(&bytes)).unwrap();
    // Damage the middle of the payload (the compressed content).
    let middle = (footer.payload_offset + footer.payload_len / 2) as usize;
    bytes[middle] ^= 0x40;
    let damaged = h.path(format!("damaged{}", std::env::consts::EXE_SUFFIX));
    bound_tests::write_executable(&damaged, &bytes);
    let out = h.run(&damaged, os![]);
    assert_eq!(out.status.code(), Some(125), "{}", bound_tests::describe(&out));
    assert!(bound_tests::stderr(&out).contains("corrupted"), "{}", bound_tests::stderr(&out));
    let listing = cache_listing(&h);
    assert!(listing.contains("Large contents: 0") || listing.contains("empty"), "{listing}");
    assert!(!listing.contains("Incomplete"), "{listing}");
}
