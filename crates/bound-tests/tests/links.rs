//! Links in bundles, on every platform: relative links in bundled
//! directories are kept as links (and must stay inside the bundle), links
//! named explicitly are followed, and links work for every user, including
//! Windows users who may not create symbolic links (bound then makes
//! junctions and hard links, as pnpm does).

use std::fs;
use std::path::Path;

use bound_tests::{Harness, assert_success, bins, os, stdout};

fn harness() -> Harness {
    Harness::new(bins!())
}

#[test]
fn relative_links_are_preserved() {
    let h = harness();
    h.write("lib/libfoo.so.1", "library");
    bound_tests::symlink_file("libfoo.so.1", h.path("lib/libfoo.so"));
    bound_tests::symlink_dir(Path::new("..").join("lib"), h.path("lib/self"));
    let artifact = h.bind("links", os!["--include", "lib", "--cwd", "bundle", "--", h.bins.fixture, "ls", "."]);
    let out = h.run(&artifact, os![]);
    assert_success(&out, "links");
    let listing = stdout(&out);
    assert!(listing.contains("lib/libfoo.so -> libfoo.so.1"), "{listing}");
    assert!(listing.contains("lib/self -> ../lib"), "{listing}");

    let reader =
        h.bind("read-link", os!["--include", "lib", "--cwd", "bundle", "--", h.bins.fixture, "read", "lib/libfoo.so"]);
    assert_eq!(stdout(&h.run(&reader, os![])), "library");
}

#[test]
fn links_leaving_the_bundle_are_rejected() {
    let h = harness();
    let absolute = h.path("outside.txt");
    fs::write(&absolute, "outside").unwrap();
    let targets = [
        absolute.clone(),
        Path::new("..").join("..").join("outside"),
        Path::new("..").join("missing-sibling"),
        Path::new("nowhere").to_path_buf(),
    ];
    for (i, target) in targets.iter().enumerate() {
        let dir = format!("d{i}");
        h.write(format!("{dir}/file"), "x");
        bound_tests::symlink_file(target, h.path(format!("{dir}/link")));
        let err = h.bound_fails(os!["--include", &dir, "-o", format!("out{i}"), "--", h.bins.fixture]);
        assert!(err.contains("error:"), "{}: {err}", target.display());
        assert!(!h.path(bound_tests::exe(&format!("out{i}"))).exists());
    }
}

#[test]
fn top_level_links_given_explicitly_are_followed() {
    let h = harness();
    h.write("real/config.toml", "real");
    bound_tests::symlink_file(Path::new("real").join("config.toml"), h.path("alias.toml"));
    let artifact = h.bind("alias", os!["--", h.bins.fixture, "report", "@file:alias.toml"]);
    let report = h.report(&artifact, os![]);
    assert!(report.args()[0].ends_with("alias.toml"));
    assert_eq!(fs::read_to_string(h.path("real/config.toml")).unwrap(), "real");
}

/// Windows: whether this process may create symbolic links (an
/// administrator, or Developer Mode).
#[cfg(windows)]
fn can_create_symlinks(h: &Harness) -> bool {
    let link = h.path("symlink-probe");
    let made = std::os::windows::fs::symlink_file("target", &link).is_ok();
    let _ = fs::remove_file(&link);
    made
}

#[test]
fn links_work_for_every_user() {
    // A bundle with a link to a file and one to a directory, extracted
    // privately and into the cache (where a bundle is written in a staging
    // directory and then moved into place).
    let h = harness();
    h.write("data/file.txt", "file");
    h.write("data/sub/x.txt", "x");
    h.write("list.txt", "data=data\nlinks/file=@link:../data/file.txt\nlinks/dir=@link:../data/sub\n");
    let links_as_symlinks = ["dir -> ../data/sub", "file -> ../data/file.txt"];
    for bundle in ["private", "shared"] {
        let common = os!["--bundle", bundle, "--include-list", "list.txt", "--cwd", "bundle", "--"];
        let mut reader_args = common.clone();
        reader_args.extend(os![h.bins.fixture, "read", "links/file", Path::new("links").join("dir").join("x.txt")]);
        let reader = h.bind(&format!("read-{bundle}"), reader_args);
        let mut lister_args = common;
        lister_args.extend(os![h.bins.fixture, "ls", "links"]);
        let lister = h.bind(&format!("ls-{bundle}"), lister_args);

        // As this user.
        assert_eq!(stdout(&h.run(&reader, os![])), "filex", "{bundle}");
        let listing = stdout(&h.run(&lister, os![]));
        #[cfg(unix)]
        assert_eq!(listing.lines().collect::<Vec<_>>(), links_as_symlinks, "{bundle}");
        #[cfg(windows)]
        {
            if can_create_symlinks(&h) {
                assert_eq!(listing.lines().collect::<Vec<_>>(), links_as_symlinks, "{bundle}");
            } else {
                assert_fallback(&listing, bundle);
            }
            // And as a user without the privilege to create symbolic links:
            // junctions and hard links, unless Developer Mode lets everyone
            // create symbolic links.
            let without = |artifact: &Path| {
                let mut cmd = std::process::Command::new(&h.bins.fixture);
                cmd.arg("without-symlinks").arg(artifact).current_dir(h.dir()).env("BOUND_CACHE_DIR", h.cache_dir());
                // A shared bundle is extracted by the first run: start from none.
                let _ = bound_platform::fs::remove_tree(&h.cache_dir().join("v1").join("trees"));
                let out = bound_tests::run(cmd.stdin(std::process::Stdio::null()));
                assert_success(&out, "without-symlinks");
                let text = stdout(&out);
                let (first, rest) = text.split_once('\n').unwrap();
                (first.trim() == "symlinks: yes", rest.to_owned())
            };
            let (_, content) = without(&reader);
            assert_eq!(content, "filex", "{bundle}");
            let (allowed, listing) = without(&lister);
            if allowed {
                assert_eq!(listing.lines().collect::<Vec<_>>(), links_as_symlinks, "{bundle}");
            } else {
                assert_fallback(&listing, bundle);
            }
        }
    }
}

/// Windows without symbolic links: the directory link is a junction to the
/// directory where the bundle is used (never the staging directory of a
/// shared bundle), the file link a hard link, which lists as a file.
#[cfg(windows)]
fn assert_fallback(listing: &str, bundle: &str) {
    let lines: Vec<&str> = listing.lines().collect();
    assert_eq!(lines.len(), 2, "{bundle}: {listing}");
    let (name, target) = lines[0].split_once(" -> ").unwrap_or_else(|| panic!("{bundle}: {listing}"));
    assert_eq!(name, "dir");
    assert!(Path::new(target).is_absolute() && target.ends_with("/data/sub"), "{bundle}: {target}");
    assert!(!target.contains(".staging-"), "{bundle}: the junction points into the staging directory: {target}");
    if bundle == "shared" {
        // The bundle stays in the cache: the junction still leads there.
        assert!(Path::new(target).is_dir(), "{bundle}: {target}");
    } else {
        // A private bundle is removed after its run; the junction led into
        // that run's own bundle directory.
        let bundle_dir = target.trim_end_matches("/data/sub").rsplit('/').next().unwrap_or_default();
        assert!(bundle_dir.starts_with("bound-"), "{bundle}: {target}");
    }
    assert_eq!(lines[1], "file", "{bundle}: {listing}");
}
