//! Format version 2 at run time: a working directory in the bundle
//! (`--cwd @bundle:DIR`) and list variables (`--env-prepend`,
//! `--env-append`).

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use bound_tests::{Harness, Report, Value, bins, os, run, same_path, stdout};

fn harness() -> Harness {
    Harness::new(bins!())
}

/// The list separator of the platform the tests run on.
const SEPARATOR: &str = if cfg!(windows) { ";" } else { ":" };

fn root(report: &Report) -> PathBuf {
    PathBuf::from(report.env("BOUND_ROOT").expect("a bundle directory exists"))
}

fn format_of(h: &Harness, artifact: &Path) -> u64 {
    let out = h.bound_output(os!["inspect", "--json", artifact]);
    let json: Value = serde_json::from_str(&stdout(&out)).unwrap();
    json["format"].as_u64().unwrap()
}

#[test]
fn a_bundled_directory_can_be_the_working_directory() {
    let h = harness();
    h.write("app/src/main.txt", "x");
    let artifact =
        h.bind("in-src", os!["--include", "app", "--cwd", "@bundle:app/src", "--", h.bins.fixture, "report"]);
    let report = h.report(&artifact, os![]);
    assert!(same_path(&report.cwd(), &root(&report).join("app").join("src")), "{}", report.cwd().display());
    assert_eq!(format_of(&h, &artifact), 2);
    // Without a version-2 feature, an artifact stays at version 1.
    let plain = h.bind("plain", os!["--include", "app", "--cwd", "bundle", "--", h.bins.fixture, "report"]);
    assert_eq!(format_of(&h, &plain), 1);
}

#[test]
fn an_empty_bundled_directory_can_be_the_working_directory() {
    let h = harness();
    let artifact =
        h.bind("empty", os!["--include-as", "work=@dir", "--cwd", "@bundle:work", "--", h.bins.fixture, "report"]);
    let report = h.report(&artifact, os![]);
    assert!(same_path(&report.cwd(), &root(&report).join("work")));
}

#[test]
fn the_working_directory_must_be_a_bundled_directory() {
    let h = harness();
    h.write("app/main.txt", "x");
    for (cwd, expected) in [
        ("@bundle:app/main.txt", "not a directory in the bundle"),
        ("@bundle:elsewhere", "nothing is bundled there"),
        ("somewhere", "expected inherit, bundle or @bundle:DIR"),
    ] {
        let err = h.bound_fails(os!["-o", "bad", "--include", "app", "--cwd", cwd, "--", h.bins.fixture, "report"]);
        assert!(err.contains(expected), "--cwd {cwd}: {err}");
    }
}

/// `NAME=VALUE` for a list option.
fn entry(name: &str, value: impl AsRef<std::ffi::OsStr>) -> OsString {
    let mut out = OsString::from(format!("{name}="));
    out.push(value);
    out
}

#[test]
fn list_entries_surround_the_callers_value_in_order() {
    let h = harness();
    h.write("one/x", "");
    h.write("two/x", "");
    let artifact = h.bind(
        "lists",
        os![
            "--include",
            "one",
            "--include",
            "two",
            "--env-prepend",
            entry("BOUND_TEST_LIST", "@bundle:one"),
            "--env-prepend",
            entry("BOUND_TEST_LIST", "second"),
            "--env-append",
            entry("BOUND_TEST_LIST", "@bundle:two"),
            "--",
            h.bins.fixture,
            "report"
        ],
    );
    assert_eq!(format_of(&h, &artifact), 2);
    let value = |caller: Option<&str>| {
        let mut cmd = h.command(&artifact);
        match caller {
            Some(value) => cmd.env("BOUND_TEST_LIST", value),
            None => cmd.env_remove("BOUND_TEST_LIST"),
        };
        let report = Report::parse(&run(&mut cmd));
        let root = root(&report);
        let (one, two) = (root.join("one"), root.join("two"));
        (report.env("BOUND_TEST_LIST").unwrap(), one.display().to_string(), two.display().to_string())
    };
    let (got, one, two) = value(Some("caller"));
    assert_eq!(got, [one.as_str(), "second", "caller", two.as_str()].join(SEPARATOR));
    // Without the caller's value, or with an empty one, only the bound entries.
    for caller in [None, Some("")] {
        let (got, one, two) = value(caller);
        assert_eq!(got, [one.as_str(), "second", two.as_str()].join(SEPARATOR), "{caller:?}");
    }
}

#[test]
fn a_bundled_directory_on_path_finds_programs_by_name() {
    let h = harness();
    let fixture = Path::new(&h.bins.fixture);
    let file_name = fixture.file_name().unwrap().to_str().unwrap();
    let name = file_name.strip_suffix(".exe").unwrap_or(file_name);
    let out = h.bound_output(os![
        "-o",
        "by-name",
        "--include-as",
        entry(&format!("tools/{file_name}"), fixture),
        "--env-prepend",
        "PATH=@bundle:tools",
        "--",
        name,
        "report"
    ]);
    bound_tests::assert_success(&out, "bound build");
    // The build knows where the program will be found.
    let messages = String::from_utf8_lossy(&out.stderr);
    assert!(messages.contains("bundled directory tools"), "{messages}");
    assert!(!messages.contains("was not found in PATH"), "{messages}");
    let artifact = h.path(bound_tests::exe("by-name"));
    let report = h.report(&artifact, os![]);
    let tools = root(&report).join("tools");
    assert!(same_path(Path::new(&report.text("exe")), &tools.join(file_name)), "{}", report.text("exe"));
    let path = report.env("PATH").unwrap();
    let first = path.split(SEPARATOR).next().unwrap();
    assert!(same_path(Path::new(first), &tools), "{path}");
}

#[test]
fn list_names_follow_the_platforms_case_rules() {
    let h = harness();
    let artifact = h.bind("case", os!["--env-prepend", "BOUND_TEST_CASE=bound", "--", h.bins.fixture, "report"]);
    let mut cmd = h.command(&artifact);
    cmd.env_remove("BOUND_TEST_CASE").env("bound_test_case", "caller");
    let report = Report::parse(&run(&mut cmd));
    if cfg!(windows) {
        // One variable, whatever the case of its name.
        assert_eq!(report.env("BOUND_TEST_CASE").unwrap(), ["bound", "caller"].join(SEPARATOR));
    } else {
        // Two variables.
        assert_eq!(report.env("BOUND_TEST_CASE").unwrap(), "bound");
        assert_eq!(report.env("bound_test_case").unwrap(), "caller");
    }
}

#[test]
fn list_options_are_checked_when_building() {
    let h = harness();
    h.write("dir/x", "");
    let separated = format!("X=a{SEPARATOR}b");
    for (args, expected) in [
        (os!["--env-prepend", &separated], "contains the list separator"),
        (os!["--env-append", "X="], "cannot be empty"),
        (os!["--env", "X=1", "--env-prepend", "X=a"], "also listed"),
        // Names compare case-insensitively in a manifest, on every platform.
        (os!["--unset", "x", "--env-append", "X=a"], "also listed"),
        (os!["--env-prepend", "X=@bundle:nowhere"], "nothing is bundled there"),
        (os!["--env-prepend", "X"], "--env-prepend expects NAME=VALUE"),
    ] {
        let mut full = os!["-o", "bad", "--include", "dir"];
        full.extend(args.clone());
        full.extend(os!["--", h.bins.fixture, "report"]);
        let err = h.bound_fails(full);
        assert!(err.contains(expected), "{args:?}: {err}");
    }
    assert!(!h.path("bad").exists() && !h.path("bad.exe").exists());
    // An entry naming a bundled directory whose name holds the separator is
    // refused too (Windows names cannot hold ':', Unix names can hold ';').
    let odd = format!("a{SEPARATOR}b");
    fs::create_dir_all(h.path(&odd)).unwrap();
    fs::write(h.path(&odd).join("x"), "").unwrap();
    let err = h.bound_fails(os![
        "-o",
        "bad",
        "--include",
        &odd,
        "--env-prepend",
        format!("X=@bundle:{odd}"),
        "--",
        h.bins.fixture,
        "report"
    ]);
    assert!(err.contains("contains the list separator"), "{err}");
}

#[test]
fn artifacts_of_either_version_nest_in_each_other() {
    let h = harness();
    h.write("work/x", "");
    let v1 = h.bind("inner-v1", os!["--", h.bins.fixture, "report"]);
    let v2 = h.bind("inner-v2", os!["--include", "work", "--cwd", "@bundle:work", "--", h.bins.fixture, "report"]);
    assert_eq!((format_of(&h, &v1), format_of(&h, &v2)), (1, 2));
    // A version-2 artifact embedding a version-1 one, and the reverse.
    let outer_v2 = h.bind("outer-v2", os!["--include", "work", "--cwd", "@bundle:work", "--embed-program", "--", &v1]);
    let outer_v1 = h.bind("outer-v1", os!["--embed-program", "--", &v2]);
    assert_eq!((format_of(&h, &outer_v2), format_of(&h, &outer_v1)), (2, 1));
    for (outer, inner_format) in [(&outer_v2, 1), (&outer_v1, 2)] {
        let out = h.bound_output(os!["inspect", "--json", outer]);
        let json: Value = serde_json::from_str(&stdout(&out)).unwrap();
        assert_eq!(json["nested"]["format"], inner_format, "{}", outer.display());
        h.report(outer, os![]);
    }
    // The inner version-2 artifact still runs in its own bundle directory.
    let report = h.report(&outer_v1, os![]);
    assert!(same_path(&report.cwd(), &root(&report).join("work")));
}

#[test]
fn inspect_shows_the_working_directory_and_list_bindings() {
    let h = harness();
    h.write("app/tools/x", "");
    let artifact = h.bind(
        "shown",
        os![
            "--include",
            "app",
            "--cwd",
            "@bundle:app",
            "--env-prepend",
            "PATH=@bundle:app/tools",
            "--env-append",
            "PATH=/extra",
            "--",
            h.bins.fixture,
            "report"
        ],
    );
    let text = stdout(&h.bound_output(os!["inspect", &artifact]));
    assert!(text.contains("Format: 2 ("), "{text}");
    assert!(text.contains("@bundle:app (a directory in the bundle)"), "{text}");
    assert!(
        text.contains(&format!(
            "PATH (list, joined with \"{SEPARATOR}\"): @file:app/tools, <the caller's PATH>, /extra"
        )),
        "{text}"
    );
    let json: Value = serde_json::from_str(&stdout(&h.bound_output(os!["inspect", "--json", &artifact]))).unwrap();
    assert_eq!(json["cwd"], serde_json::json!({ "dir": "app" }));
    assert_eq!(json["env"][0]["value"]["type"], "list");
}
