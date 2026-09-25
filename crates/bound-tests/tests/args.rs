//! Argument binding: appending, `@args` placement, escaping, and exact
//! preservation of argument boundaries on every platform.

use std::ffi::OsString;

use bound_tests::{Harness, Report, TRICKY_ARGS, Value, bins, os, run};

fn harness() -> Harness {
    Harness::new(bins!())
}

#[test]
fn runtime_arguments_are_appended() {
    let h = harness();
    let artifact = h.bind("grep-errors", os!["--", h.bins.fixture, "report", "-n", "ERROR"]);
    assert_eq!(h.report(&artifact, os![]).args(), ["-n", "ERROR"]);
    assert_eq!(h.report(&artifact, os!["test.log"]).args(), ["-n", "ERROR", "test.log"]);
    assert_eq!(h.report(&artifact, os!["a", "b c", ""]).args(), ["-n", "ERROR", "a", "b c", ""]);
}

#[test]
fn args_placeholder_positions_runtime_arguments() {
    let h = harness();
    let artifact =
        h.bind("jpeg", os!["--", h.bins.fixture, "report", "@args", "-strip", "-quality", "85", "output.jpg"]);
    assert_eq!(h.report(&artifact, os!["input.png"]).args(), ["input.png", "-strip", "-quality", "85", "output.jpg"]);
    assert_eq!(h.report(&artifact, os![]).args(), ["-strip", "-quality", "85", "output.jpg"]);
    assert_eq!(h.report(&artifact, os!["a", "b"]).args(), ["a", "b", "-strip", "-quality", "85", "output.jpg"]);
}

#[test]
fn placeholder_in_the_middle() {
    let h = harness();
    let artifact = h.bind("mid", os!["--", h.bins.fixture, "report", "first", "@args", "last"]);
    assert_eq!(h.report(&artifact, os!["x", "y"]).args(), ["first", "x", "y", "last"]);
}

#[test]
fn tricky_runtime_arguments_arrive_intact() {
    let h = harness();
    let artifact = h.bind("tricky", h.fixture_cmd("report"));
    let args: Vec<OsString> = TRICKY_ARGS.iter().map(OsString::from).collect();
    assert_eq!(h.report(&artifact, args).args(), TRICKY_ARGS);
}

#[test]
fn tricky_bound_arguments_arrive_intact() {
    let h = harness();
    let mut command = h.fixture_cmd("report");
    for arg in TRICKY_ARGS {
        // A leading @ is escaped as @@ so it is not read as a directive.
        command.push(if arg.starts_with('@') { format!("@{arg}").into() } else { (*arg).into() });
    }
    let artifact = h.bind("tricky", command);
    assert_eq!(h.report(&artifact, os![]).args(), TRICKY_ARGS);
}

#[test]
fn bound_and_runtime_arguments_combine() {
    let h = harness();
    let artifact =
        h.bind("combo", os!["--", h.bins.fixture, "report", "hello world", "@args", r"C:\Program Files\Test\"]);
    let report = h.report(&artifact, os!["\"quoted\"", "", r#"backslash\"quote"#]);
    assert_eq!(report.args(), ["hello world", "\"quoted\"", "", r#"backslash\"quote"#, r"C:\Program Files\Test\"]);
}

#[test]
fn many_runtime_arguments() {
    let h = harness();
    let artifact = h.bind("many", h.fixture_cmd("report"));
    let args: Vec<String> = (0..1000).map(|i| format!("arg-{i} ✓")).collect();
    let report = h.report(&artifact, args.iter().map(OsString::from).collect());
    assert_eq!(report.args(), args);
}

#[test]
fn many_bound_arguments() {
    let h = harness();
    let bound: Vec<String> = (0..500).map(|i| format!("bound {i}")).collect();
    let mut command = h.fixture_cmd("report");
    command.extend(bound.iter().map(OsString::from));
    let artifact = h.bind("many", command);
    let report = h.report(&artifact, os!["tail"]);
    let mut expected = bound.clone();
    expected.push("tail".into());
    assert_eq!(report.args(), expected);
}

#[test]
fn escaped_directives_are_literal() {
    let h = harness();
    let artifact = h.bind("escaped", os!["--", h.bins.fixture, "report", "@@args", "@@file:x", "@@@y", "@plain"]);
    assert_eq!(h.report(&artifact, os!["@args"]).args(), ["@args", "@file:x", "@@y", "@plain", "@args"]);
}

#[test]
fn runtime_arguments_are_never_interpreted() {
    let h = harness();
    let artifact = h.bind("literal", h.fixture_cmd("report"));
    let report = h.report(&artifact, os!["@file:/etc/passwd", "@args", "$(whoami)", "%USERNAME%"]);
    assert_eq!(report.args(), ["@file:/etc/passwd", "@args", "$(whoami)", "%USERNAME%"]);
}

#[test]
fn program_name_is_argv0() {
    let h = harness();
    let artifact = h.bind("argv0", h.fixture_cmd("report"));
    let report = h.report(&artifact, os![]);
    assert!(
        bound_tests::same_path(std::path::Path::new(&report.argv0()), &h.bins.fixture),
        "argv0 was {}",
        report.argv0()
    );
}

#[test]
fn unicode_arguments_and_environment() {
    let h = harness();
    let artifact =
        h.bind("unicode", os!["--env", "GREETING=grüße ✓ 日本", "--", h.bins.fixture, "report", "ärgümënt ✓"]);
    let report = Report::parse(&run(h.command(&artifact).arg("日本語 😀")));
    assert_eq!(report.args(), ["ärgümënt ✓", "日本語 😀"]);
    assert_eq!(report.env("GREETING").as_deref(), Some("grüße ✓ 日本"));
}

/// A string that is not Unicode, as the platform allows: bytes that are
/// not UTF-8 (Unix) or an unpaired surrogate (Windows); `tail` follows it.
/// Returns it with the fixture's hex form of it (bytes or UTF-16 units).
fn non_unicode(head: &str, tail: &str) -> (OsString, String) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = head.as_bytes().to_vec();
        bytes.extend([0xff, 0xfe]);
        bytes.extend(tail.as_bytes());
        let hex = bytes.iter().map(|b| format!("{b:02x}")).collect();
        (OsString::from_vec(bytes), hex)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let wide: Vec<u16> = head.encode_utf16().chain([0xd800]).chain(tail.encode_utf16()).collect();
        let hex = wide.iter().map(|u| format!("{u:04x}")).collect();
        (OsString::from_wide(&wide), hex)
    }
}

#[test]
fn non_unicode_arguments_are_preserved() {
    let h = harness();
    let (bound_arg, bound_hex) = non_unicode("bound-", "");
    let (runtime_arg, runtime_hex) = non_unicode("caf", "");
    let artifact = h.bind("non-unicode", os!["--", h.bins.fixture, "report", bound_arg]);
    let report = h.report(&artifact, vec![runtime_arg]);
    assert_eq!(report.raw_args(), [serde_json::json!({"hex": bound_hex}), serde_json::json!({"hex": runtime_hex})]);
    let out = h.bound_output(os!["inspect", "--json", &artifact]);
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let key = if cfg!(windows) { "windows_utf16" } else { "unix_bytes" };
    assert_eq!(doc["args"][1]["value"], serde_json::json!({ key: bound_hex }));
}

#[test]
fn environment_names_follow_the_platform() {
    // Windows compares variable names without regard to case; Unix does not.
    let h = harness();
    let artifact = h.bind("path-case", os!["--env", "Path=bound-test-value", "--", h.bins.fixture, "report"]);
    let report = h.report(&artifact, os![]);
    let named_path: Vec<_> = report.env_map().into_iter().filter(|(k, _)| k.eq_ignore_ascii_case("path")).collect();
    if cfg!(windows) {
        assert_eq!(named_path.len(), 1, "{named_path:?}");
        assert_eq!(named_path[0].1, "bound-test-value");
    } else {
        // Path set, PATH inherited: two variables.
        assert_eq!(report.env("Path").as_deref(), Some("bound-test-value"));
        assert_eq!(report.env("PATH"), std::env::var("PATH").ok());
    }
}
