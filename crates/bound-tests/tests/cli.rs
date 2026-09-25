//! Command-line behavior: error messages, overwrite protection, recursion
//! checks, `inspect` and `verify` output.

use std::fs;

use bound_format::Digest;
use bound_tests::{Harness, Value, assert_success, bins, exe, os, stderr, stdout};

fn harness() -> Harness {
    Harness::new(bins!())
}

fn assert_error(stderr: &str, expected: &str) {
    let first = stderr.lines().find(|l| l.starts_with("error:")).unwrap_or_default();
    assert_eq!(first, format!("error: {expected}"), "full stderr:\n{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(!stderr.contains("backtrace"), "{stderr}");
}

#[test]
fn output_names_follow_the_target_platform() {
    // Windows executables need the .exe extension, which bound adds;
    // elsewhere the name is kept as given.
    let h = harness();
    let out = h.bound_output(os!["-o", "mytool", "--", h.bins.fixture, "report"]);
    assert_success(&out, "bound");
    assert_eq!(h.path("mytool.exe").is_file(), cfg!(windows));
    assert_eq!(h.path("mytool").is_file(), !cfg!(windows));
    assert!(stderr(&out).contains(&exe("mytool")), "{}", stderr(&out));
    // An explicit .exe (in any case) is kept as is.
    let out = h.bound_output(os!["-o", "Other.EXE", "--", h.bins.fixture, "report"]);
    assert_success(&out, "bound");
    assert!(h.path("Other.EXE").is_file());
    assert!(!h.path("Other.EXE.exe").exists());
}

#[test]
fn output_path_is_required() {
    let h = harness();
    assert_error(&h.bound_fails(os!["--", "grep", "x"]), "output path is required");
}

#[test]
fn a_program_is_required() {
    let h = harness();
    assert_error(&h.bound_fails(os!["-o", "x"]), "no program given");
}

#[test]
fn missing_file_argument() {
    let h = harness();
    let err = h.bound_fails(os!["-o", "x", "--", h.bins.fixture, "report", "@file:config.toml"]);
    assert_error(&err, "@file:config.toml does not exist");
    assert!(!h.path(exe("x")).exists());
}

#[test]
fn args_placeholder_may_appear_once() {
    let h = harness();
    let err = h.bound_fails(os!["-o", "x", "--", h.bins.fixture, "@args", "@args"]);
    assert_error(&err, "@args may appear only once");
}

#[test]
fn embedding_a_missing_program() {
    let h = harness();
    let err = h.bound_fails(os!["--embed-program", "-o", "x", "--", "./foo"]);
    assert_error(&err, "cannot embed program \"./foo\": file does not exist");
}

#[test]
fn unsafe_destinations_are_rejected() {
    let h = harness();
    h.write("x", "x");
    let err = h.bound_fails(os!["--include-as", r"..\outside=x", "-o", "out", "--", h.bins.fixture]);
    assert!(err.contains(r#"error: --include-as ..\outside=x: unsafe resource path "..\outside""#), "{err}");
    for dest in ["../outside", "/abs", "a/../../b"] {
        let err = h.bound_fails(os!["--include-as", format!("{dest}=x"), "-o", "out", "--", h.bins.fixture]);
        assert!(err.contains(&format!("error: --include-as {dest}=x: unsafe resource path")), "{dest}: {err}");
    }
}

#[test]
fn existing_outputs_are_not_overwritten() {
    let h = harness();
    let artifact = h.bind("tool", h.fixture_cmd("report"));
    let before = fs::read(&artifact).unwrap();
    let err = h.bound_fails(os!["-o", "tool", "--", h.bins.fixture, "echo", "changed"]);
    assert!(err.contains("already exists"), "{err}");
    assert!(err.contains("--force"), "{err}");
    assert_eq!(fs::read(&artifact).unwrap(), before);

    let out = h.bound_output(os!["-o", "tool", "--force", "--", h.bins.fixture, "echo", "changed"]);
    assert_success(&out, "bound --force");
    let run = h.run(&artifact, os![]);
    assert_eq!(stdout(&run).trim(), "changed");
}

#[test]
fn output_inside_an_included_directory_is_rejected() {
    let h = harness();
    h.write("site/index.html", "x");
    let err = h.bound_fails(os!["--include", "site", "-o", "site/app", "--", h.bins.fixture]);
    assert_error(&err, "output path would be included recursively");
    let err = h.bound_fails(os!["--include", ".", "-o", "app", "--", h.bins.fixture]);
    assert_error(&err, "output path would be included recursively");
    // Case differences do not get around the check on case-insensitive systems.
    if cfg!(any(windows, target_os = "macos")) {
        let err = h.bound_fails(os!["--include", "SITE", "-o", "site/app", "--", h.bins.fixture]);
        assert_error(&err, "output path would be included recursively");
    }
}

#[test]
fn output_equal_to_an_input_is_rejected() {
    let h = harness();
    // Named as bound would name the output, so that on Windows (where
    // `.exe` is appended) the output really is the input.
    let name = exe("data");
    h.write(&name, "x");
    let err = h.bound_fails(os!["-o", &name, "--force", "--", h.bins.fixture, "read", format!("@file:{name}")]);
    assert!(err.contains("is also an input"), "{err}");
    assert_eq!(fs::read_to_string(h.path(&name)).unwrap(), "x");
}

#[test]
fn environment_errors() {
    let h = harness();
    let err = h.bound_fails(os!["--env", "BOUND_ROOT=/x", "-o", "o", "--", h.bins.fixture]);
    assert!(err.contains("BOUND_ROOT is reserved"), "{err}");
    let err = h.bound_fails(os!["--env", "NOVALUE", "-o", "o", "--", h.bins.fixture]);
    assert!(err.contains("NAME=VALUE"), "{err}");
    let err = h.bound_fails(os!["--env", "A=1", "--env", "a=2", "-o", "o", "--", h.bins.fixture]);
    assert!(err.contains("more than once"), "{err}");
    let err = h.bound_fails(os!["--env", "CFG=@file:missing.toml", "-o", "o", "--", h.bins.fixture]);
    assert_error(&err, "@file:missing.toml does not exist");
}

#[test]
fn names_differing_only_by_case_collide_where_file_systems_ignore_case() {
    let h = harness();
    h.write("a/Readme.txt", "1");
    h.write("b/readme.txt", "2");
    let args = os!["--include-as", "docs=a", "--include-as", "DOCS=b", "--cwd", "bundle", "--", h.bins.fixture];
    if cfg!(any(windows, target_os = "macos")) {
        let mut full = os!["-o", "o"];
        full.extend(args);
        let err = h.bound_fails(full);
        assert!(err.contains("differ only by case"), "{err}");
    } else {
        // Distinct files on Linux.
        let mut full = args;
        full.extend(os!["read", "docs/Readme.txt", "DOCS/readme.txt"]);
        let artifact = h.bind("o", full);
        let out = h.run(&artifact, os![]);
        assert_success(&out, "o");
        assert_eq!(stdout(&out), "12");
    }
}

#[test]
fn build_subcommand_and_shorthand_are_the_same() {
    let h = harness();
    let out = h.bound_output(os!["build", "-o", "one", "--", h.bins.fixture, "report"]);
    assert_success(&out, "bound build");
    let out = h.bound_output(os!["-o", "two", "--", h.bins.fixture, "report"]);
    assert_success(&out, "bound");
    assert_eq!(fs::read(h.path(exe("one"))).unwrap(), fs::read(h.path(exe("two"))).unwrap());
}

#[test]
fn quiet_suppresses_diagnostics() {
    let h = harness();
    let out = h.bound_output(os!["-q", "-o", "q", "--", "surely-not-installed-anywhere", "x"]);
    assert_success(&out, "bound -q");
    assert_eq!(stderr(&out), "");
    let out = h.bound_output(os!["-o", "loud", "--", "surely-not-installed-anywhere", "x"]);
    assert!(stderr(&out).contains("warning: program \"surely-not-installed-anywhere\" was not found in PATH"));
}

#[test]
fn relative_unbundled_programs_trigger_a_warning() {
    let h = harness();
    let out = h.bound_output(os!["-o", "rel", "--", "./script.sh"]);
    assert_success(&out, "bound");
    assert!(stderr(&out).contains("is a relative path and is not bundled"), "{}", stderr(&out));
}

#[test]
fn help_and_version() {
    let h = harness();
    let out = h.bound_output(os!["--help"]);
    assert_success(&out, "bound --help");
    let text = stdout(&out);
    assert!(text.contains("turns a process invocation into a program"), "{text}");
    assert!(text.contains("inspect") && text.contains("verify") && text.contains("build"));
    let out = h.bound_output(os!["build", "--help"]);
    assert!(stdout(&out).contains("@file:PATH"));
    let out = h.bound_output(os!["--version"]);
    assert!(stdout(&out).starts_with("bound "));
    // No arguments at all prints help and fails.
    let out = h.bound_output(os![]);
    assert!(!out.status.success());
}

#[test]
fn inspect_explains_the_artifact() {
    let h = harness();
    h.write("report.py", "print(1)");
    h.write("report.html", "<html/>");
    let artifact = h.bind(
        "report",
        os!["--env", "MODE=production", "--", "python", "@file:report.py", "--template", "@file:report.html"],
    );
    let out = h.bound_output(os!["inspect", &artifact]);
    assert_success(&out, "inspect");
    let text = stdout(&out);
    for expected in [
        "Bound artifact",
        "Format: 1",
        &format!("Platform: {}-{}", std::env::consts::OS, std::env::consts::ARCH),
        "Mode: external",
        "Program: python",
        "  @file:report.py\n  --template\n  @file:report.html\n  @args\n",
        "MODE=production",
        "Working directory:\n  inherit",
        &Digest::of(b"print(1)").to_hex(),
        &Digest::of(b"<html/>").to_hex(),
        "program \"python\"",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
    }
}

#[test]
fn inspect_json_is_structured_and_stable() {
    let h = harness();
    h.write("config.toml", "k = 1");
    h.write("assets/logo.svg", "<svg/>");
    let artifact = h.bind(
        "app",
        os![
            "--include",
            "assets",
            "--env",
            "CONFIG=@file:config.toml",
            "--cwd",
            "bundle",
            "--",
            h.bins.fixture,
            "report",
            "@args",
            "--verbose"
        ],
    );
    let out = h.bound_output(os!["inspect", "--json", &artifact]);
    assert_success(&out, "inspect --json");
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["inspect_format"], 1);
    assert_eq!(doc["format"], 1);
    assert_eq!(doc["platform"]["os"], std::env::consts::OS);
    assert_eq!(doc["target"]["mode"], "external");
    assert_eq!(doc["cwd"], "bundle");
    assert_eq!(doc["bundle_directory"], true);
    assert_eq!(doc["args"][0], serde_json::json!({"type": "literal", "value": "report"}));
    assert_eq!(doc["args"][1], serde_json::json!({"type": "runtime_args"}));
    assert_eq!(doc["env"][0]["name"], "CONFIG");
    assert_eq!(doc["env"][0]["value"], serde_json::json!({"type": "resource", "path": "config.toml"}));
    let resources = doc["resources"].as_array().unwrap();
    let paths: Vec<&str> = resources.iter().map(|r| r["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["assets", "assets/logo.svg", "config.toml"]);
    assert_eq!(resources[1]["sha256"], Digest::of(b"<svg/>").to_hex());
    assert_eq!(resources[1]["size"], 6);
    assert_eq!(doc["external_dependencies"][0]["kind"], "program");
    let size = fs::metadata(&artifact).unwrap().len();
    assert_eq!(doc["size"], size);
    let regions = &doc["regions"];
    let footer_end = regions["footer"]["offset"].as_u64().unwrap() + 88;
    match doc.get("code_signature") {
        // Mach-O artifacts carry an ad-hoc signature after the footer (and
        // alignment padding).
        Some(signature) => {
            let offset = signature["offset"].as_u64().unwrap();
            assert!((footer_end..=footer_end + 15).contains(&offset), "{signature}");
            assert_eq!(offset + signature["size"].as_u64().unwrap(), size);
        }
        None => assert_eq!(footer_end, size),
    }
    assert_eq!(doc.get("code_signature").is_some(), cfg!(target_os = "macos"));
}

#[test]
fn verify_accepts_an_intact_artifact() {
    let h = harness();
    h.write("config.toml", "k = 1");
    let artifact = h.bind("ok", os!["--", h.bins.fixture, "read", "@file:config.toml"]);
    let out = h.bound_output(os!["verify", &artifact]);
    assert_success(&out, "verify");
    assert!(stdout(&out).contains("OK:"), "{}", stdout(&out));
    let out = h.bound_output(os!["verify", "--json", &artifact]);
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["ok"], true);
    assert_eq!(doc["problems"], serde_json::json!([]));
}

#[test]
fn inspect_and_verify_reject_non_artifacts() {
    let h = harness();
    let plain = h.write("plain.txt", "just text");
    let err = h.bound_fails(os!["inspect", &plain]);
    assert!(err.contains("is not a bound artifact"), "{err}");
    let err = h.bound_fails(os!["verify", &plain]);
    assert!(err.contains("not a bound artifact"), "{err}");
    let err = h.bound_fails(os!["inspect", h.path("missing")]);
    assert!(err.contains("does not exist"), "{err}");
    // The launcher alone is not an artifact either.
    let err = h.bound_fails(os!["inspect", &h.bins.launcher]);
    assert!(err.contains("is not a bound artifact"), "{err}");
}

#[test]
fn artifacts_cannot_be_used_as_launchers() {
    let h = harness();
    let artifact = h.bind("inner", h.fixture_cmd("report"));
    let out = h.bound_output(os!["--launcher", &artifact, "-o", "outer", "--", h.bins.fixture]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("is itself a bound artifact"), "{}", stderr(&out));
}
