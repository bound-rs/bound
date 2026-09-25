//! Target programs: external and embedded targets, program lookup, exit
//! status, standard streams, composition and interpreted scripts.

use std::fs;
use std::io::Write;
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use std::process::{Command, Stdio};

use bound_tests::{Harness, Report, assert_success, bins, describe, exe, os, run, stderr, stdout};

fn harness() -> Harness {
    Harness::new(bins!())
}

fn dot(name: &str) -> String {
    format!(".{}{name}", std::path::MAIN_SEPARATOR)
}

#[test]
fn embedded_program_survives_removal_of_the_original() {
    let h = harness();
    let program = h.fixture_copy("fixture-program");
    let artifact = h.bind("wrapped", os!["--embed-program", "--", dot(&exe("fixture-program")), "report", "fixed-arg"]);
    fs::remove_file(&program).unwrap();
    let report = h.report(&artifact, os!["runtime arg"]);
    assert_eq!(report.args(), ["fixed-arg", "runtime arg"]);
    let root = PathBuf::from(report.env("BOUND_ROOT").unwrap());
    let running = PathBuf::from(report.raw["exe"].as_str().unwrap());
    assert!(
        bound_tests::same_path(running.parent().unwrap(), &root) || running.starts_with(&root),
        "program ran from {} instead of {}",
        running.display(),
        root.display()
    );
}

#[test]
fn embedded_program_in_a_subdirectory_keeps_its_relative_path() {
    let h = harness();
    h.fixture_copy("bin/tool");
    let artifact = h.bind("sub", os!["--embed-program", "--", format!("bin/{}", exe("tool")), "report"]);
    fs::remove_dir_all(h.path("bin")).unwrap();
    let report = h.report(&artifact, os![]);
    let root = PathBuf::from(report.env("BOUND_ROOT").unwrap());
    assert_eq!(PathBuf::from(report.argv0()), root.join("bin").join(exe("tool")));
}

#[test]
fn embedded_program_with_spaces_and_unicode_in_its_name() {
    let h = harness();
    let program = h.fixture_copy("Program Files ✓/my tool");
    let artifact = h.bind("spaced", os!["--embed-program", "--", &program, "report", "a b"]);
    fs::remove_dir_all(h.path("Program Files ✓")).unwrap();
    assert_eq!(h.report(&artifact, os!["c d"]).args(), ["a b", "c d"]);
}

#[test]
fn programs_with_spaces_in_their_paths() {
    // Like C:\Program Files\... on Windows: spaces (and a trailing
    // backslash in an argument) survive quoting, bundled or not.
    let h = harness();
    let program = h.fixture_copy("Program Files/Test App (x86)/fixture");
    let external = h.bind("external-spaces", os!["--", &program, "report", "x y"]);
    assert_eq!(
        h.report(&external, os![r"C:\Program Files\Test\", "z"]).args(),
        ["x y", r"C:\Program Files\Test\", "z"]
    );
    let embedded = h.bind("embedded-spaces", os!["--embed-program", "--", &program, "report", "x"]);
    fs::remove_dir_all(h.path("Program Files")).unwrap();
    assert_eq!(h.report(&embedded, os!["y"]).args(), ["x", "y"]);
}

#[test]
fn native_tools_can_be_bound() {
    // grep on Unix, findstr on Windows, named without a path (or, on
    // Windows, an extension); their status comes through.
    let h = harness();
    h.write("test.log", "ok\nERROR one\nfine\nERROR two\n");
    h.write("clean.log", "all good\n");
    let (tool, flag) = if cfg!(windows) { ("findstr", "/N") } else { ("grep", "-n") };
    let artifact = h.bind("find-errors", os!["--", tool, flag, "ERROR"]);
    let out = h.run(&artifact, os!["test.log"]);
    assert_success(&out, "find-errors");
    let text = stdout(&out);
    assert!(text.contains("2:ERROR one") && text.contains("4:ERROR two"), "{text}");
    // Nothing matches: both tools exit with 1.
    assert_eq!(h.run(&artifact, os!["clean.log"]).status.code(), Some(1));
}

#[test]
fn scripts_are_found_through_path() {
    // An executable script (Unix), or a batch file found through PATHEXT
    // (Windows), named without an extension.
    let h = harness();
    if cfg!(windows) {
        h.write("bin/hello.cmd", "@echo off\r\necho hello %~1\r\n");
    } else {
        let script = h.write("bin/hello", "#!/bin/sh\necho hello \"$1\"\n");
        bound_tests::write_executable(&script, &fs::read(&script).unwrap());
    }
    let artifact = h.bind("hello", os!["--", "hello", "bound world"]);
    let out = run(h.command(&artifact).env("PATH", path_with(&[h.path("bin")])));
    assert_success(&out, "hello");
    assert_eq!(stdout(&out).trim(), "hello bound world");
}

#[test]
fn embedded_programs_get_a_name_the_platform_runs() {
    // Windows starts programs by file name, so one without an extension is
    // stored as NAME.exe; elsewhere the name is kept.
    let h = harness();
    let noext = h.path("noext");
    fs::copy(&h.bins.fixture, &noext).unwrap();
    bound_tests::write_executable(&noext, &fs::read(&noext).unwrap());
    let out = h.bound_output(os!["--embed-program", "-o", "wrapped", "--", dot("noext"), "report", "fixed"]);
    assert_success(&out, "bound");
    assert_eq!(stderr(&out).contains("noext.exe"), cfg!(windows), "{}", stderr(&out));
    fs::remove_file(&noext).unwrap();
    let report = h.report(&h.path(exe("wrapped")), os!["arg"]);
    assert_eq!(report.args(), ["fixed", "arg"]);
    let expected = if cfg!(windows) { "noext.exe" } else { "noext" };
    assert!(report.argv0().to_ascii_lowercase().ends_with(expected), "{}", report.argv0());
}

#[test]
fn external_program_is_looked_up_in_path_at_run_time() {
    let h = harness();
    let bin = h.path("bin");
    h.fixture_copy("bin/fixture-on-path");
    let artifact = h.bind("lookup", os!["--", "fixture-on-path", "report", "x"]);
    let path = std::env::join_paths(
        std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())),
    )
    .unwrap();
    let report = Report::parse(&run(h.command(&artifact).env("PATH", path)));
    assert_eq!(report.args(), ["x"]);
}

#[test]
fn missing_external_program_exits_127() {
    let h = harness();
    let artifact = h.bind("missing", os!["--", "definitely-not-a-real-program-4711", "a"]);
    let out = h.run(&artifact, os![]);
    assert_eq!(out.status.code(), Some(127), "{}", bound_tests::describe(&out));
    let err = stderr(&out);
    assert!(err.contains("definitely-not-a-real-program-4711"), "{err}");
    assert!(err.contains("not found"), "{err}");
}

#[test]
fn missing_relative_program_exits_127() {
    let h = harness();
    let artifact = h.bind("relative", os!["--", dot("no-such-tool"), "a"]);
    let out = h.run(&artifact, os![]);
    assert_eq!(out.status.code(), Some(127), "{}", bound_tests::describe(&out));
}

/// `PATH` made of `dirs` followed by the caller's `PATH`.
fn path_with(dirs: &[PathBuf]) -> std::ffi::OsString {
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    std::env::join_paths(dirs.iter().cloned().chain(std::env::split_paths(&inherited))).unwrap()
}

#[test]
fn an_artifact_named_like_its_program_runs_the_next_one_in_path() {
    let h = harness();
    let real = h.fixture_copy("real/tool");
    fs::create_dir_all(h.path("wrappers")).unwrap();
    fs::create_dir_all(h.path("copies")).unwrap();
    let artifact = h.bind(&format!("wrappers{MAIN_SEPARATOR}tool"), os!["--", "tool", "report", "wrapped"]);
    // A copy of the artifact further along PATH is passed over as well.
    fs::copy(&artifact, h.path("copies").join(artifact.file_name().unwrap())).unwrap();
    let path = path_with(&[h.path("wrappers"), h.path("copies"), h.path("real")]);
    for with_resources in [false, true] {
        let artifact = if with_resources {
            h.write("x.txt", "x");
            let bundled = h.bind(
                &format!("wrappers{MAIN_SEPARATOR}tool"),
                os!["--force", "--include", "x.txt", "--", "tool", "report", "wrapped"],
            );
            fs::copy(&bundled, h.path("copies").join(bundled.file_name().unwrap())).unwrap();
            bundled
        } else {
            artifact.clone()
        };
        let report = Report::parse(&run(h.command(&artifact).env("PATH", &path)));
        assert_eq!(report.args(), ["wrapped"]);
        let ran = PathBuf::from(report.raw["exe"].as_str().unwrap());
        assert!(bound_tests::same_path(&ran, &real), "ran {} instead of {}", ran.display(), real.display());
        if cfg!(unix) {
            assert_eq!(report.argv0(), "tool", "argv[0] is the name, as with execvp");
        }
    }
}

#[test]
fn an_artifact_never_runs_itself() {
    let h = harness();
    fs::create_dir_all(h.path("bin")).unwrap();
    let artifact = h.bind(&format!("bin{MAIN_SEPARATOR}loop"), os!["--", "loop"]);
    let out = run(h.command(&artifact).env("PATH", path_with(&[h.path("bin")])));
    assert_eq!(out.status.code(), Some(127), "{}", describe(&out));
    assert!(stderr(&out).contains("not found"), "{}", describe(&out));
    assert!(Path::new(&artifact).exists());
}

#[test]
fn exit_codes_are_propagated() {
    let h = harness();
    h.write("x.txt", "x");
    let direct = h.bind("exit", h.fixture_cmd("exit"));
    let mut bundled_args = os!["--include", "x.txt"];
    bundled_args.extend(h.fixture_cmd("exit"));
    let bundled = h.bind("exit-bundled", bundled_args);
    for artifact in [&direct, &bundled] {
        for code in [0, 1, 2, 42, 125, 126, 127, 255] {
            let out = h.run(artifact, os![code.to_string()]);
            assert_eq!(out.status.code(), Some(code), "{}", artifact.display());
        }
        // Unix keeps the low 8 bits of an exit code; Windows all 32.
        for code in [256i64, 65_536, -1, -1_073_741_819] {
            let expected = if cfg!(windows) { code as i32 } else { (code & 0xff) as i32 };
            let out = h.run(artifact, os![code.to_string()]);
            assert_eq!(out.status.code(), Some(expected), "{code}: {}", artifact.display());
        }
    }
}

#[test]
fn standard_streams_are_connected() {
    let h = harness();
    h.write("x.txt", "x");
    let direct = h.bind("cat", h.fixture_cmd("cat"));
    let mut bundled_args = os!["--include", "x.txt"];
    bundled_args.extend(h.fixture_cmd("cat"));
    let bundled = h.bind("cat-bundled", bundled_args);
    let input: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    for artifact in [&direct, &bundled] {
        let mut child = h.command(artifact).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let data = input.clone();
        let writer = std::thread::spawn(move || stdin.write_all(&data));
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap().unwrap();
        assert_success(&out, "cat");
        assert!(out.stdout == input, "stdin was not forwarded intact through {}", artifact.display());
    }

    let noisy = h.bind("noisy", os!["--", h.bins.fixture, "stderr", "to stderr ✓"]);
    let out = h.run(&noisy, os![]);
    assert_success(&out, "noisy");
    assert_eq!(stderr(&out).trim_end(), "to stderr ✓");
    assert!(out.stdout.is_empty());
}

#[test]
fn report_reads_stdin() {
    let h = harness();
    let artifact = h.bind("stdin", h.fixture_cmd("report"));
    let mut child =
        h.command(&artifact).env("FIXTURE_STDIN", "1").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all("line one\nline twø\n".as_bytes()).unwrap();
    let report = Report::parse(&child.wait_with_output().unwrap());
    assert_eq!(report.stdin().as_deref(), Some("line one\nline twø\n"));
}

#[test]
fn composition_nests_artifacts() {
    let h = harness();
    let reliable = h.bind("reliable-curl", os!["--", h.bins.fixture, "report", "--retry", "5"]);
    h.write("headers.txt", "X-Api-Key: none\n");
    let api = h.bind(
        "api-curl",
        os!["--embed-program", "--", dot(reliable.file_name().unwrap().to_str().unwrap()), "-H", "@file:headers.txt"],
    );
    fs::remove_file(&reliable).unwrap();
    fs::remove_file(h.path("headers.txt")).unwrap();

    let report = h.report(&api, os!["https://example.invalid/"]);
    let args = report.args();
    assert_eq!(args.len(), 5, "{args:?}");
    assert_eq!(&args[..3], ["--retry", "5", "-H"]);
    assert!(args[3].ends_with("headers.txt"), "{args:?}");
    assert_eq!(args[4], "https://example.invalid/");
    // The inner artifact has no bundle of its own, so it hides the outer
    // artifact's BOUND_ROOT from its program.
    assert_eq!(report.env("BOUND_ROOT"), None);

    let out = h.bound_output(os!["inspect", &api]);
    assert_success(&out, "inspect");
    let text = stdout(&out);
    assert!(text.contains("Nested: a bound artifact"), "{text}");
    assert!(text.contains("runs external program") && text.contains("bound-fixture"), "{text}");
}

#[test]
fn bound_root_is_removed_when_there_is_no_bundle() {
    let h = harness();
    let artifact = h.bind("no-bundle", h.fixture_cmd("report"));
    let report = Report::parse(&run(h.command(&artifact).env("BOUND_ROOT", "/leaked/from/parent")));
    assert_eq!(report.env("BOUND_ROOT"), None);
}

#[test]
fn bare_launcher_reports_that_it_has_no_payload() {
    let h = harness();
    let out = run(Command::new(&h.bins.launcher).arg("x").stdin(Stdio::null()));
    assert_eq!(out.status.code(), Some(125));
    let err = stderr(&out);
    assert!(err.contains("no bound payload"), "{err}");
}

/// The Python 3 interpreter in PATH, which the tests need.
fn python() -> &'static str {
    ["python3", "python"]
        .into_iter()
        .find(|candidate| {
            Command::new(candidate)
                .args(["-c", "import sys; print(sys.version_info[0])"])
                .output()
                .is_ok_and(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "3")
        })
        .expect("the tests need a Python 3 interpreter in PATH (python3 or python)")
}

#[test]
fn python_script_runs_with_an_external_interpreter() {
    let python = python();
    let h = harness();
    h.write(
        "report.py",
        "import sys, pathlib\nprint('args', sys.argv[1:])\nprint(pathlib.Path(sys.argv[2]).read_text())\n",
    );
    h.write("report.html", "<template>");
    let artifact = h.bind("report", os!["--", python, "@file:report.py", "--template", "@file:report.html"]);
    fs::remove_file(h.path("report.py")).unwrap();
    fs::remove_file(h.path("report.html")).unwrap();
    let out = h.run(&artifact, os!["extra"]);
    assert_success(&out, "report");
    let text = stdout(&out);
    assert!(text.contains("<template>"), "{text}");
    assert!(text.contains("'extra'"), "{text}");
}

#[test]
fn working_directory_of_the_build_does_not_matter() {
    let h = harness();
    h.write("a/data.txt", "a data");
    let mut cmd = h.bound();
    cmd.current_dir(h.path("a")).args(os!["-o", h.path("from-a"), "--", h.bins.fixture, "read", "@file:data.txt"]);
    assert_success(&run(&mut cmd), "bound");
    let artifact = h.path(exe("from-a"));
    let elsewhere = h.path("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    let out = run(h.command(&artifact).current_dir(&elsewhere));
    assert_eq!(stdout(&out), "a data");
}

#[test]
fn artifacts_run_from_any_location() {
    let h = harness();
    let artifact = h.bind("mover", h.fixture_cmd("report"));
    let moved_dir = h.path("moved ✓ dir");
    fs::create_dir(&moved_dir).unwrap();
    let moved = moved_dir.join(exe("renamed"));
    fs::rename(&artifact, &moved).unwrap();
    assert_eq!(h.report(&moved, os!["ok"]).args(), ["ok"]);
}
