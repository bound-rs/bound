//! The projects in `examples/`, checked with their own tools and bound the
//! ways their READMEs describe, on every platform.
//!
//! They need Rust, Node.js with npm, uv, and network access (npm and PyPI
//! packages, a CPython build), as the whole test suite does; CI provides
//! them on every platform.
//!
//! The Node.js example embeds the `node` executable, which must be an
//! official build (nodejs.org, nvm, fnm, Volta, actions/setup-node): builds
//! linked against shared libraries (Homebrew's) cannot be embedded alone.
//! `BOUND_EXAMPLE_NODE` names another `node` to embed.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use bound_tests::{Harness, assert_success, bins, exe, os, run, stdout};

/// A test directory holding a copy of `examples/NAME` and an empty `bin`.
fn example(name: &str) -> Harness {
    let h = Harness::new(bins!());
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples").join(name);
    copy_tree(&source, &h.dir());
    fs::create_dir(h.path("bin")).unwrap();
    h
}

/// Copies an example without what building it leaves behind.
fn copy_tree(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let generated = ["node_modules", ".venv", "target", "bin", "build", "dist", "__pycache__", ".pytest_cache"];
        if generated.iter().any(|skip| name == *skip) {
            continue;
        }
        let dest = to.join(&name);
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir(&dest).unwrap();
            copy_tree(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

/// Runs one of the example's tools in its directory and returns stdout.
fn tool(h: &Harness, program: &str, args: &[&str]) -> String {
    // npm is a batch file on Windows, which needs its extension.
    let program = if cfg!(windows) && program == "npm" { "npm.cmd" } else { program };
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(h.dir()).env_remove("CARGO_TARGET_DIR");
    if let Err(e) = Command::new(program).arg("--version").output() {
        panic!("the example tests need {program} in PATH (see the README's Development section): {e}");
    }
    let out = run(&mut cmd);
    assert_success(&out, &format!("{program} {}", args.join(" ")));
    stdout(&out)
}

/// Runs `bound ARGS...` in the example directory.
fn bound(h: &Harness, args: Vec<OsString>) {
    assert_success(&h.bound_output(args), "bound");
}

/// Runs an artifact from `bin/` and returns its output.
fn artifact(h: &Harness, name: &str, args: Vec<OsString>) -> String {
    let out = h.run(&h.path("bin").join(exe(name)), args);
    assert_success(&out, name);
    stdout(&out)
}

fn assert_contains(text: &str, expected: &[&str]) {
    for part in expected {
        assert!(text.contains(part), "{part:?} missing from:\n{text}");
    }
}

#[test]
fn rust_example() {
    let h = example("rust");
    tool(&h, "cargo", &["test", "--locked", "--quiet"]);
    tool(&h, "cargo", &["build", "--release", "--locked", "--quiet"]);
    let program: PathBuf = ["target", "release", &exe("wordstats")].iter().collect();

    // A preset: the program, its stopwords and options in one executable.
    bound(
        &h,
        os!["--embed-program", "-o", "bin/topwords", "--", program, "--stopwords", "@file:stopwords/en.txt", "@args"],
    );
    let out = artifact(&h, "topwords", os!["samples/lighthouse.txt"]);
    assert!(out.starts_with("     8  keeper\n     5  ships\n"), "{out}");
    // Options given at run time come after the bound ones and win.
    let out = artifact(&h, "topwords", os!["--top", "1", "samples/lighthouse.txt"]);
    assert_eq!(out, "     8  keeper\n");

    // Another preset from the same program.
    bound(
        &h,
        os![
            "--embed-program",
            "-o",
            "bin/topwords-fr",
            "--",
            program,
            "--stopwords",
            "@file:stopwords/fr.txt",
            "--top",
            "3",
            "@args"
        ],
    );
    let out = artifact(&h, "topwords-fr", os!["samples/phare.txt"]);
    assert_eq!(out, "     6  gardien\n     4  brouillard\n     4  navires\n");

    // Behavior set through the environment.
    bound(
        &h,
        os![
            "--embed-program",
            "-o",
            "bin/topwords-json",
            "--env",
            "WORDSTATS_FORMAT=json",
            "--",
            program,
            "--stopwords",
            "@file:stopwords/en.txt",
            "@args"
        ],
    );
    let out = artifact(&h, "topwords-json", os!["--top", "2", "samples/lighthouse.txt"]);
    assert_eq!(out, "[{\"word\":\"keeper\",\"count\":8},{\"word\":\"ships\",\"count\":5}]\n");

    // A whole data directory, found through an environment variable.
    bound(
        &h,
        os![
            "--embed-program",
            "-o",
            "bin/wordstats",
            "--env",
            "WORDSTATS_DATA=@file:stopwords",
            "--",
            program,
            "@args"
        ],
    );
    let out = artifact(&h, "wordstats", os!["--lang", "fr", "--top", "1", "samples/phare.txt"]);
    assert_eq!(out, "     6  gardien\n");

    // Composition: an artifact bound again.
    bound(
        &h,
        os![
            "--embed-program",
            "-o",
            "bin/top3",
            "--",
            format!(".{}{}", std::path::MAIN_SEPARATOR, Path::new("bin").join(exe("topwords")).display()),
            "--top",
            "3"
        ],
    );
    let out = artifact(&h, "top3", os!["samples/lighthouse.txt"]);
    assert_eq!(out.lines().count(), 3, "{out}");

    // The program installed on the destination, found in PATH.
    tool(&h, "cargo", &["install", "--path", ".", "--root", "installed", "--locked", "--quiet"]);
    bound(&h, os!["-o", "bin/topwords-installed", "--", "wordstats", "--stopwords", "@file:stopwords/en.txt", "@args"]);
    let path = std::env::join_paths(
        std::iter::once(h.path("installed").join("bin"))
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())),
    )
    .unwrap();
    let installed = h.path("bin").join(exe("topwords-installed"));
    let out = run(h.command(&installed).args(["--top", "1", "samples/lighthouse.txt"]).env("PATH", &path));
    assert_success(&out, "topwords-installed");
    assert_eq!(stdout(&out), "     8  keeper\n");

    // Build products can go: every artifact carries what it needs.
    fs::remove_dir_all(h.path("target")).unwrap();
    fs::remove_dir_all(h.path("stopwords")).unwrap();
    let out = artifact(&h, "topwords", os!["--top", "1", "samples/lighthouse.txt"]);
    assert_eq!(out, "     8  keeper\n");
}

#[test]
fn node_example() {
    let h = example("node");
    tool(&h, "npm", &["ci", "--no-audit", "--no-fund"]);
    tool(&h, "npm", &["test"]);
    let expected = ["<title>Release notes</title>", "<strong>one executable</strong>"];

    // node_modules bundled, the destination's node.
    tool(&h, "npm", &["ci", "--omit=dev", "--no-audit", "--no-fund"]);
    let with_modules = os!["--include", "package.json", "--include", "node_modules", "--include", "templates"];
    let mut args = os!["-o", "bin/md2html", "--bundle", "shared"];
    args.extend(with_modules.clone());
    args.extend(os!["--", "node", "@file:src/md2html.js", "@args"]);
    bound(&h, args);
    assert_contains(&artifact(&h, "md2html", os!["samples/post.md"]), &expected);

    // A preset: another template, bound as an argument.
    let mut args = os!["-o", "bin/md2html-dark", "--bundle", "shared"];
    args.extend(with_modules);
    args.extend(os!["--", "node", "@file:src/md2html.js", "--template", "@file:templates/dark.html", "@args"]);
    bound(&h, args);
    assert_contains(&artifact(&h, "md2html-dark", os!["samples/post.md"]), &["<body class=\"dark\">", expected[1]]);

    // One bundled script instead of node_modules.
    tool(&h, "npm", &["ci", "--no-audit", "--no-fund"]);
    tool(&h, "npm", &["run", "bundle"]);
    bound(
        &h,
        os!["-o", "bin/md2html-single", "--include", "templates", "--", "node", "@file:build/md2html.mjs", "@args"],
    );
    assert_contains(&artifact(&h, "md2html-single", os!["samples/post.md"]), &expected);

    // Node.js itself embedded.
    let node = match std::env::var_os("BOUND_EXAMPLE_NODE") {
        Some(node) => node,
        None => tool(&h, "node", &["-p", "process.execPath"]).trim().into(),
    };
    bound(
        &h,
        os![
            "--embed-program",
            "--bundle",
            "shared",
            "-o",
            "bin/md2html-standalone",
            "--include",
            "templates",
            "--",
            node,
            "@file:build/md2html.mjs",
            "@args"
        ],
    );
    // Without node_modules, the sources or any node on PATH.
    for dir in ["node_modules", "build", "src"] {
        fs::remove_dir_all(h.path(dir)).unwrap();
    }
    let out = run(h.command(&h.path("bin").join(exe("md2html-standalone"))).arg("samples/post.md").env("PATH", ""));
    assert_success(&out, "md2html-standalone");
    assert_contains(&stdout(&out), &expected);
    // The other artifacts carry their node_modules and scripts too.
    assert_contains(&artifact(&h, "md2html", os!["samples/post.md"]), &expected);
    assert_contains(&artifact(&h, "md2html-single", os!["samples/post.md"]), &expected);
}

#[test]
fn python_example() {
    let h = example("python");
    tool(&h, "uv", &["sync", "--locked"]);
    tool(&h, "uv", &["run", "--locked", "ty", "check"]);
    tool(&h, "uv", &["run", "--locked", "pytest", "-q"]);
    let expected = ["<h1>Sales</h1>", "Nuts &amp; Bolts", "<td class=\"number\">5450.49</td>"];

    // The wheel, run by uv on the destination.
    tool(&h, "uv", &["build", "--wheel"]);
    bound(
        &h,
        os![
            "-o",
            "bin/report-uvx",
            "--bundle",
            "shared",
            "--",
            "uvx",
            "--from",
            "@file:dist/report-0.1.0-py3-none-any.whl",
            "report",
            "@args"
        ],
    );
    assert_contains(&artifact(&h, "report-uvx", os!["samples/sales.csv", "--title", "Sales"]), &expected);

    // Dependencies bundled, the destination's Python: here, the one uv
    // installed for the project.
    tool(&h, "uv", &["pip", "install", "--python", "3.13", "--target", "build/site-packages", "."]);
    let python = if cfg!(windows) { "python" } else { "python3" };
    bound(
        &h,
        os![
            "-o",
            "bin/report-py",
            "--bundle",
            "shared",
            "--env",
            "PYTHONPATH=@file:build/site-packages",
            "--",
            python,
            "-m",
            "report",
            "@args"
        ],
    );
    // (--system: not the project's .venv, which has the dependencies.)
    let interpreter = PathBuf::from(tool(&h, "uv", &["python", "find", "--system", "3.13"]).trim());
    let path = std::env::join_paths(
        std::iter::once(interpreter.parent().unwrap().to_path_buf())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let out = run(h
        .command(&h.path("bin").join(exe("report-py")))
        .args(["samples/sales.csv", "--title", "Sales"])
        .env("PATH", &path));
    assert_success(&out, "report-py");
    assert_contains(&stdout(&out), &expected);

    // Self-contained: a relocatable CPython with the app installed in it.
    tool(&h, "uv", &["python", "install", "3.13", "--install-dir", "build/runtime", "--no-bin", "--no-registry"]);
    let runtime = fs::read_dir(h.path("build/runtime"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.file_name().unwrap().to_string_lossy().starts_with("cpython-3.13."))
        .unwrap();
    fs::rename(runtime, h.path("build/python")).unwrap();
    let interpreter: PathBuf = if cfg!(windows) {
        ["build", "python", "python.exe"].iter().collect()
    } else {
        ["build", "python", "bin", "python3.13"].iter().collect()
    };
    let interpreter = interpreter.to_str().unwrap();
    tool(&h, "uv", &["pip", "install", "--python", interpreter, "--prefix", "build/python", "."]);
    let absolute = h.path(interpreter);
    // On Windows, the standard library and site-packages are in Lib; the
    // rest includes Tcl/Tk files written in Python 2, which do not compile.
    let compiled = if cfg!(windows) { "build/python/Lib" } else { "build/python" };
    tool(
        &h,
        absolute.to_str().unwrap(),
        &["-m", "compileall", "-q", "-j", "0", "--invalidation-mode", "checked-hash", compiled],
    );
    bound(
        &h,
        os![
            "--embed-program",
            "--bundle",
            "shared",
            "-o",
            "bin/report",
            "--include",
            "build/python",
            "--",
            interpreter,
            "-I",
            "-m",
            "report",
            "@args"
        ],
    );
    // Without the build directory, and ignoring a hostile environment.
    fs::remove_dir_all(h.path("build")).unwrap();
    let out = run(h
        .command(&h.path("bin").join(exe("report")))
        .args(["samples/sales.csv", "--title", "Sales"])
        .env("PYTHONHOME", h.path("nowhere"))
        .env("PYTHONPATH", h.path("nowhere")));
    assert_success(&out, "report");
    assert_contains(&stdout(&out), &expected);

    // A preset, composed from the self-contained artifact.
    let report = format!(".{}{}", std::path::MAIN_SEPARATOR, Path::new("bin").join(exe("report")).display());
    bound(
        &h,
        os![
            "--embed-program",
            "--bundle",
            "shared",
            "-o",
            "bin/sales-summary",
            "--",
            report,
            "--title",
            "Sales summary",
            "--template",
            "@file:templates/summary.html.j2",
            "@args"
        ],
    );
    assert_contains(
        &artifact(&h, "sales-summary", os!["samples/sales.csv"]),
        &["<h1>Sales summary</h1>", "<li>revenue: 5450.49</li>"],
    );
}
