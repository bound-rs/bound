//! Bundled resources: `@file`, `--include`, environment bindings, working
//! directory, and the isolation of each run's materialized copy.

use std::fs;
use std::path::{Path, PathBuf};

use bound_tests::{Harness, Report, assert_removed, assert_success, bins, os, run, same_path, stdout};

fn harness() -> Harness {
    Harness::new(bins!())
}

fn lines(text: &str) -> Vec<&str> {
    text.lines().collect()
}

#[test]
fn embedded_file_survives_removal_of_the_original() {
    let h = harness();
    h.write("config.toml", "[db]\nurl = \"x\"\n");
    let artifact = h.bind("show-config", os!["--", h.bins.fixture, "read", "@file:config.toml"]);
    fs::rename(h.path("config.toml"), h.path("elsewhere.toml")).unwrap();
    let out = h.run(&artifact, os![]);
    assert_success(&out, "show-config");
    assert_eq!(stdout(&out), "[db]\nurl = \"x\"\n");
}

#[test]
fn file_arguments_become_native_paths_under_bound_root() {
    let h = harness();
    h.write("schema.sql", "create table t;");
    let artifact = h.bind("migrate", os!["--", h.bins.fixture, "report", "--schema", "@file:schema.sql"]);
    let report = h.report(&artifact, os!["production.db"]);
    let args = report.args();
    assert_eq!(args.len(), 3);
    assert_eq!(args[0], "--schema");
    assert_eq!(args[2], "production.db");
    let schema = PathBuf::from(&args[1]);
    assert!(schema.is_absolute(), "{}", schema.display());
    let root = PathBuf::from(report.env("BOUND_ROOT").expect("BOUND_ROOT is set"));
    assert_eq!(schema, root.join("schema.sql"));
    assert!(root.is_absolute());
    assert_removed(&root);
}

#[test]
fn bundle_directory_lives_in_the_temporary_directory() {
    let h = harness();
    h.write("x.txt", "x");
    let artifact = h.bind("where", os!["--include", "x.txt", "--", h.bins.fixture, "report"]);
    let root = PathBuf::from(h.report(&artifact, os![]).env("BOUND_ROOT").unwrap());
    let temp = fs::canonicalize(std::env::temp_dir()).unwrap();
    let parent = root.parent().unwrap();
    assert!(same_path(parent, &temp), "{} is not in {}", root.display(), temp.display());
    assert!(root.file_name().unwrap().to_string_lossy().starts_with("bound-"));
}

#[test]
fn spaces_and_unicode_in_resource_names() {
    let h = harness();
    h.write("dir with space/ünïcødé file ✓.txt", "content ✓");
    let artifact = h.bind("unicode", os!["--", h.bins.fixture, "read", "@file:dir with space/ünïcødé file ✓.txt"]);
    fs::remove_dir_all(h.path("dir with space")).unwrap();
    let out = h.run(&artifact, os![]);
    assert_success(&out, "unicode");
    assert_eq!(stdout(&out), "content ✓");
}

#[test]
fn files_outside_the_current_directory_are_placed_by_name() {
    let h = harness();
    let outside = tempfile::tempdir().unwrap();
    let file = outside.path().join("external.conf");
    fs::write(&file, "from outside").unwrap();
    let mut arg = std::ffi::OsString::from("@file:");
    arg.push(&file);
    let artifact = h.bind("outside", os!["--", h.bins.fixture, "report", arg]);
    let report = h.report(&artifact, os![]);
    let root = PathBuf::from(report.env("BOUND_ROOT").unwrap());
    assert_eq!(PathBuf::from(&report.args()[0]), root.join("external.conf"));
    // No absolute build-machine path is recorded in the artifact.
    let bytes = fs::read(&artifact).unwrap();
    let needle = outside.path().to_string_lossy().into_owned();
    assert!(!bytes.windows(needle.len()).any(|w| w == needle.as_bytes()), "artifact leaks {needle}");
}

#[test]
fn environment_bindings() {
    let h = harness();
    h.write("config.toml", "cfg");
    let artifact = h.bind(
        "app",
        os![
            "--env",
            "MODE=production",
            "--env",
            "CONFIG=@file:config.toml",
            "--env",
            "EMPTY=",
            "--env",
            "UNICODE=ünï çødé ✓",
            "--env",
            "SPACES=a b  c",
            "--",
            h.bins.fixture,
            "report"
        ],
    );
    let report = h.report(&artifact, os![]);
    assert_eq!(report.env("MODE").as_deref(), Some("production"));
    assert_eq!(report.env("EMPTY").as_deref(), Some(""));
    assert_eq!(report.env("UNICODE").as_deref(), Some("ünï çødé ✓"));
    assert_eq!(report.env("SPACES").as_deref(), Some("a b  c"));
    let root = PathBuf::from(report.env("BOUND_ROOT").unwrap());
    assert_eq!(PathBuf::from(report.env("CONFIG").unwrap()), root.join("config.toml"));

    // The caller's environment is inherited...
    let report = Report::parse(&run(h.command(&artifact).env("FROM_CALLER", "yes")));
    assert_eq!(report.env("FROM_CALLER").as_deref(), Some("yes"));
    // ...but bound values win.
    let report = Report::parse(&run(h.command(&artifact).env("MODE", "caller")));
    assert_eq!(report.env("MODE").as_deref(), Some("production"));
}

#[test]
fn file_backed_environment_values_are_readable() {
    let h = harness();
    h.write("secret-free.cfg", "setting=1\n");
    let artifact = h.bind(
        "env-file",
        os!["--env", "APP_CONFIG=@file:secret-free.cfg", "--", h.bins.fixture, "read-env", "APP_CONFIG"],
    );
    fs::remove_file(h.path("secret-free.cfg")).unwrap();
    let out = h.run(&artifact, os![]);
    assert_success(&out, "env-file");
    assert_eq!(stdout(&out), "setting=1\n");
}

#[test]
fn included_directory_with_bundle_working_directory() {
    let h = harness();
    h.write("templates/index.html", "<h1>hi</h1>");
    h.write("templates/partials/nav.html", "<nav/>");
    fs::create_dir_all(h.path("templates/empty")).unwrap();
    h.write("assets/logo.png", [0x89, b'P', b'N', b'G']);
    let artifact = h.bind(
        "renderer",
        os![
            "--include",
            "./templates",
            "--include",
            "./assets/logo.png",
            "--cwd",
            "bundle",
            "--",
            h.bins.fixture,
            "ls",
            "."
        ],
    );
    fs::remove_dir_all(h.path("templates")).unwrap();
    fs::remove_dir_all(h.path("assets")).unwrap();
    let out = h.run(&artifact, os![]);
    assert_success(&out, "renderer");
    assert_eq!(
        lines(&stdout(&out)),
        [
            "assets/",
            "assets/logo.png",
            "templates/",
            "templates/empty/",
            "templates/index.html",
            "templates/partials/",
            "templates/partials/nav.html"
        ]
    );
}

#[test]
fn included_files_are_readable_through_bound_root() {
    let h = harness();
    h.write("templates/page.html", "<p>page</p>");
    let artifact = h.bind(
        "page",
        os!["--include", "templates", "--cwd", "bundle", "--", h.bins.fixture, "read", "templates/page.html"],
    );
    fs::remove_dir_all(h.path("templates")).unwrap();
    let out = h.run(&artifact, os![]);
    assert_success(&out, "page");
    assert_eq!(stdout(&out), "<p>page</p>");
}

#[test]
fn bundle_working_directory_is_bound_root() {
    let h = harness();
    h.write("x.txt", "x");
    let artifact = h.bind("cwd", os!["--include", "x.txt", "--cwd", "bundle", "--", h.bins.fixture, "report"]);
    let report = h.report(&artifact, os![]);
    let root = PathBuf::from(report.env("BOUND_ROOT").unwrap());
    assert_eq!(report.cwd(), root);
}

#[test]
fn bundle_working_directory_without_resources() {
    let h = harness();
    let artifact = h.bind("empty-bundle", os!["--cwd", "bundle", "--", h.bins.fixture, "report"]);
    let report = h.report(&artifact, os![]);
    let root = PathBuf::from(report.env("BOUND_ROOT").expect("a bundle directory exists"));
    assert_eq!(report.cwd(), root);
}

#[test]
fn inherited_working_directory_is_the_callers() {
    let h = harness();
    let sub = h.path("sub dir ✓");
    fs::create_dir(&sub).unwrap();
    for (name, extra) in [("plain", os![]), ("with-resource", os!["--include", "x.txt"])] {
        h.write("x.txt", "x");
        let mut args = extra;
        args.extend(os!["--", h.bins.fixture, "report"]);
        let artifact = h.bind(name, args);
        let report = Report::parse(&run(h.command(&artifact).current_dir(&sub)));
        assert!(same_path(&report.cwd(), &sub), "{name}: cwd {}", report.cwd().display());
    }
}

#[test]
fn include_as_places_resources_explicitly() {
    let h = harness();
    h.write("build/out/app.js", "js");
    h.write("build/out/css/site.css", "css");
    let artifact = h.bind(
        "placed",
        os![
            "--include-as",
            "web/static=build/out",
            "--include-as",
            "root.txt=build/out/app.js",
            "--cwd",
            "bundle",
            "--",
            h.bins.fixture,
            "ls",
            "."
        ],
    );
    let out = h.run(&artifact, os![]);
    assert_success(&out, "placed");
    assert_eq!(
        lines(&stdout(&out)),
        ["root.txt", "web/", "web/static/", "web/static/app.js", "web/static/css/", "web/static/css/site.css"]
    );
}

#[test]
fn including_the_current_directory_places_it_at_the_root() {
    let h = harness();
    h.write("project/a.txt", "a");
    h.write("project/sub/b.txt", "b");
    let mut cmd = h.bound();
    cmd.current_dir(h.path("project")).args(os![
        "-o",
        h.path("dot-include"),
        "--include",
        ".",
        "--cwd",
        "bundle",
        "--",
        h.bins.fixture,
        "ls",
        "."
    ]);
    assert_success(&run(&mut cmd), "bound");
    let artifact = h.path(bound_tests::exe("dot-include"));
    let out = h.run(&artifact, os![]);
    assert_eq!(lines(&stdout(&out)), ["a.txt", "sub/", "sub/b.txt"]);
}

#[test]
fn directories_can_be_file_arguments() {
    let h = harness();
    h.write("public/index.html", "home");
    let artifact = h.bind("serve", os!["--", h.bins.fixture, "ls", "@file:public"]);
    fs::remove_dir_all(h.path("public")).unwrap();
    let out = h.run(&artifact, os![]);
    assert_success(&out, "serve");
    assert_eq!(lines(&stdout(&out)), ["index.html"]);
}

#[test]
fn modifications_by_the_program_do_not_persist() {
    let h = harness();
    h.write("state.txt", "original");
    let artifact = h.bind("mutate", os!["--", h.bins.fixture, "mutate", "@file:state.txt"]);
    for _ in 0..3 {
        let out = h.run(&artifact, os![]);
        assert_success(&out, "mutate");
        assert_eq!(stdout(&out), "original");
    }
}

#[test]
fn concurrent_runs_are_isolated() {
    let h = harness();
    h.write("data.txt", "shared original");
    let mutate = h.bind("mutate", os!["--", h.bins.fixture, "mutate", "@file:data.txt"]);
    let report = h.bind("report", os!["--include", "data.txt", "--", h.bins.fixture, "report"]);

    let results: Vec<(String, String)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    let mutated = h.run(&mutate, os![]);
                    assert_success(&mutated, "mutate");
                    let reported = Report::parse(&h.run(&report, os![]));
                    (stdout(&mutated), reported.env("BOUND_ROOT").unwrap())
                })
            })
            .collect();
        handles.into_iter().map(|t| t.join().unwrap()).collect()
    });
    for (content, _) in &results {
        assert_eq!(content, "shared original");
    }
    let mut roots: Vec<&String> = results.iter().map(|(_, root)| root).collect();
    roots.sort();
    roots.dedup();
    assert_eq!(roots.len(), 16, "every run gets its own bundle directory");
}

#[test]
fn large_files_round_trip() {
    let h = harness();
    // 8 MiB of incompressible pseudo-random data plus a compressible tail.
    let mut data = Vec::with_capacity(9 << 20);
    let mut state = 0x2545_f491_4f6c_dd1du64;
    while data.len() < 8 << 20 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.extend_from_slice(&state.to_le_bytes());
    }
    data.extend(std::iter::repeat_n(b'z', 1 << 20));
    h.write("big.bin", &data);
    let artifact = h.bind("big", os!["--", h.bins.fixture, "read", "@file:big.bin"]);
    fs::remove_file(h.path("big.bin")).unwrap();
    let out = h.run(&artifact, os![]);
    assert_success(&out, "big");
    assert!(out.stdout == data, "content differs ({} vs {} bytes)", out.stdout.len(), data.len());
}

#[test]
fn empty_files_and_identical_contents() {
    let h = harness();
    h.write("d/empty", "");
    h.write("d/one", "same");
    h.write("d/two", "same");
    let artifact = h.bind(
        "dedup",
        os!["--include", "d", "--cwd", "bundle", "--", h.bins.fixture, "read", "d/empty", "d/one", "d/two"],
    );
    let out = h.run(&artifact, os![]);
    assert_success(&out, "dedup");
    assert_eq!(stdout(&out), "samesame");
}

#[test]
fn bound_root_is_removed_even_when_the_program_fails() {
    let h = harness();
    h.write("x.txt", "x");
    let artifact = h.bind("fails", os!["--include", "x.txt", "--", h.bins.fixture, "env-exit", "BOUND_ROOT", "7"]);
    let out = h.run(&artifact, os![]);
    assert_eq!(out.status.code(), Some(7));
    let root = PathBuf::from(stdout(&out).trim());
    assert!(root.is_absolute(), "{}", root.display());
    assert_removed(&root);
}

#[test]
fn include_lists_bundle_many_files_that_bundle_references_find() {
    let h = harness();
    h.write("a.txt", "a");
    h.write("dir/b.txt", "b");
    h.write("with space.txt", "c");
    // Windows line endings and blank lines are fine.
    h.write("list.txt", "data/a.txt=a.txt\r\ndata/sub/b.txt=dir/b.txt\n\nx y/z.txt=with space.txt\n");
    let artifact = h.bind(
        "listed",
        os![
            "--include-list",
            "list.txt",
            "--",
            h.bins.fixture,
            "read",
            "@bundle:data/a.txt",
            "@bundle:data/sub/b.txt",
            "@bundle:x y/z.txt"
        ],
    );
    for input in ["a.txt", "dir/b.txt", "with space.txt", "list.txt"] {
        fs::remove_file(h.path(input)).unwrap();
    }
    let out = h.run(&artifact, os![]);
    assert_success(&out, "listed");
    assert_eq!(stdout(&out), "abc");

    // A directory the list created, in the environment.
    h.write("a.txt", "a");
    h.write("list.txt", "data/a.txt=a.txt\n");
    let artifact = h.bind(
        "listed-env",
        os!["--include-list", "list.txt", "--env", "DATA=@bundle:data", "--", h.bins.fixture, "report"],
    );
    let report = h.report(&artifact, os![]);
    let root = PathBuf::from(report.env("BOUND_ROOT").unwrap());
    assert_eq!(PathBuf::from(report.env("DATA").unwrap()), root.join("data"));
}

#[test]
fn bundle_references_and_include_lists_are_checked() {
    let h = harness();
    h.write("a.txt", "a");
    let err = h.bound_fails(os!["--include", "a.txt", "-o", "x", "--", h.bins.fixture, "read", "@bundle:b.txt"]);
    assert!(err.contains("@bundle:b.txt: nothing is bundled there"), "{err}");
    let err = h.bound_fails(os!["--env", "X=@bundle:.", "-o", "x", "--", h.bins.fixture]);
    assert!(err.contains("bundle directory itself"), "{err}");
    h.write("list.txt", "ok.txt=a.txt\nno-equals-sign\n");
    let err = h.bound_fails(os!["--include-list", "list.txt", "-o", "x", "--", h.bins.fixture]);
    assert!(err.contains("list.txt, line 2: expected DEST=PATH"), "{err}");
    h.write("list.txt", "../escape=a.txt\n");
    let err = h.bound_fails(os!["--include-list", "list.txt", "-o", "x", "--", h.bins.fixture]);
    assert!(err.contains("line 1") && err.contains("unsafe resource path"), "{err}");
    let err = h.bound_fails(os!["--include-list", "missing.txt", "-o", "x", "--", h.bins.fixture]);
    assert!(err.contains("--include-list missing.txt: cannot read it"), "{err}");
}

#[test]
fn embedded_programs_can_be_placed_next_to_their_runfiles() {
    // The layout Bazel's runfiles libraries expect: the program at `tool`,
    // its files under `tool.runfiles`, and RUNFILES_DIR pointing there.
    let h = harness();
    h.write("data.txt", "data");
    let tool = bound_tests::exe("tool");
    let runfiles = format!("{tool}.runfiles");
    h.write("list.txt", format!("{runfiles}/_main/pkg/data.txt=data.txt\n"));
    // Shared, so that the files are still there after the program exits.
    let artifact = h.bind(
        "placed-program",
        os![
            "--bundle",
            "shared",
            "--embed-program-as",
            &tool,
            "--include-list",
            "list.txt",
            "--env",
            format!("RUNFILES_DIR=@bundle:{runfiles}"),
            "--unset",
            "RUNFILES_MANIFEST_FILE",
            "--",
            h.bins.fixture,
            "report"
        ],
    );
    let report = Report::parse(&run(h.command(&artifact).env("RUNFILES_MANIFEST_FILE", "/outer/MANIFEST")));
    let root = PathBuf::from(report.env("BOUND_ROOT").unwrap());
    assert!(same_path(&PathBuf::from(report.argv0()), &root.join(&tool)), "{}", report.argv0());
    let runfiles_dir = PathBuf::from(report.env("RUNFILES_DIR").unwrap());
    assert_eq!(runfiles_dir, root.join(&runfiles));
    assert_eq!(fs::read_to_string(runfiles_dir.join("_main/pkg/data.txt")).unwrap(), "data");
    assert_eq!(report.env("RUNFILES_MANIFEST_FILE"), None);

    let err = h.bound_fails(os!["--embed-program-as", "../up", "-o", "x", "--", h.bins.fixture]);
    assert!(err.contains("--embed-program-as ../up"), "{err}");
}

#[test]
fn layouts_place_the_program_and_declare_links_and_directories() {
    // A layout of the kind language rules produce: the program somewhere in
    // the bundle, files where the language expects them, copies of one file
    // from several places, links between packages, and empty directories.
    let h = harness();
    h.write("a.txt", "a");
    h.write("copy-of-a.txt", "a");
    let program = format!("tools/bin/{}", bound_tests::exe("fixture"));
    let list = format!(
        "{program}={}\ndata/a.txt=a.txt\ndata/a.txt=copy-of-a.txt\ndata/more/a.txt=a.txt\nvar/cache=@dir\n\
         links/a.txt=@link:../data/a.txt\nlinks/data=@link:../data\nlinks/data=@link:../data\n\
         links/read=@readlink:on-disk-link\n",
        h.bins.fixture.display()
    );
    // A link on disk, with the host's separators.
    bound_tests::symlink_file(Path::new("..").join("data").join("more").join("a.txt"), h.path("on-disk-link"));
    h.write("list.txt", &list);
    let artifact = h.bind(
        "layout",
        os!["--bundle", "shared", "--include-list", "list.txt", "--", format!("@bundle:{program}"), "report"],
    );
    let report = h.report(&artifact, os![]);
    let root = PathBuf::from(report.env("BOUND_ROOT").unwrap());
    assert!(same_path(&PathBuf::from(report.argv0()), &root.join(&program)), "{}", report.argv0());

    let listing = stdout(&h.run(&h.bind("layout-ls", os!["--", h.bins.fixture, "ls", &root]), os![]));
    let mut expected = vec!["data/", "data/a.txt", "data/more/", "data/more/a.txt", "tools/", "tools/bin/"];
    expected.push(&program);
    expected.extend(["var/", "var/cache/"]);
    expected.extend([
        "links/",
        "links/a.txt -> ../data/a.txt",
        "links/data -> ../data",
        "links/read -> ../data/more/a.txt",
    ]);
    expected.sort();
    assert_eq!(lines(&listing), expected);
    let read = |path: &str| fs::read_to_string(root.join(path)).unwrap();
    assert_eq!(read("links/a.txt") + &read("links/data/more/a.txt") + &read("links/read"), "aaa");
    // The program is executable (Unix), and read-only, as shared bundles are.
    let meta = fs::metadata(root.join(&program)).unwrap();
    assert!(meta.permissions().readonly());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o555);
    }
}

#[test]
fn layout_errors_are_reported() {
    let h = harness();
    h.write("a.txt", "a");
    h.write("b.txt", "b");
    h.write("list.txt", "dir/a.txt=a.txt\n");
    for (args, expected) in [
        (os!["--", "@bundle:tool"], "the program @bundle:tool is not bundled"),
        (os!["--include-list", "list.txt", "--", "@bundle:dir"], "the program @bundle:dir is a directory, not a file"),
        (os!["--embed-program", "--include-list", "list.txt", "--", "@bundle:dir/a.txt"], "already in the bundle"),
        (os!["--", "@file:a.txt"], "cannot be the program"),
        (os!["--include-as", "x=a.txt", "--include-as", "x=b.txt", "--", h.bins.fixture], "would come from both"),
        (os!["--include-as", "x=@link:/etc/passwd", "--", h.bins.fixture], "symlink target is absolute"),
        (os!["--include-as", "x=@link:../../outside", "--", h.bins.fixture], "target escapes the bundle root"),
        (os!["--include-as", "x=@link:missing", "--", h.bins.fixture], "target does not exist in the bundle"),
        (os!["--include-as", ".=@link:x", "--", h.bins.fixture], "a link cannot be the bundle root"),
    ] {
        let mut full = os!["-o", "x"];
        full.extend(args);
        let err = h.bound_fails(full);
        assert!(err.contains(expected), "expected {expected:?} in: {err}");
    }
}

/// The access list of a file or directory in SDDL, and this user as SDDL
/// names it (a SID, or an alias such as LA for the built-in Administrator).
#[cfg(windows)]
fn access_list(path: &Path) -> (String, String) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetTokenInformation, OWNER_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let text = |p: *const u16| {
        // SAFETY: a NUL-terminated string from the OS.
        unsafe {
            let n = (0..).take_while(|&i| *p.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    };
    // SAFETY: standard security queries; every OS allocation is freed.
    unsafe {
        let mut descriptor = std::ptr::null_mut();
        let rc = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        );
        assert_eq!(rc, 0, "{}", path.display());
        let mut sddl = std::ptr::null_mut();
        assert_ne!(
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl,
                std::ptr::null_mut()
            ),
            0
        );
        let list = text(sddl);
        LocalFree(sddl.cast());
        LocalFree(descriptor);

        let mut token: HANDLE = std::ptr::null_mut();
        assert_ne!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token), 0);
        let mut buffer = vec![0u64; 64];
        let mut len = 0u32;
        assert_ne!(GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), 512, &mut len), 0);
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut sid = std::ptr::null_mut();
        assert_ne!(ConvertSidToStringSidW(user.User.Sid, &mut sid), 0);
        let me = text(sid);
        LocalFree(sid.cast());
        windows_sys::Win32::Foundation::CloseHandle(token);

        // How SDDL names this user: through a descriptor owned by it.
        let owner: Vec<u16> = format!("O:{me}").encode_utf16().chain([0]).collect();
        let mut descriptor = std::ptr::null_mut();
        assert_ne!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                owner.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut()
            ),
            0
        );
        let mut named = std::ptr::null_mut();
        assert_ne!(
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION,
                &mut named,
                std::ptr::null_mut()
            ),
            0
        );
        let me = text(named).trim_start_matches("O:").to_owned();
        LocalFree(named.cast());
        LocalFree(descriptor);
        (list, me)
    }
}

#[test]
fn the_bundle_is_private() {
    // Only the user may enter a bundle directory: mode 0700 (Unix), an
    // access list for the user and the system alone, not inherited from
    // the temporary directory (Windows). Executability is kept (Unix).
    let h = harness();
    h.write("tools/run.sh", "#!/bin/sh\necho ran\n");
    h.write("tools/data.txt", "data");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(h.path("tools/run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(h.path("tools/data.txt"), fs::Permissions::from_mode(0o644)).unwrap();
        let modes = |target: &str| {
            let artifact = h.bind(
                &format!("mode-{}", target.replace('/', "-")),
                os!["--include", "tools", "--cwd", "bundle", "--", h.bins.fixture, "mode", target],
            );
            stdout(&h.run(&artifact, os![])).trim().to_owned()
        };
        assert_eq!(modes("tools/run.sh"), "700");
        assert_eq!(modes("tools/data.txt"), "600");
        assert_eq!(modes("tools"), "700");
        assert_eq!(modes("."), "700", "the bundle directory must be private");
        let exec = h.bind("exec-script", os!["--include", "tools", "--cwd", "bundle", "--", "./tools/run.sh"]);
        let out = h.run(&exec, os![]);
        assert_success(&out, "exec-script");
        assert_eq!(stdout(&out), "ran\n");
    }
    #[cfg(windows)]
    {
        use std::io::BufRead;
        let artifact = h.bind("private", os!["--include", "tools", "--", h.bins.fixture, "hold"]);
        let mut child = h.command(&artifact).stdout(std::process::Stdio::piped()).spawn().unwrap();
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let root = PathBuf::from(line.trim().split_once(' ').unwrap().1);
        let (root_list, me) = access_list(&root);
        let (file_list, _) = access_list(&root.join("tools").join("data.txt"));
        let _ = child.kill();
        let _ = child.wait();
        assert!(root_list.starts_with("D:P("), "the access list must not be inherited: {root_list}");
        for (list, what) in [(&root_list, "bundle directory"), (&file_list, "bundled file")] {
            for entry in list.split('(').skip(1) {
                let sid = entry.trim_end_matches(')').rsplit(';').next().unwrap();
                assert!(sid == me || sid == "SY", "the {what} lets {sid} in: {list}");
            }
        }
    }
}

#[test]
fn special_files_are_rejected() {
    // What is neither a file, a directory nor a link cannot be bundled, and
    // bound says which: a named pipe (Unix), a reparse point that no file
    // system filter serves (Windows).
    let h = harness();
    fs::create_dir(h.path("dir")).unwrap();
    #[cfg(unix)]
    let expected = {
        use std::os::unix::ffi::OsStrExt;
        let fifo = std::ffi::CString::new(h.path("dir/special").as_os_str().as_bytes()).unwrap();
        // SAFETY: creating a FIFO at a path we own.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        "named pipe"
    };
    #[cfg(windows)]
    let expected = {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT};
        use windows_sys::Win32::System::IO::DeviceIoControl;
        let path = h.write("dir/special", "placeholder");
        let file = fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(&path)
            .unwrap();
        // REPARSE_GUID_DATA_BUFFER with a tag that is not Microsoft's and
        // not a link's.
        let data = b"bound test";
        let mut buffer = 0x0000_beefu32.to_le_bytes().to_vec();
        buffer.extend((data.len() as u16).to_le_bytes());
        buffer.extend(0u16.to_le_bytes());
        buffer.extend([0x42u8; 16]);
        buffer.extend(data);
        let mut returned = 0u32;
        // SAFETY: a valid handle and a complete buffer of the given length.
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle().cast(),
                0x0009_00A4,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "setting a reparse point: {}", std::io::Error::last_os_error());
        "special"
    };
    let err = h.bound_fails(os!["--include", "dir", "-o", "o", "--", h.bins.fixture]);
    assert!(err.contains(expected), "{err}");
    assert!(!h.path(bound_tests::exe("o")).exists());
}

#[test]
fn non_unicode_file_names() {
    // Linux file names are bytes: names that are not UTF-8 are bundled as
    // they are. Windows names must be Unicode in a bundle (NTFS allows an
    // unpaired surrogate, which bound refuses rather than alter). macOS file
    // systems do not allow such names at all.
    let h = harness();
    fs::create_dir(h.path("d")).unwrap();
    #[cfg(unix)]
    let name = {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::OsStr::from_bytes(b"caf\xe9.txt").to_owned()
    };
    #[cfg(windows)]
    let name = {
        use std::os::windows::ffi::OsStringExt;
        let wide: Vec<u16> = "caf".encode_utf16().chain([0xd800]).chain(".txt".encode_utf16()).collect();
        std::ffi::OsString::from_wide(&wide)
    };
    let written = fs::write(h.path("d").join(&name), "odd name");
    let args = os!["--include", "d", "--cwd", "bundle", "--", h.bins.fixture, "read", Path::new("d").join(&name)];
    #[cfg(target_vendor = "apple")]
    {
        let error = written.unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EILSEQ), "{error}");
        drop(args);
    }
    #[cfg(windows)]
    {
        written.unwrap();
        let mut full = os!["-o", "odd"];
        full.extend(args);
        let err = h.bound_fails(full);
        assert!(err.contains("not valid Unicode"), "{err}");
    }
    #[cfg(all(unix, not(target_vendor = "apple")))]
    {
        written.unwrap();
        let artifact = h.bind("odd", args);
        fs::remove_dir_all(h.path("d")).unwrap();
        assert_eq!(stdout(&h.run(&artifact, os![])), "odd name");
    }
}

#[test]
fn locked_down_bundle_directories_are_still_removed() {
    // The program takes away its own write permission (Unix) or marks its
    // files read-only (Windows): the bundle directory is removed anyway.
    let h = harness();
    h.write("d/sub/f.txt", "x");
    let artifact = h.bind("lockdown", os!["--include", "d", "--cwd", "bundle", "--", h.bins.fixture, "lock", "d"]);
    let out = h.run(&artifact, os![]);
    assert_success(&out, "lockdown");
    let root = PathBuf::from(stdout(&out).trim());
    assert!(root.is_absolute(), "{root:?}");
    assert_removed(&root);
}

#[test]
fn resources_are_extracted_under_the_temporary_directory() {
    let h = harness();
    h.write("config.toml", "x");
    let artifact = h.bind("where", os!["--", h.bins.fixture, "report", "@file:config.toml"]);
    let report = h.report(&artifact, os![]);
    let root = PathBuf::from(report.env("BOUND_ROOT").unwrap());
    let temp = fs::canonicalize(std::env::temp_dir()).unwrap();
    let parent = fs::canonicalize(root.parent().unwrap()).unwrap_or_else(|_| root.parent().unwrap().to_path_buf());
    assert_eq!(parent, temp, "{} is not under {}", root.display(), temp.display());
    // A path programs can use (on Windows, a drive path, not a \\?\ one).
    let path = &report.args()[0];
    assert!(Path::new(path).is_absolute() && !path.starts_with(r"\\?\"), "{path}");
    assert!(path.ends_with(&format!("{}config.toml", std::path::MAIN_SEPARATOR)), "{path}");
}

#[test]
fn deep_resource_paths_are_extracted() {
    // Well beyond MAX_PATH (260) once placed in the temporary directory,
    // which Windows paths must handle explicitly.
    let h = harness();
    let deep: PathBuf = (0..12).map(|i| format!("directory-level-{i:02}")).collect();
    let relative = PathBuf::from("tree").join(deep).join("configuration-file-with-a-long-name.txt");
    h.write(&relative, "deep content");
    assert!(std::env::temp_dir().join("bound-0123456789abcdef").join(&relative).as_os_str().len() > 260);
    let artifact = h.bind("deep", os!["--include", "tree", "--cwd", "bundle", "--", h.bins.fixture, "read", &relative]);
    let out = h.run(&artifact, os![]);
    assert_success(&out, "deep");
    assert_eq!(stdout(&out), "deep content");
}

#[test]
fn unset_removes_inherited_variables() {
    let h = harness();
    let artifact = h.bind("unset", os!["--unset", "DROP_ME", "--env", "KEEP=1", "--", h.bins.fixture, "report"]);
    let report = Report::parse(&run(h.command(&artifact).env("DROP_ME", "x").env("OTHER", "y")));
    assert_eq!(report.env("DROP_ME"), None);
    assert_eq!(report.env("OTHER").as_deref(), Some("y"));
    assert_eq!(report.env("KEEP").as_deref(), Some("1"));
    let shown = stdout(&h.bound_output(os!["inspect", &artifact]));
    assert!(shown.contains("DROP_ME (removed)"), "{shown}");

    for (args, expected) in [
        (os!["--unset", "BOUND_ROOT"], "BOUND_ROOT is reserved"),
        (os!["--unset", "A=B"], "not a variable name"),
        (os!["--unset", "Path", "--env", "PATH=x"], "more than once"),
    ] {
        let mut full = args;
        full.extend(os!["-o", "x", "--", h.bins.fixture]);
        let err = h.bound_fails(full);
        assert!(err.contains(expected), "{err}");
    }
}
