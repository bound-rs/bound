//! Shared helpers for bound's end-to-end tests.
//!
//! Every test gets a fresh temporary directory ([`Harness`]) in which it
//! runs the `bound` command line (built from this package as
//! `bound-test-cli`, together with its launcher) and the resulting
//! artifacts. The `bound-fixture` program serves as the bound target: it
//! reports exactly what it received (argv, environment, working directory,
//! stdin) as JSON, which lets tests check process semantics precisely on
//! every platform without relying on system tools.

#![allow(clippy::unwrap_used, clippy::missing_panics_doc)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

pub use serde_json::Value;

/// Paths of the executables under test.
#[derive(Debug, Clone)]
pub struct Bins {
    pub cli: PathBuf,
    pub launcher: PathBuf,
    pub fixture: PathBuf,
}

/// Builds [`Bins`] from the paths Cargo gives integration tests.
#[macro_export]
macro_rules! bins {
    () => {
        $crate::Bins {
            cli: ::std::path::PathBuf::from(env!("CARGO_BIN_EXE_bound-test-cli")),
            launcher: ::std::path::PathBuf::from(env!("CARGO_BIN_EXE_bound-test-launcher")),
            fixture: ::std::path::PathBuf::from(env!("CARGO_BIN_EXE_bound-fixture")),
        }
    };
}

/// `os!["a", path, other]`: a `Vec<OsString>` from anything `AsRef<OsStr>`.
#[macro_export]
macro_rules! os {
    ($($e:expr),* $(,)?) => {
        vec![$(::std::ffi::OsString::from(::std::convert::AsRef::<::std::ffi::OsStr>::as_ref(&$e))),*]
    };
}

/// `name` plus the platform's executable suffix.
pub fn exe(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

/// A per-test working directory, with a cache directory of its own (so
/// that no test uses the real per-user cache).
#[derive(Debug)]
pub struct Harness {
    pub bins: Bins,
    dir: tempfile::TempDir,
    cache: tempfile::TempDir,
}

impl Drop for Harness {
    fn drop(&mut self) {
        // Shared bundles in the cache are read-only.
        let _ = bound_platform::fs::remove_tree(self.cache.path());
    }
}

impl Harness {
    pub fn new(bins: Bins) -> Harness {
        let dir = tempfile::Builder::new().prefix("bound-test-").tempdir().unwrap();
        let cache = tempfile::Builder::new().prefix("bound-test-cache-").tempdir().unwrap();
        Harness { bins, dir, cache }
    }

    /// The cache directory artifacts and `bound cache` use in this test
    /// (`BOUND_CACHE_DIR`): canonical on Unix (as the launcher makes it), a
    /// plain drive path on Windows (where canonical paths are `\\?\` paths).
    pub fn cache_dir(&self) -> PathBuf {
        if cfg!(windows) { self.cache.path().to_path_buf() } else { fs::canonicalize(self.cache.path()).unwrap() }
    }

    /// The working directory (canonicalized, e.g. `/private/var/...` on macOS).
    pub fn dir(&self) -> PathBuf {
        fs::canonicalize(self.dir.path()).unwrap()
    }

    pub fn path(&self, rel: impl AsRef<Path>) -> PathBuf {
        self.dir().join(rel)
    }

    /// Writes a file (creating parent directories) and returns its path.
    pub fn write(&self, rel: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        path
    }

    /// Copies the fixture program into the working directory under `name`
    /// (plus the executable suffix) and returns the copy's path.
    pub fn fixture_copy(&self, name: &str) -> PathBuf {
        let path = self.path(exe(name));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::copy(&self.bins.fixture, &path).unwrap();
        path
    }

    /// A `bound` command running in the working directory.
    pub fn bound(&self) -> Command {
        let mut cmd = Command::new(&self.bins.cli);
        cmd.current_dir(self.dir())
            .env("BOUND_LAUNCHER", &self.bins.launcher)
            .env("BOUND_CACHE_DIR", self.cache_dir())
            .env("NO_COLOR", "1")
            .stdin(Stdio::null());
        cmd
    }

    /// Runs `bound` with `args` and returns its output.
    pub fn bound_output(&self, args: Vec<OsString>) -> Output {
        run(self.bound().args(args))
    }

    /// Runs `bound -o OUTPUT ARGS...`, asserts success, and returns the path
    /// of the artifact (with `.exe` on Windows).
    pub fn bind(&self, output: &str, args: Vec<OsString>) -> PathBuf {
        let mut full = os!["-o", output];
        full.extend(args);
        let out = self.bound_output(full);
        assert_success(&out, "bound build");
        let mut path = self.path(output);
        if cfg!(windows) && path.extension().is_none_or(|e| !e.eq_ignore_ascii_case("exe")) {
            let mut name = path.into_os_string();
            name.push(".exe");
            path = PathBuf::from(name);
        }
        assert!(path.is_file(), "artifact {} was not created", path.display());
        path
    }

    /// Runs `bound ARGS...`, asserts failure, and returns stderr.
    pub fn bound_fails(&self, args: Vec<OsString>) -> String {
        let out = self.bound_output(args);
        assert!(!out.status.success(), "bound unexpectedly succeeded:\n{}", describe(&out));
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    /// A command running `artifact` in the working directory.
    pub fn command(&self, artifact: &Path) -> Command {
        let mut cmd = Command::new(artifact);
        cmd.current_dir(self.dir()).env("BOUND_CACHE_DIR", self.cache_dir()).stdin(Stdio::null());
        cmd
    }

    /// Runs an artifact with arguments and returns its output.
    pub fn run(&self, artifact: &Path, args: Vec<OsString>) -> Output {
        run(self.command(artifact).args(args))
    }

    /// Runs an artifact whose target is `bound-fixture report`, asserts
    /// success, and parses the report.
    pub fn report(&self, artifact: &Path, args: Vec<OsString>) -> Report {
        Report::parse(&self.run(artifact, args))
    }

    /// The fixture as an external program: `-- <fixture> MODE`.
    pub fn fixture_cmd(&self, mode: &str) -> Vec<OsString> {
        os!["--", self.bins.fixture, mode]
    }
}

/// Runs a command, retrying briefly if Linux reports the executable busy
/// (ETXTBSY), which can happen when another test thread forked while the
/// file was still open for writing.
pub fn run(cmd: &mut Command) -> Output {
    for _ in 0..50 {
        match cmd.output() {
            Ok(out) => return out,
            Err(e) if cfg!(target_os = "linux") && e.raw_os_error() == Some(26) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("cannot run {cmd:?}: {e}"),
        }
    }
    panic!("{cmd:?} stayed busy (ETXTBSY)")
}

pub fn describe(out: &Output) -> String {
    format!(
        "status: {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

pub fn assert_success(out: &Output, what: &str) {
    assert!(out.status.success(), "{what} failed:\n{}", describe(out));
}

pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// What `bound-fixture report` saw.
#[derive(Debug, Clone)]
pub struct Report {
    pub raw: Value,
}

impl Report {
    pub fn parse(out: &Output) -> Report {
        assert_success(out, "artifact");
        let text = stdout(out);
        let raw = serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("bad report ({e}):\n{}", describe(out)));
        Report { raw }
    }

    /// The arguments after `report`, which must all be Unicode.
    pub fn args(&self) -> Vec<String> {
        self.raw["argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap_or_else(|| panic!("non-Unicode argument {v}")).to_owned())
            .collect()
    }

    /// The raw encoded arguments (strings or `{"hex": ...}`).
    pub fn raw_args(&self) -> Vec<Value> {
        self.raw["argv"].as_array().unwrap().clone()
    }

    pub fn argv0(&self) -> String {
        self.raw["argv0"].as_str().unwrap().to_owned()
    }

    pub fn cwd(&self) -> PathBuf {
        PathBuf::from(self.raw["cwd"].as_str().unwrap())
    }

    /// A numeric field (`ppid`, `pgid`, `sid` on Unix).
    pub fn number(&self, field: &str) -> i64 {
        self.raw[field].as_i64().unwrap_or_else(|| panic!("no {field} in report"))
    }

    /// A text field (`console`).
    pub fn text(&self, field: &str) -> String {
        self.raw[field].as_str().unwrap_or_else(|| panic!("no {field} in report")).to_owned()
    }

    /// A list of numbers (`console_processes` on Windows).
    pub fn numbers(&self, field: &str) -> Vec<i64> {
        let list = self.raw[field].as_array().unwrap_or_else(|| panic!("no {field} in report"));
        list.iter().map(|v| v.as_i64().unwrap()).collect()
    }

    pub fn pid(&self) -> u32 {
        self.raw["pid"].as_u64().unwrap() as u32
    }

    pub fn stdin(&self) -> Option<String> {
        self.raw["stdin"].as_str().map(str::to_owned)
    }

    /// Environment variable (case-insensitive on Windows).
    pub fn env(&self, name: &str) -> Option<String> {
        let env = self.env_map();
        env.iter()
            .find(|(k, _)| if cfg!(windows) { k.eq_ignore_ascii_case(name) } else { *k == name })
            .map(|(_, v)| v.as_str().unwrap().to_owned())
    }

    pub fn env_map(&self) -> BTreeMap<String, Value> {
        self.raw["env"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

/// Canonicalizes both paths and compares them (handles `/private/var` on
/// macOS and 8.3 short names on Windows).
/// Waits until `path` no longer exists: bundle directories are removed by
/// a reaper process shortly after the program exits.
pub fn assert_removed(path: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while path.exists() {
        assert!(std::time::Instant::now() < deadline, "{} was left behind", path.display());
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

pub fn same_path(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Assembles an artifact from raw parts with a correct footer, signed the
/// way bound signs artifacts; used to craft malformed or malicious
/// artifacts.
pub fn craft(launcher: &[u8], payload: &[u8], manifest: &[u8]) -> Vec<u8> {
    use bound_format::{Digest, Footer};
    let footer = Footer {
        payload_offset: launcher.len() as u64,
        payload_len: payload.len() as u64,
        manifest_offset: (launcher.len() + payload.len()) as u64,
        manifest_len: manifest.len() as u64,
        manifest_sha256: Digest::of(manifest),
    };
    let mut out = Vec::with_capacity(launcher.len() + payload.len() + manifest.len() + 88);
    out.extend_from_slice(launcher);
    out.extend_from_slice(payload);
    out.extend_from_slice(manifest);
    out.extend_from_slice(&footer.encode());
    seal(out)
}

/// Signs an artifact that ends with its footer the way bound does (macOS
/// runs nothing unsigned); artifacts for other platforms are unchanged.
pub fn seal(mut artifact: Vec<u8>) -> Vec<u8> {
    bound_format::writer::sign_assembled(&mut artifact, "bound-test").unwrap();
    artifact
}

/// An artifact without the code signature that may follow its footer:
/// edit this, then [`seal`] it.
pub fn bound_region(artifact: &[u8]) -> Vec<u8> {
    let (_, end) = bound_format::footer::read_footer(&mut std::io::Cursor::new(artifact)).unwrap();
    artifact[..end as usize].to_vec()
}

/// Splits an artifact into (launcher, payload, manifest in its JSON form).
pub fn dissect(artifact: &[u8]) -> (Vec<u8>, Vec<u8>, Value) {
    let (footer, _) = bound_format::footer::read_footer(&mut std::io::Cursor::new(artifact)).unwrap();
    let p = footer.payload_offset as usize;
    let m = footer.manifest_offset as usize;
    let end = m + footer.manifest_len as usize;
    let manifest = bound_format::Manifest::decode(&artifact[m..end]).unwrap();
    (artifact[..p].to_vec(), artifact[p..m].to_vec(), serde_json::to_value(&manifest).unwrap())
}

/// Encodes a manifest given in its JSON form (as [`dissect`] and `bound
/// inspect --json` show it) the way artifacts store manifests, without
/// validating anything, so that tests can craft invalid manifests. This is
/// an implementation of the encoding in docs/format.md independent of
/// bound's own; variant names it does not know are written as index 99.
pub fn encode_manifest(m: &Value) -> Vec<u8> {
    let mut w = Wire::default();
    w.uint(&m["format"]);
    w.text(&m["generator"]);
    for key in ["os", "arch", "binary_format"] {
        w.text(&m["platform"][key]);
    }
    for region in ["launcher", "payload"] {
        w.uint(&m[region]["size"]);
        w.digest(&m[region]["sha256"]);
    }
    let target = &m["target"];
    match w.variant(&target["mode"], &["external", "embedded"]) {
        Some(0) => w.os_value(&target["program"]),
        Some(_) => w.path(&target["resource"]),
        None => {}
    }
    w.list(&m["args"], |w, arg| match w.variant(&arg["type"], &["literal", "resource", "runtime_args"]) {
        Some(0) => w.os_value(&arg["value"]),
        Some(1) => w.path(&arg["path"]),
        _ => {}
    });
    w.list(&m["env"], |w, binding| {
        w.os_value(&binding["name"]);
        let value = &binding["value"];
        match w.variant(&value["type"], &["literal", "resource", "unset"]) {
            Some(0) => w.os_value(&value["value"]),
            Some(1) => w.path(&value["path"]),
            _ => {}
        }
    });
    w.variant(&m["cwd"], &["inherit", "bundle"]);
    w.variant(&m["bundle"], &["private", "shared"]);
    w.list(&m["resources"], |w, r| match w.variant(&r["type"], &["dir", "file", "symlink"]) {
        Some(0) => w.path(&r["path"]),
        Some(1) => {
            w.path(&r["path"]);
            w.uint(&r["size"]);
            w.digest(&r["sha256"]);
            w.0.push(u8::from(r["executable"].as_bool().unwrap()));
        }
        Some(_) => {
            w.path(&r["path"]);
            w.path(&r["target"]);
        }
        None => {}
    });
    w.list(&m["blobs"], |w, blob| {
        w.digest(&blob["sha256"]);
        w.uint(&blob["size"]);
        w.uint(&blob["offset"]);
        w.uint(&blob["stored_size"]);
        w.variant(&blob["compression"], &["stored", "zstd"]);
    });
    w.0
}

/// A postcard writer for [`encode_manifest`].
#[derive(Default)]
struct Wire(Vec<u8>);

impl Wire {
    fn varint(&mut self, mut n: u64) {
        while n >= 0x80 {
            self.0.push(n as u8 | 0x80);
            n >>= 7;
        }
        self.0.push(n as u8);
    }

    fn uint(&mut self, v: &Value) {
        self.varint(v.as_u64().unwrap_or_else(|| panic!("not an unsigned integer: {v}")));
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.varint(bytes.len() as u64);
        self.0.extend_from_slice(bytes);
    }

    fn text(&mut self, v: &Value) {
        self.bytes(v.as_str().unwrap_or_else(|| panic!("not a string: {v}")).as_bytes());
    }

    fn digest(&mut self, v: &Value) {
        let digest = from_hex(v);
        assert_eq!(digest.len(), 32, "not a digest: {v}");
        self.0.extend_from_slice(&digest);
    }

    /// Writes the index of `v` in `names` (99 if it is not there).
    fn variant(&mut self, v: &Value, names: &[&str]) -> Option<usize> {
        let index = names.iter().position(|name| v == name);
        self.varint(index.map_or(99, |i| i as u64));
        index
    }

    fn os_value(&mut self, v: &Value) {
        match v {
            Value::String(text) => {
                self.varint(0);
                self.bytes(text.as_bytes());
            }
            Value::Object(o) if o.contains_key("unix_bytes") => {
                self.varint(1);
                self.bytes(&from_hex(&o["unix_bytes"]));
            }
            Value::Object(o) => {
                let units = from_hex(&o["windows_utf16"]);
                self.varint(2);
                self.varint(units.len() as u64 / 2);
                for pair in units.chunks(2) {
                    self.varint(u64::from(u16::from_be_bytes([pair[0], pair[1]])));
                }
            }
            other => panic!("not a string value: {other}"),
        }
    }

    fn path(&mut self, v: &Value) {
        match v {
            Value::String(text) => self.bytes(text.as_bytes()),
            Value::Object(o) => self.bytes(&from_hex(&o["unix_bytes"])),
            other => panic!("not a path: {other}"),
        }
    }

    fn list(&mut self, v: &Value, mut each: impl FnMut(&mut Wire, &Value)) {
        let items = v.as_array().unwrap_or_else(|| panic!("not a list: {v}"));
        self.varint(items.len() as u64);
        for item in items {
            each(self, item);
        }
    }
}

fn from_hex(v: &Value) -> Vec<u8> {
    let hex = v.as_str().unwrap_or_else(|| panic!("not hex: {v}"));
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

/// Creates a symbolic link to a file (on Windows, this needs Developer Mode
/// or an administrator, as the test suite does).
pub fn symlink_file(target: impl AsRef<Path>, link: impl AsRef<Path>) {
    let (target, link) = (target.as_ref(), link.as_ref());
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(target, link);
    made.unwrap_or_else(|e| panic!("cannot create symlink {} -> {}: {e}", link.display(), target.display()));
}

/// Creates a symbolic link to a directory (see [`symlink_file`]).
pub fn symlink_dir(target: impl AsRef<Path>, link: impl AsRef<Path>) {
    let (target, link) = (target.as_ref(), link.as_ref());
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_dir(target, link);
    made.unwrap_or_else(|e| panic!("cannot create symlink {} -> {}: {e}", link.display(), target.display()));
}

/// Spawns a command, retrying while Linux reports the executable busy (see
/// [`run`]).
pub fn spawn(cmd: &mut Command) -> std::process::Child {
    for _ in 0..50 {
        match cmd.spawn() {
            Ok(child) => return child,
            Err(e) if cfg!(target_os = "linux") && e.raw_os_error() == Some(26) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("cannot start {cmd:?}: {e}"),
        }
    }
    panic!("{cmd:?} stayed busy (ETXTBSY)")
}

/// Waits for a child, killing it and failing after `limit`.
pub fn wait_timeout(child: &mut std::process::Child, limit: Duration) -> std::process::ExitStatus {
    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("process did not exit within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Windows: `(process, parent, executable file name)` of every process.
#[cfg(windows)]
pub fn processes() -> Vec<(u32, u32, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
    };
    let mut found = Vec::new();
    // SAFETY: a process snapshot walked with correctly sized entries.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        assert_ne!(snapshot, INVALID_HANDLE_VALUE);
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            found.push((entry.th32ProcessID, entry.th32ParentProcessID, name));
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
    }
    found
}

/// Writes `bytes` as an executable file.
pub fn write_executable(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Values that exercise argument quoting on every platform.
pub const TRICKY_ARGS: &[&str] = &[
    "",
    " ",
    "hello world",
    "\"quoted\"",
    "'single'",
    r"C:\Program Files\Test\",
    r#"backslash\"quote"#,
    r"trailing\\",
    r"\\server\share",
    "a\tb",
    "line1\nline2",
    "^",
    "&",
    "|",
    "%",
    "!",
    "%PATH%",
    "!PATH!",
    "<in",
    ">out",
    "(paren)",
    "semi;colon",
    "$HOME",
    "`tick`",
    "$(sub)",
    "*",
    "?",
    "~",
    "#hash",
    "-n",
    "--flag=value",
    "=",
    "日本語",
    "émoji 😀",
    "ümlaut",
    "@args",
    "@file:not-a-directive",
];
