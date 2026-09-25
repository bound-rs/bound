//! Starting the target program and mirroring its outcome.
//!
//! * **Unix**: the launcher always *becomes* the program with `execve`
//!   ([`exec`], [`exec_search`]). The program keeps the PID, parent, process
//!   group, session, signal mask and dispositions the artifact was started
//!   with, so signals, job control and exit statuses are exactly those of
//!   the program started directly. When a bundle directory must be removed
//!   afterwards, a detached reaper process ([`start_reaper`]) waits for that
//!   PID to exit and removes it.
//! * **Windows** has no `exec`: the launcher starts the program as a child
//!   ([`run_supervised`]) in a job object that terminates it if the
//!   launcher is terminated, waits for it and exits with its exit code
//!   ([`exit_like`]). The bundle directory is removed by a detached reaper
//!   that waits for the launcher to exit.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(windows)]
use std::process::ExitStatus;

/// Replaces the current process with `cmd`, passing through the SIGPIPE
/// disposition the process was started with. Only returns on failure.
#[cfg(unix)]
pub fn exec(cmd: &mut Command) -> io::Error {
    crate::unix::exec(cmd)
}

/// Replaces the current process with the program `name`, found as
/// execvp(3) would find it in `path_var` (the `PATH` the program will
/// see), except that candidates for which `skip` returns true are passed
/// over. `cwd` is the program's working directory, against which relative
/// `PATH` entries are resolved. `command` builds the command to run for a
/// candidate path. Only returns on failure (`NotFound` if nothing was found).
#[cfg(unix)]
pub fn exec_search(
    name: &OsStr,
    path_var: Option<&OsStr>,
    cwd: Option<&Path>,
    skip: &dyn Fn(&Path) -> bool,
    command: &dyn Fn(&Path) -> Command,
) -> io::Error {
    crate::unix::exec_search(name, path_var, cwd, skip, command)
}

/// Finds the program `name` as `CreateProcessW` (through the Rust standard
/// library) would: in `child_path` if the program's environment sets its
/// own `PATH`, then the directory of the running executable, the system
/// directory, the Windows directory, and the caller's `PATH`; `.exe` is
/// appended to names without an extension. If that finds nothing and the
/// name has no extension, each `PATHEXT` extension is tried in each
/// absolute directory of the `PATH` the program sees, as `cmd.exe` would
/// (so `npm` finds `npm.cmd`). Candidates for which `skip` returns true are
/// passed over. The current directory is never searched.
#[cfg(windows)]
pub fn find_program(name: &OsStr, child_path: Option<&OsStr>, skip: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    crate::windows::find_program(name, child_path, skip)
}

/// Runs `cmd` as a child that shares this process's standard streams and
/// console (or, if this process has no console, has none either), and
/// waits for it. The child is placed in a job object that terminates it if
/// the launcher is terminated (programs it starts itself are not
/// affected). `Ctrl+C` and `Ctrl+Break` reach every process attached to the
/// console, so the launcher ignores them and lets the child decide.
#[cfg(windows)]
pub fn run_supervised(cmd: &mut Command) -> io::Result<ExitStatus> {
    crate::windows::run_supervised(cmd)
}

/// Installs the console control handler. Call it before doing work that
/// must be cleaned up (such as materializing resources), so that an
/// interrupt during that work is recorded instead of killing the launcher
/// halfway; then check [`interrupted`] before starting the program.
#[cfg(windows)]
pub fn prepare_supervision() {
    crate::windows::prepare_supervision();
}

/// A console interrupt received after [`prepare_supervision`] while no
/// program was running.
#[cfg(windows)]
pub fn interrupted() -> Option<i32> {
    crate::windows::interrupted()
}

/// Exits as a console program interrupted by Ctrl+C does
/// (`STATUS_CONTROL_C_EXIT`).
#[cfg(windows)]
pub fn exit_interrupted(interruption: i32) -> ! {
    let _ = interruption;
    std::process::exit(crate::windows::STATUS_CONTROL_C_EXIT as i32)
}

/// Exits the current process with the exit code of `status` (Windows exit
/// codes are 32-bit, and `exit` passes all of them through).
#[cfg(windows)]
pub fn exit_like(status: ExitStatus) -> ! {
    std::process::exit(status.code().unwrap_or(1))
}

/// Starts a detached reaper process that removes the directory `dir` once
/// this process has exited, and on Unix, the program that replaced it with
/// `exec`. The reaper is not a child of the program, holds none of the
/// caller's handles or descriptors, and does not receive signals or console
/// events meant for the program.
///
/// Unix: must be called while the process is single-threaded.
pub fn start_reaper(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        crate::unix::start_reaper(dir)
    }
    #[cfg(windows)]
    {
        crate::windows::start_reaper(dir)
    }
}

/// Windows: if this process was started as a reaper by [`start_reaper`],
/// does the reaper's work and exits; otherwise returns at once. Call it
/// first thing in the launcher. (On Unix the reaper is a forked copy of the
/// launcher and needs no entry point.)
#[cfg(windows)]
pub fn run_reaper_if_requested() {
    crate::windows::run_reaper_if_requested();
}

/// Whether `program` is a bare name that the OS would look up in `PATH`
/// (as opposed to a path relative to the working directory).
pub fn is_bare_name(program: &OsStr) -> bool {
    let bytes = program.as_encoded_bytes();
    if cfg!(windows) { !bytes.iter().any(|b| matches!(b, b'/' | b'\\' | b':')) } else { !bytes.contains(&b'/') }
}

/// Turns a verbatim drive path (`\\?\C:\dir\file`) into the plain form
/// (`C:\dir\file`) when that is lossless: no component that Win32 path
/// parsing would reinterpret, and short enough for APIs limited to
/// `MAX_PATH`. `cmd.exe` in particular cannot run batch files given as
/// verbatim paths. Other paths, and every path on Unix, are returned as is.
pub fn plain_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else { return path };
        let Prefix::VerbatimDisk(letter) = prefix.kind() else { return path };
        let mut plain = PathBuf::from(format!("{}:\\", char::from(letter)));
        for component in components {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    let text = name.to_string_lossy();
                    if text.ends_with('.') || text.ends_with(' ') || text == "." || text == ".." {
                        return path;
                    }
                    plain.push(name);
                }
                _ => return path,
            }
        }
        if plain.as_os_str().len() >= 260 {
            return path;
        }
        plain
    }
    #[cfg(not(windows))]
    {
        path
    }
}

/// Default for `PATHEXT` when the variable is unset.
#[cfg(windows)]
const DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";

/// Looks for `name` in the directories of `path_var` the way a shell would,
/// returning the first match. Relative and empty `PATH` entries are skipped:
/// they would make the result depend on the working directory.
///
/// Unix: the file must be executable. Windows: if `name` has no extension,
/// each extension of `PATHEXT` is tried in order (`.COM;.EXE;.BAT;.CMD` by
/// default), as `cmd.exe` does.
pub fn find_in_path(name: &OsStr, path_var: Option<&OsStr>) -> Option<PathBuf> {
    if !is_bare_name(name) || name.is_empty() {
        return None;
    }
    let dirs: Vec<PathBuf> =
        std::env::split_paths(path_var?).filter(|d| !d.as_os_str().is_empty() && d.is_absolute()).collect();
    for dir in dirs {
        for candidate in candidates(&dir, name) {
            if crate::fs::is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(unix)]
fn candidates(dir: &Path, name: &OsStr) -> Vec<PathBuf> {
    vec![dir.join(name)]
}

#[cfg(windows)]
pub(crate) fn candidates(dir: &Path, name: &OsStr) -> Vec<PathBuf> {
    let has_extension = Path::new(name).extension().is_some();
    if has_extension {
        return vec![dir.join(name)];
    }
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| DEFAULT_PATHEXT.to_owned());
    pathext
        .split(';')
        .filter(|ext| ext.len() > 1 && ext.starts_with('.'))
        .map(|ext| {
            let mut file = name.to_os_string();
            file.push(ext.to_ascii_lowercase());
            dir.join(file)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbatim_paths_become_plain() {
        if cfg!(windows) {
            assert_eq!(plain_path(PathBuf::from(r"\\?\C:\dir\x.cmd")), PathBuf::from(r"C:\dir\x.cmd"));
            assert_eq!(plain_path(PathBuf::from(r"C:\dir\x.cmd")), PathBuf::from(r"C:\dir\x.cmd"));
            // Not representable without the verbatim prefix: kept.
            let dotted = PathBuf::from(r"\\?\C:\dir.\x.cmd");
            assert_eq!(plain_path(dotted.clone()), dotted);
            let unc = PathBuf::from(r"\\?\UNC\server\share\x.cmd");
            assert_eq!(plain_path(unc.clone()), unc);
        } else {
            // Unix paths have no verbatim form: they are kept as they are.
            for path in ["/usr/bin/env", "relative/x", r"\\?\C:\x"] {
                assert_eq!(plain_path(PathBuf::from(path)), PathBuf::from(path));
            }
        }
    }

    #[test]
    fn bare_names() {
        assert!(is_bare_name(OsStr::new("grep")));
        assert!(is_bare_name(OsStr::new("findstr.exe")));
        assert!(!is_bare_name(OsStr::new("./tool")));
        assert!(!is_bare_name(OsStr::new("/usr/bin/env")));
        if cfg!(windows) {
            assert!(!is_bare_name(OsStr::new(r".\tool.exe")));
            assert!(!is_bare_name(OsStr::new(r"C:tool.exe")));
        }
    }

    #[test]
    fn finds_programs_on_a_given_path() {
        let dir = tempfile::tempdir().unwrap();
        let name = if cfg!(windows) { "tool.cmd" } else { "tool" };
        let file = dir.path().join(name);
        std::fs::write(&file, b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path_var = std::env::join_paths([Path::new("relative/ignored"), dir.path()]).unwrap();
        assert_eq!(find_in_path(OsStr::new("tool"), Some(&path_var)), Some(file.clone()));
        assert_eq!(find_in_path(OsStr::new("missing"), Some(&path_var)), None);
        assert_eq!(find_in_path(OsStr::new("./tool"), Some(&path_var)), None);
        assert_eq!(find_in_path(OsStr::new("tool"), None), None);
    }

    #[test]
    fn non_executable_files_are_not_programs() {
        // Without the execute bit (Unix), or an extension of PATHEXT
        // (Windows), a file is not a program.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("data"), b"x").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"x").unwrap();
        let path_var = dir.path().as_os_str().to_owned();
        assert_eq!(find_in_path(OsStr::new("data"), Some(&path_var)), None);
        assert_eq!(find_in_path(OsStr::new("notes"), Some(&path_var)), None);
    }
}
