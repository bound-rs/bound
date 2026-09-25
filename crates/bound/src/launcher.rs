//! Locating and identifying the launcher that artifacts are built from.
//!
//! The launcher is a small native executable (`bound-launcher`) compiled
//! for one platform. bound does not assume it matches the host: the
//! launcher's executable header is inspected and the resulting
//! [`Platform`] decides output naming and file-name rules. Today the
//! launcher is found next to `bound` itself; supporting `--target` later
//! only needs another way to pick the file, not a new artifact format.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use bound_format::Platform;
use bound_format::footer::has_magic;

use crate::error::{CliError, fail};

/// File name of the launcher for the host platform.
pub fn launcher_file_name() -> String {
    format!("bound-launcher{}", std::env::consts::EXE_SUFFIX)
}

/// Environment variable that overrides the launcher location.
pub const LAUNCHER_ENV: &str = "BOUND_LAUNCHER";

/// A launcher executable and the platform it targets.
#[derive(Debug, Clone)]
pub struct Launcher {
    pub path: PathBuf,
    pub platform: Platform,
}

/// Finds the launcher: `explicit` (from `--launcher`), else `$BOUND_LAUNCHER`,
/// else `bound-launcher` next to the running `bound` executable (both as
/// invoked and with symlinks resolved, which covers package managers that
/// symlink binaries into a shared `bin` directory).
pub fn find(explicit: Option<&Path>) -> Result<Launcher, CliError> {
    let env = std::env::var_os(LAUNCHER_ENV).filter(|v| !v.is_empty());
    let exe = std::env::current_exe().ok();
    let path = locate(explicit, env, exe.as_deref())?;
    identify(&path)
}

/// The search itself, separated from the process environment for testing.
pub fn locate(explicit: Option<&Path>, env: Option<OsString>, exe: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = env {
        return Ok(PathBuf::from(path));
    }
    let name = launcher_file_name();
    let Some(exe) = exe else {
        return fail("cannot determine the location of bound to find its launcher")
            .map_err(|e: CliError| e.with_hint("pass --launcher PATH"));
    };
    let mut candidates = Vec::new();
    if let Some(dir) = exe.parent() {
        candidates.push(dir.join(&name));
    }
    if let Ok(real) = std::fs::canonicalize(exe) {
        if let Some(dir) = real.parent() {
            candidates.push(dir.join(&name));
        }
    }
    for candidate in &candidates {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }
    Err(CliError::new(format!("cannot find the bound launcher: expected {name} next to {}", exe.display()))
        .with_hint(format!("reinstall bound, pass --launcher PATH, or set {LAUNCHER_ENV}")))
}

/// Checks that `path` is a native executable and not already an artifact,
/// and identifies its platform.
pub fn identify(path: &Path) -> Result<Launcher, CliError> {
    let shown = path.display();
    let mut file = File::open(path).map_err(|e| CliError::new(format!("cannot open launcher {shown}: {e}")))?;
    let is_artifact = has_magic(&mut file).map_err(|e| CliError::new(format!("cannot read launcher {shown}: {e}")))?;
    if is_artifact {
        return fail(format!("launcher {shown} is itself a bound artifact, not a bare launcher"));
    }
    let mut header = Vec::with_capacity(4096);
    std::io::Seek::rewind(&mut file)
        .and_then(|()| file.take(4096).read_to_end(&mut header))
        .map_err(|e| CliError::new(format!("cannot read launcher {shown}: {e}")))?;
    let platform = Platform::sniff(&header).ok_or_else(|| {
        CliError::new(format!("launcher {shown} is not a recognized executable (expected ELF, Mach-O or PE)"))
    })?;
    Ok(Launcher { path: path.to_path_buf(), platform })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_and_environment_take_precedence() {
        let explicit = Path::new("/x/launcher");
        assert_eq!(locate(Some(explicit), Some("/env".into()), None).unwrap(), explicit);
        assert_eq!(locate(None, Some("/env".into()), None).unwrap(), Path::new("/env"));
    }

    #[test]
    fn finds_a_sibling_launcher() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join(format!("bound{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&exe, b"").unwrap();
        let err = locate(None, None, Some(&exe)).unwrap_err();
        assert!(err.message.contains("cannot find the bound launcher"), "{err:?}");
        let launcher = dir.path().join(launcher_file_name());
        std::fs::write(&launcher, b"").unwrap();
        assert_eq!(locate(None, None, Some(&exe)).unwrap(), launcher);
    }

    #[test]
    fn follows_a_symlinked_bound() {
        let install = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let name = format!("bound{}", std::env::consts::EXE_SUFFIX);
        let real = install.path().join(&name);
        std::fs::write(&real, b"").unwrap();
        std::fs::write(install.path().join(launcher_file_name()), b"").unwrap();
        let link = bin.path().join(&name);
        // On Windows, symbolic links need Developer Mode or an administrator.
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&real, &link).unwrap();
        let found = locate(None, None, Some(&link)).unwrap();
        assert_eq!(found.file_name().unwrap(), launcher_file_name().as_str());
    }

    #[test]
    fn identify_rejects_non_executables() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("not-a-launcher");
        std::fs::write(&script, b"#!/bin/sh\necho hi\n").unwrap();
        let err = identify(&script).unwrap_err();
        assert!(err.message.contains("not a recognized executable"), "{err:?}");
    }

    #[test]
    fn identify_accepts_a_native_executable() {
        let exe = std::env::current_exe().unwrap();
        let launcher = identify(&exe).unwrap();
        assert_eq!(launcher.platform.os, std::env::consts::OS);
    }
}
