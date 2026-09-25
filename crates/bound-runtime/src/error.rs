use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::PathBuf;

use bound_format::osvalue::{NotRepresentable, escape_control};
use bound_format::{FooterError, ReadError};

use crate::{EXIT_CANNOT_EXECUTE, EXIT_LAUNCHER_FAILURE, EXIT_NOT_FOUND};

/// Why the launcher could not start the bound program.
#[derive(Debug)]
pub enum LaunchError {
    Refused(&'static str),
    SelfRead(io::Error),
    Artifact { path: PathBuf, error: ReadError },
    UnexpectedArguments,
    Unrepresentable(String),
    Materialize(String),
    Cleanup(io::Error),
    NotFound { program: String, path_lookup: bool },
    CannotExecute { program: String, error: io::Error, hint: Option<&'static str> },
    Internal(&'static str),
}

impl LaunchError {
    /// The process exit status that reports this error, following the
    /// convention of `env(1)`: 127 not found, 126 not executable, 125 for
    /// failures of the launcher itself.
    pub fn exit_code(&self) -> i32 {
        match self {
            LaunchError::NotFound { .. } => EXIT_NOT_FOUND,
            LaunchError::CannotExecute { .. } => EXIT_CANNOT_EXECUTE,
            _ => EXIT_LAUNCHER_FAILURE,
        }
    }

    pub(crate) fn spawn(program: &OsStr, error: io::Error, embedded: bool) -> LaunchError {
        // The name comes from the manifest: never let it put control
        // sequences on the user's terminal.
        let shown = escape_control(&program.to_string_lossy());
        match error.kind() {
            io::ErrorKind::NotFound => {
                LaunchError::NotFound { program: shown, path_lookup: crate::is_path_lookup(program) }
            }
            io::ErrorKind::PermissionDenied if embedded && cfg!(unix) => LaunchError::CannotExecute {
                program: shown,
                error,
                hint: Some(
                    "if the temporary directory is mounted noexec, set TMPDIR to a directory that allows execution",
                ),
            },
            _ => LaunchError::CannotExecute { program: shown, error, hint: None },
        }
    }
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LaunchError::Refused(why) => f.write_str(why),
            LaunchError::SelfRead(e) => write!(f, "cannot read this program's executable: {e}"),
            LaunchError::Artifact { path, error: ReadError::Footer(FooterError::NotAnArtifact) } => write!(
                f,
                "no bound payload is attached to {} (this is a bare launcher, or the file was modified); create programs with `bound build`",
                path.display()
            ),
            LaunchError::Artifact { path, error } => write!(
                f,
                "the bound payload of {} is damaged or invalid: {error} (run `bound verify` for details)",
                path.display()
            ),
            LaunchError::UnexpectedArguments => f.write_str("this program does not accept arguments"),
            LaunchError::Unrepresentable(what) => write!(f, "{what}"),
            LaunchError::Materialize(msg) => write!(f, "cannot prepare bundled resources: {msg}"),
            LaunchError::Cleanup(e) => write!(f, "cannot start the process that removes bundled resources: {e}"),
            LaunchError::NotFound { program, path_lookup: true } => {
                write!(f, "cannot run \"{program}\": program not found in PATH")
            }
            LaunchError::NotFound { program, path_lookup: false } => {
                write!(f, "cannot run \"{program}\": no such file")
            }
            LaunchError::CannotExecute { program, error, hint } => {
                write!(f, "cannot run \"{program}\": {error}")?;
                if let Some(hint) = hint {
                    write!(f, " ({hint})")?;
                }
                Ok(())
            }
            LaunchError::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for LaunchError {}

impl From<NotRepresentable> for LaunchError {
    fn from(e: NotRepresentable) -> Self {
        LaunchError::Unrepresentable(e.to_string())
    }
}

impl From<bound_format::NameError> for LaunchError {
    fn from(e: bound_format::NameError) -> Self {
        LaunchError::Materialize(e.to_string())
    }
}
