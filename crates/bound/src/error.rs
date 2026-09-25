//! User-facing errors.

use std::fmt;

/// An error reported to the user as `error: MESSAGE` (plus an optional
/// `hint:` line), without a backtrace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub message: String,
    pub hint: Option<String>,
}

impl CliError {
    pub fn new(message: impl Into<String>) -> CliError {
        CliError { message: message.into(), hint: None }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> CliError {
        self.hint = Some(hint.into());
        self
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// Shorthand for `Err(CliError::new(...))`.
pub(crate) fn fail<T>(message: impl Into<String>) -> Result<T, CliError> {
    Err(CliError::new(message))
}
