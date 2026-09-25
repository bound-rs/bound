//! Privilege checks.

/// Fails if the process runs with set-user-ID or set-group-ID privileges.
///
/// A bound launcher consults the environment (temporary directory, `PATH`)
/// and writes files; doing that with privileges borrowed from a set-ID bit
/// would let the caller steer a privileged process. bound artifacts are not
/// designed to be set-ID programs, so the launcher refuses outright.
pub fn check_not_setid() -> Result<(), &'static str> {
    #[cfg(unix)]
    {
        if crate::unix::is_setid() {
            return Err("refusing to run with set-user-ID or set-group-ID privileges");
        }
    }
    Ok(())
}
