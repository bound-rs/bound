//! Access to the running executable.

use std::fs::File;
use std::io;
use std::path::PathBuf;

/// Opens the executable image of the current process for reading, and
/// returns it with its path (for messages only).
///
/// On Linux the file is opened through `/proc/self/exe`, which refers to the
/// image that is actually running even if the path has since been replaced
/// or deleted. Elsewhere the path reported by the OS is opened.
pub fn open_current_exe() -> io::Result<(File, PathBuf)> {
    let path = std::env::current_exe()?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if let Ok(file) = File::open("/proc/self/exe") {
            return Ok((file, path));
        }
    }
    let file = File::open(&path)?;
    Ok((file, path))
}
