//! Unix implementations (Linux, macOS and other Unix-likes).

use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::ptr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub(crate) fn is_setid() -> bool {
    // SAFETY: these calls cannot fail and have no preconditions.
    unsafe { libc::getuid() != libc::geteuid() || libc::getgid() != libc::getegid() }
}

/// The process umask, read once. Reading it means setting it, so it is
/// set to a restrictive value for the instant between the two calls.
pub(crate) fn umask() -> u32 {
    static UMASK: OnceLock<u32> = OnceLock::new();
    // SAFETY: umask(2) cannot fail; the original value is restored at once.
    *UMASK.get_or_init(|| {
        // SAFETY: as above.
        let current = unsafe { libc::umask(0o077) };
        // SAFETY: restores the value just read.
        unsafe { libc::umask(current) };
        // mode_t is u16 on macOS and u32 on Linux.
        #[allow(clippy::useless_conversion)]
        let widened = u32::from(current);
        widened
    })
}

/// Whether creating with `mode` yields exactly `mode` under the umask, so
/// that no corrective chmod is needed.
fn umask_preserves(mode: u32) -> bool {
    mode & !umask() == mode
}

pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        check_trusted_location(parent)?;
    }
    create_dir(path)?;
    #[cfg(target_vendor = "apple")]
    make_private(path)?;
    Ok(())
}

/// Refuses a location in which another user could rename the private
/// directory and put their own in its place: `dir` and every directory
/// above it must be owned by this user or by root, and must not be
/// writable by group or others unless it has the sticky bit (as `/tmp`
/// has).
fn check_trusted_location(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid cannot fail.
    let me = unsafe { libc::geteuid() };
    for ancestor in dir.ancestors().filter(|a| !a.as_os_str().is_empty()) {
        let meta = fs::metadata(ancestor)?;
        let mode = meta.permissions().mode();
        let problem = if meta.uid() != me && meta.uid() != 0 {
            "is owned by another user"
        } else if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            "is writable by other users and not sticky"
        } else {
            continue;
        };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} {problem}, so files created in {} could be replaced; set TMPDIR to a private directory",
                ancestor.display(),
                dir.display()
            ),
        ));
    }
    Ok(())
}

/// macOS: removes the access control entries a new directory inherits
/// from its parent (unlike Linux default ACLs, they are not limited by
/// the mode), so that the mode alone governs access and nothing created
/// inside inherits them. Entries could have been created through them
/// before they were removed, so the directory must still be empty.
#[cfg(target_vendor = "apple")]
fn make_private(path: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    type Acl = *mut std::ffi::c_void;
    const ACL_TYPE_EXTENDED: libc::c_uint = 0x0000_0100;
    unsafe extern "C" {
        fn acl_init(count: libc::c_int) -> Acl;
        fn acl_set_fd_np(fd: libc::c_int, acl: Acl, acl_type: libc::c_uint) -> libc::c_int;
        fn acl_free(object: *mut std::ffi::c_void) -> libc::c_int;
    }

    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    // SAFETY: an empty ACL from acl_init is applied to a descriptor we own
    // and freed afterwards.
    unsafe {
        let empty = acl_init(0);
        if empty.is_null() {
            return Err(io::Error::last_os_error());
        }
        let rc = acl_set_fd_np(dir.as_raw_fd(), empty, ACL_TYPE_EXTENDED);
        let error = io::Error::last_os_error();
        acl_free(empty);
        if rc != 0 {
            return Err(error);
        }
    }
    if fs::read_dir(path)?.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("another process created files in {} while it was being made private", path.display()),
        ));
    }
    Ok(())
}

pub(crate) fn create_dir(path: &Path) -> io::Result<()> {
    // mkdir(2) fails on any existing entry, including a planted symlink.
    DirBuilder::new().mode(0o700).create(path)?;
    if !umask_preserves(0o700) {
        // An unusual umask removed owner bits: apply the exact mode.
        fs::set_permissions(path, Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(crate) fn create_new_file(path: &Path, executable: bool) -> io::Result<File> {
    let mode = if executable { 0o700 } else { 0o600 };
    // O_CREAT|O_EXCL (create_new) refuses existing entries, symlinks
    // included; O_NOFOLLOW is belt and braces.
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !umask_preserves(mode) {
        file.set_permissions(Permissions::from_mode(mode))?;
    }
    Ok(file)
}

pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    if fs::symlink_metadata(dir).is_err() {
        if let Some(parent) = dir.parent() {
            DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
        }
        match DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {
                #[cfg(target_vendor = "apple")]
                make_private(dir)?;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    let meta = fs::symlink_metadata(dir)?;
    // SAFETY: geteuid cannot fail.
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a directory of this user", dir.display()),
        ));
    }
    if meta.mode() & 0o077 != 0 {
        fs::set_permissions(dir, Permissions::from_mode(0o700))?;
    }
    let canonical = fs::canonicalize(dir)?;
    if let Some(parent) = canonical.parent() {
        check_trusted_location(parent)?;
    }
    Ok(canonical)
}

/// Creates `dst` from `src`: a clone sharing storage where the file system
/// supports it, a copy otherwise.
pub(crate) fn clone_file(src: &File, dst: &Path, executable: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mode = if executable { 0o700 } else { 0o600 };
    #[cfg(target_vendor = "apple")]
    {
        const CLONE_NOFOLLOW: u32 = 0x0001;
        const CLONE_NOOWNERCOPY: u32 = 0x0002;
        let target = CString::new(dst.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
        // SAFETY: cloning from a descriptor we own to a NUL-terminated path;
        // fclonefileat creates the destination and fails if it exists.
        let rc = unsafe {
            libc::fclonefileat(src.as_raw_fd(), libc::AT_FDCWD, target.as_ptr(), CLONE_NOFOLLOW | CLONE_NOOWNERCOPY)
        };
        if rc == 0 {
            // The clone has the source's (read-only) mode.
            return fs::set_permissions(dst, Permissions::from_mode(mode));
        }
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::ENOTSUP | libc::EXDEV | libc::EINVAL)) {
            return Err(error);
        }
    }
    let mut out = create_new_file(dst, executable)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: FICLONE between two descriptors we own.
        if unsafe { libc::ioctl(out.as_raw_fd(), libc::FICLONE, src.as_raw_fd()) } == 0 {
            return Ok(());
        }
    }
    let _ = mode;
    io::copy(&mut &*src, &mut out)?;
    Ok(())
}

/// rename(2) that fails with `AlreadyExists` instead of replacing the
/// destination; `Unsupported` where the system or file system cannot.
pub(crate) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    let nul = |_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte");
    let from = CString::new(from.as_os_str().as_bytes()).map_err(nul)?;
    let to = CString::new(to.as_os_str().as_bytes()).map_err(nul)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: renameat2 with valid NUL-terminated paths.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        ) as libc::c_int
    };
    #[cfg(target_vendor = "apple")]
    // SAFETY: renamex_np with valid NUL-terminated paths.
    let rc = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    let rc = {
        let _ = (from, to);
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    };
    if rc == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOSYS | libc::EINVAL | libc::ENOTSUP) => Err(io::Error::from(io::ErrorKind::Unsupported)),
        _ => Err(error),
    }
}

/// Makes reads from `file` blocking again after an `O_NONBLOCK` open.
pub(crate) fn clear_nonblocking(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: F_GETFL/F_SETFL on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Adds owner rwx to every real directory in the tree (never through
/// symlinks), so that a tree the child locked down can be removed.
pub(crate) fn make_tree_writable(root: &Path) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        match fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() => {
                let mode = meta.permissions().mode() | 0o700;
                let _ = fs::set_permissions(&dir, Permissions::from_mode(mode));
            }
            _ => continue,
        }
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(entry.path());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SIGPIPE.
//
// Rust's runtime sets SIGPIPE to "ignore" before `main`, and std resets it
// to the default in every child it starts. Both hide what the launcher's
// caller chose: a program started through bound would always get the
// default, even from a parent that deliberately ignores SIGPIPE. So the
// disposition the launcher was started with is captured by a constructor
// that runs before the Rust runtime, and re-applied in the child.

static SIGPIPE_WAS_IGNORED: AtomicBool = AtomicBool::new(false);

extern "C" fn capture_sigpipe() {
    // SAFETY: querying a disposition does not change it.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(libc::SIGPIPE, ptr::null(), &mut action) == 0 {
            SIGPIPE_WAS_IGNORED.store(action.sa_sigaction == libc::SIG_IGN, Ordering::SeqCst);
        }
    }
}

#[used]
#[cfg_attr(target_vendor = "apple", unsafe(link_section = "__DATA,__mod_init_func"))]
#[cfg_attr(not(target_vendor = "apple"), unsafe(link_section = ".init_array"))]
static CAPTURE_SIGPIPE: extern "C" fn() = capture_sigpipe;

/// Arranges for the program started by `cmd` to get the SIGPIPE
/// disposition the launcher itself was started with.
fn pass_through_sigpipe(cmd: &mut Command) {
    // Referencing the constructor keeps it linked into every binary that
    // starts programs.
    std::hint::black_box(&CAPTURE_SIGPIPE);
    if SIGPIPE_WAS_IGNORED.load(Ordering::SeqCst) {
        // SAFETY: signal() is async-signal-safe; the hook runs after std's
        // own reset of SIGPIPE in the child.
        unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGPIPE, libc::SIG_IGN);
                Ok(())
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Starting the program.

/// The search path execvp(3) uses when `PATH` is unset.
const DEFAULT_PATH: &str = if cfg!(target_vendor = "apple") { "/usr/bin:/bin" } else { "/bin:/usr/bin" };

/// Replaces the current process with `cmd`. Only returns on failure.
pub(crate) fn exec(cmd: &mut Command) -> io::Error {
    pass_through_sigpipe(cmd);
    cmd.exec()
}

/// Replaces the current process with the program `name`, looked up the way
/// execvp(3) does it: each directory of `path_var` in order (the system
/// default if it is unset; an empty entry is the working directory), where a
/// candidate that cannot be executed (`EACCES`) is passed over. Candidates
/// for which `skip` returns true are passed over as well. Relative entries
/// are relative to `cwd`, the working directory the program gets.
///
/// `command` builds the command for a candidate path. Only returns on
/// failure: `NotFound` when nothing was found, the `EACCES` error when only
/// unexecutable candidates were, or the first other error.
pub(crate) fn exec_search(
    name: &OsStr,
    path_var: Option<&OsStr>,
    cwd: Option<&Path>,
    skip: &dyn Fn(&Path) -> bool,
    command: &dyn Fn(&Path) -> Command,
) -> io::Error {
    let path_var = path_var.unwrap_or(OsStr::new(DEFAULT_PATH));
    let mut denied = None;
    for entry in path_var.as_bytes().split(|&b| b == b':') {
        let dir = if entry.is_empty() { Path::new(".") } else { Path::new(OsStr::from_bytes(entry)) };
        let candidate = dir.join(name);
        let located = match cwd {
            Some(cwd) if candidate.is_relative() => cwd.join(&candidate),
            _ => candidate.clone(),
        };
        match fs::metadata(&located) {
            Ok(meta) if meta.is_file() => {}
            // execve(2) fails with EACCES for directories and unsearchable
            // paths, and execvp keeps looking.
            Ok(_) => {
                denied.get_or_insert_with(|| io::Error::from_raw_os_error(libc::EACCES));
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                denied.get_or_insert(e);
                continue;
            }
            Err(_) => continue,
        }
        if skip(&located) {
            continue;
        }
        let error = exec(&mut command(&candidate));
        match error.raw_os_error() {
            Some(libc::EACCES) => denied = Some(error),
            // The errors after which execvp tries the next directory.
            Some(libc::ENOENT | libc::ENOTDIR | libc::ESTALE | libc::ENODEV | libc::ETIMEDOUT) => {}
            _ => return error,
        }
    }
    denied.unwrap_or_else(|| io::Error::from(io::ErrorKind::NotFound))
}

// ---------------------------------------------------------------------------
// The reaper.
//
// The launcher execs the program, so nothing of it is left to remove the
// bundle directory once the program exits. A reaper process does that: it
// watches the PID the launcher and then the program run as, and removes the
// directory when that process has exited (including by SIGKILL). It is
// started with a double fork, which keeps the program's view of the world
// exactly what it would be without bound:
//
// * the reaper is not the program's child (it is adopted by init, or by the
//   nearest subreaper), so the program has exactly the children it creates
//   and wait(2) in the program never sees the reaper;
// * it runs in a session of its own, so terminal signals, hangups and
//   signals to the program's process group never reach it, and it ignores
//   the usual termination signals so it outlives the program;
// * it closes every descriptor it inherited, so a reader of the program's
//   output sees end-of-file as soon as the program exits, and it leaves the
//   caller's working directory;
// * it watches with a pidfd (Linux 5.3+) or kqueue (macOS), or by polling
//   the process's start time where neither is available, and the launcher
//   waits until the watch is in place, so no exit can go unnoticed.

/// Starts a reaper that removes `dir` once this process, or the program
/// that replaces it through `exec`, has exited.
///
/// Must be called while the process is single-threaded.
pub(crate) fn start_reaper(dir: &Path) -> io::Result<()> {
    let dir = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    // Everything that allocates happens before fork.
    let inherited = open_descriptors();
    // SAFETY: getpid cannot fail.
    let watched = unsafe { libc::getpid() };
    let (ready_read, ready_write) = cloexec_pipe()?;

    // SAFETY: the process is single-threaded, so the child may run any code;
    // neither child ever returns from this function.
    let intermediate = unsafe { libc::fork() };
    if intermediate < 0 {
        let error = io::Error::last_os_error();
        close(ready_read);
        close(ready_write);
        return Err(error);
    }
    if intermediate == 0 {
        // SAFETY: as above. `_exit` skips exit handlers and stdio buffers,
        // which belong to the launcher.
        unsafe {
            libc::setsid();
            match libc::fork() {
                0 => reaper(watched, &dir, &inherited, ready_read, ready_write),
                -1 => libc::_exit(1),
                _ => libc::_exit(0),
            }
        }
    }

    close(ready_write);
    // Collect the intermediate process (if SIGCHLD is ignored, the kernel
    // already has, and waitpid fails with ECHILD).
    loop {
        // SAFETY: waiting for our own child.
        let rc = unsafe { libc::waitpid(intermediate, ptr::null_mut(), 0) };
        if rc >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break;
        }
    }
    // The reaper writes one byte once it is watching; end-of-file means it
    // could not start.
    let mut byte = 0u8;
    let n = loop {
        // SAFETY: reading into a valid one-byte buffer.
        let n = unsafe { libc::read(ready_read, (&raw mut byte).cast(), 1) };
        if n >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break n;
        }
    };
    close(ready_read);
    if n == 1 { Ok(()) } else { Err(io::Error::other("the cleanup process could not be started")) }
}

fn close(fd: libc::c_int) {
    // SAFETY: closing a descriptor this module owns.
    unsafe {
        libc::close(fd);
    }
}

fn cloexec_pipe() -> io::Result<(libc::c_int, libc::c_int)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe(2) fills the array; FD_CLOEXEC is set before any exec
    // can happen (the process is single-threaded).
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        for fd in fds {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    Ok((fds[0], fds[1]))
}

/// The descriptors currently open in this process.
fn open_descriptors() -> Vec<libc::c_int> {
    let listing = if cfg!(any(target_os = "linux", target_os = "android")) { "/proc/self/fd" } else { "/dev/fd" };
    let mut fds: Vec<libc::c_int> = match fs::read_dir(listing) {
        Ok(entries) => entries.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect(),
        Err(_) => (0..1024).collect(),
    };
    // Drops the descriptor of the listing itself, closed by now.
    // SAFETY: F_GETFD only queries.
    fds.retain(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1);
    fds
}

/// The body of the reaper process.
///
/// # Safety
///
/// Must only run in a freshly forked child of a single-threaded process.
unsafe fn reaper(
    watched: libc::pid_t,
    dir: &CStr,
    inherited: &[libc::c_int],
    ready_read: libc::c_int,
    mut ready_write: libc::c_int,
) -> ! {
    // SAFETY: plain system calls on descriptors and memory this process owns.
    unsafe {
        for sig in [
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
            libc::SIGPIPE,
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGALRM,
            libc::SIGTSTP,
            libc::SIGTTIN,
            libc::SIGTTOU,
        ] {
            libc::signal(sig, libc::SIG_IGN);
        }
        libc::close(ready_read);
        if ready_write <= 2 {
            // Standard descriptors are about to be replaced.
            let moved = libc::fcntl(ready_write, libc::F_DUPFD_CLOEXEC, 3);
            libc::close(ready_write);
            ready_write = moved;
        }
        for &fd in inherited {
            if fd != ready_write {
                libc::close(fd);
            }
        }
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            for fd in 0..3 {
                if fd != null {
                    libc::dup2(null, fd);
                }
            }
            if null > 2 {
                libc::close(null);
            }
        }
        libc::chdir(c"/".as_ptr());
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::prctl(libc::PR_SET_NAME, c"bound-reaper".as_ptr());

        // The launcher is blocked until the byte below is written, so it is
        // certainly alive while the watch is set up.
        let watch = Watch::new(watched);
        libc::write(ready_write, [1u8].as_ptr().cast(), 1);
        libc::close(ready_write);
        if let Some(watch) = watch {
            watch.wait();
        }
        let _ = crate::fs::remove_tree(Path::new(OsStr::from_bytes(dir.to_bytes())));
        libc::_exit(0)
    }
}

/// Notification of the exit of a process.
enum Watch {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Pidfd(libc::c_int),
    #[cfg(target_vendor = "apple")]
    Kqueue { kq: libc::c_int, pid: libc::pid_t, start: Option<u64> },
    /// Polls whether the process with this PID and start time still exists.
    Poll { pid: libc::pid_t, start: Option<u64> },
}

impl Watch {
    /// Starts watching `pid`, which must be alive; `None` if it is not.
    fn new(pid: libc::pid_t) -> Option<Watch> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // SAFETY: pidfd_open takes a PID and flags and returns a new descriptor.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if fd >= 0 {
                return Some(Watch::Pidfd(fd as libc::c_int));
            }
            // Otherwise (Linux before 5.3, or a seccomp filter): poll.
        }
        let start = start_time(pid);
        if !alive(pid, start) {
            return None;
        }
        #[cfg(target_vendor = "apple")]
        {
            // SAFETY: registering an EVFILT_PROC filter on a new kqueue.
            unsafe {
                let kq = libc::kqueue();
                if kq >= 0 {
                    let mut change: libc::kevent = std::mem::zeroed();
                    change.ident = pid as libc::uintptr_t;
                    change.filter = libc::EVFILT_PROC;
                    change.flags = libc::EV_ADD | libc::EV_ONESHOT;
                    change.fflags = libc::NOTE_EXIT;
                    if libc::kevent(kq, &change, 1, ptr::null_mut(), 0, ptr::null()) == 0 {
                        return Some(Watch::Kqueue { kq, pid, start });
                    }
                    libc::close(kq);
                }
            }
        }
        Some(Watch::Poll { pid, start })
    }

    /// Blocks until the process has exited.
    fn wait(self) {
        match self {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Watch::Pidfd(fd) => loop {
                let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
                // SAFETY: polling one valid pollfd.
                let rc = unsafe { libc::poll(&mut poll, 1, -1) };
                if rc > 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    return;
                }
            },
            #[cfg(target_vendor = "apple")]
            Watch::Kqueue { kq, pid, start } => loop {
                // NOTE_EXIT is reliable; the periodic check is a safety net.
                let timeout = libc::timespec { tv_sec: 30, tv_nsec: 0 };
                // SAFETY: waiting for one event into a valid struct.
                let n = unsafe {
                    let mut event: libc::kevent = std::mem::zeroed();
                    libc::kevent(kq, ptr::null(), 0, &mut event, 1, &timeout)
                };
                if n > 0 || (n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted) {
                    return;
                }
                if !alive(pid, start) {
                    return;
                }
            },
            Watch::Poll { pid, start } => {
                while alive(pid, start) {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

/// Whether the process `pid` exists and, if its start time was known,
/// is still the same process.
fn alive(pid: libc::pid_t, start: Option<u64>) -> bool {
    match (start, start_time(pid)) {
        (Some(expected), Some(actual)) => expected == actual,
        (Some(_), None) => false,
        // SAFETY: signal 0 only checks for existence.
        (None, _) => unsafe {
            libc::kill(pid, 0) == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        },
    }
}

/// When the process `pid` started, in a platform-specific unit; with the PID
/// this identifies a process uniquely.
fn start_time(pid: libc::pid_t) -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // Field 22 of /proc/PID/stat, counted after the parenthesized name,
        // which may itself contain spaces and parentheses.
        let stat = fs::read(format!("/proc/{pid}/stat")).ok()?;
        let after_name = &stat[stat.iter().rposition(|&b| b == b')')? + 1..];
        let field = after_name.split(|&b| b == b' ').filter(|f| !f.is_empty()).nth(19)?;
        std::str::from_utf8(field).ok()?.parse().ok()
    }
    #[cfg(target_vendor = "apple")]
    {
        // SAFETY: proc_pidinfo fills at most `size` bytes of the struct.
        unsafe {
            let mut info: libc::proc_bsdinfo = std::mem::zeroed();
            let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
            let n = libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size);
            if n != size {
                return None;
            }
            Some(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_times_identify_processes() {
        // SAFETY: getpid cannot fail.
        let me = unsafe { libc::getpid() };
        let start = start_time(me);
        if cfg!(any(target_os = "linux", target_vendor = "apple")) {
            assert!(start.is_some());
        }
        assert!(alive(me, start));
        if let Some(start) = start {
            assert!(!alive(me, Some(start + 1)), "a different start time is a different process");
        }
    }

    #[test]
    fn exited_processes_are_not_alive() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id() as libc::pid_t;
        let start = start_time(pid);
        child.wait().unwrap();
        assert!(!alive(pid, start) || start.is_none());
    }

    #[test]
    fn the_reaper_removes_the_directory_after_the_process_exits() {
        use std::os::unix::process::CommandExt;
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("bound-test");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("file"), b"x").unwrap();
        // A child that starts a reaper for the directory, then execs sleep.
        let target = dir.clone();
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("0.3");
        // SAFETY: start_reaper runs in the single-threaded child before exec.
        unsafe {
            cmd.pre_exec(move || start_reaper(&target));
        }
        let mut child = cmd.spawn().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(dir.exists(), "removed while the process was still running");
        child.wait().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while dir.exists() {
            assert!(std::time::Instant::now() < deadline, "the reaper did not remove {}", dir.display());
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
