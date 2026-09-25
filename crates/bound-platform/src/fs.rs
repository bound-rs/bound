//! File-system operations whose safety depends on the platform.

use std::fs::{self, File, Metadata};
use std::io;
use std::path::{Path, PathBuf};

/// What a directory entry is, determined without following links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file. `executable` reflects the Unix execute bits; it is
    /// always `false` on Windows, where executability is a matter of file
    /// name and format rather than metadata.
    File {
        executable: bool,
    },
    Dir,
    /// A symbolic link. On Windows this is any name-surrogate reparse point,
    /// which includes junctions and volume mount points.
    Link,
    /// Anything else (FIFO, socket, device), described for error messages.
    Other(&'static str),
}

/// Classifies an entry from metadata obtained with [`fs::symlink_metadata`].
pub fn classify(meta: &Metadata) -> EntryKind {
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return EntryKind::Link;
    }
    if file_type.is_dir() {
        return EntryKind::Dir;
    }
    if file_type.is_file() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            return EntryKind::File { executable: meta.permissions().mode() & 0o111 != 0 };
        }
        #[cfg(not(unix))]
        {
            return EntryKind::File { executable: false };
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if file_type.is_fifo() {
            return EntryKind::Other("named pipe");
        }
        if file_type.is_socket() {
            return EntryKind::Other("socket");
        }
        if file_type.is_block_device() || file_type.is_char_device() {
            return EntryKind::Other("device");
        }
    }
    EntryKind::Other("special file")
}

/// The directory under which private runtime directories are created: the
/// platform's temporary directory (`TMPDIR` on Unix, `GetTempPath2W` /
/// `%TEMP%` on Windows). On Unix the path is canonicalized so that it matches
/// what `getcwd` reports inside it (e.g. `/private/var/...` on macOS).
pub fn temp_base() -> PathBuf {
    let mut base = std::env::temp_dir();
    if cfg!(unix) && base.as_os_str().is_empty() {
        // `TMPDIR=` (set but empty) means unset, not the working directory.
        base = PathBuf::from("/tmp");
    }
    #[cfg(unix)]
    {
        if let Ok(real) = fs::canonicalize(&base) {
            return real;
        }
    }
    base
}

/// Creates a new directory named `prefix` + random suffix inside `parent`,
/// accessible only by the current user (mode `0700` on Unix; on Windows a
/// protected DACL granting access to the current user and SYSTEM only).
///
/// The directory is always freshly created by this call, never reused: an
/// existing entry with the chosen name (including a planted symlink) makes
/// the attempt fail and another random name is tried.
pub fn create_private_dir(parent: &Path, prefix: &str) -> io::Result<PathBuf> {
    let mut last_error = None;
    for _ in 0..16 {
        let path = parent.join(format!("{prefix}{}", crate::random_hex(8)?));
        #[cfg(unix)]
        let result = crate::unix::create_private_dir(&path);
        #[cfg(windows)]
        let result = crate::windows::create_private_dir(&path);
        match result {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last_error = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("could not create a unique directory")))
}

/// Creates one directory inside a private tree. Fails if anything already
/// exists at `path`.
pub fn create_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        crate::unix::create_dir(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

/// Creates a new file for writing. Fails if anything already exists at
/// `path`, including a symlink or reparse point, which is never followed.
/// On Unix the file is private (`0600`, or `0700` if `executable`).
pub fn create_new_file(path: &Path, executable: bool) -> io::Result<File> {
    #[cfg(unix)]
    {
        crate::unix::create_new_file(path, executable)
    }
    #[cfg(windows)]
    {
        let _ = executable;
        crate::windows::create_new_file(path)
    }
}

/// Creates the file a new artifact is written to. It is private (`0600`)
/// while being written; [`finish_output_file`] then makes it executable.
/// Fails if `path` exists.
pub fn create_output_file(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

/// Gives a finished artifact its final permissions: executable by everyone
/// the process's umask allows, like a compiler's output (Unix; nothing to
/// do on Windows).
pub fn finish_output_file(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o777 & !crate::unix::umask()))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

/// The per-user cache directory: `BOUND_CACHE_DIR` if set; otherwise
/// `~/Library/Caches/bound` (macOS), `$XDG_CACHE_HOME/bound` or
/// `~/.cache/bound` (Linux and other Unix), `%LOCALAPPDATA%\bound\cache`
/// (Windows). `None` when caching is turned off with `BOUND_CACHE=0` (or
/// `off`, `no`, `false`), or when there is no home directory.
pub fn cache_dir() -> Option<PathBuf> {
    let off = std::env::var("BOUND_CACHE")
        .is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "off" | "no" | "false"));
    if off {
        return None;
    }
    let absolute = |var: &str| std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute());
    if let Some(dir) = absolute("BOUND_CACHE_DIR") {
        return Some(dir);
    }
    if cfg!(windows) {
        return absolute("LOCALAPPDATA").map(|dir| dir.join("bound").join("cache"));
    }
    if cfg!(target_vendor = "apple") {
        return absolute("HOME").map(|home| home.join("Library").join("Caches").join("bound"));
    }
    absolute("XDG_CACHE_HOME")
        .map(|dir| dir.join("bound"))
        .or_else(|| absolute("HOME").map(|home| home.join(".cache").join("bound")))
}

/// Creates `dir` (and any missing parent) if needed and makes sure it is a
/// private directory of this user, in a location no other user can alter:
/// owned by this user, accessible to nobody else (the mode is corrected if
/// needed), and not a link. Returns its canonical path.
pub fn ensure_private_dir(dir: &Path) -> io::Result<PathBuf> {
    #[cfg(unix)]
    {
        crate::unix::ensure_private_dir(dir)
    }
    #[cfg(windows)]
    {
        crate::windows::ensure_private_dir(dir)
    }
}

/// Creates the new file `dst` with the contents of `src`, private to this
/// user (`0600`, or `0700` if `executable`). The copy shares storage with
/// `src` where the file system can clone files (APFS, Btrfs, XFS), and is
/// an ordinary copy elsewhere; either way, changing one never changes the
/// other. Fails if `dst` exists.
pub fn clone_file(src: &File, dst: &Path, executable: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        crate::unix::clone_file(src, dst, executable)
    }
    #[cfg(windows)]
    {
        let _ = executable;
        let mut out = crate::windows::create_new_file(dst)?;
        io::copy(&mut &*src, &mut out)?;
        Ok(())
    }
}

/// Makes an entry read-only: Unix removes every write bit (`0555` for
/// directories and executables, `0444` for other files); Windows sets the
/// read-only attribute.
pub fn set_read_only(path: &Path, is_dir: bool, executable: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_dir || executable { 0o555 } else { 0o444 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        // Directories too: Windows does not enforce it on them, but it
        // seals a shared bundle (see is_sealed_dir).
        let _ = (is_dir, executable);
        let mut permissions = fs::symlink_metadata(path)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions)
    }
}

/// Whether `path` is a real directory (not a link) of this user that was
/// sealed with [`set_read_only`] and not made writable since, such as a
/// shared bundle: nobody can write to it (Unix), or it is still marked
/// read-only (Windows, which does not enforce the mark on directories).
pub fn is_sealed_dir(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = fs::symlink_metadata(path) else { return false };
        // SAFETY: geteuid cannot fail.
        meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o222 == 0
    }
    #[cfg(windows)]
    {
        crate::windows::is_sealed_dir(path)
    }
}

/// Makes a tree of files and directories that were just written durable,
/// as a group, before it is renamed into place. `entries` are the files and
/// directories under `root` (`true` for a directory).
///
/// Flushing entry by entry costs a device cache flush each on macOS
/// (`F_FULLFSYNC`) and a journal commit each on Linux: seconds for
/// thousands of files. Instead, Linux flushes the file system once
/// (`syncfs`), and macOS sends each entry's data to the device (`fsync`)
/// and then flushes the device's cache once.
///
/// Windows has no such grouped flush for unprivileged processes, and a
/// file-by-file one costs a device flush plus, because each file is opened
/// for writing again, another antivirus scan: 3 ms per file on a cloud
/// VM, a minute for 10,000 files. Windows therefore relies on NTFS's
/// journal alone (file data written shortly before a system crash can be
/// lost; `bound cache clean` removes the entry).
pub fn sync_tree<'a>(root: &Path, entries: impl IntoIterator<Item = (&'a Path, bool)>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        drop(entries);
        let dir = fs::File::open(root)?;
        // SAFETY: syncfs on a descriptor we own.
        if unsafe { libc::syncfs(dir.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(target_vendor = "apple")]
    {
        use std::os::fd::AsRawFd;
        for (path, _) in entries {
            let file = fs::File::open(path)?;
            // SAFETY: fsync on a descriptor we own. (File::sync_all would
            // use F_FULLFSYNC, which also flushes the device's cache.)
            if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        fs::File::open(root)?.sync_all()
    }
    #[cfg(windows)]
    {
        drop(entries);
        let _ = root;
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
    {
        for (path, is_dir) in entries {
            sync_path(path, is_dir)?;
        }
        sync_path(root, true)
    }
}

/// Flushes a file or directory to stable storage.
pub fn sync_path(path: &Path, is_dir: bool) -> io::Result<()> {
    if is_dir && cfg!(windows) {
        // Windows cannot open directories this way, and does not need to.
        return Ok(());
    }
    // FlushFileBuffers needs a handle with write access on Windows.
    fs::OpenOptions::new().read(true).write(cfg!(windows)).open(path)?.sync_all()
}

/// Removes a file, including a read-only one (which Windows refuses to
/// delete as is).
pub fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        #[cfg(windows)]
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            let mut permissions = fs::symlink_metadata(path)?.permissions();
            // This clears the read-only attribute; it grants nothing.
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            fs::set_permissions(path, permissions)?;
            fs::remove_file(path)
        }
        other => other,
    }
}

/// Renames `from` to `to`, failing with `AlreadyExists` instead of
/// replacing an existing `to`. Where the file system cannot do this
/// atomically, `to` is checked first (a narrow race remains).
pub fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        match crate::unix::rename_no_replace(from, to) {
            Err(e) if e.kind() == io::ErrorKind::Unsupported => {}
            other => return other,
        }
        if fs::symlink_metadata(to).is_ok() {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        fs::rename(from, to)
    }
    #[cfg(windows)]
    {
        crate::windows::rename_no_replace(from, to)
    }
}

/// What identifies a file found while walking a directory, to detect that
/// it was replaced before it is read: device and inode on Unix; size and
/// creation time on Windows (directory listings may report a stale
/// modification time, so it is not compared).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    len: u64,
    #[cfg(windows)]
    created: Option<std::time::SystemTime>,
}

impl FileIdentity {
    pub fn of(meta: &Metadata) -> FileIdentity {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            FileIdentity { dev: meta.dev(), ino: meta.ino() }
        }
        #[cfg(windows)]
        {
            FileIdentity { len: meta.len(), created: meta.created().ok() }
        }
    }
}

/// Opens an input file for reading. Never blocks (a named pipe is not
/// waited on), refuses anything but a regular file, does not follow a
/// final symbolic link unless `follow` is set, and, given `expected`, fails
/// if the file is no longer the one identified then.
pub fn open_input(path: &Path, follow: bool, expected: Option<&FileIdentity>) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let nofollow = if follow { 0 } else { libc::O_NOFOLLOW };
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | nofollow);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        if !follow {
            options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
        }
    }
    let file = options.open(path)?;
    // Devices and pipes (such as \\.\pipe\NAME) are not read: a pipe could
    // block forever.
    #[cfg(windows)]
    let file = crate::windows::served_file(path, file, follow)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    if expected.is_some_and(|identity| *identity != FileIdentity::of(&meta)) {
        return Err(io::Error::other("the file changed while it was being bundled"));
    }
    #[cfg(unix)]
    crate::unix::clear_nonblocking(&file)?;
    Ok(file)
}

/// How [`create_link`] made a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// A symbolic link with the relative target.
    Symlink,
    /// Windows: a junction (a directory link that any user can create) to
    /// the absolute path of the directory.
    Junction,
    /// Windows: a hard link to the file.
    HardLink,
    /// Windows, on file systems without hard links: a copy of the file.
    Copy,
}

/// Where a link leads, for creating it where symbolic links are not
/// available.
#[derive(Clone, Copy, Debug)]
pub struct LinkDestination<'a> {
    /// What the link resolves to, every link followed, where it is now.
    pub now: &'a Path,
    /// The same, where the bundle will be used (a shared bundle is written
    /// in a staging directory and then renamed into place).
    pub then: &'a Path,
    /// Whether it is a directory (otherwise a file).
    pub is_dir: bool,
}

/// Creates the link `link` with the relative `target`, which leads to
/// `destination`.
///
/// Unix: a symbolic link. Windows: a symbolic link when this user may create
/// them (with Developer Mode, or the privilege administrators have);
/// otherwise, as pnpm does, a junction to the directory or a hard link to
/// the file, which programs follow like links. A junction holds an absolute
/// path: `destination.then`, where the bundle will be used.
pub fn create_link(target: &Path, link: &Path, destination: LinkDestination<'_>) -> io::Result<LinkKind> {
    #[cfg(unix)]
    {
        let _ = destination;
        std::os::unix::fs::symlink(target, link).map(|()| LinkKind::Symlink)
    }
    #[cfg(windows)]
    {
        crate::windows::create_link(target, link, destination, true)
    }
}

/// Removes a directory tree without following symlinks inside it.
///
/// Unix: if removal fails because the child left directories without write
/// permission, owner permissions are restored and removal is retried.
/// Windows: files can be briefly locked (by virus scanners, or by processes
/// that are still exiting), so removal is retried with a short backoff.
pub fn remove_tree(path: &Path) -> io::Result<()> {
    let first = match fs::remove_dir_all(path) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => e,
    };
    #[cfg(unix)]
    {
        crate::unix::make_tree_writable(path);
        match fs::remove_dir_all(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => {}
        }
    }
    #[cfg(windows)]
    {
        crate::windows::make_tree_writable(path);
        for delay_ms in [10, 20, 40, 80, 160, 320] {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            match fs::remove_dir_all(path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(_) => {}
            }
        }
    }
    Err(first)
}

/// Whether `path` names a regular file that the platform would execute
/// (Unix: any execute bit; Windows: any file).
pub fn is_executable_file(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(meta) if meta.is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// The accounts other than this user and the system that `path` lets
    /// in (Windows), or its permission bits for group and others (Unix).
    fn others_allowed(path: &Path) -> String {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            format!("{:o}", fs::symlink_metadata(path).unwrap().permissions().mode() & 0o077)
        }
        #[cfg(windows)]
        {
            let me = crate::windows::current_user_sid().unwrap().to_string_lossy().into_owned();
            let grants = crate::windows::access_of(path).unwrap().grants.expect("a DACL");
            let others: Vec<String> =
                grants.into_iter().map(|(sid, _)| sid).filter(|sid| *sid != me && sid != "S-1-5-18").collect();
            if others.is_empty() { "0".to_owned() } else { others.join(",") }
        }
    }

    /// Lets every user change `dir`'s entries: writable by all without the
    /// sticky bit (Unix), or an ACE letting everyone delete them (Windows).
    fn open_to_others(dir: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o777)).unwrap();
        }
        #[cfg(windows)]
        {
            let me = crate::windows::current_user_sid().unwrap().to_string_lossy().into_owned();
            // DT: FILE_DELETE_CHILD.
            crate::windows::set_dacl(dir, &format!("D:P(A;OICI;FA;;;{me})(A;;DT;;;WD)")).unwrap();
        }
    }

    /// Lets every user add entries to `dir` but not change others' (the
    /// sticky bit on Unix, as /tmp has; on Windows, the right to add only).
    fn shared_like_tmp(dir: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o1777)).unwrap();
        }
        #[cfg(windows)]
        {
            let me = crate::windows::current_user_sid().unwrap().to_string_lossy().into_owned();
            crate::windows::set_dacl(dir, &format!("D:P(A;OICI;FA;;;{me})(A;;0x100006;;;WD)")).unwrap();
        }
    }

    /// A symbolic link (on Windows, this needs Developer Mode or an
    /// administrator).
    fn symlink(target: &Path, link: &Path, is_dir: bool) {
        #[cfg(unix)]
        {
            let _ = is_dir;
            std::os::unix::fs::symlink(target, link).unwrap();
        }
        #[cfg(windows)]
        {
            let made = if is_dir {
                std::os::windows::fs::symlink_dir(target, link)
            } else {
                std::os::windows::fs::symlink_file(target, link)
            };
            made.unwrap();
        }
    }

    #[test]
    fn private_dirs_are_fresh_and_private() {
        let parent = tempfile::tempdir().unwrap();
        let a = create_private_dir(parent.path(), "bound-").unwrap();
        let b = create_private_dir(parent.path(), "bound-").unwrap();
        assert_ne!(a, b);
        assert!(a.file_name().unwrap().to_str().unwrap().starts_with("bound-"));
        assert_eq!(others_allowed(&a), "0");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&a).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn parents_others_can_change_are_refused() {
        let parent = tempfile::tempdir().unwrap();
        open_to_others(parent.path());
        let err = create_private_dir(parent.path(), "x-").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let expected = if cfg!(windows) { "delete or rename its entries" } else { "not sticky" };
        assert!(err.to_string().contains(expected), "{err}");
        // A directory where everyone may only add entries (like /tmp) is
        // fine.
        shared_like_tmp(parent.path());
        create_private_dir(parent.path(), "x-").unwrap();
    }

    #[test]
    fn ancestors_others_can_change_are_refused() {
        let outer = tempfile::tempdir().unwrap();
        let inner = outer.path().join("inner");
        fs::create_dir(&inner).unwrap();
        open_to_others(outer.path());
        let err = create_private_dir(&inner, "x-").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains(&outer.path().display().to_string()), "{err}");
        let err = ensure_private_dir(&inner.join("cache")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        shared_like_tmp(outer.path());
        create_private_dir(&inner, "x-").unwrap();
        ensure_private_dir(&inner.join("cache")).unwrap();
    }

    #[test]
    fn existing_cache_directories_are_made_private() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("cache");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("inside"), b"x").unwrap();
        // Readable by others: made private again, as chmod 700 would.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        }
        #[cfg(windows)]
        {
            let me = crate::windows::current_user_sid().unwrap().to_string_lossy().into_owned();
            crate::windows::set_dacl(&dir, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FR;;;WD)")).unwrap();
        }
        assert_ne!(others_allowed(&dir), "0");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(others_allowed(&dir), "0");
        if cfg!(windows) {
            // What inherited the old access list inherits the new one.
            assert_eq!(others_allowed(&dir.join("inside")), "0");
        }
    }

    #[test]
    fn inherited_access_is_removed() {
        // A parent whose entries inherit access for other users: an ACL
        // entry for everyone (macOS, Windows), a default ACL (Linux).
        let parent = tempfile::tempdir().unwrap();
        #[cfg(target_vendor = "apple")]
        {
            let grant = std::process::Command::new("chmod")
                .args([
                    "+a",
                    "everyone allow list,add_file,search,add_subdirectory,read,write,file_inherit,directory_inherit",
                ])
                .arg(parent.path())
                .status()
                .unwrap();
            assert!(grant.success());
        }
        #[cfg(target_os = "linux")]
        let has_acls = linux_acl::grant_default(parent.path());
        #[cfg(windows)]
        {
            // Inherit-only: for what is created inside, not the parent
            // itself (which could otherwise not be trusted at all).
            let me = crate::windows::current_user_sid().unwrap().to_string_lossy().into_owned();
            crate::windows::set_dacl(parent.path(), &format!("D:P(A;OICI;FA;;;{me})(A;OICIIO;FA;;;WD)")).unwrap();
        }

        let dir = create_private_dir(parent.path(), "bound-").unwrap();
        let file = dir.join("f");
        create_new_file(&file, false).unwrap();
        for path in [&dir, &file] {
            #[cfg(target_vendor = "apple")]
            {
                let listing = std::process::Command::new("ls").arg("-lde").arg(path).output().unwrap();
                let text = String::from_utf8_lossy(&listing.stdout).into_owned();
                assert!(!text.contains("everyone"), "{} kept an inherited ACL: {text}", path.display());
            }
            #[cfg(target_os = "linux")]
            {
                // Inherited entries may be there, but the mask (the group
                // bits of the mode) leaves them no permission.
                let mask = linux_acl::mask(path);
                assert!(mask.unwrap_or(0) == 0, "{}: ACL mask {mask:?}", path.display());
                assert!(has_acls || mask.is_none());
            }
            assert_eq!(others_allowed(path), "0", "{}", path.display());
        }
    }

    /// POSIX ACLs through their extended attributes, as the kernel stores
    /// them (no libacl needed).
    #[cfg(target_os = "linux")]
    mod linux_acl {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::path::Path;

        const USER_OBJ: u16 = 0x01;
        const USER: u16 = 0x02;
        const GROUP_OBJ: u16 = 0x04;
        const MASK: u16 = 0x10;
        const OTHER: u16 = 0x20;

        fn c_path(path: &Path) -> CString {
            CString::new(path.as_os_str().as_bytes()).unwrap()
        }

        /// Gives `dir` a default ACL granting everything to everyone and to
        /// the user nobody. False if the file system has no ACLs.
        pub(super) fn grant_default(dir: &Path) -> bool {
            let mut acl = 2u32.to_le_bytes().to_vec();
            for (tag, id) in
                [(USER_OBJ, u32::MAX), (USER, 65534), (GROUP_OBJ, u32::MAX), (MASK, u32::MAX), (OTHER, u32::MAX)]
            {
                acl.extend(tag.to_le_bytes());
                acl.extend(7u16.to_le_bytes());
                acl.extend(id.to_le_bytes());
            }
            let path = c_path(dir);
            // SAFETY: NUL-terminated strings and a buffer of the given size.
            let rc = unsafe {
                libc::setxattr(path.as_ptr(), c"system.posix_acl_default".as_ptr(), acl.as_ptr().cast(), acl.len(), 0)
            };
            if rc == 0 {
                return true;
            }
            let error = std::io::Error::last_os_error();
            assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP), "setting a default ACL: {error}");
            false
        }

        /// The permissions of the mask entry of `path`'s access ACL, if it
        /// has one.
        pub(super) fn mask(path: &Path) -> Option<u16> {
            let path = c_path(path);
            let mut buffer = [0u8; 1024];
            // SAFETY: a NUL-terminated path and name, and a buffer of the
            // given size.
            let n = unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    c"system.posix_acl_access".as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if n < 0 {
                return None;
            }
            buffer[4..n as usize]
                .chunks_exact(8)
                .find(|entry| u16::from_le_bytes([entry[0], entry[1]]) == MASK)
                .map(|entry| u16::from_le_bytes([entry[2], entry[3]]))
        }
    }

    #[test]
    fn new_files_are_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        create_new_file(&path, false).unwrap().write_all(b"x").unwrap();
        assert_eq!(create_new_file(&path, false).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert!(create_dir(&path).is_err());
    }

    #[test]
    fn new_files_never_follow_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"original").unwrap();
        let link = dir.path().join("link");
        symlink(&victim, &link, false);
        assert!(create_new_file(&link, false).is_err());
        let dangling = dir.path().join("dangling");
        symlink(&dir.path().join("nowhere"), &dangling, false);
        assert!(create_new_file(&dangling, false).is_err());
        assert!(!dir.path().join("nowhere").exists());
        assert_eq!(fs::read(&victim).unwrap(), b"original");

        let exe = dir.path().join("exe");
        create_new_file(&exe, true).unwrap();
        assert!(is_executable_file(&exe));
        // Executable bits exist on Unix only; Windows runs files by name.
        assert_eq!(classify(&fs::symlink_metadata(&exe).unwrap()), EntryKind::File { executable: cfg!(unix) });
        assert_eq!(classify(&fs::symlink_metadata(&link).unwrap()), EntryKind::Link);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&exe).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn remove_tree_handles_locked_down_directories() {
        let parent = tempfile::tempdir().unwrap();
        let root = create_private_dir(parent.path(), "t-").unwrap();
        let sub = root.join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("f"), b"x").unwrap();
        // Locked down as a program or a sealed bundle leaves it: no write
        // permission (Unix), read-only attributes (Windows).
        set_read_only(&sub.join("f"), false, false).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sub, fs::Permissions::from_mode(0o500)).unwrap();
        }
        #[cfg(windows)]
        set_read_only(&sub, true, true).unwrap();
        // Links to something outside must be removed, not followed.
        let outside = parent.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"k").unwrap();
        symlink(&outside, &root.join("escape"), true);
        #[cfg(windows)]
        crate::windows::create_link(
            Path::new("outside"),
            &root.join("junction"),
            LinkDestination { now: &outside, then: &outside, is_dir: true },
            false,
        )
        .unwrap();
        remove_tree(&root).unwrap();
        assert!(!root.exists());
        assert!(outside.join("keep").exists());
        remove_tree(&root).unwrap();
    }

    #[test]
    fn links_lead_where_they_point() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("data").join("sub")).unwrap();
        fs::write(root.join("data").join("file.txt"), "file").unwrap();
        fs::write(root.join("data").join("sub").join("x.txt"), "x").unwrap();
        fs::create_dir(root.join("links")).unwrap();
        let (file, sub) = (root.join("data").join("file.txt"), root.join("data").join("sub"));
        let up = Path::new("..").join("data");
        let file_kind = create_link(
            &up.join("file.txt"),
            &root.join("links").join("file"),
            LinkDestination { now: &file, then: &file, is_dir: false },
        )
        .unwrap();
        let dir_kind = create_link(
            &up.join("sub"),
            &root.join("links").join("dir"),
            LinkDestination { now: &sub, then: &sub, is_dir: true },
        )
        .unwrap();
        assert_eq!(fs::read_to_string(root.join("links").join("file")).unwrap(), "file");
        assert_eq!(fs::read_to_string(root.join("links").join("dir").join("x.txt")).unwrap(), "x");
        // Symbolic links, unless Windows lets this user create none.
        if cfg!(unix) {
            assert_eq!((file_kind, dir_kind), (LinkKind::Symlink, LinkKind::Symlink));
        } else {
            assert!(
                matches!(
                    (file_kind, dir_kind),
                    (LinkKind::Symlink, LinkKind::Symlink) | (LinkKind::HardLink | LinkKind::Copy, LinkKind::Junction)
                ),
                "{file_kind:?} {dir_kind:?}"
            );
        }
        // Existing entries are never replaced.
        let again = LinkDestination { now: &file, then: &file, is_dir: false };
        assert!(create_link(&up.join("file.txt"), &root.join("links").join("file"), again).is_err());
    }

    #[test]
    fn sealed_directories_are_recognized() {
        let parent = tempfile::tempdir().unwrap();
        let dir = create_private_dir(parent.path(), "s-").unwrap();
        fs::write(dir.join("f"), b"x").unwrap();
        assert!(!is_sealed_dir(&dir));
        set_read_only(&dir.join("f"), false, false).unwrap();
        set_read_only(&dir, true, true).unwrap();
        assert!(is_sealed_dir(&dir));
        // Made writable again: no longer sealed.
        let mut permissions = fs::metadata(&dir).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(&dir, permissions).unwrap();
        assert!(!is_sealed_dir(&dir));
        assert!(!is_sealed_dir(&dir.join("f")));
        remove_tree(&dir).unwrap();
    }

    #[test]
    fn temp_base_exists() {
        assert!(temp_base().is_dir());
    }
}
