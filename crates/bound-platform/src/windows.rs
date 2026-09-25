//! Windows implementations.

use std::ffi::{OsStr, OsString, c_void};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::ptr;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED, ERROR_PRIVILEGE_NOT_HELD, FILETIME,
    HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree, SetHandleInformation,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorDacl,
    GetTokenInformation, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
    TokenOwner, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_TYPE_DISK, FileAttributeTagInfo,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileType, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::Console::{
    CTRL_BREAK_EVENT, CTRL_C_EVENT, GetConsoleProcessList, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE, SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DETACHED_PROCESS,
    GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, INFINITE, OpenProcess, OpenProcessToken,
    PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, STARTF_USESTDHANDLES, STARTUPINFOW,
    WaitForSingleObject,
};
use windows_sys::core::BOOL;

use crate::fs::{LinkDestination, LinkKind};

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned open by the OS and is closed once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Memory allocated by the OS with LocalAlloc.
struct LocalMemory(*mut c_void);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to require LocalFree.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn to_wide(s: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = s.encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL character"));
    }
    wide.push(0);
    Ok(wide)
}

/// A buffer holding the token information of this process of one class,
/// aligned for its structures.
fn token_information(class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    // SAFETY: the standard token-query sequence: the buffer is sized from
    // the first call; the token handle is closed by the guard.
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);
        let mut len = 0u32;
        GetTokenInformation(token.0, class, ptr::null_mut(), 0, &mut len);
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
        if GetTokenInformation(token.0, class, buffer.as_mut_ptr().cast(), len, &mut len) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer)
    }
}

/// Returns the SID of the user running this process, in string form.
pub(crate) fn current_user_sid() -> io::Result<OsString> {
    let buffer = token_information(TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER whose SID points into it.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    sid_string(sid).map(OsString::from)
}

/// The SIDs that own what this process creates: the user, and the token's
/// default owner, which for an elevated administrator is the
/// Administrators group.
fn own_sids() -> io::Result<[String; 2]> {
    let user = current_user_sid()?.to_string_lossy().into_owned();
    let buffer = token_information(TokenOwner)?;
    // SAFETY: the buffer holds a TOKEN_OWNER whose SID points into it.
    let owner = sid_string(unsafe { (*buffer.as_ptr().cast::<TOKEN_OWNER>()).Owner })?;
    Ok([user, owner])
}

/// `CreateDirectoryW` accepts at most 248 characters unless the path uses
/// the `\\?\` form. Temporary paths are normally far shorter.
fn long_path_form(path: &Path) -> PathBuf {
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    let is_drive_absolute = wide.len() >= 3
        && (wide[0] as u8 as char).is_ascii_alphabetic()
        && wide[1] == u16::from(b':')
        && wide[2] == u16::from(b'\\');
    if wide.len() < 240 || !is_drive_absolute || wide.contains(&u16::from(b'/')) {
        return path.to_path_buf();
    }
    let mut out = OsString::from(r"\\?\");
    out.push(path.as_os_str());
    PathBuf::from(out)
}

/// A security descriptor made from SDDL, freed on drop.
struct Descriptor(LocalMemory);

impl Descriptor {
    fn from_sddl(sddl: &OsStr) -> io::Result<Descriptor> {
        let sddl = to_wide(sddl)?;
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: a NUL-terminated string in, an OS allocation out, owned
        // by the guard.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(LocalMemory(descriptor)))
    }

    /// A protected DACL (P: nothing inherited from the parent) granting
    /// full control to the current user and to SYSTEM, inherited by every
    /// file and directory created inside (OI|CI).
    fn private() -> io::Result<Descriptor> {
        let mut sddl = OsString::from("D:P(A;OICI;FA;;;");
        sddl.push(current_user_sid()?);
        sddl.push(")(A;OICI;FA;;;SY)");
        Descriptor::from_sddl(&sddl)
    }

    fn dacl(&self) -> io::Result<*mut ACL> {
        let (mut present, mut defaulted, mut dacl) = (0, 0, ptr::null_mut());
        // SAFETY: the descriptor is valid while self lives.
        if unsafe { GetSecurityDescriptorDacl(self.0.0, &mut present, &mut dacl, &mut defaulted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(dacl)
    }
}

/// Well-known accounts trusted like root on Unix: the system, the
/// administrators, the installer service, and the owner of the object.
const TRUSTED_SIDS: [&str; 4] =
    ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", "S-1-3-4"];

/// Rights that let an account remove, rename or re-permission a
/// directory's entries: delete a child, delete, change the DACL or the
/// owner, or all rights.
const REPLACE_RIGHTS: u32 = 0x0000_0040 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x1000_0000;

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: a valid SID in, an OS allocation out, freed by the guard.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut text) == 0 {
            return Err(io::Error::last_os_error());
        }
        let _free = LocalMemory(text.cast());
        let mut n = 0;
        while *text.add(n) != 0 {
            n += 1;
        }
        Ok(String::from_utf16_lossy(std::slice::from_raw_parts(text, n)))
    }
}

/// The owner and the access granted by the DACL of a file or directory.
pub(crate) struct Access {
    pub(crate) owner: String,
    /// `(SID, rights)` of each ACE allowing access to the object itself
    /// (not inherit-only); `None` for a null DACL, which allows everything.
    pub(crate) grants: Option<Vec<(String, u32)>>,
}

pub(crate) fn access_of(path: &Path) -> io::Result<Access> {
    let wide = to_wide(path.as_os_str())?;
    let (mut owner, mut dacl, mut descriptor): (PSID, *mut ACL, PSECURITY_DESCRIPTOR) =
        (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    // SAFETY: the out pointers point into the descriptor, which the guard
    // frees after they are last used.
    unsafe {
        let rc = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        );
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let _free = LocalMemory(descriptor);
        let owner = sid_string(owner)?;
        if dacl.is_null() {
            return Ok(Access { owner, grants: None });
        }
        let mut grants = Vec::new();
        for index in 0..u32::from((*dacl).AceCount) {
            let mut ace: *mut c_void = ptr::null_mut();
            if GetAce(dacl, index, &mut ace) == 0 {
                return Err(io::Error::last_os_error());
            }
            let header = &*ace.cast::<ACE_HEADER>();
            // Allowed ACEs only: deny ACEs only take rights away.
            if header.AceType != 0 || header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
                continue;
            }
            let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            let sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
            grants.push((sid_string(sid)?, allowed.Mask));
        }
        Ok(Access { owner, grants: Some(grants) })
    }
}

/// Replaces the DACL of `path` with the one of `descriptor`, protected from
/// inheritance; what inherits from `path` is updated too.
fn set_protected_dacl(path: &Path, descriptor: &Descriptor) -> io::Result<()> {
    let wide = to_wide(path.as_os_str())?;
    // SAFETY: a valid path and a DACL owned by the descriptor.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            descriptor.dacl()?,
            ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// Replaces the DACL of `path` with the protected one described in SDDL
/// (for tests, which need directories others may change).
#[cfg(test)]
pub(crate) fn set_dacl(path: &Path, sddl: &str) -> io::Result<()> {
    set_protected_dacl(path, &Descriptor::from_sddl(OsStr::new(sddl))?)
}

/// Refuses a location in which another user could rename the private
/// directory and put their own in its place (as Unix refuses directories
/// writable by others without the sticky bit): `dir` and every directory
/// above it must be owned by this user or a trusted account, and must not
/// let anyone else delete, rename or re-permission their entries.
pub(crate) fn check_trusted_location(dir: &Path) -> io::Result<()> {
    let me = current_user_sid()?.to_string_lossy().into_owned();
    let trusted = |sid: &str| sid == me || TRUSTED_SIDS.contains(&sid);
    for ancestor in dir.ancestors().filter(|a| !a.as_os_str().is_empty()) {
        let access = access_of(ancestor)?;
        let problem = if !trusted(&access.owner) {
            format!("is owned by another account ({})", access.owner)
        } else {
            match &access.grants {
                None => "has no access control list, so anyone may change it".to_owned(),
                Some(grants) => match grants.iter().find(|(sid, rights)| !trusted(sid) && rights & REPLACE_RIGHTS != 0)
                {
                    Some((sid, _)) => format!("lets another account ({sid}) delete or rename its entries"),
                    None => continue,
                },
            }
        };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} {problem}, so files created in {} could be replaced; set TMP to a private directory",
                ancestor.display(),
                dir.display()
            ),
        ));
    }
    Ok(())
}

pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        check_trusted_location(parent)?;
    }
    let descriptor = Descriptor::private()?;
    let path = to_wide(long_path_form(path).as_os_str())?;

    // SAFETY: all pointers are valid NUL-terminated wide strings or
    // correctly initialized structures; the descriptor outlives the call.
    unsafe {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: 0,
        };
        // Fails with ERROR_ALREADY_EXISTS for any existing entry, including
        // a planted junction or symlink, which are therefore never reused.
        if CreateDirectoryW(path.as_ptr(), &attributes) == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) fn create_new_file(path: &Path) -> io::Result<File> {
    // CREATE_NEW refuses any existing entry; FILE_FLAG_OPEN_REPARSE_POINT
    // guarantees a reparse point is never followed.
    OpenOptions::new().write(true).create_new(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path)
}

pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<PathBuf> {
    if std::fs::symlink_metadata(dir).is_err() {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match create_private_dir(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a plain directory", dir.display()),
        ));
    }
    let mine = own_sids()?;
    let me = &mine[0];
    let access = access_of(dir)?;
    if !mine.contains(&access.owner) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a directory of this user", dir.display()),
        ));
    }
    // Anyone else allowed in (a directory made by other means than this
    // function): make it private, as Unix does with chmod 700. The DACL is
    // applied to everything inside as well.
    let shared =
        access.grants.as_ref().is_none_or(|grants| grants.iter().any(|(sid, _)| sid != me && sid != "S-1-5-18"));
    if shared {
        set_protected_dacl(dir, &Descriptor::private()?)?;
    }
    if let Some(parent) = dir.parent() {
        check_trusted_location(parent)?;
    }
    // Paths under it are given to programs, which expect drive paths.
    Ok(crate::process::plain_path(dir.to_path_buf()))
}

/// Whether `path` is a directory of this user sealed by
/// [`crate::fs::set_read_only`]: marked read-only, as nothing that changed
/// it could leave it (Windows ignores the mark, so it is only a seal).
pub(crate) fn is_sealed_dir(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return false };
    if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !meta.permissions().readonly() {
        return false;
    }
    let Ok(mine) = own_sids() else { return false };
    access_of(path).is_ok_and(|access| mine.contains(&access.owner))
}

/// Clears the read-only attribute of every file and directory in the tree
/// (never following links or junctions), so that the tree can be removed.
pub(crate) fn make_tree_writable(root: &Path) {
    let clear = |path: &Path, meta: &std::fs::Metadata| {
        if meta.permissions().readonly() {
            let mut permissions = meta.permissions();
            // Windows-only: this clears the read-only attribute and
            // grants nothing to anyone.
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            let _ = std::fs::set_permissions(path, permissions);
        }
    };
    if let Ok(meta) = std::fs::symlink_metadata(root) {
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
            clear(root, &meta);
        }
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                continue;
            }
            clear(&entry.path(), &meta);
            if meta.is_dir() {
                stack.push(entry.path());
            }
        }
    }
}

/// Set once creating a symbolic link has failed for lack of the privilege,
/// so that the other links of the bundle go straight to the fallbacks.
static SYMLINKS_UNAVAILABLE: AtomicBool = AtomicBool::new(false);

/// Whether an error means the file system cannot do this at all (FAT).
fn unsupported(e: &io::Error) -> bool {
    matches!(e.raw_os_error().map(|code| code as u32), Some(ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED))
}

/// See [`crate::fs::create_link`]. `try_symlink: false` goes straight to the
/// fallbacks (for tests: an administrator may always create symlinks).
pub(crate) fn create_link(
    target: &Path,
    link: &Path,
    destination: LinkDestination<'_>,
    try_symlink: bool,
) -> io::Result<LinkKind> {
    if try_symlink && !SYMLINKS_UNAVAILABLE.load(Ordering::Relaxed) {
        // std asks for SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE, which
        // Developer Mode honors.
        let created = if destination.is_dir {
            std::os::windows::fs::symlink_dir(target, link)
        } else {
            std::os::windows::fs::symlink_file(target, link)
        };
        match created {
            Ok(()) => return Ok(LinkKind::Symlink),
            Err(e) if e.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD as i32) => {
                SYMLINKS_UNAVAILABLE.store(true, Ordering::Relaxed);
            }
            Err(e) if unsupported(&e) => {}
            Err(e) => return Err(e),
        }
    }
    if destination.is_dir {
        create_junction(link, destination.then)?;
        return Ok(LinkKind::Junction);
    }
    match std::fs::hard_link(destination.now, link) {
        Ok(()) => Ok(LinkKind::HardLink),
        Err(e) if unsupported(&e) => {
            let mut from = File::open(destination.now)?;
            let mut to = create_new_file(link)?;
            io::copy(&mut from, &mut to)?;
            Ok(LinkKind::Copy)
        }
        Err(e) => Err(e),
    }
}

const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

/// Creates a junction: a new directory `link` made a mount point for the
/// directory `target`, an absolute path (which need not exist yet).
fn create_junction(link: &Path, target: &Path) -> io::Result<()> {
    let target = crate::process::plain_path(target.to_path_buf());
    if !target.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "a junction needs an absolute target"));
    }
    let print: Vec<u16> = target.as_os_str().encode_wide().collect();
    // The NT form of the path: \??\C:\dir, or \??\UNC\server\share\dir.
    let mut substitute: Vec<u16> = r"\??\".encode_utf16().collect();
    match print.strip_prefix(&[u16::from(b'\\'), u16::from(b'\\')][..]) {
        Some(unc) => {
            substitute.extend(r"UNC\".encode_utf16());
            substitute.extend_from_slice(unc);
        }
        None => substitute.extend_from_slice(&print),
    }
    // MountPointReparseBuffer: offsets and lengths in bytes, then the two
    // names, each followed by a NUL.
    let (substitute_len, print_len) = (substitute.len() * 2, print.len() * 2);
    let data_len = 8 + substitute_len + 2 + print_len + 2;
    let too_long = || io::Error::new(io::ErrorKind::InvalidInput, "the junction target is too long");
    let field = |n: usize| u16::try_from(n).map_err(|_| too_long());
    let mut buffer = Vec::with_capacity(8 + data_len);
    buffer.extend(IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buffer.extend(field(data_len)?.to_le_bytes());
    buffer.extend(0u16.to_le_bytes());
    buffer.extend(0u16.to_le_bytes());
    buffer.extend(field(substitute_len)?.to_le_bytes());
    buffer.extend(field(substitute_len + 2)?.to_le_bytes());
    buffer.extend(field(print_len)?.to_le_bytes());
    for unit in substitute.iter().chain(&[0]).chain(&print).chain(&[0]) {
        buffer.extend(unit.to_le_bytes());
    }

    // An exclusive create: an existing entry is never reused.
    std::fs::create_dir(link)?;
    let result = (|| {
        let dir = OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(link)?;
        let mut returned = 0u32;
        // SAFETY: the handle is open for writing and the buffer is a
        // complete REPARSE_DATA_BUFFER of the given length.
        let ok = unsafe {
            DeviceIoControl(
                dir.as_raw_handle() as HANDLE,
                FSCTL_SET_REPARSE_POINT,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir(link);
    }
    result
}

/// The file to read for the input `file`, opened from `path` without
/// following a final reparse point unless `follow`: refuses anything that
/// is not a file on disk (a device, or a pipe that could block), and a link
/// swapped in for a file; a reparse point that is not a link (such as a
/// cloud file's placeholder) is opened again, through the file system filter
/// that serves its content, and must be the same file.
pub(crate) fn served_file(path: &Path, file: File, follow: bool) -> io::Result<File> {
    let not_a_file = || io::Error::new(io::ErrorKind::InvalidInput, "not a regular file");
    // SAFETY: querying an open handle.
    if unsafe { GetFileType(file.as_raw_handle() as HANDLE) } != FILE_TYPE_DISK {
        return Err(not_a_file());
    }
    if follow {
        return Ok(file);
    }
    let mut tag = FILE_ATTRIBUTE_TAG_INFO { FileAttributes: 0, ReparseTag: 0 };
    // SAFETY: a valid handle and a buffer of the size given.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileAttributeTagInfo,
            (&raw mut tag).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return Ok(file);
    }
    // Name surrogates are links and junctions, which the bundle keeps as
    // such: this one replaced the file that was found.
    if tag.ReparseTag & 0x2000_0000 != 0 {
        return Err(io::Error::other("the file was replaced by a link while it was being bundled"));
    }
    let served = OpenOptions::new().read(true).open(path)?;
    if file_id(&served)? != file_id(&file)? {
        return Err(io::Error::other("the file changed while it was being bundled"));
    }
    Ok(served)
}

/// The volume and index that identify an open file.
fn file_id(file: &File) -> io::Result<(u32, u64)> {
    // SAFETY: a valid handle and a zeroed structure to fill.
    unsafe {
        let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        if GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((info.dwVolumeSerialNumber, u64::from(info.nFileIndexHigh) << 32 | u64::from(info.nFileIndexLow)))
    }
}

/// MoveFileExW without MOVEFILE_REPLACE_EXISTING: fails if `to` exists.
pub(crate) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    let from = to_wide(from.as_os_str())?;
    let to = to_wide(to.as_os_str())?;
    // SAFETY: valid NUL-terminated wide strings.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether a child is running (console events then belong to it).
static CHILD_RUNNING: AtomicBool = AtomicBool::new(false);
/// A Ctrl+C / Ctrl+Break received while no child was running.
static PENDING: AtomicU32 = AtomicU32::new(NO_EVENT);
const NO_EVENT: u32 = u32::MAX;

unsafe extern "system" fn console_handler(ctrl_type: u32) -> BOOL {
    match ctrl_type {
        // The child is attached to the same console and receives the event
        // itself; the launcher stays alive to wait for it and clean up.
        CTRL_C_EVENT | CTRL_BREAK_EVENT => {
            if !CHILD_RUNNING.load(Ordering::SeqCst) {
                PENDING.store(ctrl_type, Ordering::SeqCst);
            }
            1
        }
        // Close, logoff and shutdown: default handling.
        _ => 0,
    }
}

pub(crate) fn prepare_supervision() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        // SAFETY: registers a handler with the correct signature.
        unsafe {
            SetConsoleCtrlHandler(Some(console_handler), 1);
        }
    });
}

/// A console interrupt received while no child was running.
pub(crate) fn interrupted() -> Option<i32> {
    match PENDING.load(Ordering::SeqCst) {
        NO_EVENT => None,
        event => Some(event as i32),
    }
}

/// STATUS_CONTROL_C_EXIT: how a console process killed by Ctrl+C exits.
pub(crate) const STATUS_CONTROL_C_EXIT: u32 = 0xC000_013A;

/// A job object that terminates its processes when its last handle closes,
/// that is, when the launcher exits or is terminated. Processes created by
/// the program break away from it silently, so only the program itself is
/// tied to the launcher (as with Windows launchers such as `py.exe`).
fn kill_on_close_job() -> Option<OwnedHandle> {
    // SAFETY: creating an unnamed, non-inheritable job and setting its
    // limits from a zero-initialized structure of the documented type.
    unsafe {
        let job = CreateJobObjectW(ptr::null(), ptr::null());
        if job.is_null() {
            return None;
        }
        let job = OwnedHandle(job);
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
        let ok = SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw const info).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        (ok != 0).then_some(job)
    }
}

/// Whether this process is attached to a console. (Whether it has a window
/// does not tell: a console created with `CREATE_NO_WINDOW`, as services and
/// GUI programs start tools, has none.)
fn has_console() -> bool {
    let mut first = 0u32;
    // SAFETY: a buffer of one process ID; the count returned may exceed it.
    unsafe { GetConsoleProcessList(&mut first, 1) != 0 }
}

pub(crate) fn run_supervised(cmd: &mut Command) -> io::Result<ExitStatus> {
    prepare_supervision();
    // The program shares the launcher's console, with or without a window.
    // Started without any (detached), the launcher starts the program
    // without one too, as its caller would have: a console program would
    // otherwise be given a new console, and a window.
    if !has_console() {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(DETACHED_PROCESS);
    }
    // The program's standard handles are this process's, which the standard
    // library passes as inheritable duplicates; the originals, inheritable
    // too when the caller passed them on, would reach the program a second
    // time. Kept here, they leave the program exactly the handles its caller
    // gave the launcher.
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: querying and updating this process's own standard handles;
        // an invalid or pseudo handle just makes the update fail.
        unsafe {
            let handle = GetStdHandle(which);
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
    let job = kill_on_close_job();
    CHILD_RUNNING.store(true, Ordering::SeqCst);
    let result = cmd.spawn().and_then(|mut child| {
        if let Some(job) = &job {
            // Best effort: without the job, the program merely survives a
            // terminated launcher.
            // SAFETY: both handles are valid; the child has not been waited for.
            unsafe {
                AssignProcessToJobObject(job.0, child.as_raw_handle() as HANDLE);
            }
        }
        child.wait()
    });
    CHILD_RUNNING.store(false, Ordering::SeqCst);
    // Closing the job now terminates nothing: the program has exited.
    drop(job);
    result
}

// ---------------------------------------------------------------------------
// Program lookup.

fn system_dir(get: unsafe extern "system" fn(*mut u16, u32) -> u32) -> Option<PathBuf> {
    let mut buffer = vec![0u16; 512];
    // SAFETY: the buffer length is passed; the API returns the length
    // written, or the size needed if the buffer is too small.
    let n = unsafe { get(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if n == 0 || n >= buffer.len() {
        return None;
    }
    Some(PathBuf::from(OsString::from_wide(&buffer[..n])))
}

pub(crate) fn find_program(name: &OsStr, child_path: Option<&OsStr>, skip: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    let parent_path = std::env::var_os("PATH");
    let usable = |candidate: &Path| candidate.is_file() && !skip(candidate);

    // The standard library's order (see `Command` in std): the child's own
    // PATH, the application directory, the system and Windows directories,
    // then the parent's PATH, appending ".exe" to names without a dot.
    let has_dot = name.encode_wide().any(|u| u == u16::from(b'.'));
    let file_name = if has_dot {
        name.to_os_string()
    } else {
        let mut with_exe = name.to_os_string();
        with_exe.push(".exe");
        with_exe
    };
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(paths) = child_path {
        dirs.extend(std::env::split_paths(paths).filter(|p| !p.as_os_str().is_empty()));
    }
    if let Some(app_dir) = std::env::current_exe().ok().and_then(|exe| exe.parent().map(Path::to_path_buf)) {
        dirs.push(app_dir);
    }
    dirs.extend(system_dir(GetSystemDirectoryW));
    dirs.extend(system_dir(GetWindowsDirectoryW));
    if let Some(paths) = &parent_path {
        dirs.extend(std::env::split_paths(paths).filter(|p| !p.as_os_str().is_empty()));
    }
    if let Some(found) = dirs.iter().map(|dir| dir.join(&file_name)).find(|c| usable(c)) {
        return Some(found);
    }

    // Shell-style PATHEXT search over the absolute entries of the PATH the
    // program will see.
    if Path::new(name).extension().is_some() {
        return None;
    }
    let path_var = child_path.map(OsStr::to_os_string).or(parent_path)?;
    std::env::split_paths(&path_var)
        .filter(|dir| dir.is_absolute())
        .flat_map(|dir| crate::process::candidates(&dir, name))
        .find(|c| usable(c))
}

// ---------------------------------------------------------------------------
// The reaper.
//
// The launcher starts a second copy of the artifact as the reaper: detached
// from the console (no console events), in its own process group, with no
// inherited handles (it never holds the caller's pipes), outside the
// caller's job if that is allowed (so a job that is closed when the
// launcher exits cannot kill it before it has cleaned up), and with an
// environment consisting only of the request below. It waits for the
// launcher, identified by PID and creation time, to exit, and then removes
// the bundle directory, retrying while files are still in use.

/// Environment variable carrying a reaper request:
/// `PID:CREATION-TIME:DIRECTORY`.
const REAPER_VAR: &str = "BOUND_INTERNAL_REAPER";

fn creation_time(process: HANDLE) -> io::Result<u64> {
    let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: valid process handle and out-pointers.
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime))
}

pub(crate) fn start_reaper(dir: &Path) -> io::Result<()> {
    let exe = std::env::current_exe()?;
    // SAFETY: pseudo-handle and ID of the current process.
    let (pid, created) = unsafe { (GetCurrentProcessId(), creation_time(GetCurrentProcess())?) };

    let mut request = OsString::from(format!("{REAPER_VAR}={pid}:{created}:"));
    request.push(dir);
    let mut environment: Vec<u16> = Vec::new();
    if let Some(root) = std::env::var_os("SystemRoot") {
        // Some system DLLs expect it.
        let mut entry = OsString::from("SystemRoot=");
        entry.push(root);
        environment.extend(to_wide(&entry)?);
    }
    environment.extend(to_wide(&request)?);
    environment.push(0);

    let application = to_wide(exe.as_os_str())?;
    let mut command_line = OsString::from("\"");
    command_line.push(&exe);
    command_line.push("\"");
    let mut command_line = to_wide(&command_line)?;
    let working_dir = to_wide(dir.parent().unwrap_or(dir).as_os_str())?;

    // SAFETY: all strings are NUL-terminated wide strings that outlive the
    // call (the command line is mutable, as CreateProcessW requires); no
    // handles are inherited and the standard handles are null.
    unsafe {
        let mut startup: STARTUPINFOW = std::mem::zeroed();
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        startup.dwFlags = STARTF_USESTDHANDLES;
        let mut info: PROCESS_INFORMATION = std::mem::zeroed();
        let base = CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
        let mut started = false;
        for flags in [base | CREATE_BREAKAWAY_FROM_JOB, base] {
            if CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                flags,
                environment.as_ptr().cast(),
                working_dir.as_ptr(),
                &startup,
                &mut info,
            ) != 0
            {
                started = true;
                break;
            }
            // Breaking away is refused by jobs that do not allow it.
            if io::Error::last_os_error().raw_os_error() != Some(ERROR_ACCESS_DENIED as i32) {
                break;
            }
        }
        if !started {
            return Err(io::Error::last_os_error());
        }
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
    }
    Ok(())
}

/// Whether `dir` looks like a bundle directory the launcher created: an
/// absolute, real directory (not a link or junction) named `bound-` and 16
/// hexadecimal digits.
fn is_bundle_dir(dir: &Path) -> bool {
    let named_like_one = dir.file_name().and_then(OsStr::to_str).is_some_and(|name| {
        name.len() == 22 && name.starts_with("bound-") && name[6..].bytes().all(|b| b.is_ascii_hexdigit())
    });
    named_like_one
        && dir.is_absolute()
        && std::fs::symlink_metadata(dir)
            .is_ok_and(|meta| meta.is_dir() && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0)
}

pub(crate) fn run_reaper_if_requested() {
    let Some(request) = std::env::var_os(REAPER_VAR) else { return };
    let Some((pid, created, dir)) = parse_reaper_request(&request) else { return };
    // Only a launcher starts reapers, as its own children: a request found
    // in the environment of any other process (a stray variable) is
    // ignored, and the artifact runs normally.
    if parent_process_id() != Some(pid) || !is_bundle_dir(&dir) {
        return;
    }
    reap(pid, created, &dir);
    std::process::exit(0);
}

/// Parses `PID:CREATION-TIME:DIRECTORY`.
fn parse_reaper_request(request: &OsStr) -> Option<(u32, u64, PathBuf)> {
    let wide: Vec<u16> = request.encode_wide().collect();
    let mut parts = wide.splitn(3, |&u| u == u16::from(b':'));
    let number = |part: Option<&[u16]>| String::from_utf16(part?).ok()?.parse::<u64>().ok();
    let pid = number(parts.next()).and_then(|pid| u32::try_from(pid).ok())?;
    let created = number(parts.next())?;
    let dir = PathBuf::from(OsString::from_wide(parts.next()?));
    Some((pid, created, dir))
}

/// What the reaper does: waits until the launcher has exited, then removes
/// the bundle directory.
fn reap(pid: u32, created: u64, dir: &Path) {
    wait_for_exit(pid, created);
    remove_patiently(dir);
}

/// The ID of the process that created this one.
fn parent_process_id() -> Option<u32> {
    // SAFETY: a process snapshot walked with correctly sized entries and
    // closed by the guard.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let snapshot = OwnedHandle(snapshot);
        let me = GetCurrentProcessId();
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot.0, &mut entry) != 0;
        while more {
            if entry.th32ProcessID == me {
                return Some(entry.th32ParentProcessID);
            }
            more = Process32NextW(snapshot.0, &mut entry) != 0;
        }
        None
    }
}

/// The process with this PID and creation time, if it still exists (a
/// different creation time means the PID was reused: that process is
/// gone).
fn open_process(pid: u32, created: u64) -> Option<OwnedHandle> {
    // SAFETY: opening a process by ID; the handle is owned by the guard.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let process = OwnedHandle(process);
    creation_time(process.0).is_ok_and(|t| t == created).then_some(process)
}

/// Waits until the process with this PID and creation time has exited.
fn wait_for_exit(pid: u32, created: u64) {
    if let Some(process) = open_process(pid, created) {
        // SAFETY: a valid process handle.
        unsafe {
            WaitForSingleObject(process.0, INFINITE);
        }
    }
}

/// Removes the directory, retrying for a few seconds while files are still
/// in use (by the program's process during its final teardown, or by a
/// virus scanner).
fn remove_patiently(dir: &Path) {
    let mut delay = Duration::from_millis(10);
    for _ in 0..10 {
        if crate::fs::remove_tree(dir).is_ok() {
            return;
        }
        std::thread::sleep(delay);
        delay *= 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_looks_like_a_sid() {
        let sid = current_user_sid().unwrap();
        assert!(sid.to_string_lossy().starts_with("S-1-"), "{sid:?}");
    }

    /// Whether the process with this PID and creation time is running.
    fn alive(pid: u32, created: u64) -> bool {
        // SAFETY: a zero timeout only polls the handle.
        open_process(pid, created).is_some_and(|process| unsafe { WaitForSingleObject(process.0, 0) } != 0)
    }

    #[test]
    fn start_times_identify_processes() {
        // SAFETY: pseudo-handle and ID of the current process.
        let (me, created) = unsafe { (GetCurrentProcessId(), creation_time(GetCurrentProcess()).unwrap()) };
        assert!(alive(me, created));
        assert!(!alive(me, created + 1), "a different start time is a different process");
    }

    #[test]
    fn exited_processes_are_not_alive() {
        use std::os::windows::io::AsRawHandle;
        let mut child = Command::new("cmd.exe").args(["/c", "exit", "0"]).spawn().unwrap();
        let pid = child.id();
        let created = creation_time(child.as_raw_handle() as HANDLE).unwrap();
        child.wait().unwrap();
        assert!(!alive(pid, created));
    }

    #[test]
    fn the_reaper_removes_the_directory_after_the_process_exits() {
        use std::os::windows::io::AsRawHandle;
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("bound-0123456789abcdef");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("file"), b"x").unwrap();
        // Only absolute, real directories named like bundles are reaped.
        assert!(is_bundle_dir(&dir));
        assert!(!is_bundle_dir(&parent.path().join("bound-01234567")));
        assert!(!is_bundle_dir(Path::new(r"relative\bound-0123456789abcdef")));

        let mut child = Command::new("ping.exe")
            .args(["-n", "2", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let created = creation_time(child.as_raw_handle() as HANDLE).unwrap();
        let request = OsString::from(format!("{pid}:{created}:{}", dir.display()));
        assert_eq!(parse_reaper_request(&request), Some((pid, created, dir.clone())));
        let reaper = {
            let dir = dir.clone();
            std::thread::spawn(move || reap(pid, created, &dir))
        };
        std::thread::sleep(Duration::from_millis(100));
        assert!(dir.exists(), "removed while the process was still running");
        child.wait().unwrap();
        reaper.join().unwrap();
        assert!(!dir.exists(), "the reaper did not remove {}", dir.display());
    }

    #[test]
    fn bundle_directories_are_recognized_strictly() {
        let parent = tempfile::tempdir().unwrap();
        let good = parent.path().join("bound-0123456789abcdef");
        std::fs::create_dir(&good).unwrap();
        assert!(is_bundle_dir(&good));
        for bad in ["bound-0123", "other-0123456789abcdef", "bound-0123456789abcdeg"] {
            let path = parent.path().join(bad);
            std::fs::create_dir(&path).unwrap();
            assert!(!is_bundle_dir(&path), "{bad}");
        }
        assert!(!is_bundle_dir(Path::new("bound-0123456789abcdef")), "relative paths are refused");
        assert!(!is_bundle_dir(&parent.path().join("bound-fedcba9876543210")), "missing directories are refused");
    }

    #[test]
    fn the_current_process_has_a_creation_time() {
        // SAFETY: pseudo-handle of the current process.
        let created = creation_time(unsafe { GetCurrentProcess() }).unwrap();
        assert!(created > 0);
    }

    #[test]
    fn long_paths_get_the_verbatim_prefix() {
        let short = Path::new(r"C:\Temp\x");
        assert_eq!(long_path_form(short), short);
        let long = PathBuf::from(format!(r"C:\{}", "a".repeat(260)));
        assert!(long_path_form(&long).as_os_str().to_string_lossy().starts_with(r"\\?\C:\"));
    }

    #[test]
    fn links_fall_back_to_junctions_and_hard_links() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::process::plain_path(std::fs::canonicalize(dir.path()).unwrap());
        std::fs::create_dir(root.join("store")).unwrap();
        std::fs::write(root.join(r"store\file.txt"), "content").unwrap();
        let store = root.join("store");
        let file = root.join(r"store\file.txt");
        let to_dir = LinkDestination { now: &store, then: &store, is_dir: true };
        let to_file = LinkDestination { now: &file, then: &file, is_dir: false };

        // As for a user without the privilege to create symbolic links.
        let kind = create_link(Path::new("store"), &root.join("dir-link"), to_dir, false).unwrap();
        assert_eq!(kind, LinkKind::Junction);
        assert_eq!(std::fs::read_to_string(root.join(r"dir-link\file.txt")).unwrap(), "content");
        let kind = create_link(Path::new(r"store\file.txt"), &root.join("file-link"), to_file, false).unwrap();
        assert_eq!(kind, LinkKind::HardLink);
        assert_eq!(std::fs::read_to_string(root.join("file-link")).unwrap(), "content");
        // Existing entries are never replaced.
        assert!(create_link(Path::new("store"), &root.join("dir-link"), to_dir, false).is_err());
        assert!(create_link(Path::new("store"), &root.join("file-link"), to_file, false).is_err());

        // A junction holds the path where the bundle will be: it may not
        // exist yet.
        let later = root.join(r"final\store");
        let ahead = LinkDestination { now: &store, then: &later, is_dir: true };
        create_link(Path::new("store"), &root.join("ahead"), ahead, false).unwrap();
        let shown = std::fs::read_link(root.join("ahead")).unwrap();
        assert!(shown.to_string_lossy().ends_with(r"final\store"), "{}", shown.display());

        // Removing a tree removes its junctions, never what they lead to.
        std::fs::create_dir(root.join("tree")).unwrap();
        create_link(Path::new(r"..\store"), &root.join(r"tree\j"), to_dir, false).unwrap();
        crate::fs::remove_tree(&root.join("tree")).unwrap();
        assert!(!root.join("tree").exists());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "content");
    }
}
