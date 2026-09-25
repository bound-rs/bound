//! A tiny cross-platform program used as the target of bound artifacts in
//! tests. The first argument selects a mode:
//!
//! ```text
//! report [ARGS]...     print JSON: argv, argv0, cwd, env, pid, ppid, exe, and on
//!                      Unix pgid, sid (+stdin if FIXTURE_STDIN=1)
//! exit CODE            exit with CODE
//! cat                  copy stdin to stdout
//! echo [TEXT]...       print the arguments separated by spaces
//! stderr TEXT          print TEXT to stderr
//! read FILE...         print the contents of each file
//! write FILE TEXT      replace FILE's contents with TEXT
//! mutate FILE          print FILE's contents, then overwrite it
//! ls DIR               list DIR recursively (sorted; directories end in /)
//! env NAME             print $NAME, or exit 3 if unset
//! read-env NAME        print the contents of the file named by $NAME
//! env-exit NAME CODE   print $NAME, then exit with CODE
//! sleep MS             sleep for MS milliseconds
//! mode PATH            (Unix) print the permission bits of PATH in octal
//! lock PATH            make PATH and everything in it read-only (Unix:
//!                      no write permission; Windows: read-only attributes),
//!                      then print BOUND_ROOT ("-" if unset)
//! wait-signal          print "ready", wait for an interrupt/termination
//!                      signal (Windows: Ctrl+C/Ctrl+Break), print its
//!                      name (and "duplicate" if a second one follows) and
//!                      exit with 100 + its number
//! kill-self SIGNAL     terminate by the given signal number (Unix), or with
//!                      the given status, such as 0xC0000005 (Windows)
//! disposition SIGNAL   (Unix) print "ignored", "default" or "handled"
//! flood                write lines to stdout until that fails
//! hold                 print "PID BOUND_ROOT" ("-" if unset), then sleep
//!                      until killed
//! children             print "none" if this process has no children
//! fds                  print the open file descriptors (Unix), or the
//!                      inheritable handles other than the standard ones
//!                      and how many standard ones are inheritable
//!                      (Windows: "VALUES; std N"), sorted
//!
//! Windows only, as test drivers:
//! console MODE PROG..  run PROG in this process's console, send it console
//!                      events (MODE: break, interrupt or ignored), print
//!                      its output and "exit CODE"
//! spawn-clean PROG..   run PROG inheriting only the standard handles and
//!                      one event, printing "handles: ..." first
//! without-symlinks PROG..
//!                      run PROG without the privilege to create symbolic
//!                      links, printing "symlinks: yes|no" first
//! ```

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

/// Encodes a platform string exactly: a JSON string when it is Unicode,
/// otherwise `{"hex": ...}` of its raw bytes (Unix) or code units (Windows).
fn encode(s: &OsStr) -> Value {
    if let Some(text) = s.to_str() {
        return Value::String(text.to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let hex: String = s.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        json!({ "hex": hex })
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let hex: String = s.encode_wide().map(|u| format!("{u:04x}")).collect();
        json!({ "hex": hex })
    }
}

/// The SIGPIPE disposition this process was started with, captured by a
/// constructor before Rust's runtime replaces it with "ignore".
#[cfg(unix)]
static ORIGINAL_SIGPIPE_IGNORED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn capture_sigpipe() {
    // SAFETY: querying a disposition does not change it.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut action);
        ORIGINAL_SIGPIPE_IGNORED.store(action.sa_sigaction == libc::SIG_IGN, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(unix)]
#[used]
#[cfg_attr(target_vendor = "apple", unsafe(link_section = "__DATA,__mod_init_func"))]
#[cfg_attr(not(target_vendor = "apple"), unsafe(link_section = ".init_array"))]
static CAPTURE_SIGPIPE: extern "C" fn() = capture_sigpipe;

fn fail(msg: &str) -> ! {
    eprintln!("bound-fixture: {msg}");
    std::process::exit(99)
}

fn main() {
    let mut args = std::env::args_os();
    let argv0 = args.next().unwrap_or_default();
    let mode = args.next().unwrap_or_default();
    let rest: Vec<OsString> = args.collect();
    let arg = |i: usize| rest.get(i).cloned().unwrap_or_else(|| fail("missing argument"));
    let text = |i: usize| arg(i).into_string().unwrap_or_else(|_| fail("argument is not Unicode"));

    match mode.to_str().unwrap_or("") {
        "report" => report(&argv0, &rest),
        "exit" => {
            let code: i64 = text(0).parse().unwrap_or_else(|_| fail("bad exit code"));
            std::process::exit(code as i32)
        }
        "cat" => {
            io::copy(&mut io::stdin().lock(), &mut io::stdout().lock()).unwrap_or_else(|e| fail(&e.to_string()));
        }
        "echo" => {
            let words: Vec<String> = rest.iter().map(|a| a.to_string_lossy().into_owned()).collect();
            println!("{}", words.join(" "));
        }
        "stderr" => eprintln!("{}", text(0)),
        "read" => {
            let mut out = io::stdout().lock();
            for path in &rest {
                let data = std::fs::read(path).unwrap_or_else(|e| fail(&format!("{}: {e}", path.to_string_lossy())));
                out.write_all(&data).unwrap();
            }
        }
        "write" => std::fs::write(arg(0), text(1)).unwrap_or_else(|e| fail(&e.to_string())),
        "mutate" => {
            let path = arg(0);
            let old = std::fs::read(&path).unwrap_or_else(|e| fail(&e.to_string()));
            io::stdout().write_all(&old).unwrap();
            std::fs::write(&path, b"mutated by the child").unwrap_or_else(|e| fail(&e.to_string()));
        }
        "ls" => {
            let root = arg(0);
            let mut entries = Vec::new();
            list(Path::new(&root), Path::new(""), &mut entries);
            entries.sort();
            for entry in entries {
                println!("{entry}");
            }
        }
        "env" => match std::env::var_os(arg(0)) {
            Some(value) => println!("{}", value.to_string_lossy()),
            None => std::process::exit(3),
        },
        "env-exit" => {
            println!("{}", std::env::var_os(arg(0)).unwrap_or_default().to_string_lossy());
            io::stdout().flush().unwrap();
            std::process::exit(text(1).parse().unwrap_or_else(|_| fail("bad exit code")))
        }
        "read-env" => {
            let path = std::env::var_os(arg(0)).unwrap_or_else(|| fail("variable not set"));
            let data = std::fs::read(&path).unwrap_or_else(|e| fail(&format!("{}: {e}", path.to_string_lossy())));
            io::stdout().write_all(&data).unwrap();
        }
        "sleep" => std::thread::sleep(Duration::from_millis(text(0).parse().unwrap_or(0))),
        "mode" => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = std::fs::symlink_metadata(arg(0)).unwrap_or_else(|e| fail(&e.to_string()));
                println!("{:o}", meta.permissions().mode() & 0o7777);
            }
            #[cfg(not(unix))]
            fail("mode is Unix-only");
        }
        "lock" => {
            lock(Path::new(&arg(0)));
            let root = std::env::var_os("BOUND_ROOT").unwrap_or_else(|| "-".into());
            println!("{}", root.to_string_lossy());
        }
        "wait-signal" => wait_signal(),
        "kill-self" => {
            #[cfg(unix)]
            {
                let sig: i32 = text(0).parse().unwrap_or_else(|_| fail("bad signal"));
                // SAFETY: plain libc calls.
                unsafe {
                    libc::signal(sig, libc::SIG_DFL);
                    libc::raise(sig);
                }
                fail("signal did not terminate the process");
            }
            #[cfg(windows)]
            {
                let text = text(0);
                let code = match text.strip_prefix("0x") {
                    Some(hex) => u32::from_str_radix(hex, 16),
                    None => text.parse(),
                }
                .unwrap_or_else(|_| fail("bad status"));
                // SAFETY: terminating the current process.
                unsafe {
                    windows_sys::Win32::System::Threading::TerminateProcess(
                        windows_sys::Win32::System::Threading::GetCurrentProcess(),
                        code,
                    );
                }
                fail("TerminateProcess returned");
            }
        }
        "disposition" => {
            #[cfg(unix)]
            {
                let sig: i32 = text(0).parse().unwrap_or_else(|_| fail("bad signal"));
                std::hint::black_box(&CAPTURE_SIGPIPE);
                if sig == libc::SIGPIPE {
                    // Rust replaced it at startup; report what we were given.
                    let ignored = ORIGINAL_SIGPIPE_IGNORED.load(std::sync::atomic::Ordering::SeqCst);
                    println!("{}", if ignored { "ignored" } else { "default" });
                    return;
                }
                // SAFETY: querying the disposition does not change it.
                let current = unsafe {
                    let mut action: libc::sigaction = std::mem::zeroed();
                    libc::sigaction(sig, std::ptr::null(), &mut action);
                    action.sa_sigaction
                };
                println!(
                    "{}",
                    match current {
                        libc::SIG_IGN => "ignored",
                        libc::SIG_DFL => "default",
                        _ => "handled",
                    }
                );
            }
            #[cfg(not(unix))]
            fail("disposition is Unix-only");
        }
        "hold" => {
            let root = std::env::var_os("BOUND_ROOT").unwrap_or_else(|| "-".into());
            println!("{} {}", std::process::id(), root.to_string_lossy());
            io::stdout().flush().unwrap();
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
        "children" => {
            #[cfg(unix)]
            let none = {
                // SAFETY: a non-blocking wait for any child.
                let rc = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
                rc == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
            };
            #[cfg(windows)]
            let none = win::children().is_empty();
            println!("{}", if none { "none" } else { "some" });
        }
        "fds" => {
            #[cfg(unix)]
            {
                let listing = if cfg!(target_os = "linux") { "/proc/self/fd" } else { "/dev/fd" };
                let mut fds: Vec<i32> = std::fs::read_dir(listing)
                    .unwrap_or_else(|e| fail(&e.to_string()))
                    .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
                    .collect();
                // Drop the descriptor of the listing itself, closed by now.
                // SAFETY: F_GETFD only queries.
                fds.retain(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1);
                fds.sort_unstable();
                let shown: Vec<String> = fds.iter().map(i32::to_string).collect();
                println!("{}", shown.join(" "));
            }
            #[cfg(windows)]
            println!("{}", win::handle_summary(&win::inheritable_handles()));
        }
        #[cfg(windows)]
        "console" => {
            let mode = text(0);
            std::process::exit(win::console(&mode, &arg(1), &rest[2..]))
        }
        #[cfg(windows)]
        "spawn-clean" => std::process::exit(win::spawn_clean(&arg(0), &rest[1..])),
        #[cfg(windows)]
        "without-symlinks" => std::process::exit(win::without_symlinks(&arg(0), &rest[1..])),
        "flood" => {
            let mut out = io::stdout().lock();
            while out.write_all(b"y\n").is_ok() {}
            // Only reached if writing failed without a fatal SIGPIPE.
            std::process::exit(3);
        }
        other => fail(&format!("unknown mode {other:?}")),
    }
}

fn report(argv0: &OsStr, rest: &[OsString]) {
    let env: BTreeMap<String, Value> =
        std::env::vars_os().map(|(k, v)| (k.to_string_lossy().into_owned(), encode(&v))).collect();
    let stdin = if std::env::var_os("FIXTURE_STDIN").is_some() {
        let mut data = String::new();
        io::stdin().read_to_string(&mut data).unwrap_or_else(|e| fail(&e.to_string()));
        Value::String(data)
    } else {
        Value::Null
    };
    let cwd = std::env::current_dir().map(|p| encode(p.as_os_str())).unwrap_or(Value::Null);
    let exe = std::env::current_exe().map(|p| encode(p.as_os_str())).unwrap_or(Value::Null);
    let doc = json!({
        "argv0": encode(argv0),
        "argv": rest.iter().map(|a| encode(a)).collect::<Vec<_>>(),
        "cwd": cwd,
        "exe": exe,
        "pid": std::process::id(),
        "env": env,
        "stdin": stdin,
    });
    #[cfg(unix)]
    let doc = {
        let mut doc = doc;
        // SAFETY: these calls cannot fail for the calling process.
        let (ppid, pgid, sid) = unsafe { (libc::getppid(), libc::getpgrp(), libc::getsid(0)) };
        doc["ppid"] = json!(ppid);
        doc["pgid"] = json!(pgid);
        doc["sid"] = json!(sid);
        // Whether there is a controlling terminal.
        doc["console"] = json!(if std::fs::File::open("/dev/tty").is_ok() { "terminal" } else { "none" });
        doc
    };
    #[cfg(windows)]
    let doc = {
        let mut doc = doc;
        doc["ppid"] = json!(win::parent_id());
        let (console, attached) = win::console_state();
        doc["console"] = json!(console);
        doc["console_processes"] = json!(attached);
        doc
    };
    println!("{doc}");
}

/// Makes `path` and everything in it read-only, as a program locking down
/// its files would.
fn lock(path: &Path) {
    let meta = std::fs::symlink_metadata(path).unwrap_or_else(|e| fail(&format!("{}: {e}", path.display())));
    if meta.is_dir() {
        for entry in std::fs::read_dir(path).unwrap_or_else(|e| fail(&e.to_string())) {
            lock(&entry.unwrap().path());
        }
    }
    if meta.file_type().is_symlink() {
        return;
    }
    let mut permissions = meta.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(if meta.is_dir() { 0o500 } else { 0o400 });
    }
    #[cfg(windows)]
    permissions.set_readonly(true);
    std::fs::set_permissions(path, permissions).unwrap_or_else(|e| fail(&format!("{}: {e}", path.display())));
}

fn list(root: &Path, rel: &Path, out: &mut Vec<String>) {
    let dir = root.join(rel);
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| fail(&format!("{}: {e}", dir.display())));
    for entry in entries {
        let entry = entry.unwrap();
        let rel = rel.join(entry.file_name());
        let shown = rel.to_string_lossy().replace('\\', "/");
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            out.push(format!("{shown}/"));
            list(root, &rel, out);
        } else if kind.is_symlink() {
            // Shown with / whatever the host's separator, and a junction's
            // absolute target as a plain path (not \\?\C:\...).
            let target = std::fs::read_link(entry.path()).unwrap();
            let target = target.to_string_lossy();
            let target = target.strip_prefix(r"\\?\").unwrap_or(&target);
            out.push(format!("{shown} -> {}", target.replace('\\', "/")));
        } else {
            out.push(shown);
        }
    }
}

#[cfg(unix)]
fn wait_signal() {
    use std::sync::atomic::{AtomicI32, Ordering};
    static RECEIVED: AtomicI32 = AtomicI32::new(0);
    extern "C" fn handler(sig: libc::c_int) {
        RECEIVED.store(sig, Ordering::SeqCst);
    }
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGUSR1, libc::SIGQUIT] {
        // SAFETY: installs a handler that only stores to an atomic.
        unsafe {
            libc::signal(sig, handler as *const () as libc::sighandler_t);
        }
    }
    println!("ready");
    io::stdout().flush().unwrap();
    let mut count = 0;
    loop {
        let sig = RECEIVED.swap(0, Ordering::SeqCst);
        if sig != 0 {
            count += 1;
            let name = match sig {
                libc::SIGINT => "SIGINT",
                libc::SIGTERM => "SIGTERM",
                libc::SIGHUP => "SIGHUP",
                libc::SIGUSR1 => "SIGUSR1",
                libc::SIGQUIT => "SIGQUIT",
                _ => "other",
            };
            println!("{name}");
            io::stdout().flush().unwrap();
            // Linger briefly so a duplicate delivery would be observed.
            std::thread::sleep(Duration::from_millis(300));
            if RECEIVED.load(Ordering::SeqCst) != 0 {
                println!("duplicate");
            }
            let _ = count;
            std::process::exit(100 + sig);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(windows)]
fn wait_signal() {
    use std::sync::atomic::{AtomicU32, Ordering};
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};
    static RECEIVED: AtomicU32 = AtomicU32::new(u32::MAX);
    unsafe extern "system" fn handler(ctrl: u32) -> windows_sys::core::BOOL {
        RECEIVED.store(ctrl, Ordering::SeqCst);
        1
    }
    // SAFETY: registers a handler with the correct signature.
    unsafe {
        SetConsoleCtrlHandler(Some(handler), 1);
    }
    println!("ready");
    io::stdout().flush().unwrap();
    loop {
        let ctrl = RECEIVED.swap(u32::MAX, Ordering::SeqCst);
        if ctrl != u32::MAX {
            let name = match ctrl {
                CTRL_C_EVENT => "CTRL_C",
                CTRL_BREAK_EVENT => "CTRL_BREAK",
                _ => "other",
            };
            println!("{name}");
            io::stdout().flush().unwrap();
            // Linger briefly so a duplicate delivery would be observed.
            std::thread::sleep(Duration::from_millis(300));
            if RECEIVED.load(Ordering::SeqCst) != u32::MAX {
                println!("duplicate");
                io::stdout().flush().unwrap();
            }
            std::process::exit(100 + ctrl as i32);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Windows test drivers: processes, handles, console events, privileges.
#[cfg(windows)]
mod win {
    use std::ffi::{OsStr, OsString};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::ptr;
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{
        CloseHandle, FILETIME, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LUID,
        SetHandleInformation,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_REMOVED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, GenerateConsoleCtrlEvent, GetConsoleProcessList, GetConsoleWindow,
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CreateEventW, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, GetProcessTimes,
        INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess, OpenProcessToken,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    use super::fail;

    /// `(process, parent)` for every process.
    fn processes() -> Vec<(u32, u32)> {
        let mut found = Vec::new();
        // SAFETY: a process snapshot walked with correctly sized entries.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                fail("cannot list processes");
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut more = Process32FirstW(snapshot, &mut entry) != 0;
            while more {
                found.push((entry.th32ProcessID, entry.th32ParentProcessID));
                more = Process32NextW(snapshot, &mut entry) != 0;
            }
            CloseHandle(snapshot);
        }
        found
    }

    pub fn parent_id() -> Option<u32> {
        // SAFETY: cannot fail.
        let me = unsafe { GetCurrentProcessId() };
        processes().into_iter().find(|(pid, _)| *pid == me).map(|(_, parent)| parent)
    }

    /// When `process` was created (a FILETIME, as a number).
    fn creation_time(process: HANDLE) -> Option<u64> {
        // SAFETY: four FILETIMEs for GetProcessTimes to fill.
        unsafe {
            let mut times: [FILETIME; 4] = std::mem::zeroed();
            let [created, exited, kernel, user] = &mut times;
            (GetProcessTimes(process, created, exited, kernel, user) != 0)
                .then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
        }
    }

    /// When the process `pid` was created, if it can be opened.
    fn started(pid: u32) -> Option<u64> {
        // SAFETY: a query-only handle, closed below.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return None;
            }
            let time = creation_time(process);
            CloseHandle(process);
            time
        }
    }

    /// The processes this one created that are still running: those naming
    /// it as their parent that were created after it. (A parent ID can be
    /// stale: a process outlives its parent, whose ID is then reused.)
    pub fn children() -> Vec<u32> {
        // SAFETY: cannot fail.
        let (me, this) = unsafe { (GetCurrentProcessId(), GetCurrentProcess()) };
        let born = creation_time(this).unwrap_or_else(|| fail("cannot read this process's creation time"));
        processes()
            .into_iter()
            .filter(|&(pid, parent)| parent == me && started(pid).is_some_and(|time| time >= born))
            .map(|(pid, _)| pid)
            .collect()
    }

    /// The console this process is attached to: "window", "no window" (as
    /// with `CREATE_NO_WINDOW`) or "none" (detached), and the processes
    /// attached to it.
    pub fn console_state() -> (&'static str, Vec<u32>) {
        let mut attached = vec![0u32; 64];
        // SAFETY: the buffer's length is passed.
        let n = unsafe { GetConsoleProcessList(attached.as_mut_ptr(), attached.len() as u32) } as usize;
        if n == 0 {
            return ("none", Vec::new());
        }
        attached.truncate(n);
        // SAFETY: GetConsoleWindow has no preconditions.
        let kind = if unsafe { GetConsoleWindow() }.is_null() { "no window" } else { "window" };
        (kind, attached)
    }

    /// The values of this process's inheritable handles (handle values are
    /// multiples of 4; a process has far fewer than 16384 of them).
    pub fn inheritable_handles() -> Vec<usize> {
        (1..16384usize)
            .map(|n| n * 4)
            .filter(|&value| {
                let mut flags = 0u32;
                // SAFETY: querying a handle value that may not be open is
                // allowed: it fails.
                unsafe { GetHandleInformation(value as HANDLE, &mut flags) != 0 && flags & HANDLE_FLAG_INHERIT != 0 }
            })
            .collect()
    }

    /// The standard handles of this process that are valid, without repeats.
    fn standard_handles() -> Vec<usize> {
        let mut handles = Vec::new();
        for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            // SAFETY: querying this process's standard handles.
            let handle = unsafe { GetStdHandle(which) };
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE && !handles.contains(&(handle as usize)) {
                handles.push(handle as usize);
            }
        }
        handles
    }

    /// `inheritable` as "VALUES; std N": the values of the handles other than
    /// the standard ones (which inheritance keeps), and how many standard
    /// handles are among them (which a program receives through its startup
    /// information, whatever their values).
    pub fn handle_summary(inheritable: &[usize]) -> String {
        let standard = standard_handles();
        let mut other: Vec<usize> = inheritable.iter().copied().filter(|h| !standard.contains(h)).collect();
        other.sort_unstable();
        let shown: Vec<String> = other.iter().map(usize::to_string).collect();
        let std = standard.iter().filter(|h| inheritable.contains(h)).count();
        format!("{}; std {std}", shown.join(" "))
    }

    /// A command line in the quoting CreateProcess and CommandLineToArgvW
    /// agree on (the arguments of these tests have no quotes).
    fn command_line(program: &OsStr, args: &[OsString]) -> Vec<u16> {
        let mut line: Vec<u16> = Vec::new();
        for (i, part) in std::iter::once(program).chain(args.iter().map(OsString::as_os_str)).enumerate() {
            if i > 0 {
                line.push(u16::from(b' '));
            }
            line.push(u16::from(b'"'));
            line.extend(part.encode_wide());
            line.push(u16::from(b'"'));
        }
        line.push(0);
        line
    }

    /// Runs `program` inheriting exactly the standard handles and one event
    /// (a handle a caller passes on deliberately, like a jobserver's), and
    /// prints their values first. Returns its exit code.
    pub fn spawn_clean(program: &OsStr, args: &[OsString]) -> i32 {
        // SAFETY: standard handle, event and process-creation calls with
        // correctly initialized structures; the attribute list outlives the
        // CreateProcessW call.
        unsafe {
            let event = CreateEventW(ptr::null(), 1, 0, ptr::null());
            if event.is_null() {
                fail("cannot create an event");
            }
            let mut handles = vec![event];
            for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
                let handle = GetStdHandle(which);
                if !handle.is_null() && handle != INVALID_HANDLE_VALUE && !handles.contains(&handle) {
                    handles.push(handle);
                }
            }
            for &handle in &handles {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            }
            let values: Vec<usize> = handles.iter().map(|&h| h as usize).collect();
            println!("handles: {}", handle_summary(&values));
            std::io::stdout().flush().unwrap();

            let mut size = 0usize;
            InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size);
            let mut storage = vec![0u64; size.div_ceil(8)];
            let attributes: LPPROC_THREAD_ATTRIBUTE_LIST = storage.as_mut_ptr().cast();
            if InitializeProcThreadAttributeList(attributes, 1, 0, &mut size) == 0
                || UpdateProcThreadAttribute(
                    attributes,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    handles.len() * std::mem::size_of::<HANDLE>(),
                    ptr::null_mut(),
                    ptr::null(),
                ) == 0
            {
                fail("cannot set up the handle list");
            }
            let mut startup: STARTUPINFOEXW = std::mem::zeroed();
            startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            startup.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
            startup.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
            startup.lpAttributeList = attributes;
            let mut line = command_line(program, args);
            let mut info: PROCESS_INFORMATION = std::mem::zeroed();
            // Without a console, whose handles Windows would add.
            if CreateProcessW(
                ptr::null(),
                line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                ptr::null(),
                ptr::null(),
                &startup.StartupInfo,
                &mut info,
            ) == 0
            {
                fail(&format!("cannot start the program: {}", std::io::Error::last_os_error()));
            }
            DeleteProcThreadAttributeList(attributes);
            WaitForSingleObject(info.hProcess, INFINITE);
            let mut code = 0u32;
            GetExitCodeProcess(info.hProcess, &mut code);
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
            code as i32
        }
    }

    /// Whether this process can create a symbolic link.
    fn can_create_symlinks() -> bool {
        let dir = std::env::temp_dir().join(format!("bound-fixture-link-{}", std::process::id()));
        let made = std::os::windows::fs::symlink_file("target", &dir).is_ok();
        let _ = std::fs::remove_file(&dir);
        made
    }

    /// Runs `program` without the privilege to create symbolic links (as a
    /// standard user runs, unless Developer Mode is on), printing whether
    /// this process can still create them. Returns its exit code.
    pub fn without_symlinks(program: &OsStr, args: &[OsString]) -> i32 {
        let name: Vec<u16> = "SeCreateSymbolicLinkPrivilege".encode_utf16().chain([0]).collect();
        // SAFETY: token calls with valid out-pointers; removing a privilege
        // from our own token is permanent for this process and its children.
        unsafe {
            let mut token: HANDLE = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
                fail("cannot open the process token");
            }
            let mut luid = LUID { LowPart: 0, HighPart: 0 };
            if LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) == 0 {
                fail("cannot look up the privilege");
            }
            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_REMOVED }],
            };
            // Fails harmlessly (ERROR_NOT_ALL_ASSIGNED) without the privilege.
            AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut());
            CloseHandle(token);
        }
        println!("symlinks: {}", if can_create_symlinks() { "yes" } else { "no" });
        std::io::stdout().flush().unwrap();
        let status = Command::new(program).args(args).status().unwrap_or_else(|e| fail(&e.to_string()));
        status.code().unwrap_or(99)
    }

    unsafe extern "system" fn handled(_ctrl: u32) -> windows_sys::core::BOOL {
        1
    }

    /// Runs `program` (which prints "ready" before waiting for an event) in
    /// this process's console, which the test gave it, and sends console
    /// events: `break`, Ctrl+Break to its process group; `interrupt`,
    /// Ctrl+C to the whole console; `ignored`, Ctrl+C while this process
    /// ignores it (which its children inherit), then Ctrl+Break. Prints the
    /// program's output, then "exit CODE".
    pub fn console(mode: &str, program: &OsStr, args: &[OsString]) -> i32 {
        // SAFETY: registering handlers for this process's own events. What
        // this process ignores its children inherit: Ctrl+C ignored for
        // `ignored`, and otherwise processed normally, whatever this process
        // inherited (a process group's first process ignores Ctrl+C).
        unsafe {
            SetConsoleCtrlHandler(None, i32::from(mode == "ignored"));
            SetConsoleCtrlHandler(Some(handled), 1);
        }
        let flags = if mode == "break" { CREATE_NEW_PROCESS_GROUP } else { 0 };
        let mut child = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .creation_flags(flags)
            .spawn()
            .unwrap_or_else(|e| fail(&e.to_string()));
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        out.read_line(&mut line).unwrap_or_else(|e| fail(&e.to_string()));
        print!("{line}");
        // The program is waiting; give its launcher a moment to wait too.
        std::thread::sleep(Duration::from_millis(200));
        // SAFETY: sending console events to processes of this console.
        let sent = unsafe {
            match mode {
                "break" => GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id()),
                "interrupt" => GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0),
                "ignored" => {
                    let first = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
                    std::thread::sleep(Duration::from_millis(500));
                    first & GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0)
                }
                other => fail(&format!("unknown console mode {other}")),
            }
        };
        if sent == 0 {
            let _ = child.kill();
            fail(&format!("cannot send console events: {}", std::io::Error::last_os_error()));
        }
        // The rest of the output, and the exit, within a time limit.
        let reader = std::thread::spawn(move || {
            let mut rest = String::new();
            let _ = out.read_to_string(&mut rest);
            rest
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap_or_else(|e| fail(&e.to_string())) {
                break Some(status);
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        print!("{}", reader.join().unwrap_or_default());
        match status {
            Some(status) => println!("exit {}", status.code().unwrap_or(99)),
            None => println!("timeout: the program did not exit"),
        }
        0
    }
}
