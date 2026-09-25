//! How the program runs as the artifact: its place among processes, what it
//! inherits, how its exit, interruption and termination come back, and the
//! cleanup of its bundle directory.
//!
//! Every test runs on every platform and checks that platform's form of the
//! behavior: `exec`, signals and a terminal on Unix; a supervising launcher,
//! a job object and console events on Windows.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bound_tests::{Harness, Report, assert_removed, bins, os, run, spawn, stdout, wait_timeout};

fn harness() -> Harness {
    Harness::new(bins!())
}

/// An artifact running the fixture in `mode`, with a bundled resource (so
/// there is a bundle directory to clean up) or without.
fn artifact(h: &Harness, name: &str, with_resources: bool, mode: &[&str]) -> PathBuf {
    let mut args = Vec::new();
    if with_resources {
        h.write("resource.txt", "r");
        args.extend(os!["--include", "resource.txt"]);
    }
    args.extend(os!["--", h.bins.fixture]);
    args.extend(mode.iter().map(OsString::from));
    h.bind(name, args)
}

/// Whether the tests run under user-mode emulation (an amd64 container on
/// Apple silicon, for example).
#[cfg(unix)]
fn emulated() -> bool {
    !emulator_dirs().is_empty()
}

/// Where the files of a user-mode emulator are, if the tests run under one:
/// it keeps descriptors of its own in every process, and appears as the
/// executable of other processes in /proc.
#[cfg(unix)]
fn emulator_dirs() -> Vec<String> {
    let mut dirs = Vec::new();
    if !cfg!(target_os = "linux") {
        return dirs;
    }
    if std::fs::read_to_string("/proc/self/maps").is_ok_and(|maps| maps.contains("/rosetta")) {
        dirs.push("/run/rosetta".to_owned());
    }
    let by_pid = std::fs::read_link(format!("/proc/{}/exe", std::process::id())).ok();
    if let Some(emulator) = by_pid.filter(|exe| std::fs::read_link("/proc/self/exe").ok().as_ref() != Some(exe)) {
        dirs.extend(emulator.parent().map(|dir| dir.to_string_lossy().into_owned()));
    }
    dirs
}

/// Starts the `hold` fixture and returns it with its PID and bundle root.
fn start_holding(h: &Harness, artifact: &Path) -> (Child, u32, PathBuf) {
    let mut child = spawn(h.command(artifact).stdout(Stdio::piped()));
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let (pid, root) = line.trim().split_once(' ').unwrap();
    (child, pid.parse().unwrap(), PathBuf::from(root))
}

/// Windows: runs `artifact` (a `wait-signal` fixture) through the fixture's
/// console driver, in a console of its own (the tests may have none), which
/// sends it console events as `mode` says. Returns the driver's report:
/// the program's output, then "exit CODE".
#[cfg(windows)]
fn through_a_console(h: &Harness, mode: &str, artifact: &Path) -> String {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    let mut cmd = Command::new(&h.bins.fixture);
    cmd.args(os!["console", mode, artifact])
        .current_dir(h.dir())
        .env("BOUND_CACHE_DIR", h.cache_dir())
        .stdin(Stdio::null())
        .creation_flags(CREATE_NEW_CONSOLE);
    let out = run(&mut cmd);
    assert!(out.status.success(), "console driver: {}", bound_tests::describe(&out));
    stdout(&out).replace("\r\n", "\n")
}

/// The ways a caller can start a program as far as its console (Windows:
/// the test's own, a new one with a window, a new one without, or none) or
/// its terminal (Unix: the test's own, or none, in a new session) goes.
const CALLERS: &[&str] = if cfg!(windows) {
    &["the test's console", "a new console", "a console without a window", "no console"]
} else {
    &["the test's terminal", "no terminal"]
};

/// Makes `cmd` start its program the way `caller` (one of `CALLERS`) does.
fn started_by<'a>(cmd: &'a mut Command, caller: &str) -> &'a mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        match caller {
            "a new console" => cmd.creation_flags(CREATE_NEW_CONSOLE),
            "a console without a window" => cmd.creation_flags(CREATE_NO_WINDOW),
            "no console" => cmd.creation_flags(DETACHED_PROCESS),
            _ => cmd,
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        match caller {
            // SAFETY: setsid is async-signal-safe.
            "no terminal" => unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                })
            },
            _ => cmd,
        }
    }
}

#[test]
fn the_program_runs_as_the_artifact() {
    let h = harness();
    for with_resources in [false, true] {
        let artifact = artifact(&h, &format!("self-{with_resources}"), with_resources, &["report"]);
        let child = spawn(h.command(&artifact).stdout(Stdio::piped()));
        let pid = child.id();
        let report = Report::parse(&child.wait_with_output().unwrap());
        #[cfg(unix)]
        {
            // exec: the program replaces the launcher, keeping its PID,
            // parent, process group and session.
            // SAFETY: these calls cannot fail.
            let (me, group, session) = unsafe { (libc::getpid(), libc::getpgrp(), libc::getsid(0)) };
            assert_eq!(report.pid(), pid, "with_resources={with_resources}: the program must have the artifact's PID");
            assert_eq!(report.number("ppid"), i64::from(me), "with_resources={with_resources}: parent");
            assert_eq!(report.number("pgid"), i64::from(group), "with_resources={with_resources}: process group");
            assert_eq!(report.number("sid"), i64::from(session), "with_resources={with_resources}: session");
        }
        #[cfg(windows)]
        {
            // Windows has no exec: the launcher supervises the program, its
            // only child, and exits with its status.
            assert_ne!(report.pid(), pid, "with_resources={with_resources}");
            assert_eq!(
                report.number("ppid"),
                i64::from(pid),
                "with_resources={with_resources}: the launcher is its parent"
            );
        }
    }
}

#[test]
fn the_program_has_no_children_it_did_not_create() {
    // Neither the reaper nor, on Windows, a console of the program's own
    // (whose host process would be its child), however the caller starts it.
    let h = harness();
    for with_resources in [false, true] {
        let artifact = artifact(&h, &format!("children-{with_resources}"), with_resources, &["children"]);
        for caller in CALLERS {
            let out = run(started_by(&mut h.command(&artifact), caller));
            assert_eq!(stdout(&out).trim(), "none", "{caller}, with_resources={with_resources}");
        }
    }
}

#[test]
fn the_program_has_the_callers_console() {
    // Windows: the program has the console the caller gave the artifact
    // (with a window, without one, or none at all), shared with the
    // launcher rather than one of its own. Unix: the program keeps the
    // caller's controlling terminal, or has none in a new session.
    let h = harness();
    for with_resources in [false, true] {
        let artifact = artifact(&h, &format!("console-{with_resources}"), with_resources, &["report"]);
        for caller in CALLERS {
            let context = format!("{caller}, with_resources={with_resources}");
            let direct = Report::parse(&run(started_by(Command::new(&h.bins.fixture).arg("report"), caller)));
            let bound = Report::parse(&run(started_by(&mut h.command(&artifact), caller)));
            assert_eq!(bound.text("console"), direct.text("console"), "{context}");
            #[cfg(windows)]
            if bound.text("console") != "none" {
                let attached = bound.numbers("console_processes");
                assert!(
                    attached.contains(&bound.number("ppid")),
                    "{context}: the program must share the launcher's console, not have one of its own: {attached:?}"
                );
            }
        }
    }
}

#[test]
fn the_program_has_exactly_the_callers_descriptors() {
    // A caller with only the standard descriptors or handles, plus one it
    // passes on deliberately (like a jobserver's), starts the program
    // directly and through the artifact: the program must see the same.
    let h = harness();
    #[cfg(unix)]
    let listing = |program: &Path, args: Vec<OsString>| {
        use std::os::unix::process::CommandExt;
        let mut cmd = h.command(program);
        cmd.args(args);
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                for fd in 3..256 {
                    libc::close(fd);
                }
                if libc::dup2(1, 7) != 7 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        stdout(&run(&mut cmd))
    };
    #[cfg(windows)]
    let listing = |program: &Path, args: Vec<OsString>| {
        let mut cmd = Command::new(&h.bins.fixture);
        cmd.arg("spawn-clean").arg(program).args(args).current_dir(h.dir()).env("BOUND_CACHE_DIR", h.cache_dir());
        let text = stdout(&run(cmd.stdin(Stdio::null())));
        let mut lines = text.lines();
        // Handles inherited keep their values; standard handles arrive through
        // the startup information, as copies.
        let passed = lines.next().unwrap().strip_prefix("handles: ").unwrap().to_owned();
        let seen = lines.next().unwrap_or_default().to_owned();
        assert_eq!(seen, passed, "the program's inheritable handles differ from those its caller passed");
        // Each caller's handle values are its own: between runs, compare how
        // many there are.
        let (other, std) = seen.split_once("; ").unwrap();
        format!("{} other; {std}\n", other.split_whitespace().count())
    };
    let direct = listing(&h.bins.fixture, os!["fds"]);
    // Natively, exactly these; an emulator (an amd64 container on Apple
    // silicon) adds descriptors of its own to every process, so there the
    // direct run is the reference.
    #[cfg(unix)]
    if !emulated() {
        assert_eq!(direct, "0 1 2 7\n");
    }
    for with_resources in [false, true] {
        let artifact = artifact(&h, &format!("fds-{with_resources}"), with_resources, &["fds"]);
        assert_eq!(listing(&artifact, os![]), direct, "with_resources={with_resources}");
    }
}

#[test]
fn abnormal_exits_are_propagated() {
    // Killed by a signal (Unix), or ended with an NTSTATUS such as a crash
    // leaves (Windows): the caller sees exactly that.
    let h = harness();
    for with_resources in [false, true] {
        let artifact = artifact(&h, &format!("kill-{with_resources}"), with_resources, &["kill-self"]);
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            for sig in [libc::SIGTERM, libc::SIGKILL, libc::SIGSEGV, libc::SIGABRT] {
                let out = h.run(&artifact, os![sig.to_string()]);
                assert_eq!(out.status.signal(), Some(sig), "with_resources={with_resources}: {:?}", out.status);
            }
        }
        #[cfg(windows)]
        for status in [0xC000_0005u32, 0xC000_0409, 0xC000_013A] {
            let out = h.run(&artifact, os![format!("0x{status:x}")]);
            assert_eq!(out.status.code(), Some(status as i32), "with_resources={with_resources}: {:?}", out.status);
        }
    }
}

#[test]
fn the_bundle_is_removed_when_the_artifact_is_killed() {
    let h = harness();
    let artifact = artifact(&h, "hold", true, &["hold"]);
    let (mut child, pid, root) = start_holding(&h, &artifact);
    assert!(root.join("resource.txt").exists());
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        // SIGKILL: nothing in the launcher can react; the reaper does.
        assert_eq!(pid, child.id());
        child.kill().unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject};
        assert_ne!(pid, child.id(), "on Windows the program is a child of the launcher");
        // SAFETY: opening a process by ID for waiting; closed below.
        let program = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        assert!(!program.is_null(), "the program is not running");
        // TerminateProcess on the launcher, as Task Manager or a supervisor
        // would: the program goes with it (a kill-on-close job).
        child.kill().unwrap();
        child.wait().unwrap();
        // SAFETY: waiting on the handle opened above, then closing it.
        let waited = unsafe {
            let waited = WaitForSingleObject(program, 10_000);
            CloseHandle(program);
            waited
        };
        assert_eq!(waited, WAIT_OBJECT_0, "the program outlived the launcher");
    }
    assert_removed(&root);
}

#[test]
fn output_readers_see_end_of_file_when_the_program_exits() {
    let h = harness();
    let artifact = artifact(&h, "eof", true, &["echo", "done"]);
    for _ in 0..5 {
        let mut child = spawn(h.command(&artifact).stdout(Stdio::piped()));
        let mut output = String::new();
        let start = Instant::now();
        // Would block until the reaper exits if it held the pipe.
        child.stdout.take().unwrap().read_to_string(&mut output).unwrap();
        assert_eq!(output.replace("\r\n", "\n"), "done\n");
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(child.wait().unwrap().success());
    }
}

#[test]
fn the_reaper_is_detached_from_the_caller() {
    let h = harness();
    let artifact = artifact(&h, "reaper", true, &["hold"]);
    let (mut child, program, root) = start_holding(&h, &artifact);
    let reaper = reaper::find(&artifact, program, child.id());
    reaper::check_detached(reaper, program, child.id());
    child.kill().unwrap();
    child.wait().unwrap();
    assert_removed(&root);
}

/// Finding the reaper process of an artifact, and checking what it is
/// attached to, the way each platform exposes processes.
mod reaper {
    use std::path::Path;
    use std::time::{Duration, Instant};

    /// Waits for the process that runs the artifact's image and is neither
    /// the launcher nor the program: the reaper.
    pub fn find(artifact: &Path, program: u32, launcher: u32) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let found: Vec<u32> =
                candidates(artifact).into_iter().filter(|&pid| pid != program && pid != launcher).collect();
            match found.as_slice() {
                [reaper] => return *reaper,
                [] if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                other => panic!("expected one reaper process for {}, found {other:?}", artifact.display()),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn candidates(artifact: &Path) -> Vec<u32> {
        // The reaper names itself; its executable is the artifact (under an
        // emulator, the emulator: then its command line names the artifact).
        let artifact_bytes = artifact.as_os_str().as_encoded_bytes().to_vec();
        std::fs::read_dir("/proc")
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| {
                std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|c| c.trim() == "bound-reaper")
                    && (std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|exe| exe == artifact)
                        || std::fs::read(format!("/proc/{pid}/cmdline"))
                            .is_ok_and(|line| line.split(|&b| b == 0).any(|arg| arg == artifact_bytes.as_slice())))
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    pub fn check_detached(reaper: u32, program: u32, _launcher: u32) {
        let stat = std::fs::read_to_string(format!("/proc/{reaper}/stat")).unwrap();
        let fields: Vec<&str> = stat[stat.rfind(')').unwrap() + 2..].split(' ').collect();
        let (ppid, session): (u32, i32) = (fields[1].parse().unwrap(), fields[3].parse().unwrap());
        assert_ne!(ppid, program, "the reaper must not be the program's child");
        // SAFETY: getsid cannot fail for the calling process.
        assert_ne!(session, unsafe { libc::getsid(0) }, "the reaper must have its own session");
        // Only /dev/null and the watch on the program (and, under an
        // emulator, the emulator's own files).
        let emulator = super::emulator_dirs();
        let fds: Vec<String> = std::fs::read_dir(format!("/proc/{reaper}/fd"))
            .unwrap()
            .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
            .map(|target| target.to_string_lossy().into_owned())
            .collect();
        for target in &fds {
            let emulated = emulator.iter().any(|dir| target.starts_with(dir.as_str()));
            assert!(
                target == "/dev/null" || target.contains("pidfd") || emulated,
                "the reaper holds {target}: {fds:?}"
            );
        }
        assert_eq!(std::fs::read_link(format!("/proc/{reaper}/cwd")).unwrap(), Path::new("/"));
    }

    #[cfg(target_vendor = "apple")]
    fn path_of(pid: i32) -> Option<std::path::PathBuf> {
        use std::os::unix::ffi::OsStrExt;
        let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: the buffer has the size given.
        let n = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        (n > 0).then(|| std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&buffer[..n as usize])))
    }

    #[cfg(target_vendor = "apple")]
    fn candidates(artifact: &Path) -> Vec<u32> {
        let artifact = std::fs::canonicalize(artifact).unwrap();
        let mut pids = vec![0i32; 8192];
        // SAFETY: the buffer has the size given, in bytes.
        let n = unsafe {
            libc::proc_listallpids(pids.as_mut_ptr().cast(), (pids.len() * std::mem::size_of::<i32>()) as i32)
        };
        pids.truncate(n.max(0) as usize);
        pids.into_iter()
            .filter(|&pid| pid > 0 && path_of(pid).is_some_and(|path| path == artifact))
            .map(|pid| pid as u32)
            .collect()
    }

    /// `struct proc_fileinfo` and `struct vnode_fdinfowithpath` of
    /// <sys/proc_info.h>, which libc does not declare.
    #[cfg(target_vendor = "apple")]
    #[repr(C)]
    struct VnodeFdInfoWithPath {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: i64,
        fi_type: i32,
        fi_guardflags: u32,
        pvip: libc::vnode_info_path,
    }

    #[cfg(target_vendor = "apple")]
    const PROC_PIDFDVNODEPATHINFO: libc::c_int = 2;

    #[cfg(target_vendor = "apple")]
    pub fn check_detached(reaper: u32, program: u32, _launcher: u32) {
        let pid = reaper as i32;
        // SAFETY: proc_pidinfo fills at most the size given.
        let (bsd, vnodes) = unsafe {
            let mut bsd: libc::proc_bsdinfo = std::mem::zeroed();
            let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
            assert_eq!(libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut bsd).cast(), size), size);
            let mut vnodes: libc::proc_vnodepathinfo = std::mem::zeroed();
            let size = std::mem::size_of::<libc::proc_vnodepathinfo>() as i32;
            assert_eq!(libc::proc_pidinfo(pid, libc::PROC_PIDVNODEPATHINFO, 0, (&raw mut vnodes).cast(), size), size);
            (bsd, vnodes)
        };
        assert_ne!(bsd.pbi_ppid, program, "the reaper must not be the program's child");
        // SAFETY: getsid only reads.
        let (theirs, ours) = unsafe { (libc::getsid(pid), libc::getsid(0)) };
        assert_ne!(theirs, ours, "the reaper must have its own session");
        // SAFETY: vip_path is a NUL-terminated C string.
        let cwd = unsafe { std::ffi::CStr::from_ptr(vnodes.pvi_cdir.vip_path.as_ptr().cast()) };
        assert_eq!(cwd.to_bytes(), b"/", "the reaper leaves the caller's working directory");

        // Its descriptors: /dev/null and the kqueue watching the program.
        let mut fds = vec![unsafe { std::mem::zeroed::<libc::proc_fdinfo>() }; 256];
        let size = (fds.len() * std::mem::size_of::<libc::proc_fdinfo>()) as i32;
        // SAFETY: the buffer has the size given.
        let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), size) };
        fds.truncate(n.max(0) as usize / std::mem::size_of::<libc::proc_fdinfo>());
        assert!(!fds.is_empty());
        for fd in fds {
            match fd.proc_fdtype as libc::c_int {
                libc::PROX_FDTYPE_KQUEUE => {}
                libc::PROX_FDTYPE_VNODE => {
                    // SAFETY: proc_pidfdinfo fills at most the size given.
                    let path = unsafe {
                        let mut info: VnodeFdInfoWithPath = std::mem::zeroed();
                        let size = std::mem::size_of::<VnodeFdInfoWithPath>() as i32;
                        let got = libc::proc_pidfdinfo(
                            pid,
                            fd.proc_fd,
                            PROC_PIDFDVNODEPATHINFO,
                            (&raw mut info).cast(),
                            size,
                        );
                        assert_eq!(got, size, "descriptor {}", fd.proc_fd);
                        std::ffi::CStr::from_ptr(info.pvip.vip_path.as_ptr().cast()).to_string_lossy().into_owned()
                    };
                    assert_eq!(path, "/dev/null", "the reaper holds descriptor {}", fd.proc_fd);
                }
                other => panic!("the reaper holds descriptor {} of type {other}", fd.proc_fd),
            }
        }
    }

    #[cfg(windows)]
    use bound_tests::processes;

    #[cfg(windows)]
    fn candidates(artifact: &Path) -> Vec<u32> {
        let name = artifact.file_name().unwrap().to_string_lossy().to_lowercase();
        processes().into_iter().filter(|(_, _, exe)| exe.to_lowercase() == name).map(|(pid, _, _)| pid).collect()
    }

    #[cfg(windows)]
    pub fn check_detached(reaper: u32, program: u32, launcher: u32) {
        // A detached process (no console, a process group of its own, no
        // handles) that the launcher started beside the program, not under
        // it, and outside the kill-on-close job that holds the program.
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        let parent = processes().into_iter().find(|(pid, _, _)| *pid == reaper).map(|(_, parent, _)| parent);
        assert_eq!(parent, Some(launcher), "the launcher starts the reaper");
        assert_ne!(parent, Some(program), "the reaper must not be the program's child");
        // SAFETY: opening two processes for queries; closed below.
        unsafe {
            let (reaper, program) = (
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, reaper),
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, program),
            );
            assert!(!reaper.is_null() && !program.is_null());
            let (mut reaper_in_job, mut program_in_job) = (0, 0);
            assert_ne!(IsProcessInJob(program, std::ptr::null_mut(), &mut program_in_job), 0);
            assert_ne!(IsProcessInJob(reaper, std::ptr::null_mut(), &mut reaper_in_job), 0);
            assert_ne!(program_in_job, 0, "the program runs in the launcher's job");
            // The reaper breaks away from the jobs it may leave: then it is
            // in none; otherwise (a job that forbids it) it stays where the
            // caller put the launcher, but never in the launcher's own.
            if reaper_in_job != 0 {
                let mut in_caller_job = 0;
                let launcher = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, launcher);
                IsProcessInJob(launcher, std::ptr::null_mut(), &mut in_caller_job);
                CloseHandle(launcher);
                assert_ne!(in_caller_job, 0, "the reaper is in a job its launcher is not in");
            }
            CloseHandle(reaper);
            CloseHandle(program);
        }
    }
}

#[test]
fn closed_pipes_end_programs_as_usual() {
    // A program writing to a reader that went away ends as it would
    // without bound: by SIGPIPE, unless its caller ignored the signal
    // (Unix), or through the error the write returns (Windows).
    let h = harness();
    let ending = |program: &Path, args: Vec<OsString>| {
        let mut cmd = h.command(program);
        cmd.args(args).stdout(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // SAFETY: signal() is async-signal-safe.
            unsafe {
                cmd.pre_exec(|| {
                    libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                    Ok(())
                });
            }
        }
        let mut child = spawn(&mut cmd);
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), "y");
        drop(out);
        wait_timeout(&mut child, Duration::from_secs(10))
    };
    // The fixture, a Rust program, ignores SIGPIPE: its write fails, and it
    // exits with 3.
    let direct = ending(&h.bins.fixture, os!["flood"]);
    assert_eq!(direct.code(), Some(3), "{direct:?}");
    for with_resources in [false, true] {
        let artifact = artifact(&h, &format!("flood-{with_resources}"), with_resources, &["flood"]);
        let through = ending(&artifact, os![]);
        assert_eq!(format!("{through:?}"), format!("{direct:?}"), "with_resources={with_resources}");
    }

    #[cfg(unix)]
    {
        // The disposition itself comes through: default, even though the
        // launcher is a Rust program (which ignores SIGPIPE), or ignored if
        // the caller ignored it.
        use std::os::unix::process::CommandExt;
        for with_resources in [false, true] {
            let artifact = artifact(&h, &format!("pipe-{with_resources}"), with_resources, &["disposition", "13"]);
            for (disposition, expected) in [(libc::SIG_DFL, "default"), (libc::SIG_IGN, "ignored")] {
                let mut cmd = h.command(&artifact);
                // SAFETY: signal() is async-signal-safe.
                unsafe {
                    cmd.pre_exec(move || {
                        libc::signal(libc::SIGPIPE, disposition);
                        Ok(())
                    });
                }
                assert_eq!(stdout(&run(&mut cmd)).trim(), expected, "with_resources={with_resources}");
            }
        }
        // And a C program, yes(1), ends by the signal through bound too.
        use std::os::unix::process::ExitStatusExt;
        let yes = ["/usr/bin/yes", "/bin/yes"].into_iter().find(|p| Path::new(p).exists()).expect("yes(1)");
        let direct = ending(Path::new(yes), os!["y"]);
        assert_eq!(direct.signal(), Some(libc::SIGPIPE), "{direct:?}");
        h.write("resource.txt", "r");
        for resources in [os![], os!["--include", "resource.txt"]] {
            let mut args = resources.clone();
            args.extend(os!["--", yes, "y"]);
            let artifact = h.bind(&format!("yes-{}", resources.len()), args);
            assert_eq!(ending(&artifact, os![]).signal(), Some(libc::SIGPIPE));
        }
    }
}

/// Starts `wait-signal` in its own process group (as a supervisor would,
/// and so that the terminal running the tests, if any, cannot reach it),
/// waits until it is ready, and returns the child and a reader for the rest
/// of its output.
#[cfg(unix)]
fn start_waiting(h: &Harness, artifact: &Path) -> (Child, BufReader<std::process::ChildStdout>) {
    use std::os::unix::process::CommandExt;
    let mut child = spawn(h.command(artifact).stdout(Stdio::piped()).process_group(0));
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n");
    (child, out)
}

#[test]
fn termination_requests_reach_the_program_once() {
    // Signals sent to the artifact (Unix), Ctrl+Break sent to its process
    // group (Windows): the program gets each exactly once, and its status
    // comes back.
    let h = harness();
    for with_resources in [false, true] {
        let artifact = artifact(&h, &format!("sig-{with_resources}"), with_resources, &["wait-signal"]);
        #[cfg(unix)]
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGUSR1, libc::SIGQUIT] {
            let (mut child, mut out) = start_waiting(&h, &artifact);
            // SAFETY: sending a signal to our own child.
            unsafe { libc::kill(child.id() as libc::pid_t, sig) };
            let status = wait_timeout(&mut child, Duration::from_secs(10));
            let mut rest = String::new();
            out.read_to_string(&mut rest).unwrap();
            assert!(!rest.contains("duplicate"), "signal {sig} delivered twice: {rest}");
            assert_eq!(status.code(), Some(100 + sig), "with_resources={with_resources}, signal {sig}: {rest}");
        }
        #[cfg(windows)]
        {
            let report = through_a_console(&h, "break", &artifact);
            assert_eq!(report, "ready\nCTRL_BREAK\nexit 101\n", "with_resources={with_resources}");
        }
    }
}

/// A pseudo-terminal pair.
#[cfg(unix)]
struct Pty {
    master: std::os::fd::OwnedFd,
    slave: std::os::fd::OwnedFd,
}

#[cfg(unix)]
fn open_pty() -> Pty {
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: standard pseudo-terminal allocation; every returned descriptor
    // is checked and owned.
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");
        // Keep the terminal out of processes other tests start meanwhile.
        libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC);
        assert_eq!(libc::grantpt(master), 0);
        assert_eq!(libc::unlockpt(master), 0);
        let name = libc::ptsname(master);
        assert!(!name.is_null());
        let slave = libc::open(name, libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        assert!(slave >= 0, "cannot open the pty slave");
        Pty { master: OwnedFd::from_raw_fd(master), slave: OwnedFd::from_raw_fd(slave) }
    }
}

#[test]
fn keyboard_interrupts_reach_the_program_exactly_once() {
    // ^C typed at a terminal (Unix) or Ctrl+C in a console (Windows) reaches
    // the program once: neither lost nor delivered again by the launcher.
    let h = harness();
    for with_resources in [false, true] {
        let artifact = artifact(&h, &format!("tty-{with_resources}"), with_resources, &["wait-signal"]);
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::process::CommandExt;
            use std::sync::{Arc, Mutex};
            let pty = open_pty();
            let mut cmd = Command::new(&artifact);
            cmd.current_dir(h.dir())
                .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
                .stdout(Stdio::from(pty.slave.try_clone().unwrap()))
                .stderr(Stdio::from(pty.slave.try_clone().unwrap()));
            // SAFETY: only async-signal-safe calls between fork and exec.
            unsafe {
                cmd.pre_exec(|| {
                    // New session with the pty as controlling terminal, so
                    // the launcher's group is the terminal's foreground group.
                    if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = spawn(&mut cmd);
            drop(cmd);
            drop(pty.slave);

            let output = Arc::new(Mutex::new(Vec::new()));
            let mut master = std::fs::File::from(pty.master);
            let mut reader = master.try_clone().unwrap();
            let sink = Arc::clone(&output);
            let pump = std::thread::spawn(move || {
                let mut buf = [0u8; 256];
                while let Ok(n) = reader.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    sink.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            });
            let seen = |needle: &str| String::from_utf8_lossy(&output.lock().unwrap()).contains(needle);
            let start = Instant::now();
            while !seen("ready") {
                assert!(start.elapsed() < Duration::from_secs(10), "program never became ready");
                std::thread::sleep(Duration::from_millis(10));
            }
            // ^C through the line discipline: SIGINT to the foreground group.
            master.write_all(&[0x03]).unwrap();
            let status = wait_timeout(&mut child, Duration::from_secs(10));
            drop(master);
            let _ = pump.join();
            let text = String::from_utf8_lossy(&output.lock().unwrap()).into_owned();
            assert!(text.contains("SIGINT"), "with_resources={with_resources}: {text:?}");
            assert!(!text.contains("duplicate"), "with_resources={with_resources}: delivered twice: {text:?}");
            assert_eq!(status.code(), Some(100 + libc::SIGINT), "with_resources={with_resources}: {status:?} {text:?}");
        }
        #[cfg(windows)]
        {
            let report = through_a_console(&h, "interrupt", &artifact);
            assert_eq!(report, "ready\nCTRL_C\nexit 100\n", "with_resources={with_resources}");
        }
    }
}

#[test]
fn ignored_interrupts_stay_ignored() {
    // A caller that ignores interrupts (SIGINT ignored on Unix, Ctrl+C
    // ignored on Windows) passes that on to the program, as it would
    // without bound.
    let h = harness();
    for with_resources in [false, true] {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let artifact = artifact(&h, &format!("ign-{with_resources}"), with_resources, &["disposition", "2"]);
            let mut cmd = h.command(&artifact);
            // SAFETY: signal() is async-signal-safe.
            unsafe {
                cmd.pre_exec(|| {
                    libc::signal(libc::SIGINT, libc::SIG_IGN);
                    Ok(())
                });
            }
            assert_eq!(stdout(&run(&mut cmd)).trim(), "ignored", "with_resources={with_resources}");
            assert_eq!(stdout(&h.run(&artifact, os![])).trim(), "default", "with_resources={with_resources}");
        }
        #[cfg(windows)]
        {
            // The Ctrl+C goes unnoticed; the Ctrl+Break that follows does not.
            let artifact = artifact(&h, &format!("ign-{with_resources}"), with_resources, &["wait-signal"]);
            let report = through_a_console(&h, "ignored", &artifact);
            assert_eq!(report, "ready\nCTRL_BREAK\nexit 101\n", "with_resources={with_resources}");
        }
    }
}

#[test]
fn replacing_a_running_artifact() {
    // Rebuilding an artifact that is running: Unix replaces the file, and
    // the running process keeps its own copy; Windows cannot replace a
    // running executable, and bound says so.
    let h = harness();
    let artifact = h.bind("busy", os!["--", h.bins.fixture, "hold"]);
    let mut child = spawn(h.command(&artifact).stdout(Stdio::piped()));
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let out = h.bound_output(os!["-o", "busy", "--force", "--", h.bins.fixture, "report", "new"]);
    let still_running = child.try_wait().unwrap().is_none();
    let _ = child.kill();
    let _ = child.wait();
    assert!(still_running, "the running artifact was disturbed");
    if cfg!(windows) {
        assert!(!out.status.success(), "replacing a running executable should fail");
        let err = bound_tests::stderr(&out);
        assert!(err.contains("cannot replace") && err.contains("in use"), "{err}");
    } else {
        bound_tests::assert_success(&out, "bound");
        assert_eq!(h.report(&artifact, os![]).args(), ["new"]);
    }
}
