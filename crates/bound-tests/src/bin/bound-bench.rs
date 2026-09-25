//! Benchmarks for bound: build time, launch overhead, extraction and
//! verification throughput, and peak memory, on any platform.
//!
//! ```text
//! cargo build --release -p bound -p bound-tests
//! target/release/bound-bench [--quick | --startup]
//! ```
//!
//! The tool uses the `bound`, `bound-launcher` and `bound-fixture`
//! executables next to itself. Times are wall-clock medians over several
//! runs; memory is the peak resident set (Unix `ru_maxrss`, Windows peak
//! working set) of the measured process itself: `bound` for builds, the
//! launcher for runs (on Unix the launcher becomes the program, and the
//! figure covers both; macOS reports the program's alone). "run" is what
//! the caller waits for; "cleaned" is the time until the bundle directory
//! has also been removed, which the reaper does after the program exits.
//! Runs use a cache of their own: "first run" is one run with an empty
//! cache (for a shared bundle, the run that extracts and seals it), and the
//! other runs find the cache filled, as they would on a user's machine.
//!
//! `--quick` makes the large cases smaller. `--startup` runs only the
//! start-up cases (the program started directly, and as artifacts with
//! nothing or one small file bundled), without first writing the inputs of
//! the large cases: on Windows, antivirus scanning of those keeps the
//! machine busy for a while, and process creation times vary widely under
//! load.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Measurement {
    median: Duration,
    p90: Duration,
    peak_rss: u64,
}

/// Runs `cmd` once, returning its wall time and peak memory.
fn run_once(cmd: &mut Command) -> (Duration, u64) {
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit());
    let start = Instant::now();
    let child = cmd.spawn().unwrap_or_else(|e| panic!("cannot run {cmd:?}: {e}"));
    let (ok, rss) = wait_with_peak(child);
    let elapsed = start.elapsed();
    assert!(ok, "{cmd:?} failed");
    (elapsed, rss)
}

#[cfg(unix)]
fn wait_with_peak(child: std::process::Child) -> (bool, u64) {
    let pid = child.id() as libc::pid_t;
    let mut status = 0;
    // SAFETY: waiting for our own child and reading its resource usage.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        loop {
            let rc = libc::wait4(pid, &mut status, 0, &mut usage);
            if rc == pid {
                break;
            }
            assert!(std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted, "wait4 failed");
        }
        usage
    };
    // Linux reports kilobytes, macOS bytes.
    let rss = if cfg!(target_vendor = "apple") { usage.ru_maxrss as u64 } else { usage.ru_maxrss as u64 * 1024 };
    let ok = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    // Already reaped by wait4; dropping `Child` neither waits nor kills.
    drop(child);
    (ok, rss)
}

#[cfg(windows)]
fn wait_with_peak(mut child: std::process::Child) -> (bool, u64) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    let status = child.wait().unwrap();
    // SAFETY: querying an exited process whose handle we still own.
    let peak = unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(child.as_raw_handle(), &mut counters, counters.cb) != 0 {
            counters.PeakWorkingSetSize as u64
        } else {
            0
        }
    };
    (status.success(), peak)
}

fn measure(runs: usize, mut make: impl FnMut() -> Command) -> Measurement {
    let mut times = Vec::with_capacity(runs);
    let mut peak = 0;
    // One untimed warm-up run fills the page cache.
    run_once(&mut make());
    for _ in 0..runs {
        let (time, rss) = run_once(&mut make());
        times.push(time);
        peak = peak.max(rss);
    }
    times.sort();
    Measurement { median: times[times.len() / 2], p90: times[(times.len() * 9) / 10], peak_rss: peak }
}

/// Like [`measure`] for artifact runs, which use `tmp` as their temporary
/// directory: also measures the time until the run's bundle directory has
/// been removed (by the reaper, after the program exits), and waits for
/// that before the next run so that runs do not overlap.
fn measure_run(runs: usize, tmp: &std::path::Path, mut make: impl FnMut() -> Command) -> (Measurement, Duration) {
    let settle = || {
        let deadline = Instant::now() + Duration::from_secs(60);
        while fs::read_dir(tmp).unwrap().next().is_some() {
            assert!(Instant::now() < deadline, "bundle directories were not removed");
            std::thread::sleep(Duration::from_micros(200));
        }
    };
    let mut times = Vec::with_capacity(runs);
    let mut cleaned = Vec::with_capacity(runs);
    let mut peak = 0;
    settle();
    run_once(&mut make());
    for _ in 0..runs {
        settle();
        let start = Instant::now();
        let (time, rss) = run_once(&mut make());
        settle();
        times.push(time);
        cleaned.push(start.elapsed());
        peak = peak.max(rss);
    }
    times.sort();
    cleaned.sort();
    let measurement =
        Measurement { median: times[times.len() / 2], p90: times[(times.len() * 9) / 10], peak_rss: peak };
    (measurement, cleaned[cleaned.len() / 2])
}

fn fmt_time(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms < 10.0 {
        format!("{ms:.2} ms")
    } else if ms < 1000.0 {
        format!("{ms:.1} ms")
    } else {
        format!("{:.2} s", ms / 1000.0)
    }
}

fn fmt_mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

struct Workload {
    name: &'static str,
    /// Arguments to `bound` before `--`.
    options: Vec<OsString>,
    /// Fixture mode and arguments after the program.
    program_args: Vec<OsString>,
    runs: usize,
}

/// Deterministic pseudo-random bytes (incompressible).
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Text-like, compressible bytes.
fn text(len: usize) -> Vec<u8> {
    let line = b"2026-09-25T12:00:00Z INFO request handled path=/api/v1/items status=200 duration_ms=12\n";
    line.iter().copied().cycle().take(len).collect()
}

/// Writes a large file one megabyte at a time, keeping this process small:
/// on Linux a child's peak RSS includes its parent's RSS at spawn time.
fn write_large(path: &std::path::Path, len: usize, chunk: impl Fn(usize) -> Vec<u8>) {
    use std::io::Write;
    let mut file = std::io::BufWriter::new(fs::File::create(path).unwrap());
    let mut written = 0;
    let mut index = 0;
    while written < len {
        let piece = chunk(index);
        let n = piece.len().min(len - written);
        file.write_all(&piece[..n]).unwrap();
        written += n;
        index += 1;
    }
    file.flush().unwrap();
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let startup = std::env::args().any(|a| a == "--startup");
    let exe_dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let exe = |name: &str| exe_dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    let bound = exe("bound");
    let fixture = exe("bound-fixture");
    for needed in [&bound, &exe("bound-launcher"), &fixture] {
        assert!(needed.is_file(), "missing {}; run `cargo build --release -p bound -p bound-tests`", needed.display());
    }

    let work = tempfile::Builder::new().prefix("bound-bench-").tempdir().unwrap();
    let dir = work.path().to_path_buf();
    let big = if quick { 16 << 20 } else { 100 << 20 };
    let many = if quick { 2_000 } else { 10_000 };
    let fast = if quick { 10 } else { 30 };

    // Inputs.
    fs::write(dir.join("small.txt"), text(4096)).unwrap();
    if !startup {
        for (name, count, size) in [("files1k", 1_000usize, 4096usize), ("filesmany", many, 1024)] {
            let d = dir.join(name);
            fs::create_dir_all(&d).unwrap();
            for i in 0..count {
                let sub = d.join(format!("d{}", i % 32));
                fs::create_dir_all(&sub).unwrap();
                fs::write(sub.join(format!("f{i}.txt")), noise(size, i as u64 + 1)).unwrap();
            }
        }
        write_large(&dir.join("big-noise.bin"), big, |i| noise(1 << 20, 7 + i as u64));
        write_large(&dir.join("big-text.log"), big, |_| text(1 << 20));
    }

    let os = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
    let workloads = [
        Workload { name: "no resources", options: vec![], program_args: os(&["exit", "0"]), runs: fast },
        Workload {
            name: "1 file (4 KiB)",
            options: os(&["--include", "small.txt"]),
            program_args: os(&["exit", "0"]),
            runs: fast,
        },
        Workload {
            name: "1,000 files (4 MiB)",
            options: os(&["--include", "files1k"]),
            program_args: os(&["exit", "0"]),
            runs: 10,
        },
        Workload {
            name: if quick { "2,000 files (2 MiB)" } else { "10,000 files (10 MiB)" },
            options: os(&["--include", "filesmany"]),
            program_args: os(&["exit", "0"]),
            runs: 5,
        },
        Workload {
            name: if quick { "2,000 files, shared" } else { "10,000 files, shared" },
            options: os(&["--bundle", "shared", "--include", "filesmany"]),
            program_args: os(&["exit", "0"]),
            runs: 10,
        },
        Workload {
            name: if quick { "16 MiB incompressible" } else { "100 MiB incompressible" },
            options: os(&["--include", "big-noise.bin"]),
            program_args: os(&["exit", "0"]),
            runs: 5,
        },
        Workload {
            name: if quick { "16 MiB text" } else { "100 MiB text" },
            options: os(&["--include", "big-text.log"]),
            program_args: os(&["exit", "0"]),
            runs: 5,
        },
    ];
    // The start-up cases come first.
    let workloads = if startup { &workloads[..2] } else { &workloads[..] };

    println!(
        "bound benchmark: {} {} ({} runs per fast case{}{})\n",
        std::env::consts::OS,
        std::env::consts::ARCH,
        fast,
        if quick { ", quick" } else { "" },
        if startup { ", start-up only" } else { "" }
    );

    // Baseline: the program started directly.
    let direct = measure(fast, || {
        let mut c = Command::new(&fixture);
        c.args(["exit", "0"]);
        c
    });
    println!(
        "Direct start of the target program: {} (p90 {}), peak {}\n",
        fmt_time(direct.median),
        fmt_time(direct.p90),
        fmt_mib(direct.peak_rss)
    );

    // Artifacts extract into a private temporary directory, so that the
    // removal of each run's bundle directory can be observed.
    let tmp = dir.join("tmp");
    fs::create_dir(&tmp).unwrap();
    let cache = dir.join("cache");
    let with_tmp = |mut c: Command| {
        for var in ["TMPDIR", "TMP", "TEMP"] {
            c.env(var, &tmp);
        }
        c.env("BOUND_CACHE_DIR", &cache);
        c
    };

    println!(
        "| workload | artifact | build | build peak | first run | run | run p90 | overhead | cleaned | launcher peak |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    let mut caches = vec![cache.clone()];
    let mut artifacts: Vec<(&str, PathBuf)> = Vec::new();
    for (i, w) in workloads.iter().enumerate() {
        let output = dir.join(format!("artifact{i}{}", std::env::consts::EXE_SUFFIX));
        let build = measure(if w.runs > 5 { 5 } else { 3 }, || {
            let mut c = Command::new(&bound);
            c.current_dir(&dir).arg("-q").arg("--force").arg("-o").arg(&output);
            c.args(&w.options).arg("--").arg(&fixture).args(&w.program_args);
            c
        });
        let size = fs::metadata(&output).unwrap().len();
        let empty_cache = dir.join(format!("cache-first-{i}"));
        let (first, _) = run_once(with_tmp(Command::new(&output)).env("BOUND_CACHE_DIR", &empty_cache));
        caches.push(empty_cache);
        let (run, cleaned) = measure_run(w.runs, &tmp, || with_tmp(Command::new(&output)));
        let overhead = run.median.saturating_sub(direct.median);
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | +{} | {} | {} |",
            w.name,
            fmt_mib(size),
            fmt_time(build.median),
            fmt_mib(build.peak_rss),
            fmt_time(first),
            fmt_time(run.median),
            fmt_time(run.p90),
            fmt_time(overhead),
            fmt_time(cleaned),
            fmt_mib(run.peak_rss)
        );
        artifacts.push((w.name, output));
    }

    if !startup {
        println!("\n| workload | inspect | inspect peak | verify | verify peak |");
        println!("|---|---:|---:|---:|---:|");
    }
    for (name, artifact) in artifacts.iter().skip(2) {
        let inspect = measure(3, || {
            let mut c = Command::new(&bound);
            c.arg("inspect").arg(artifact);
            c
        });
        let verify = measure(3, || {
            let mut c = Command::new(&bound);
            c.arg("verify").arg(artifact);
            c
        });
        println!(
            "| {name} | {} | {} | {} | {} |",
            fmt_time(inspect.median),
            fmt_mib(inspect.peak_rss),
            fmt_time(verify.median),
            fmt_mib(verify.peak_rss)
        );
    }

    // Shared bundles are read-only; `bound cache clean` removes them.
    for cache in caches {
        let _ =
            Command::new(&bound).args(["cache", "clean"]).env("BOUND_CACHE_DIR", cache).stdout(Stdio::null()).status();
    }
}
