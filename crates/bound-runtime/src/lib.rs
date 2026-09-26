//! The bound launcher runtime.
//!
//! This is the code inside every bound artifact. When an artifact runs, the
//! launcher:
//!
//! 1. opens its own executable and reads the footer and manifest
//!    (everything is validated before use);
//! 2. if the artifact has resources (or runs in the bundle directory),
//!    creates a fresh private directory, starts a reaper process that
//!    removes it once the program has exited, and materializes the
//!    resources into it, verifying every content hash while writing;
//! 3. builds the target's argv, environment and working directory
//!    ([`plan`]);
//! 4. starts the target with native process APIs, never through a shell:
//!    on Unix it always `exec`s, so the program keeps the artifact's PID
//!    and receives its signals directly; on Windows it runs the program as
//!    a child and exits with its exit code.
//!
//! A bare program name is looked up as the platform would look it up, but
//! never resolves to the artifact itself (or a copy of it): an artifact
//! named like the program it wraps runs the next program of that name.

#![forbid(unsafe_code)]

pub mod cache;
mod error;
mod materialize;
mod plan;

use std::convert::Infallible;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use bound_format::footer::read_footer;
use bound_format::{ArtifactReader, BundleMode, Digest, NameRules, Resource, Target};
use bound_platform::process;

pub use cache::Cache;
pub use error::LaunchError;
pub use materialize::{Root, materialize, shared_bundle};
pub use plan::{Invocation, plan};

/// Exit status when the launcher fails before the program starts.
pub const EXIT_LAUNCHER_FAILURE: i32 = 125;
/// Exit status when the program exists but could not be started.
pub const EXIT_CANNOT_EXECUTE: i32 = 126;
/// Exit status when the program could not be found.
pub const EXIT_NOT_FOUND: i32 = 127;

/// Entry point of the launcher executable.
pub fn main() -> ! {
    #[cfg(windows)]
    process::run_reaper_if_requested();
    match launch() {
        Ok(never) => match never {},
        Err(error) => {
            eprintln!("{}: bound: {error}", artifact_name());
            std::process::exit(error.exit_code())
        }
    }
}

/// Name used to prefix launcher error messages: the artifact's file name.
fn artifact_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| bound_format::osvalue::escape_control(&s.to_string_lossy())))
        .unwrap_or_else(|| "bound".to_owned())
}

fn launch() -> Result<Infallible, LaunchError> {
    bound_platform::privilege::check_not_setid().map_err(LaunchError::Refused)?;

    let (file, exe_path) = bound_platform::exe::open_current_exe().map_err(LaunchError::SelfRead)?;
    // Unbuffered: the reader does large reads of its own, and blobs are
    // located by seeking.
    let mut reader = ArtifactReader::open(file, NameRules::host())
        .map_err(|e| LaunchError::Artifact { path: exe_path, error: e })?;

    let runtime_args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if !runtime_args.is_empty() && !reader.manifest().accepts_runtime_args() {
        return Err(LaunchError::UnexpectedArguments);
    }

    let bundle = if reader.manifest().needs_root() {
        let manifest = reader.manifest();
        let wants_cache = manifest.bundle == BundleMode::Shared
            || manifest
                .resources
                .iter()
                .any(|r| matches!(r, Resource::File { size, .. } if *size >= cache::MIN_CACHED_CONTENT));
        let cache = if wants_cache { Cache::open() } else { None };
        let shared = match &cache {
            Some(cache) if reader.manifest().bundle == BundleMode::Shared => shared_bundle(&mut reader, cache)?,
            _ => None,
        };
        Some(match shared {
            Some(path) => Bundle::Shared(path),
            None => Bundle::Private(private_bundle(&mut reader, cache.as_ref())?),
        })
    } else {
        None
    };

    let this = reader.footer().manifest_sha256;
    let manifest = reader.into_manifest();
    let invocation = plan(&manifest, bundle.as_ref().map(Bundle::path), runtime_args, &|name| std::env::var_os(name))?;
    let embedded = matches!(manifest.target, Target::Embedded { .. });
    let is_this_artifact = |candidate: &Path| is_copy_of(candidate, &this);

    #[cfg(unix)]
    {
        let program = invocation.program.as_os_str();
        let error = if process::is_bare_name(program) {
            let path_var = invocation.child_path_var();
            process::exec_search(program, path_var.as_deref(), invocation.cwd.as_deref(), &is_this_artifact, &|path| {
                invocation.command_for(path)
            })
        } else {
            process::exec(&mut invocation.command())
        };
        // A private bundle is dropped on return, which removes it now.
        Err(LaunchError::spawn(program, error, embedded))
    }
    #[cfg(windows)]
    {
        let program = invocation.program.as_os_str();
        let mut command = if process::is_bare_name(program) {
            match process::find_program(program, invocation.path_override(), &is_this_artifact) {
                Some(found) => invocation.command_for(&process::plain_path(found)),
                None => return Err(LaunchError::spawn(program, std::io::ErrorKind::NotFound.into(), embedded)),
            }
        } else {
            invocation.command()
        };
        // The reaper of a private bundle is running by now (see
        // `private_bundle`).
        let status = process::run_supervised(&mut command).map_err(|e| LaunchError::spawn(program, e, embedded))?;
        if let Some(Bundle::Private(root)) = bundle {
            root.finish();
        }
        process::exit_like(status)
    }
}

/// The bundle directory of a run.
enum Bundle {
    /// New for this run, removed after it.
    Private(Root),
    /// Shared by every run, in the cache.
    Shared(PathBuf),
}

impl Bundle {
    fn path(&self) -> &Path {
        match self {
            Bundle::Private(root) => root.path(),
            Bundle::Shared(path) => path,
        }
    }
}

/// Creates and fills a private bundle directory. On Unix a reaper that
/// removes it however the program ends (even if the launcher dies while
/// extracting) is started first, so that no way the launcher ends leaves
/// the directory behind.
fn private_bundle<R: Read + Seek>(reader: &mut ArtifactReader<R>, cache: Option<&Cache>) -> Result<Root, LaunchError> {
    // Unix: the reaper is forked at once (the process must still be
    // single-threaded), and required, since nothing else can clean up after
    // exec. Windows: it is started on another thread, while the files are
    // extracted, and running before the program starts.
    #[cfg(unix)]
    let root = {
        let mut root = Root::create(&bound_platform::fs::temp_base())?;
        process::start_reaper(root.path()).map_err(LaunchError::Cleanup)?;
        root.set_reaped();
        root
    };
    #[cfg(windows)]
    let mut root = Root::create(&bound_platform::fs::temp_base())?;
    #[cfg(windows)]
    {
        root.start_reaper_in_background();
        process::prepare_supervision();
    }
    materialize(reader, root.path(), root.path(), cache)?;
    #[cfg(windows)]
    root.await_reaper();
    #[cfg(windows)]
    if let Some(interruption) = process::interrupted() {
        // Interrupted before the program started: report it as the program
        // would have.
        drop(root);
        process::exit_interrupted(interruption);
    }
    Ok(root)
}

/// Whether the file at `path` is a bound artifact with the manifest digest
/// `this`: the running artifact itself, a link to it, or a copy of it.
fn is_copy_of(path: &Path, this: &Digest) -> bool {
    File::open(path)
        .ok()
        .and_then(|mut file| read_footer(&mut file).ok())
        .is_some_and(|(footer, _)| footer.manifest_sha256 == *this)
}

/// Whether `program` would be looked up in `PATH` (for messages).
pub(crate) fn is_path_lookup(program: &std::ffi::OsStr) -> bool {
    process::is_bare_name(program) && !Path::new(program).is_absolute()
}
