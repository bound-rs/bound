//! Materializing bundled resources on disk.
//!
//! Every run gets a fresh private directory, so runs never share or corrupt
//! each other's files and a program that modifies its resources only
//! modifies its own copy. Creation order guarantees nothing is ever written
//! through a link: directories and files are created first (each with an
//! exclusive create that refuses existing entries), and links last. (On
//! Windows, a link is a symbolic link where the user may create them, and
//! otherwise a junction to its directory or a hard link to its file.)

use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

use bound_format::{ArtifactReader, Resource};
use bound_platform::fs::{self as pfs, LinkDestination};

use crate::LaunchError;
use crate::cache::{Cache, MIN_CACHED_CONTENT};

const COPY_BUFFER: usize = 256 * 1024;

/// A bundle root: a new private directory for one run.
///
/// Dropping it removes the directory, which is what happens when the launch
/// fails. Once the program runs, the directory belongs to the reaper, if
/// one was started ([`Root::set_reaped`], [`Root::start_reaper_in_background`]);
/// otherwise [`Root::finish`] removes it.
#[derive(Debug)]
pub struct Root {
    path: PathBuf,
    removed: bool,
    reaper: Reaper,
}

#[derive(Debug)]
enum Reaper {
    None,
    Started,
    /// Being started on another thread.
    Pending(std::thread::JoinHandle<io::Result<()>>),
}

impl Root {
    /// Creates a new private directory under `parent`.
    pub fn create(parent: &Path) -> Result<Root, LaunchError> {
        let path = pfs::create_private_dir(parent, "bound-")
            .map_err(|e| failed("cannot create a private directory in", parent, e))?;
        Ok(Root { path, removed: false, reaper: Reaper::None })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Records that a reaper will remove the directory after the program.
    pub fn set_reaped(&mut self) {
        self.reaper = Reaper::Started;
    }

    /// Starts a reaper on another thread, so that starting a process (slow
    /// on Windows) overlaps the extraction instead of delaying it.
    pub fn start_reaper_in_background(&mut self) {
        let dir = self.path.clone();
        let spawned = std::thread::Builder::new().spawn(move || bound_platform::process::start_reaper(&dir));
        if let Ok(thread) = spawned {
            self.reaper = Reaper::Pending(thread);
        }
    }

    /// Waits until the reaper started by [`Root::start_reaper_in_background`]
    /// is running, so that from then on the directory is removed however the
    /// launcher ends. If it could not be started, the launcher removes the
    /// directory itself after the program ([`Root::finish`]).
    pub fn await_reaper(&mut self) {
        if let Reaper::Pending(thread) = std::mem::replace(&mut self.reaper, Reaper::None) {
            if thread.join().is_ok_and(|started| started.is_ok()) {
                self.reaper = Reaper::Started;
            }
        }
    }

    /// Called after the program exited: removes the directory unless a
    /// reaper does. A reaper still being started is not waited for: the
    /// directory is removed now, and the reaper will find nothing to do.
    /// Best effort: a directory still in use (by a background process the
    /// program started) is left behind rather than turning a successful run
    /// into a failure.
    pub fn finish(mut self) {
        self.removed = true;
        let reaped = match std::mem::replace(&mut self.reaper, Reaper::None) {
            Reaper::None => false,
            Reaper::Started => true,
            Reaper::Pending(thread) => thread.is_finished() && thread.join().is_ok_and(|started| started.is_ok()),
        };
        if !reaped {
            let _ = pfs::remove_tree(&self.path);
        }
    }

    /// Removes the directory tree now, reporting failure.
    pub fn remove(mut self) -> io::Result<()> {
        self.removed = true;
        pfs::remove_tree(&self.path)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        if !self.removed {
            let _ = pfs::remove_tree(&self.path);
        }
    }
}

fn failed(what: &str, path: &Path, error: impl std::fmt::Display) -> LaunchError {
    // Paths include resource names from the manifest.
    let path = bound_format::osvalue::escape_control(&path.display().to_string());
    LaunchError::Materialize(format!("{what} {path}: {error}"))
}

fn corrupted(resource: &Resource, error: &io::Error) -> LaunchError {
    LaunchError::Materialize(format!(
        "resource \"{}\" is corrupted: {error} (run `bound verify` for details)",
        resource.path()
    ))
}

/// Extracts all resources of `reader` into the new directory `root`,
/// verifying every content hash while writing. `used_at` is where the
/// bundle will be used: `root`, or where a shared bundle is moved.
///
/// With a `cache`, contents of at least [`MIN_CACHED_CONTENT`] bytes are
/// taken from it (cloned where the file system allows it, copied
/// otherwise), after being stored in it by the first run that needs them.
pub fn materialize<R: Read + Seek>(
    reader: &mut ArtifactReader<R>,
    root: &Path,
    used_at: &Path,
    cache: Option<&Cache>,
) -> Result<(), LaunchError> {
    let (manifest, mut blobs) = reader.split();
    let resources = &manifest.resources;
    let mut buffer = vec![0u8; COPY_BUFFER];

    for resource in resources {
        let target = root.join(resource.path().to_native()?);
        match resource {
            Resource::Dir { .. } => {
                pfs::create_dir(&target).map_err(|e| failed("cannot create directory", &target, e))?;
            }
            Resource::File { sha256, executable, size, .. } => {
                if let Some(cache) = cache.filter(|_| *size >= MIN_CACHED_CONTENT) {
                    let cached = match cache.blob(sha256, *size) {
                        Some(file) => Some(file),
                        None => match cache
                            .store_blob(sha256, *size, |out| copy(&mut blobs.open(sha256)?, out, &mut buffer))
                        {
                            Ok(file) => Some(file),
                            Err(e) if e.kind() == io::ErrorKind::InvalidData => return Err(corrupted(resource, &e)),
                            // The cache is only an optimization.
                            Err(_) => None,
                        },
                    };
                    if let Some(cached) = cached {
                        pfs::clone_file(&cached, &target, *executable)
                            .map_err(|e| failed("cannot create file", &target, e))?;
                        continue;
                    }
                }
                let mut out =
                    pfs::create_new_file(&target, *executable).map_err(|e| failed("cannot create file", &target, e))?;
                let mut content =
                    blobs.open(sha256).map_err(|e| failed("cannot read bundled content for", &target, e))?;
                copy(&mut content, &mut out, &mut buffer).map_err(|e| {
                    if e.kind() == io::ErrorKind::InvalidData {
                        corrupted(resource, &e)
                    } else {
                        failed("cannot write", &target, e)
                    }
                })?;
            }
            Resource::Symlink { .. } => {}
        }
    }

    if resources.iter().any(|r| matches!(r, Resource::Symlink { .. })) {
        let links = bound_format::resolve_links(resources).map_err(|e| LaunchError::Materialize(e.to_string()))?;
        for resolved in links {
            let Resource::Symlink { path, target } = &resources[resolved.index] else { continue };
            let link = root.join(path.to_native()?);
            let destination = resolved.target.to_native()?;
            let (now, then) = (root.join(&destination), used_at.join(&destination));
            let destination = LinkDestination { now: &now, then: &then, is_dir: resolved.is_dir };
            pfs::create_link(&target.to_native()?, &link, destination)
                .map_err(|e| failed("cannot create link", &link, e))?;
        }
    }
    Ok(())
}

/// The shared bundle of the artifact read by `reader`: taken from the
/// cache, or materialized and sealed there by this run. `None` if the cache
/// cannot hold it (the caller then materializes a private bundle).
pub fn shared_bundle<R: Read + Seek>(
    reader: &mut ArtifactReader<R>,
    cache: &Cache,
) -> Result<Option<PathBuf>, LaunchError> {
    let digest = reader.footer().manifest_sha256;
    if let Some(path) = cache.tree(&digest) {
        return Ok(Some(path));
    }
    let Ok(staging) = cache.staging_dir() else { return Ok(None) };
    let guard = Root { path: staging.clone(), removed: false, reaper: Reaper::None };
    materialize(reader, &staging, &cache.tree_path(&digest), Some(cache))?;
    match cache.install_tree(&staging, reader.manifest(), &digest) {
        Ok(path) => {
            let mut guard = guard;
            guard.removed = true;
            Ok(Some(path))
        }
        Err(_) => Ok(None),
    }
}

/// Copies to EOF (which is when the content is verified).
fn copy(src: &mut impl Read, dst: &mut impl Write, buffer: &mut [u8]) -> io::Result<()> {
    loop {
        let n = match src.read(buffer) {
            Ok(0) => return dst.flush(),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        dst.write_all(&buffer[..n])?;
    }
}
