//! Choosing, checking and writing the output file.
//!
//! The artifact is written to a temporary file in the destination
//! directory and moved into place only once it is complete, so a failed or
//! interrupted build never leaves a truncated executable behind. Without
//! `--force` the final step refuses to replace anything, even a file that
//! appeared while the build was running.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use bound_format::writer::LARGE_CONTENT;
use bound_format::{ArtifactWriter, Digest, EncodedBlob, Encoder, Manifest, Platform, Resource};
use bound_platform::fs::FileIdentity;

use super::Diagnostic;
use super::resources::{Entry, Inputs, ResourceSet};
use crate::error::{CliError, fail};
use crate::launcher::Launcher;

/// The checked destination of a build.
#[derive(Debug)]
pub(super) struct OutputPlan {
    /// Where the artifact will be written, as the user spelled it (plus
    /// `.exe` for Windows targets).
    pub path: PathBuf,
    /// The same location with the directory resolved.
    pub canonical: PathBuf,
    pub force: bool,
}

/// Whether `path` ends in `.exe` (in any case).
pub fn has_exe_extension(path: &Path) -> bool {
    path.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe"))
}

/// Applies the naming rule for the target: Windows executables need the
/// `.exe` extension, so it is appended when missing. Nothing is appended for
/// other targets.
pub fn output_name(requested: &Path, platform: &Platform) -> PathBuf {
    if platform.is_windows() && !has_exe_extension(requested) {
        let mut name = requested.as_os_str().to_owned();
        name.push(".exe");
        PathBuf::from(name)
    } else {
        requested.to_path_buf()
    }
}

fn ends_with_separator(path: &Path) -> bool {
    let last = path.as_os_str().as_encoded_bytes().last().copied();
    last == Some(b'/') || (cfg!(windows) && last == Some(b'\\'))
}

/// Folds case where the file system usually ignores it (Windows, macOS).
fn fold(path: &Path) -> PathBuf {
    if cfg!(any(windows, target_vendor = "apple")) {
        PathBuf::from(path.to_string_lossy().to_lowercase())
    } else {
        path.to_path_buf()
    }
}

pub(super) fn plan(
    requested: &Path,
    platform: &Platform,
    force: bool,
    inputs: &Inputs,
    launcher: &Path,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<OutputPlan, CliError> {
    if requested.as_os_str().is_empty() {
        return fail("output path is required");
    }
    if ends_with_separator(requested) {
        return fail(format!("output path {} must name a file, not a directory", requested.display()));
    }
    let path = output_name(requested, platform);
    if path != requested {
        diagnostics.push(Diagnostic::Note(format!(
            "writing {} (Windows executables need the .exe extension)",
            path.display()
        )));
    }
    let Some(file_name) = path.file_name() else {
        return fail(format!("output path {} must name a file", path.display()));
    };
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let canonical_parent = fs::canonicalize(&parent)
        .map_err(|_| CliError::new(format!("output directory {} does not exist", parent.display())))?;
    let canonical = canonical_parent.join(file_name);

    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_dir() => return fail(format!("output path {} is a directory", path.display())),
        Ok(_) if !force => {
            return Err(CliError::new(format!("output file {} already exists", path.display()))
                .with_hint("use --force to replace it"));
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return fail(format!("cannot access {}: {e}", path.display())),
    }

    let target = fold(&canonical);
    for dir in &inputs.dirs {
        if target.starts_with(fold(dir)) {
            return Err(CliError::new("output path would be included recursively").with_hint(format!(
                "{} is inside the included directory {}; write the output somewhere else",
                path.display(),
                dir.display()
            )));
        }
    }
    // When the output already exists, compare its real location too.
    let existing = fs::canonicalize(&path).ok().map(|p| fold(&p));
    let is_output = |candidate: &Path| {
        let candidate = fold(candidate);
        candidate == target || existing.as_ref() == Some(&candidate)
    };
    if let Some(file) = inputs.files.iter().find(|f| is_output(f)) {
        return fail(format!("output path {} is also an input ({})", path.display(), file.display()));
    }
    if fs::canonicalize(launcher).is_ok_and(|l| is_output(&l)) {
        return fail(format!("output path {} is the launcher itself", path.display()));
    }
    Ok(OutputPlan { path, canonical, force })
}

/// Removes the temporary file unless it has been moved into place.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Writes the artifact and moves it into place. Returns the final manifest
/// and the artifact size.
pub(super) fn write(
    plan: &OutputPlan,
    launcher: &Launcher,
    resources: &ResourceSet,
    mut manifest: Manifest,
) -> Result<(Manifest, u64), CliError> {
    let dir = plan.canonical.parent().unwrap_or(Path::new("."));
    let mut tmp_name = OsString::from(".");
    tmp_name.push(plan.canonical.file_name().unwrap_or_default());
    let suffix = bound_platform::random_hex(6).map_err(|e| CliError::new(e.to_string()))?;
    tmp_name.push(format!(".{suffix}.bound-tmp"));
    let tmp = TempFile(dir.join(tmp_name));

    let file = bound_platform::fs::create_output_file(&tmp.0)
        .map_err(|e| CliError::new(format!("cannot create a file in {}: {e}", dir.display())))?;
    let mut launcher_file = File::open(&launcher.path)
        .map_err(|e| CliError::new(format!("cannot read launcher {}: {e}", launcher.path.display())))?;
    let write_error = |e: &dyn std::fmt::Display| CliError::new(format!("cannot write {}: {e}", plan.path.display()));
    let mut writer = ArtifactWriter::new(file, &mut launcher_file).map_err(|e| write_error(&e))?;

    let mut list = Vec::new();
    let mut files = Vec::new();
    for (path, entry) in resources.entries() {
        list.push(match entry {
            Entry::Dir => Resource::Dir { path: path.clone() },
            Entry::File { source, executable, identity, follow, len, .. } => {
                files.push(FileJob { position: list.len(), source, identity, follow: *follow, len: *len });
                // Filled in once the content is stored.
                Resource::File { path: path.clone(), size: 0, sha256: Digest([0; 32]), executable: *executable }
            }
            Entry::Symlink { target, .. } => Resource::Symlink { path: path.clone(), target: target.clone() },
        });
    }
    store_files(&mut writer, &files, &mut list)?;
    manifest.resources = list;
    let (file, manifest) = writer.finish(manifest).map_err(|e| write_error(&e))?;
    bound_platform::fs::finish_output_file(&file).map_err(|e| write_error(&e))?;
    file.sync_all().map_err(|e| write_error(&e))?;
    let size = file.metadata().map_err(|e| write_error(&e))?.len();
    drop(file);

    install(&tmp.0, &plan.path, plan.force)?;
    Ok((manifest, size))
}

/// A file to store, and where its resource is in the manifest.
struct FileJob<'a> {
    position: usize,
    source: &'a Path,
    identity: &'a FileIdentity,
    follow: bool,
    len: u64,
}

/// Most bytes of files read into memory at once.
const BATCH_BYTES: u64 = 32 * 1024 * 1024;
/// Most files in one batch.
const BATCH_FILES: usize = 1024;

/// Stores the contents of `files`, filling in their resources in `list`.
///
/// Files are read, hashed and compressed on several threads, in batches of
/// consecutive files, and the results are written in manifest order, so
/// the artifact is the same whatever the number of threads. Files too
/// large to hold in memory are streamed on this thread, where zstd
/// compresses them with threads of its own.
fn store_files<W>(writer: &mut ArtifactWriter<W>, files: &[FileJob<'_>], list: &mut [Resource]) -> Result<(), CliError>
where
    W: io::Read + io::Write + io::Seek + bound_format::Truncate,
{
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get().min(8));
    let mut record = |job: &FileJob<'_>, blob: bound_format::BlobRef| {
        if let Resource::File { size, sha256, .. } = &mut list[job.position] {
            *size = blob.size;
            *sha256 = blob.sha256;
        }
    };
    let mut next = 0;
    while next < files.len() {
        let job = &files[next];
        if job.len >= LARGE_CONTENT {
            let mut content = open(job)?;
            let blob = writer.add_blob(&mut content).map_err(|e| cannot_bundle(job.source, e))?;
            record(job, blob);
            next += 1;
            continue;
        }
        let mut end = next;
        let mut bytes = 0;
        while end < files.len()
            && files[end].len < LARGE_CONTENT
            && end - next < BATCH_FILES
            && (end == next || bytes + files[end].len <= BATCH_BYTES)
        {
            bytes += files[end].len;
            end += 1;
        }
        let batch = &files[next..end];
        for (job, encoded) in batch.iter().zip(encode_batch(batch, threads)) {
            let blob = writer.add_encoded(encoded?).map_err(|e| cannot_bundle(job.source, e))?;
            record(job, blob);
        }
        next = end;
    }
    Ok(())
}

/// Reads and encodes a batch of small files on up to `threads` threads.
/// Results are in the order of `batch`.
fn encode_batch(batch: &[FileJob<'_>], threads: usize) -> Vec<Result<EncodedBlob, CliError>> {
    let slots: Vec<OnceLock<Result<EncodedBlob, CliError>>> = batch.iter().map(|_| OnceLock::new()).collect();
    let next = AtomicUsize::new(0);
    let work = || {
        let mut encoder = match Encoder::new() {
            Ok(encoder) => encoder,
            Err(e) => {
                let _ = slots[0].set(Err(CliError::new(format!("cannot start compression: {e}"))));
                return;
            }
        };
        loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            let Some(job) = batch.get(i) else { return };
            let _ = slots[i].set(encode_file(job, &mut encoder));
        }
    };
    let workers = threads.min(batch.len());
    if workers <= 1 {
        work();
    } else {
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(work);
            }
        });
    }
    slots
        .into_iter()
        .map(|slot| slot.into_inner().unwrap_or_else(|| Err(CliError::new("internal error: a file was skipped"))))
        .collect()
}

fn encode_file(job: &FileJob<'_>, encoder: &mut Encoder) -> Result<EncodedBlob, CliError> {
    let mut content = Vec::with_capacity(usize::try_from(job.len).unwrap_or(0));
    // One byte more than the limit reveals a file that grew meanwhile.
    open(job)?.take(LARGE_CONTENT).read_to_end(&mut content).map_err(|e| cannot_read(job.source, e))?;
    if content.len() as u64 >= LARGE_CONTENT {
        return Err(cannot_read(job.source, "the file changed while it was being bundled"));
    }
    encoder.encode(content).map_err(|e| cannot_bundle(job.source, e))
}

fn open(job: &FileJob<'_>) -> Result<File, CliError> {
    bound_platform::fs::open_input(job.source, job.follow, Some(job.identity)).map_err(|e| cannot_read(job.source, e))
}

fn cannot_read(path: &Path, error: impl std::fmt::Display) -> CliError {
    CliError::new(format!("cannot read {}: {error}", path.display()))
}

fn cannot_bundle(path: &Path, error: impl std::fmt::Display) -> CliError {
    CliError::new(format!("cannot bundle {}: {error}", path.display()))
}

/// Moves the finished file into place. Without `force`, an existing file
/// is never replaced: a hard link, or where the file system has none, a
/// rename that refuses to replace, fails instead.
fn install(tmp: &Path, dest: &Path, force: bool) -> Result<(), CliError> {
    let exists = || {
        CliError::new(format!("output file {} already exists", dest.display())).with_hint("use --force to replace it")
    };
    let result = if force {
        fs::rename(tmp, dest)
    } else {
        match fs::hard_link(tmp, dest) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(exists()),
            Err(_) => bound_platform::fs::rename_no_replace(tmp, dest),
        }
    };
    result.map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            return exists();
        }
        let busy = cfg!(windows) && (e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(32));
        let error = CliError::new(format!("cannot replace {}: {e}", dest.display()));
        if busy {
            error.with_hint("the file may be in use; if the program is running, close it and try again")
        } else {
            error
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform(os: &str) -> Platform {
        Platform { os: os.into(), arch: "x86_64".into(), binary_format: "x".into() }
    }

    #[test]
    fn exe_suffix_only_for_windows_targets() {
        assert_eq!(output_name(Path::new("tool"), &platform("windows")), Path::new("tool.exe"));
        assert_eq!(output_name(Path::new("tool.EXE"), &platform("windows")), Path::new("tool.EXE"));
        assert_eq!(output_name(Path::new("tool.v2"), &platform("windows")), Path::new("tool.v2.exe"));
        assert_eq!(output_name(Path::new("tool"), &platform("linux")), Path::new("tool"));
        assert_eq!(output_name(Path::new("tool"), &platform("macos")), Path::new("tool"));
    }

    #[test]
    fn refuses_existing_outputs_and_recursive_inclusion() {
        let dir = tempfile::tempdir().unwrap();
        // Names carry the host's executable suffix, which bound would add.
        let exe = |name: &str| dir.path().join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
        let existing = exe("out");
        fs::write(&existing, "x").unwrap();
        let host = Platform::host();
        let launcher = dir.path().join("launcher");
        let mut diags = Vec::new();
        let none = Inputs::default();

        let err = plan(&existing, &host, false, &none, &launcher, &mut diags).unwrap_err();
        assert!(err.message.contains("already exists"));
        assert!(plan(&existing, &host, true, &none, &launcher, &mut diags).is_ok());

        let inputs = Inputs { dirs: vec![fs::canonicalize(dir.path()).unwrap()], files: vec![] };
        let err = plan(&exe("new"), &host, false, &inputs, &launcher, &mut diags).unwrap_err();
        assert_eq!(err.message, "output path would be included recursively");

        let inputs = Inputs { dirs: vec![], files: vec![fs::canonicalize(&existing).unwrap()] };
        let err = plan(&existing, &host, true, &inputs, &launcher, &mut diags).unwrap_err();
        assert!(err.message.contains("is also an input"));

        let err = plan(&dir.path().join("missing-dir/out"), &host, false, &none, &launcher, &mut diags).unwrap_err();
        assert!(err.message.contains("does not exist"));
        let subdir = exe("subdir");
        fs::create_dir(&subdir).unwrap();
        let err = plan(&subdir, &host, true, &none, &launcher, &mut diags).unwrap_err();
        assert!(err.message.contains("is a directory"));
    }

    #[test]
    fn install_never_clobbers_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("tmp");
        let dest = dir.path().join("dest");
        fs::write(&tmp, "new").unwrap();
        fs::write(&dest, "old").unwrap();
        assert!(install(&tmp, &dest, false).is_err());
        assert_eq!(fs::read(&dest).unwrap(), b"old");
        install(&tmp, &dest, true).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"new");
    }
}
