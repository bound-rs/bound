//! Managing the cache of bundled files (`bound cache`).
//!
//! Artifacts keep large bundled contents, and shared bundles, in a
//! per-user cache (see `bound_runtime::cache`). These commands show where
//! it is and what it holds, and remove entries.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use bound_runtime::cache::{Cache, CacheEntry, EntryKind};

use crate::cli::CacheCommand;
use crate::error::CliError;
use crate::style::size;

pub fn run(command: CacheCommand) -> Result<ExitCode, CliError> {
    let dir = bound_platform::fs::cache_dir();
    match command {
        CacheCommand::Dir => match dir {
            Some(dir) => println!("{}", dir.display()),
            None => println!("(the cache is turned off: BOUND_CACHE is set, or there is no home directory)"),
        },
        CacheCommand::List => match existing(dir.as_deref())? {
            Some(cache) => print!("{}", render(&cache, &entries(&cache)?)),
            None => println!("The cache is empty."),
        },
        CacheCommand::Clean { unused } => {
            let Some(cache) = existing(dir.as_deref())? else {
                println!("The cache is empty.");
                return Ok(ExitCode::SUCCESS);
            };
            let cutoff = unused.map(|days| SystemTime::now() - Duration::from_secs(u64::from(days) * 86_400));
            let (mut removed, mut bytes) = (0usize, 0u64);
            for entry in entries(&cache)? {
                let stale = match cutoff {
                    None => true,
                    Some(cutoff) => entry.last_used.is_none_or(|used| used < cutoff),
                };
                if stale {
                    cache
                        .remove(&entry)
                        .map_err(|e| CliError::new(format!("cannot remove {}: {e}", entry.path.display())))?;
                    removed += 1;
                    bytes += entry.bytes;
                }
            }
            println!("Removed {removed} cache entr{} ({}).", if removed == 1 { "y" } else { "ies" }, size(bytes));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Opens the cache if it exists, without creating it.
fn existing(dir: Option<&Path>) -> Result<Option<Cache>, CliError> {
    let Some(dir) = dir else { return Ok(None) };
    if !dir.join("v1").is_dir() {
        return Ok(None);
    }
    Cache::open_at(dir).map(Some).map_err(|e| CliError::new(format!("cannot use the cache in {}: {e}", dir.display())))
}

fn entries(cache: &Cache) -> Result<Vec<CacheEntry>, CliError> {
    cache.entries().map_err(|e| CliError::new(format!("cannot read the cache in {}: {e}", cache.root().display())))
}

fn ago(time: Option<SystemTime>) -> String {
    let Some(elapsed) = time.and_then(|t| SystemTime::now().duration_since(t).ok()) else {
        return "unknown".into();
    };
    let secs = elapsed.as_secs();
    match secs {
        0..120 => "just now".into(),
        120..7_200 => format!("{} minutes ago", secs / 60),
        7_200..172_800 => format!("{} hours ago", secs / 3_600),
        _ => format!("{} days ago", secs / 86_400),
    }
}

fn render(cache: &Cache, entries: &[CacheEntry]) -> String {
    let mut out = format!("Cache: {}\n", cache.root().display());
    let total: u64 = entries.iter().map(|e| e.bytes).sum();
    let of = |kind: EntryKind| entries.iter().filter(move |e| e.kind == kind);
    let sum = |kind: EntryKind| of(kind).map(|e| e.bytes).sum::<u64>();

    out.push_str(&format!("Shared bundles: {} ({})\n", of(EntryKind::Tree).count(), size(sum(EntryKind::Tree))));
    for tree in of(EntryKind::Tree) {
        let name = tree.path.file_name().map(PathBuf::from).unwrap_or_default();
        out.push_str(&format!("  {}  {:>10}  last used {}\n", name.display(), size(tree.bytes), ago(tree.last_used)));
    }
    out.push_str(&format!("Large contents: {} ({})\n", of(EntryKind::Blob).count(), size(sum(EntryKind::Blob))));
    let staging = of(EntryKind::Staging).count();
    if staging > 0 {
        out.push_str(&format!(
            "Incomplete entries (interrupted runs): {staging} ({})\n",
            size(sum(EntryKind::Staging))
        ));
    }
    out.push_str(&format!("Total: {}\n", size(total)));
    out
}
