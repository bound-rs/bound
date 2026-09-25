//! The per-user cache: decoded large contents, and shared bundle
//! directories.
//!
//! ```text
//! <cache directory>/v1/
//!     blobs/<2 hex digits>/<content sha256>   decoded contents, read-only
//!     trees/<manifest sha256>/                shared bundles, read-only
//!     trees/<manifest sha256>.used            last use of a shared bundle
//!     trees/.staging-<random>/                a shared bundle being written
//!     tmp/                                    contents being written
//! ```
//!
//! Every entry is written under a staging name, verified (contents are
//! hashed while they are decoded from the artifact, as always), flushed to
//! disk, made read-only and only then renamed into place, so an entry that
//! exists is complete. (Bundles are staged next to their final place:
//! moving a read-only directory to another parent is not allowed.) The
//! cache directory is private to the user and checked like the temporary
//! directory (see `bound_platform::fs::ensure_private_dir`). The cache is
//! an optimization only: when it is turned off or cannot be used, the
//! launcher reads everything from the artifact itself.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bound_format::{Digest, Manifest, Resource};
use bound_platform::fs as pfs;

/// Contents at least this large are kept in the cache when a private
/// bundle is materialized; later runs clone or copy them from there.
pub const MIN_CACHED_CONTENT: u64 = 1024 * 1024;

/// Version of the cache layout.
const LAYOUT: &str = "v1";

/// An opened cache.
#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    /// Opens the user's cache, creating it if needed. `None` if caching is
    /// turned off or the cache directory cannot be used safely.
    pub fn open() -> Option<Cache> {
        Cache::open_at(&pfs::cache_dir()?).ok()
    }

    /// Opens the cache in `dir`, creating it if needed.
    pub fn open_at(dir: &Path) -> io::Result<Cache> {
        let dir = pfs::ensure_private_dir(dir)?;
        let root = dir.join(LAYOUT);
        for sub in ["", "blobs", "trees", "tmp"] {
            match fs::create_dir(root.join(sub)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Ok(Cache { root })
    }

    /// The directory holding this version of the cache.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn blob_path(&self, sha256: &Digest) -> PathBuf {
        let hex = sha256.to_string();
        self.root.join("blobs").join(&hex[..2]).join(hex)
    }

    /// Opens the cached content with this hash and size, if there is one.
    pub fn blob(&self, sha256: &Digest, size: u64) -> Option<File> {
        let path = self.blob_path(sha256);
        let file = pfs::open_input(&path, false, None).ok()?;
        if file.metadata().ok()?.len() != size {
            return None;
        }
        // Record the use, for `bound cache clean --unused`.
        let _ = file.set_modified(SystemTime::now());
        Some(file)
    }

    /// Stores a content: `write` fills a new file in the staging area,
    /// which becomes the cache entry once it has been written completely
    /// (an error from `write`, such as a hash mismatch, discards it).
    /// Returns the entry, opened for reading.
    pub fn store_blob(
        &self,
        sha256: &Digest,
        size: u64,
        write: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> io::Result<File> {
        let staging = self.root.join("tmp").join(format!("blob-{}", bound_platform::random_hex(8)?));
        let result = (|| {
            let mut file = pfs::create_new_file(&staging, false)?;
            write(&mut file)?;
            file.flush()?;
            file.sync_data()?;
            drop(file);
            pfs::set_read_only(&staging, false, false)?;
            let path = self.blob_path(sha256);
            if let Some(parent) = path.parent() {
                match fs::create_dir(parent) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
            }
            match pfs::rename_no_replace(&staging, &path) {
                Ok(()) => Ok(()),
                // Stored by a concurrent run: the same content.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
                Err(e) => Err(e),
            }
        })();
        if result.is_err() || staging.exists() {
            let _ = pfs::remove_file(&staging);
        }
        result?;
        self.blob(sha256, size).ok_or_else(|| io::Error::other("the stored content disappeared"))
    }

    /// Where the shared bundle of the artifact with this manifest digest is
    /// (or will be) in the cache.
    pub fn tree_path(&self, digest: &Digest) -> PathBuf {
        self.root.join("trees").join(digest.to_string())
    }

    /// The shared bundle of the artifact with this manifest digest, if it
    /// is in the cache and sealed (a read-only directory of this user).
    pub fn tree(&self, digest: &Digest) -> Option<PathBuf> {
        let path = self.tree_path(digest);
        if !pfs::is_sealed_dir(&path) {
            return None;
        }
        // Record the use, for `bound cache clean --unused`.
        let marker = path.with_extension("used");
        if let Ok(file) = fs::OpenOptions::new().create(true).truncate(false).write(true).open(&marker) {
            let _ = file.set_modified(SystemTime::now());
        }
        Some(path)
    }

    /// A new private directory in which to write a shared bundle.
    pub fn staging_dir(&self) -> io::Result<PathBuf> {
        pfs::create_private_dir(&self.root.join("trees"), ".staging-")
    }

    /// Seals the materialized bundle `staging` of `manifest` (flushes it to
    /// disk and makes it read-only) and moves it into place as the shared
    /// bundle of the artifact with this manifest digest. If a concurrent
    /// run installed it first, `staging` is removed and that one is used.
    /// A damaged entry in the way is moved aside first.
    ///
    /// The contents are durable before the tree is sealed, and the tree is
    /// sealed before it is moved into place: after a crash, a tree in place
    /// is either complete or not sealed (and then extracted again).
    pub fn install_tree(&self, staging: &Path, manifest: &Manifest, digest: &Digest) -> io::Result<PathBuf> {
        // Children before their parents: resources are sorted by path.
        let mut entries = Vec::with_capacity(manifest.resources.len());
        for resource in manifest.resources.iter().rev() {
            let path = staging.join(resource.path().to_native().map_err(io::Error::other)?);
            match resource {
                Resource::Dir { .. } => entries.push((path, true, true)),
                Resource::File { executable, .. } => entries.push((path, false, *executable)),
                Resource::Symlink { .. } => {}
            }
        }
        pfs::sync_tree(staging, entries.iter().map(|(path, is_dir, _)| (path.as_path(), *is_dir)))?;
        for (path, is_dir, executable) in &entries {
            pfs::set_read_only(path, *is_dir, *executable)?;
        }
        pfs::set_read_only(staging, true, true)?;

        let path = self.tree_path(digest);
        if fs::symlink_metadata(&path).is_ok() && !pfs::is_sealed_dir(&path) {
            let aside = self.root.join("trees").join(format!(".stale-{}", bound_platform::random_hex(8)?));
            fs::rename(&path, &aside)?;
            let _ = pfs::remove_tree(&aside);
        }
        match pfs::rename_no_replace(staging, &path) {
            Ok(()) => Ok(path),
            Err(e) if matches!(e.kind(), io::ErrorKind::AlreadyExists | io::ErrorKind::DirectoryNotEmpty) => {
                let _ = pfs::remove_tree(staging);
                if pfs::is_sealed_dir(&path) { Ok(path) } else { Err(e) }
            }
            Err(e) => Err(e),
        }
    }
}

/// One entry of the cache, as listed by `bound cache list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    pub kind: EntryKind,
    pub path: PathBuf,
    /// Total size of the files in the entry.
    pub bytes: u64,
    pub last_used: Option<SystemTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A decoded content.
    Blob,
    /// A shared bundle.
    Tree,
    /// Left over from an interrupted run.
    Staging,
}

impl Cache {
    /// Lists every entry.
    pub fn entries(&self) -> io::Result<Vec<CacheEntry>> {
        let mut out = Vec::new();
        for shard in read_dir_sorted(&self.root.join("blobs"))? {
            for blob in read_dir_sorted(&shard)? {
                let meta = fs::symlink_metadata(&blob)?;
                out.push(CacheEntry {
                    kind: EntryKind::Blob,
                    bytes: meta.len(),
                    last_used: meta.modified().ok(),
                    path: blob,
                });
            }
        }
        for tree in read_dir_sorted(&self.root.join("trees"))? {
            if tree.extension().is_some_and(|e| e == "used") {
                continue;
            }
            if tree.file_name().is_some_and(|name| name.to_string_lossy().starts_with('.')) {
                let last_used = fs::symlink_metadata(&tree).and_then(|m| m.modified()).ok();
                out.push(CacheEntry { kind: EntryKind::Staging, bytes: tree_size(&tree), last_used, path: tree });
                continue;
            }
            let last_used = fs::metadata(tree.with_extension("used"))
                .or_else(|_| fs::symlink_metadata(&tree))
                .and_then(|m| m.modified())
                .ok();
            out.push(CacheEntry { kind: EntryKind::Tree, bytes: tree_size(&tree), last_used, path: tree });
        }
        for staged in read_dir_sorted(&self.root.join("tmp"))? {
            let last_used = fs::symlink_metadata(&staged).and_then(|m| m.modified()).ok();
            out.push(CacheEntry { kind: EntryKind::Staging, bytes: tree_size(&staged), last_used, path: staged });
        }
        Ok(out)
    }

    /// Removes an entry listed by [`Cache::entries`].
    pub fn remove(&self, entry: &CacheEntry) -> io::Result<()> {
        if !entry.path.starts_with(&self.root) {
            return Err(io::Error::other("not a cache entry"));
        }
        match entry.kind {
            EntryKind::Blob => pfs::remove_file(&entry.path),
            EntryKind::Tree => {
                let _ = fs::remove_file(entry.path.with_extension("used"));
                pfs::remove_tree(&entry.path)
            }
            EntryKind::Staging if entry.path.is_dir() => pfs::remove_tree(&entry.path),
            EntryKind::Staging => pfs::remove_file(&entry.path),
        }
    }
}

fn read_dir_sorted(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut entries: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(entries) => entries.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    entries.sort();
    Ok(entries)
}

/// Total size of the files under `path`, without following links.
fn tree_size(path: &Path) -> u64 {
    let Ok(meta) = fs::symlink_metadata(path) else { return 0 };
    if !meta.is_dir() {
        return meta.len();
    }
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            match entry.metadata() {
                Ok(meta) if meta.is_dir() => stack.push(entry.path()),
                Ok(meta) if meta.is_file() => total += meta.len(),
                _ => {}
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> Digest {
        Digest([n; 32])
    }

    #[test]
    fn contents_are_stored_once_and_found_again() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::open_at(&dir.path().join("cache")).unwrap();
        assert!(cache.blob(&digest(1), 5).is_none());
        let stored = cache.store_blob(&digest(1), 5, |f| f.write_all(b"hello")).unwrap();
        assert_eq!(stored.metadata().unwrap().len(), 5);
        assert!(cache.blob(&digest(1), 5).is_some());
        assert!(cache.blob(&digest(1), 6).is_none(), "a size mismatch is not a hit");
        // Storing again (as a concurrent run would) is harmless.
        cache.store_blob(&digest(1), 5, |f| f.write_all(b"hello")).unwrap();
        // A failed write leaves nothing behind.
        let err = cache.store_blob(&digest(2), 5, |_| Err(io::Error::from(io::ErrorKind::InvalidData)));
        assert!(err.is_err());
        assert!(cache.blob(&digest(2), 5).is_none());
        let entries = cache.entries().unwrap();
        assert_eq!(entries.iter().filter(|e| e.kind == EntryKind::Blob).count(), 1);
        assert!(entries.iter().all(|e| e.kind != EntryKind::Staging), "{entries:?}");
    }

    #[test]
    fn clones_of_cached_contents_are_independent() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::open_at(&dir.path().join("cache")).unwrap();
        let blob = cache.store_blob(&digest(3), 8, |f| f.write_all(b"original")).unwrap();
        let copy = dir.path().join("copy");
        pfs::clone_file(&blob, &copy, false).unwrap();
        fs::write(&copy, b"modified").unwrap();
        let mut again = String::new();
        io::Read::read_to_string(&mut cache.blob(&digest(3), 8).unwrap(), &mut again).unwrap();
        assert_eq!(again, "original");
        assert!(pfs::clone_file(&blob, &copy, false).is_err(), "clones never replace files");
    }
}
