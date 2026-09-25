//! Collecting the files and directories that go into a bundle.
//!
//! Every input is given a place under the bundle root:
//!
//! * a relative path inside the current directory keeps its relative path
//!   (`./templates` -> `templates`, `assets/logo.png` -> `assets/logo.png`),
//!   so a program run with `--cwd bundle` finds files where it expects them;
//! * any other path (absolute, or reaching outside the current directory)
//!   is placed at the root under its final name (`/opt/data` -> `data`);
//! * `--include-as DEST=PATH` chooses the place explicitly.
//!
//! Directory trees are walked without following symbolic links. Two inputs
//! may not claim the same place unless they are the same: the same file, or
//! files with the same content (such as the copies of one file that build
//! systems make), or links with the same target. In bundles for Windows and
//! macOS, whose file systems ignore case, names that differ only by case are
//! rejected because they would collide.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use bound_format::{Digest, LinkTarget, NameRules, Resource, ResourcePath};
use bound_platform::fs::{EntryKind, FileIdentity, classify};

use crate::error::{CliError, fail};

/// Where an input goes in the bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// The bundle root itself (only meaningful for directories).
    Root,
    At(ResourcePath),
}

/// A bundle entry and where its content comes from.
#[derive(Debug, Clone)]
pub enum Entry {
    Dir,
    /// A file to bundle. `identity` is what the file was when it was found,
    /// and `follow` whether its path may end in a symbolic link (true for
    /// files named on the command line, false for files found by walking
    /// a directory), so that the file read is the file that was checked.
    File {
        source: PathBuf,
        canonical: PathBuf,
        executable: bool,
        origin: String,
        identity: FileIdentity,
        follow: bool,
        /// Size when the file was found.
        len: u64,
    },
    Symlink {
        target: LinkTarget,
        origin: String,
    },
}

/// Canonical paths of the inputs named on the command line, used to keep
/// the output from being bundled into itself.
#[derive(Debug, Default)]
pub struct Inputs {
    pub dirs: Vec<PathBuf>,
    pub files: Vec<PathBuf>,
}

/// The set of entries of a bundle, kept sorted by resource path.
#[derive(Debug)]
pub struct ResourceSet {
    rules: NameRules,
    /// Whether names that differ only by case collide.
    fold_case: bool,
    /// Whether files are also recorded executable by their content.
    detect_executables: bool,
    entries: BTreeMap<ResourcePath, Entry>,
    folded: HashMap<Vec<u8>, ResourcePath>,
    inputs: Inputs,
}

/// The default place of `path` in the bundle (see the module docs).
pub fn default_placement(path: &Path) -> Result<Placement, CliError> {
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    let mut outside = false;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => outside = true,
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    outside = true;
                }
            }
            Component::Normal(name) => parts.push(name),
        }
    }
    let unsafe_name = |e: bound_format::NameError| CliError::new(e.to_string());
    if outside {
        let name = match path.file_name() {
            Some(name) => name.to_owned(),
            None => fs::canonicalize(path).ok().and_then(|p| p.file_name().map(|n| n.to_owned())).ok_or_else(|| {
                CliError::new(format!("cannot choose a bundle name for {}", path.display()))
                    .with_hint("use --include-as DEST=PATH to name it explicitly")
            })?,
        };
        return ResourcePath::from_host_component(&name).map(Placement::At).map_err(unsafe_name);
    }
    if parts.is_empty() {
        return Ok(Placement::Root);
    }
    let relative: PathBuf = parts.iter().collect();
    ResourcePath::from_host_path(&relative).map(Placement::At).map_err(unsafe_name)
}

impl ResourceSet {
    /// Whether something is bundled at `path`.
    pub fn contains(&self, path: &ResourcePath) -> bool {
        self.entries.contains_key(path)
    }

    /// A set for a bundle materialized under `rules`, on file systems that
    /// ignore case if `fold_case`.
    pub fn new(rules: NameRules, fold_case: bool) -> ResourceSet {
        ResourceSet {
            rules,
            fold_case,
            detect_executables: false,
            entries: BTreeMap::new(),
            folded: HashMap::new(),
            inputs: Inputs::default(),
        }
    }

    /// Also records files as executable by their content (a `#!` line, an
    /// ELF or Mach-O program or library): for bundles for Unix built where
    /// files have no executable bits (Windows).
    pub fn detect_executables(&mut self, detect: bool) {
        self.detect_executables = detect;
    }

    /// Whether the file at `path` is recorded executable, given its mode.
    fn is_executable(&self, path: &Path, by_mode: bool) -> bool {
        by_mode || (self.detect_executables && content_is_executable(path))
    }

    pub fn entries(&self) -> impl Iterator<Item = (&ResourcePath, &Entry)> {
        self.entries.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn inputs(&self) -> &Inputs {
        &self.inputs
    }

    /// The entries as manifest resources with placeholder content hashes,
    /// for validating the tree before any content is written.
    pub fn preview(&self) -> Vec<Resource> {
        self.entries
            .iter()
            .map(|(path, entry)| match entry {
                Entry::Dir => Resource::Dir { path: path.clone() },
                Entry::File { executable, .. } => {
                    Resource::File { path: path.clone(), size: 0, sha256: Digest([0; 32]), executable: *executable }
                }
                Entry::Symlink { target, .. } => Resource::Symlink { path: path.clone(), target: target.clone() },
            })
            .collect()
    }

    /// Adds a file or directory tree from disk. A symlink given here is
    /// followed (the user named it explicitly); links found *inside* a
    /// directory are preserved, never followed. Returns the placement used.
    pub fn add_path(&mut self, path: &Path, placement: Option<Placement>, origin: &str) -> Result<Placement, CliError> {
        let meta = fs::metadata(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CliError::new(format!("{origin}: {} does not exist", path.display()))
            } else {
                CliError::new(format!("{origin}: cannot read {}: {e}", path.display()))
            }
        })?;
        let canonical = fs::canonicalize(path)
            .map_err(|e| CliError::new(format!("{origin}: cannot resolve {}: {e}", path.display())))?;
        let placement = match placement {
            Some(p) => p,
            None => default_placement(path)?,
        };
        match classify(&meta) {
            EntryKind::Dir => {
                self.inputs.dirs.push(canonical.clone());
                self.add_tree(&placement, path, &canonical, origin)?;
            }
            EntryKind::File { executable } => {
                let Placement::At(dest) = &placement else {
                    return fail(format!("{origin}: a file cannot be placed at the bundle root itself"));
                };
                self.inputs.files.push(canonical.clone());
                let executable = self.is_executable(path, executable);
                self.insert(
                    dest.clone(),
                    Entry::File {
                        source: path.to_path_buf(),
                        canonical,
                        executable,
                        origin: origin.to_owned(),
                        identity: FileIdentity::of(&meta),
                        follow: true,
                        len: meta.len(),
                    },
                )?;
            }
            EntryKind::Link => unreachable!("metadata() follows links"),
            EntryKind::Other(kind) => {
                return fail(format!("{origin}: {} is a {kind}, which cannot be bundled", path.display()));
            }
        }
        Ok(placement)
    }

    /// Adds the program file at `dest`, marked executable.
    pub fn add_program(&mut self, source: &Path, dest: ResourcePath) -> Result<(), CliError> {
        let canonical =
            fs::canonicalize(source).map_err(|e| CliError::new(format!("cannot resolve {}: {e}", source.display())))?;
        let meta = fs::metadata(source).map_err(|e| CliError::new(format!("cannot read {}: {e}", source.display())))?;
        self.inputs.files.push(canonical.clone());
        self.insert(
            dest,
            Entry::File {
                source: source.to_path_buf(),
                canonical,
                executable: true,
                origin: "the embedded program".to_owned(),
                identity: FileIdentity::of(&meta),
                follow: true,
                len: meta.len(),
            },
        )
    }

    fn add_tree(
        &mut self,
        placement: &Placement,
        root: &Path,
        canonical_root: &Path,
        origin: &str,
    ) -> Result<(), CliError> {
        let base = match placement {
            Placement::Root => None,
            Placement::At(dest) => {
                self.insert(dest.clone(), Entry::Dir)?;
                Some(dest.clone())
            }
        };
        let mut stack = vec![(base, root.to_path_buf(), canonical_root.to_path_buf())];
        #[cfg(unix)]
        let mut seen = std::collections::HashSet::new();

        while let Some((dest, dir, canonical_dir)) = stack.pop() {
            let read_error = |e: std::io::Error| CliError::new(format!("{origin}: cannot read {}: {e}", dir.display()));
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let meta = fs::metadata(&dir).map_err(read_error)?;
                if !seen.insert((meta.dev(), meta.ino())) {
                    return fail(format!(
                        "{origin}: {} is reachable twice (a bind mount or file-system loop)",
                        dir.display()
                    ));
                }
            }
            let mut children: Vec<fs::DirEntry> = fs::read_dir(&dir).and_then(|it| it.collect()).map_err(read_error)?;
            children.sort_by_key(|entry| entry.file_name());

            for child in children {
                let name = child.file_name();
                let path = child.path();
                let dest = match &dest {
                    Some(parent) => parent.join_host(&name),
                    None => ResourcePath::from_host_component(&name),
                }
                .map_err(|e| CliError::new(format!("{origin}: cannot bundle {}: {e}", path.display())))?;
                // DirEntry::metadata does not follow symlinks.
                let meta = child
                    .metadata()
                    .map_err(|e| CliError::new(format!("{origin}: cannot read {}: {e}", path.display())))?;
                let canonical = canonical_dir.join(&name);
                match classify(&meta) {
                    EntryKind::Dir => {
                        self.insert(dest.clone(), Entry::Dir)?;
                        stack.push((Some(dest), path, canonical));
                    }
                    EntryKind::File { executable } => {
                        let executable = self.is_executable(&path, executable);
                        self.insert(
                            dest,
                            Entry::File {
                                source: path,
                                canonical,
                                executable,
                                origin: origin.to_owned(),
                                identity: FileIdentity::of(&meta),
                                follow: false,
                                len: meta.len(),
                            },
                        )?;
                    }
                    EntryKind::Link => self.add_link(dest, &path, origin)?,
                    EntryKind::Other(kind) => {
                        return fail(format!("{origin}: {} is a {kind}, which cannot be bundled", path.display()));
                    }
                }
            }
        }
        Ok(())
    }

    /// Adds a symbolic link at `dest` with the given target. Validation
    /// checks that it resolves inside the bundle.
    pub fn add_symlink(&mut self, dest: ResourcePath, target: LinkTarget, origin: &str) -> Result<(), CliError> {
        self.insert(dest, Entry::Symlink { target, origin: origin.to_owned() })
    }

    /// Adds a directory at `dest` (and its ancestors).
    pub fn add_dir(&mut self, dest: ResourcePath) -> Result<(), CliError> {
        self.insert(dest, Entry::Dir)
    }

    /// Marks the file at `path`, which the program will run, executable.
    pub fn mark_program(&mut self, path: &ResourcePath) -> Result<(), CliError> {
        match self.entries.get_mut(path) {
            Some(Entry::File { executable, .. }) => {
                *executable = true;
                Ok(())
            }
            Some(other) => fail(format!("the program @bundle:{path} is {}, not a file", describe(other))),
            None => fail(format!("the program @bundle:{path} is not bundled")),
        }
    }

    /// Adds the symbolic link at `path` itself (not what it points to) at
    /// `dest`. Its target must be relative (so not a Windows junction, whose
    /// target is absolute); validation checks that it resolves inside the
    /// bundle.
    pub fn add_link(&mut self, dest: ResourcePath, path: &Path, origin: &str) -> Result<(), CliError> {
        let target = fs::read_link(path)
            .map_err(|e| CliError::new(format!("{origin}: cannot read link {}: {e}", path.display())))?;
        let target = LinkTarget::from_host_path(&target).map_err(|e| {
            CliError::new(format!(
                "{origin}: cannot bundle symlink {} -> {}: {}",
                path.display(),
                target.display(),
                e.reason
            ))
            .with_hint("bound keeps only relative links that stay inside the bundle")
        })?;
        self.insert(dest, Entry::Symlink { target, origin: origin.to_owned() })
    }

    /// Inserts an entry and its ancestor directories.
    fn insert(&mut self, path: ResourcePath, entry: Entry) -> Result<(), CliError> {
        path.validate(self.rules).map_err(|e| CliError::new(e.to_string()))?;
        for ancestor in path.ancestors() {
            self.insert_one(ancestor, Entry::Dir)?;
        }
        self.insert_one(path, entry)
    }

    fn insert_one(&mut self, path: ResourcePath, entry: Entry) -> Result<(), CliError> {
        let key = path.fold_key();
        if let Some(existing) = self.folded.get(&key).filter(|_| self.fold_case) {
            if *existing != path {
                return fail(format!(
                    "resources \"{existing}\" and \"{path}\" differ only by case; they would collide on case-insensitive file systems (Windows, macOS)"
                ));
            }
        }
        let Some(existing) = self.entries.get_mut(&path) else {
            self.folded.insert(key, path.clone());
            self.entries.insert(path, entry);
            return Ok(());
        };
        match (existing, entry) {
            (Entry::Dir, Entry::Dir) => Ok(()),
            (Entry::File { canonical: a, executable, .. }, Entry::File { canonical: b, executable: more, .. })
                if *a == b =>
            {
                *executable |= more;
                Ok(())
            }
            (
                Entry::File { source: a, len: a_len, executable, .. },
                Entry::File { source: b, len: b_len, executable: more, origin, .. },
            ) if *a_len == b_len
                && same_content(a, &b).map_err(|e| {
                    CliError::new(format!("{origin}: cannot compare {} with {}: {e}", b.display(), a.display()))
                })? =>
            {
                *executable |= more;
                Ok(())
            }
            (Entry::Symlink { target: a, .. }, Entry::Symlink { target: b, .. }) if *a == b => Ok(()),
            (Entry::Dir, _) | (_, Entry::Dir) => {
                fail(format!("resource \"{path}\" is needed both as a directory and as a file"))
            }
            (existing, entry) => fail(format!(
                "resource \"{path}\" would come from both {} and {}",
                describe(existing),
                describe(&entry)
            ))
            .map_err(|e: CliError| e.with_hint("use --include-as DEST=PATH to place one of them elsewhere")),
        }
    }
}

/// Whether a file's content is that of a Unix executable: a script with a
/// `#!` line, or an ELF or Mach-O program or library (not an object file).
fn content_is_executable(path: &Path) -> bool {
    let mut header = [0u8; 20];
    let Ok(mut file) = fs::File::open(path) else { return false };
    let Ok(n) = read_full(&mut file, &mut header) else { return false };
    looks_executable(&header[..n])
}

fn looks_executable(header: &[u8]) -> bool {
    let u16_at = |at: usize, big: bool| {
        header
            .get(at..at + 2)
            .map(|b| if big { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) })
    };
    let u32_at = |at: usize, big: bool| {
        header.get(at..at + 4).map(|b| {
            let b = [b[0], b[1], b[2], b[3]];
            if big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
        })
    };
    if header.starts_with(b"#!") {
        return true;
    }
    if header.starts_with(b"\x7fELF") {
        // e_type: ET_EXEC or ET_DYN (programs, libraries), not ET_REL.
        let big = header.get(5) == Some(&2);
        return matches!(u16_at(16, big), Some(2 | 3));
    }
    match u32_at(0, true) {
        // Mach-O, 32 and 64 bits, either byte order: MH_EXECUTE, MH_DYLIB,
        // MH_BUNDLE (not MH_OBJECT).
        Some(0xfeed_face | 0xfeed_facf) => matches!(u32_at(12, true), Some(2 | 6 | 8)),
        Some(0xcefa_edfe | 0xcffa_edfe) => matches!(u32_at(12, false), Some(2 | 6 | 8)),
        // A universal binary, whose architecture count is small, unlike the
        // version that follows the same magic in a Java class file.
        Some(0xcafe_babe) => matches!(u32_at(4, true), Some(1..=20)),
        _ => false,
    }
}

/// Whether two files of the same size have the same bytes.
fn same_content(a: &Path, b: &Path) -> io::Result<bool> {
    let (mut a, mut b) = (fs::File::open(a)?, fs::File::open(b)?);
    let (mut left, mut right) = (vec![0; 64 * 1024], vec![0; 64 * 1024]);
    loop {
        let n = read_full(&mut a, &mut left)?;
        let m = read_full(&mut b, &mut right)?;
        if n != m || left[..n] != right[..m] {
            return Ok(false);
        }
        if n == 0 {
            return Ok(true);
        }
    }
}

/// Reads until `buf` is full or the end of the file.
fn read_full(file: &mut fs::File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn describe(entry: &Entry) -> String {
    match entry {
        Entry::Dir => "a directory".to_owned(),
        Entry::File { source, origin, .. } => format!("{} ({origin})", source.display()),
        Entry::Symlink { origin, .. } => format!("a symlink ({origin})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> Placement {
        Placement::At(ResourcePath::new(s).unwrap())
    }

    #[test]
    fn placements() {
        assert_eq!(default_placement(Path::new("./templates")).unwrap(), at("templates"));
        assert_eq!(default_placement(Path::new("assets/logo.png")).unwrap(), at("assets/logo.png"));
        assert_eq!(default_placement(Path::new("a/./b/../c")).unwrap(), at("a/c"));
        assert_eq!(default_placement(Path::new("../shared/x.toml")).unwrap(), at("x.toml"));
        assert_eq!(default_placement(Path::new("a/../../b")).unwrap(), at("b"));
        assert_eq!(default_placement(Path::new(".")).unwrap(), Placement::Root);
        let absolute = std::env::temp_dir().join("data");
        assert_eq!(default_placement(&absolute).unwrap(), at("data"));
    }

    #[test]
    fn collects_a_tree_and_detects_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("t/sub")).unwrap();
        fs::write(root.join("t/a.txt"), "a").unwrap();
        fs::write(root.join("t/sub/b.txt"), "b").unwrap();
        fs::create_dir(root.join("t/empty")).unwrap();
        fs::write(root.join("other.txt"), "o").unwrap();

        let mut set = ResourceSet::new(NameRules::Portable, true);
        set.add_path(&root.join("t"), Some(at("t")), "--include t").unwrap();
        // The same file again through another route is fine.
        set.add_path(&root.join("t/a.txt"), Some(at("t/a.txt")), "@file:t/a.txt").unwrap();
        let names: Vec<String> = set.entries().map(|(p, _)| p.display()).collect();
        assert_eq!(names, ["t", "t/a.txt", "t/empty", "t/sub", "t/sub/b.txt"]);

        // Nor a copy of it.
        fs::write(root.join("copy.txt"), "a").unwrap();
        set.add_path(&root.join("copy.txt"), Some(at("t/a.txt")), "@file:copy.txt").unwrap();
        // A different file at the same place is not.
        let err = set.add_path(&root.join("other.txt"), Some(at("t/a.txt")), "@file:other.txt").unwrap_err();
        assert!(err.message.contains("would come from both"), "{err:?}");
        fs::write(root.join("same-size.txt"), "b").unwrap();
        let err = set.add_path(&root.join("same-size.txt"), Some(at("t/a.txt")), "x").unwrap_err();
        assert!(err.message.contains("would come from both"), "{err:?}");
        // Nor a file where a directory is.
        let err = set.add_path(&root.join("other.txt"), Some(at("t/sub")), "x").unwrap_err();
        assert!(err.message.contains("both as a directory and as a file"), "{err:?}");
        // Nor, where file systems ignore case, a name differing only by case.
        let err = set.add_path(&root.join("other.txt"), Some(at("T/A.txt")), "x").unwrap_err();
        assert!(err.message.contains("differ only by case"), "{err:?}");
        let mut linux = ResourceSet::new(NameRules::Portable, false);
        linux.add_path(&root.join("t"), Some(at("t")), "--include t").unwrap();
        linux.add_path(&root.join("other.txt"), Some(at("T/A.txt")), "x").unwrap();
    }

    #[test]
    fn missing_inputs_are_reported() {
        let mut set = ResourceSet::new(NameRules::Portable, false);
        let err = set.add_path(Path::new("definitely/missing"), None, "@file:definitely/missing").unwrap_err();
        assert_eq!(err.message, "@file:definitely/missing: definitely/missing does not exist");
    }

    #[test]
    fn windows_rules_apply_to_windows_bundles() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("x"), "x").unwrap();
        let mut set = ResourceSet::new(NameRules::Windows, true);
        let err = set.add_path(&dir.path().join("x"), Some(at("aux.txt")), "x").unwrap_err();
        assert!(err.message.contains("reserved device name"), "{err:?}");
    }

    /// A symbolic link to a file (on Windows, this needs Developer Mode or
    /// an administrator).
    fn symlink_file(target: &Path, link: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(target, link).unwrap();
    }

    #[test]
    fn symlinks_are_preserved_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let t = dir.path().join("t");
        fs::create_dir_all(t.join("sub")).unwrap();
        fs::write(t.join("real.txt"), "r").unwrap();
        symlink_file(Path::new("real.txt"), &t.join("alias.txt"));
        symlink_file(&Path::new("..").join("real.txt"), &t.join("sub").join("up.txt"));
        let mut set = ResourceSet::new(NameRules::Portable, false);
        set.add_path(&t, Some(at("t")), "--include t").unwrap();
        let target = |name: &str| match set.entries().find(|(p, _)| p.display() == name) {
            Some((_, Entry::Symlink { target, .. })) => target.display(),
            other => panic!("{name}: {other:?}"),
        };
        assert_eq!(target("t/alias.txt"), "real.txt");
        // Written with / whatever the host's separator.
        assert_eq!(target("t/sub/up.txt"), "../real.txt");

        let outside = dir.path().join("outside.txt");
        fs::write(&outside, "o").unwrap();
        symlink_file(&outside, &t.join("escape"));
        let mut set = ResourceSet::new(NameRules::Portable, false);
        let err = set.add_path(&t, Some(at("t")), "--include t").unwrap_err();
        assert!(err.message.contains("absolute"), "{err:?}");
    }

    #[test]
    fn declared_links_and_directories() {
        let target = |t: &str| LinkTarget::from_bytes(t.as_bytes()).unwrap();
        let path = |p: &str| ResourcePath::new(p).unwrap();
        let mut set = ResourceSet::new(NameRules::Portable, false);
        set.add_dir(path("store/a/lib")).unwrap();
        set.add_symlink(path("node_modules/a"), target("../store/a"), "x").unwrap();
        // The same link twice is one link; another target is a conflict.
        set.add_symlink(path("node_modules/a"), target("../store/a"), "y").unwrap();
        let err = set.add_symlink(path("node_modules/a"), target("../store/b"), "z").unwrap_err();
        assert!(err.message.contains("would come from both"), "{err:?}");
        let names: Vec<String> = set.entries().map(|(p, _)| p.display()).collect();
        assert_eq!(names, ["node_modules", "node_modules/a", "store", "store/a", "store/a/lib"]);

        let err = set.mark_program(&path("store/a")).unwrap_err();
        assert!(err.message.contains("not a file"), "{err:?}");
        let err = set.mark_program(&path("bin/tool")).unwrap_err();
        assert!(err.message.contains("is not bundled"), "{err:?}");
    }

    #[test]
    fn executables_are_recognized_by_their_content() {
        let elf = |class_data: [u8; 2], e_type: [u8; 2]| {
            let mut h = vec![0x7f, b'E', b'L', b'F', class_data[0], class_data[1], 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            h.extend(e_type);
            h
        };
        for yes in [
            b"#!/bin/sh\n".to_vec(),
            elf([2, 1], [2, 0]), // 64-bit little-endian program
            elf([2, 1], [3, 0]), // shared library (or PIE)
            elf([1, 2], [0, 2]), // 32-bit big-endian program
            [0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1, 3, 0, 0, 0, 2, 0, 0, 0].to_vec(), // Mach-O program
            [0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 7, 0, 0, 0, 3, 0, 0, 0, 6].to_vec(), // Mach-O dylib (big-endian)
            [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2].to_vec(), // universal binary
        ] {
            assert!(looks_executable(&yes), "{yes:x?}");
        }
        for no in [
            b"hello".to_vec(),
            b"#".to_vec(),
            Vec::new(),
            elf([2, 1], [1, 0]),                                                   // object file
            [0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1, 3, 0, 0, 0, 1, 0, 0, 0].to_vec(), // Mach-O object
            [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52].to_vec(),                        // Java class file
            b"MZ\x90\x00".to_vec(),                                                // Windows program
        ] {
            assert!(!looks_executable(&no), "{no:x?}");
        }
    }

    #[test]
    fn executable_bits_are_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("tool.sh");
        let data = dir.path().join("data.txt");
        fs::write(&tool, "#!/bin/sh\n").unwrap();
        fs::write(&data, "data\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let executable = |set: &ResourceSet, name: &str| {
            matches!(set.entries().find(|(p, _)| p.display() == name), Some((_, Entry::File { executable: true, .. })))
        };

        // The file's executable bit, on file systems that have them.
        let mut set = ResourceSet::new(NameRules::Portable, false);
        set.add_path(&tool, Some(at("tool.sh")), "x").unwrap();
        set.add_path(dir.path(), Some(at("tree")), "x").unwrap();
        assert_eq!(executable(&set, "tool.sh"), cfg!(unix));
        assert_eq!(executable(&set, "tree/tool.sh"), cfg!(unix));
        assert!(!executable(&set, "tree/data.txt"));

        // Or its content, for bundles for Unix built on Windows.
        let mut set = ResourceSet::new(NameRules::Portable, false);
        set.detect_executables(true);
        set.add_path(&tool, Some(at("tool.sh")), "x").unwrap();
        set.add_path(dir.path(), Some(at("tree")), "x").unwrap();
        assert!(executable(&set, "tool.sh") && executable(&set, "tree/tool.sh"));
        assert!(!executable(&set, "tree/data.txt"));
    }
}
