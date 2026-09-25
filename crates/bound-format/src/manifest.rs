//! The manifest: the description of a bound invocation and its resources.
//!
//! The manifest is the single source of truth for what an artifact does.
//! Artifacts store it in a compact binary encoding ([`Manifest::encode`]),
//! which is decoded strictly ([`Manifest::decode`]) and then validated as a
//! whole by [`Manifest::validate`] before anything acts on it, because it is
//! untrusted input: an artifact may have been crafted by an attacker. The
//! JSON form these types serialize to is what `bound inspect --json` shows.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::footer::FORMAT_VERSION;
use crate::hash::Digest;
use crate::limits::{MAX_LABEL_LEN, MAX_SYMLINK_DEPTH, MAX_ZSTD_RATIO};
use crate::names::{LinkTarget, NameRules, ResourcePath, folds_case};
use crate::osvalue::OsValue;
use crate::platform::Platform;
use crate::wire;

/// Name of the environment variable through which the target program finds
/// the materialized bundle root. Manifests may not bind it themselves.
pub const BOUND_ROOT_ENV: &str = "BOUND_ROOT";

/// The complete description of a bound artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Manifest {
    /// Artifact format version; equal to the footer's version.
    pub format: u16,
    /// The tool that produced the artifact, e.g. `bound 0.1.0`. Informational.
    pub generator: String,
    /// Platform of the launcher, identified from its executable header.
    pub platform: Platform,
    /// Size and hash of the launcher region.
    pub launcher: RegionInfo,
    /// Size and hash of the stored payload region (every byte of it,
    /// including compression padding that decoding would ignore).
    pub payload: RegionInfo,
    /// The program to run.
    pub target: Target,
    /// Argument template; see [`ArgTemplate`].
    pub args: Vec<ArgTemplate>,
    /// Environment variables set for the target, in order.
    pub env: Vec<EnvBinding>,
    /// Working directory of the target.
    pub cwd: CwdMode,
    /// How the bundle directory is provided.
    pub bundle: BundleMode,
    /// Every entry of the bundle, sorted by path.
    pub resources: Vec<Resource>,
    /// Stored file contents, in payload order.
    pub blobs: Vec<Blob>,
}

/// Size and SHA-256 of a region of the artifact file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RegionInfo {
    pub size: u64,
    pub sha256: Digest,
}

/// The program an artifact runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Target {
    /// Not bundled: resolved on the destination system at run time using the
    /// platform's native rules (e.g. `PATH`). An external dependency.
    External { program: OsValue },
    /// Bundled as a resource and materialized before launch.
    Embedded { resource: ResourcePath },
}

/// One element of the argument template.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ArgTemplate {
    /// Passed through unchanged.
    Literal { value: OsValue },
    /// Replaced by the absolute native path of a materialized resource.
    Resource { path: ResourcePath },
    /// Replaced by the arguments given at run time (zero or more). If the
    /// template has no such element, run-time arguments are rejected.
    RuntimeArgs,
}

/// An environment variable binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EnvBinding {
    pub name: OsValue,
    pub value: EnvValue,
}

/// The value of an environment binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EnvValue {
    Literal {
        value: OsValue,
    },
    /// The absolute native path of a materialized resource.
    Resource {
        path: ResourcePath,
    },
    /// Removed from the environment the program inherits. (An empty struct
    /// variant, so that the JSON form is `{"type": "unset"}`.)
    Unset {},
}

/// Where the target runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CwdMode {
    /// The caller's working directory.
    Inherit,
    /// The materialized bundle root.
    Bundle,
}

/// How the bundle directory is provided to each run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleMode {
    /// A new private directory for every run, removed after the program
    /// exits. The program may modify its files.
    Private,
    /// One read-only directory per user and artifact, extracted into the
    /// user's cache on the first run and reused by every later run. The
    /// program must not modify its files.
    Shared,
}

/// An entry of the bundle tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Resource {
    Dir {
        path: ResourcePath,
    },
    File {
        path: ResourcePath,
        size: u64,
        sha256: Digest,
        /// Materialized with execute permission (Unix). Ignored on Windows,
        /// where executability depends on the file name and format.
        executable: bool,
    },
    /// A relative symbolic link that resolves inside the bundle. (Where
    /// symbolic links cannot be created, see [`resolve_links`].)
    Symlink {
        path: ResourcePath,
        target: LinkTarget,
    },
}

impl Resource {
    pub fn path(&self) -> &ResourcePath {
        match self {
            Resource::Dir { path } | Resource::File { path, .. } | Resource::Symlink { path, .. } => path,
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Resource::Dir { .. } => "directory",
            Resource::File { .. } => "file",
            Resource::Symlink { .. } => "symlink",
        }
    }
}

/// Stored bytes of one distinct file content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Blob {
    /// Hash of the uncompressed content.
    pub sha256: Digest,
    /// Uncompressed size.
    pub size: u64,
    /// Offset relative to the start of the payload.
    pub offset: u64,
    /// Size of the stored (possibly compressed) bytes.
    pub stored_size: u64,
    pub compression: Compression,
}

/// How a blob is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    /// Uncompressed.
    Stored,
    /// One Zstandard frame (RFC 8878).
    Zstd,
}

/// A manifest that failed to parse or validate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ManifestError(pub String);

fn err<T>(msg: impl Into<String>) -> Result<T, ManifestError> {
    Err(ManifestError(msg.into()))
}

impl Manifest {
    /// Encodes the manifest as artifacts store it: the postcard wire format
    /// of the schema in `docs/format.md`.
    pub fn encode(&self) -> Vec<u8> {
        wire::encode(self)
    }

    /// Decodes a manifest as artifacts store it. Decoding is strict: lists
    /// are bounded by the format's limits, trailing bytes are rejected, and
    /// only the canonical encoding (the one [`Manifest::encode`] produces)
    /// is accepted, so one manifest digest corresponds to one meaning. Call
    /// [`Manifest::validate`] before acting on the result.
    pub fn decode(bytes: &[u8]) -> Result<Manifest, ManifestError> {
        wire::decode(bytes)
    }

    /// Whether running this artifact requires a materialized bundle root.
    pub fn needs_root(&self) -> bool {
        !self.resources.is_empty() || self.cwd == CwdMode::Bundle
    }

    /// Looks up a resource by path.
    pub fn resource(&self, path: &ResourcePath) -> Option<&Resource> {
        self.resources.binary_search_by(|r| r.path().cmp(path)).ok().map(|i| &self.resources[i])
    }

    /// Looks up the blob holding content with the given hash.
    pub fn blob(&self, sha256: &Digest) -> Option<&Blob> {
        self.blobs.iter().find(|b| &b.sha256 == sha256)
    }

    /// Whether the template accepts run-time arguments.
    pub fn accepts_runtime_args(&self) -> bool {
        self.args.iter().any(|a| matches!(a, ArgTemplate::RuntimeArgs))
    }

    /// Checks every structural and semantic rule of the format.
    ///
    /// `payload_len` is the size of the payload region from the footer;
    /// `rules` are the file-name rules of the platform that will materialize
    /// the resources (the target platform's own rules are always applied as
    /// well).
    pub fn validate(&self, payload_len: u64, rules: NameRules) -> Result<(), ManifestError> {
        if self.format != FORMAT_VERSION {
            return err(format!("manifest format {} does not match artifact format {FORMAT_VERSION}", self.format));
        }
        if self.generator.len() > MAX_LABEL_LEN || self.generator.chars().any(char::is_control) {
            return err("generator field is too long or contains control characters");
        }
        self.platform.validate().map_err(ManifestError)?;
        if self.launcher.size == 0 {
            return err("launcher size is zero");
        }
        if self.payload.size != payload_len {
            return err(format!(
                "manifest payload size {} does not match the payload region ({payload_len} bytes)",
                self.payload.size
            ));
        }
        let rules = rules.stricter(NameRules::for_os(&self.platform.os));
        let fold_case = folds_case(&self.platform.os) || rules == NameRules::Windows;

        let blobs = self.validate_blobs(payload_len)?;
        let tree = validate_resources(&self.resources, rules, fold_case, Some(&blobs))?;
        if let Some(unused) = self.blobs.iter().find(|b| !tree.used_blobs.contains(&b.sha256)) {
            return err(format!("blob {} is not used by any resource", unused.sha256));
        }
        let tree = tree.nodes;
        validate_symlinks(&self.resources, &tree)?;
        self.validate_target(&tree)?;
        self.validate_args(&tree)?;
        self.validate_env(&tree)?;
        Ok(())
    }

    fn validate_blobs(&self, payload_len: u64) -> Result<HashMap<Digest, &Blob>, ManifestError> {
        let mut by_hash = HashMap::new();
        let mut expected = 0u64;
        for blob in &self.blobs {
            if blob.offset != expected {
                return err(format!(
                    "blob {} starts at payload offset {} but the previous blob ends at {expected}",
                    blob.sha256, blob.offset
                ));
            }
            expected = blob
                .offset
                .checked_add(blob.stored_size)
                .ok_or_else(|| ManifestError("blob extent overflows".into()))?;
            match blob.compression {
                Compression::Stored if blob.size != blob.stored_size => {
                    return err(format!("stored blob {} has inconsistent sizes", blob.sha256));
                }
                Compression::Zstd if blob.stored_size == 0 => {
                    return err(format!("compressed blob {} is empty", blob.sha256));
                }
                Compression::Zstd if blob.size > blob.stored_size.saturating_mul(MAX_ZSTD_RATIO) => {
                    return err(format!(
                        "compressed blob {} claims an impossible expansion ({} -> {} bytes)",
                        blob.sha256, blob.stored_size, blob.size
                    ));
                }
                _ => {}
            }
            if by_hash.insert(blob.sha256, blob).is_some() {
                return err(format!("blob {} is stored more than once", blob.sha256));
            }
        }
        if expected != payload_len {
            return err(format!("blobs cover {expected} bytes but the payload region is {payload_len} bytes"));
        }
        Ok(by_hash)
    }

    fn validate_target(&self, tree: &HashMap<&ResourcePath, Node<'_>>) -> Result<(), ManifestError> {
        match &self.target {
            Target::External { program } => {
                if program.is_empty() {
                    return err("external program name is empty");
                }
                self.check_value("program name", program)
            }
            Target::Embedded { resource } => match tree.get(resource) {
                Some(Node::File { executable: true }) => self.check_not_shadowed(resource, tree),
                Some(Node::File { executable: false }) => {
                    err(format!("embedded program \"{resource}\" is not marked executable"))
                }
                _ => err(format!("embedded program \"{resource}\" is not a file in the bundle")),
            },
        }
    }

    /// Windows starts `NAME.exe` in preference to a program path `NAME` that
    /// does not end in `.exe`, so a bundle must not contain both: the program
    /// that ran would not be the one the manifest names.
    fn check_not_shadowed(
        &self,
        program: &ResourcePath,
        tree: &HashMap<&ResourcePath, Node<'_>>,
    ) -> Result<(), ManifestError> {
        if self.platform.os != "windows" || program.as_bytes().to_ascii_lowercase().ends_with(b".exe") {
            return Ok(());
        }
        let mut with_exe = program.as_bytes().to_vec();
        with_exe.extend_from_slice(b".exe");
        let key = ResourcePath::from_bytes(&with_exe).map(|p| p.fold_key());
        let shadowed = key.is_ok_and(|key| tree.keys().any(|path| path.fold_key() == key));
        if shadowed {
            return err(format!(
                "embedded program \"{program}\" would be shadowed on Windows by \"{program}.exe\" in the same bundle"
            ));
        }
        Ok(())
    }

    fn validate_args(&self, tree: &HashMap<&ResourcePath, Node<'_>>) -> Result<(), ManifestError> {
        let mut runtime = 0;
        for arg in &self.args {
            match arg {
                ArgTemplate::Literal { value } => self.check_value("argument", value)?,
                ArgTemplate::Resource { path } => {
                    if !tree.contains_key(path) {
                        return err(format!("argument refers to missing resource \"{path}\""));
                    }
                }
                ArgTemplate::RuntimeArgs => runtime += 1,
            }
        }
        if runtime > 1 {
            return err("@args may appear only once");
        }
        Ok(())
    }

    fn validate_env(&self, tree: &HashMap<&ResourcePath, Node<'_>>) -> Result<(), ManifestError> {
        let mut seen = HashSet::new();
        for binding in &self.env {
            let name = &binding.name;
            if name.is_empty() || name.contains_ascii(b'=') {
                return err(format!("invalid environment variable name \"{name}\""));
            }
            self.check_value("environment variable name", name)?;
            let key = name.fold_key();
            if key == OsValue::from(BOUND_ROOT_ENV) {
                return err(format!("environment variable {BOUND_ROOT_ENV} is reserved"));
            }
            if !seen.insert(key) {
                return err(format!(
                    "environment variable \"{name}\" is bound more than once (names are compared case-insensitively)"
                ));
            }
            match &binding.value {
                EnvValue::Literal { value } => self.check_value("environment value", value)?,
                EnvValue::Resource { path } => {
                    if !tree.contains_key(path) {
                        return err(format!("environment variable \"{name}\" refers to missing resource \"{path}\""));
                    }
                }
                EnvValue::Unset {} => {}
            }
        }
        Ok(())
    }

    fn check_value(&self, what: &str, value: &OsValue) -> Result<(), ManifestError> {
        if value.contains_nul() {
            return err(format!("{what} \"{value}\" contains a NUL character"));
        }
        if !value.representable_on(&self.platform.os) {
            return err(format!("{what} \"{value}\" cannot be represented on {}", self.platform.os));
        }
        Ok(())
    }
}

/// Result of checking the resource tree.
struct Tree<'a> {
    nodes: HashMap<&'a ResourcePath, Node<'a>>,
    used_blobs: HashSet<Digest>,
}

/// Checks the shape of a resource list on its own: paths valid under
/// `rules` (plus the rules of `os`), sorted and unique, parents declared as
/// directories, no names that differ only by case where file systems ignore
/// case, and symlinks resolving inside the bundle. Content (blob)
/// references are not checked. Builders use this to reject a bad tree
/// before writing any content.
pub fn validate_tree(resources: &[Resource], os: &str, rules: NameRules) -> Result<(), ManifestError> {
    let rules = rules.stricter(NameRules::for_os(os));
    let tree = validate_resources(resources, rules, folds_case(os) || rules == NameRules::Windows, None)?;
    validate_symlinks(resources, &tree.nodes)
}

/// `fold_case`: the bundle is for a file system that ignores case, where
/// names that differ only by case would be the same file. Elsewhere they
/// are distinct (Linux software such as the terminfo database has them);
/// extraction creates every entry exclusively, so if it happens on a file
/// system that ignores case after all, it fails rather than overwrite.
fn validate_resources<'a>(
    resources: &'a [Resource],
    rules: NameRules,
    fold_case: bool,
    blobs: Option<&HashMap<Digest, &Blob>>,
) -> Result<Tree<'a>, ManifestError> {
    let mut nodes: HashMap<&ResourcePath, Node<'_>> = HashMap::new();
    let mut folded: HashMap<Vec<u8>, &ResourcePath> = HashMap::new();
    let mut used_blobs = HashSet::new();
    let mut previous: Option<&ResourcePath> = None;

    for resource in resources {
        let path = resource.path();
        path.validate(rules).map_err(|e| ManifestError(e.to_string()))?;
        if let Some(prev) = previous {
            if prev >= path {
                return err(format!(
                    "resources must be sorted by path without duplicates (\"{path}\" follows \"{prev}\")"
                ));
            }
        }
        previous = Some(path);

        if let Some(parent) = path.parent() {
            match nodes.get(&parent) {
                Some(Node::Dir) => {}
                Some(_) => {
                    return err(format!("\"{parent}\" is not a directory but contains \"{path}\""));
                }
                None => {
                    return err(format!("parent directory \"{parent}\" of \"{path}\" is not declared"));
                }
            }
        }
        if let Some(other) = folded.insert(path.fold_key(), path).filter(|_| fold_case) {
            return err(format!(
                "resources \"{other}\" and \"{path}\" differ only by case and would collide on case-insensitive file systems"
            ));
        }

        let node = match resource {
            Resource::Dir { .. } => Node::Dir,
            Resource::File { size, sha256, executable, .. } => {
                if let Some(blobs) = blobs {
                    let Some(blob) = blobs.get(sha256) else {
                        return err(format!("file \"{path}\" refers to missing content {sha256}"));
                    };
                    if blob.size != *size {
                        return err(format!("file \"{path}\" size {size} does not match its content"));
                    }
                    used_blobs.insert(*sha256);
                }
                Node::File { executable: *executable }
            }
            Resource::Symlink { target, .. } => Node::Symlink(target),
        };
        nodes.insert(path, node);
    }
    Ok(Tree { nodes, used_blobs })
}

/// Where a symbolic link of a bundle leads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedLink {
    /// The index of the link in the resources.
    pub index: usize,
    /// The resource it resolves to, following every link on the way.
    pub target: ResourcePath,
    /// Whether that resource is a directory (otherwise a file).
    pub is_dir: bool,
}

/// Resolves every symbolic link of a validated resource list, as
/// [`validate_tree`] does. Where links cannot be created as such (Windows
/// without the privilege), they are materialized from this: a junction to a
/// directory, a hard link to a file.
pub fn resolve_links(resources: &[Resource]) -> Result<Vec<ResolvedLink>, ManifestError> {
    let mut nodes = HashMap::with_capacity(resources.len());
    for resource in resources {
        let node = match resource {
            Resource::Dir { .. } => Node::Dir,
            Resource::File { executable, .. } => Node::File { executable: *executable },
            Resource::Symlink { target, .. } => Node::Symlink(target),
        };
        nodes.insert(resource.path(), node);
    }
    let tree = IndexedTree::build(resources, &nodes)?;
    let mut resolver = LinkResolver { tree: &tree, memo: HashMap::new() };
    let mut links = Vec::new();
    for (index, resource) in resources.iter().enumerate() {
        if let Resource::Symlink { path, target } = resource {
            let id = resolver
                .resolve(index + 1, 0)
                .map_err(|reason| ManifestError(format!("symlink \"{path}\" -> \"{}\": {reason}", target.display())))?;
            links.push(ResolvedLink {
                index,
                target: resources[id - 1].path().clone(),
                is_dir: matches!(tree.kinds[id], Node::Dir),
            });
        }
    }
    Ok(links)
}

fn validate_symlinks(resources: &[Resource], tree: &HashMap<&ResourcePath, Node<'_>>) -> Result<(), ManifestError> {
    if !resources.iter().any(|r| matches!(r, Resource::Symlink { .. })) {
        return Ok(());
    }
    let indexed = IndexedTree::build(resources, tree)?;
    let mut resolver = LinkResolver { tree: &indexed, memo: HashMap::new() };
    for (id, resource) in resources.iter().enumerate() {
        if let Resource::Symlink { path, target } = resource {
            resolver
                .resolve(id + 1, 0)
                .map_err(|reason| ManifestError(format!("symlink \"{path}\" -> \"{}\": {reason}", target.display())))?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Node<'a> {
    Dir,
    File { executable: bool },
    Symlink(&'a LinkTarget),
}

/// Id of the bundle root in an [`IndexedTree`].
const ROOT: usize = 0;

/// The validated resource tree with nodes addressed by id (the root is 0,
/// resource `i` is `i + 1`), so that walking a path costs one hash lookup
/// per component, independent of the path's length.
struct IndexedTree<'a> {
    kinds: Vec<Node<'a>>,
    parents: Vec<usize>,
    children: HashMap<(usize, &'a [u8]), usize>,
}

impl<'a> IndexedTree<'a> {
    fn build(
        resources: &'a [Resource],
        nodes: &HashMap<&'a ResourcePath, Node<'a>>,
    ) -> Result<IndexedTree<'a>, ManifestError> {
        let mut tree = IndexedTree {
            kinds: Vec::with_capacity(resources.len() + 1),
            parents: Vec::with_capacity(resources.len() + 1),
            children: HashMap::with_capacity(resources.len()),
        };
        tree.kinds.push(Node::Dir);
        tree.parents.push(ROOT);
        let mut ids: HashMap<&'a [u8], usize> = HashMap::with_capacity(resources.len());
        for resource in resources {
            let path = resource.path();
            let bytes = path.as_bytes();
            let (parent, name) = match bytes.iter().rposition(|&b| b == b'/') {
                Some(i) => {
                    let parent = ids.get(&bytes[..i]).copied();
                    (
                        parent.ok_or_else(|| ManifestError(format!("parent of \"{path}\" is not declared")))?,
                        &bytes[i + 1..],
                    )
                }
                None => (ROOT, bytes),
            };
            let id = tree.kinds.len();
            let kind = nodes.get(path).copied().ok_or_else(|| ManifestError("inconsistent resource tree".into()))?;
            tree.kinds.push(kind);
            tree.parents.push(parent);
            tree.children.insert((parent, name), id);
            ids.insert(bytes, id);
        }
        Ok(tree)
    }
}

/// Resolves symlinks against the bundle tree exactly as the kernel would
/// after extraction (`..` applies to the resolved location), refusing any
/// resolution that leaves the bundle, ends at the root, or dangles.
struct LinkResolver<'t, 'a> {
    tree: &'t IndexedTree<'a>,
    /// Links already resolved: each link resolves to a fixed node, so
    /// memoizing keeps the work linear even for adversarial link graphs.
    memo: HashMap<usize, usize>,
}

impl LinkResolver<'_, '_> {
    fn resolve(&mut self, link: usize, depth: usize) -> Result<usize, &'static str> {
        if let Some(&done) = self.memo.get(&link) {
            return Ok(done);
        }
        if depth >= MAX_SYMLINK_DEPTH {
            return Err("too many levels of symbolic links");
        }
        let Node::Symlink(target) = self.tree.kinds[link] else {
            return Err("not a symbolic link");
        };
        let mut current = self.tree.parents[link];
        let parts: Vec<&[u8]> = target.components().collect();
        for (i, part) in parts.iter().enumerate() {
            let last = i + 1 == parts.len();
            match *part {
                b"." => {}
                b".." => {
                    if current == ROOT {
                        return Err("target escapes the bundle root");
                    }
                    current = self.tree.parents[current];
                }
                name => {
                    let Some(&child) = self.tree.children.get(&(current, name)) else {
                        return Err("target does not exist in the bundle");
                    };
                    current = match self.tree.kinds[child] {
                        Node::Dir => child,
                        Node::File { .. } if last => child,
                        Node::File { .. } => return Err("target traverses a regular file"),
                        Node::Symlink(_) => {
                            let resolved = self.resolve(child, depth + 1)?;
                            if !last && !matches!(self.tree.kinds[resolved], Node::Dir) {
                                return Err("target traverses a non-directory");
                            }
                            resolved
                        }
                    };
                }
            }
        }
        if current == ROOT {
            return Err("target resolves to the bundle root");
        }
        self.memo.insert(link, current);
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> Digest {
        Digest([n; 32])
    }

    fn rp(s: &str) -> ResourcePath {
        ResourcePath::new(s).unwrap()
    }

    fn base() -> Manifest {
        Manifest {
            format: FORMAT_VERSION,
            generator: "bound test".into(),
            platform: Platform { os: "linux".into(), arch: "x86_64".into(), binary_format: "elf".into() },
            launcher: RegionInfo { size: 1000, sha256: digest(0) },
            payload: RegionInfo { size: 0, sha256: digest(0) },
            target: Target::External { program: "grep".into() },
            args: vec![ArgTemplate::Literal { value: "-n".into() }, ArgTemplate::RuntimeArgs],
            env: vec![],
            cwd: CwdMode::Inherit,
            bundle: BundleMode::Private,
            resources: vec![],
            blobs: vec![],
        }
    }

    fn with_files(files: &[(&str, u8)]) -> Manifest {
        let mut m = base();
        let mut offset = 0;
        let mut dirs = std::collections::BTreeSet::new();
        for (path, id) in files {
            for a in rp(path).ancestors() {
                dirs.insert(a);
            }
            if m.blob(&digest(*id)).is_none() {
                m.blobs.push(Blob {
                    sha256: digest(*id),
                    size: 10,
                    offset,
                    stored_size: 10,
                    compression: Compression::Stored,
                });
                offset += 10;
            }
        }
        for d in dirs {
            m.resources.push(Resource::Dir { path: d });
        }
        for (path, id) in files {
            m.resources.push(Resource::File { path: rp(path), size: 10, sha256: digest(*id), executable: false });
        }
        m.resources.sort_by(|a, b| a.path().cmp(b.path()));
        m.payload.size = offset;
        m
    }

    fn payload_len(m: &Manifest) -> u64 {
        m.blobs.iter().map(|b| b.stored_size).sum()
    }

    fn check(m: &Manifest) -> Result<(), ManifestError> {
        m.validate(payload_len(m), NameRules::Portable)
    }

    #[test]
    fn valid_manifests_pass_and_round_trip() {
        let mut m = with_files(&[("a/b.txt", 1), ("a/c.txt", 1), ("d.txt", 2)]);
        m.args.push(ArgTemplate::Resource { path: rp("d.txt") });
        m.env.push(EnvBinding { name: "CONFIG".into(), value: EnvValue::Resource { path: rp("a/b.txt") } });
        check(&m).unwrap();
        let decoded = Manifest::decode(&m.encode()).unwrap();
        assert_eq!(decoded, m);
        assert!(decoded.needs_root());
        assert!(!base().needs_root());
    }

    #[test]
    fn json_shape_is_stable() {
        // The form `bound inspect --json` shows.
        let json = serde_json::to_string_pretty(&base()).unwrap();
        assert!(json.contains(r#""mode": "external""#), "{json}");
        assert!(json.contains(r#""type": "runtime_args""#), "{json}");
        assert!(json.contains(r#""cwd": "inherit""#), "{json}");
        assert!(json.contains(r#""bundle": "private""#), "{json}");
    }

    #[test]
    fn case_folding_catches_sigma_and_sharp_s() {
        for (a, b) in [("ας", "ασ"), ("straße", "strasse"), ("README", "readme"), ("Ünï", "üNÏ")] {
            assert_eq!(rp(a).fold_key(), rp(b).fold_key(), "{a} / {b}");
        }
        assert_ne!(rp("a").fold_key(), rp("b").fold_key());
        let mut m = with_files(&[("ας", 1), ("ασ", 2)]);
        m.platform.os = "macos".into();
        assert!(check(&m).unwrap_err().0.contains("differ only by case"));
    }

    #[test]
    fn windows_programs_cannot_be_shadowed_by_exe_siblings() {
        let mut m = with_files(&[("tool", 1), ("TOOL.EXE", 2)]);
        for resource in &mut m.resources {
            if let Resource::File { executable, .. } = resource {
                *executable = true;
            }
        }
        m.target = Target::Embedded { resource: rp("tool") };
        check(&m).unwrap();
        m.platform = Platform { os: "windows".into(), arch: "x86_64".into(), binary_format: "pe".into() };
        assert!(check(&m).unwrap_err().0.contains("shadowed"));
        m.target = Target::Embedded { resource: rp("TOOL.EXE") };
        check(&m).unwrap();
    }

    #[test]
    fn structural_errors() {
        let good = with_files(&[("a/b.txt", 1), ("c.txt", 2)]);
        check(&good).unwrap();

        let mut unsorted = good.clone();
        unsorted.resources.reverse();
        assert!(check(&unsorted).is_err());

        let mut missing_parent = good.clone();
        missing_parent.resources.retain(|r| r.path().as_str() != Some("a"));
        assert!(check(&missing_parent).unwrap_err().0.contains("not declared"));

        let mut wrong_size = good.clone();
        if let Resource::File { size, .. } = &mut wrong_size.resources[1] {
            *size = 11;
        }
        assert!(check(&wrong_size).is_err());

        let mut gap = good.clone();
        gap.blobs[1].offset += 1;
        gap.payload.size += 1;
        assert!(
            gap.validate(payload_len(&good) + 1, NameRules::Portable).unwrap_err().0.contains("previous blob ends")
        );

        assert!(good.validate(payload_len(&good) + 1, NameRules::Portable).is_err());

        let mut unused = good.clone();
        unused.blobs.push(Blob {
            sha256: digest(9),
            size: 1,
            offset: 20,
            stored_size: 1,
            compression: Compression::Stored,
        });
        unused.payload.size = 21;
        assert!(unused.validate(21, NameRules::Portable).unwrap_err().0.contains("not used"));

        let mut bomb = good.clone();
        bomb.blobs[0].compression = Compression::Zstd;
        bomb.blobs[0].size = u64::MAX;
        assert!(check(&bomb).is_err());

        let mut version = good.clone();
        version.format = 2;
        assert!(check(&version).is_err());
    }

    #[test]
    fn case_collisions_are_rejected_where_file_systems_ignore_case() {
        for files in [&[("Readme", 1), ("readme", 2)][..], &[("Dir/x", 1), ("dir/y", 2)]] {
            let mut m = with_files(files);
            // Distinct files on Linux...
            check(&m).unwrap();
            // ...the same file on macOS and Windows,
            for os in ["macos", "windows"] {
                m.platform.os = os.into();
                assert!(check(&m).unwrap_err().0.contains("differ only by case"), "{os} {files:?}");
            }
            // and wherever a reader materializes with Windows rules.
            m.platform.os = "linux".into();
            assert!(m.validate(payload_len(&m), NameRules::Windows).is_err());
            assert!(validate_tree(&m.resources, "macos", NameRules::Portable).is_err());
            validate_tree(&m.resources, "linux", NameRules::Portable).unwrap();
        }
    }

    #[test]
    fn windows_names_depend_on_rules() {
        let m = with_files(&[("con.txt", 1)]);
        check(&m).unwrap();
        assert!(m.validate(10, NameRules::Windows).is_err());
        let mut windows = m.clone();
        windows.platform.os = "windows".into();
        assert!(check(&windows).is_err(), "target platform rules must apply too");
    }

    #[test]
    fn target_args_and_env_rules() {
        let mut m = with_files(&[("bin/tool", 1)]);
        m.target = Target::Embedded { resource: rp("bin/tool") };
        assert!(check(&m).unwrap_err().0.contains("not marked executable"));
        if let Resource::File { executable, .. } = &mut m.resources[1] {
            *executable = true;
        }
        check(&m).unwrap();
        m.target = Target::Embedded { resource: rp("bin") };
        assert!(check(&m).is_err());

        let mut twice = base();
        twice.args.push(ArgTemplate::RuntimeArgs);
        assert!(check(&twice).unwrap_err().0.contains("only once"));

        let mut dangling = base();
        dangling.args.push(ArgTemplate::Resource { path: rp("nope") });
        assert!(check(&dangling).is_err());

        let mut nul = base();
        nul.args.push(ArgTemplate::Literal { value: "a\0b".into() });
        assert!(check(&nul).is_err());

        let mut empty_program = base();
        empty_program.target = Target::External { program: "".into() };
        assert!(check(&empty_program).is_err());

        let env = |name: &str| EnvBinding { name: name.into(), value: EnvValue::Literal { value: "x".into() } };
        let mut dup = base();
        dup.env = vec![env("Path"), env("PATH")];
        assert!(check(&dup).unwrap_err().0.contains("more than once"));
        let mut reserved = base();
        reserved.env = vec![env("bound_root")];
        assert!(check(&reserved).unwrap_err().0.contains("reserved"));
        for bad in ["", "A=B"] {
            let mut m = base();
            m.env = vec![env(bad)];
            assert!(check(&m).is_err(), "{bad:?}");
        }

        let mut windows = base();
        windows.platform.os = "windows".into();
        windows.args.push(ArgTemplate::Literal { value: OsValue::UnixBytes(vec![0xff]) });
        assert!(check(&windows).is_err());
    }

    fn with_links(files: &[&str], dirs: &[&str], links: &[(&str, &str)]) -> Manifest {
        let mut m = with_files(&files.iter().map(|f| (*f, 1)).collect::<Vec<_>>());
        for d in dirs {
            m.resources.push(Resource::Dir { path: rp(d) });
        }
        for (path, target) in links {
            m.resources
                .push(Resource::Symlink { path: rp(path), target: LinkTarget::from_bytes(target.as_bytes()).unwrap() });
        }
        m.resources.sort_by(|a, b| a.path().cmp(b.path()));
        m.resources.dedup_by(|a, b| a.path() == b.path());
        m
    }

    #[test]
    fn symlinks_inside_the_bundle_are_accepted() {
        let m = with_links(
            &["lib/libfoo.so.1", "share/data.txt"],
            &["bin"],
            &[
                ("lib/libfoo.so", "libfoo.so.1"),
                ("bin/data", "../share/data.txt"),
                ("bin/lib", "../lib"),
                ("bin/via", "lib/libfoo.so"),
                ("share/self", "."),
            ],
        );
        check(&m).unwrap();
    }

    #[test]
    fn escaping_or_broken_symlinks_are_rejected() {
        let cases: &[(&[(&str, &str)], &str)] = &[
            (&[("up", "..")], "escapes"),
            (&[("d/up", "../..")], "escapes"),
            (&[("d/x", "../../etc/passwd")], "escapes"),
            (&[("root", ".")], "root"),
            (&[("d/r", "..")], "root"),
            (&[("dangling", "nope")], "does not exist"),
            (&[("d/through", "f/x")], "traverses a regular file"),
            (&[("a", "b"), ("b", "a")], "too many levels"),
            (&[("d/self", "."), ("d/esc", "self/../../..")], "escapes"),
        ];
        for (links, expected) in cases {
            let m = with_links(&["d/f"], &["d"], links);
            let e = check(&m).expect_err(&format!("{links:?} should fail"));
            assert!(e.0.contains(expected), "{links:?}: {e}");
        }
        // Windows bundles have links too (materialized as junctions or hard
        // links where symbolic links need a privilege).
        let m = with_links(&["x"], &[], &[("l", "x")]);
        let mut windows = m.clone();
        windows.platform.os = "windows".into();
        check(&windows).unwrap();
    }

    #[test]
    fn links_resolve_through_other_links() {
        let m =
            with_links(&["d/f", "e/g"], &["d", "e"], &[("d/up", "../e"), ("l", "d/up"), ("m", "l/g"), ("n", "d/f")]);
        check(&m).unwrap();
        let resolved: Vec<(String, String, bool)> = resolve_links(&m.resources)
            .unwrap()
            .into_iter()
            .map(|link| (m.resources[link.index].path().display(), link.target.display(), link.is_dir))
            .collect();
        let expected = [("d/up", "e", true), ("l", "e", true), ("m", "e/g", false), ("n", "d/f", false)];
        assert_eq!(resolved, expected.map(|(a, b, dir)| (a.to_owned(), b.to_owned(), dir)).to_vec(),);
    }

    #[test]
    fn symlinks_cannot_be_parents() {
        let mut m = with_links(&["d/f"], &["d"], &[("l", "d")]);
        m.resources.push(Resource::Dir { path: rp("l/sub") });
        m.resources.sort_by(|a, b| a.path().cmp(b.path()));
        assert!(check(&m).unwrap_err().0.contains("is not a directory"));
    }

    #[test]
    fn deep_link_targets_resolve_in_linear_time() {
        // A 1000-level directory chain and many links walking all of it.
        let depth = 1000;
        let mut path = String::from("d");
        let mut dirs = vec![path.clone()];
        for _ in 1..depth {
            path.push_str("/d");
            dirs.push(path.clone());
        }
        let deep_target = vec!["d"; depth].join("/");
        let mut m = with_files(&[]);
        for d in &dirs {
            m.resources.push(Resource::Dir { path: rp(d) });
        }
        for i in 0..300 {
            m.resources.push(Resource::Symlink {
                path: rp(&format!("link{i}")),
                target: LinkTarget::from_bytes(deep_target.as_bytes()).unwrap(),
            });
        }
        m.resources.sort_by(|a, b| a.path().cmp(b.path()));
        let start = std::time::Instant::now();
        check(&m).unwrap();
        assert!(start.elapsed() < std::time::Duration::from_secs(2), "{:?}", start.elapsed());
    }

    #[test]
    fn adversarial_link_graphs_resolve_quickly() {
        // Each link traverses the previous one several times; without
        // memoization this would take exponential time.
        let mut links = vec![("l0".to_string(), "d".to_string())];
        for i in 1..30 {
            let prev = format!("l{}", i - 1);
            links.push((format!("l{i}"), format!("{prev}/../{prev}/../{prev}")));
        }
        let links: Vec<(&str, &str)> = links.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let m = with_links(&["d/f"], &["d"], &links);
        let start = std::time::Instant::now();
        let _ = check(&m);
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
}
