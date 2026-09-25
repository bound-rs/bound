//! Explaining artifacts (`bound inspect`).
//!
//! Inspection reads the footer and manifest (validating both) and reports
//! what the artifact will run, with which arguments, environment and
//! working directory, which resources it carries, and what it still needs
//! from the destination system. It does not verify content hashes; that is
//! `bound verify`.

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};

use bound_format::exe::{self, SignatureKind};
use bound_format::footer::MagicScan;
use bound_format::manifest::BOUND_ROOT_ENV;
use bound_format::{
    ArgTemplate, ArtifactReader, BundleMode, CwdMode, Digest, EnvValue, FOOTER_LEN, Footer, FooterError, MAGIC,
    Manifest, NameRules, OsValue, Platform, ReadError, Resource, Target,
};
use serde::Serialize;

use crate::error::CliError;
use crate::style::size;

/// Version of the `bound inspect --json` document.
pub const INSPECT_JSON_VERSION: u32 = 1;

/// How many levels of nested artifacts are examined.
const MAX_NESTING: usize = 8;

/// Total size of the embedded programs examined for nested artifacts,
/// across all levels.
const MAX_NESTED_SCAN: u64 = 256 * 1024 * 1024;

/// Paths longer than this are not used to align the resource listing.
const MAX_LISTING_WIDTH: usize = 60;

/// A parsed artifact.
#[derive(Debug)]
pub struct Inspection {
    pub path: PathBuf,
    pub file_len: u64,
    pub footer: Footer,
    /// A platform code signature after the bound regions.
    pub signature: Option<SignatureInfo>,
    pub manifest: Manifest,
    /// If the embedded program is itself a bound artifact, its manifest.
    pub nested: Option<Box<Inspection>>,
    /// Whether nested artifacts were not examined because of the depth
    /// or size limits.
    pub nesting_limited: bool,
}

/// A platform code signature, as `inspect` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SignatureInfo {
    pub kind: SignatureKind,
    pub offset: u64,
    pub size: u64,
    /// Mach-O: whether it was made with a signing identity (`false` for an
    /// ad-hoc signature, such as the one bound gives every macOS artifact).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<bool>,
}

impl SignatureInfo {
    fn describe(&self) -> String {
        match (self.kind, self.identity) {
            (SignatureKind::MachO, Some(true)) => {
                "Mach-O, signed with an identity (check it with `codesign --verify --strict`)".into()
            }
            (SignatureKind::MachO, _) => {
                "Mach-O, ad hoc (sign for distribution with `codesign --sign IDENTITY --force`)".into()
            }
            (SignatureKind::Authenticode, _) => {
                "Authenticode (check it with `signtool verify /pa` or Get-AuthenticodeSignature)".into()
            }
        }
    }
}

/// Turns a read error into a user-facing message.
pub fn open_error(path: &Path, error: ReadError) -> CliError {
    match error {
        ReadError::Footer(FooterError::NotAnArtifact) => {
            CliError::new(format!("{} is not a bound artifact", path.display()))
        }
        ReadError::Footer(FooterError::UnsupportedVersion(version)) => {
            CliError::new(format!("unsupported bound artifact format version {version}"))
                .with_hint("the artifact was made by a newer bound; upgrade bound to read it")
        }
        other => CliError::new(format!("{}: {other}", path.display())),
    }
}

pub(crate) fn open_file(path: &Path) -> Result<BufReader<File>, CliError> {
    // Never blocks on a named pipe, and refuses anything but a file.
    bound_platform::fs::open_input(path, true, None).map(BufReader::new).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::new(format!("{} does not exist", path.display()))
        } else {
            CliError::new(format!("cannot open {}: {e}", path.display()))
        }
    })
}

pub fn inspect(path: &Path) -> Result<Inspection, CliError> {
    let reader = ArtifactReader::open(open_file(path)?, NameRules::Portable).map_err(|e| open_error(path, e))?;
    let mut budget = MAX_NESTED_SCAN;
    Ok(inspect_reader(path, reader, 0, &mut budget))
}

fn inspect_reader<R: Read + Seek>(
    path: &Path,
    mut reader: ArtifactReader<R>,
    depth: usize,
    budget: &mut u64,
) -> Inspection {
    let (nested, nesting_limited) = match nested_artifact(&mut reader, depth, budget) {
        Nested::Found(inner) => (Some(inner), false),
        Nested::None => (None, false),
        Nested::Limited => (None, true),
    };
    let signature = reader.signature().copied().map(|signature| {
        let identity = (signature.kind == SignatureKind::MachO)
            .then(|| reader.read_signature(1 << 20).is_ok_and(|blob| exe::macho_signature_has_identity(&blob)));
        SignatureInfo { kind: signature.kind, offset: signature.offset, size: signature.len, identity }
    });
    Inspection {
        path: path.to_path_buf(),
        file_len: reader.file_len(),
        footer: reader.footer().clone(),
        signature,
        manifest: reader.into_manifest(),
        nested,
        nesting_limited,
    }
}

enum Nested {
    Found(Box<Inspection>),
    None,
    /// Not examined: too deep, or the size budget is spent.
    Limited,
}

/// If the embedded program is a bound artifact, inspects it too (this is
/// how composed artifacts are explained, and the basis for future
/// flattening).
///
/// Memory use stays constant: the program is first streamed through a
/// [`MagicScan`], which keeps only the few bytes needed to recognize an
/// artifact; only a nested artifact is then extracted to a private
/// temporary file and opened from there. Nesting depth and the total size
/// examined are limited, so a crafted artifact cannot make inspection
/// recurse or extract without bound.
fn nested_artifact<R: Read + Seek>(reader: &mut ArtifactReader<R>, depth: usize, budget: &mut u64) -> Nested {
    let Target::Embedded { resource } = &reader.manifest().target else { return Nested::None };
    let resource = resource.clone();
    let Some(&Resource::File { sha256, size, .. }) = reader.manifest().resource(&resource) else {
        return Nested::None;
    };
    if size < MAGIC.len() as u64 {
        return Nested::None;
    }
    if depth >= MAX_NESTING || size > *budget {
        return Nested::Limited;
    }
    *budget -= size;
    let mut scan = MagicScan::new(size);
    let scanned = reader.open_blob(&sha256).and_then(|mut blob| io::copy(&mut blob, &mut scan));
    if scanned.is_err() || !scan.found() {
        return Nested::None;
    }
    if size > *budget {
        return Nested::Limited;
    }
    *budget -= size;
    extract_and_inspect(reader, &resource, &sha256, depth, budget).map_or(Nested::None, |i| Nested::Found(Box::new(i)))
}

fn extract_and_inspect<R: Read + Seek>(
    reader: &mut ArtifactReader<R>,
    resource: &bound_format::ResourcePath,
    sha256: &Digest,
    depth: usize,
    budget: &mut u64,
) -> Option<Inspection> {
    let dir = bound_platform::fs::create_private_dir(&bound_platform::fs::temp_base(), "bound-inspect-").ok()?;
    let _cleanup = RemoveOnDrop(dir.clone());
    let path = dir.join("program");
    let mut file = bound_platform::fs::create_new_file(&path, false).ok()?;
    io::copy(&mut reader.open_blob(sha256).ok()?, &mut file).ok()?;
    drop(file);
    let inner = ArtifactReader::open(File::open(&path).ok()?, NameRules::Portable).ok()?;
    Some(inspect_reader(&PathBuf::from(resource.display()), inner, depth + 1, budget))
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = bound_platform::fs::remove_tree(&self.0);
    }
}

/// The artifact's identity: the SHA-256 of its manifest, which in turn
/// pins the launcher, payload and every resource.
pub fn digest(inspection: &Inspection) -> Digest {
    inspection.footer.manifest_sha256
}

fn quote_arg(value: &OsValue) -> String {
    let text = value.display();
    if text.is_empty() || text.chars().any(|c| c.is_whitespace() || c == '"' || c == '\'') {
        format!("{text:?}")
    } else if text.starts_with('@') {
        // Shown as it would be written on the bound command line.
        format!("@{text}")
    } else {
        text
    }
}

/// One-line description of what an artifact runs.
pub fn summarize_target(manifest: &Manifest, nested: Option<&Inspection>) -> String {
    match (&manifest.target, nested) {
        (Target::External { program }, _) => format!("external program \"{}\"", program.display()),
        (Target::Embedded { resource }, Some(inner)) => format!(
            "embedded bound artifact \"{resource}\", which runs {}",
            summarize_target(&inner.manifest, inner.nested.as_deref())
        ),
        (Target::Embedded { resource }, None) => format!("embedded program \"{resource}\""),
    }
}

/// Programs the artifact needs from the destination system.
pub fn external_programs(inspection: &Inspection) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Some(inspection);
    while let Some(ins) = current {
        if let Target::External { program } = &ins.manifest.target {
            out.push(program.display());
        }
        current = ins.nested.as_deref();
    }
    out
}

/// Writes the human-readable report.
pub fn render(ins: &Inspection, out: &mut dyn Write) -> io::Result<()> {
    let m = &ins.manifest;
    let f = &ins.footer;
    let mut failure = None;
    let mut line = |s: String| {
        if failure.is_none() {
            if let Err(e) = out.write_all(s.as_bytes()).and_then(|()| out.write_all(b"\n")) {
                failure = Some(e);
            }
        }
    };

    line(format!("Bound artifact: {}", ins.path.display()));
    line(format!("Format: {} ({})", m.format, m.generator));
    line(format!("Platform: {} ({})", m.platform, m.platform.binary_format));
    let signature_size = ins.signature.map(|s| format!(", code signature {}", size(s.size))).unwrap_or_default();
    line(format!(
        "Size: {} (launcher {}, payload {}, manifest {}{signature_size})",
        size(ins.file_len),
        size(f.payload_offset),
        size(f.payload_len),
        size(f.manifest_len)
    ));
    line(format!("Digest: {}", digest(ins)));
    line(format!(
        "Code signature: {}",
        ins.signature
            .map_or_else(|| "none (sign it with the platform's tools; see docs/platforms.md)".into(), |s| s.describe())
    ));

    line("Target:".into());
    match &m.target {
        Target::External { program } => {
            line("  Mode: external (not bundled; resolved on the destination system)".into());
            line(format!("  Program: {}", program.display()));
        }
        Target::Embedded { resource } => {
            line("  Mode: embedded (bundled in this artifact)".into());
            line(format!("  Program: {resource}"));
            if let Some(inner) = &ins.nested {
                line(format!(
                    "  Nested: a bound artifact ({}) that runs {}",
                    digest(inner),
                    summarize_target(&inner.manifest, inner.nested.as_deref())
                ));
            }
            if ins.nesting_limited {
                line("  Nested: not examined (nesting too deep or too large)".into());
            }
        }
    }

    line("Arguments:".into());
    if m.args.is_empty() {
        line("  (none; run-time arguments are rejected)".into());
    }
    for arg in &m.args {
        line(format!(
            "  {}",
            match arg {
                ArgTemplate::Literal { value } => quote_arg(value),
                ArgTemplate::Resource { path } => format!("@file:{path}"),
                ArgTemplate::RuntimeArgs => "@args".to_owned(),
            }
        ));
    }

    line("Environment:".into());
    line("  (inherited from the caller, plus:)".into());
    for binding in &m.env {
        match &binding.value {
            EnvValue::Literal { value } => line(format!("  {}={}", binding.name.display(), quote_arg(value))),
            EnvValue::Resource { path } => line(format!("  {}=@file:{path}", binding.name.display())),
            EnvValue::Unset {} => line(format!("  {} (removed)", binding.name.display())),
        }
    }
    if m.needs_root() {
        line(format!("  {BOUND_ROOT_ENV}=<bundle directory>"));
    } else {
        line(format!("  {BOUND_ROOT_ENV} (removed; there is no bundle directory)"));
    }

    line("Working directory:".into());
    line(match m.cwd {
        CwdMode::Inherit => "  inherit".into(),
        CwdMode::Bundle => "  bundle (the bundle directory)".into(),
    });

    let files = m.resources.iter().filter(|r| matches!(r, Resource::File { .. })).count();
    let bytes: u64 = m.resources.iter().map(|r| if let Resource::File { size, .. } = r { *size } else { 0 }).sum();
    line(format!("Resources: {files} file(s), {}", size(bytes)));
    if m.resources.is_empty() {
        line("  (none)".into());
    }
    let width = m
        .resources
        .iter()
        .map(|r| r.path().display().chars().count() + 1)
        .filter(|&w| w <= MAX_LISTING_WIDTH)
        .max()
        .unwrap_or(0);
    for resource in &m.resources {
        match resource {
            Resource::Dir { path } => line(format!("  {:width$}  directory", format!("{path}/"))),
            Resource::File { path, size: n, sha256, executable } => line(format!(
                "  {:width$}  {:>10}  {}{sha256}",
                path.display(),
                size(*n),
                if *executable { "executable  " } else { "" }
            )),
            Resource::Symlink { path, target } => {
                line(format!("  {:width$}  symlink -> {}", path.display(), target.display()));
            }
        }
    }
    if m.needs_root() {
        line(match m.bundle {
            BundleMode::Private => "  materialized in a new private temporary directory on every run".into(),
            BundleMode::Shared => {
                "  materialized once in a read-only directory in the user's cache, shared by every run".into()
            }
        });
    }

    line("Requires on the destination system:".into());
    let programs = external_programs(ins);
    for program in &programs {
        line(format!("  program \"{program}\" (resolved when the artifact runs, e.g. through PATH)"));
    }
    if matches!(m.target, Target::Embedded { .. }) {
        line("  any shared libraries the embedded program loads (they are not bundled)".into());
    }
    if programs.is_empty() && !matches!(m.target, Target::Embedded { .. }) {
        line("  nothing beyond the operating system".into());
    }
    failure.map_or(Ok(()), Err)
}

#[derive(Serialize)]
struct Region {
    offset: u64,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<Digest>,
}

#[derive(Serialize)]
struct Regions {
    launcher: Region,
    payload: Region,
    manifest: Region,
    footer: Region,
}

#[derive(Serialize)]
struct Dependency {
    kind: &'static str,
    name: String,
}

#[derive(Serialize)]
struct InspectDocument<'a> {
    inspect_format: u32,
    path: OsValue,
    size: u64,
    digest: Digest,
    format: u16,
    generator: &'a str,
    platform: &'a Platform,
    regions: Regions,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_signature: Option<SignatureInfo>,
    target: &'a Target,
    #[serde(skip_serializing_if = "Option::is_none")]
    nested: Option<Box<InspectDocument<'a>>>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    nested_not_examined: bool,
    args: &'a [ArgTemplate],
    env: &'a [bound_format::EnvBinding],
    cwd: CwdMode,
    bundle: BundleMode,
    bundle_directory: bool,
    resources: &'a [Resource],
    external_dependencies: Vec<Dependency>,
}

fn document(ins: &Inspection) -> InspectDocument<'_> {
    let m = &ins.manifest;
    let f = &ins.footer;
    let external_dependencies = match &m.target {
        Target::External { program } => vec![Dependency { kind: "program", name: program.display() }],
        Target::Embedded { .. } => Vec::new(),
    };
    InspectDocument {
        inspect_format: INSPECT_JSON_VERSION,
        path: OsValue::from_os_str(ins.path.as_os_str()),
        size: ins.file_len,
        digest: f.manifest_sha256,
        format: m.format,
        generator: &m.generator,
        platform: &m.platform,
        regions: Regions {
            launcher: Region { offset: 0, size: f.payload_offset, sha256: Some(m.launcher.sha256) },
            payload: Region { offset: f.payload_offset, size: f.payload_len, sha256: Some(m.payload.sha256) },
            manifest: Region { offset: f.manifest_offset, size: f.manifest_len, sha256: Some(f.manifest_sha256) },
            footer: Region { offset: f.footer_offset(), size: FOOTER_LEN as u64, sha256: None },
        },
        code_signature: ins.signature,
        target: &m.target,
        nested: ins.nested.as_deref().map(|inner| Box::new(document(inner))),
        nested_not_examined: ins.nesting_limited,
        args: &m.args,
        env: &m.env,
        cwd: m.cwd,
        bundle: m.bundle,
        bundle_directory: m.needs_root(),
        resources: &m.resources,
        external_dependencies,
    }
}

/// Writes the stable JSON document (see `docs/format.md`).
pub fn render_json(ins: &Inspection, out: &mut dyn Write) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *out, &document(ins)).map_err(io::Error::from)?;
    out.write_all(b"\n")
}
