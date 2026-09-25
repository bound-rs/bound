//! Creating artifacts (`bound build`).
//!
//! A build partially applies a process invocation: it records the program,
//! the argument template, environment bindings and working-directory mode in
//! a manifest, bundles the referenced files, and appends everything to a
//! native launcher.

mod output;
mod resources;
mod template;

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use bound_format::osvalue::{split_once_ascii, strip_ascii_prefix};
use bound_format::{
    ArgTemplate, BundleMode, CwdMode, Digest, EnvBinding, EnvValue, FORMAT_VERSION, LinkTarget, Manifest, NameRules,
    OsValue, Platform, RegionInfo, ResourcePath, Target,
};
use bound_platform::process;

pub use output::{has_exe_extension, output_name};
pub use resources::{Entry, Placement, ResourceSet, default_placement};
pub use template::{ArgSpec, EnvSpec, EnvSpecValue, parse_arg, parse_args, parse_env};

use crate::error::{CliError, fail};
use crate::launcher;

/// Everything `bound build` was asked to do.
#[derive(Debug, Clone)]
pub struct BuildRequest {
    pub output: Option<PathBuf>,
    pub force: bool,
    pub embed_program: bool,
    /// Where to place the embedded program in the bundle (default: as
    /// `--include` would place it).
    pub program_as: Option<String>,
    pub includes: Vec<PathBuf>,
    /// `DEST=SOURCE` pairs (see [`Source`]).
    pub includes_as: Vec<OsString>,
    /// Files listing `DEST=SOURCE` pairs, one per line.
    pub include_lists: Vec<PathBuf>,
    pub env: Vec<OsString>,
    /// Variables to remove from the inherited environment.
    pub unset: Vec<OsString>,
    pub cwd: CwdMode,
    pub bundle: BundleMode,
    pub launcher: Option<PathBuf>,
    /// The program followed by its arguments.
    pub command: Vec<OsString>,
}

/// A non-fatal message about the build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Diagnostic {
    Warning(String),
    Note(String),
}

/// The result of a successful build.
#[derive(Debug)]
pub struct BuildOutcome {
    pub output: PathBuf,
    pub size: u64,
    pub manifest: Manifest,
    pub diagnostics: Vec<Diagnostic>,
}

/// Builds an artifact.
pub fn build(request: &BuildRequest) -> Result<BuildOutcome, CliError> {
    let mut diagnostics = Vec::new();
    let Some(requested_output) = &request.output else {
        return Err(CliError::new("output path is required").with_hint("pass -o OUTPUT"));
    };
    let Some((program, program_args)) = request.command.split_first() else {
        return Err(CliError::new("no program given").with_hint("usage: bound -o OUTPUT -- PROGRAM [ARGS]..."));
    };
    let program = parse_program(program)?;

    let launcher = launcher::find(request.launcher.as_deref())?;
    let platform = launcher.platform.clone();
    let mut resources =
        ResourceSet::new(NameRules::for_os(&platform.os), bound_format::names::folds_case(&platform.os));
    // Windows file systems have no executable bits to preserve.
    resources.detect_executables(cfg!(windows) && !platform.is_windows());

    let target = match &program {
        Program::Bundled(path) => {
            if request.embed_program {
                return fail(format!(
                    "the program @bundle:{path} is already in the bundle; --embed-program and --embed-program-as bundle a program from disk"
                ));
            }
            Target::Embedded { resource: path.clone() }
        }
        Program::Named(name) if request.embed_program => {
            embed_program(name, request.program_as.as_deref(), &platform, &mut resources, &mut diagnostics)?
        }
        Program::Named(name) => external_program(name, &platform, &mut diagnostics),
    };

    // `@bundle:` references, checked once everything is bundled.
    let mut references = Vec::new();
    let mut args = Vec::new();
    for spec in parse_args(program_args)? {
        args.push(match spec {
            ArgSpec::Literal(value) => ArgTemplate::Literal { value: OsValue::from_os_str(&value) },
            ArgSpec::RuntimeArgs => ArgTemplate::RuntimeArgs,
            ArgSpec::File(path) => ArgTemplate::Resource { path: add_file_reference(&mut resources, &path)? },
            ArgSpec::Bundled(path) => {
                references.push(path.clone());
                ArgTemplate::Resource { path }
            }
        });
    }

    let mut env = Vec::new();
    let mut names = HashSet::new();
    for raw in &request.env {
        let spec = parse_env(raw)?;
        let name = OsValue::from_os_str(&spec.name);
        if !names.insert(name.fold_key()) {
            return fail(format!(
                "environment variable {name} is set more than once (names are compared case-insensitively)"
            ));
        }
        let value = match spec.value {
            EnvSpecValue::Literal(value) => EnvValue::Literal { value: OsValue::from_os_str(&value) },
            EnvSpecValue::File(path) => EnvValue::Resource { path: add_file_reference(&mut resources, &path)? },
            EnvSpecValue::Bundled(path) => {
                references.push(path.clone());
                EnvValue::Resource { path }
            }
        };
        env.push(EnvBinding { name, value });
    }
    for raw in &request.unset {
        let name = parse_unset(raw)?;
        if !names.insert(name.fold_key()) {
            return fail(format!(
                "environment variable {name} is set or unset more than once (names are compared case-insensitively)"
            ));
        }
        env.push(EnvBinding { name, value: EnvValue::Unset {} });
    }

    for path in &request.includes {
        resources.add_path(path, None, &format!("--include {}", path.display()))?;
    }
    for spec in &request.includes_as {
        let origin = format!("--include-as {}", spec.to_string_lossy());
        let (placement, source) = parse_include_as(spec, &origin)?;
        add_source(&mut resources, placement, source, &origin)?;
    }
    for list in &request.include_lists {
        add_include_list(&mut resources, list)?;
    }
    for path in &references {
        if !resources.contains(path) {
            return Err(CliError::new(format!("@bundle:{path}: nothing is bundled there"))
                .with_hint("bundle it with --include, --include-as or --include-list"));
        }
    }
    if let Program::Bundled(path) = &program {
        resources
            .mark_program(path)
            .map_err(|e| e.with_hint("bundle the program with --include-as or --include-list"))?;
        if platform.is_windows() {
            check_windows_program(path, &mut diagnostics)?;
        }
    }

    // Reject a bad tree (e.g. a symlink escaping the bundle) before
    // spending time compressing content.
    bound_format::manifest::validate_tree(&resources.preview(), &platform.os, NameRules::Portable)
        .map_err(|e| CliError::new(format!("invalid bundle: {e}")))?;

    let plan =
        output::plan(requested_output, &platform, request.force, resources.inputs(), &launcher.path, &mut diagnostics)?;

    let placeholder = RegionInfo { size: 0, sha256: Digest([0; 32]) };
    let manifest = Manifest {
        format: FORMAT_VERSION,
        generator: format!("bound {}", env!("CARGO_PKG_VERSION")),
        platform,
        launcher: placeholder.clone(),
        payload: placeholder,
        target,
        args,
        env,
        cwd: request.cwd,
        bundle: request.bundle,
        resources: Vec::new(),
        blobs: Vec::new(),
    };
    if manifest.bundle == BundleMode::Shared && resources.is_empty() && manifest.cwd != CwdMode::Bundle {
        diagnostics.push(Diagnostic::Warning(
            "--bundle shared has no effect: nothing is bundled, so there is no bundle directory".into(),
        ));
    }
    let (manifest, size) = output::write(&plan, &launcher, &resources, manifest)?;
    Ok(BuildOutcome { output: plan.path, size, manifest, diagnostics })
}

/// Bundles the target of an `@file:` reference and returns its place.
fn add_file_reference(resources: &mut ResourceSet, path: &Path) -> Result<ResourcePath, CliError> {
    let origin = format!("@file:{}", path.display());
    if !path.exists() {
        return fail(format!("{origin} does not exist"));
    }
    match resources.add_path(path, None, &origin)? {
        Placement::At(dest) => Ok(dest),
        Placement::Root => fail(format!("{origin} names the current directory; name a file or subdirectory")),
    }
}

/// What a `DEST=SOURCE` pair (of `--include-as` or an `--include-list`
/// file) bundles at `DEST`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// The file or directory tree at a path (followed if it is a link).
    Path(PathBuf),
    /// `@link:TARGET`: a symbolic link with this target.
    Link(LinkTarget),
    /// `@readlink:PATH`: a symbolic link with the target of the link at
    /// PATH (the link itself, not what it points to).
    ReadLink(PathBuf),
    /// `@dir`: a directory, empty unless something else is bundled in it.
    Dir,
}

const LINK_SOURCE: &str = "@link:";
const READLINK_SOURCE: &str = "@readlink:";
const DIR_SOURCE: &str = "@dir";

/// Parses a `DEST=SOURCE` pair (of `--include-as`, or a line of an
/// `--include-list` file, as `origin` says). `DEST` is a `/`-separated path
/// inside the bundle, or `.` for the bundle root. `SOURCE` is a path, or one
/// of the directives `@link:TARGET`, `@readlink:PATH` and `@dir`; `@@`
/// escapes a path that starts with `@`.
fn parse_include_as(spec: &OsStr, origin: &str) -> Result<(Placement, Source), CliError> {
    let Some((dest, source)) = split_once_ascii(spec, b'=') else {
        return fail(format!("{origin}: expected DEST=PATH"));
    };
    if source.is_empty() {
        return fail(format!("{origin}: PATH is empty"));
    }
    let Some(dest) = dest.to_str() else {
        return fail(format!("{origin}: DEST must be valid Unicode"));
    };
    let dest = dest.trim_end_matches('/');
    let placement = match dest {
        "" => return fail(format!("{origin}: DEST is empty (use . for the bundle root)")),
        "." => Placement::Root,
        _ => Placement::At(ResourcePath::new(dest).map_err(|e| CliError::new(format!("{origin}: {e}")))?),
    };
    let source = if let Some(path) = strip_ascii_prefix(&source, "@@") {
        let mut escaped = OsString::from("@");
        escaped.push(path);
        Source::Path(PathBuf::from(escaped))
    } else if let Some(target) = strip_ascii_prefix(&source, LINK_SOURCE) {
        let Some(target) = target.to_str() else {
            return fail(format!("{origin}: the link target must be valid Unicode"));
        };
        let target = LinkTarget::from_bytes(target.as_bytes()).map_err(|e| {
            CliError::new(format!("{origin}: {}", e.reason))
                .with_hint("a bundled link's target is relative to the link's directory and stays in the bundle")
        })?;
        Source::Link(target)
    } else if let Some(path) = strip_ascii_prefix(&source, READLINK_SOURCE) {
        if path.is_empty() {
            return fail(format!("{origin}: @readlink: needs the path of a symbolic link"));
        }
        Source::ReadLink(PathBuf::from(path))
    } else if source == DIR_SOURCE {
        Source::Dir
    } else {
        Source::Path(PathBuf::from(source))
    };
    if matches!(source, Source::Link(_) | Source::ReadLink(_)) && placement == Placement::Root {
        return fail(format!("{origin}: a link cannot be the bundle root"));
    }
    Ok((placement, source))
}

/// Bundles what a `DEST=SOURCE` pair names.
fn add_source(resources: &mut ResourceSet, placement: Placement, source: Source, origin: &str) -> Result<(), CliError> {
    match (placement, source) {
        (placement, Source::Path(path)) => resources.add_path(&path, Some(placement), origin).map(drop),
        (Placement::At(dest), Source::Link(target)) => resources.add_symlink(dest, target, origin),
        (Placement::At(dest), Source::ReadLink(path)) => resources.add_link(dest, &path, origin),
        (Placement::At(dest), Source::Dir) => resources.add_dir(dest),
        (Placement::Root, Source::Dir) => Ok(()),
        (Placement::Root, Source::Link(_) | Source::ReadLink(_)) => unreachable!("rejected when parsed"),
    }
}

/// Bundles every `DEST=SOURCE` line of an `--include-list` file. Relative
/// paths are relative to the current directory, as on the command line.
/// The list is for generated inputs too long for a command line, such as
/// the runfiles of a Bazel target.
fn add_include_list(resources: &mut ResourceSet, list: &Path) -> Result<(), CliError> {
    let text = std::fs::read(list)
        .map_err(|e| CliError::new(format!("--include-list {}: cannot read it: {e}", list.display())))?;
    let text = String::from_utf8(text)
        .map_err(|_| CliError::new(format!("--include-list {}: the file is not valid UTF-8", list.display())))?;
    for (number, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let origin = format!("--include-list {}, line {}", list.display(), number + 1);
        let (placement, source) = parse_include_as(OsStr::new(line), &origin)?;
        add_source(resources, placement, source, &origin)?;
    }
    Ok(())
}

/// The program of the invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Program {
    /// A program name or path (`@@` unescaped).
    Named(OsString),
    /// `@bundle:PATH`: a file that the includes bundle.
    Bundled(ResourcePath),
}

/// Parses the program, which takes the same directives as an argument
/// where they make sense.
fn parse_program(program: &OsStr) -> Result<Program, CliError> {
    if program.is_empty() {
        return fail("the program name is empty");
    }
    match parse_arg(program)? {
        ArgSpec::Literal(name) => Ok(Program::Named(name)),
        ArgSpec::Bundled(path) => Ok(Program::Bundled(path)),
        ArgSpec::File(path) => Err(CliError::new(format!("@file:{} cannot be the program", path.display()))
            .with_hint(format!("to bundle the program, use --embed-program -- {}", path.display()))),
        ArgSpec::RuntimeArgs => fail("@args cannot be the program"),
    }
}

/// Windows starts programs by file name, so a program in the bundle needs
/// an extension Windows can execute.
fn check_windows_program(path: &ResourcePath, diagnostics: &mut Vec<Diagnostic>) -> Result<(), CliError> {
    let name = String::from_utf8_lossy(path.file_name()).into_owned();
    let extension = Path::new(&name).extension().map(|e| e.to_string_lossy().to_ascii_lowercase());
    match extension.as_deref() {
        Some("exe" | "com" | "bat" | "cmd") => Ok(()),
        None => Err(CliError::new(format!("the program @bundle:{path} has no extension, so Windows cannot start it"))
            .with_hint("bundle it under a name ending in .exe")),
        Some(other) => {
            diagnostics.push(Diagnostic::Warning(format!(
                "Windows cannot start a .{other} file directly; make its interpreter the program instead"
            )));
            Ok(())
        }
    }
}

/// Parses the NAME of `--unset NAME`.
fn parse_unset(name: &OsStr) -> Result<OsValue, CliError> {
    let shown = name.to_string_lossy();
    if name.is_empty() || name.as_encoded_bytes().contains(&b'=') {
        return fail(format!("--unset \"{shown}\": not a variable name"));
    }
    if shown.eq_ignore_ascii_case(bound_format::manifest::BOUND_ROOT_ENV) {
        return fail("BOUND_ROOT is reserved: bound sets or removes it at run time");
    }
    Ok(OsValue::from_os_str(name))
}

fn external_program(program: &OsStr, platform: &Platform, diagnostics: &mut Vec<Diagnostic>) -> Target {
    let shown = program.to_string_lossy();
    if !process::is_bare_name(program) && !Path::new(program).is_absolute() {
        diagnostics.push(Diagnostic::Warning(format!(
            "program \"{shown}\" is a relative path and is not bundled; it will be resolved against the working directory each time the artifact runs (use --embed-program to bundle it)"
        )));
    } else if process::is_bare_name(program)
        && *platform == Platform::host()
        && process::find_in_path(program, std::env::var_os("PATH").as_deref()).is_none()
    {
        diagnostics.push(Diagnostic::Warning(format!(
            "program \"{shown}\" was not found in PATH on this machine; the artifact will look for it when it runs"
        )));
    }
    Target::External { program: OsValue::from_os_str(program) }
}

fn embed_program(
    program: &OsStr,
    program_as: Option<&str>,
    platform: &Platform,
    resources: &mut ResourceSet,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Target, CliError> {
    let shown = program.to_string_lossy();
    let source = if process::is_bare_name(program) {
        match process::find_in_path(program, std::env::var_os("PATH").as_deref()) {
            Some(found) => {
                diagnostics.push(Diagnostic::Note(format!("embedding {} (found in PATH)", found.display())));
                found
            }
            None => {
                let error = CliError::new(format!("cannot embed program \"{shown}\": not found in PATH"));
                let sep = std::path::MAIN_SEPARATOR;
                return Err(if Path::new(program).is_file() {
                    error.with_hint(format!("to embed the file in the current directory, write .{sep}{shown}"))
                } else {
                    error
                });
            }
        }
    } else {
        match std::fs::metadata(program) {
            Ok(meta) if meta.is_file() => PathBuf::from(program),
            Ok(_) => return fail(format!("cannot embed program \"{shown}\": not a regular file")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return fail(format!("cannot embed program \"{shown}\": file does not exist"));
            }
            Err(e) => return fail(format!("cannot embed program \"{shown}\": {e}")),
        }
    };

    let placement = match program_as.map(|dest| dest.trim_end_matches('/')) {
        None => default_placement(&source)?,
        Some("" | ".") => return fail("--embed-program-as needs a path in the bundle, such as bin/tool"),
        Some(dest) => Placement::At(
            ResourcePath::new(dest).map_err(|e| CliError::new(format!("--embed-program-as {dest}: {}", e.reason)))?,
        ),
    };
    let Placement::At(mut dest) = placement else {
        return fail(format!("cannot embed program \"{shown}\": not a file"));
    };
    if platform.is_windows() {
        dest = windows_program_name(dest, diagnostics)?;
    }
    describe_embedded(&source, platform, diagnostics);
    resources.add_program(&source, dest.clone())?;
    Ok(Target::Embedded { resource: dest })
}

/// Windows starts programs by file name: make sure the embedded program has
/// an extension Windows can execute.
fn windows_program_name(dest: ResourcePath, diagnostics: &mut Vec<Diagnostic>) -> Result<ResourcePath, CliError> {
    let name = String::from_utf8_lossy(dest.file_name()).into_owned();
    let extension = Path::new(&name).extension().map(|e| e.to_string_lossy().to_ascii_lowercase());
    match extension.as_deref() {
        Some("exe" | "com" | "bat" | "cmd") => Ok(dest),
        None => {
            let mut bytes = dest.as_bytes().to_vec();
            bytes.extend_from_slice(b".exe");
            let renamed = ResourcePath::from_bytes(&bytes).map_err(|e| CliError::new(e.to_string()))?;
            diagnostics.push(Diagnostic::Note(format!(
                "the embedded program is stored as \"{renamed}\" so that Windows can run it"
            )));
            Ok(renamed)
        }
        Some(other) => {
            diagnostics.push(Diagnostic::Warning(format!(
                "Windows cannot start a .{other} file directly; bind its interpreter as the program instead (for example: bound -o tool.exe -- INTERPRETER @file:{name})"
            )));
            Ok(dest)
        }
    }
}

/// Adds notes about what kind of program is being embedded.
fn describe_embedded(source: &Path, platform: &Platform, diagnostics: &mut Vec<Diagnostic>) {
    let Ok(mut file) = File::open(source) else { return };
    let mut header = Vec::with_capacity(4096);
    if (&mut file).take(4096).read_to_end(&mut header).is_err() {
        return;
    }
    if let Some(line) = header.strip_prefix(b"#!") {
        let line: Vec<u8> = line.iter().copied().take_while(|&b| b != b'\n' && b != b'\r').take(200).collect();
        diagnostics.push(Diagnostic::Note(format!(
            "the embedded program is a script (#!{}); its interpreter is not bundled and must exist where the artifact runs",
            String::from_utf8_lossy(&line).trim()
        )));
        return;
    }
    if bound_format::footer::has_magic(&mut file).unwrap_or(false) {
        diagnostics.push(Diagnostic::Note(
            "the embedded program is itself a bound artifact; it will run nested inside this one".to_owned(),
        ));
    }
    if let Some(found) = Platform::sniff(&header) {
        if found.os != platform.os || (found.arch != platform.arch && found.arch != "universal") {
            diagnostics.push(Diagnostic::Warning(format!(
                "the embedded program is a {found} executable, but the artifact is for {platform}"
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn include_as_specs() {
        let parse_include_as = |spec: &OsStr| parse_include_as(spec, "--include-as");
        let (placement, source) = parse_include_as(OsStr::new("assets/img=./build/images")).unwrap();
        assert_eq!(placement, Placement::At(ResourcePath::new("assets/img").unwrap()));
        assert_eq!(source, Source::Path(PathBuf::from("./build/images")));
        assert_eq!(parse_include_as(OsStr::new(".=dist")).unwrap().0, Placement::Root);
        assert_eq!(
            parse_include_as(OsStr::new("data/=x")).unwrap().0,
            Placement::At(ResourcePath::new("data").unwrap())
        );
        for bad in ["nodest", "=x", "d=", "../up=x", "..\\outside=x", "/abs=x", "a//b=x"] {
            assert!(parse_include_as(OsStr::new(bad)).is_err(), "{bad}");
        }
        let err = parse_include_as(OsStr::new("..\\outside=x")).unwrap_err();
        assert!(err.message.starts_with("--include-as: unsafe resource path \"..\\outside\""), "{}", err.message);

        // Directives, and the escape for paths that start with @.
        let source = |spec: &str| parse_include_as(OsStr::new(spec)).map(|(_, source)| source);
        assert_eq!(source("a/b=@link:../c").unwrap(), Source::Link(LinkTarget::from_bytes(b"../c").unwrap()));
        assert_eq!(source("a=@readlink:x/y").unwrap(), Source::ReadLink(PathBuf::from("x/y")));
        assert_eq!(source("a=@dir").unwrap(), Source::Dir);
        assert_eq!(source(".=@dir").unwrap(), Source::Dir);
        assert_eq!(source("a=@@dir").unwrap(), Source::Path(PathBuf::from("@dir")));
        assert_eq!(source("a=@types/x").unwrap(), Source::Path(PathBuf::from("@types/x")));
        assert_eq!(source("a=@directory").unwrap(), Source::Path(PathBuf::from("@directory")));
        for bad in ["a=@link:/etc/passwd", "a=@link:", "a=@readlink:", ".=@link:x", ".=@readlink:x"] {
            assert!(source(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn programs() {
        let named = |s: &str| Program::Named(OsString::from(s));
        assert_eq!(parse_program(OsStr::new("python3")).unwrap(), named("python3"));
        assert_eq!(parse_program(OsStr::new("@@bundle:x")).unwrap(), named("@bundle:x"));
        assert_eq!(parse_program(OsStr::new("@plain")).unwrap(), named("@plain"));
        assert_eq!(
            parse_program(OsStr::new("@bundle:python/bin/python3")).unwrap(),
            Program::Bundled(ResourcePath::new("python/bin/python3").unwrap())
        );
        for bad in ["", "@args", "@file:tool", "@bundle:", "@bundle:../x"] {
            assert!(parse_program(OsStr::new(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn bundled_windows_programs() {
        let mut diags = Vec::new();
        assert!(check_windows_program(&ResourcePath::new("python/python.exe").unwrap(), &mut diags).is_ok());
        assert!(check_windows_program(&ResourcePath::new("bin/tool.CMD").unwrap(), &mut diags).is_ok());
        assert!(diags.is_empty());
        let err = check_windows_program(&ResourcePath::new("bin/python3").unwrap(), &mut diags).unwrap_err();
        assert!(err.message.contains("has no extension"), "{}", err.message);
        check_windows_program(&ResourcePath::new("app/main.py").unwrap(), &mut diags).unwrap();
        assert!(matches!(diags.last(), Some(Diagnostic::Warning(w)) if w.contains(".py")));
    }

    #[test]
    fn windows_program_names() {
        let mut diags = Vec::new();
        let renamed = windows_program_name(ResourcePath::new("bin/tool").unwrap(), &mut diags).unwrap();
        assert_eq!(renamed.as_str(), Some("bin/tool.exe"));
        assert!(matches!(diags.last(), Some(Diagnostic::Note(_))));
        let kept = windows_program_name(ResourcePath::new("tool.CMD").unwrap(), &mut diags).unwrap();
        assert_eq!(kept.as_str(), Some("tool.CMD"));
        windows_program_name(ResourcePath::new("task.ps1").unwrap(), &mut diags).unwrap();
        assert!(matches!(diags.last(), Some(Diagnostic::Warning(w)) if w.contains(".ps1")));
    }
}
