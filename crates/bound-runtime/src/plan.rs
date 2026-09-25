//! Turning a manifest into a concrete invocation.
//!
//! This step is pure: given the manifest, the bundle root (if any) and the
//! run-time arguments, it computes exactly what will be passed to the OS.
//! Arguments are kept as a vector end to end; no command string is ever
//! built and no shell is involved.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use bound_format::manifest::BOUND_ROOT_ENV;
use bound_format::{ArgTemplate, CwdMode, EnvValue, Manifest, ResourcePath, Target};

use crate::LaunchError;

/// Everything needed to start the target process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// The program: a name to look up, a relative path, or an absolute path.
    pub program: OsString,
    /// Arguments after the program name.
    pub args: Vec<OsString>,
    /// Variables to set, in order, on top of the inherited environment.
    pub env_set: Vec<(OsString, OsString)>,
    /// Variables to remove from the inherited environment.
    pub env_remove: Vec<OsString>,
    /// Working directory, or `None` to inherit the caller's.
    pub cwd: Option<PathBuf>,
}

impl Invocation {
    /// Builds the native command. Standard streams are inherited.
    pub fn command(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        self.configure(&mut cmd);
        cmd
    }

    /// Builds the native command for the program found at `path` by a
    /// `PATH` lookup. On Unix the program still receives its name as
    /// `argv[0]`, as with execvp(3).
    pub fn command_for(&self, path: &Path) -> Command {
        let mut cmd = Command::new(path);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.arg0(&self.program);
        }
        self.configure(&mut cmd);
        cmd
    }

    fn configure(&self, cmd: &mut Command) {
        cmd.args(&self.args);
        for name in &self.env_remove {
            cmd.env_remove(name);
        }
        for (name, value) in &self.env_set {
            cmd.env(name, value);
        }
        if let Some(dir) = &self.cwd {
            cmd.current_dir(dir);
        }
    }

    /// The `PATH` set by the artifact's own environment bindings, if any.
    pub fn path_override(&self) -> Option<&OsStr> {
        let is_path = |name: &OsStr| {
            if cfg!(windows) { name.eq_ignore_ascii_case("PATH") } else { name == "PATH" }
        };
        self.env_set.iter().rev().find(|(name, _)| is_path(name)).map(|(_, value)| value.as_os_str())
    }

    /// The `PATH` the child will see.
    pub fn child_path_var(&self) -> Option<OsString> {
        match self.path_override() {
            Some(value) => Some(value.to_os_string()),
            None => std::env::var_os("PATH"),
        }
    }
}

/// Resolves the manifest against a bundle root and run-time arguments.
///
/// * resource references become absolute native paths under `root`;
/// * the `runtime_args` element is replaced by `runtime_args` (if the
///   template has none, run-time arguments are an error);
/// * `BOUND_ROOT` is set to the root when there is one, and removed from
///   the inherited environment otherwise, so a nested artifact never sees
///   its parent's root;
/// * the working directory is inherited or set to the root.
pub fn plan(manifest: &Manifest, root: Option<&Path>, runtime_args: Vec<OsString>) -> Result<Invocation, LaunchError> {
    let resolve = |path: &ResourcePath| -> Result<OsString, LaunchError> {
        let root = root.ok_or(LaunchError::Internal("resource referenced without a bundle root"))?;
        Ok(root.join(path.to_native()?).into_os_string())
    };

    let program = match &manifest.target {
        Target::External { program } => program.to_os_string()?,
        Target::Embedded { resource } => resolve(resource)?,
    };

    let mut runtime = Some(runtime_args);
    let mut args = Vec::with_capacity(manifest.args.len());
    for element in &manifest.args {
        match element {
            ArgTemplate::Literal { value } => args.push(value.to_os_string()?),
            ArgTemplate::Resource { path } => args.push(resolve(path)?),
            ArgTemplate::RuntimeArgs => args.extend(runtime.take().unwrap_or_default()),
        }
    }
    if runtime.is_some_and(|extra| !extra.is_empty()) {
        return Err(LaunchError::UnexpectedArguments);
    }

    let mut env_set = Vec::with_capacity(manifest.env.len() + 1);
    let mut env_remove = Vec::new();
    for binding in &manifest.env {
        let name = binding.name.to_os_string()?;
        match &binding.value {
            EnvValue::Literal { value } => env_set.push((name, value.to_os_string()?)),
            EnvValue::Resource { path } => env_set.push((name, resolve(path)?)),
            EnvValue::Unset {} => env_remove.push(name),
        }
    }
    match root {
        Some(root) => env_set.push((BOUND_ROOT_ENV.into(), root.as_os_str().to_owned())),
        None => env_remove.push(BOUND_ROOT_ENV.into()),
    }

    let cwd = match manifest.cwd {
        CwdMode::Inherit => None,
        CwdMode::Bundle => {
            Some(root.ok_or(LaunchError::Internal("bundle working directory without a root"))?.to_path_buf())
        }
    };

    Ok(Invocation { program, args, env_set, env_remove, cwd })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bound_format::{BundleMode, Digest, EnvBinding, OsValue, Platform, RegionInfo, Resource};

    fn manifest(target: Target, args: Vec<ArgTemplate>) -> Manifest {
        let region = RegionInfo { size: 1, sha256: Digest([0; 32]) };
        Manifest {
            format: 1,
            generator: "test".into(),
            platform: Platform::host(),
            launcher: region.clone(),
            payload: region,
            target,
            args,
            env: vec![],
            cwd: CwdMode::Inherit,
            bundle: BundleMode::Private,
            resources: vec![Resource::File {
                path: ResourcePath::new("dir/config.toml").unwrap(),
                size: 0,
                sha256: Digest([1; 32]),
                executable: true,
            }],
            blobs: vec![],
        }
    }

    fn lit(s: &str) -> ArgTemplate {
        ArgTemplate::Literal { value: OsValue::from(s) }
    }

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn runtime_args_are_appended_or_placed() {
        let external = Target::External { program: "grep".into() };
        let m = manifest(external.clone(), vec![lit("-n"), lit("ERROR"), ArgTemplate::RuntimeArgs]);
        let inv = plan(&m, None, os(&["a.log", "b log"])).unwrap();
        assert_eq!(inv.program, "grep");
        assert_eq!(inv.args, os(&["-n", "ERROR", "a.log", "b log"]));

        let m = manifest(external, vec![ArgTemplate::RuntimeArgs, lit("-strip"), lit("out.jpg")]);
        let inv = plan(&m, None, os(&["in.png"])).unwrap();
        assert_eq!(inv.args, os(&["in.png", "-strip", "out.jpg"]));
        let inv = plan(&m, None, vec![]).unwrap();
        assert_eq!(inv.args, os(&["-strip", "out.jpg"]));
    }

    #[test]
    fn argument_boundaries_are_preserved_exactly() {
        let tricky = [
            "",
            " ",
            "hello world",
            "\"quoted\"",
            r"C:\Program Files\x\",
            r#"a\"b"#,
            "^&|%!<>()",
            "日本語 ☃",
            "$HOME `x` $(y)",
        ];
        let m = manifest(Target::External { program: "p".into() }, vec![ArgTemplate::RuntimeArgs]);
        let inv = plan(&m, None, os(&tricky)).unwrap();
        assert_eq!(inv.args, os(&tricky));
    }

    #[test]
    fn runtime_args_are_rejected_without_a_placeholder() {
        let m = manifest(Target::External { program: "p".into() }, vec![lit("x")]);
        assert!(matches!(plan(&m, None, os(&["y"])), Err(LaunchError::UnexpectedArguments)));
        assert!(plan(&m, None, vec![]).is_ok());
    }

    #[test]
    fn resources_become_native_paths_under_the_root() {
        let root = std::env::temp_dir().join("bound-test-root");
        let mut m = manifest(
            Target::Embedded { resource: ResourcePath::new("dir/config.toml").unwrap() },
            vec![ArgTemplate::Resource { path: ResourcePath::new("dir/config.toml").unwrap() }],
        );
        m.env.push(EnvBinding {
            name: "CONFIG".into(),
            value: EnvValue::Resource { path: ResourcePath::new("dir/config.toml").unwrap() },
        });
        m.cwd = CwdMode::Bundle;
        let inv = plan(&m, Some(&root), vec![]).unwrap();
        let expected = root.join("dir").join("config.toml").into_os_string();
        assert_eq!(inv.program, expected);
        assert_eq!(inv.args, vec![expected.clone()]);
        assert!(inv.env_set.contains(&("CONFIG".into(), expected)));
        assert!(inv.env_set.contains(&(BOUND_ROOT_ENV.into(), root.clone().into_os_string())));
        assert_eq!(inv.cwd.as_deref(), Some(root.as_path()));
        assert!(inv.env_remove.is_empty());
    }

    #[test]
    fn bound_root_is_removed_when_there_is_no_root() {
        let m = manifest(Target::External { program: "p".into() }, vec![]);
        let inv = plan(&m, None, vec![]).unwrap();
        assert_eq!(inv.env_remove, vec![OsString::from(BOUND_ROOT_ENV)]);
        assert!(inv.cwd.is_none());
    }

    #[test]
    fn child_path_var_prefers_bindings() {
        let mut inv = plan(&manifest(Target::External { program: "p".into() }, vec![]), None, vec![]).unwrap();
        inv.env_set.push(("PATH".into(), "/custom".into()));
        assert_eq!(inv.child_path_var(), Some(OsString::from("/custom")));
    }
}
