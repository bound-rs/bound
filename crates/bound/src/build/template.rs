//! Parsing the bound invocation.
//!
//! Directives are recognized only when they form a whole argument:
//!
//! * `@args` marks where run-time arguments go (at most once; if absent,
//!   run-time arguments are appended at the end);
//! * `@file:PATH` bundles `PATH` and is replaced at run time by the absolute
//!   native path of the materialized copy;
//! * `@bundle:PATH` is replaced at run time by the absolute native path of
//!   `PATH` in the bundle directory, which something else bundled;
//! * an argument starting with `@@` is literal, with one leading `@`
//!   removed (`@@args` passes the text `@args`).
//!
//! Every other argument is passed through byte for byte.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use bound_format::manifest::BOUND_ROOT_ENV;
use bound_format::osvalue::{split_once_ascii, strip_ascii_prefix};
use bound_format::{CwdMode, ResourcePath};

use crate::error::{CliError, fail};

const ARGS_DIRECTIVE: &str = "@args";
const FILE_DIRECTIVE: &str = "@file:";
const BUNDLE_DIRECTIVE: &str = "@bundle:";
const ESCAPE: &str = "@@";

/// One parsed element of the bound argument list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgSpec {
    Literal(OsString),
    File(PathBuf),
    Bundled(ResourcePath),
    RuntimeArgs,
}

/// A parsed `--env NAME=VALUE` (or `--env-prepend`, `--env-append`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSpec {
    pub name: OsString,
    pub value: EnvSpecValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvSpecValue {
    Literal(OsString),
    File(PathBuf),
    Bundled(ResourcePath),
}

/// Classifies one argument.
pub fn parse_arg(arg: &OsStr) -> Result<ArgSpec, CliError> {
    if arg == ARGS_DIRECTIVE {
        return Ok(ArgSpec::RuntimeArgs);
    }
    if let Some(rest) = strip_ascii_prefix(arg, ESCAPE) {
        let mut literal = OsString::from("@");
        literal.push(rest);
        return Ok(ArgSpec::Literal(literal));
    }
    if let Some(path) = strip_ascii_prefix(arg, FILE_DIRECTIVE) {
        if path.is_empty() {
            return fail("@file: needs a path, as in @file:config.toml");
        }
        return Ok(ArgSpec::File(PathBuf::from(path)));
    }
    if let Some(path) = strip_ascii_prefix(arg, BUNDLE_DIRECTIVE) {
        return parse_bundle_path(&path).map(ArgSpec::Bundled);
    }
    Ok(ArgSpec::Literal(arg.to_owned()))
}

/// Parses the `PATH` of `@bundle:PATH`: a `/`-separated path in the bundle.
fn parse_bundle_path(path: &OsStr) -> Result<ResourcePath, CliError> {
    let shown = path.to_string_lossy();
    let Some(text) = path.to_str() else {
        return fail(format!("@bundle:{shown}: the path must be valid Unicode"));
    };
    match text.trim_end_matches('/') {
        "" => fail("@bundle: needs a path in the bundle, as in @bundle:data/config.toml"),
        "." => fail("@bundle:. names the bundle directory itself, which the program finds in BOUND_ROOT"),
        text => ResourcePath::new(text).map_err(|e| CliError::new(format!("@bundle:{shown}: {}", e.reason))),
    }
}

/// Parses the arguments that follow the program. The result always contains
/// exactly one [`ArgSpec::RuntimeArgs`]: where `@args` was written, or at
/// the end.
pub fn parse_args(args: &[OsString]) -> Result<Vec<ArgSpec>, CliError> {
    let mut out = Vec::with_capacity(args.len() + 1);
    let mut placeholder = false;
    for arg in args {
        let spec = parse_arg(arg)?;
        if spec == ArgSpec::RuntimeArgs {
            if placeholder {
                return fail("@args may appear only once");
            }
            placeholder = true;
        }
        out.push(spec);
    }
    if !placeholder {
        out.push(ArgSpec::RuntimeArgs);
    }
    Ok(out)
}

/// Parses the `NAME=VALUE` of `option` (`--env`, `--env-prepend` or
/// `--env-append`), where VALUE may be `@file:PATH`, `@bundle:PATH` or
/// `@@`-escaped.
pub fn parse_env(spec: &OsStr, option: &str) -> Result<EnvSpec, CliError> {
    let Some((name, value)) = split_once_ascii(spec, b'=') else {
        let error = CliError::new(format!("{option} expects NAME=VALUE, got \"{}\"", spec.to_string_lossy()));
        return Err(if option == "--env" { error.with_hint("use NAME= to set an empty value") } else { error });
    };
    if name.is_empty() {
        return fail(format!("{option} \"{}\": the variable name is empty", spec.to_string_lossy()));
    }
    if name.to_string_lossy().eq_ignore_ascii_case(BOUND_ROOT_ENV) {
        return fail(format!("{BOUND_ROOT_ENV} is reserved: bound sets it to the bundle directory at run time"));
    }
    let value = match parse_arg(&value)? {
        ArgSpec::File(path) => EnvSpecValue::File(path),
        ArgSpec::Bundled(path) => EnvSpecValue::Bundled(path),
        ArgSpec::Literal(text) => EnvSpecValue::Literal(text),
        // `@args` has no meaning in an environment value.
        ArgSpec::RuntimeArgs => EnvSpecValue::Literal(value),
    };
    Ok(EnvSpec { name, value })
}

/// Parses `--cwd`: `inherit`, `bundle`, or `@bundle:DIR` for a directory in
/// the bundle.
pub fn parse_cwd(value: &str) -> Result<CwdMode, CliError> {
    match value {
        "inherit" => Ok(CwdMode::Inherit),
        "bundle" => Ok(CwdMode::Bundle),
        _ => match strip_ascii_prefix(OsStr::new(value), BUNDLE_DIRECTIVE) {
            Some(path) => parse_bundle_path(&path).map(CwdMode::Dir),
            None => fail(format!("--cwd \"{value}\": expected inherit, bundle or @bundle:DIR")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn directives() {
        assert_eq!(parse_arg(OsStr::new("@args")).unwrap(), ArgSpec::RuntimeArgs);
        assert_eq!(parse_arg(OsStr::new("@file:a b.sql")).unwrap(), ArgSpec::File("a b.sql".into()));
        assert_eq!(parse_arg(OsStr::new("@@args")).unwrap(), ArgSpec::Literal("@args".into()));
        assert_eq!(parse_arg(OsStr::new("@@file:x")).unwrap(), ArgSpec::Literal("@file:x".into()));
        assert_eq!(parse_arg(OsStr::new("@@@x")).unwrap(), ArgSpec::Literal("@@x".into()));
        for literal in ["@argsx", "@file", "@", "x@file:y", "--config=@file:x", "@response.rsp", ""] {
            assert_eq!(parse_arg(OsStr::new(literal)).unwrap(), ArgSpec::Literal(literal.into()), "{literal}");
        }
        assert!(parse_arg(OsStr::new("@file:")).is_err());
        assert_eq!(
            parse_arg(OsStr::new("@bundle:tool.runfiles/")).unwrap(),
            ArgSpec::Bundled(ResourcePath::new("tool.runfiles").unwrap())
        );
        assert_eq!(parse_arg(OsStr::new("@@bundle:x")).unwrap(), ArgSpec::Literal("@bundle:x".into()));
        for bad in ["@bundle:", "@bundle:.", "@bundle:../x", "@bundle:/etc", "@bundle:a//b"] {
            assert!(parse_arg(OsStr::new(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn runtime_args_default_to_the_end() {
        let specs = parse_args(&os(&["-n", "ERROR"])).unwrap();
        assert_eq!(specs.last(), Some(&ArgSpec::RuntimeArgs));
        let specs = parse_args(&os(&["@args", "-strip"])).unwrap();
        assert_eq!(specs, vec![ArgSpec::RuntimeArgs, ArgSpec::Literal("-strip".into())]);
        let err = parse_args(&os(&["@args", "x", "@args"])).unwrap_err();
        assert_eq!(err.message, "@args may appear only once");
    }

    #[test]
    fn env_specs() {
        let spec = parse_env(OsStr::new("MODE=production=yes"), "--env").unwrap();
        assert_eq!(spec.name, "MODE");
        assert_eq!(spec.value, EnvSpecValue::Literal("production=yes".into()));
        let spec = parse_env(OsStr::new("CONFIG=@file:config.toml"), "--env").unwrap();
        assert_eq!(spec.value, EnvSpecValue::File("config.toml".into()));
        let spec = parse_env(OsStr::new("EMPTY="), "--env").unwrap();
        assert_eq!(spec.value, EnvSpecValue::Literal("".into()));
        let spec = parse_env(OsStr::new("AT=@@file:x"), "--env").unwrap();
        assert_eq!(spec.value, EnvSpecValue::Literal("@file:x".into()));
        assert!(parse_env(OsStr::new("NOVALUE"), "--env").is_err());
        assert!(parse_env(OsStr::new("=x"), "--env").is_err());
        assert!(parse_env(OsStr::new("bound_root=x"), "--env").unwrap_err().message.contains("reserved"));
        let err = parse_env(OsStr::new("PATH"), "--env-prepend").unwrap_err();
        assert!(err.message.starts_with("--env-prepend expects NAME=VALUE"), "{}", err.message);
        let spec = parse_env(OsStr::new("PATH=@bundle:bin"), "--env-prepend").unwrap();
        assert_eq!(spec.value, EnvSpecValue::Bundled(ResourcePath::new("bin").unwrap()));
    }

    #[test]
    fn working_directories() {
        assert_eq!(parse_cwd("inherit").unwrap(), CwdMode::Inherit);
        assert_eq!(parse_cwd("bundle").unwrap(), CwdMode::Bundle);
        assert_eq!(parse_cwd("@bundle:app/src/").unwrap(), CwdMode::Dir(ResourcePath::new("app/src").unwrap()));
        for bad in ["", "Bundle", "@bundle:", "@bundle:.", "@bundle:../x", "@file:x"] {
            assert!(parse_cwd(bad).is_err(), "{bad:?}");
        }
    }

    /// A name that is not Unicode: bytes that are not UTF-8 on Unix, an
    /// unpaired surrogate on Windows.
    fn non_unicode(prefix: &str) -> OsString {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let mut bytes = prefix.as_bytes().to_vec();
            bytes.extend_from_slice(b"caf\xe9.txt");
            OsString::from_vec(bytes)
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            let mut wide: Vec<u16> = prefix.encode_utf16().collect();
            wide.extend("caf".encode_utf16());
            wide.push(0xd800);
            wide.extend(".txt".encode_utf16());
            OsString::from_wide(&wide)
        }
    }

    #[test]
    fn non_unicode_is_preserved() {
        let raw = non_unicode("@file:");
        assert!(raw.to_str().is_none());
        assert_eq!(parse_arg(&raw).unwrap(), ArgSpec::File(non_unicode("").into()));
        let literal = non_unicode("");
        assert_eq!(parse_arg(&literal).unwrap(), ArgSpec::Literal(literal.clone()));
    }
}
