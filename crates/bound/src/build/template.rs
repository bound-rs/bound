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

use bound_format::ResourcePath;
use bound_format::manifest::BOUND_ROOT_ENV;
use bound_format::osvalue::{split_once_ascii, strip_ascii_prefix};

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

/// A parsed `--env NAME=VALUE`.
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

/// Parses `NAME=VALUE`, where VALUE may be `@file:PATH` or `@@`-escaped.
pub fn parse_env(spec: &OsStr) -> Result<EnvSpec, CliError> {
    let Some((name, value)) = split_once_ascii(spec, b'=') else {
        return Err(CliError::new(format!("--env expects NAME=VALUE, got \"{}\"", spec.to_string_lossy()))
            .with_hint("use NAME= to set an empty value"));
    };
    if name.is_empty() {
        return fail(format!("--env \"{}\": the variable name is empty", spec.to_string_lossy()));
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
        let spec = parse_env(OsStr::new("MODE=production=yes")).unwrap();
        assert_eq!(spec.name, "MODE");
        assert_eq!(spec.value, EnvSpecValue::Literal("production=yes".into()));
        let spec = parse_env(OsStr::new("CONFIG=@file:config.toml")).unwrap();
        assert_eq!(spec.value, EnvSpecValue::File("config.toml".into()));
        let spec = parse_env(OsStr::new("EMPTY=")).unwrap();
        assert_eq!(spec.value, EnvSpecValue::Literal("".into()));
        let spec = parse_env(OsStr::new("AT=@@file:x")).unwrap();
        assert_eq!(spec.value, EnvSpecValue::Literal("@file:x".into()));
        assert!(parse_env(OsStr::new("NOVALUE")).is_err());
        assert!(parse_env(OsStr::new("=x")).is_err());
        assert!(parse_env(OsStr::new("bound_root=x")).unwrap_err().message.contains("reserved"));
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
