//! Resource names: the platform-neutral paths of entries inside a bundle.
//!
//! A [`ResourcePath`] is a non-empty sequence of components joined by `/`.
//! It is always relative to the bundle root and can never name anything
//! outside it: components may not be empty, `.` or `..`, and may not contain
//! `/`, `\`, NUL or control characters. Conversion to a native path happens
//! only at materialization time, via [`ResourcePath::to_native`], which
//! additionally enforces Windows naming rules when running on Windows.

use std::ffi::OsStr;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::{Serialize, Serializer};

use crate::limits::{MAX_COMPONENT_LEN, MAX_PATH_LEN};
use crate::osvalue::{OsValue, display_bytes};

/// Which file-name rules to enforce.
///
/// [`NameRules::Portable`] rules are enforced everywhere; they are enough to
/// guarantee that a name stays inside the bundle root on every platform.
/// [`NameRules::Windows`] additionally rejects names that Windows would
/// reinterpret (drive letters and stream separators via `:`, reserved device
/// names such as `CON`, trailing dots and spaces that Win32 silently strips).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameRules {
    Portable,
    Windows,
}

impl NameRules {
    /// The rules for a target identified by its [`crate::Platform::os`].
    pub fn for_os(os: &str) -> NameRules {
        if os == "windows" { NameRules::Windows } else { NameRules::Portable }
    }

    /// The rules for the platform this code is running on.
    pub fn host() -> NameRules {
        if cfg!(windows) { NameRules::Windows } else { NameRules::Portable }
    }

    /// The stricter of two rule sets.
    pub fn stricter(self, other: NameRules) -> NameRules {
        if self == NameRules::Windows || other == NameRules::Windows { NameRules::Windows } else { NameRules::Portable }
    }
}

/// Whether the file systems of `os` (a [`crate::Platform::os`] identifier)
/// ignore case, as Windows and macOS file systems do unless formatted
/// otherwise: names that differ only by case are then the same file.
pub fn folds_case(os: &str) -> bool {
    matches!(os, "macos" | "windows")
}

/// A rejected resource path or symlink target.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsafe resource path \"{path}\": {reason}")]
pub struct NameError {
    /// Display form of the offending path (control characters escaped).
    pub path: String,
    pub reason: &'static str,
}

impl NameError {
    fn new(path: &[u8], reason: &'static str) -> NameError {
        NameError { path: display_bytes(path), reason }
    }
}

/// A validated, normalized path of a resource inside the bundle.
///
/// Ordering is bytewise, which places every directory before its contents.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourcePath(Vec<u8>);

impl ResourcePath {
    /// Parses a `/`-separated path under the portable rules.
    pub fn new(path: &str) -> Result<ResourcePath, NameError> {
        ResourcePath::from_bytes(path.as_bytes())
    }

    /// Parses `/`-separated bytes under the portable rules. The input must
    /// already be in canonical form (no empty, `.` or `..` components).
    pub fn from_bytes(path: &[u8]) -> Result<ResourcePath, NameError> {
        if path.is_empty() {
            return Err(NameError::new(path, "path is empty"));
        }
        if path.len() > MAX_PATH_LEN {
            return Err(NameError::new(path, "path is too long"));
        }
        if path[0] == b'/' {
            return Err(NameError::new(path, "absolute paths are not allowed"));
        }
        for component in path.split(|&b| b == b'/') {
            check_component(component, NameRules::Portable).map_err(|r| NameError::new(path, r))?;
        }
        Ok(ResourcePath(path.to_vec()))
    }

    /// Builds a path from a native relative path, normalizing `.` and `..`
    /// lexically. Absolute paths (including Windows drive, UNC and device
    /// paths) and paths that climb above their starting point are rejected.
    pub fn from_host_path(path: &Path) -> Result<ResourcePath, NameError> {
        let raw = host_display_bytes(path);
        let mut parts: Vec<Vec<u8>> = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => {
                    return Err(NameError::new(&raw, "absolute paths are not allowed"));
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    if parts.pop().is_none() {
                        return Err(NameError::new(&raw, "path escapes the bundle root"));
                    }
                }
                Component::Normal(name) => {
                    parts.push(host_component_bytes(name).map_err(|r| NameError::new(&raw, r))?);
                }
            }
        }
        if parts.is_empty() {
            return Err(NameError::new(&raw, "path is empty"));
        }
        ResourcePath::from_bytes(&parts.join(&b'/')).map_err(|e| NameError::new(&raw, e.reason))
    }

    /// Builds a single-component path from one native file name.
    pub fn from_host_component(name: &OsStr) -> Result<ResourcePath, NameError> {
        let bytes = host_component_bytes(name).map_err(|r| NameError::new(name.to_string_lossy().as_bytes(), r))?;
        if bytes.contains(&b'/') {
            return Err(NameError::new(&bytes, "contains a path separator"));
        }
        ResourcePath::from_bytes(&bytes)
    }

    /// Appends one native file name (as produced by a directory listing).
    pub fn join_host(&self, name: &OsStr) -> Result<ResourcePath, NameError> {
        let mut bytes = self.0.clone();
        let component = host_component_bytes(name).map_err(|r| {
            let mut shown = bytes.clone();
            shown.push(b'/');
            shown.extend_from_slice(name.to_string_lossy().as_bytes());
            NameError::new(&shown, r)
        })?;
        bytes.push(b'/');
        bytes.extend_from_slice(&component);
        ResourcePath::from_bytes(&bytes)
    }

    /// Checks the path against `rules` (the portable rules always hold).
    pub fn validate(&self, rules: NameRules) -> Result<(), NameError> {
        if rules == NameRules::Windows {
            for component in self.components() {
                check_windows_component(component).map_err(|r| NameError::new(&self.0, r))?;
            }
        }
        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The path as text, if it is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    pub fn components(&self) -> impl Iterator<Item = &[u8]> {
        self.0.split(|&b| b == b'/')
    }

    /// The final component.
    pub fn file_name(&self) -> &[u8] {
        match self.0.iter().rposition(|&b| b == b'/') {
            Some(i) => &self.0[i + 1..],
            None => &self.0,
        }
    }

    /// The containing directory, or `None` for top-level entries.
    pub fn parent(&self) -> Option<ResourcePath> {
        let i = self.0.iter().rposition(|&b| b == b'/')?;
        Some(ResourcePath(self.0[..i].to_vec()))
    }

    /// All proper ancestors, outermost first.
    pub fn ancestors(&self) -> Vec<ResourcePath> {
        let mut out = Vec::new();
        for (i, &b) in self.0.iter().enumerate() {
            if b == b'/' {
                out.push(ResourcePath(self.0[..i].to_vec()));
            }
        }
        out
    }

    /// Key used to detect names that collide on case-insensitive file
    /// systems (the default on Windows and macOS).
    ///
    /// Round trips through upper and lower case approximate full case
    /// folding, so that final and medial sigma (`ς`, `σ`) and `ß`/`ss`
    /// share a key; erring towards collisions only rejects more. Unicode
    /// normalization is not applied: names that differ only by composition
    /// (`é` as one or two code points) pass here, and on a
    /// normalization-insensitive file system such as APFS their extraction
    /// fails safely, because every file is created exclusively.
    pub fn fold_key(&self) -> Vec<u8> {
        if self.0.is_ascii() {
            return self.0.to_ascii_lowercase();
        }
        match std::str::from_utf8(&self.0) {
            Ok(s) => {
                let once = s.to_uppercase().to_lowercase();
                once.to_uppercase().to_lowercase().into_bytes()
            }
            Err(_) => self.0.to_ascii_lowercase(),
        }
    }

    /// Converts to a relative native path. On Windows this also enforces
    /// [`NameRules::Windows`], so the result can be joined to a directory
    /// without being reinterpreted as a drive, device or stream.
    pub fn to_native(&self) -> Result<PathBuf, NameError> {
        #[cfg(windows)]
        self.validate(NameRules::Windows)?;
        let mut out = PathBuf::new();
        for component in self.components() {
            out.push(native_component(component).map_err(|r| NameError::new(&self.0, r))?);
        }
        Ok(out)
    }

    /// Terminal-safe display form.
    pub fn display(&self) -> String {
        display_bytes(&self.0)
    }
}

impl fmt::Display for ResourcePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

impl fmt::Debug for ResourcePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResourcePath({:?})", self.display())
    }
}

impl Serialize for ResourcePath {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        bytes_to_osvalue(&self.0).serialize(s)
    }
}

/// The target of a symbolic link stored in a bundle: a relative,
/// `/`-separated path that may use `.` and `..`. Whether it stays inside the
/// bundle is checked against the whole resource tree during manifest
/// validation.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkTarget(Vec<u8>);

impl LinkTarget {
    pub fn from_bytes(target: &[u8]) -> Result<LinkTarget, NameError> {
        if target.is_empty() {
            return Err(NameError::new(target, "symlink target is empty"));
        }
        if target.len() > MAX_PATH_LEN {
            return Err(NameError::new(target, "symlink target is too long"));
        }
        if target[0] == b'/' {
            return Err(NameError::new(target, "symlink target is absolute"));
        }
        for component in target.split(|&b| b == b'/') {
            if component == b"." || component == b".." {
                continue;
            }
            check_component(component, NameRules::Portable).map_err(|r| NameError::new(target, r))?;
        }
        Ok(LinkTarget(target.to_vec()))
    }

    /// Converts a native symlink target read from disk.
    pub fn from_host_path(path: &Path) -> Result<LinkTarget, NameError> {
        let raw = host_display_bytes(path);
        let mut parts: Vec<Vec<u8>> = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => {
                    return Err(NameError::new(&raw, "symlink target is absolute"));
                }
                Component::CurDir => parts.push(b".".to_vec()),
                Component::ParentDir => parts.push(b"..".to_vec()),
                Component::Normal(name) => {
                    parts.push(host_component_bytes(name).map_err(|r| NameError::new(&raw, r))?);
                }
            }
        }
        LinkTarget::from_bytes(&parts.join(&b'/')).map_err(|e| NameError::new(&raw, e.reason))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn components(&self) -> impl Iterator<Item = &[u8]> {
        self.0.split(|&b| b == b'/')
    }

    /// Converts to a relative native path.
    pub fn to_native(&self) -> Result<PathBuf, NameError> {
        let mut out = PathBuf::new();
        for component in self.components() {
            out.push(native_component(component).map_err(|r| NameError::new(&self.0, r))?);
        }
        Ok(out)
    }

    pub fn display(&self) -> String {
        display_bytes(&self.0)
    }
}

impl fmt::Debug for LinkTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkTarget({:?})", self.display())
    }
}

impl Serialize for LinkTarget {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        bytes_to_osvalue(&self.0).serialize(s)
    }
}

fn bytes_to_osvalue(bytes: &[u8]) -> OsValue {
    match std::str::from_utf8(bytes) {
        Ok(s) => OsValue::Unicode(s.to_owned()),
        Err(_) => OsValue::UnixBytes(bytes.to_vec()),
    }
}

/// Checks a single component under `rules`.
fn check_component(c: &[u8], rules: NameRules) -> Result<(), &'static str> {
    if c.is_empty() {
        return Err("empty path component");
    }
    if c == b"." || c == b".." {
        return Err("'.' and '..' components are not allowed");
    }
    if c.len() > MAX_COMPONENT_LEN {
        return Err("path component is too long");
    }
    for &b in c {
        match b {
            b'/' => return Err("contains a path separator"),
            b'\\' => return Err("contains a backslash"),
            0 => return Err("contains a NUL byte"),
            0x01..=0x1f | 0x7f => return Err("contains a control character"),
            _ => {}
        }
    }
    // C1 and other non-ASCII control characters (such as U+009B, which
    // some terminals treat like ESC [).
    if std::str::from_utf8(c).is_ok_and(|s| s.chars().any(char::is_control)) {
        return Err("contains a control character");
    }
    if rules == NameRules::Windows {
        check_windows_component(c)?;
    }
    Ok(())
}

/// Windows-specific component checks. The portable checks have already
/// excluded separators, NUL and control characters.
fn check_windows_component(c: &[u8]) -> Result<(), &'static str> {
    let s = std::str::from_utf8(c).map_err(|_| "is not valid Unicode, which Windows requires")?;
    if s.chars().any(|ch| matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*')) {
        return Err("contains a character reserved on Windows (one of <>:\"|?*)");
    }
    if s.ends_with('.') || s.ends_with(' ') {
        return Err("ends with a dot or space, which Windows silently removes");
    }
    if is_windows_device_name(s) {
        return Err("is a reserved device name on Windows");
    }
    Ok(())
}

/// Whether Win32 path parsing would treat `name` as a device such as `CON`
/// or `COM1`, with or without an extension (`nul.txt` is still NUL).
pub fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") {
        return true;
    }
    match upper.strip_prefix("COM").or_else(|| upper.strip_prefix("LPT")) {
        Some(rest) => {
            let mut chars = rest.chars();
            matches!((chars.next(), chars.next()), (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None))
        }
        None => false,
    }
}

fn host_component_bytes(name: &OsStr) -> Result<Vec<u8>, &'static str> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(name.as_bytes().to_vec())
    }
    #[cfg(not(unix))]
    {
        name.to_str().map(|s| s.as_bytes().to_vec()).ok_or("file name is not valid Unicode")
    }
}

fn host_display_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().into_owned().into_bytes()
    }
}

fn native_component(c: &[u8]) -> Result<&OsStr, &'static str> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(OsStr::from_bytes(c))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(c).map(OsStr::new).map_err(|_| "is not valid Unicode")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        for ok in ["a", "a/b", "templates/index.html", "dir with space/file é.txt", "..a", "日本/語"] {
            let p = ResourcePath::new(ok).unwrap();
            assert_eq!(p.as_str(), Some(ok));
            p.validate(NameRules::Windows).unwrap();
        }
        // Legal on Unix, but Windows would strip the trailing dots.
        for unix_only in ["a..", "..."] {
            let p = ResourcePath::new(unix_only).unwrap();
            assert!(p.validate(NameRules::Windows).is_err());
        }
    }

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        for bad in [
            "",
            "/",
            "/abs",
            "../foo",
            "..",
            ".",
            "a/../b",
            "a/./b",
            "a//b",
            "a/",
            "foo/../../bar",
            "..\\foo",
            "foo\\..\\..\\bar",
            "a\\b",
            "C:\\outside",
            "\\\\server\\share\\path",
            "\\\\?\\C:\\foo",
            "a\0b",
            "a\nb",
            "a\x7fb",
        ] {
            assert!(ResourcePath::new(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn windows_rules() {
        for bad in [
            "C:",
            "C:outside",
            "a/C:x",
            "file:stream",
            "CON",
            "con",
            "nul.txt",
            "Aux.tar.gz",
            "COM1",
            "lpt9.log",
            "COM\u{b9}",
            "CONIN$",
            "conout$",
            "trailing.",
            "trailing ",
            "a/b.",
            "q?",
            "a*b",
            "x|y",
            "<x>",
            "\"q\"",
        ] {
            let p = ResourcePath::new(bad).unwrap();
            assert!(p.validate(NameRules::Windows).is_err(), "{bad:?} should be rejected on Windows");
            p.validate(NameRules::Portable).unwrap();
        }
        for ok in ["CONFIG", "console", "COM10", "LPT", "nul_", "com1x.txt", "aux-thing"] {
            ResourcePath::new(ok).unwrap().validate(NameRules::Windows).unwrap();
        }
        let non_utf8 = ResourcePath::from_bytes(b"caf\xe9").unwrap();
        assert!(non_utf8.validate(NameRules::Windows).is_err());
    }

    #[test]
    fn host_paths_are_normalized() {
        let p = ResourcePath::from_host_path(Path::new("./a/./b/../c.txt")).unwrap();
        assert_eq!(p.as_str(), Some("a/c.txt"));
        assert!(ResourcePath::from_host_path(Path::new("../x")).is_err());
        assert!(ResourcePath::from_host_path(Path::new("a/../../x")).is_err());
        assert!(ResourcePath::from_host_path(Path::new("/etc/passwd")).is_err());
        assert!(ResourcePath::from_host_path(Path::new(".")).is_err());
        #[cfg(windows)]
        {
            for bad in [r"..\x", r"C:\x", r"C:x", r"\\server\share\x", r"\\?\C:\x", r"\x", r"a\..\..\x"] {
                assert!(ResourcePath::from_host_path(Path::new(bad)).is_err(), "{bad}");
            }
            assert_eq!(ResourcePath::from_host_path(Path::new(r"a\b\c")).unwrap().as_str(), Some("a/b/c"));
        }
        #[cfg(unix)]
        {
            // On Unix a backslash is an ordinary byte, but bound refuses it.
            assert!(ResourcePath::from_host_path(Path::new(r"..\x")).is_err());
        }
    }

    #[test]
    fn structure_helpers() {
        let p = ResourcePath::new("a/b/c").unwrap();
        assert_eq!(p.file_name(), b"c");
        assert_eq!(p.parent().unwrap().as_str(), Some("a/b"));
        let ancestors: Vec<_> = p.ancestors().iter().map(|a| a.display()).collect();
        assert_eq!(ancestors, ["a", "a/b"]);
        assert!(ResourcePath::new("a").unwrap().parent().is_none());
        assert_eq!(p.join_host(OsStr::new("d")).unwrap().as_str(), Some("a/b/c/d"));
        assert!(p.join_host(OsStr::new("..")).is_err());
        assert_eq!(
            ResourcePath::new("Dir/File").unwrap().fold_key(),
            ResourcePath::new("dir/FILE").unwrap().fold_key()
        );
        assert!(ResourcePath::new("a").unwrap() < ResourcePath::new("a/b").unwrap());
    }

    #[test]
    fn json_forms() {
        let p = ResourcePath::new("a/b.txt").unwrap();
        assert_eq!(serde_json::to_string(&p).unwrap(), r#""a/b.txt""#);
        let bytes = ResourcePath::from_bytes(b"a/\xff").unwrap();
        assert_eq!(serde_json::to_string(&bytes).unwrap(), r#"{"unix_bytes":"612fff"}"#);
    }

    #[test]
    fn link_targets() {
        for ok in ["x", "../lib/x.so", "./a", "a/../b", "..", "."] {
            LinkTarget::from_bytes(ok.as_bytes()).unwrap();
        }
        for bad in ["", "/etc/passwd", "a//b", "a/", "a\\b", "..\\x", "a\0"] {
            assert!(LinkTarget::from_bytes(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert!(LinkTarget::from_host_path(Path::new("/abs")).is_err());
        assert_eq!(LinkTarget::from_host_path(Path::new("../a/./b")).unwrap().as_bytes(), b"../a/b");
    }

    #[test]
    fn to_native_joins_components() {
        let p = ResourcePath::new("a/b c/d").unwrap();
        assert_eq!(p.to_native().unwrap(), Path::new("a").join("b c").join("d"));
    }

    #[test]
    fn to_native_enforces_the_hosts_rules() {
        // Names Windows cannot create are refused there, and fine elsewhere.
        for name in ["C:x", "con"] {
            let native = ResourcePath::new(name).unwrap().to_native();
            assert_eq!(native.is_err(), cfg!(windows), "{name}: {native:?}");
        }
    }
}
