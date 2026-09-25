//! Platform strings (arguments, environment values, program names) as they
//! are stored in a manifest.
//!
//! Unix strings are arbitrary bytes and Windows strings are arbitrary UTF-16
//! code units; both are usually, but not always, valid Unicode. A manifest
//! stores valid Unicode as text and falls back to the raw form otherwise, so
//! no value is ever silently altered. The JSON form (`bound inspect --json`)
//! is a plain string or an explicitly tagged object:
//!
//! ```json
//! "hello"                          // valid Unicode, any platform
//! {"unix_bytes": "66ff6f"}         // non-UTF-8 bytes, Unix only
//! {"windows_utf16": "0066d800"}    // ill-formed UTF-16, Windows only
//! ```

use std::ffi::{OsStr, OsString};
use std::fmt;

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::hash::encode_hex;

/// A platform string stored in a manifest.
///
/// The non-Unicode variants are only produced when the input cannot be
/// represented as Unicode; decoding rejects them when the content *is* valid
/// Unicode, so every value has exactly one encoding.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum OsValue {
    /// Valid Unicode; representable on every platform.
    Unicode(String),
    /// Bytes that are not valid UTF-8. Only meaningful on Unix.
    UnixBytes(Vec<u8>),
    /// UTF-16 code units that are not valid UTF-16. Only meaningful on Windows.
    WindowsWide(Vec<u16>),
}

/// Error returned when a stored value cannot be expressed on this platform.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("value {0} cannot be represented on this platform")]
pub struct NotRepresentable(pub String);

impl OsValue {
    /// Converts a native string without loss.
    pub fn from_os_str(s: &OsStr) -> OsValue {
        if let Some(text) = s.to_str() {
            return OsValue::Unicode(text.to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            OsValue::UnixBytes(s.as_bytes().to_vec())
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            OsValue::WindowsWide(s.encode_wide().collect())
        }
        #[cfg(not(any(unix, windows)))]
        {
            OsValue::Unicode(s.to_string_lossy().into_owned())
        }
    }

    /// Converts back to a native string, failing if the value was captured
    /// on a platform whose strings this platform cannot express.
    pub fn to_os_string(&self) -> Result<OsString, NotRepresentable> {
        match self {
            OsValue::Unicode(s) => Ok(OsString::from(s)),
            #[cfg(unix)]
            OsValue::UnixBytes(bytes) => {
                use std::os::unix::ffi::OsStringExt;
                Ok(OsString::from_vec(bytes.clone()))
            }
            #[cfg(windows)]
            OsValue::WindowsWide(wide) => {
                use std::os::windows::ffi::OsStringExt;
                Ok(OsString::from_wide(wide))
            }
            #[allow(unreachable_patterns)]
            other => Err(NotRepresentable(other.display())),
        }
    }

    /// Whether this value can be passed to a process on `os`
    /// (an [`crate::Platform::os`] identifier such as `"windows"`).
    pub fn representable_on(&self, os: &str) -> bool {
        match self {
            OsValue::Unicode(_) => true,
            OsValue::UnixBytes(_) => os != "windows",
            OsValue::WindowsWide(_) => os == "windows",
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            OsValue::Unicode(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            OsValue::Unicode(s) => s.is_empty(),
            OsValue::UnixBytes(b) => b.is_empty(),
            OsValue::WindowsWide(w) => w.is_empty(),
        }
    }

    /// Whether the value contains a NUL, which no process API can transmit.
    pub fn contains_nul(&self) -> bool {
        match self {
            OsValue::Unicode(s) => s.contains('\0'),
            OsValue::UnixBytes(b) => b.contains(&0),
            OsValue::WindowsWide(w) => w.contains(&0),
        }
    }

    /// Whether the value contains `c` (an ASCII character).
    pub fn contains_ascii(&self, c: u8) -> bool {
        debug_assert!(c.is_ascii());
        match self {
            OsValue::Unicode(s) => s.as_bytes().contains(&c),
            OsValue::UnixBytes(b) => b.contains(&c),
            OsValue::WindowsWide(w) => w.contains(&u16::from(c)),
        }
    }

    /// A human-readable rendering. Invalid sequences are shown as `\xNN`
    /// (bytes) or `\u{NNNN}` (lone surrogates); control characters are
    /// escaped so the result is safe to print to a terminal.
    pub fn display(&self) -> String {
        match self {
            OsValue::Unicode(s) => escape_control(s),
            OsValue::UnixBytes(bytes) => display_bytes(bytes),
            OsValue::WindowsWide(wide) => {
                let mut out = String::new();
                for unit in char::decode_utf16(wide.iter().copied()) {
                    match unit {
                        Ok(c) => push_escaped(&mut out, c),
                        Err(e) => out.push_str(&format!("\\u{{{:04x}}}", e.unpaired_surrogate())),
                    }
                }
                out
            }
        }
    }

    /// Case-insensitive comparison key, used for environment variable names
    /// (which Windows treats case-insensitively).
    pub fn fold_key(&self) -> OsValue {
        match self {
            OsValue::Unicode(s) => OsValue::Unicode(s.to_uppercase()),
            OsValue::UnixBytes(b) => OsValue::UnixBytes(b.to_ascii_uppercase()),
            OsValue::WindowsWide(w) => {
                OsValue::WindowsWide(w.iter().map(|&u| if (0x61..=0x7a).contains(&u) { u - 0x20 } else { u }).collect())
            }
        }
    }
}

impl From<&str> for OsValue {
    fn from(s: &str) -> OsValue {
        OsValue::Unicode(s.to_owned())
    }
}

impl From<String> for OsValue {
    fn from(s: String) -> OsValue {
        OsValue::Unicode(s)
    }
}

impl fmt::Display for OsValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

/// If `s` starts with the ASCII `prefix`, returns the remainder, preserving
/// any non-Unicode content exactly.
pub fn strip_ascii_prefix(s: &OsStr, prefix: &str) -> Option<OsString> {
    assert!(prefix.is_ascii(), "prefix must be ASCII");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let rest = s.as_bytes().strip_prefix(prefix.as_bytes())?;
        Some(OsStr::from_bytes(rest).to_owned())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let wide: Vec<u16> = s.encode_wide().collect();
        let pre: Vec<u16> = prefix.encode_utf16().collect();
        let rest = wide.strip_prefix(pre.as_slice())?;
        Some(OsString::from_wide(rest))
    }
    #[cfg(not(any(unix, windows)))]
    {
        s.to_str()?.strip_prefix(prefix).map(OsString::from)
    }
}

/// Splits `s` at the first occurrence of the ASCII character `sep`,
/// preserving any non-Unicode content on both sides exactly.
pub fn split_once_ascii(s: &OsStr, sep: u8) -> Option<(OsString, OsString)> {
    assert!(sep.is_ascii(), "separator must be ASCII");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = s.as_bytes();
        let i = bytes.iter().position(|&b| b == sep)?;
        Some((OsStr::from_bytes(&bytes[..i]).to_owned(), OsStr::from_bytes(&bytes[i + 1..]).to_owned()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let wide: Vec<u16> = s.encode_wide().collect();
        let i = wide.iter().position(|&u| u == u16::from(sep))?;
        Some((OsString::from_wide(&wide[..i]), OsString::from_wide(&wide[i + 1..])))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let (a, b) = s.to_str()?.split_once(sep as char)?;
        Some((a.into(), b.into()))
    }
}

pub(crate) fn display_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            push_escaped(&mut out, c);
        }
        for b in chunk.invalid() {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

/// Escapes control characters, and the invisible characters that reorder
/// the display of text (bidirectional overrides and isolates), so that
/// untrusted text is safe on a terminal and shows what it contains.
pub fn escape_control(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        push_escaped(&mut out, c);
    }
    out
}

/// Characters that change the direction in which text is displayed.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn push_escaped(out: &mut String, c: char) {
    match c {
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if c.is_control() || is_bidi_control(c) => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
        c => out.push(c),
    }
}

const UNIX_BYTES_KEY: &str = "unix_bytes";
const WINDOWS_UTF16_KEY: &str = "windows_utf16";

impl Serialize for OsValue {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            OsValue::Unicode(text) => s.serialize_str(text),
            OsValue::UnixBytes(bytes) => {
                let mut map = s.serialize_map(Some(1))?;
                map.serialize_entry(UNIX_BYTES_KEY, &encode_hex(bytes))?;
                map.end()
            }
            OsValue::WindowsWide(wide) => {
                let mut map = s.serialize_map(Some(1))?;
                let hex: String = wide.iter().map(|u| format!("{u:04x}")).collect();
                map.serialize_entry(WINDOWS_UTF16_KEY, &hex)?;
                map.end()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_form() {
        let v = OsValue::from("héllo wörld \"quoted\" \\");
        assert_eq!(serde_json::to_string(&v).unwrap(), r#""héllo wörld \"quoted\" \\""#);
        let bytes = OsValue::UnixBytes(vec![0x66, 0xff, 0x6f]);
        assert_eq!(serde_json::to_string(&bytes).unwrap(), r#"{"unix_bytes":"66ff6f"}"#);
        let wide = OsValue::WindowsWide(vec![0x66, 0xd800]);
        assert_eq!(serde_json::to_string(&wide).unwrap(), r#"{"windows_utf16":"0066d800"}"#);
    }

    #[test]
    fn display_escapes_invalid_and_control() {
        assert_eq!(OsValue::UnixBytes(vec![b'a', 0xff, b'\n']).display(), "a\\xff\\n");
        assert_eq!(OsValue::WindowsWide(vec![0x61, 0xdc00]).display(), "a\\u{dc00}");
        assert_eq!(OsValue::from("\x1b[31m").display(), "\\u{001b}[31m");
    }

    #[test]
    fn portability() {
        assert!(OsValue::from("x").representable_on("windows"));
        assert!(!OsValue::UnixBytes(vec![0xff]).representable_on("windows"));
        assert!(OsValue::UnixBytes(vec![0xff]).representable_on("linux"));
        assert!(!OsValue::WindowsWide(vec![0xd800]).representable_on("macos"));
    }

    #[test]
    fn host_round_trip_and_prefix() {
        let s = OsStr::new("@file:dir/x y.toml");
        let v = OsValue::from_os_str(s);
        assert_eq!(v.to_os_string().unwrap(), s);
        assert_eq!(strip_ascii_prefix(s, "@file:").unwrap(), OsStr::new("dir/x y.toml"));
        assert_eq!(strip_ascii_prefix(s, "@args"), None);
        let (k, v) = split_once_ascii(OsStr::new("A=b=c"), b'=').unwrap();
        assert_eq!((k.as_os_str(), v.as_os_str()), (OsStr::new("A"), OsStr::new("b=c")));
        assert_eq!(split_once_ascii(OsStr::new("novalue"), b'='), None);
    }

    #[test]
    fn host_non_unicode() {
        // Not Unicode: bytes that are not UTF-8 on Unix, an unpaired
        // surrogate on Windows. Each is kept exactly, and the other form
        // cannot be represented.
        #[cfg(unix)]
        let (s, expected, foreign) = {
            use std::os::unix::ffi::OsStrExt;
            let s = OsStr::from_bytes(b"@file:\xff\xfe").to_owned();
            (s, OsValue::UnixBytes(b"@file:\xff\xfe".to_vec()), OsValue::WindowsWide(vec![0xd800]))
        };
        #[cfg(windows)]
        let (s, expected, foreign) = {
            use std::os::windows::ffi::OsStringExt;
            let wide: Vec<u16> = "@file:".encode_utf16().chain([0xd800]).collect();
            (OsString::from_wide(&wide), OsValue::WindowsWide(wide), OsValue::UnixBytes(vec![0xff]))
        };
        let v = OsValue::from_os_str(&s);
        assert_eq!(v, expected);
        assert_eq!(v.to_os_string().unwrap(), s);
        assert!(strip_ascii_prefix(&s, "@file:").unwrap().to_str().is_none());
        assert!(foreign.to_os_string().is_err());
    }
}
