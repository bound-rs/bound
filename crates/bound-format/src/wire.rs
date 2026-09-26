//! The binary encoding of manifests.
//!
//! Artifacts store their manifest in the [postcard wire format][spec], a
//! compact positional encoding of serde data: no field names; unsigned
//! integers as LEB128 varints; `u8` and `bool` as one byte; strings and
//! byte strings as a varint length followed by the bytes; lists as a varint
//! count followed by the elements; enums as a varint variant index followed
//! by the variant's fields; structs and fixed-size arrays (the 32-byte
//! digests) as their elements in order. The types below are the schema,
//! which `docs/format.md` lists: their fields and variants are never
//! reordered within a format version.
//!
//! Decoding is strict. A list's count is checked against the limits in
//! [`crate::limits`] before any element is read (environment bindings are
//! read by hand for that: the entries of their list values share one budget),
//! values are checked as they
//! become manifest types, bytes after the manifest are an error, and the
//! decoded manifest must encode back to exactly the input, so that every
//! manifest has one encoding (postcard itself accepts over-long varints).
//!
//! [spec]: https://postcard.jamesmunns.com/wire-format

use std::borrow::Cow;

use postcard::ser_flavors::Flavor;
use serde::{Deserialize, Serialize, Serializer};

use crate::hash::Digest;
use crate::limits::{MAX_ARGS, MAX_BLOBS, MAX_ENV, MAX_LIST_ENTRIES, MAX_RESOURCES};
use crate::manifest::{
    ArgTemplate, Blob, BundleMode, Compression, CwdMode, EnvBinding, EnvValue, ListEntry, Manifest, ManifestError,
    RegionInfo, Resource, Target,
};
use crate::names::{LinkTarget, ResourcePath};
use crate::osvalue::OsValue;
use crate::platform::Platform;

// ---------------------------------------------------------------------------
// Schema. The manifest itself is, in order: format version (u16), generator
// (string), platform, launcher region, payload region, target, arguments
// (list), environment (list), working directory, bundle mode, resources
// (list) and blobs (list); see `encode_into` and `decode`.

/// A byte string: resource paths, link targets and non-UTF-8 Unix strings.
#[derive(Deserialize)]
#[serde(transparent)]
struct Bytes<'a>(&'a [u8]);

impl Serialize for Bytes<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

#[derive(Serialize, Deserialize)]
struct WirePlatform<'a> {
    os: &'a str,
    arch: &'a str,
    binary_format: &'a str,
}

#[derive(Serialize, Deserialize)]
struct WireRegion {
    size: u64,
    sha256: [u8; 32],
}

/// A platform string ([`OsValue`]).
#[derive(Serialize, Deserialize)]
enum WireOsValue<'a> {
    Unicode(&'a str),
    #[serde(borrow)]
    UnixBytes(Bytes<'a>),
    /// UTF-16 code units, each a varint.
    WindowsWide(Cow<'a, [u16]>),
}

#[derive(Serialize, Deserialize)]
enum WireTarget<'a> {
    External(#[serde(borrow)] WireOsValue<'a>),
    Embedded(#[serde(borrow)] Bytes<'a>),
}

#[derive(Serialize, Deserialize)]
enum WireArg<'a> {
    Literal(#[serde(borrow)] WireOsValue<'a>),
    Resource(#[serde(borrow)] Bytes<'a>),
    RuntimeArgs,
}

#[derive(Serialize, Deserialize)]
struct WireEnv<'a> {
    #[serde(borrow)]
    name: WireOsValue<'a>,
    #[serde(borrow)]
    value: WireEnvValue<'a>,
}

/// An environment value. [`decode`] reads it by hand ([`Input::env`]), so
/// that list entries are counted before they are read; the derived
/// `Deserialize` serves tools that read manifests with postcard alone.
#[derive(Serialize, Deserialize)]
enum WireEnvValue<'a> {
    Literal(#[serde(borrow)] WireOsValue<'a>),
    Resource(#[serde(borrow)] Bytes<'a>),
    Unset,
    /// Format version 2: the entries before and after the caller's value.
    List(#[serde(borrow)] Vec<WireListEntry<'a>>, #[serde(borrow)] Vec<WireListEntry<'a>>),
}

#[derive(Serialize, Deserialize)]
enum WireListEntry<'a> {
    Literal(#[serde(borrow)] WireOsValue<'a>),
    Resource(#[serde(borrow)] Bytes<'a>),
}

#[derive(Serialize, Deserialize)]
enum WireCwd<'a> {
    Inherit,
    Bundle,
    /// Format version 2.
    Dir(#[serde(borrow)] Bytes<'a>),
}

#[derive(Serialize, Deserialize)]
enum WireBundle {
    Private,
    Shared,
}

#[derive(Serialize, Deserialize)]
enum WireResource<'a> {
    Dir {
        #[serde(borrow)]
        path: Bytes<'a>,
    },
    File {
        #[serde(borrow)]
        path: Bytes<'a>,
        size: u64,
        sha256: [u8; 32],
        executable: bool,
    },
    Symlink {
        #[serde(borrow)]
        path: Bytes<'a>,
        #[serde(borrow)]
        target: Bytes<'a>,
    },
}

#[derive(Serialize, Deserialize)]
struct WireBlob {
    sha256: [u8; 32],
    size: u64,
    offset: u64,
    stored_size: u64,
    compression: WireCompression,
}

#[derive(Serialize, Deserialize)]
enum WireCompression {
    Stored,
    Zstd,
}

// ---------------------------------------------------------------------------
// Encoding

/// Encodes a manifest.
pub(crate) fn encode(manifest: &Manifest) -> Vec<u8> {
    encode_into(manifest, Collect(Vec::new())).expect("encoding into memory cannot fail")
}

fn encode_into<F: Flavor>(m: &Manifest, output: F) -> postcard::Result<F::Output> {
    let mut ser = postcard::Serializer { output };
    m.format.serialize(&mut ser)?;
    m.generator.serialize(&mut ser)?;
    WirePlatform::from(&m.platform).serialize(&mut ser)?;
    WireRegion::from(&m.launcher).serialize(&mut ser)?;
    WireRegion::from(&m.payload).serialize(&mut ser)?;
    WireTarget::from(&m.target).serialize(&mut ser)?;
    (&mut ser).collect_seq(m.args.iter().map(WireArg::from))?;
    (&mut ser).collect_seq(m.env.iter().map(WireEnv::from))?;
    WireCwd::from(&m.cwd).serialize(&mut ser)?;
    WireBundle::from(m.bundle).serialize(&mut ser)?;
    (&mut ser).collect_seq(m.resources.iter().map(WireResource::from))?;
    (&mut ser).collect_seq(m.blobs.iter().map(WireBlob::from))?;
    ser.output.finalize()
}

/// Collects an encoding in memory.
struct Collect(Vec<u8>);

impl Flavor for Collect {
    type Output = Vec<u8>;

    fn try_extend(&mut self, data: &[u8]) -> postcard::Result<()> {
        self.0.extend_from_slice(data);
        Ok(())
    }

    fn try_push(&mut self, data: u8) -> postcard::Result<()> {
        self.0.push(data);
        Ok(())
    }

    fn finalize(self) -> postcard::Result<Vec<u8>> {
        Ok(self.0)
    }
}

/// Compares an encoding with existing bytes as it is produced, without
/// building a copy; the output is whether they were equal.
struct Compare<'a> {
    rest: &'a [u8],
}

impl Flavor for Compare<'_> {
    type Output = bool;

    fn try_extend(&mut self, data: &[u8]) -> postcard::Result<()> {
        match self.rest.strip_prefix(data) {
            Some(rest) => {
                self.rest = rest;
                Ok(())
            }
            None => Err(postcard::Error::SerializeBufferFull),
        }
    }

    fn try_push(&mut self, data: u8) -> postcard::Result<()> {
        self.try_extend(&[data])
    }

    fn finalize(self) -> postcard::Result<bool> {
        Ok(self.rest.is_empty())
    }
}

impl<'a> From<&'a Platform> for WirePlatform<'a> {
    fn from(p: &'a Platform) -> Self {
        WirePlatform { os: &p.os, arch: &p.arch, binary_format: &p.binary_format }
    }
}

impl From<&RegionInfo> for WireRegion {
    fn from(r: &RegionInfo) -> Self {
        WireRegion { size: r.size, sha256: r.sha256.0 }
    }
}

impl<'a> From<&'a OsValue> for WireOsValue<'a> {
    fn from(value: &'a OsValue) -> Self {
        match value {
            OsValue::Unicode(text) => WireOsValue::Unicode(text),
            OsValue::UnixBytes(bytes) => WireOsValue::UnixBytes(Bytes(bytes)),
            OsValue::WindowsWide(wide) => WireOsValue::WindowsWide(Cow::Borrowed(wide)),
        }
    }
}

impl<'a> From<&'a Target> for WireTarget<'a> {
    fn from(target: &'a Target) -> Self {
        match target {
            Target::External { program } => WireTarget::External(program.into()),
            Target::Embedded { resource } => WireTarget::Embedded(Bytes(resource.as_bytes())),
        }
    }
}

impl<'a> From<&'a ArgTemplate> for WireArg<'a> {
    fn from(arg: &'a ArgTemplate) -> Self {
        match arg {
            ArgTemplate::Literal { value } => WireArg::Literal(value.into()),
            ArgTemplate::Resource { path } => WireArg::Resource(Bytes(path.as_bytes())),
            ArgTemplate::RuntimeArgs => WireArg::RuntimeArgs,
        }
    }
}

impl<'a> From<&'a EnvBinding> for WireEnv<'a> {
    fn from(binding: &'a EnvBinding) -> Self {
        let value = match &binding.value {
            EnvValue::Literal { value } => WireEnvValue::Literal(value.into()),
            EnvValue::Resource { path } => WireEnvValue::Resource(Bytes(path.as_bytes())),
            EnvValue::Unset {} => WireEnvValue::Unset,
            EnvValue::List { before, after } => WireEnvValue::List(
                before.iter().map(WireListEntry::from).collect(),
                after.iter().map(WireListEntry::from).collect(),
            ),
        };
        WireEnv { name: (&binding.name).into(), value }
    }
}

impl<'a> From<&'a ListEntry> for WireListEntry<'a> {
    fn from(entry: &'a ListEntry) -> Self {
        match entry {
            ListEntry::Literal { value } => WireListEntry::Literal(value.into()),
            ListEntry::Resource { path } => WireListEntry::Resource(Bytes(path.as_bytes())),
        }
    }
}

impl<'a> From<&'a CwdMode> for WireCwd<'a> {
    fn from(cwd: &'a CwdMode) -> Self {
        match cwd {
            CwdMode::Inherit => WireCwd::Inherit,
            CwdMode::Bundle => WireCwd::Bundle,
            CwdMode::Dir(path) => WireCwd::Dir(Bytes(path.as_bytes())),
        }
    }
}

impl From<BundleMode> for WireBundle {
    fn from(bundle: BundleMode) -> Self {
        match bundle {
            BundleMode::Private => WireBundle::Private,
            BundleMode::Shared => WireBundle::Shared,
        }
    }
}

impl<'a> From<&'a Resource> for WireResource<'a> {
    fn from(resource: &'a Resource) -> Self {
        match resource {
            Resource::Dir { path } => WireResource::Dir { path: Bytes(path.as_bytes()) },
            Resource::File { path, size, sha256, executable } => WireResource::File {
                path: Bytes(path.as_bytes()),
                size: *size,
                sha256: sha256.0,
                executable: *executable,
            },
            Resource::Symlink { path, target } => {
                WireResource::Symlink { path: Bytes(path.as_bytes()), target: Bytes(target.as_bytes()) }
            }
        }
    }
}

impl From<&Blob> for WireBlob {
    fn from(blob: &Blob) -> Self {
        WireBlob {
            sha256: blob.sha256.0,
            size: blob.size,
            offset: blob.offset,
            stored_size: blob.stored_size,
            compression: match blob.compression {
                Compression::Stored => WireCompression::Stored,
                Compression::Zstd => WireCompression::Zstd,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Decoding

/// Decodes a manifest and checks that `bytes` are its only encoding. The
/// manifest still has to be validated.
pub(crate) fn decode(bytes: &[u8]) -> Result<Manifest, ManifestError> {
    let mut input = Input { de: postcard::Deserializer::from_bytes(bytes) };
    let format = input.field("format version")?;
    let generator = input.field::<&str>("generator")?.to_owned();
    let platform = input.field::<WirePlatform<'_>>("platform")?.parse();
    let launcher = input.field::<WireRegion>("launcher region")?.parse();
    let payload = input.field::<WireRegion>("payload region")?.parse();
    let target = input.field::<WireTarget<'_>>("target")?.parse().map_err(|e| ManifestError(format!("target: {e}")))?;
    let args = input.list("argument", MAX_ARGS, WireArg::parse)?;
    let env = input.env()?;
    let cwd = input
        .field::<WireCwd<'_>>("working directory")?
        .parse()
        .map_err(|e| ManifestError(format!("working directory: {e}")))?;
    let bundle = input.field::<WireBundle>("bundle mode")?.parse();
    let resources = input.list("resource", MAX_RESOURCES, WireResource::parse)?;
    let blobs = input.list("blob", MAX_BLOBS, |blob: WireBlob| Ok(blob.parse()))?;
    let rest = input.de.finalize().map_err(|e| ManifestError(describe(e).to_owned()))?;
    if !rest.is_empty() {
        return Err(ManifestError("unexpected data after the manifest".into()));
    }

    let manifest =
        Manifest { format, generator, platform, launcher, payload, target, args, env, cwd, bundle, resources, blobs };
    if !matches!(encode_into(&manifest, Compare { rest: bytes }), Ok(true)) {
        return Err(ManifestError("manifest is not in canonical form".into()));
    }
    Ok(manifest)
}

struct Input<'de> {
    de: postcard::Deserializer<'de, postcard::de_flavors::Slice<'de>>,
}

impl<'de> Input<'de> {
    /// Reads the next value; `what` names it in errors.
    fn read<T: Deserialize<'de>>(&mut self, what: impl FnOnce() -> String) -> Result<T, ManifestError> {
        T::deserialize(&mut self.de).map_err(|e| ManifestError(format!("{}: {}", what(), describe(e))))
    }

    fn field<T: Deserialize<'de>>(&mut self, name: &str) -> Result<T, ManifestError> {
        self.read(|| name.to_owned())
    }

    /// Reads a list of at most `max` elements, each converted by `parse`.
    fn list<W: Deserialize<'de>, T>(
        &mut self,
        noun: &str,
        max: usize,
        parse: impl Fn(W) -> Result<T, String>,
    ) -> Result<Vec<T>, ManifestError> {
        // A list is a varint count (postcard's usize, which reads the same
        // as a u64) followed by the elements. The count is checked before
        // anything is allocated for the elements.
        let count: u64 = self.read(|| format!("number of {noun}s"))?;
        if count > max as u64 {
            return Err(ManifestError(format!("more than {max} {noun}s")));
        }
        let mut out = Vec::with_capacity(count.min(4096) as usize);
        for i in 0..count {
            let wire = self.read(|| format!("{noun} {i}"))?;
            out.push(parse(wire).map_err(|e| ManifestError(format!("{noun} {i}: {e}")))?);
        }
        Ok(out)
    }

    /// Reads the environment bindings. They are read by hand rather than as
    /// derived values, so that the entries of all list values together are
    /// checked against [`MAX_LIST_ENTRIES`] before any of them is read.
    fn env(&mut self) -> Result<Vec<EnvBinding>, ManifestError> {
        let count: u64 = self.read(|| "number of environment bindings".to_owned())?;
        if count > MAX_ENV as u64 {
            return Err(ManifestError(format!("more than {MAX_ENV} environment bindings")));
        }
        let mut budget = MAX_LIST_ENTRIES as u64;
        let mut out = Vec::with_capacity(count.min(4096) as usize);
        for i in 0..count {
            let at = |e: String| ManifestError(format!("environment binding {i}: {e}"));
            let name = self.read::<WireOsValue<'_>>(|| format!("environment binding {i}"))?.parse().map_err(at)?;
            // An enum is its variant index, a varint, then the variant's fields.
            let value = match self.read::<u32>(|| format!("environment binding {i}"))? {
                0 => EnvValue::Literal {
                    value: self.read::<WireOsValue<'_>>(|| format!("environment binding {i}"))?.parse().map_err(at)?,
                },
                1 => EnvValue::Resource {
                    path: parse_path(self.read(|| format!("environment binding {i}"))?).map_err(at)?,
                },
                2 => EnvValue::Unset {},
                3 => {
                    let before = self.list_entries(i, "before", &mut budget)?;
                    let after = self.list_entries(i, "after", &mut budget)?;
                    EnvValue::List { before, after }
                }
                _ => return Err(at("unknown variant".into())),
            };
            out.push(EnvBinding { name, value });
        }
        Ok(out)
    }

    /// Reads one of a list value's two entry lists, spending `budget`.
    fn list_entries(&mut self, binding: u64, part: &str, budget: &mut u64) -> Result<Vec<ListEntry>, ManifestError> {
        let count: u64 = self.read(|| format!("environment binding {binding}: number of {part} entries"))?;
        if count > *budget {
            return Err(ManifestError(format!("more than {MAX_LIST_ENTRIES} list entries")));
        }
        *budget -= count;
        let mut out = Vec::with_capacity(count.min(4096) as usize);
        for j in 0..count {
            let what = || format!("environment binding {binding}: {part} entry {j}");
            let at = |e: String| ManifestError(format!("{}: {e}", what()));
            out.push(match self.read::<u32>(what)? {
                0 => ListEntry::Literal { value: self.read::<WireOsValue<'_>>(what)?.parse().map_err(at)? },
                1 => ListEntry::Resource { path: parse_path(self.read(what)?).map_err(at)? },
                _ => return Err(at("unknown variant".into())),
            });
        }
        Ok(out)
    }
}

/// Describes a decoding error. postcard's messages are fixed strings: no
/// input is ever echoed.
fn describe(e: postcard::Error) -> &'static str {
    match e {
        postcard::Error::DeserializeUnexpectedEnd => "unexpected end of data",
        postcard::Error::DeserializeBadVarint => "malformed or out-of-range integer",
        postcard::Error::DeserializeBadBool => "malformed boolean",
        postcard::Error::DeserializeBadUtf8 => "text is not valid UTF-8",
        // serde reports unknown variant indexes with a custom error, which
        // is the only kind of custom error these types produce.
        postcard::Error::DeserializeBadEnum | postcard::Error::SerdeDeCustom => "unknown variant",
        _ => "malformed data",
    }
}

fn parse_path(bytes: Bytes<'_>) -> Result<ResourcePath, String> {
    ResourcePath::from_bytes(bytes.0).map_err(|e| e.to_string())
}

impl WirePlatform<'_> {
    fn parse(self) -> Platform {
        Platform { os: self.os.to_owned(), arch: self.arch.to_owned(), binary_format: self.binary_format.to_owned() }
    }
}

impl WireRegion {
    fn parse(self) -> RegionInfo {
        RegionInfo { size: self.size, sha256: Digest(self.sha256) }
    }
}

impl WireOsValue<'_> {
    /// Non-Unicode forms are only for values that are not valid Unicode,
    /// so that each value has one encoding.
    fn parse(self) -> Result<OsValue, String> {
        match self {
            WireOsValue::Unicode(text) => Ok(OsValue::Unicode(text.to_owned())),
            WireOsValue::UnixBytes(Bytes(bytes)) => {
                if std::str::from_utf8(bytes).is_ok() {
                    return Err("a string stored as bytes is valid UTF-8 (it must be stored as Unicode)".into());
                }
                Ok(OsValue::UnixBytes(bytes.to_vec()))
            }
            WireOsValue::WindowsWide(wide) => {
                if char::decode_utf16(wide.iter().copied()).all(|c| c.is_ok()) {
                    return Err("a string stored as UTF-16 is well-formed (it must be stored as Unicode)".into());
                }
                Ok(OsValue::WindowsWide(wide.into_owned()))
            }
        }
    }
}

impl WireTarget<'_> {
    fn parse(self) -> Result<Target, String> {
        Ok(match self {
            WireTarget::External(program) => Target::External { program: program.parse()? },
            WireTarget::Embedded(resource) => Target::Embedded { resource: parse_path(resource)? },
        })
    }
}

impl WireArg<'_> {
    fn parse(self) -> Result<ArgTemplate, String> {
        Ok(match self {
            WireArg::Literal(value) => ArgTemplate::Literal { value: value.parse()? },
            WireArg::Resource(path) => ArgTemplate::Resource { path: parse_path(path)? },
            WireArg::RuntimeArgs => ArgTemplate::RuntimeArgs,
        })
    }
}

impl WireCwd<'_> {
    fn parse(self) -> Result<CwdMode, String> {
        Ok(match self {
            WireCwd::Inherit => CwdMode::Inherit,
            WireCwd::Bundle => CwdMode::Bundle,
            WireCwd::Dir(path) => CwdMode::Dir(parse_path(path)?),
        })
    }
}

impl WireBundle {
    fn parse(self) -> BundleMode {
        match self {
            WireBundle::Private => BundleMode::Private,
            WireBundle::Shared => BundleMode::Shared,
        }
    }
}

impl WireResource<'_> {
    fn parse(self) -> Result<Resource, String> {
        Ok(match self {
            WireResource::Dir { path } => Resource::Dir { path: parse_path(path)? },
            WireResource::File { path, size, sha256, executable } => {
                Resource::File { path: parse_path(path)?, size, sha256: Digest(sha256), executable }
            }
            WireResource::Symlink { path, target } => Resource::Symlink {
                path: parse_path(path)?,
                target: LinkTarget::from_bytes(target.0).map_err(|e| e.to_string())?,
            },
        })
    }
}

impl WireBlob {
    fn parse(self) -> Blob {
        Blob {
            sha256: Digest(self.sha256),
            size: self.size,
            offset: self.offset,
            stored_size: self.stored_size,
            compression: match self.compression {
                WireCompression::Stored => Compression::Stored,
                WireCompression::Zstd => Compression::Zstd,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(s: &str) -> ResourcePath {
        ResourcePath::new(s).unwrap()
    }

    /// A small manifest whose encoding is spelled out in `golden_fields`.
    fn golden() -> Manifest {
        Manifest {
            format: 1,
            generator: "bound 0.1.0".into(),
            platform: Platform { os: "linux".into(), arch: "x86_64".into(), binary_format: "elf".into() },
            launcher: RegionInfo { size: 1000, sha256: Digest([0xaa; 32]) },
            payload: RegionInfo { size: 5, sha256: Digest([0xbb; 32]) },
            target: Target::External { program: "grep".into() },
            args: vec![
                ArgTemplate::Literal { value: "-n".into() },
                ArgTemplate::Resource { path: rp("a.txt") },
                ArgTemplate::RuntimeArgs,
            ],
            env: vec![EnvBinding { name: "MODE".into(), value: EnvValue::Literal { value: "prod".into() } }],
            cwd: CwdMode::Bundle,
            bundle: BundleMode::Shared,
            resources: vec![Resource::File {
                path: rp("a.txt"),
                size: 5,
                sha256: Digest([0xcc; 32]),
                executable: false,
            }],
            blobs: vec![Blob {
                sha256: Digest([0xcc; 32]),
                size: 5,
                offset: 0,
                stored_size: 5,
                compression: Compression::Stored,
            }],
        }
    }

    /// The encoding of [`golden`], field by field: this pins the format.
    fn golden_fields() -> Vec<(&'static str, Vec<u8>)> {
        let cat = |parts: &[&[u8]]| parts.concat();
        vec![
            ("format", vec![1]),
            ("generator", cat(&[&[11], b"bound 0.1.0"])),
            ("platform", cat(&[&[5], b"linux", &[6], b"x86_64", &[3], b"elf"])),
            // 1000 as a varint, then the digest.
            ("launcher", cat(&[&[0xe8, 0x07], &[0xaa; 32]])),
            ("payload", cat(&[&[5], &[0xbb; 32]])),
            // External, Unicode, "grep".
            ("target", cat(&[&[0, 0, 4], b"grep"])),
            // Three arguments: Literal(Unicode "-n"), Resource "a.txt", RuntimeArgs.
            ("args", cat(&[&[3, 0, 0, 2], b"-n", &[1, 5], b"a.txt", &[2]])),
            // One binding: name Unicode "MODE", value Literal(Unicode "prod").
            ("env", cat(&[&[1, 0, 4], b"MODE", &[0, 0, 4], b"prod"])),
            ("cwd", vec![1]),
            ("bundle", vec![1]),
            // One File: path, size, digest, not executable.
            ("resources", cat(&[&[1, 1, 5], b"a.txt", &[5], &[0xcc; 32], &[0]])),
            // One blob: digest, size, offset, stored size, Stored.
            ("blobs", cat(&[&[1], &[0xcc; 32], &[5, 0, 5, 0]])),
        ]
    }

    /// The golden encoding with one field replaced by `bytes`.
    fn with_field(name: &str, bytes: &[u8]) -> Vec<u8> {
        let fields = golden_fields();
        assert!(fields.iter().any(|(n, _)| *n == name), "no field {name}");
        fields.into_iter().flat_map(|(n, b)| if n == name { bytes.to_vec() } else { b }).collect()
    }

    fn decode_err(bytes: &[u8]) -> String {
        decode(bytes).expect_err("decoding should fail").0
    }

    #[test]
    fn the_encoding_is_pinned() {
        let expected: Vec<u8> = golden_fields().into_iter().flat_map(|(_, b)| b).collect();
        assert_eq!(encode(&golden()), expected);
        assert_eq!(decode(&expected).unwrap(), golden());
    }

    #[test]
    fn the_encoding_is_plain_postcard() {
        // The same schema as one derived struct: tools can read manifests
        // with postcard and these definitions alone.
        #[derive(Serialize, Deserialize)]
        struct Schema<'a> {
            format: u16,
            generator: &'a str,
            #[serde(borrow)]
            platform: WirePlatform<'a>,
            launcher: WireRegion,
            payload: WireRegion,
            #[serde(borrow)]
            target: WireTarget<'a>,
            #[serde(borrow)]
            args: Vec<WireArg<'a>>,
            #[serde(borrow)]
            env: Vec<WireEnv<'a>>,
            #[serde(borrow)]
            cwd: WireCwd<'a>,
            bundle: WireBundle,
            #[serde(borrow)]
            resources: Vec<WireResource<'a>>,
            blobs: Vec<WireBlob>,
        }
        let m = varied();
        let schema = Schema {
            format: m.format,
            generator: &m.generator,
            platform: (&m.platform).into(),
            launcher: (&m.launcher).into(),
            payload: (&m.payload).into(),
            target: (&m.target).into(),
            args: m.args.iter().map(WireArg::from).collect(),
            env: m.env.iter().map(WireEnv::from).collect(),
            cwd: (&m.cwd).into(),
            bundle: m.bundle.into(),
            resources: m.resources.iter().map(WireResource::from).collect(),
            blobs: m.blobs.iter().map(WireBlob::from).collect(),
        };
        let bytes = postcard::serialize_with_flavor(&schema, Collect(Vec::new())).unwrap();
        assert_eq!(bytes, encode(&m));
        let read: Schema<'_> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(read.resources.len(), m.resources.len());
        assert_eq!(read.env.len(), m.env.len());
    }

    /// Every kind of value (the manifest need not be valid to encode).
    fn varied() -> Manifest {
        let mut m = golden();
        m.target = Target::Embedded { resource: rp("bin/tool") };
        m.args.push(ArgTemplate::Literal { value: OsValue::UnixBytes(vec![0x66, 0xff]) });
        m.args.push(ArgTemplate::Literal { value: OsValue::WindowsWide(vec![0x66, 0xd800]) });
        m.env.push(EnvBinding { name: "CONFIG".into(), value: EnvValue::Resource { path: rp("a.txt") } });
        m.env.push(EnvBinding { name: "RUNFILES_MANIFEST_FILE".into(), value: EnvValue::Unset {} });
        m.env.push(EnvBinding {
            name: "PATH".into(),
            value: EnvValue::List {
                before: vec![ListEntry::Resource { path: rp("bin") }, ListEntry::Literal { value: "/opt/x".into() }],
                after: vec![ListEntry::Literal { value: OsValue::UnixBytes(vec![0xff]) }],
            },
        });
        m.cwd = CwdMode::Dir(rp("bin"));
        m.bundle = BundleMode::Private;
        m.resources.insert(0, Resource::Dir { path: rp("bin") });
        m.resources.push(Resource::Symlink { path: rp("link"), target: LinkTarget::from_bytes(b"../x").unwrap() });
        m.blobs[0].compression = Compression::Zstd;
        m.blobs[0].size = u64::MAX;
        m
    }

    #[test]
    fn every_kind_of_value_round_trips() {
        let m = varied();
        assert_eq!(decode(&encode(&m)).unwrap(), m);
    }

    #[test]
    fn truncated_or_extended_encodings_are_rejected() {
        let bytes = encode(&varied());
        for cut in 0..bytes.len() {
            assert!(decode(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        let err = decode_err(&[bytes.as_slice(), &[0]].concat());
        assert!(err.contains("unexpected data after the manifest"), "{err}");
    }

    #[test]
    fn only_the_canonical_encoding_is_accepted() {
        // 1 as a two-byte varint describes the same manifest.
        let err = decode_err(&with_field("format", &[0x81, 0x00]));
        assert!(err.contains("canonical"), "{err}");
        let err = decode_err(&with_field("cwd", &[0x81, 0x00]));
        assert!(err.contains("canonical"), "{err}");
        // Values that are valid Unicode must be stored as Unicode.
        let err = decode_err(&with_field("target", &[0, 1, 3, b'a', b'b', b'c']));
        assert!(err.contains("target: a string stored as bytes is valid UTF-8"), "{err}");
        let err = decode_err(&with_field("target", &[0, 2, 1, 0x61]));
        assert!(err.contains("target: a string stored as UTF-16 is well-formed"), "{err}");
        // An unpaired surrogate (0xd800) is what the UTF-16 form is for.
        let lone = with_field("target", &[0, 2, 1, 0x80, 0xb0, 0x03]);
        assert_eq!(decode(&lone).unwrap().target, Target::External { program: OsValue::WindowsWide(vec![0xd800]) });
    }

    #[test]
    fn malformed_values_are_rejected_with_their_location() {
        let cases: &[(&str, &[u8], &str)] = &[
            ("target", &[7], "target: unknown variant"),
            ("cwd", &[3], "working directory: unknown variant"),
            ("cwd", &[2, 3, b'.', b'.', b'/'], "working directory: unsafe resource path"),
            ("env", &[1, 0, 1, b'X', 4], "environment binding 0: unknown variant"),
            ("env", &[1, 0, 1, b'X', 3, 1, 2], "environment binding 0: before entry 0: unknown variant"),
            ("generator", &[2, 0xff, 0xfe], "generator: text is not valid UTF-8"),
            ("format", &[0xff, 0xff, 0xff, 0x01], "format version: malformed or out-of-range integer"),
            ("args", &[1, 9], "argument 0: unknown variant"),
            ("resources", &[1, 0, 4, b'.', b'.', b'/', b'x'], "resource 0: unsafe resource path \"../x\""),
            ("resources", &[1, 2, 1, b'l', 2, b'/', b'x'], "resource 0: unsafe resource path \"/x\""),
        ];
        for (field, bytes, expected) in cases {
            let err = decode_err(&with_field(field, bytes));
            assert!(err.contains(expected), "{field}: {err}");
        }
        let mut file = with_field("blobs", &[0]);
        let flag = file.len() - 2; // the File's executable flag, before the empty blob list
        file[flag] = 2;
        let err = decode_err(&file);
        assert!(err.contains("resource 0: malformed boolean"), "{err}");
    }

    #[test]
    fn lists_are_bounded_before_their_elements_are_read() {
        // A count of u64::MAX with nothing after it.
        let err = decode_err(&with_field("args", &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]));
        assert!(err.contains(&format!("more than {MAX_ARGS} arguments")), "{err}");
        let mut count = Vec::new();
        let mut n = MAX_RESOURCES as u64 + 1;
        while n >= 0x80 {
            count.push((n as u8) | 0x80);
            n >>= 7;
        }
        count.push(n as u8);
        let err = decode_err(&with_field("resources", &count));
        assert!(err.contains(&format!("more than {MAX_RESOURCES} resources")), "{err}");
    }

    /// A varint.
    fn varint(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while n >= 0x80 {
            out.push((n as u8) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
        out
    }

    #[test]
    fn version_2_values_are_pinned() {
        let cat = |parts: &[&[u8]]| parts.concat();
        // Dir, then the path.
        let bytes = with_field("cwd", &cat(&[&[2, 3], b"bin"]));
        assert_eq!(decode(&bytes).unwrap().cwd, CwdMode::Dir(rp("bin")));
        // One binding "P": List, one entry before (Resource "a.txt"), one
        // after (Literal Unicode "x").
        let bytes = with_field("env", &cat(&[&[1, 0, 1], b"P", &[3, 1, 1, 5], b"a.txt", &[1, 0, 0, 1], b"x"]));
        let expected = EnvValue::List {
            before: vec![ListEntry::Resource { path: rp("a.txt") }],
            after: vec![ListEntry::Literal { value: "x".into() }],
        };
        assert_eq!(decode(&bytes).unwrap().env[0].value, expected);
    }

    #[test]
    fn list_entries_share_one_budget_checked_before_they_are_read() {
        // A count past the budget with nothing after it.
        let too_many = [&[1, 0, 1, b'P', 3][..], &varint(MAX_LIST_ENTRIES as u64 + 1)].concat();
        let err = decode_err(&with_field("env", &too_many));
        assert!(err.contains(&format!("more than {MAX_LIST_ENTRIES} list entries")), "{err}");
        // A full budget in one list leaves nothing for the next.
        let mut full = [&[1, 0, 1, b'P', 3][..], &varint(MAX_LIST_ENTRIES as u64)].concat();
        for _ in 0..MAX_LIST_ENTRIES {
            full.extend_from_slice(&[0, 0, 1, b'a']);
        }
        full.push(1);
        let err = decode_err(&with_field("env", &full));
        assert!(err.contains(&format!("more than {MAX_LIST_ENTRIES} list entries")), "{err}");
    }

    #[test]
    fn error_messages_do_not_echo_control_characters() {
        let path = b"x\x1b]0;pwned\x07";
        let err = decode_err(&with_field("resources", &[&[1, 0, path.len() as u8][..], path].concat()));
        assert!(err.contains("resource 0: unsafe resource path"), "{err}");
        assert!(!err.contains('\u{1b}') && !err.contains('\u{7}'), "{err:?}");
    }

    #[test]
    fn damaged_encodings_never_panic_and_never_decode_ambiguously() {
        let bytes = encode(&varied());
        for i in 0..bytes.len() {
            for mask in [0x01, 0x80, 0xff] {
                let mut damaged = bytes.clone();
                damaged[i] ^= mask;
                if let Ok(m) = decode(&damaged) {
                    assert_eq!(encode(&m), damaged, "byte {i} mask {mask:#x}");
                }
            }
        }
    }

    #[test]
    fn the_encoding_is_compact() {
        let mut m = golden();
        m.resources.clear();
        m.blobs.clear();
        for i in 0..1000u32 {
            let sha256 = Digest::of(&i.to_le_bytes());
            m.resources.push(Resource::File {
                path: rp(&format!("f{i:04}.txt")),
                size: 100,
                sha256,
                executable: false,
            });
            m.blobs.push(Blob { sha256, size: 100, offset: 0, stored_size: 60, compression: Compression::Zstd });
        }
        let binary = encode(&m).len();
        let json = serde_json::to_vec_pretty(&m).unwrap().len();
        assert!(binary * 4 < json, "binary {binary} bytes, JSON {json} bytes");
    }
}
