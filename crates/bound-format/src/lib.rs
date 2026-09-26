//! The on-disk format of bound artifacts.
//!
//! A bound artifact is an ordinary native executable (the *launcher*)
//! followed by three appended regions:
//!
//! ```text
//! [launcher][payload][manifest][footer]
//! ```
//!
//! * the **payload** holds the (compressed) contents of every embedded file;
//! * the **manifest** describes the bound invocation and every resource,
//!   including SHA-256 hashes, in a compact binary encoding (postcard);
//! * the **footer** is a fixed-size little-endian structure at the very end of
//!   the file that locates the other regions and pins the manifest hash.
//!
//! This crate is deliberately platform-independent: it reads, writes and
//! validates artifacts but never runs them. The same parser is used on Linux,
//! macOS and Windows, and it treats every input as untrusted. See
//! `docs/format.md` for the normative description.

#![forbid(unsafe_code)]

mod decode;
pub mod exe;
pub mod footer;
pub mod hash;
pub mod limits;
pub mod manifest;
pub mod names;
pub mod osvalue;
pub mod platform;
pub mod reader;
pub mod verify;
mod wire;
#[cfg(feature = "write")]
pub mod writer;

pub use footer::{FOOTER_LEN, FORMAT_VERSION, Footer, FooterError, MAGIC};
pub use hash::Digest;
pub use manifest::{
    ArgTemplate, Blob, BundleMode, Compression, CwdMode, EnvBinding, EnvValue, ListEntry, Manifest, ManifestError,
    RegionInfo, ResolvedLink, Resource, Target, list_separator, resolve_links,
};
pub use names::{LinkTarget, NameError, NameRules, ResourcePath};
pub use osvalue::OsValue;
pub use platform::Platform;
pub use reader::{ArtifactReader, BlobReader, Blobs, ReadError};
#[cfg(feature = "write")]
pub use writer::{ArtifactWriter, BlobRef, EncodedBlob, Encoder, Truncate, WriteError};
