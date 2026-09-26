//! Hard limits applied to untrusted artifact data.
//!
//! Every length read from an artifact is checked against these limits (and
//! against the real file size) before it is used to allocate memory or to
//! drive a loop.

/// Largest manifest the reader will load into memory.
pub const MAX_MANIFEST_LEN: u64 = 64 * 1024 * 1024;

/// Longest allowed single path component, in bytes.
pub const MAX_COMPONENT_LEN: usize = 255;

/// Longest allowed resource path or symlink target, in bytes.
pub const MAX_PATH_LEN: usize = 4096;

/// Maximum ratio between the decoded and stored size of a zstd blob. The
/// densest zstd encoding, a run-length block, turns 4 bytes into at most
/// 128 KiB; larger declared sizes are necessarily lies.
pub const MAX_ZSTD_RATIO: u64 = 32 * 1024;

/// Largest zstd window (history) a frame may require, which bounds the
/// memory decoding needs. bound compresses with smaller windows.
pub const MAX_ZSTD_WINDOW: u64 = 8 * 1024 * 1024;

/// Maximum number of symbolic links followed while resolving one link target.
pub const MAX_SYMLINK_DEPTH: usize = 40;

/// Longest allowed string in informational manifest fields.
pub const MAX_LABEL_LEN: usize = 256;

/// Most resources (files, directories and links) in one manifest. Parsing
/// stops at this count, which bounds the memory an artifact can make a
/// reader allocate.
pub const MAX_RESOURCES: usize = 1_000_000;

/// Most stored blobs in one manifest (at most one per file).
pub const MAX_BLOBS: usize = MAX_RESOURCES;

/// Most elements in the argument template. Real command lines are far
/// shorter: operating systems limit them to a few megabytes (Unix) or
/// 32,767 characters (Windows).
pub const MAX_ARGS: usize = 100_000;

/// Most environment bindings in one manifest.
pub const MAX_ENV: usize = 100_000;

/// Most entries in all the list bindings of one manifest together (see
/// `EnvValue::List`). Like the other lists, each is checked against what is
/// left of this budget before any of its entries is read.
pub const MAX_LIST_ENTRIES: usize = 100_000;
