//! Writing artifacts.
//!
//! Output is deterministic: the same launcher bytes, contents (added in the
//! same order) and manifest always produce byte-identical artifacts, on any
//! machine and with any number of threads. How each content is stored
//! depends only on its bytes: content whose first 64 KiB do not compress
//! (media, archives, already-compressed data) is stored as is; everything
//! else is compressed with zstd at a fixed level. Contents smaller than
//! [`LARGE_CONTENT`] are compressed in one piece by an [`Encoder`], which
//! may run on any thread ([`ArtifactWriter::add_encoded`]); larger ones are
//! streamed through zstd's multithreaded mode, whose output does not depend
//! on the number of threads.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use zstd::stream::raw::CParameter;

use crate::exe;
use crate::footer::FOOTER_LEN;
use crate::footer::Footer;
use crate::hash::{Digest, Hasher};
use crate::limits::MAX_MANIFEST_LEN;
use crate::manifest::{Blob, Compression, Manifest, ManifestError, RegionInfo};
use crate::names::NameRules;

/// zstd compression level for every compressed blob.
const LEVEL: i32 = 9;
/// Level used to estimate whether content compresses.
const PROBE_LEVEL: i32 = 1;
/// How much of a content decides whether it is compressed.
const PROBE_LEN: usize = 64 * 1024;
/// Contents of at least this size are streamed rather than compressed in
/// one piece.
pub const LARGE_CONTENT: u64 = 8 * 1024 * 1024;
/// Read size when streaming large contents and the launcher.
const CHUNK: usize = 1024 * 1024;
/// zstd's unit of work when it compresses a large content on several
/// threads.
const ZSTD_JOB_SIZE: u32 = 4 * 1024 * 1024;
/// Most threads zstd uses for one content.
const MAX_ZSTD_WORKERS: u32 = 4;
/// Largest launcher accepted (they are about 1 MiB).
const MAX_LAUNCHER_LEN: u64 = 256 * 1024 * 1024;

/// Output streams that can be cut back, used to discard duplicate content.
pub trait Truncate {
    fn truncate_to(&mut self, len: u64) -> io::Result<()>;
}

impl Truncate for File {
    fn truncate_to(&mut self, len: u64) -> io::Result<()> {
        self.set_len(len)
    }
}

impl Truncate for Cursor<Vec<u8>> {
    fn truncate_to(&mut self, len: u64) -> io::Result<()> {
        let len = usize::try_from(len).map_err(|_| io::Error::other("length overflow"))?;
        self.get_mut().truncate(len);
        Ok(())
    }
}

impl<T: Truncate + ?Sized> Truncate for &mut T {
    fn truncate_to(&mut self, len: u64) -> io::Result<()> {
        (**self).truncate_to(len)
    }
}

/// Errors from finishing an artifact.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("refusing to write an invalid manifest: {0}")]
    Manifest(#[from] ManifestError),
}

/// Identifies content added with [`ArtifactWriter::add_blob`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobRef {
    pub sha256: Digest,
    pub size: u64,
}

/// A content encoded for storage by an [`Encoder`], ready to be appended
/// with [`ArtifactWriter::add_encoded`].
#[derive(Debug)]
pub struct EncodedBlob {
    sha256: Digest,
    size: u64,
    compression: Compression,
    data: Vec<u8>,
}

impl EncodedBlob {
    pub fn sha256(&self) -> Digest {
        self.sha256
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn compression(&self) -> Compression {
        self.compression
    }
}

/// Compression state for contents smaller than [`LARGE_CONTENT`]. Create one
/// per thread and reuse it.
pub struct Encoder {
    compressor: zstd::bulk::Compressor<'static>,
    probe: zstd::bulk::Compressor<'static>,
}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encoder").finish_non_exhaustive()
    }
}

impl Encoder {
    pub fn new() -> io::Result<Encoder> {
        let mut compressor = zstd::bulk::Compressor::new(LEVEL)?;
        // Contents are verified with SHA-256; zstd's own checksum would be
        // redundant.
        compressor.set_parameter(CParameter::ChecksumFlag(false))?;
        compressor.set_parameter(CParameter::ContentSizeFlag(true))?;
        compressor.set_parameter(CParameter::DictIdFlag(false))?;
        let probe = zstd::bulk::Compressor::new(PROBE_LEVEL)?;
        Ok(Encoder { compressor, probe })
    }

    /// Encodes one content held in memory, which must be smaller than
    /// [`LARGE_CONTENT`]: hashes it, and compresses it if that is worth it.
    pub fn encode(&mut self, content: Vec<u8>) -> io::Result<EncodedBlob> {
        let size = content.len() as u64;
        if size >= LARGE_CONTENT {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "content is too large to encode in memory"));
        }
        let sha256 = Digest::of(&content);
        if self.worth_compressing(&content[..content.len().min(PROBE_LEN)])? {
            let compressed = self.compressor.compress(&content)?;
            if compressed.len() < content.len() {
                return Ok(EncodedBlob { sha256, size, compression: Compression::Zstd, data: compressed });
            }
        }
        Ok(EncodedBlob { sha256, size, compression: Compression::Stored, data: content })
    }

    /// Whether `sample` (the start of a content) shrinks by at least about
    /// 3% when compressed at a fast level. Depends only on the bytes.
    fn worth_compressing(&mut self, sample: &[u8]) -> io::Result<bool> {
        if sample.is_empty() {
            return Ok(false);
        }
        let compressed = self.probe.compress(sample)?;
        Ok(compressed.len() < sample.len() - sample.len() / 32)
    }
}

/// Incrementally writes `[launcher][payload][manifest][footer]`, followed
/// for Mach-O launchers by an ad-hoc code signature.
pub struct ArtifactWriter<W> {
    prepared: exe::PreparedLauncher,
    out: W,
    launcher: RegionInfo,
    payload_len: u64,
    /// Hash of the payload written so far.
    payload_hasher: Hasher,
    blobs: Vec<Blob>,
    /// Blob position by content hash, for deduplication.
    index: HashMap<Digest, usize>,
    encoder: Encoder,
    /// zstd workers for large contents.
    threads: u32,
}

impl<W> std::fmt::Debug for ArtifactWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtifactWriter")
            .field("launcher", &self.launcher)
            .field("payload_len", &self.payload_len)
            .field("blobs", &self.blobs.len())
            .finish()
    }
}

impl<W: Read + Write + Seek + Truncate> ArtifactWriter<W> {
    /// Starts an artifact by copying the launcher into the (empty) output.
    ///
    /// A code signature the launcher carries is removed: it would cover
    /// only the launcher, and a signature must be the last thing in a file.
    /// Mach-O artifacts get an ad-hoc signature of their own when finished.
    pub fn new(mut out: W, launcher: &mut dyn Read) -> io::Result<ArtifactWriter<W>> {
        let mut bytes = Vec::new();
        launcher.take(MAX_LAUNCHER_LEN + 1).read_to_end(&mut bytes)?;
        if bytes.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "launcher is empty"));
        }
        if bytes.len() as u64 > MAX_LAUNCHER_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "launcher is larger than 256 MiB"));
        }
        let prepared = exe::prepare_launcher(&mut bytes)?;
        // The launcher's hash leaves out the header fields signing rewrites.
        let fields = exe::layout(&bytes[..bytes.len().min(exe::HEADER_LEN)]).signing_fields;
        let mut normalized = bytes[..bytes.len().min(exe::HEADER_LEN)].to_vec();
        exe::blank_fields(&mut normalized, 0, &fields);
        let mut hasher = Hasher::new();
        hasher.update(&normalized);
        hasher.update(&bytes[normalized.len()..]);

        out.seek(SeekFrom::Start(0))?;
        out.truncate_to(0)?;
        out.write_all(&bytes)?;
        let size = bytes.len() as u64;
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get().min(8)) as u32;
        Ok(ArtifactWriter {
            prepared,
            out,
            launcher: RegionInfo { size, sha256: hasher.finalize() },
            payload_len: 0,
            payload_hasher: Hasher::new(),
            blobs: Vec::new(),
            index: HashMap::new(),
            encoder: Encoder::new()?,
            threads,
        })
    }

    pub fn launcher(&self) -> &RegionInfo {
        &self.launcher
    }

    /// Sets how many threads compress each large content. This affects
    /// speed only: the output is the same for any count.
    pub fn set_threads(&mut self, threads: u32) {
        self.threads = threads.max(1);
    }

    /// Blobs written so far, in payload order.
    pub fn blobs(&self) -> &[Blob] {
        &self.blobs
    }

    /// Whether content with this hash is already stored.
    pub fn contains(&self, sha256: &Digest) -> bool {
        self.index.contains_key(sha256)
    }

    /// Adds `content` to the payload. Identical content is stored once:
    /// content that was already added is not written again, and the
    /// existing blob is referenced instead.
    pub fn add_blob(&mut self, content: &mut dyn Read) -> io::Result<BlobRef> {
        let mut head = Vec::new();
        content.take(LARGE_CONTENT).read_to_end(&mut head)?;
        if (head.len() as u64) < LARGE_CONTENT {
            let blob = self.encoder.encode(head)?;
            return self.add_encoded(blob);
        }
        self.add_large(head, content)
    }

    /// Appends a content encoded (possibly on another thread) by an
    /// [`Encoder`], unless the same content is already stored.
    pub fn add_encoded(&mut self, blob: EncodedBlob) -> io::Result<BlobRef> {
        let reference = BlobRef { sha256: blob.sha256, size: blob.size };
        if self.index.contains_key(&blob.sha256) {
            return Ok(reference);
        }
        let mut sink = PayloadSink { out: &mut self.out, hasher: &mut self.payload_hasher, count: 0 };
        sink.write_all(&blob.data)?;
        self.record(Blob {
            sha256: blob.sha256,
            size: blob.size,
            offset: self.payload_len,
            stored_size: blob.data.len() as u64,
            compression: blob.compression,
        });
        Ok(reference)
    }

    /// Streams a content of at least [`LARGE_CONTENT`] bytes (`head` is its
    /// start, `rest` the remainder), compressing it with zstd's
    /// multithreaded mode if its start compresses.
    fn add_large(&mut self, head: Vec<u8>, rest: &mut dyn Read) -> io::Result<BlobRef> {
        let start = self.launcher.size + self.payload_len;
        let snapshot = self.payload_hasher.clone();
        let compress = self.encoder.worth_compressing(&head[..PROBE_LEN])?;
        let mut content_hash = Hasher::new();
        let mut size = 0u64;
        let mut chunk = vec![0u8; CHUNK];
        let mut sink = PayloadSink { out: &mut self.out, hasher: &mut self.payload_hasher, count: 0 };
        // Fed in fixed-size pieces, so that the input's chunking never
        // depends on how the source satisfies reads.
        let mut feed = |out: &mut dyn Write| -> io::Result<()> {
            content_hash.update(&head);
            size += head.len() as u64;
            out.write_all(&head)?;
            loop {
                let filled = fill(rest, &mut chunk)?;
                if filled == 0 {
                    return Ok(());
                }
                content_hash.update(&chunk[..filled]);
                size += filled as u64;
                out.write_all(&chunk[..filled])?;
            }
        };
        if compress {
            let mut encoder = zstd::stream::write::Encoder::new(&mut sink, LEVEL)?;
            encoder.include_checksum(false)?;
            encoder.include_dictid(false)?;
            // Always at least one worker: zstd's single-threaded mode
            // produces different output. The job size is fixed (so the
            // output does not depend on the number of workers either) and
            // small enough to bound memory: each worker holds about two
            // jobs.
            encoder.multithread(self.threads.clamp(1, MAX_ZSTD_WORKERS))?;
            encoder.set_parameter(CParameter::JobSize(ZSTD_JOB_SIZE))?;
            feed(&mut encoder)?;
            encoder.finish()?;
        } else {
            feed(&mut sink)?;
        }
        let stored_size = sink.count;
        let sha256 = content_hash.finalize();

        if self.index.contains_key(&sha256) {
            self.out.seek(SeekFrom::Start(start))?;
            self.out.truncate_to(start)?;
            self.payload_hasher = snapshot;
            return Ok(BlobRef { sha256, size });
        }
        let compression = if compress { Compression::Zstd } else { Compression::Stored };
        self.record(Blob { sha256, size, offset: self.payload_len, stored_size, compression });
        Ok(BlobRef { sha256, size })
    }

    fn record(&mut self, blob: Blob) {
        self.payload_len += blob.stored_size;
        self.index.insert(blob.sha256, self.blobs.len());
        self.blobs.push(blob);
    }

    /// Completes the artifact: fills in the fields of `manifest` that
    /// describe what was written (`launcher`, `payload`, `blobs`), validates
    /// it, and appends the manifest and the footer. Returns the output and
    /// the final manifest.
    pub fn finish(mut self, mut manifest: Manifest) -> Result<(W, Manifest), WriteError> {
        let end = self.out.seek(SeekFrom::End(0))?;
        if end != self.launcher.size + self.payload_len {
            return Err(io::Error::other("output changed size while the artifact was written").into());
        }
        manifest.launcher = self.launcher.clone();
        manifest.payload = RegionInfo { size: self.payload_len, sha256: self.payload_hasher.finalize() };
        manifest.blobs = self.blobs;
        manifest.validate(self.payload_len, NameRules::Portable)?;

        let encoded = manifest.encode();
        if encoded.len() as u64 > MAX_MANIFEST_LEN {
            return Err(ManifestError(format!(
                "the manifest would be {} bytes, more than the limit of {MAX_MANIFEST_LEN} bytes (too many resources?)",
                encoded.len()
            ))
            .into());
        }
        // Everything written must be readable: decode the bytes back, which
        // catches values that encode but are not canonical (such as bytes
        // stored as non-Unicode that are valid Unicode).
        Manifest::decode(&encoded)?;
        let footer = Footer {
            payload_offset: self.launcher.size,
            payload_len: self.payload_len,
            manifest_offset: self.launcher.size + self.payload_len,
            manifest_len: encoded.len() as u64,
            manifest_sha256: Digest::of(&encoded),
        };
        self.out.write_all(&encoded)?;
        self.out.write_all(&footer.encode())?;
        if let exe::PreparedLauncher::MachO(macho) = &self.prepared {
            let identifier = format!("bound-{}", &footer.manifest_sha256.to_string()[..16]);
            sign_macho(&mut self.out, macho, footer.footer_offset() + FOOTER_LEN as u64, &identifier)?;
        }
        self.out.flush()?;
        Ok((self.out, manifest))
    }
}

/// Signs an artifact put together other than by [`ArtifactWriter`] (tools
/// and tests that assemble artifacts by hand) the way the writer signs its
/// own: if `artifact`, which must end with its footer, is a Mach-O with an
/// `LC_CODE_SIGNATURE` command (as the launchers of bound's Mach-O artifacts
/// are), its header is updated and an ad-hoc signature named `identifier`
/// that covers everything is appended. Other artifacts are left unchanged.
pub fn sign_assembled(artifact: &mut Vec<u8>, identifier: &str) -> io::Result<()> {
    let header = &artifact[..artifact.len().min(exe::HEADER_LEN)];
    let Some(macho) = exe::MachOLauncher::from_header(header) else { return Ok(()) };
    let end = artifact.len() as u64;
    sign_macho(&mut Cursor::new(artifact), &macho, end, identifier)
}

/// Makes a Mach-O artifact that ends at `end` signable and signs it ad
/// hoc: pads to 16 bytes, extends `__LINKEDIT` over everything (so that
/// `codesign` can later re-sign the whole file) and appends a signature
/// whose page hashes cover every byte before it, bound regions included.
fn sign_macho<W: Read + Write + Seek>(
    out: &mut W,
    macho: &exe::MachOLauncher,
    end: u64,
    identifier: &str,
) -> io::Result<()> {
    let offset = end.next_multiple_of(16);
    if offset > exe::MAX_SIGNED_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "macOS artifacts are limited to 4 GiB (the size a code signature can cover)",
        ));
    }
    out.seek(SeekFrom::Start(end))?;
    out.write_all(&vec![0u8; (offset - end) as usize])?;
    let len = exe::MachOLauncher::signature_len(offset, identifier);
    for (at, bytes) in macho.patches(offset, len) {
        out.seek(SeekFrom::Start(at as u64))?;
        out.write_all(&bytes)?;
    }
    // Hash every page of the (patched) file up to the signature.
    out.seek(SeekFrom::Start(0))?;
    let page_size = exe::cs_page_size() as usize;
    let mut page = vec![0u8; page_size];
    let mut hashes = Vec::with_capacity(offset.div_ceil(page_size as u64) as usize);
    let mut remaining = offset;
    while remaining > 0 {
        let n = remaining.min(page_size as u64) as usize;
        out.read_exact(&mut page[..n])?;
        hashes.push(Digest::of(&page[..n]).0);
        remaining -= n as u64;
    }
    out.seek(SeekFrom::Start(offset))?;
    out.write_all(&macho.signature(offset, identifier, &hashes))?;
    Ok(())
}

/// Everything written to the payload goes through this sink, which counts
/// it and adds it to the payload hash.
struct PayloadSink<'a, W> {
    out: &'a mut W,
    hasher: &'a mut Hasher,
    count: u64,
}

impl<W: Write> Write for PayloadSink<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Reads until `buf` is full or the source is exhausted.
fn fill(src: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match src.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FooterError;
    use crate::hash::Digest;
    use crate::manifest::{ArgTemplate, BundleMode, CwdMode, Resource, Target};
    use crate::names::ResourcePath;
    use crate::platform::Platform;
    use crate::reader::{ArtifactReader, ReadError};
    use crate::verify::verify;

    const LAUNCHER: &[u8] = b"\x7fELF-pretend-launcher-bytes";

    fn build(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = ArtifactWriter::new(Cursor::new(Vec::new()), &mut &LAUNCHER[..]).unwrap();
        let mut resources = Vec::new();
        let mut dirs = std::collections::BTreeSet::new();
        for (path, content) in files {
            let path = ResourcePath::new(path).unwrap();
            dirs.extend(path.ancestors());
            let blob = writer.add_blob(&mut &content[..]).unwrap();
            resources.push(Resource::File { path, size: blob.size, sha256: blob.sha256, executable: false });
        }
        resources.extend(dirs.into_iter().map(|path| Resource::Dir { path }));
        resources.sort_by(|a, b| a.path().cmp(b.path()));
        let manifest = Manifest {
            format: 1,
            generator: "test".into(),
            platform: Platform { os: "linux".into(), arch: "x86_64".into(), binary_format: "elf".into() },
            launcher: placeholder(),
            payload: placeholder(),
            target: Target::External { program: "cat".into() },
            args: vec![ArgTemplate::RuntimeArgs],
            env: vec![],
            cwd: CwdMode::Inherit,
            bundle: BundleMode::Private,
            resources,
            blobs: vec![],
        };
        writer.finish(manifest).unwrap().0.into_inner()
    }

    fn placeholder() -> RegionInfo {
        RegionInfo { size: 0, sha256: Digest([0; 32]) }
    }

    fn read_all(artifact: &[u8], path: &str) -> io::Result<Vec<u8>> {
        let mut reader = ArtifactReader::open(Cursor::new(artifact), NameRules::Portable).unwrap();
        let sha = match reader.manifest().resource(&ResourcePath::new(path).unwrap()) {
            Some(Resource::File { sha256, .. }) => *sha256,
            other => panic!("unexpected {other:?}"),
        };
        let mut out = Vec::new();
        reader.open_blob(&sha)?.read_to_end(&mut out)?;
        Ok(out)
    }

    fn sample() -> Vec<u8> {
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 97) as u8).collect();
        let big: &'static [u8] = Box::leak(big.into_boxed_slice());
        build(&[("a.txt", b"hello"), ("dir/b.bin", big), ("dir/copy.txt", b"hello"), ("empty", b"")])
    }

    #[test]
    fn round_trip_and_dedup() {
        let artifact = sample();
        assert!(artifact.starts_with(LAUNCHER));
        assert_eq!(read_all(&artifact, "a.txt").unwrap(), b"hello");
        assert_eq!(read_all(&artifact, "dir/copy.txt").unwrap(), b"hello");
        assert_eq!(read_all(&artifact, "empty").unwrap(), b"");
        assert_eq!(read_all(&artifact, "dir/b.bin").unwrap().len(), 200_000);
        let reader = ArtifactReader::open(Cursor::new(&artifact), NameRules::Portable).unwrap();
        assert_eq!(reader.manifest().blobs.len(), 3, "identical content is stored once");
        assert!(verify(Cursor::new(&artifact)).unwrap().is_ok());
    }

    #[test]
    fn corrupted_content_is_never_handed_out() {
        let artifact = build(&[("a.txt", b"hello world")]);
        let reader = ArtifactReader::open(Cursor::new(&artifact), NameRules::Portable).unwrap();
        let blob = reader.manifest().blobs[0].clone();
        assert_eq!(blob.compression, Compression::Stored);
        let mut damaged = artifact.clone();
        damaged[(reader.footer().payload_offset + blob.offset) as usize] ^= 1;

        let mut reader = ArtifactReader::open(Cursor::new(&damaged), NameRules::Portable).unwrap();
        let mut content = reader.open_blob(&blob.sha256).unwrap();
        // Reading exactly the declared size fails: the last bytes are only
        // returned once the whole content has been verified.
        let mut buf = [0u8; 11];
        assert_eq!(content.read_exact(&mut buf).unwrap_err().kind(), io::ErrorKind::InvalidData);
        // And the failure sticks.
        assert_eq!(content.read(&mut buf).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(content.read(&mut buf).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    #[test]
    fn storage_follows_compressibility() {
        let random = noise(300_000);
        let text: Vec<u8> = b"compressible line of text\n".iter().copied().cycle().take(300_000).collect();
        let random: &'static [u8] = Box::leak(random.into_boxed_slice());
        let text: &'static [u8] = Box::leak(text.into_boxed_slice());
        let artifact = build(&[("noise.bin", random), ("text.txt", text), ("empty", b""), ("tiny", b"x")]);
        let reader = ArtifactReader::open(Cursor::new(&artifact), NameRules::Portable).unwrap();
        let compression = |path: &str| {
            let Some(Resource::File { sha256, .. }) = reader.manifest().resource(&ResourcePath::new(path).unwrap())
            else {
                panic!("missing {path}")
            };
            let blob = reader.manifest().blob(sha256).unwrap();
            (blob.compression, blob.stored_size, blob.size)
        };
        let (c, stored, size) = compression("noise.bin");
        assert_eq!((c, stored), (Compression::Stored, size));
        let (c, stored, size) = compression("text.txt");
        assert_eq!(c, Compression::Zstd);
        assert!(stored < size / 50, "{stored} of {size}");
        assert_eq!(compression("empty"), (Compression::Stored, 0, 0));
        assert_eq!(compression("tiny").0, Compression::Stored);
        for (path, content) in [("noise.bin", random), ("text.txt", text), ("empty", &b""[..]), ("tiny", b"x")] {
            assert_eq!(read_all(&artifact, path).unwrap(), content, "{path}");
        }
        assert!(verify(Cursor::new(&artifact)).unwrap().is_ok());
        // Damage inside a stored blob is caught by its content hash too.
        let mut bad = artifact.clone();
        let start = reader.footer().payload_offset as usize;
        bad[start + 1000] ^= 1;
        assert!(read_all(&bad, "noise.bin").is_err());
    }

    #[test]
    fn large_contents_are_identical_whatever_the_thread_count() {
        // Compressible but not trivially so, and larger than LARGE_CONTENT.
        let content: Vec<u8> = (0..(LARGE_CONTENT as usize + 3_000_000))
            .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[3] % 16 + b'a')
            .collect();
        let write = |threads: u32| {
            let mut writer = ArtifactWriter::new(Cursor::new(Vec::new()), &mut &LAUNCHER[..]).unwrap();
            writer.set_threads(threads);
            let blob = writer.add_blob(&mut &content[..]).unwrap();
            assert_eq!(writer.blobs()[0].compression, Compression::Zstd);
            (blob, writer.out.into_inner())
        };
        let (blob, one) = write(1);
        assert_eq!(blob.size, content.len() as u64);
        for threads in [2, 4, 7] {
            assert!(write(threads).1 == one, "{threads} threads changed the output");
        }
    }

    #[test]
    fn contents_encoded_elsewhere_match_contents_added_directly() {
        let text: Vec<u8> = b"some text\n".iter().copied().cycle().take(100_000).collect();
        let mut direct = ArtifactWriter::new(Cursor::new(Vec::new()), &mut &LAUNCHER[..]).unwrap();
        direct.add_blob(&mut &text[..]).unwrap();
        let mut encoded = ArtifactWriter::new(Cursor::new(Vec::new()), &mut &LAUNCHER[..]).unwrap();
        let blob = Encoder::new().unwrap().encode(text.clone()).unwrap();
        assert_eq!(blob.compression(), Compression::Zstd);
        encoded.add_encoded(blob).unwrap();
        // Duplicates are not stored twice.
        encoded.add_encoded(Encoder::new().unwrap().encode(text).unwrap()).unwrap();
        assert_eq!(encoded.blobs().len(), 1);
        assert!(direct.out.into_inner() == encoded.out.into_inner());
    }

    #[test]
    fn output_is_deterministic() {
        assert_eq!(sample(), sample());
    }

    #[test]
    fn payload_corruption_is_detected() {
        let artifact = sample();
        let reader = ArtifactReader::open(Cursor::new(&artifact), NameRules::Portable).unwrap();
        let payload_start = reader.footer().payload_offset as usize;
        let payload_end = reader.footer().manifest_offset as usize;
        for pos in (payload_start..payload_end).step_by(97) {
            let mut bad = artifact.clone();
            bad[pos] ^= 0x55;
            let report = verify(Cursor::new(&bad)).unwrap();
            assert!(!report.is_ok(), "flip at {pos} was not detected");
        }
    }

    #[test]
    fn launcher_corruption_is_detected() {
        let mut bad = sample();
        bad[3] ^= 1;
        let report = verify(Cursor::new(&bad)).unwrap();
        assert!(report.launcher.is_err());
        assert_eq!(report.problems().len(), 1);
    }

    #[test]
    fn manifest_corruption_is_detected() {
        let artifact = sample();
        let reader = ArtifactReader::open(Cursor::new(&artifact), NameRules::Portable).unwrap();
        let start = reader.footer().manifest_offset as usize;
        let mut bad = artifact.clone();
        bad[start + 10] ^= 0x20;
        assert!(matches!(
            ArtifactReader::open(Cursor::new(&bad), NameRules::Portable),
            Err(ReadError::ManifestHash { .. })
        ));
    }

    #[test]
    fn arbitrary_damage_never_panics() {
        let artifact = sample();
        // Truncation at every offset near the end, and a sweep elsewhere.
        let n = artifact.len();
        let cuts = (0..n).rev().take(400).chain((0..n).step_by(509));
        for cut in cuts {
            let r = verify(Cursor::new(&artifact[..cut]));
            assert!(r.is_err() || !r.unwrap().is_ok(), "truncation at {cut} accepted");
        }
        // Single-byte flips across the whole file, including the footer.
        for pos in (0..n).step_by(13).chain(n - 88..n) {
            let mut bad = artifact.clone();
            bad[pos] = bad[pos].wrapping_add(1);
            if let Ok(report) = verify(Cursor::new(&bad)) {
                assert!(!report.is_ok(), "flip at {pos} accepted");
            }
        }
    }

    #[test]
    fn appended_garbage_is_not_an_artifact() {
        let mut artifact = sample();
        artifact.extend_from_slice(b"trailing");
        assert!(matches!(
            ArtifactReader::open(Cursor::new(&artifact), NameRules::Portable),
            Err(ReadError::Footer(FooterError::NotAnArtifact))
        ));
    }

    #[test]
    fn finish_rejects_invalid_manifests() {
        let mut writer = ArtifactWriter::new(Cursor::new(Vec::new()), &mut &LAUNCHER[..]).unwrap();
        writer.add_blob(&mut &b"data"[..]).unwrap();
        // The blob is not referenced by any resource.
        let manifest = Manifest {
            format: 1,
            generator: "test".into(),
            platform: Platform::host(),
            launcher: placeholder(),
            payload: placeholder(),
            target: Target::External { program: "x".into() },
            args: vec![],
            env: vec![],
            cwd: CwdMode::Inherit,
            bundle: BundleMode::Private,
            resources: vec![],
            blobs: vec![],
        };
        assert!(matches!(writer.finish(manifest), Err(WriteError::Manifest(_))));
    }

    #[test]
    fn last_payload_byte_changes_are_detected() {
        // Whatever the last byte of the payload holds, the payload hash
        // covers it.
        let artifact = sample();
        let reader = ArtifactReader::open(Cursor::new(&artifact), NameRules::Portable).unwrap();
        let last = reader.footer().manifest_offset as usize - 1;
        for mask in [0x80u8, 0x40, 0x20] {
            let mut bad = artifact.clone();
            bad[last] ^= mask;
            let report = verify(Cursor::new(&bad)).unwrap();
            assert!(!report.is_ok(), "mask {mask:#x} not detected");
        }
    }
}
