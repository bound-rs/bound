//! Reading artifacts.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Take};

use crate::decode::{DecoderScratch, ZstdReader};
use crate::exe::CodeSignature;
use crate::footer::{Footer, FooterError, locate};
use crate::hash::{Digest, Hasher};
use crate::manifest::{Blob, Compression, Manifest, ManifestError};
use crate::names::NameRules;

/// Errors that prevent an artifact from being opened at all.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error(transparent)]
    Footer(#[from] FooterError),
    #[error("manifest is corrupted: its SHA-256 is {actual} but the footer expects {expected}")]
    ManifestHash { expected: Digest, actual: Digest },
    #[error("invalid manifest: {0}")]
    Manifest(#[from] ManifestError),
    #[error("could not read artifact: {0}")]
    Io(#[from] io::Error),
}

/// An opened artifact whose footer and manifest have been fully validated.
pub struct ArtifactReader<R> {
    inner: R,
    file_len: u64,
    footer: Footer,
    signature: Option<CodeSignature>,
    signing_fields: Vec<std::ops::Range<usize>>,
    manifest: Manifest,
    /// Blob position by content hash.
    blob_index: HashMap<Digest, usize>,
    /// Decompression state shared by all blobs.
    scratch: Box<DecoderScratch>,
}

impl<R> std::fmt::Debug for ArtifactReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtifactReader").field("file_len", &self.file_len).field("footer", &self.footer).finish()
    }
}

impl<R: Read + Seek> ArtifactReader<R> {
    /// Opens an artifact: locates the footer, loads the manifest (bounded by
    /// the format's size limit), checks its hash, decodes it strictly and
    /// validates it. Blob contents are *not* read; they are verified as they
    /// are streamed through [`ArtifactReader::open_blob`].
    ///
    /// `rules` are the file-name rules of the platform that will use the
    /// resources; the target platform's rules are applied in any case.
    pub fn open(mut inner: R, rules: NameRules) -> Result<ArtifactReader<R>, ReadError> {
        let located = locate(&mut inner)?;
        let (footer, file_len) = (located.footer, located.file_len);

        inner.seek(SeekFrom::Start(footer.manifest_offset))?;
        let mut bytes = Vec::new();
        (&mut inner).take(footer.manifest_len).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != footer.manifest_len {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "manifest is truncated").into());
        }
        let actual = Digest::of(&bytes);
        if actual != footer.manifest_sha256 {
            return Err(ReadError::ManifestHash { expected: footer.manifest_sha256, actual });
        }

        let manifest = Manifest::decode(&bytes)?;
        if manifest.format != footer.format_version {
            return Err(ManifestError(format!(
                "manifest format {} does not match the artifact's format {}",
                manifest.format, footer.format_version
            ))
            .into());
        }
        manifest.validate(footer.payload_len, rules)?;
        if manifest.launcher.size != footer.payload_offset {
            return Err(ManifestError(format!(
                "manifest launcher size {} does not match the footer ({})",
                manifest.launcher.size, footer.payload_offset
            ))
            .into());
        }
        let blob_index = manifest.blobs.iter().enumerate().map(|(i, b)| (b.sha256, i)).collect();
        Ok(ArtifactReader {
            inner,
            file_len,
            footer,
            signature: located.signature,
            signing_fields: located.signing_fields,
            manifest,
            blob_index,
            scratch: Box::new(DecoderScratch::new()),
        })
    }

    pub fn footer(&self) -> &Footer {
        &self.footer
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Length of the whole file, including any code signature.
    pub fn file_len(&self) -> u64 {
        self.file_len
    }

    /// The platform code signature after the bound regions, if any.
    pub fn signature(&self) -> Option<&CodeSignature> {
        self.signature.as_ref()
    }

    /// Header fields of the launcher that code signing rewrites, which the
    /// launcher's hash leaves out (see [`crate::exe`]).
    pub fn signing_fields(&self) -> &[std::ops::Range<usize>] {
        &self.signing_fields
    }

    /// Reads the platform code signature's bytes (at most `limit`).
    pub fn read_signature(&mut self, limit: usize) -> io::Result<Vec<u8>> {
        let Some(signature) = self.signature else { return Ok(Vec::new()) };
        self.inner.seek(SeekFrom::Start(signature.offset))?;
        let mut out = Vec::new();
        (&mut self.inner).take(signature.len.min(limit as u64)).read_to_end(&mut out)?;
        Ok(out)
    }

    /// Streams the launcher region.
    pub fn open_launcher(&mut self) -> io::Result<Take<&mut R>> {
        self.inner.seek(SeekFrom::Start(0))?;
        Ok((&mut self.inner).take(self.footer.payload_offset))
    }

    /// Streams the raw payload region.
    pub fn open_payload(&mut self) -> io::Result<Take<&mut R>> {
        self.inner.seek(SeekFrom::Start(self.footer.payload_offset))?;
        Ok((&mut self.inner).take(self.footer.payload_len))
    }

    /// Streams the decoded content with the given hash.
    ///
    /// The returned reader verifies the size and SHA-256 of the content and
    /// the exact extent of the stored bytes. It hands out the final bytes
    /// only after they have been verified, and reports any mismatch as an
    /// [`io::ErrorKind::InvalidData`] error, on that read and every later
    /// one. A consumer that reads the full declared size (or to EOF) has
    /// therefore received exactly the recorded content.
    pub fn open_blob(&mut self, sha256: &Digest) -> io::Result<BlobReader<'_, &mut R>> {
        self.split().1.into_blob(sha256)
    }

    /// Borrows the manifest together with access to the blobs, so that
    /// resources can be read while walking the manifest.
    pub fn split(&mut self) -> (&Manifest, Blobs<'_, R>) {
        let blobs = Blobs {
            inner: &mut self.inner,
            payload_offset: self.footer.payload_offset,
            blobs: &self.manifest.blobs,
            index: &self.blob_index,
            scratch: &mut self.scratch,
        };
        (&self.manifest, blobs)
    }

    /// Consumes the reader, keeping only the manifest.
    pub fn into_manifest(self) -> Manifest {
        self.manifest
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Access to the blobs of an artifact, borrowed from an [`ArtifactReader`].
pub struct Blobs<'a, R> {
    inner: &'a mut R,
    payload_offset: u64,
    blobs: &'a [Blob],
    index: &'a HashMap<Digest, usize>,
    scratch: &'a mut DecoderScratch,
}

impl<R> std::fmt::Debug for Blobs<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blobs").field("count", &self.blobs.len()).finish()
    }
}

impl<'a, R: Read + Seek> Blobs<'a, R> {
    fn find(&self, sha256: &Digest) -> io::Result<&'a Blob> {
        let blobs: &'a [Blob] = self.blobs;
        let index = *self
            .index
            .get(sha256)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no stored content with hash {sha256}")))?;
        Ok(&blobs[index])
    }

    /// Streams the decoded content with the given hash; see
    /// [`ArtifactReader::open_blob`].
    pub fn open(&mut self, sha256: &Digest) -> io::Result<BlobReader<'_, &mut R>> {
        let blob = self.find(sha256)?;
        // Validation guarantees the blob lies within the payload region.
        self.inner.seek(SeekFrom::Start(self.payload_offset + blob.offset))?;
        let region = (&mut *self.inner).take(blob.stored_size);
        Ok(BlobReader::new(region, blob, &mut *self.scratch))
    }

    fn into_blob(self, sha256: &Digest) -> io::Result<BlobReader<'a, &'a mut R>> {
        let blob = self.find(sha256)?;
        self.inner.seek(SeekFrom::Start(self.payload_offset + blob.offset))?;
        let region = self.inner.take(blob.stored_size);
        Ok(BlobReader::new(region, blob, self.scratch))
    }
}

enum Source<'s, R: Read> {
    Stored(Take<R>),
    Zstd(ZstdReader<'s, R>),
}

impl<R: Read> Source<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Source::Stored(region) => region.read(buf),
            Source::Zstd(decoder) => decoder.read(buf),
        }
    }
}

enum State {
    Reading(Hasher),
    Verified,
    Failed(io::ErrorKind, String),
}

/// A reader over one blob's decoded content that verifies it.
pub struct BlobReader<'s, R: Read> {
    source: Source<'s, R>,
    expected_size: u64,
    expected_hash: Digest,
    produced: u64,
    state: State,
}

impl<R: Read> std::fmt::Debug for BlobReader<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobReader")
            .field("expected_size", &self.expected_size)
            .field("expected_hash", &self.expected_hash)
            .field("produced", &self.produced)
            .finish()
    }
}

impl<'s, R: Read> BlobReader<'s, R> {
    fn new(region: Take<R>, blob: &Blob, scratch: &'s mut DecoderScratch) -> BlobReader<'s, R> {
        let source = match blob.compression {
            Compression::Stored => Source::Stored(region),
            Compression::Zstd => Source::Zstd(ZstdReader::new(region, scratch)),
        };
        BlobReader {
            source,
            expected_size: blob.size,
            expected_hash: blob.sha256,
            produced: 0,
            state: State::Reading(Hasher::new()),
        }
    }

    /// Reads at most the remaining declared size, and verifies the content
    /// as soon as all of it has been produced.
    fn read_checked(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.expected_size - self.produced;
        if remaining == 0 {
            self.verify()?;
            return Ok(0);
        }
        let want = buf.len().min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let n = loop {
            match self.source.read(&mut buf[..want]) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                other => break other?,
            }
        };
        if n == 0 {
            return Err(corrupt(format!("content is truncated ({} of {} bytes)", self.produced, self.expected_size)));
        }
        if let State::Reading(hasher) = &mut self.state {
            hasher.update(&buf[..n]);
        }
        self.produced += n as u64;
        if self.produced == self.expected_size {
            self.verify()?;
        }
        Ok(n)
    }

    /// Checks that the stored bytes end exactly here and that the content
    /// has the recorded hash.
    fn verify(&mut self) -> io::Result<()> {
        let mut probe = [0u8; 1];
        loop {
            match self.source.read(&mut probe) {
                Ok(0) => break,
                Ok(_) => {
                    return Err(corrupt(format!("content is larger than the declared {} bytes", self.expected_size)));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if let State::Reading(hasher) = std::mem::replace(&mut self.state, State::Verified) {
            let actual = hasher.finalize();
            if actual != self.expected_hash {
                return Err(corrupt(format!(
                    "content hash mismatch (expected {}, found {actual})",
                    self.expected_hash
                )));
            }
        }
        Ok(())
    }
}

fn corrupt(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl<R: Read> Read for BlobReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &self.state {
            State::Verified => return Ok(0),
            State::Failed(kind, message) => return Err(io::Error::new(*kind, message.clone())),
            State::Reading(_) => {}
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let result = self.read_checked(buf);
        if let Err(e) = &result {
            self.state = State::Failed(e.kind(), e.to_string());
        }
        result
    }
}
