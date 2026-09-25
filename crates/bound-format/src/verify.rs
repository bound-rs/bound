//! Full integrity verification of an artifact.
//!
//! Verification recomputes every hash recorded in the artifact: the manifest
//! hash (from the footer), the launcher hash and every stored content hash
//! (from the manifest). It proves that the file is internally consistent and
//! undamaged. It does not prove who produced it; that is the job of a
//! signature, which bound does not implement yet.

use std::collections::HashMap;
use std::io::{self, Read, Seek};

use crate::hash::{Digest, HashingReader};
use crate::names::NameRules;
use crate::reader::{ArtifactReader, ReadError};
use crate::{Footer, Manifest, RegionInfo, Resource};

/// The outcome of checking one stored content blob.
#[derive(Debug)]
pub struct BlobCheck {
    pub sha256: Digest,
    /// Positions in the manifest's resource list of the files whose content
    /// is this blob.
    pub resources: Vec<usize>,
    pub result: Result<(), String>,
}

/// Everything verification found.
#[derive(Debug)]
pub struct VerifyReport {
    pub file_len: u64,
    pub footer: Footer,
    /// A platform code signature after the bound regions. bound does not
    /// check it; the platform's tools do.
    pub signature: Option<crate::exe::CodeSignature>,
    pub manifest: Manifest,
    pub launcher: Result<(), String>,
    pub payload: Result<(), String>,
    pub blobs: Vec<BlobCheck>,
}

impl VerifyReport {
    pub fn is_ok(&self) -> bool {
        self.launcher.is_ok() && self.payload.is_ok() && self.blobs.iter().all(|b| b.result.is_ok())
    }

    /// Human-readable descriptions of every problem found.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Err(e) = &self.launcher {
            out.push(format!("launcher: {e}"));
        }
        if let Err(e) = &self.payload {
            out.push(format!("payload: {e}"));
        }
        for blob in &self.blobs {
            if let Err(e) = &blob.result {
                let names: Vec<String> =
                    blob.resources.iter().map(|&i| format!("\"{}\"", self.manifest.resources[i].path())).collect();
                out.push(format!("resource {}: {e}", names.join(", ")));
            }
        }
        out
    }
}

/// Verifies an artifact. Structural failures (unreadable footer, corrupt or
/// invalid manifest) are returned as errors; content failures are collected
/// in the report so every damaged resource can be listed.
pub fn verify<R: Read + Seek>(inner: R) -> Result<VerifyReport, ReadError> {
    let mut reader = ArtifactReader::open(inner, NameRules::Portable)?;
    let launcher_info = reader.manifest().launcher.clone();
    let payload_info = reader.manifest().payload.clone();
    // Code signing rewrites a few header fields; the hash leaves them out.
    let fields = reader.signing_fields().to_vec();
    let launcher = check_region(reader.open_launcher().map(|r| Blanking::new(r, fields)), "launcher", &launcher_info);
    let payload = check_region(reader.open_payload(), "payload", &payload_info);

    let (manifest, mut contents) = reader.split();
    let mut users: HashMap<Digest, Vec<usize>> = HashMap::new();
    for (i, resource) in manifest.resources.iter().enumerate() {
        if let Resource::File { sha256, .. } = resource {
            users.entry(*sha256).or_default().push(i);
        }
    }
    let mut blobs = Vec::with_capacity(manifest.blobs.len());
    for blob in &manifest.blobs {
        let resources = users.remove(&blob.sha256).unwrap_or_default();
        let result = contents
            .open(&blob.sha256)
            .and_then(|mut content| io::copy(&mut content, &mut io::sink()))
            .map(|_| ())
            .map_err(|e| e.to_string());
        blobs.push(BlobCheck { sha256: blob.sha256, resources, result });
    }

    Ok(VerifyReport {
        file_len: reader.file_len(),
        footer: reader.footer().clone(),
        signature: reader.signature().copied(),
        manifest: reader.into_manifest(),
        launcher,
        payload,
        blobs,
    })
}

/// Reads `inner` with the bytes in `fields` (file offsets) replaced by
/// zeros.
#[derive(Debug)]
pub struct Blanking<R> {
    inner: R,
    position: usize,
    fields: Vec<std::ops::Range<usize>>,
}

impl<R> Blanking<R> {
    pub fn new(inner: R, fields: Vec<std::ops::Range<usize>>) -> Blanking<R> {
        Blanking { inner, position: 0, fields }
    }
}

impl<R: Read> Read for Blanking<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        crate::exe::blank_fields(&mut buf[..n], self.position, &self.fields);
        self.position += n;
        Ok(n)
    }
}

fn check_region(region: io::Result<impl Read>, name: &str, expected: &RegionInfo) -> Result<(), String> {
    let mut hashing = HashingReader::new(region.map_err(|e| e.to_string())?);
    io::copy(&mut hashing, &mut io::sink()).map_err(|e| e.to_string())?;
    let (digest, size) = hashing.finish();
    if size != expected.size {
        return Err(format!("{name} is truncated ({size} of {} bytes)", expected.size));
    }
    if digest != expected.sha256 {
        return Err(format!("{name} hash mismatch (expected {}, found {digest})", expected.sha256));
    }
    Ok(())
}
