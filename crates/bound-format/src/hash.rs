//! SHA-256 digests and hex encoding.

use std::fmt;
use std::io::{self, Read, Write};

use serde::{Serialize, Serializer};
use sha2::Digest as _;

/// A SHA-256 digest. Serialized as 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// Hashes `data` in one go.
    pub fn of(data: &[u8]) -> Digest {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// The canonical lowercase hex form.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }

    /// Parses the canonical form: exactly 64 lowercase hex characters.
    pub fn from_hex(s: &str) -> Option<Digest> {
        if s.len() != 64 {
            return None;
        }
        let bytes = decode_hex(s)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(Digest(out))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

/// Incremental SHA-256.
#[derive(Clone, Default)]
pub struct Hasher(sha2::Sha256);

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hasher")
    }
}

impl Hasher {
    pub fn new() -> Hasher {
        Hasher(sha2::Sha256::new())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> Digest {
        let out = self.0.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        Digest(bytes)
    }
}

/// A reader adapter that hashes and counts everything read through it.
#[derive(Debug)]
pub struct HashingReader<R> {
    inner: R,
    hasher: Hasher,
    count: u64,
}

impl<R: Read> HashingReader<R> {
    pub fn new(inner: R) -> Self {
        HashingReader { inner, hasher: Hasher::new(), count: 0 }
    }

    /// Returns the digest and number of bytes read so far.
    pub fn finish(self) -> (Digest, u64) {
        (self.hasher.finalize(), self.count)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }
}

/// A writer adapter that hashes and counts everything written through it.
#[derive(Debug)]
pub struct HashingWriter<W> {
    inner: W,
    hasher: Hasher,
    count: u64,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner: W) -> Self {
        HashingWriter { inner, hasher: Hasher::new(), count: 0 }
    }

    pub fn finish(self) -> (W, Digest, u64) {
        (self.inner, self.hasher.finalize(), self.count)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

/// Decodes lowercase hex. Uppercase is rejected so every value has exactly
/// one encoding (which keeps manifests canonical and builds deterministic).
pub(crate) fn decode_hex(s: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes.chunks_exact(2).map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        assert_eq!(Digest::of(b"abc").to_hex(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn hex_round_trip_and_strictness() {
        let d = Digest::of(b"hello");
        assert_eq!(Digest::from_hex(&d.to_hex()), Some(d));
        assert_eq!(Digest::from_hex(&d.to_hex().to_uppercase()), None);
        assert_eq!(Digest::from_hex("abc"), None);
        assert_eq!(decode_hex("0g"), None);
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex(""), Some(vec![]));
    }

    #[test]
    fn hashing_adapters_agree() {
        let data = vec![7u8; 100_000];
        let mut r = HashingReader::new(&data[..]);
        io::copy(&mut r, &mut io::sink()).unwrap();
        let (d1, n1) = r.finish();
        let mut w = HashingWriter::new(Vec::new());
        w.write_all(&data).unwrap();
        let (_, d2, n2) = w.finish();
        assert_eq!((d1, n1), (d2, n2));
        assert_eq!(d1, Digest::of(&data));
    }
}
