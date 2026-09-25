//! The fixed-size footer at the end of every artifact.
//!
//! Layout (all integers little-endian, 88 bytes in total):
//!
//! | offset | size | field             |
//! |-------:|-----:|-------------------|
//! |      0 |    8 | `payload_offset`  |
//! |      8 |    8 | `payload_len`     |
//! |     16 |    8 | `manifest_offset` |
//! |     24 |    8 | `manifest_len`    |
//! |     32 |   32 | `manifest_sha256` |
//! |     64 |    4 | `flags` (must be 0) |
//! |     68 |    2 | `footer_len` (88) |
//! |     70 |    2 | `format_version` (1) |
//! |     72 |   16 | magic `<bound-artifact>` |
//!
//! The last 20 bytes (`footer_len`, `format_version`, magic) are stable across
//! format versions, so any reader can identify an artifact and report an
//! unsupported version without understanding the rest of the footer.
//!
//! The footer ends the bound regions, which end the file unless a platform
//! code signature follows them (see [`locate`]).

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::exe::{self, CodeSignature};
use crate::hash::Digest;
use crate::limits::MAX_MANIFEST_LEN;

/// Identifies a bound artifact: the last 16 bytes of the footer.
pub const MAGIC: [u8; 16] = *b"<bound-artifact>";

/// The artifact format version this crate reads and writes.
pub const FORMAT_VERSION: u16 = 1;

/// Size of a version-1 footer.
pub const FOOTER_LEN: usize = 88;

/// Size of the version-independent tail: `footer_len`, `format_version`, magic.
pub const TAIL_LEN: usize = 20;

/// Locations of the artifact regions plus the manifest hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Footer {
    /// Start of the payload, which is also the length of the launcher.
    pub payload_offset: u64,
    pub payload_len: u64,
    pub manifest_offset: u64,
    pub manifest_len: u64,
    pub manifest_sha256: Digest,
}

/// Errors from locating or decoding a footer.
#[derive(Debug, thiserror::Error)]
pub enum FooterError {
    #[error("not a bound artifact (no bound footer found)")]
    NotAnArtifact,
    #[error(
        "unsupported bound artifact format version {0} (this bound supports version {FORMAT_VERSION}); a newer bound is required"
    )]
    UnsupportedVersion(u16),
    #[error("malformed bound footer: {0}")]
    Malformed(String),
    #[error("could not read artifact: {0}")]
    Io(#[from] io::Error),
}

impl Footer {
    /// Serializes the footer.
    pub fn encode(&self) -> [u8; FOOTER_LEN] {
        let mut out = [0u8; FOOTER_LEN];
        out[0..8].copy_from_slice(&self.payload_offset.to_le_bytes());
        out[8..16].copy_from_slice(&self.payload_len.to_le_bytes());
        out[16..24].copy_from_slice(&self.manifest_offset.to_le_bytes());
        out[24..32].copy_from_slice(&self.manifest_len.to_le_bytes());
        out[32..64].copy_from_slice(&self.manifest_sha256.0);
        out[64..68].copy_from_slice(&0u32.to_le_bytes());
        out[68..70].copy_from_slice(&(FOOTER_LEN as u16).to_le_bytes());
        out[70..72].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        out[72..88].copy_from_slice(&MAGIC);
        out
    }

    /// Decodes a version-1 footer and checks it against the file length.
    ///
    /// The regions must tile the file exactly: the launcher occupies
    /// `[0, payload_offset)`, then the payload, the manifest and the footer
    /// follow back to back with no gaps.
    pub fn decode(buf: &[u8; FOOTER_LEN], file_len: u64) -> Result<Footer, FooterError> {
        let u64_at = |i: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&buf[i..i + 8]);
            u64::from_le_bytes(b)
        };
        check_tail(&buf[FOOTER_LEN - TAIL_LEN..])?;

        let mut sha = [0u8; 32];
        sha.copy_from_slice(&buf[32..64]);
        let footer = Footer {
            payload_offset: u64_at(0),
            payload_len: u64_at(8),
            manifest_offset: u64_at(16),
            manifest_len: u64_at(24),
            manifest_sha256: Digest(sha),
        };
        let flags = u32::from_le_bytes([buf[64], buf[65], buf[66], buf[67]]);
        if flags != 0 {
            return Err(malformed(format!("unknown flags {flags:#x}")));
        }

        let footer_offset =
            file_len.checked_sub(FOOTER_LEN as u64).ok_or_else(|| malformed("file is shorter than its footer"))?;
        if footer.payload_offset == 0 {
            return Err(malformed("launcher region is empty"));
        }
        if footer.payload_offset.checked_add(footer.payload_len) != Some(footer.manifest_offset) {
            return Err(malformed("payload does not end where the manifest starts"));
        }
        if footer.manifest_offset.checked_add(footer.manifest_len) != Some(footer_offset) {
            return Err(malformed("manifest does not end where the footer starts"));
        }
        if footer.manifest_len == 0 {
            return Err(malformed("manifest is empty"));
        }
        if footer.manifest_len > MAX_MANIFEST_LEN {
            return Err(malformed(format!(
                "manifest length {} exceeds the limit of {MAX_MANIFEST_LEN} bytes",
                footer.manifest_len
            )));
        }
        Ok(footer)
    }

    /// Offset of the footer itself (the end of the manifest).
    pub fn footer_offset(&self) -> u64 {
        self.manifest_offset + self.manifest_len
    }
}

fn malformed(msg: impl Into<String>) -> FooterError {
    FooterError::Malformed(msg.into())
}

/// Validates the version-independent tail: magic, version, footer length.
fn check_tail(tail: &[u8]) -> Result<(), FooterError> {
    debug_assert_eq!(tail.len(), TAIL_LEN);
    if tail[4..20] != MAGIC {
        return Err(FooterError::NotAnArtifact);
    }
    let footer_len = u16::from_le_bytes([tail[0], tail[1]]);
    let version = u16::from_le_bytes([tail[2], tail[3]]);
    if version == 0 {
        return Err(malformed("format version 0 is invalid"));
    }
    if version > FORMAT_VERSION {
        return Err(FooterError::UnsupportedVersion(version));
    }
    if usize::from(footer_len) != FOOTER_LEN {
        return Err(malformed(format!("footer length {footer_len} does not match format version {version}")));
    }
    Ok(())
}

/// Most zero bytes allowed between the footer and what follows it: code
/// signatures are aligned (to 16 bytes on Mach-O, 8 for Authenticode).
pub const MAX_PADDING: u64 = 15;

/// Where the bound regions of a file end, and what follows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    pub footer: Footer,
    /// Length of the whole file.
    pub file_len: u64,
    /// End of the footer, and so of the bound regions.
    pub end: u64,
    /// A platform code signature after the bound regions, which ends the
    /// file.
    pub signature: Option<CodeSignature>,
    /// Header fields of the launcher that code signing rewrites; they are
    /// left out of the launcher's hash.
    pub signing_fields: Vec<std::ops::Range<usize>>,
}

/// Finds the end of the bound regions: the end of the file, or the start
/// of a platform code signature that ends the file (a Mach-O
/// `LC_CODE_SIGNATURE` or an Authenticode certificate table named by the
/// executable's header), in either case after at most [`MAX_PADDING`] zero
/// bytes. Returns `None` if no bound footer magic is there.
fn find_end<R: Read + Seek>(r: &mut R) -> io::Result<Option<(u64, u64, exe::Layout)>> {
    let file_len = r.seek(SeekFrom::End(0))?;
    let mut header = vec![0u8; header_len(file_len)];
    r.seek(SeekFrom::Start(0))?;
    r.read_exact(&mut header)?;
    let (limit, layout) = region_limit(&header, file_len);
    let start = window_start(limit);
    let mut window = vec![0u8; (limit - start) as usize];
    r.seek(SeekFrom::Start(start))?;
    r.read_exact(&mut window)?;
    Ok(magic_end(&window, limit).map(|end| (end, file_len, layout)))
}

/// How much of the start of a file of `file_len` bytes the executable
/// header is read from.
fn header_len(file_len: u64) -> usize {
    usize::try_from(file_len).unwrap_or(usize::MAX).min(exe::HEADER_LEN)
}

/// Where the bound regions can end at the latest, given the file's header:
/// at the code signature the header names, if it ends the file, and
/// otherwise at the end of the file.
fn region_limit(header: &[u8], file_len: u64) -> (u64, exe::Layout) {
    let layout = exe::layout(header);
    let limit = match layout.signature {
        Some(signature) if signature.offset.checked_add(signature.len) == Some(file_len) => signature.offset,
        _ => file_len,
    };
    (limit, layout)
}

/// Start of the bytes before `limit` that may hold the magic and padding.
fn window_start(limit: u64) -> u64 {
    limit.saturating_sub(MAX_PADDING + MAGIC.len() as u64)
}

/// Finds the magic in `window`, the bytes from [`window_start`] to `limit`:
/// it must be followed by at most [`MAX_PADDING`] zero bytes, and the whole
/// version-independent tail must fit before its end. Returns the end of the
/// magic.
fn magic_end(window: &[u8], limit: u64) -> Option<u64> {
    for padding in 0..=MAX_PADDING.min(window.len() as u64) {
        let end = window.len() - padding as usize;
        if padding > 0 && window[end] != 0 {
            break;
        }
        if end >= MAGIC.len() && window[end - MAGIC.len()..end] == MAGIC {
            let end = limit - padding;
            return (end >= TAIL_LEN as u64).then_some(end);
        }
    }
    None
}

/// Decides whether content of a known length is a bound artifact (as
/// [`has_magic`] decides for a file) while the content is written through
/// it, keeping only the executable header and the few bytes before the end
/// of the bound regions. Used to recognize artifacts nested in artifacts
/// without extracting every embedded program.
#[derive(Debug)]
pub struct MagicScan {
    len: u64,
    written: u64,
    header: Vec<u8>,
    /// Once the header is complete: where the window starts, where the
    /// bound regions end at the latest, and the window's bytes.
    window: Option<(u64, u64, Vec<u8>)>,
}

impl MagicScan {
    pub fn new(len: u64) -> MagicScan {
        MagicScan { len, written: 0, header: Vec::with_capacity(header_len(len)), window: None }
    }

    /// Whether exactly the announced length was written and it carries a
    /// bound footer magic where one belongs.
    pub fn found(mut self) -> bool {
        self.open_window();
        match &self.window {
            Some((_, limit, window)) if self.written == self.len => magic_end(window, *limit).is_some(),
            _ => false,
        }
    }

    /// Positions the window once the header is complete, and fills it with
    /// what the header already holds.
    fn open_window(&mut self) {
        if self.window.is_some() || self.header.len() < header_len(self.len) {
            return;
        }
        let (limit, _) = region_limit(&self.header, self.len);
        let start = window_start(limit);
        self.window = Some((start, limit, vec![0; (limit - start) as usize]));
        let header = std::mem::take(&mut self.header);
        self.capture(0, &header);
        self.header = header;
    }

    /// Copies the part of `data`, which starts at offset `at`, that falls in
    /// the window.
    fn capture(&mut self, at: u64, data: &[u8]) {
        let Some((start, limit, window)) = &mut self.window else { return };
        let from = at.max(*start);
        let to = at.saturating_add(data.len() as u64).min(*limit);
        if from < to {
            window[(from - *start) as usize..(to - *start) as usize]
                .copy_from_slice(&data[(from - at) as usize..(to - at) as usize]);
        }
    }
}

impl Write for MagicScan {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut rest = buf;
        if self.window.is_none() {
            let take = (header_len(self.len) - self.header.len()).min(rest.len());
            self.header.extend_from_slice(&rest[..take]);
            self.written += take as u64;
            rest = &rest[take..];
            self.open_window();
        }
        self.capture(self.written, rest);
        self.written = self.written.saturating_add(rest.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Locates and validates the footer of `r` (see [`Located`]).
pub fn locate<R: Read + Seek>(r: &mut R) -> Result<Located, FooterError> {
    let Some((end, file_len, layout)) = find_end(r)? else { return Err(FooterError::NotAnArtifact) };
    let mut tail = [0u8; TAIL_LEN];
    r.seek(SeekFrom::Start(end - TAIL_LEN as u64))?;
    r.read_exact(&mut tail)?;
    check_tail(&tail)?;

    if end < FOOTER_LEN as u64 {
        return Err(malformed("file is shorter than its footer"));
    }
    let mut buf = [0u8; FOOTER_LEN];
    r.seek(SeekFrom::Start(end - FOOTER_LEN as u64))?;
    r.read_exact(&mut buf)?;
    let footer = Footer::decode(&buf, end)?;
    let signature = layout.signature.filter(|s| s.offset.checked_add(s.len) == Some(file_len));
    // Header fields past the launcher region are not the launcher's.
    let signing_fields =
        layout.signing_fields.into_iter().filter(|f| (f.end as u64) <= footer.payload_offset).collect();
    Ok(Located { footer, file_len, end, signature, signing_fields })
}

/// Reads and validates the footer of `r`. Returns the footer and the end of
/// the bound regions (see [`locate`]).
pub fn read_footer<R: Read + Seek>(r: &mut R) -> Result<(Footer, u64), FooterError> {
    locate(r).map(|located| (located.footer, located.end))
}

/// Cheaply checks whether `r` carries a bound footer magic where a footer
/// would be, without validating anything else.
pub fn has_magic<R: Read + Seek>(r: &mut R) -> io::Result<bool> {
    Ok(find_end(r)?.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample(launcher: u64, payload: u64, manifest: u64) -> (Footer, Vec<u8>) {
        let footer = Footer {
            payload_offset: launcher,
            payload_len: payload,
            manifest_offset: launcher + payload,
            manifest_len: manifest,
            manifest_sha256: Digest::of(b"m"),
        };
        let mut file = vec![0xaa; (launcher + payload + manifest) as usize];
        file.extend_from_slice(&footer.encode());
        (footer, file)
    }

    #[test]
    fn round_trip() {
        let (footer, file) = sample(100, 50, 25);
        let (read, len) = read_footer(&mut Cursor::new(&file)).unwrap();
        assert_eq!(read, footer);
        assert_eq!(len, file.len() as u64);
        assert!(has_magic(&mut Cursor::new(&file)).unwrap());
    }

    #[test]
    fn not_an_artifact() {
        for data in [&b""[..], b"short", &[0u8; 4096][..]] {
            assert!(matches!(read_footer(&mut Cursor::new(data)), Err(FooterError::NotAnArtifact)));
        }
    }

    #[test]
    fn newer_version_is_reported() {
        let (_, mut file) = sample(10, 0, 5);
        let n = file.len();
        file[n - 18..n - 16].copy_from_slice(&7u16.to_le_bytes());
        match read_footer(&mut Cursor::new(&file)) {
            Err(e @ FooterError::UnsupportedVersion(7)) => {
                assert!(e.to_string().contains("unsupported bound artifact format version 7"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn inconsistent_offsets_are_rejected() {
        let (footer, file) = sample(100, 50, 25);
        let body = &file[..file.len() - FOOTER_LEN];
        let cases: Vec<Footer> = vec![
            Footer { payload_offset: 0, ..footer.clone() },
            Footer { payload_len: 51, ..footer.clone() },
            Footer { manifest_offset: u64::MAX, ..footer.clone() },
            Footer { manifest_len: u64::MAX, ..footer.clone() },
            Footer { payload_len: u64::MAX - 50, ..footer.clone() },
            Footer { manifest_len: 0, manifest_offset: 175, payload_len: 75, ..footer.clone() },
        ];
        for bad in cases {
            let mut data = body.to_vec();
            data.extend_from_slice(&bad.encode());
            let err = read_footer(&mut Cursor::new(&data)).unwrap_err();
            assert!(matches!(err, FooterError::Malformed(_)), "{bad:?} gave {err:?}");
        }
    }

    #[test]
    fn nonzero_flags_and_bad_length_are_rejected() {
        let (_, mut file) = sample(10, 0, 5);
        let n = file.len();
        let mut flagged = file.clone();
        flagged[n - 24] = 1;
        assert!(matches!(read_footer(&mut Cursor::new(&flagged)), Err(FooterError::Malformed(_))));
        file[n - 20..n - 18].copy_from_slice(&4000u16.to_le_bytes());
        assert!(matches!(read_footer(&mut Cursor::new(&file)), Err(FooterError::Malformed(_))));
    }

    #[test]
    fn scanning_agrees_with_locating() {
        let (_, plain) = sample(100, 50, 25);
        let mut padded = plain.clone();
        padded.extend_from_slice(&[0; 3]);
        let mut garbage = plain.clone();
        garbage.push(1);
        let mut big = vec![0x55; exe::HEADER_LEN + 1000];
        big.extend_from_slice(&plain);
        for data in [&plain, &padded, &garbage, &big, &vec![0; 10], &Vec::new()] {
            let expected = has_magic(&mut Cursor::new(data)).unwrap();
            for chunk in [1, 7, 4096, usize::MAX] {
                let mut scan = MagicScan::new(data.len() as u64);
                for piece in data.chunks(chunk.min(data.len().max(1))) {
                    scan.write_all(piece).unwrap();
                }
                assert_eq!(scan.found(), expected, "{} bytes in chunks of {chunk}", data.len());
            }
        }
        assert!(has_magic(&mut Cursor::new(&padded)).unwrap());
        assert!(!has_magic(&mut Cursor::new(&garbage)).unwrap());
        // Too little or too much content is not an artifact.
        let mut short = MagicScan::new(plain.len() as u64 + 1);
        short.write_all(&plain).unwrap();
        assert!(!short.found());
        let mut long = MagicScan::new(plain.len() as u64 - 1);
        long.write_all(&plain).unwrap();
        assert!(!long.found());
    }

    #[test]
    fn a_magic_without_room_for_the_tail_is_not_an_artifact() {
        // Found by fuzzing: 19 bytes ending in the magic.
        let mut data = vec![0x33, 0x01, 0x00];
        data.extend_from_slice(&MAGIC);
        for len in [data.len(), data.len() + 1] {
            let mut padded = data.clone();
            padded.resize(len, 0);
            assert!(!has_magic(&mut Cursor::new(&padded)).unwrap());
            assert!(matches!(read_footer(&mut Cursor::new(&padded)), Err(FooterError::NotAnArtifact)));
            let mut scan = MagicScan::new(padded.len() as u64);
            scan.write_all(&padded).unwrap();
            assert!(!scan.found());
        }
        let mut twenty = vec![0x58, 0x00, 0x01, 0x00];
        twenty.extend_from_slice(&MAGIC);
        assert!(has_magic(&mut Cursor::new(&twenty)).unwrap());
        assert!(matches!(read_footer(&mut Cursor::new(&twenty)), Err(FooterError::Malformed(_))));
    }

    #[test]
    fn every_truncation_fails_cleanly() {
        let (_, file) = sample(10, 3, 5);
        for len in 0..file.len() {
            assert!(read_footer(&mut Cursor::new(&file[..len])).is_err(), "len {len}");
        }
    }
}
