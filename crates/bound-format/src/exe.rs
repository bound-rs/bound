//! What bound needs to know about executable formats to coexist with
//! platform code signing:
//!
//! * where a code signature lies. Signing tools put it at the end of the
//!   file, after the bound regions: `codesign` at the end of a Mach-O's
//!   `__LINKEDIT` segment, `signtool` (Authenticode) in a certificate table
//!   named by the PE header;
//! * which header fields signing rewrites, so that they can be left out of
//!   the launcher's hash and signing does not look like damage;
//! * (writing) how to lay out a Mach-O artifact so that `codesign` accepts
//!   it, and how to give it the ad-hoc signature every executable needs on
//!   Apple silicon.
//!
//! Headers come from untrusted artifacts: every offset is bounds-checked,
//! and anything unexpected simply means "no signature".

use std::ops::Range;

use serde::Serialize;

/// How much of the start of a file [`layout`] examines.
pub const HEADER_LEN: usize = 64 * 1024;

/// A platform code signature that ends a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeSignature {
    pub kind: SignatureKind,
    /// File offset of the signature data.
    pub offset: u64,
    pub len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureKind {
    /// A Mach-O code signature (`LC_CODE_SIGNATURE`): ad-hoc or made by
    /// `codesign` with an identity.
    MachO,
    /// A Windows Authenticode certificate table.
    Authenticode,
}

impl std::fmt::Display for SignatureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SignatureKind::MachO => "Mach-O code signature",
            SignatureKind::Authenticode => "Authenticode signature",
        })
    }
}

/// What an executable's header says about code signing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layout {
    /// The code signature the header points to, if any.
    pub signature: Option<CodeSignature>,
    /// Header fields that code signing rewrites, as byte ranges from the
    /// start of the file: the PE checksum and certificate table entry; the
    /// Mach-O `__LINKEDIT` sizes and `LC_CODE_SIGNATURE` location.
    pub signing_fields: Vec<Range<usize>>,
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(i..i.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i.checked_add(4)?)?.try_into().ok()?))
}

fn u64_at(b: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(i..i.checked_add(8)?)?.try_into().ok()?))
}

/// Examines the start of an executable (up to [`HEADER_LEN`] bytes).
pub fn layout(header: &[u8]) -> Layout {
    if u32_at(header, 0) == Some(MH_MAGIC_64) {
        return MachO::parse(header).map(|m| m.layout(header)).unwrap_or_default();
    }
    if header.starts_with(b"MZ") {
        return pe_layout(header).unwrap_or_default();
    }
    Layout::default()
}

// ---------------------------------------------------------------------------
// PE

fn pe_layout(h: &[u8]) -> Option<Layout> {
    let pe = usize::try_from(u32_at(h, 0x3c)?).ok()?;
    if h.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let optional_size = usize::from(u16_at(h, pe + 20)?);
    let opt = pe + 24;
    let opt_end = opt.checked_add(optional_size)?;
    let (count_at, dirs_at) = match u16_at(h, opt)? {
        0x10b => (opt + 92, opt + 96),
        0x20b => (opt + 108, opt + 112),
        _ => return None,
    };
    let mut layout = Layout::default();
    if opt + 68 <= opt_end {
        layout.signing_fields.push(opt + 64..opt + 68);
    }
    // Data directory 4: the certificate table, whose "address" is a file
    // offset.
    let security = dirs_at + 4 * 8;
    if u32_at(h, count_at)? >= 5 && security + 8 <= opt_end {
        let (offset, len) = (u32_at(h, security)?, u32_at(h, security + 4)?);
        layout.signing_fields.push(security..security + 8);
        if len > 0 {
            layout.signature =
                Some(CodeSignature { kind: SignatureKind::Authenticode, offset: offset.into(), len: len.into() });
        }
    }
    Some(layout)
}

// ---------------------------------------------------------------------------
// Mach-O (64-bit little-endian, the only kind macOS still runs)

const MH_MAGIC_64: u32 = 0xfeed_facf;
const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1d;
#[cfg(feature = "write")]
const CPU_TYPE_ARM64: u32 = 0x0100_000c;

/// The load commands of a Mach-O image that bound cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MachO {
    cputype: u32,
    /// Offset of the end of the load commands.
    commands_end: usize,
    /// Lowest file offset of any section: the room for load commands.
    first_section: Option<u64>,
    /// Offset of the `__TEXT` segment command, and its file offset and size.
    text: Option<(u64, u64)>,
    /// Offset of the `__LINKEDIT` segment command.
    linkedit: Option<usize>,
    /// Offset of the `LC_CODE_SIGNATURE` command.
    code_signature: Option<usize>,
}

impl MachO {
    fn parse(h: &[u8]) -> Option<MachO> {
        let cputype = u32_at(h, 4)?;
        let ncmds = u32_at(h, 16)?;
        let sizeofcmds = usize::try_from(u32_at(h, 20)?).ok()?;
        let commands_end = 32usize.checked_add(sizeofcmds)?;
        if commands_end > h.len() {
            return None;
        }
        let mut macho =
            MachO { cputype, commands_end, first_section: None, text: None, linkedit: None, code_signature: None };
        let mut at = 32usize;
        for _ in 0..ncmds {
            let cmd = u32_at(h, at)?;
            let size = usize::try_from(u32_at(h, at + 4)?).ok()?;
            let end = at.checked_add(size)?;
            if size < 8 || end > commands_end {
                return None;
            }
            match cmd {
                LC_SEGMENT_64 if size >= 72 => {
                    let name = h.get(at + 8..at + 24)?;
                    if name == b"__LINKEDIT\0\0\0\0\0\0" {
                        macho.linkedit = Some(at);
                    } else if name == b"__TEXT\0\0\0\0\0\0\0\0\0\0" {
                        macho.text = Some((u64_at(h, at + 40)?, u64_at(h, at + 48)?));
                    }
                    let sections = usize::try_from(u32_at(h, at + 64)?).ok()?;
                    for i in 0..sections {
                        let section = at.checked_add(72)?.checked_add(i.checked_mul(80)?)?;
                        if section + 80 > end {
                            return None;
                        }
                        let offset = u64::from(u32_at(h, section + 48)?);
                        if offset != 0 {
                            macho.first_section = Some(macho.first_section.map_or(offset, |o| o.min(offset)));
                        }
                    }
                }
                LC_CODE_SIGNATURE if size >= 16 => macho.code_signature = Some(at),
                _ => {}
            }
            at = end;
        }
        Some(macho)
    }

    fn layout(&self, h: &[u8]) -> Layout {
        let mut layout = Layout::default();
        if let Some(at) = self.linkedit {
            layout.signing_fields.push(at + 32..at + 40); // vmsize
            layout.signing_fields.push(at + 48..at + 56); // filesize
        }
        if let Some(at) = self.code_signature {
            layout.signing_fields.push(at + 8..at + 16); // dataoff, datasize
            layout.signature = self.signature(h);
        }
        layout
    }

    /// The code signature `LC_CODE_SIGNATURE` points to.
    fn signature(&self, h: &[u8]) -> Option<CodeSignature> {
        let at = self.code_signature?;
        let (offset, len) = (u32_at(h, at + 8)?, u32_at(h, at + 12)?);
        (len > 0).then_some(CodeSignature { kind: SignatureKind::MachO, offset: offset.into(), len: len.into() })
    }
}

/// Replaces the bytes of `chunk`, which starts at file offset `offset`, that
/// fall in any of `fields` with zeros.
pub fn blank_fields(chunk: &mut [u8], offset: usize, fields: &[Range<usize>]) {
    let chunk_end = offset.saturating_add(chunk.len());
    for field in fields {
        let start = field.start.max(offset);
        let end = field.end.min(chunk_end);
        if start < end {
            chunk[start - offset..end - offset].fill(0);
        }
    }
}

/// Whether a Mach-O code signature at the end of `data` (from `offset`) was
/// made by a signing identity rather than ad hoc: its super blob holds a
/// non-empty CMS signature.
pub fn macho_signature_has_identity(data: &[u8]) -> bool {
    const CSSLOT_SIGNATURESLOT: u32 = 0x10000;
    let be = |i: usize| Some(u32::from_be_bytes(data.get(i..i.checked_add(4)?)?.try_into().ok()?));
    let Some(count) = be(8) else { return false };
    (0..count.min(64) as usize).any(|i| {
        let entry = 12 + i * 8;
        match (be(entry), be(entry + 4)) {
            (Some(CSSLOT_SIGNATURESLOT), Some(at)) => be(at as usize + 4).is_some_and(|len| len > 8),
            _ => false,
        }
    })
}

// ---------------------------------------------------------------------------
// Writing (Mach-O artifacts are signed ad hoc by the writer)

/// A launcher prepared to become a signable Mach-O artifact.
#[cfg(feature = "write")]
#[derive(Debug, Clone)]
pub(crate) struct MachOLauncher {
    /// Offset of the `__LINKEDIT` segment command and the segment's file
    /// offset.
    linkedit: (usize, u64),
    /// Offset of the `LC_CODE_SIGNATURE` command.
    code_signature: usize,
    /// `__TEXT`'s file offset and size (the executable segment).
    text: (u64, u64),
    /// The VM page size of the architecture.
    page_size: u64,
}

/// What a launcher needs before bound regions can be appended to it.
#[cfg(feature = "write")]
#[derive(Debug, Clone)]
pub(crate) enum PreparedLauncher {
    /// ELF, or anything else: used as is.
    Plain,
    /// A Mach-O launcher: its old signature was removed, and the artifact
    /// is signed when finished.
    MachO(MachOLauncher),
}

#[cfg(feature = "write")]
fn invalid(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.into())
}

/// Prepares launcher bytes for appending: removes an existing code
/// signature (Mach-O: the linker's ad-hoc signature, which covers only the
/// launcher; PE: a certificate table, which must be the last thing in a
/// signed file), and makes sure a Mach-O launcher has an `LC_CODE_SIGNATURE`
/// command for the artifact's own signature.
#[cfg(feature = "write")]
pub(crate) fn prepare_launcher(bytes: &mut Vec<u8>) -> std::io::Result<PreparedLauncher> {
    let header_len = bytes.len().min(HEADER_LEN);
    if u32_at(bytes, 0) == Some(MH_MAGIC_64) {
        return prepare_macho(bytes).map(PreparedLauncher::MachO);
    }
    let layout = layout(&bytes[..header_len]);
    if let Some(signature) = layout.signature {
        if signature.kind == SignatureKind::Authenticode && signature.offset + signature.len == bytes.len() as u64 {
            bytes.truncate(signature.offset as usize);
            // Clear the certificate table entry and the checksum.
            let fields = layout.signing_fields.clone();
            blank_fields(bytes, 0, &fields);
        }
    }
    Ok(PreparedLauncher::Plain)
}

#[cfg(feature = "write")]
fn prepare_macho(bytes: &mut Vec<u8>) -> std::io::Result<MachOLauncher> {
    let header_len = bytes.len().min(HEADER_LEN);
    let macho =
        MachO::parse(&bytes[..header_len]).ok_or_else(|| invalid("the launcher's Mach-O header is malformed"))?;
    let linkedit = macho.linkedit.ok_or_else(|| invalid("the launcher has no __LINKEDIT segment"))?;
    let linkedit_fileoff = u64_at(bytes, linkedit + 40).ok_or_else(|| invalid("bad __LINKEDIT"))?;
    let linkedit_filesize = u64_at(bytes, linkedit + 48).ok_or_else(|| invalid("bad __LINKEDIT"))?;
    if linkedit_fileoff.checked_add(linkedit_filesize) != Some(bytes.len() as u64) {
        return Err(invalid("the launcher's __LINKEDIT segment does not end the file"));
    }
    let text = macho.text.ok_or_else(|| invalid("the launcher has no __TEXT segment"))?;
    let code_signature = match macho.code_signature {
        Some(at) => {
            // Remove the old signature, which ends the file.
            if let Some(old) = macho.signature(bytes) {
                if old.offset + old.len != bytes.len() as u64 || old.offset < linkedit_fileoff {
                    return Err(invalid("the launcher's code signature is not at the end of the file"));
                }
                bytes.truncate(old.offset as usize);
            }
            at
        }
        None => {
            // Add the command in the space before the first section.
            let at = macho.commands_end;
            let room = macho.first_section.map_or(0, |first| first.saturating_sub(at as u64));
            if room < 16 {
                return Err(invalid("the launcher has no room for a code signature command"));
            }
            bytes[at..at + 16].copy_from_slice(&[0; 16]);
            bytes[at..at + 4].copy_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&16u32.to_le_bytes());
            let ncmds = u32_at(bytes, 16).unwrap_or(0) + 1;
            let sizeofcmds = u32_at(bytes, 20).unwrap_or(0) + 16;
            bytes[16..20].copy_from_slice(&ncmds.to_le_bytes());
            bytes[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
            at
        }
    };
    Ok(MachOLauncher { linkedit: (linkedit, linkedit_fileoff), code_signature, text, page_size: vm_page_size(&macho) })
}

/// The VM page size of a Mach-O's architecture, to which segment sizes are
/// rounded.
#[cfg(feature = "write")]
fn vm_page_size(macho: &MachO) -> u64 {
    if macho.cputype == CPU_TYPE_ARM64 { 0x4000 } else { 0x1000 }
}

/// Code signing page size (4 KiB, as the linker and `codesign` use).
#[cfg(feature = "write")]
const CS_PAGE_SIZE: u64 = 4096;
#[cfg(feature = "write")]
const CODE_DIRECTORY_LEN: u64 = 88;
#[cfg(feature = "write")]
const SUPER_BLOB_LEN: u64 = 12 + 8;

#[cfg(feature = "write")]
impl MachOLauncher {
    /// Reads the layout of a Mach-O that is ready to be signed: one with an
    /// `LC_CODE_SIGNATURE` command, as every Mach-O artifact bound writes
    /// has. `None` for anything else.
    pub(crate) fn from_header(h: &[u8]) -> Option<MachOLauncher> {
        if u32_at(h, 0) != Some(MH_MAGIC_64) {
            return None;
        }
        let macho = MachO::parse(h)?;
        let linkedit = macho.linkedit?;
        Some(MachOLauncher {
            linkedit: (linkedit, u64_at(h, linkedit + 40)?),
            code_signature: macho.code_signature?,
            text: macho.text?,
            page_size: vm_page_size(&macho),
        })
    }

    /// The size of the ad-hoc signature for `code_len` bytes of code.
    pub(crate) fn signature_len(code_len: u64, identifier: &str) -> u64 {
        let pages = code_len.div_ceil(CS_PAGE_SIZE);
        SUPER_BLOB_LEN + CODE_DIRECTORY_LEN + identifier.len() as u64 + 1 + pages * 32
    }

    /// The header changes for a signature of `signature_len` bytes at
    /// `signature_offset` (which is where the signed code ends): new values
    /// for `__LINKEDIT`'s vmsize and filesize, and for `LC_CODE_SIGNATURE`.
    pub(crate) fn patches(&self, signature_offset: u64, signature_len: u64) -> Vec<(usize, Vec<u8>)> {
        let (linkedit, linkedit_fileoff) = self.linkedit;
        let filesize = signature_offset + signature_len - linkedit_fileoff;
        let vmsize = filesize.div_ceil(self.page_size) * self.page_size;
        let mut command = Vec::with_capacity(8);
        command.extend_from_slice(&(signature_offset as u32).to_le_bytes());
        command.extend_from_slice(&(signature_len as u32).to_le_bytes());
        vec![
            (linkedit + 32, vmsize.to_le_bytes().to_vec()),
            (linkedit + 48, filesize.to_le_bytes().to_vec()),
            (self.code_signature + 8, command),
        ]
    }

    /// Builds the ad-hoc signature (a super blob holding one code
    /// directory) from the SHA-256 of each 4 KiB page of the code.
    pub(crate) fn signature(&self, code_len: u64, identifier: &str, page_hashes: &[[u8; 32]]) -> Vec<u8> {
        const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
        const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
        const CS_ADHOC: u32 = 0x2;
        const CS_LINKER_SIGNED: u32 = 0x2_0000;
        const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;
        let total = Self::signature_len(code_len, identifier);
        let directory_len = total - SUPER_BLOB_LEN;
        let ident_offset = CODE_DIRECTORY_LEN;
        let hash_offset = ident_offset + identifier.len() as u64 + 1;

        let mut out = Vec::with_capacity(total as usize);
        let u32be = |out: &mut Vec<u8>, v: u32| out.extend_from_slice(&v.to_be_bytes());
        let u64be = |out: &mut Vec<u8>, v: u64| out.extend_from_slice(&v.to_be_bytes());
        // Super blob with one index entry: the code directory.
        u32be(&mut out, CSMAGIC_EMBEDDED_SIGNATURE);
        u32be(&mut out, total as u32);
        u32be(&mut out, 1);
        u32be(&mut out, 0); // CSSLOT_CODEDIRECTORY
        u32be(&mut out, SUPER_BLOB_LEN as u32);
        // Code directory, version 0x20400.
        u32be(&mut out, CSMAGIC_CODEDIRECTORY);
        u32be(&mut out, directory_len as u32);
        u32be(&mut out, 0x20400);
        u32be(&mut out, CS_ADHOC | CS_LINKER_SIGNED);
        u32be(&mut out, hash_offset as u32);
        u32be(&mut out, ident_offset as u32);
        u32be(&mut out, 0); // special slots
        u32be(&mut out, page_hashes.len() as u32);
        u32be(&mut out, code_len as u32);
        out.extend_from_slice(&[32, 2, 0, 12]); // SHA-256, 2^12-byte pages
        u32be(&mut out, 0); // spare2
        u32be(&mut out, 0); // scatterOffset
        u32be(&mut out, 0); // teamOffset
        u32be(&mut out, 0); // spare3
        u64be(&mut out, 0); // codeLimit64
        u64be(&mut out, self.text.0);
        u64be(&mut out, self.text.1);
        u64be(&mut out, CS_EXECSEG_MAIN_BINARY);
        out.extend_from_slice(identifier.as_bytes());
        out.push(0);
        for hash in page_hashes {
            out.extend_from_slice(hash);
        }
        debug_assert_eq!(out.len() as u64, total);
        out
    }
}

/// Largest artifact a Mach-O code signature can cover (its code limit is a
/// 32-bit field).
#[cfg(feature = "write")]
pub(crate) const MAX_SIGNED_LEN: u64 = u32::MAX as u64;

#[cfg(feature = "write")]
pub(crate) fn cs_page_size() -> u64 {
    CS_PAGE_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal PE32+ header with a certificate table entry.
    fn pe(checksum: u32, security: (u32, u32)) -> Vec<u8> {
        let mut h = vec![0u8; 0x200];
        h[0..2].copy_from_slice(b"MZ");
        h[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        h[0x80..0x84].copy_from_slice(b"PE\0\0");
        h[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        h[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader
        let opt = 0x98;
        h[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        h[opt + 64..opt + 68].copy_from_slice(&checksum.to_le_bytes());
        h[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let dir = opt + 112 + 32;
        h[dir..dir + 4].copy_from_slice(&security.0.to_le_bytes());
        h[dir + 4..dir + 8].copy_from_slice(&security.1.to_le_bytes());
        h
    }

    #[test]
    fn authenticode_tables_are_found() {
        let h = pe(0x1234, (0x1000, 0x200));
        let found = layout(&h);
        assert_eq!(
            found.signature,
            Some(CodeSignature { kind: SignatureKind::Authenticode, offset: 0x1000, len: 0x200 })
        );
        let opt = 0x98;
        assert_eq!(found.signing_fields, vec![opt + 64..opt + 68, opt + 144..opt + 152]);
        assert_eq!(layout(&pe(0, (0, 0))).signature, None);
    }

    #[test]
    fn truncated_or_garbage_headers_have_no_signature() {
        let h = pe(0, (0x1000, 0x200));
        for cut in 0..h.len() {
            let _ = layout(&h[..cut]);
        }
        assert_eq!(layout(b"MZ").signature, None);
        let mut bad = h.clone();
        bad[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(layout(&bad), Layout::default());
        let mut macho = vec![0u8; 64];
        macho[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        macho[16..20].copy_from_slice(&1000u32.to_le_bytes());
        macho[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(layout(&macho), Layout::default());
    }

    #[test]
    fn blanking_applies_to_the_overlapping_part_of_a_chunk() {
        let mut chunk = vec![1u8; 10];
        blank_fields(&mut chunk, 100, &[95..102, 108..120, 0..5]);
        assert_eq!(chunk, [0, 0, 1, 1, 1, 1, 1, 1, 0, 0]);
    }

    #[test]
    fn identities_are_told_apart_from_ad_hoc_signatures() {
        let mut adhoc = Vec::new();
        for v in [0xfade_0cc0u32, 28, 1, 0, 20] {
            adhoc.extend_from_slice(&v.to_be_bytes());
        }
        assert!(!macho_signature_has_identity(&adhoc));
        let mut signed = Vec::new();
        for v in [0xfade_0cc0u32, 100, 2, 0, 28, 0x10000, 36, 0, 0, 0xfade_0b01, 64] {
            signed.extend_from_slice(&v.to_be_bytes());
        }
        assert!(macho_signature_has_identity(&signed));
    }
}
