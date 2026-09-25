//! Identification of the platform an executable targets.
//!
//! bound never assumes that the launcher it embeds matches the machine it
//! runs on: it inspects the launcher's header (ELF, Mach-O or PE) and records
//! the result in the manifest. This is what lets output naming (`.exe`),
//! file-name rules and inspection follow the *target*, which is also the
//! foundation for future cross-target builds.

use std::fmt;

use serde::Serialize;

use crate::limits::MAX_LABEL_LEN;

/// The operating system, architecture and executable format of a launcher.
///
/// Values are open-ended lowercase identifiers so that newer artifacts stay
/// inspectable by older tools: `os` is e.g. `linux`, `macos`, `windows`;
/// `arch` is e.g. `x86_64`, `aarch64`; `binary_format` is `elf`, `mach-o`
/// or `pe`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Platform {
    pub os: String,
    pub arch: String,
    pub binary_format: String,
}

impl Platform {
    /// The platform this code was compiled for.
    pub fn host() -> Platform {
        let binary_format = if cfg!(windows) {
            "pe"
        } else if cfg!(target_vendor = "apple") {
            "mach-o"
        } else {
            "elf"
        };
        Platform {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            binary_format: binary_format.to_owned(),
        }
    }

    pub fn is_windows(&self) -> bool {
        self.os == "windows"
    }

    /// Identifies an executable from its first bytes. Returns `None` if the
    /// bytes are not a recognized ELF, Mach-O or PE image. `header` should
    /// hold at least the first 4 KiB of the file when available.
    pub fn sniff(header: &[u8]) -> Option<Platform> {
        sniff_elf(header).or_else(|| sniff_macho(header)).or_else(|| sniff_pe(header))
    }

    /// Checks that every field is a short lowercase identifier.
    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [("os", &self.os), ("arch", &self.arch), ("binary_format", &self.binary_format)] {
            let ok = !value.is_empty()
                && value.len() <= MAX_LABEL_LEN
                && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
            if !ok {
                return Err(format!("platform {name} {value:?} is not a valid identifier"));
            }
        }
        Ok(())
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.os, self.arch)
    }
}

fn platform(os: &str, arch: &str, format: &str) -> Platform {
    Platform { os: os.to_owned(), arch: arch.to_owned(), binary_format: format.to_owned() }
}

fn sniff_elf(h: &[u8]) -> Option<Platform> {
    if h.len() < 20 || &h[..4] != b"\x7fELF" {
        return None;
    }
    let machine = match h[5] {
        1 => u16::from_le_bytes([h[18], h[19]]),
        2 => u16::from_be_bytes([h[18], h[19]]),
        _ => return None,
    };
    let arch = match machine {
        0x3e => "x86_64",
        0xb7 => "aarch64",
        0x03 => "x86",
        0x28 => "arm",
        0xf3 => "riscv",
        _ => "unknown",
    };
    // EI_OSABI is 0 (System V) for almost every Linux executable.
    let os = match h[7] {
        9 => "freebsd",
        12 => "openbsd",
        2 => "netbsd",
        _ => "linux",
    };
    Some(platform(os, arch, "elf"))
}

fn sniff_macho(h: &[u8]) -> Option<Platform> {
    if h.len() < 8 {
        return None;
    }
    let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    match magic {
        // MH_MAGIC_64 / MH_MAGIC, little-endian.
        0xfeed_facf | 0xfeed_face => {
            let cputype = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
            let arch = match cputype {
                0x0100_0007 => "x86_64",
                0x0100_000c => "aarch64",
                7 => "x86",
                _ => "unknown",
            };
            Some(platform("macos", arch, "mach-o"))
        }
        // FAT_MAGIC (big-endian on disk). Java class files share this magic,
        // but their "architecture count" is a version number (>= 45).
        _ if u32::from_be_bytes([h[0], h[1], h[2], h[3]]) == 0xcafe_babe => {
            let count = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
            (1..=20).contains(&count).then(|| platform("macos", "universal", "mach-o"))
        }
        _ => None,
    }
}

fn sniff_pe(h: &[u8]) -> Option<Platform> {
    if h.len() < 0x40 || &h[..2] != b"MZ" {
        return None;
    }
    let pe = u32::from_le_bytes([h[0x3c], h[0x3d], h[0x3e], h[0x3f]]) as usize;
    let sig = h.get(pe..pe.checked_add(6)?)?;
    if &sig[..4] != b"PE\0\0" {
        return None;
    }
    let arch = match u16::from_le_bytes([sig[4], sig[5]]) {
        0x8664 => "x86_64",
        0xaa64 => "aarch64",
        0x014c => "x86",
        _ => "unknown",
    };
    Some(platform("windows", arch, "pe"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_elf() {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = 2;
        h[5] = 1;
        h[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        assert_eq!(Platform::sniff(&h), Some(platform("linux", "x86_64", "elf")));
        h[18..20].copy_from_slice(&0xb7u16.to_le_bytes());
        assert_eq!(Platform::sniff(&h).unwrap().arch, "aarch64");
    }

    #[test]
    fn sniffs_macho() {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes());
        h[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        assert_eq!(Platform::sniff(&h), Some(platform("macos", "aarch64", "mach-o")));
        h[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        assert_eq!(Platform::sniff(&h).unwrap().arch, "x86_64");
        let mut fat = vec![0u8; 64];
        fat[..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        fat[4..8].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(Platform::sniff(&fat).unwrap().arch, "universal");
        fat[4..8].copy_from_slice(&52u32.to_be_bytes()); // a Java class file
        assert_eq!(Platform::sniff(&fat), None);
    }

    #[test]
    fn sniffs_pe() {
        let mut h = vec![0u8; 256];
        h[..2].copy_from_slice(b"MZ");
        h[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        h[0x80..0x84].copy_from_slice(b"PE\0\0");
        h[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        assert_eq!(Platform::sniff(&h), Some(platform("windows", "x86_64", "pe")));
        h[0x84..0x86].copy_from_slice(&0xaa64u16.to_le_bytes());
        assert_eq!(Platform::sniff(&h).unwrap().arch, "aarch64");
        // e_lfanew pointing past the buffer must not panic.
        h[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(Platform::sniff(&h), None);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(Platform::sniff(b""), None);
        assert_eq!(Platform::sniff(b"#!/bin/sh\necho hi\n"), None);
        assert_eq!(Platform::sniff(&[0xff; 4096]), None);
    }

    #[test]
    fn host_executable_is_sniffed_as_host() {
        let exe = std::env::current_exe().unwrap();
        let bytes = std::fs::read(exe).unwrap();
        let sniffed = Platform::sniff(&bytes[..bytes.len().min(4096)]).unwrap();
        let host = Platform::host();
        assert_eq!(sniffed.binary_format, host.binary_format);
        assert_eq!(sniffed.os, host.os);
        assert_eq!(sniffed.arch, host.arch);
    }

    #[test]
    fn validation() {
        Platform::host().validate().unwrap();
        assert!(platform("Linux", "x86_64", "elf").validate().is_err());
        assert!(platform("", "x86_64", "elf").validate().is_err());
    }
}
