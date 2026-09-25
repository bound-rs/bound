//! Arbitrary bytes as an artifact: opening, streaming every blob and full
//! verification must never panic, hang or allocate unboundedly, and
//! recognizing an artifact while streaming it must agree with the reader.
#![no_main]

use std::io::{Cursor, Read, Write};

use bound_format::footer::{MagicScan, has_magic};
use bound_format::{ArtifactReader, NameRules, Resource};
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    for rules in [NameRules::Portable, NameRules::Windows] {
        let Ok(mut reader) = ArtifactReader::open(Cursor::new(data), rules) else { continue };
        let manifest = reader.manifest().clone();
        for resource in &manifest.resources {
            common::assert_contained(resource.path());
            if let Resource::File { sha256, .. } = resource {
                if let Ok(mut blob) = reader.open_blob(sha256) {
                    let mut buf = [0u8; 8192];
                    while let Ok(n) = blob.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                    }
                }
            }
        }
    }
    let _ = bound_format::verify::verify(Cursor::new(data));

    // Recognizing an artifact while streaming it agrees with locating its
    // footer in a file.
    let mut scan = MagicScan::new(data.len() as u64);
    scan.write_all(data).unwrap();
    assert_eq!(scan.found(), has_magic(&mut Cursor::new(data)).unwrap());
});
