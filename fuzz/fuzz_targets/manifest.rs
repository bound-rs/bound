//! Arbitrary bytes as a manifest: strict decoding and validation must never
//! panic; whatever decodes must be the canonical encoding of what it decodes
//! to (so each manifest has exactly one encoding), and whatever validates
//! must name only paths inside the bundle.
#![no_main]

use bound_format::{Manifest, NameRules};
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let Ok(manifest) = Manifest::decode(data) else { return };
    assert_eq!(manifest.encode(), data, "only the canonical encoding decodes");

    let blob_total = manifest.blobs.iter().fold(0u64, |sum, b| sum.saturating_add(b.stored_size));
    for rules in [NameRules::Portable, NameRules::Windows] {
        let _ = bound_format::manifest::validate_tree(&manifest.resources, &manifest.platform.os, rules);
        for payload_len in [blob_total, manifest.payload.size] {
            if manifest.validate(payload_len, rules).is_ok() {
                for resource in &manifest.resources {
                    common::assert_contained(resource.path());
                    if rules == NameRules::Windows {
                        resource.path().validate(NameRules::Windows).expect("validated under Windows rules");
                    }
                }
            }
        }
    }
});
