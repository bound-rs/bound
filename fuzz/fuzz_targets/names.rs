//! Arbitrary bytes as resource paths, link targets and platform strings.
#![no_main]

use bound_format::{LinkTarget, NameRules, OsValue, ResourcePath};
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    if let Ok(path) = ResourcePath::from_bytes(data) {
        common::assert_contained(&path);
        assert!(path.components().all(|c| !c.is_empty() && c != b"." && c != b".."));
        assert!(!path.as_bytes().contains(&b'\\') && !path.as_bytes().contains(&0));
        if path.validate(NameRules::Windows).is_ok() {
            for component in path.components() {
                let text = std::str::from_utf8(component).expect("Windows names are Unicode");
                assert!(!text.contains(':') && !text.ends_with('.') && !text.ends_with(' '));
                assert!(!bound_format::names::is_windows_device_name(text));
            }
        }
        serde_json::to_string(&path).unwrap();
    }
    if let Ok(target) = LinkTarget::from_bytes(data) {
        assert!(!target.as_bytes().starts_with(b"/"));
        let _ = target.to_native();
    }
    // Display forms are safe to print to a terminal.
    let value = match std::str::from_utf8(data) {
        Ok(text) => OsValue::from(text),
        Err(_) => OsValue::UnixBytes(data.to_vec()),
    };
    let shown = value.display();
    assert!(!shown.chars().any(char::is_control), "{shown:?}");
});
