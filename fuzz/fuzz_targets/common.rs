use std::path::{Component, Path};

use bound_format::ResourcePath;

/// The oracle for every validated resource path: its native form must
/// consist of exactly as many plain components as the resource path has,
/// so nothing (separators, prefixes, `..`) was smuggled through.
pub fn assert_contained(path: &ResourcePath) {
    let Ok(native) = path.to_native() else { return };
    let components: Vec<Component<'_>> = Path::new(&native).components().collect();
    assert_eq!(components.len(), path.components().count(), "{path:?} -> {native:?}");
    for component in components {
        assert!(matches!(component, Component::Normal(_)), "{path:?} -> {native:?}");
    }
}
