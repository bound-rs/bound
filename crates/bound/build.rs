//! Link settings for the `bound` and `bound-launcher` executables.

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os == "windows" && env == "msvc" {
        // Resolve the executables' own DLL imports from System32 only
        // (LOAD_LIBRARY_SEARCH_SYSTEM32). Artifacts are often run from
        // directories such as Downloads, where a planted DLL would
        // otherwise be loaded ahead of the system's.
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
