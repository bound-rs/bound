//! Integrity and hostile input: corruption detection, crafted malicious
//! manifests, malformed footers, and reproducible builds.

use std::fs;
use std::path::{Path, PathBuf};

use bound_tests::{
    Harness, Value, bins, bound_region, craft, dissect, encode_manifest, exe, os, seal, stderr, write_executable,
};

fn harness() -> Harness {
    Harness::new(bins!())
}

/// An artifact whose program reads a bundled file.
fn sample(h: &Harness) -> PathBuf {
    h.write("config.toml", "key = \"value\"\n");
    h.write("dir/a.txt", "a");
    h.bind("sample", os!["--include", "dir", "--", h.bins.fixture, "read", "@file:config.toml"])
}

fn offsets(bytes: &[u8]) -> bound_format::Footer {
    bound_format::footer::read_footer(&mut std::io::Cursor::new(bytes)).unwrap().0
}

fn write_variant(h: &Harness, name: &str, bytes: &[u8]) -> PathBuf {
    let path = h.path(exe(name));
    write_executable(&path, bytes);
    path
}

#[test]
fn verify_detects_payload_corruption_and_the_launcher_refuses_to_run() {
    let h = harness();
    let artifact = sample(&h);
    let original = fs::read(&artifact).unwrap();
    let footer = offsets(&original);

    // Damage that changes decoded content: verify fails and the launcher
    // refuses to start the program.
    let mut bytes = original.clone();
    bytes[footer.payload_offset as usize] ^= 0x40;
    let bad = write_variant(&h, "payload-content", &bytes);
    let out = h.bound_output(os!["verify", &bad]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("failed verification"), "{}", stderr(&out));
    let out = h.run(&bad, os![]);
    assert_eq!(out.status.code(), Some(125), "{}", bound_tests::describe(&out));
    assert!(out.stdout.is_empty(), "the program must not run with corrupted resources");
    assert!(stderr(&out).contains("corrupted"), "{}", stderr(&out));

    // Damage to the last byte of the payload: verify detects it through the
    // payload hash, and the launcher either refuses or materializes exactly
    // the original content.
    for (i, mask) in [0x80u8, 0x40, 0x20].into_iter().enumerate() {
        let mut bytes = original.clone();
        bytes[footer.manifest_offset as usize - 1] ^= mask;
        let bad = write_variant(&h, &format!("payload-padding-{i}"), &bytes);
        let out = h.bound_output(os!["verify", &bad]);
        assert_eq!(out.status.code(), Some(1), "mask {mask:#x}");
        let out = h.run(&bad, os![]);
        assert!(
            out.status.code() == Some(125) || bound_tests::stdout(&out) == "key = \"value\"\n",
            "mask {mask:#x}: {}",
            bound_tests::describe(&out)
        );
    }
}

#[test]
fn verify_detects_manifest_corruption() {
    let h = harness();
    let mut bytes = fs::read(sample(&h)).unwrap();
    let footer = offsets(&bytes);
    bytes[footer.manifest_offset as usize + 20] ^= 0x01;
    let bad = write_variant(&h, "manifest", &bytes);
    let out = h.bound_output(os!["verify", &bad]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("manifest is corrupted"), "{}", stderr(&out));
    let out = h.run(&bad, os![]);
    assert_eq!(out.status.code(), Some(125));
}

#[test]
fn verify_detects_launcher_corruption() {
    let h = harness();
    let mut bytes = fs::read(sample(&h)).unwrap();
    let footer = offsets(&bytes);
    // Somewhere in the middle of the launcher, away from the headers.
    bytes[footer.payload_offset as usize / 2] ^= 0xff;
    let bad = h.path("launcher-corrupt.bin");
    fs::write(&bad, &bytes).unwrap();
    let out = h.bound_output(os!["verify", &bad]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("launcher"), "{}", stderr(&out));
}

#[test]
fn verify_detects_truncation_and_appended_data() {
    let h = harness();
    let bytes = fs::read(sample(&h)).unwrap();
    for (name, variant) in [
        ("cut-1", bytes[..bytes.len() - 1].to_vec()),
        ("cut-100", bytes[..bytes.len() - 100].to_vec()),
        ("cut-half", bytes[..bytes.len() / 2].to_vec()),
        ("appended", [bytes.clone(), b"extra".to_vec()].concat()),
    ] {
        let bad = h.path(name);
        fs::write(&bad, &variant).unwrap();
        let out = h.bound_output(os!["verify", &bad]);
        assert_eq!(out.status.code(), Some(1), "{name}");
        assert!(!stderr(&out).contains("panicked"), "{name}: {}", stderr(&out));
    }
}

#[test]
fn unsupported_format_versions_fail_gracefully() {
    let h = harness();
    let mut bytes = bound_region(&fs::read(sample(&h)).unwrap());
    let n = bytes.len();
    bytes[n - 18..n - 16].copy_from_slice(&7u16.to_le_bytes());
    let newer = write_variant(&h, "newer", &seal(bytes));
    for command in ["inspect", "verify"] {
        let err = h.bound_fails(os![command, &newer]);
        assert!(err.contains("error: unsupported bound artifact format version 7"), "{command}: {err}");
    }
    let out = h.run(&newer, os![]);
    assert_eq!(out.status.code(), Some(125));
    assert!(stderr(&out).contains("unsupported bound artifact format version 7"), "{}", stderr(&out));
}

#[test]
fn absurd_footer_values_are_rejected_without_allocating() {
    let h = harness();
    let bytes = bound_region(&fs::read(sample(&h)).unwrap());
    let footer = offsets(&bytes);
    let body = &bytes[..bytes.len() - bound_format::FOOTER_LEN];
    let cases = [
        bound_format::Footer { manifest_len: u64::MAX / 2, ..footer.clone() },
        bound_format::Footer { payload_offset: u64::MAX - 1, ..footer.clone() },
        bound_format::Footer { payload_len: footer.payload_len + 1, ..footer.clone() },
        bound_format::Footer { manifest_offset: 0, ..footer.clone() },
    ];
    for (i, bad) in cases.into_iter().enumerate() {
        let mut variant = body.to_vec();
        variant.extend_from_slice(&bad.encode());
        let path = write_variant(&h, &format!("footer-{i}"), &seal(variant));
        let err = h.bound_fails(os!["inspect", &path]);
        assert!(err.contains("malformed bound footer"), "case {i}: {err}");
        let out = h.run(&path, os![]);
        assert_eq!(out.status.code(), Some(125), "case {i}");
    }
}

/// Rebuilds `artifact` with its manifest edited by `edit`.
fn tamper(h: &Harness, artifact: &Path, name: &str, edit: impl FnOnce(&mut Value)) -> PathBuf {
    let bytes = fs::read(artifact).unwrap();
    let (launcher, payload, mut manifest) = dissect(&bytes);
    edit(&mut manifest);
    write_variant(h, name, &craft(&launcher, &payload, &encode_manifest(&manifest)))
}

fn resource_index(manifest: &Value, path: &str) -> usize {
    manifest["resources"].as_array().unwrap().iter().position(|r| r["path"] == path).unwrap()
}

/// Renames the resource `config.toml` (and the argument that refers to it).
fn rename_resource(manifest: &mut Value, to: &str) {
    let i = resource_index(manifest, "config.toml");
    manifest["resources"][i]["path"] = Value::String(to.to_owned());
    for arg in manifest["args"].as_array_mut().unwrap() {
        if arg["type"] == "resource" {
            arg["path"] = Value::String(to.to_owned());
        }
    }
    // Keep resources sorted so that only the path itself is at fault.
    let resources = manifest["resources"].as_array_mut().unwrap();
    resources.sort_by(|a, b| a["path"].as_str().unwrap().cmp(b["path"].as_str().unwrap()));
}

fn assert_rejected(h: &Harness, artifact: &Path, what: &str, escape: Option<&Path>) {
    let inspect = h.bound_fails(os!["inspect", artifact]);
    assert!(inspect.contains("invalid manifest"), "{what}: inspect said {inspect}");
    let verify = h.bound_fails(os!["verify", artifact]);
    assert!(verify.contains("invalid manifest"), "{what}: verify said {verify}");
    let out = h.run(artifact, os![]);
    assert_eq!(out.status.code(), Some(125), "{what}: {}", bound_tests::describe(&out));
    assert!(out.stdout.is_empty(), "{what}: the program must not run");
    if let Some(escape) = escape {
        assert!(!escape.exists(), "{what}: {} was created", escape.display());
    }
}

#[test]
fn path_traversal_in_manifests_is_rejected_everywhere() {
    let h = harness();
    let artifact = sample(&h);
    let marker = format!("bound-escape-{}", std::process::id());
    let temp = std::env::temp_dir();
    let cases = [
        format!("../{marker}"),
        format!("..\\{marker}"),
        format!("dir/../../{marker}"),
        format!("dir\\..\\..\\{marker}"),
        format!("/tmp/{marker}"),
        format!("C:\\{marker}"),
        format!("\\\\server\\share\\{marker}"),
        format!("\\\\?\\C:\\{marker}"),
        "./config.toml".to_owned(),
        "dir//config.toml".to_owned(),
        "dir/".to_owned(),
        "".to_owned(),
        "a\u{0}b".to_owned(),
        "line\nbreak".to_owned(),
    ];
    for (i, bad) in cases.iter().enumerate() {
        let variant = tamper(&h, &artifact, &format!("traversal-{i}"), |m| rename_resource(m, bad));
        assert_rejected(&h, &variant, &format!("{bad:?}"), Some(&temp.join(&marker)));
    }
    assert!(!h.dir().parent().unwrap().join(&marker).exists());
}

#[test]
fn windows_reserved_names_are_rejected_for_windows_artifacts() {
    let h = harness();
    let artifact = sample(&h);
    for (i, bad) in [
        "CON",
        "nul.txt",
        "aux",
        "COM1",
        "lpt9.log",
        "C:config",
        "config:stream",
        "trailing.",
        "trailing ",
        "a*b",
        "q?",
    ]
    .iter()
    .enumerate()
    {
        let variant = tamper(&h, &artifact, &format!("windows-{i}"), |m| {
            rename_resource(m, bad);
            m["platform"]["os"] = Value::String("windows".into());
        });
        assert_rejected(&h, &variant, bad, None);
    }
}

#[test]
fn windows_names_are_enforced_by_the_windows_launcher_whatever_the_manifest_says() {
    let h = harness();
    let artifact = sample(&h);
    let variant = tamper(&h, &artifact, "device-name", |m| rename_resource(m, "aux.txt"));
    let out = h.run(&variant, os![]);
    if cfg!(windows) {
        assert_eq!(out.status.code(), Some(125), "{}", bound_tests::describe(&out));
    } else {
        // An ordinary file name on Unix.
        assert!(out.status.success(), "{}", bound_tests::describe(&out));
        assert_eq!(bound_tests::stdout(&out), "key = \"value\"\n");
    }
}

#[test]
fn malformed_manifests_are_rejected() {
    let h = harness();
    let artifact = sample(&h);
    type Edit = Box<dyn FnOnce(&mut Value)>;
    let edits: Vec<(&str, Edit)> = vec![
        ("unknown target mode", Box::new(|m| m["target"]["mode"] = "shell".into())),
        ("unknown resource type", Box::new(|m| m["resources"][0]["type"] = "device".into())),
        (
            "Unicode stored as bytes",
            Box::new(|m| m["target"] = serde_json::json!({"mode": "external", "program": {"unix_bytes": "677265"}})),
        ),
        ("format mismatch", Box::new(|m| m["format"] = 2.into())),
        (
            "duplicate resource",
            Box::new(|m| {
                let first = m["resources"][0].clone();
                m["resources"].as_array_mut().unwrap().insert(0, first);
            }),
        ),
        (
            "case collision",
            Box::new(|m| {
                // Names that differ only by case collide where file systems
                // ignore case, as on macOS.
                m["platform"]["os"] = "macos".into();
                m["resources"].as_array_mut().unwrap().push(serde_json::json!({"type": "dir", "path": "DIR"}));
                let resources = m["resources"].as_array_mut().unwrap();
                resources.sort_by(|a, b| a["path"].as_str().unwrap().cmp(b["path"].as_str().unwrap()));
            }),
        ),
        (
            "missing parent",
            Box::new(|m| {
                let i = resource_index(m, "dir");
                m["resources"].as_array_mut().unwrap().remove(i);
            }),
        ),
        (
            "size mismatch",
            Box::new(|m| {
                let i = resource_index(m, "config.toml");
                m["resources"][i]["size"] = 1_000_000.into();
            }),
        ),
        (
            "blob gap",
            Box::new(|m| {
                m["blobs"][0]["offset"] = 1.into();
            }),
        ),
        (
            "impossible expansion",
            Box::new(|m| {
                m["blobs"][0]["size"] = u64::MAX.into();
            }),
        ),
        (
            "second placeholder",
            Box::new(|m| {
                m["args"].as_array_mut().unwrap().push(serde_json::json!({"type": "runtime_args"}));
            }),
        ),
        (
            "NUL in argument",
            Box::new(|m| {
                m["args"].as_array_mut().unwrap().push(serde_json::json!({"type": "literal", "value": "a\u{0}b"}));
            }),
        ),
        (
            "reserved variable",
            Box::new(|m| {
                m["env"] = serde_json::json!([{"name": "BOUND_ROOT", "value": {"type": "literal", "value": "/"}}]);
            }),
        ),
        (
            "escaping symlink",
            Box::new(|m| {
                m["resources"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({"type": "symlink", "path": "zz", "target": "../../etc/passwd"}));
            }),
        ),
        (
            "absolute symlink",
            Box::new(|m| {
                m["resources"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({"type": "symlink", "path": "zz", "target": "/etc/passwd"}));
            }),
        ),
        (
            "embedded target not executable",
            Box::new(|m| {
                m["target"] = serde_json::json!({"mode": "embedded", "resource": "config.toml"});
            }),
        ),
        (
            "launcher size lie",
            Box::new(|m| {
                m["launcher"]["size"] = 1.into();
            }),
        ),
    ];
    for (i, (what, edit)) in edits.into_iter().enumerate() {
        let variant = tamper(&h, &artifact, &format!("malformed-{i}"), edit);
        assert_rejected(&h, &variant, what, None);
    }

    // Damage to the encoding itself (the footer's hash still matches).
    let bytes = fs::read(&artifact).unwrap();
    let (launcher, payload, manifest) = dissect(&bytes);
    let encoded = encode_manifest(&manifest);
    let damaged: [(&str, Vec<u8>); 3] = [
        ("trailing data", [encoded.as_slice(), &[0]].concat()),
        ("truncated", encoded[..encoded.len() - 1].to_vec()),
        ("not a manifest", b"{\"format\": 1}".to_vec()),
    ];
    for (what, manifest) in damaged {
        let variant =
            write_variant(&h, &format!("damaged-{}", what.replace(' ', "-")), &craft(&launcher, &payload, &manifest));
        assert_rejected(&h, &variant, what, None);
    }
}

#[test]
fn manifest_strings_cannot_inject_terminal_sequences() {
    let h = harness();
    let artifact = sample(&h);
    let hostile = "missing-\u{1b}]0;pwned\u{7}-\u{1b}[2J-program";
    let variant = tamper(&h, &artifact, "escape", |m| {
        m["target"] = serde_json::json!({"mode": "external", "program": hostile});
    });
    let out = h.run(&variant, os![]);
    assert_eq!(out.status.code(), Some(127), "{}", bound_tests::describe(&out));
    let err = stderr(&out);
    assert!(!err.contains('\u{1b}') && !err.contains('\u{7}'), "raw control characters in {err:?}");
    assert!(err.contains("\\u{001b}"), "{err:?}");
    for command in ["inspect", "verify"] {
        let out = h.bound_output(os![command, &variant]);
        let text = format!("{}{}", bound_tests::stdout(&out), stderr(&out));
        assert!(!text.contains('\u{1b}') && !text.contains('\u{7}'), "{command}: raw control characters");
    }
}

#[test]
fn decoder_messages_cannot_inject_terminal_sequences() {
    let h = harness();
    let artifact = sample(&h);
    let hostile = "x\u{1b}]0;pwned\u{7}\u{202e}";
    let (launcher, payload, manifest) = dissect(&fs::read(&artifact).unwrap());
    let trailing = [encode_manifest(&manifest), hostile.as_bytes().to_vec()].concat();
    let variants = [
        write_variant(&h, "trailing", &craft(&launcher, &payload, &trailing)),
        tamper(&h, &artifact, "path", |m| rename_resource(m, hostile)),
    ];
    for variant in &variants {
        let out = h.run(variant, os![]);
        assert_eq!(out.status.code(), Some(125), "{}", bound_tests::describe(&out));
        for text in [stderr(&out), stderr(&h.bound_output(os!["inspect", variant]))] {
            assert!(text.contains("invalid manifest"), "{text:?}");
            assert!(!text.chars().any(|c| matches!(c, '\u{1b}' | '\u{7}' | '\u{202e}')), "{text:?}");
        }
    }
}

#[test]
fn only_canonically_encoded_manifests_are_accepted() {
    let h = harness();
    let bytes = fs::read(sample(&h)).unwrap();
    let (launcher, payload, manifest) = dissect(&bytes);
    let footer = offsets(&bytes);
    let stored = &bytes[footer.manifest_offset as usize..(footer.manifest_offset + footer.manifest_len) as usize];
    // The tests' own encoder writes exactly what bound writes.
    let encoded = encode_manifest(&manifest);
    assert_eq!(encoded, stored);
    // The same manifest with its format version (1) as a two-byte varint.
    assert_eq!(encoded[0], 1);
    let overlong = [&[0x81, 0x00], &encoded[1..]].concat();
    let variant = write_variant(&h, "overlong", &craft(&launcher, &payload, &overlong));
    let err = h.bound_fails(os!["inspect", &variant]);
    assert!(err.contains("canonical"), "{err}");
    assert_eq!(h.run(&variant, os![]).status.code(), Some(125));
}

/// Wraps `inner` (an artifact) as the embedded program of a new artifact
/// whose launcher is a few fake bytes (inspection never runs launchers).
fn wrap(inner: &[u8]) -> Vec<u8> {
    use bound_format::{
        ArgTemplate, ArtifactWriter, BundleMode, CwdMode, Manifest, Platform, RegionInfo, Resource, Target,
    };
    let mut writer = ArtifactWriter::new(std::io::Cursor::new(Vec::new()), &mut &b"\x7fELF-fake"[..]).unwrap();
    let blob = writer.add_blob(&mut &inner[..]).unwrap();
    let program = bound_format::ResourcePath::new("inner").unwrap();
    let placeholder = RegionInfo { size: 0, sha256: bound_format::Digest([0; 32]) };
    let manifest = Manifest {
        format: 1,
        generator: "test".into(),
        platform: Platform { os: "linux".into(), arch: "x86_64".into(), binary_format: "elf".into() },
        launcher: placeholder.clone(),
        payload: placeholder,
        target: Target::Embedded { resource: program.clone() },
        args: vec![ArgTemplate::RuntimeArgs],
        env: vec![],
        cwd: CwdMode::Inherit,
        bundle: BundleMode::Private,
        resources: vec![Resource::File { path: program, size: blob.size, sha256: blob.sha256, executable: true }],
        blobs: vec![],
    };
    writer.finish(manifest).unwrap().0.into_inner()
}

#[test]
fn deeply_nested_artifacts_are_inspected_to_a_limit() {
    let h = harness();
    let innermost = fs::read(sample(&h)).unwrap();
    let mut artifact = innermost;
    for _ in 0..12 {
        artifact = wrap(&artifact);
    }
    let path = write_variant(&h, "nested", &artifact);
    let out = h.bound_output(os!["inspect", &path]);
    let text = bound_tests::stdout(&out);
    assert!(out.status.success(), "{}", bound_tests::describe(&out));
    assert!(text.contains("Nested: a bound artifact"), "{text}");
    let out = h.bound_output(os!["inspect", "--json", &path]);
    assert!(out.status.success(), "{}", bound_tests::describe(&out));
    let mut doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut depth = 0;
    while doc.get("nested").is_some() {
        doc = doc["nested"].take();
        depth += 1;
    }
    assert_eq!(depth, 8, "nesting is examined to a fixed depth");
    assert_eq!(doc["nested_not_examined"], true);
}

#[test]
fn inspecting_a_named_pipe_does_not_block() {
    // A FIFO (Unix) or a pipe server waiting for a client (Windows): reading
    // either would wait forever. bound refuses them at once.
    let h = harness();
    for command in ["inspect", "verify"] {
        #[cfg(unix)]
        let pipe = {
            use std::os::unix::ffi::OsStrExt;
            let fifo = h.path(format!("fifo-{command}"));
            let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
            // SAFETY: creating a FIFO at a path we own.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            fifo
        };
        #[cfg(windows)]
        let (pipe, _server) = {
            use std::os::windows::ffi::OsStrExt;
            use std::os::windows::io::FromRawHandle;
            use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
            use windows_sys::Win32::System::Pipes::{
                CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
            };
            let pipe = PathBuf::from(format!(r"\\.\pipe\bound-test-{}-{command}", std::process::id()));
            let wide: Vec<u16> = pipe.as_os_str().encode_wide().chain([0]).collect();
            // SAFETY: a valid name; the handle is closed by the guard.
            let handle = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    4096,
                    4096,
                    0,
                    std::ptr::null(),
                )
            };
            assert_ne!(handle, windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE);
            // SAFETY: the handle was just created and is closed once.
            (pipe, unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle) })
        };
        let start = std::time::Instant::now();
        let err = h.bound_fails(os![command, &pipe]);
        assert!(err.contains("not a regular file"), "{command}: {err}");
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
    }
}

#[test]
fn lying_content_sizes_are_caught() {
    let h = harness();
    // One compressible file (stored with zstd) and one tiny file (stored as
    // is), then claim more content than either holds, consistently in the
    // resource and blob tables.
    h.write("big.txt", "compressible text\n".repeat(1000));
    h.write("tiny.txt", "t");
    let artifact = h.bind("sizes", os!["--", h.bins.fixture, "read", "@file:big.txt", "@file:tiny.txt"]);
    let lie = |name: &str, target: &str| {
        tamper(&h, &artifact, name, |m| {
            let i = resource_index(m, target);
            let sha = m["resources"][i]["sha256"].clone();
            let blob = m["blobs"].as_array_mut().unwrap().iter_mut().find(|b| b["sha256"] == sha).unwrap();
            let claimed = blob["size"].as_u64().unwrap() + 5;
            blob["size"] = claimed.into();
            m["resources"][i]["size"] = claimed.into();
        })
    };

    // Compressed: the manifest is consistent, so the lie surfaces when the
    // content is decoded, by verify or by the launcher.
    let compressed = lie("liar-compressed", "big.txt");
    let out = h.bound_output(os!["verify", &compressed]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("truncated"), "{}", stderr(&out));
    assert_eq!(h.run(&compressed, os![]).status.code(), Some(125));

    // Stored as is: sizes must match exactly, so the manifest itself is
    // rejected.
    let stored = lie("liar-stored", "tiny.txt");
    assert_rejected(&h, &stored, "stored size lie", None);
}

#[test]
fn builds_are_reproducible() {
    let h = harness();
    h.write("config.toml", "k = 1\n");
    h.write("templates/a.html", "a");
    h.write("templates/b/c.html", "c");
    let args = || {
        os![
            "--include",
            "templates",
            "--env",
            "MODE=prod",
            "--env",
            "CFG=@file:config.toml",
            "--cwd",
            "bundle",
            "--",
            h.bins.fixture,
            "report",
            "@file:config.toml",
            "@args",
            "tail"
        ]
    };
    let first = h.bind("first", args());
    let second = h.bind("second", args());
    let a = fs::read(&first).unwrap();
    assert_eq!(a, fs::read(&second).unwrap(), "two identical builds differ");

    // The same inputs in a different directory produce the same bytes.
    let other = harness();
    other.write("config.toml", "k = 1\n");
    other.write("templates/a.html", "a");
    other.write("templates/b/c.html", "c");
    let args = os![
        "--include",
        "templates",
        "--env",
        "MODE=prod",
        "--env",
        "CFG=@file:config.toml",
        "--cwd",
        "bundle",
        "--",
        h.bins.fixture,
        "report",
        "@file:config.toml",
        "@args",
        "tail"
    ];
    let third = other.bind("third", args);
    assert_eq!(a, fs::read(&third).unwrap(), "builds in different directories differ");

    // Nothing about the build directory leaks into the artifact.
    for dir in [h.dir(), other.dir()] {
        let needle = dir.to_string_lossy().into_owned();
        assert!(!a.windows(needle.len()).any(|w| w == needle.as_bytes()), "artifact contains {needle}");
    }
}

#[test]
fn reproducible_with_embedded_programs() {
    let h = harness();
    h.fixture_copy("tool");
    let dot = format!(".{}{}", std::path::MAIN_SEPARATOR, exe("tool"));
    let first = h.bind("e1", os!["--embed-program", "--", &dot, "report"]);
    let second = h.bind("e2", os!["--embed-program", "--", &dot, "report"]);
    assert_eq!(fs::read(first).unwrap(), fs::read(second).unwrap());
}
