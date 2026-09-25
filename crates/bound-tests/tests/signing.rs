//! Platform code signing: artifacts can be signed as a whole (Authenticode
//! on Windows, `codesign` on macOS) and remain valid artifacts, because
//! readers find the footer before the signature and the launcher's hash
//! leaves out the header fields that signing rewrites.

use std::fs;
use std::path::{Path, PathBuf};

use bound_tests::{Harness, Value, assert_success, bins, os, stdout};

fn harness() -> Harness {
    Harness::new(bins!())
}

/// A minimal PE32+ header (enough for bound to identify the platform and
/// find the certificate table entry), padded to `len` bytes.
fn pe_launcher(len: usize) -> Vec<u8> {
    let mut h = vec![0u8; len];
    h[0..2].copy_from_slice(b"MZ");
    h[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    h[0x80..0x84].copy_from_slice(b"PE\0\0");
    h[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // x86_64
    h[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader
    h[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    h[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
    h
}

const CHECKSUM: usize = 0x98 + 64;
const SECURITY: usize = 0x98 + 112 + 4 * 8;

/// Signs a PE file the way `signtool` lays it out: zero padding to 8
/// bytes, a certificate table appended, and the header's checksum and
/// certificate table entry updated.
fn authenticode_sign(bytes: &mut Vec<u8>) {
    while !bytes.len().is_multiple_of(8) {
        bytes.push(0);
    }
    let offset = bytes.len() as u32;
    let certificate: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 251) as u8).collect();
    let length = 8 + certificate.len() as u32;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
    bytes.extend_from_slice(&0x0002u16.to_le_bytes()); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
    bytes.extend_from_slice(&certificate);
    bytes[SECURITY..SECURITY + 4].copy_from_slice(&offset.to_le_bytes());
    bytes[SECURITY + 4..SECURITY + 8].copy_from_slice(&length.to_le_bytes());
    bytes[CHECKSUM..CHECKSUM + 4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
}

fn build_windows_artifact(h: &Harness, launcher: &[u8], name: &str) -> PathBuf {
    fs::write(h.path("fake-launcher.exe"), launcher).unwrap();
    h.write("data.txt", "data");
    let out = h.bound_output(os![
        "-q",
        "--force",
        "--launcher",
        h.path("fake-launcher.exe"),
        "-o",
        name,
        "--include",
        "data.txt",
        "--",
        "tool.exe"
    ]);
    assert_success(&out, "bound build");
    h.path(format!("{name}.exe"))
}

fn inspect_json(h: &Harness, artifact: &Path) -> Value {
    let out = h.bound_output(os!["inspect", "--json", artifact]);
    assert_success(&out, "inspect");
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn authenticode_signed_artifacts_stay_valid() {
    let h = harness();
    // Every padding length signtool can produce.
    for extra in 0..8 {
        let artifact = build_windows_artifact(&h, &pe_launcher(0x400 + extra), &format!("tool{extra}"));
        let mut bytes = fs::read(&artifact).unwrap();
        assert!(inspect_json(&h, &artifact).get("code_signature").is_none());
        authenticode_sign(&mut bytes);
        fs::write(&artifact, &bytes).unwrap();

        let out = h.bound_output(os!["verify", &artifact]);
        assert_success(&out, "verify of a signed artifact");
        assert!(stdout(&out).contains("signature  present (Authenticode signature"), "{}", stdout(&out));
        let doc = inspect_json(&h, &artifact);
        assert_eq!(doc["code_signature"]["kind"], "authenticode");
        assert_eq!(doc["size"], bytes.len());
    }
}

#[test]
fn signatures_must_end_the_file_and_padding_must_be_zero() {
    let h = harness();
    let artifact = build_windows_artifact(&h, &pe_launcher(0x401), "tool");
    let mut signed = fs::read(&artifact).unwrap();
    authenticode_sign(&mut signed);

    let mut trailing = signed.clone();
    trailing.extend_from_slice(b"junk");
    fs::write(&artifact, &trailing).unwrap();
    assert!(!h.bound_output(os!["verify", &artifact]).status.success(), "data after the signature");

    // Non-zero bytes where the padding would be.
    let padding_at = signed.len() - 1008 - 1;
    let mut dirty = signed.clone();
    assert_eq!(dirty[padding_at], 0, "the test needs a padding byte");
    dirty[padding_at] = 1;
    fs::write(&artifact, &dirty).unwrap();
    assert!(!h.bound_output(os!["verify", &artifact]).status.success(), "non-zero padding");
}

#[test]
fn signing_does_not_hide_other_launcher_changes() {
    let h = harness();
    let artifact = build_windows_artifact(&h, &pe_launcher(0x400), "tool");
    let mut signed = fs::read(&artifact).unwrap();
    authenticode_sign(&mut signed);
    signed[0x200] ^= 1; // a launcher byte that signing never touches
    fs::write(&artifact, &signed).unwrap();
    let out = h.bound_output(os!["verify", &artifact]);
    assert!(!out.status.success());
    assert!(bound_tests::stderr(&out).contains("launcher"), "{}", bound_tests::stderr(&out));
}

#[test]
fn a_signed_launchers_signature_is_not_carried_into_artifacts() {
    let h = harness();
    let mut launcher = pe_launcher(0x400);
    authenticode_sign(&mut launcher);
    let artifact = build_windows_artifact(&h, &launcher, "tool");
    let doc = inspect_json(&h, &artifact);
    assert!(doc.get("code_signature").is_none(), "{doc}");
    let bytes = fs::read(&artifact).unwrap();
    assert_eq!(&bytes[SECURITY..SECURITY + 8], &[0; 8]);
    assert_success(&h.bound_output(os!["verify", &artifact]), "verify");
}

/// Signs `artifact` with the platform's own tool, as a distributor would:
/// Windows, Authenticode with a temporary self-signed certificate (in the
/// user's store, or the machine's where the user's is unavailable, as over
/// SSH), reporting what Windows says of the signature; macOS, `codesign`
/// with the hardened runtime and entitlements, as for notarization.
#[cfg(windows)]
fn platform_sign(_h: &Harness, artifact: &Path) -> String {
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
$cert = $null
$failures = @()
foreach ($store in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') {{
  try {{ $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=bound test' -CertStoreLocation $store; break }}
  catch {{ $failures += "${{store}}: $($_.Exception.Message)" }}
}}
if (-not $cert) {{ throw ("cannot create a code signing certificate`n" + ($failures -join "`n")) }}
try {{
  $signed = Set-AuthenticodeSignature -FilePath '{path}' -Certificate $cert -HashAlgorithm SHA256
  if (-not $signed.SignerCertificate) {{ throw $signed.StatusMessage }}
  (Get-AuthenticodeSignature -FilePath '{path}').Status
}} finally {{
  Remove-Item -Path $cert.PSPath
}}"#,
        path = artifact.display()
    );
    // Windows PowerShell finds its own modules only when started without
    // the module path of a PowerShell 7 that may have started the tests
    // (as CI's shell): it would load PowerShell 7's copies, which it cannot.
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .env_remove("PSModulePath")
        .output()
        .unwrap();
    assert_success(&out, "Authenticode signing");
    stdout(&out).trim().to_owned()
}

#[cfg(target_os = "macos")]
fn platform_sign(h: &Harness, artifact: &Path) -> String {
    h.write(
        "entitlements.plist",
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>
"#,
    );
    let out = std::process::Command::new("codesign")
        .args(["--sign", "-", "--force", "--options", "runtime", "--entitlements"])
        .arg(h.path("entitlements.plist"))
        .arg(artifact)
        .output()
        .unwrap();
    assert_success(&out, "codesign");
    codesign_verify(artifact)
}

/// What `codesign --verify --strict` says of a file ("valid" if it accepts it).
#[cfg(target_os = "macos")]
fn codesign_verify(path: &Path) -> String {
    let out = std::process::Command::new("codesign")
        .args(["--verify", "--strict", "--verbose=2"])
        .arg(path)
        .output()
        .unwrap();
    if out.status.success() { "valid".to_owned() } else { String::from_utf8_lossy(&out.stderr).into_owned() }
}

#[test]
fn artifacts_are_signed_as_the_platform_requires() {
    // macOS runs only signed code on Apple silicon: bound signs artifacts
    // (ad hoc) as it writes them, and the signature passes strict
    // validation. Windows and Linux run unsigned programs: artifacts carry
    // no signature until someone signs them.
    let h = harness();
    h.write("data.txt", "data");
    let artifact = h.bind("signed", os!["--include", "data.txt", "--", h.bins.fixture, "read", "@file:data.txt"]);
    let doc = inspect_json(&h, &artifact);
    #[cfg(target_os = "macos")]
    {
        assert_eq!(codesign_verify(&artifact), "valid");
        assert_eq!(doc["code_signature"]["kind"], "mach_o");
        assert_eq!(doc["code_signature"]["identity"], false);
    }
    #[cfg(not(target_os = "macos"))]
    assert!(doc.get("code_signature").is_none(), "{doc}");
    let run = h.run(&artifact, os![]);
    assert_success(&run, "artifact");
    assert_eq!(stdout(&run), "data");
}

#[test]
fn artifacts_can_be_signed_with_the_platforms_tool() {
    // Signed (again) by the platform's own tool, an artifact is still a
    // valid artifact: it runs, `bound verify` accepts it, and the platform
    // accepts the signature. Linux has no signatures for programs: there,
    // an artifact runs and verifies as bound built it.
    let h = harness();
    h.write("data.txt", "data");
    let artifact = h.bind("resigned", os!["--include", "data.txt", "--", h.bins.fixture, "read", "@file:data.txt"]);
    #[cfg(windows)]
    {
        // Windows checks the signed hash first; a self-signed certificate
        // then fails only for its untrusted root.
        let status = platform_sign(&h, &artifact);
        assert!(!["HashMismatch", "NotSigned", "Incompatible"].contains(&status.as_str()), "{status}");
        assert_eq!(inspect_json(&h, &artifact)["code_signature"]["kind"], "authenticode");
    }
    #[cfg(target_os = "macos")]
    assert_eq!(platform_sign(&h, &artifact), "valid");
    let run = h.run(&artifact, os![]);
    assert_success(&run, "signed artifact");
    assert_eq!(stdout(&run), "data");
    assert_success(&h.bound_output(os!["verify", &artifact]), "verify after signing");
}
