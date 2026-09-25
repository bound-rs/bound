//! Integrity checking (`bound verify`).
//!
//! Verification recomputes every hash in the artifact (footer -> manifest
//! -> launcher, payload and each resource), so any modified byte is
//! detected. It proves integrity, not authenticity: anyone can produce a
//! consistent artifact. Signatures are a separate, future feature.

use std::path::Path;

use bound_format::Resource;
use bound_format::verify::{VerifyReport, verify as verify_artifact};
use serde::Serialize;

use crate::error::CliError;
use crate::inspect::{open_error, open_file};
use crate::style::size;

/// Verifies an artifact. Structural problems that prevent reading it at all
/// are errors; content problems are listed in the report.
pub fn verify(path: &Path) -> Result<VerifyReport, CliError> {
    verify_artifact(open_file(path)?).map_err(|e| open_error(path, e))
}

pub fn render(path: &Path, report: &VerifyReport) -> String {
    let m = &report.manifest;
    let files = m.resources.iter().filter(|r| matches!(r, Resource::File { .. })).count();
    let status = |ok: bool| if ok { "ok" } else { "FAILED" };
    let mut out = format!("Verifying {}\n", path.display());
    out.push_str(&format!("  footer     ok (format {})\n", m.format));
    out.push_str(&format!("  manifest   ok (sha256 {})\n", report.footer.manifest_sha256));
    out.push_str(&format!("  launcher   {} ({})\n", status(report.launcher.is_ok()), size(m.launcher.size)));
    out.push_str(&format!("  payload    {} ({})\n", status(report.payload.is_ok()), size(m.payload.size)));
    let bad = report.blobs.iter().filter(|b| b.result.is_err()).count();
    out.push_str(&format!(
        "  resources  {} ({files} file(s) in {} stored blob(s){})\n",
        status(bad == 0),
        report.blobs.len(),
        if bad > 0 { format!(", {bad} damaged") } else { String::new() }
    ));
    if let Some(signature) = &report.signature {
        let tool = match signature.kind {
            bound_format::exe::SignatureKind::MachO => "codesign --verify --strict",
            bound_format::exe::SignatureKind::Authenticode => "signtool verify /pa",
        };
        out.push_str(&format!(
            "  signature  present ({}, {}): not checked by bound; use `{tool}`\n",
            signature.kind,
            size(signature.len)
        ));
    }
    if report.is_ok() {
        out.push_str(&format!("OK: {} is intact (integrity only; this is not a signature check)\n", path.display()));
    }
    out
}

#[derive(Serialize)]
struct VerifyDocument {
    ok: bool,
    path: String,
    digest: bound_format::Digest,
    problems: Vec<String>,
    /// The kind of platform code signature present, if any (not checked).
    #[serde(skip_serializing_if = "Option::is_none")]
    code_signature: Option<bound_format::exe::SignatureKind>,
}

pub fn render_json(path: &Path, report: &VerifyReport) -> String {
    let doc = VerifyDocument {
        ok: report.is_ok(),
        path: path.display().to_string(),
        digest: report.footer.manifest_sha256,
        problems: report.problems(),
        code_signature: report.signature.map(|s| s.kind),
    };
    let mut out = serde_json::to_string_pretty(&doc).expect("report serializes");
    out.push('\n');
    out
}

/// JSON for artifacts that could not be read at all.
pub fn render_json_error(path: &Path, error: &CliError) -> String {
    let doc = serde_json::json!({
        "ok": false,
        "path": path.display().to_string(),
        "problems": [error.message],
    });
    let mut out = serde_json::to_string_pretty(&doc).expect("report serializes");
    out.push('\n');
    out
}
