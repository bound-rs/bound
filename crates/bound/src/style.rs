//! Terminal presentation helpers.

use std::io::IsTerminal;

/// Whether to color diagnostics on stderr: only on a terminal, and never
/// when `NO_COLOR` is set.
pub fn color_stderr() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal()
}

/// Formats a diagnostic label such as `error:` or `warning:`.
pub fn label(text: &str, color: &str) -> String {
    if color_stderr() { format!("\x1b[1;{color}m{text}:\x1b[0m") } else { format!("{text}:") }
}

pub fn error_label() -> String {
    label("error", "31")
}

pub fn warning_label() -> String {
    label("warning", "33")
}

pub fn note_label() -> String {
    label("note", "36")
}

pub fn hint_label() -> String {
    label("hint", "32")
}

/// Human-readable byte count (binary units).
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    #[test]
    fn sizes() {
        assert_eq!(super::size(0), "0 B");
        assert_eq!(super::size(1023), "1023 B");
        assert_eq!(super::size(1024), "1.0 KiB");
        assert_eq!(super::size(1536 * 1024), "1.5 MiB");
    }
}
