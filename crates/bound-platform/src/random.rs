use std::io;

/// Returns `bytes` bytes of OS randomness as lowercase hex.
pub fn random_hex(bytes: usize) -> io::Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| io::Error::other(format!("no OS randomness: {e}")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn distinct_and_hex() {
        let a = super::random_hex(8).unwrap();
        let b = super::random_hex(8).unwrap();
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
