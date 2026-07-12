//! Fast lowercase hex encoding for memory dumps.

const HEX_LUT: &[u8; 16] = b"0123456789abcdef";

/// Lowercase-hex encode a byte slice.
///
/// This is a branchless table lookup into a preallocated buffer. The tight loop
/// auto-vectorizes, unlike the per-byte `format!("{:02x}", b)` it replaces, which
/// dominates the cost of large `debug_read_memory` responses (up to 256 KiB =
/// half a million formatting calls).
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = vec![0u8; bytes.len() * 2];
    for (i, &b) in bytes.iter().enumerate() {
        out[2 * i] = HEX_LUT[(b >> 4) as usize];
        out[2 * i + 1] = HEX_LUT[(b & 0x0f) as usize];
    }
    // SAFETY: every byte written is an ASCII hex digit, so the buffer is UTF-8.
    unsafe { String::from_utf8_unchecked(out) }
}

#[cfg(test)]
mod tests {
    use super::to_hex;

    #[test]
    fn encodes_known_vectors() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(to_hex(&[0x00, 0x0f, 0x90, 0xc3, 0xff]), "000f90c3ff");
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn matches_format_macro_reference() {
        let bytes: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        let reference: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(to_hex(&bytes), reference);
    }
}
