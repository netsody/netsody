use faster_hex::{hex_decode, hex_encode};

pub fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
    let mut bytes = [0u8; N];
    hex_decode(hex.as_bytes(), &mut bytes).expect("Invalid hex string");
    bytes
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = vec![0u8; bytes.len() * 2];
    hex_encode(bytes, &mut hex).expect("Failed to encode bytes to hex");
    String::from_utf8(hex).expect("Invalid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(
            hex_to_bytes::<32>("ab7a1654d463f9986530bed00569cc895697827b802153b8ef1598579713045f"),
            [
                171, 122, 22, 84, 212, 99, 249, 152, 101, 48, 190, 208, 5, 105, 204, 137, 86, 151,
                130, 123, 128, 33, 83, 184, 239, 21, 152, 87, 151, 19, 4, 95
            ]
        );

        assert_eq!(
            hex_to_bytes::<64>(
                "3e6499116ba86b4884345891f3421a5a16c902247326928ce41c10ad8a66bd1f668178a3be9ad22f4f6e94c835ac824cf365db86bb486ab4a42c021dec09c0e4"
            ),
            [
                62, 100, 153, 17, 107, 168, 107, 72, 132, 52, 88, 145, 243, 66, 26, 90, 22, 201, 2,
                36, 115, 38, 146, 140, 228, 28, 16, 173, 138, 102, 189, 31, 102, 129, 120, 163,
                190, 154, 210, 47, 79, 110, 148, 200, 53, 172, 130, 76, 243, 101, 219, 134, 187,
                72, 106, 180, 164, 44, 2, 29, 236, 9, 192, 228
            ]
        );
    }
}
