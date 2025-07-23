#[derive(Debug, thiserror::Error)]
pub enum HexError {
    #[error("Invalid hex string length")]
    InvalidLength,
    #[error("Invalid hex character: {0}")]
    InvalidCharacter(u8),
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
const HEX_LOOKUP: [u8; 256] = {
    let mut lookup = [0xFF; 256];
    let mut i = 0;
    while i < 16 {
        lookup[HEX_CHARS[i] as usize] = i as u8;
        lookup[HEX_CHARS[i].to_ascii_uppercase() as usize] = i as u8;
        i += 1;
    }
    lookup
};

pub fn hex_to_bytes<const N: usize>(hex: &str) -> Result<[u8; N], HexError> {
    if hex.len() != N * 2 {
        return Err(HexError::InvalidLength);
    }

    let mut bytes = [0u8; N];
    let hex_bytes = hex.as_bytes();

    for i in 0..N {
        let high = HEX_LOOKUP[hex_bytes[i * 2] as usize];
        let low = HEX_LOOKUP[hex_bytes[i * 2 + 1] as usize];

        if high == 0xFF || low == 0xFF {
            return Err(HexError::InvalidCharacter(
                hex_bytes[i * 2 + if high == 0xFF { 0 } else { 1 }],
            ));
        }

        bytes[i] = (high << 4) | low;
    }

    Ok(bytes)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = Vec::with_capacity(bytes.len() * 2);

    for &byte in bytes {
        hex.push(HEX_CHARS[(byte >> 4) as usize]);
        hex.push(HEX_CHARS[(byte & 0x0F) as usize]);
    }

    unsafe { String::from_utf8_unchecked(hex) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(
            hex_to_bytes::<32>("ab7a1654d463f9986530bed00569cc895697827b802153b8ef1598579713045f")
                .unwrap(),
            [
                171, 122, 22, 84, 212, 99, 249, 152, 101, 48, 190, 208, 5, 105, 204, 137, 86, 151,
                130, 123, 128, 33, 83, 184, 239, 21, 152, 87, 151, 19, 4, 95
            ]
        );

        assert_eq!(
            hex_to_bytes::<64>(
                "3e6499116ba86b4884345891f3421a5a16c902247326928ce41c10ad8a66bd1f668178a3be9ad22f4f6e94c835ac824cf365db86bb486ab4a42c021dec09c0e4"
            ).unwrap(),
            [
                62, 100, 153, 17, 107, 168, 107, 72, 132, 52, 88, 145, 243, 66, 26, 90, 22, 201, 2,
                36, 115, 38, 146, 140, 228, 28, 16, 173, 138, 102, 189, 31, 102, 129, 120, 163,
                190, 154, 210, 47, 79, 110, 148, 200, 53, 172, 130, 76, 243, 101, 219, 134, 187,
                72, 106, 180, 164, 44, 2, 29, 236, 9, 192, 228
            ]
        );
    }

    #[test]
    fn test_bytes_to_hex() {
        let bytes = [
            171, 122, 22, 84, 212, 99, 249, 152, 101, 48, 190, 208, 5, 105, 204, 137, 86, 151, 130,
            123, 128, 33, 83, 184, 239, 21, 152, 87, 151, 19, 4, 95,
        ];
        assert_eq!(
            bytes_to_hex(&bytes),
            "ab7a1654d463f9986530bed00569cc895697827b802153b8ef1598579713045f"
        );
    }
}
