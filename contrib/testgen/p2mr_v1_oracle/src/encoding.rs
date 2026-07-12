use sha2::{Digest, Sha256};

pub const MAX_HEX_BYTES: usize = 4 * 1024 * 1024;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    let mut input = Vec::with_capacity(64 + message.len());
    input.extend_from_slice(&tag_hash);
    input.extend_from_slice(&tag_hash);
    input.extend_from_slice(message);
    sha256(&input)
}

pub fn decode_hex(value: &str, context: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err(format!("{context}: odd-length hex"));
    }
    if value.len() / 2 > MAX_HEX_BYTES {
        return Err(format!("{context}: hex value exceeds size limit"));
    }
    hex::decode(value).map_err(|error| format!("{context}: invalid hex: {error}"))
}

pub fn decode_32(value: &str, context: &str) -> Result<[u8; 32], String> {
    decode_hex(value, context)?
        .try_into()
        .map_err(|_| format!("{context}: expected 32 bytes"))
}

pub fn compact_size(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=252 => output.push(value as u8),
        253..=0xffff => {
            output.push(253);
            output.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(254);
            output.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            output.push(255);
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
}

pub fn serialized_bytes(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(9 + value.len());
    compact_size(value.len() as u64, &mut output);
    output.extend_from_slice(value);
    output
}

pub struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }

    pub fn peek(&self, offset: usize) -> Option<u8> {
        self.data.get(self.position + offset).copied()
    }

    pub fn read_u8(&mut self) -> Result<u8, String> {
        Ok(self.read_exact(1)?[0])
    }

    pub fn read_u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.read_exact(4)?.try_into().unwrap()))
    }

    pub fn read_i32(&mut self) -> Result<i32, String> {
        Ok(i32::from_le_bytes(self.read_exact(4)?.try_into().unwrap()))
    }

    pub fn read_i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_le_bytes(self.read_exact(8)?.try_into().unwrap()))
    }

    pub fn read_exact(&mut self, size: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(size)
            .ok_or("input offset overflow")?;
        if end > self.data.len() {
            return Err("truncated input".to_string());
        }
        let result = &self.data[self.position..end];
        self.position = end;
        Ok(result)
    }

    pub fn read_compact_size(&mut self) -> Result<u64, String> {
        let prefix = self.read_u8()?;
        match prefix {
            0..=252 => Ok(prefix as u64),
            253 => {
                let value = u16::from_le_bytes(self.read_exact(2)?.try_into().unwrap()) as u64;
                if value < 253 {
                    Err("noncanonical CompactSize".to_string())
                } else {
                    Ok(value)
                }
            }
            254 => {
                let value = u32::from_le_bytes(self.read_exact(4)?.try_into().unwrap()) as u64;
                if value <= 0xffff {
                    Err("noncanonical CompactSize".to_string())
                } else {
                    Ok(value)
                }
            }
            255 => {
                let value = u64::from_le_bytes(self.read_exact(8)?.try_into().unwrap());
                if value <= 0xffff_ffff {
                    Err("noncanonical CompactSize".to_string())
                } else {
                    Ok(value)
                }
            }
        }
    }

    pub fn read_bytes(&mut self, maximum: usize) -> Result<Vec<u8>, String> {
        let size: usize = self
            .read_compact_size()?
            .try_into()
            .map_err(|_| "byte string length does not fit usize")?;
        if size > maximum {
            return Err("byte string exceeds size limit".to_string());
        }
        Ok(self.read_exact(size)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_boundaries_roundtrip() {
        for value in [0, 252, 253, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000] {
            let mut encoded = Vec::new();
            compact_size(value, &mut encoded);
            let mut reader = Reader::new(&encoded);
            assert_eq!(reader.read_compact_size().unwrap(), value);
            assert_eq!(reader.remaining(), 0);
        }
    }

    #[test]
    fn compact_size_rejects_noncanonical_encodings() {
        for encoded in [
            &[253, 1, 0][..],
            &[254, 0xff, 0, 0, 0],
            &[255, 1, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert!(Reader::new(encoded).read_compact_size().is_err());
        }
    }

    #[test]
    fn embedded_p2mr_leaf_known_answer() {
        let result = tagged_hash("P2MRLeaf", &[0xc0, 0x01, 0x00]);
        assert_eq!(
            hex::encode(result),
            "fae97225114b26d9ef3e3bea70f90d08fec30d9833c50b23e4a6cf8c33e6b200"
        );
    }

    #[test]
    fn embedded_tagged_hash_known_answers() {
        let message = [0u8, 1, 2];
        for (tag, expected) in [
            (
                "TapLeaf",
                "c3e90a36f39ab5cf9f76ec292d5be9b475ea9f5239a25854f981bb103d17894d",
            ),
            (
                "P2MRLeaf",
                "da460df6bf49626804816b7a540272e4d002c0c079069980dbaca701029b500a",
            ),
            (
                "TapSighash",
                "912b2d0be4ffc7b96d53e84ce69cdaf976e2511ce79f0f7f758f1165cb1db4fb",
            ),
            (
                "P2MRSighash",
                "9958fa210c8701d4e2e76c32aa2eb7af352d608b3d63c11c3ba701eeb2083c89",
            ),
        ] {
            assert_eq!(hex::encode(tagged_hash(tag, &message)), expected);
        }
    }
}
