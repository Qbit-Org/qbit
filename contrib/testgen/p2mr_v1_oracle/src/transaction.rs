use crate::encoding::{compact_size, Reader};

const MAX_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
const MAX_INPUTS_OR_OUTPUTS: usize = 100_000;
const MAX_SCRIPT_BYTES: usize = 1024 * 1024;
const MAX_WITNESS_ITEMS: usize = 10_000;
const MAX_WITNESS_ITEM_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub previous_txid: [u8; 32],
    pub previous_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: i64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

fn bounded_count(value: u64, maximum: usize, what: &str) -> Result<usize, String> {
    let value: usize = value
        .try_into()
        .map_err(|_| format!("{what} count does not fit usize"))?;
    if value > maximum {
        Err(format!("{what} count exceeds limit"))
    } else {
        Ok(value)
    }
}

impl Transaction {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() > MAX_TRANSACTION_BYTES {
            return Err("transaction exceeds size limit".to_string());
        }
        let mut reader = Reader::new(data);
        let version = reader.read_i32()?;
        let has_witness = reader.peek(0) == Some(0) && reader.peek(1) == Some(1);
        if has_witness {
            reader.read_exact(2)?;
        }
        let input_count =
            bounded_count(reader.read_compact_size()?, MAX_INPUTS_OR_OUTPUTS, "input")?;
        if input_count == 0 {
            return Err("transaction has no inputs".to_string());
        }
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            inputs.push(TxIn {
                previous_txid: reader.read_exact(32)?.try_into().unwrap(),
                previous_vout: reader.read_u32()?,
                script_sig: reader.read_bytes(MAX_SCRIPT_BYTES)?,
                sequence: reader.read_u32()?,
                witness: Vec::new(),
            });
        }
        let output_count =
            bounded_count(reader.read_compact_size()?, MAX_INPUTS_OR_OUTPUTS, "output")?;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(TxOut {
                value: reader.read_i64()?,
                script_pubkey: reader.read_bytes(MAX_SCRIPT_BYTES)?,
            });
        }
        if has_witness {
            for input in &mut inputs {
                let count = bounded_count(
                    reader.read_compact_size()?,
                    MAX_WITNESS_ITEMS,
                    "witness item",
                )?;
                input.witness.reserve(count);
                for _ in 0..count {
                    input
                        .witness
                        .push(reader.read_bytes(MAX_WITNESS_ITEM_BYTES)?);
                }
            }
            if !inputs.iter().any(|input| !input.witness.is_empty()) {
                return Err("superfluous witness record".to_string());
            }
        }
        let lock_time = reader.read_u32()?;
        if reader.remaining() != 0 {
            return Err("trailing transaction bytes".to_string());
        }
        let tx = Self {
            version,
            inputs,
            outputs,
            lock_time,
        };
        if tx.serialize(has_witness) != data {
            return Err("transaction does not roundtrip canonically".to_string());
        }
        Ok(tx)
    }

    pub fn serialize(&self, include_witness: bool) -> Vec<u8> {
        let has_witness =
            include_witness && self.inputs.iter().any(|input| !input.witness.is_empty());
        let mut output = Vec::new();
        output.extend_from_slice(&self.version.to_le_bytes());
        if has_witness {
            output.extend_from_slice(&[0, 1]);
        }
        compact_size(self.inputs.len() as u64, &mut output);
        for input in &self.inputs {
            output.extend_from_slice(&input.previous_txid);
            output.extend_from_slice(&input.previous_vout.to_le_bytes());
            compact_size(input.script_sig.len() as u64, &mut output);
            output.extend_from_slice(&input.script_sig);
            output.extend_from_slice(&input.sequence.to_le_bytes());
        }
        compact_size(self.outputs.len() as u64, &mut output);
        for txout in &self.outputs {
            txout.serialize_into(&mut output);
        }
        if has_witness {
            for input in &self.inputs {
                compact_size(input.witness.len() as u64, &mut output);
                for item in &input.witness {
                    compact_size(item.len() as u64, &mut output);
                    output.extend_from_slice(item);
                }
            }
        }
        output.extend_from_slice(&self.lock_time.to_le_bytes());
        output
    }
}

impl TxOut {
    pub fn serialize_into(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.value.to_le_bytes());
        compact_size(self.script_pubkey.len() as u64, output);
        output.extend_from_slice(&self.script_pubkey);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_roundtrips_small_witness_transaction() {
        let original = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_txid: [0; 32],
                previous_vout: 0,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: vec![vec![1]],
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        let raw = original.serialize(true);
        let tx = Transaction::parse(&raw).unwrap();
        assert_eq!(tx, original);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.serialize(true), raw);
    }

    #[test]
    fn rejects_witness_marker_with_only_empty_stacks() {
        let transaction = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_txid: [0; 32],
                previous_vout: 0,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        let mut raw = transaction.serialize(false);
        raw.splice(4..4, [0, 1]);
        assert_eq!(
            Transaction::parse(&raw).unwrap_err(),
            "superfluous witness record"
        );
    }
}
