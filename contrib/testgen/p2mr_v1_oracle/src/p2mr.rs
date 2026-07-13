use crate::encoding::{compact_size, decode_32, decode_hex, serialized_bytes, sha256, tagged_hash};
use crate::script;
use crate::transaction::{Transaction, TxOut};
use bitcoinpqc::{PublicKey, Signature};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const P2MR_LEAF_VERSION: u8 = 0xc0;
const MAX_CONTROL_SIZE: usize = 1 + 32 * 128;
const PQC_PUBLIC_KEY_SIZE: usize = 32;
const PQC_SIGNATURE_SIZE: usize = 3680;
const VALIDATION_WEIGHT_OFFSET: i64 = 50;
const VALIDATION_WEIGHT_PER_PQC: i64 = 3730;

#[derive(Clone)]
pub struct Observation {
    pub id: String,
    pub category: String,
    pub accepted: bool,
    pub stage: String,
    pub error: String,
}

#[derive(Clone)]
struct Expected {
    accepted: bool,
    stage: String,
    error: String,
}

#[derive(Clone)]
struct SpentOutput {
    value: i64,
    script_pubkey: Vec<u8>,
}

fn object<'a>(value: &'a Value, context: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{context}: expected object"))
}

fn string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    context: &str,
) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context}: missing string {field}"))
}

fn unsigned(object: &Map<String, Value>, field: &str, context: &str) -> Result<u64, String> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{context}: missing unsigned integer {field}"))
}

fn expected(value: &Value, context: &str) -> Result<Expected, String> {
    let expected = object(value, context)?;
    exact_object_keys(expected, &["accepted", "stage", "error"], context)?;
    Ok(Expected {
        accepted: expected
            .get("accepted")
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("{context}: missing accepted"))?,
        stage: string(expected, "stage", context)?.to_string(),
        error: string(expected, "error", context)?.to_string(),
    })
}

fn exact_object_keys(
    object: &Map<String, Value>,
    expected: &[&str],
    context: &str,
) -> Result<(), String> {
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    if actual != expected {
        return Err(format!("{context}: unknown or missing fields"));
    }
    Ok(())
}

fn checked_observation(
    id: &str,
    category: &str,
    observed: Expected,
    expected: Expected,
) -> Result<Observation, String> {
    if observed.accepted != expected.accepted
        || observed.stage != expected.stage
        || observed.error != expected.error
    {
        return Err(format!(
            "{id}: expected ({}, {}, {}), observed ({}, {}, {})",
            expected.accepted,
            expected.stage,
            expected.error,
            observed.accepted,
            observed.stage,
            observed.error
        ));
    }
    Ok(Observation {
        id: id.to_string(),
        category: category.to_string(),
        accepted: observed.accepted,
        stage: observed.stage,
        error: observed.error,
    })
}

pub fn leaf_hash(version: u8, script: &[u8], tag: &str) -> [u8; 32] {
    let mut message = vec![version];
    compact_size(script.len() as u64, &mut message);
    message.extend_from_slice(script);
    tagged_hash(tag, &message)
}

fn branch_hash(left: &[u8; 32], right: &[u8; 32], tag: &str) -> [u8; 32] {
    tagged_hash(tag, &branch_preimage(left, right))
}

fn branch_preimage(left: &[u8; 32], right: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(64);
    if left < right {
        message.extend_from_slice(left);
        message.extend_from_slice(right);
    } else {
        message.extend_from_slice(right);
        message.extend_from_slice(left);
    }
    message
}

fn bech32_polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    let generators = [
        0x3b6a57b2u32,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3,
    ];
    let mut checksum = 1u32;
    for value in values {
        let top = checksum >> 25;
        checksum = (checksum & 0x01ff_ffff) << 5 ^ u32::from(value);
        for (bit, generator) in generators.iter().enumerate() {
            if (top >> bit) & 1 != 0 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

fn witness_v2_address(hrp: &str, program: &[u8; 32]) -> String {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut data = vec![2u8];
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in program {
        accumulator = accumulator << 8 | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(((accumulator >> bits) & 31) as u8);
        }
    }
    if bits != 0 {
        data.push(((accumulator << (5 - bits)) & 31) as u8);
    }
    let mut expanded = Vec::with_capacity(hrp.len() * 2 + 1 + data.len() + 6);
    expanded.extend(hrp.bytes().map(|byte| byte >> 5));
    expanded.push(0);
    expanded.extend(hrp.bytes().map(|byte| byte & 31));
    expanded.extend_from_slice(&data);
    expanded.extend_from_slice(&[0; 6]);
    let checksum = bech32_polymod(expanded) ^ 0x2bc8_30a3;
    let mut result = format!("{hrp}1");
    for value in data
        .into_iter()
        .chain((0..6).map(|index| ((checksum >> (5 * (5 - index))) & 31) as u8))
    {
        result.push(CHARSET[value as usize] as char);
    }
    result
}

fn root_from_control(
    control: &[u8],
    script: &[u8],
    leaf_tag: &str,
    branch_tag: &str,
) -> Result<[u8; 32], String> {
    if control.is_empty() || control.len() > MAX_CONTROL_SIZE || (control.len() - 1) % 32 != 0 {
        return Err("SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE".to_string());
    }
    if control[0] & 1 == 0 {
        return Err("SCRIPT_ERR_P2MR_CONTROL_BIT0".to_string());
    }
    let mut root = leaf_hash(control[0] & 0xfe, script, leaf_tag);
    for sibling in control[1..].chunks_exact(32) {
        root = branch_hash(&root, &sibling.try_into().unwrap(), branch_tag);
    }
    Ok(root)
}

fn program_from_script_pubkey(script_pubkey: &[u8], context: &str) -> Result<[u8; 32], String> {
    if script_pubkey.len() != 34 || script_pubkey[..2] != [0x52, 0x20] {
        return Err(format!("{context}: expected native v2/32 scriptPubKey"));
    }
    Ok(script_pubkey[2..].try_into().unwrap())
}

fn commitment_outcome(control: &[u8], script_bytes: &[u8], program: &[u8; 32]) -> Expected {
    let root = match root_from_control(control, script_bytes, "P2MRLeaf", "P2MRBranch") {
        Ok(root) => root,
        Err(error) if error == "SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE" => {
            return Expected {
                accepted: false,
                stage: "control-size".to_string(),
                error,
            }
        }
        Err(error) => {
            return Expected {
                accepted: false,
                stage: "control-marker".to_string(),
                error,
            }
        }
    };
    if root != *program {
        return Expected {
            accepted: false,
            stage: "commitment".to_string(),
            error: "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH".to_string(),
        };
    }
    if control[0] & 0xfe != P2MR_LEAF_VERSION {
        return Expected {
            accepted: true,
            stage: "upgrade-success".to_string(),
            error: "SCRIPT_ERR_OK".to_string(),
        };
    }
    match script::evaluate(
        script_bytes,
        &[],
        |_, _, _| Err("unsupported signature in commitment-only case".to_string()),
        |_, _, _| Err("unsupported data signature in commitment-only case".to_string()),
    ) {
        Ok(()) => Expected {
            accepted: true,
            stage: "script-complete".to_string(),
            error: "SCRIPT_ERR_OK".to_string(),
        },
        Err(error) => Expected {
            accepted: false,
            stage: "script-execution".to_string(),
            error,
        },
    }
}

pub fn evaluate_commitment(case: &Value) -> Result<Observation, String> {
    let case = object(case, "commitment case")?;
    let id = string(case, "id", "commitment case")?;
    let script_bytes = decode_hex(
        string(case, "leaf_script", id)?,
        &format!("{id}.leaf_script"),
    )?;
    let control = decode_hex(
        string(case, "control_block", id)?,
        &format!("{id}.control_block"),
    )?;
    let program = decode_32(
        string(case, "merkle_root", id)?,
        &format!("{id}.merkle_root"),
    )?;
    let declared_version: u8 = unsigned(case, "leaf_version", id)?
        .try_into()
        .map_err(|_| format!("{id}: leaf_version exceeds one byte"))?;
    if !control.is_empty() && control[0] & 0xfe != declared_version {
        return Err(format!("{id}: leaf_version does not match control block"));
    }
    if let Some(script_pubkey) = case.get("scriptPubKey").and_then(Value::as_str) {
        let script_pubkey = decode_hex(script_pubkey, &format!("{id}.scriptPubKey"))?;
        if program_from_script_pubkey(&script_pubkey, id)? != program {
            return Err(format!("{id}: scriptPubKey does not contain merkle_root"));
        }
    }
    for (field, hrp) in [("mainnet_address", "qb"), ("regtest_address", "qbrt")] {
        if let Some(declared) = case.get(field).and_then(Value::as_str) {
            if witness_v2_address(hrp, &program) != declared {
                return Err(format!("{id}: {field} mismatch"));
            }
        }
    }
    if let Some(declared) = case.get("leaf_preimage").and_then(Value::as_str) {
        let mut preimage = vec![declared_version];
        compact_size(script_bytes.len() as u64, &mut preimage);
        preimage.extend_from_slice(&script_bytes);
        if hex::encode(preimage) != declared {
            return Err(format!("{id}: leaf preimage mismatch"));
        }
    }
    if let Some(declared) = case.get("leaf_hash").and_then(Value::as_str) {
        if hex::encode(leaf_hash(declared_version, &script_bytes, "P2MRLeaf")) != declared {
            return Err(format!("{id}: leaf hash mismatch"));
        }
    }
    if let Some(siblings_value) = case.get("siblings") {
        let siblings = siblings_value
            .as_array()
            .ok_or_else(|| format!("{id}: siblings must be an array"))?;
        if control.len() != 1 + siblings.len() * 32 {
            return Err(format!("{id}: sibling count does not match control path"));
        }
        let declared_preimages = case
            .get("branch_preimages")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{id}: branch_preimages must be an array"))?;
        if declared_preimages.len() != siblings.len() {
            return Err(format!("{id}: branch preimage count mismatch"));
        }
        let mut running = leaf_hash(declared_version, &script_bytes, "P2MRLeaf");
        for (index, sibling) in siblings.iter().enumerate() {
            let sibling = decode_32(
                sibling
                    .as_str()
                    .ok_or_else(|| format!("{id}: sibling is not hex"))?,
                &format!("{id}.siblings[{index}]"),
            )?;
            if sibling != control[1 + index * 32..1 + (index + 1) * 32] {
                return Err(format!("{id}: sibling does not match control path"));
            }
            let preimage = branch_preimage(&running, &sibling);
            let declared = decode_hex(
                declared_preimages[index]
                    .as_str()
                    .ok_or_else(|| format!("{id}: branch preimage is not hex"))?,
                &format!("{id}.branch_preimages[{index}]"),
            )?;
            if declared != preimage {
                return Err(format!("{id}: branch preimage {index} mismatch"));
            }
            running = tagged_hash("P2MRBranch", &preimage);
        }
        if running != program {
            return Err(format!("{id}: branch preimages do not produce merkle_root"));
        }
    }
    if let Some(wrong_preimage) = case.get("wrong_leaf_preimage").and_then(Value::as_str) {
        let wrong_preimage = decode_hex(wrong_preimage, &format!("{id}.wrong_leaf_preimage"))?;
        let wrong_hash = tagged_hash("P2MRLeaf", &wrong_preimage);
        if wrong_hash != decode_32(string(case, "wrong_leaf_hash", id)?, id)?
            || wrong_hash != program
        {
            return Err(format!("{id}: wrong leaf preimage/hash/root mismatch"));
        }
        let mut canonical = vec![declared_version];
        compact_size(script_bytes.len() as u64, &mut canonical);
        canonical.extend_from_slice(&script_bytes);
        if wrong_preimage == canonical {
            return Err(format!("{id}: wrong leaf preimage is canonical"));
        }
    }
    if let Some(wrong_preimage) = case.get("wrong_branch_preimage").and_then(Value::as_str) {
        let wrong_preimage = decode_hex(wrong_preimage, &format!("{id}.wrong_branch_preimage"))?;
        if wrong_preimage.len() != 64 {
            return Err(format!("{id}: wrong branch preimage must be 64 bytes"));
        }
        let wrong_root = tagged_hash("P2MRBranch", &wrong_preimage);
        if wrong_root != decode_32(string(case, "wrong_merkle_root", id)?, id)?
            || wrong_root != program
        {
            return Err(format!("{id}: wrong branch preimage/root mismatch"));
        }
        if wrong_preimage[..32] <= wrong_preimage[32..] {
            return Err(format!(
                "{id}: wrong branch preimage is lexicographically sorted"
            ));
        }
    }
    let declared_expected = expected(
        case.get("expected")
            .ok_or_else(|| format!("{id}: missing expected"))?,
        id,
    )?;
    if let Some(expected_error) = case.get("expected_error").and_then(Value::as_str) {
        if expected_error != declared_expected.error {
            return Err(format!("{id}: expected_error differs from expected.error"));
        }
    }
    checked_observation(
        id,
        "commitment",
        commitment_outcome(&control, &script_bytes, &program),
        declared_expected,
    )
}

fn parse_spent_outputs(case: &Map<String, Value>, id: &str) -> Result<Vec<SpentOutput>, String> {
    let values = case
        .get("spentOutputs")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{id}: spentOutputs must be an array"))?;
    if values.len() > 100_000 {
        return Err(format!("{id}: too many spent outputs"));
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let output = object(value, &format!("{id}.spentOutputs[{index}]"))?;
            Ok(SpentOutput {
                value: output
                    .get("amount")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| format!("{id}: missing spent output amount"))?,
                script_pubkey: decode_hex(
                    string(output, "scriptPubKey", id)?,
                    &format!("{id}.spentOutputs[{index}].scriptPubKey"),
                )?,
            })
        })
        .collect()
}

fn p2mr_sigmsg(
    tx: &Transaction,
    spent_outputs: &[SpentOutput],
    input_index: usize,
    hash_type: u8,
    annex_hash: Option<[u8; 32]>,
    leaf: &[u8; 32],
    codesep: u32,
) -> Result<Option<Vec<u8>>, String> {
    if tx.inputs.len() != spent_outputs.len() || input_index >= tx.inputs.len() {
        return Err("spent output/input mismatch".to_string());
    }
    if !matches!(hash_type, 0x00 | 0x01 | 0x02 | 0x03 | 0x81 | 0x82 | 0x83) {
        return Err("SCRIPT_ERR_P2MR_SIG_HASHTYPE".to_string());
    }
    let output_type = if hash_type == 0 { 1 } else { hash_type & 3 };
    let anyone_can_pay = hash_type & 0x80 != 0;
    if output_type == 3 && input_index >= tx.outputs.len() {
        return Ok(None);
    }
    let mut message = vec![0, hash_type];
    message.extend_from_slice(&tx.version.to_le_bytes());
    message.extend_from_slice(&tx.lock_time.to_le_bytes());
    if !anyone_can_pay {
        let mut prevouts = Vec::new();
        let mut amounts = Vec::new();
        let mut scripts = Vec::new();
        let mut sequences = Vec::new();
        for (input, spent) in tx.inputs.iter().zip(spent_outputs) {
            prevouts.extend_from_slice(&input.previous_txid);
            prevouts.extend_from_slice(&input.previous_vout.to_le_bytes());
            amounts.extend_from_slice(&spent.value.to_le_bytes());
            scripts.extend_from_slice(&serialized_bytes(&spent.script_pubkey));
            sequences.extend_from_slice(&input.sequence.to_le_bytes());
        }
        message.extend_from_slice(&sha256(&prevouts));
        message.extend_from_slice(&sha256(&amounts));
        message.extend_from_slice(&sha256(&scripts));
        message.extend_from_slice(&sha256(&sequences));
    }
    if output_type == 1 {
        let mut outputs = Vec::new();
        for output in &tx.outputs {
            output.serialize_into(&mut outputs);
        }
        message.extend_from_slice(&sha256(&outputs));
    }
    message.push(2 + u8::from(annex_hash.is_some()));
    if anyone_can_pay {
        let input = &tx.inputs[input_index];
        let spent = &spent_outputs[input_index];
        message.extend_from_slice(&input.previous_txid);
        message.extend_from_slice(&input.previous_vout.to_le_bytes());
        TxOut {
            value: spent.value,
            script_pubkey: spent.script_pubkey.clone(),
        }
        .serialize_into(&mut message);
        message.extend_from_slice(&input.sequence.to_le_bytes());
    } else {
        message.extend_from_slice(&(input_index as u32).to_le_bytes());
    }
    if let Some(hash) = annex_hash {
        message.extend_from_slice(&hash);
    }
    if output_type == 3 {
        let mut output = Vec::new();
        tx.outputs[input_index].serialize_into(&mut output);
        message.extend_from_slice(&sha256(&output));
    }
    message.extend_from_slice(leaf);
    message.push(0);
    message.extend_from_slice(&codesep.to_le_bytes());
    Ok(Some(message))
}

fn parse_signature(signature: &[u8], hash_type: u8) -> Result<&[u8], String> {
    if hash_type == 0 {
        if signature.len() != PQC_SIGNATURE_SIZE {
            return Err("SCRIPT_ERR_P2MR_SIG_SIZE".to_string());
        }
        Ok(signature)
    } else {
        if signature.len() != PQC_SIGNATURE_SIZE + 1 {
            return Err("SCRIPT_ERR_P2MR_SIG_SIZE".to_string());
        }
        if signature[PQC_SIGNATURE_SIZE] != hash_type {
            return Err("SCRIPT_ERR_P2MR_SIG_HASHTYPE".to_string());
        }
        Ok(&signature[..PQC_SIGNATURE_SIZE])
    }
}

fn primitive_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String> {
    if pubkey.len() != PQC_PUBLIC_KEY_SIZE {
        return Err("SCRIPT_ERR_PUBKEYTYPE".to_string());
    }
    if signature.len() != PQC_SIGNATURE_SIZE {
        return Err("SCRIPT_ERR_P2MR_SIG_SIZE".to_string());
    }
    let pubkey = PublicKey::try_from_slice(pubkey).map_err(|_| "SCRIPT_ERR_PUBKEYTYPE")?;
    let signature = Signature::try_from_slice(signature).map_err(|_| "SCRIPT_ERR_P2MR_SIG_SIZE")?;
    Ok(bitcoinpqc::verify(&pubkey, message, &signature).is_ok())
}

fn check_p2mr_signature(
    pubkey: &[u8],
    message: &[u8],
    signature: &[u8],
    hash_type: u8,
) -> Result<bool, String> {
    if signature.is_empty() {
        return Ok(false);
    }
    if primitive_verify(pubkey, message, parse_signature(signature, hash_type)?)? {
        Ok(true)
    } else {
        Err("SCRIPT_ERR_P2MR_SIG".to_string())
    }
}

fn witness_serialized_size(witness: &[Vec<u8>]) -> usize {
    let mut encoded = Vec::new();
    compact_size(witness.len() as u64, &mut encoded);
    for item in witness {
        compact_size(item.len() as u64, &mut encoded);
        encoded.extend_from_slice(item);
    }
    encoded.len()
}

struct ParsedWitness {
    stack: Vec<Vec<u8>>,
    script: Vec<u8>,
    control: Vec<u8>,
    annex: Option<Vec<u8>>,
}

fn split_witness(mut witness: Vec<Vec<u8>>) -> Result<ParsedWitness, String> {
    let annex = if witness.len() >= 2
        && witness
            .last()
            .is_some_and(|item| item.first() == Some(&0x50))
    {
        Some(witness.pop().unwrap())
    } else {
        None
    };
    if witness.len() < 2 {
        return Err("insufficient witness after annex".to_string());
    }
    let control = witness.pop().unwrap();
    let script = witness.pop().unwrap();
    Ok(ParsedWitness {
        stack: witness,
        script,
        control,
        annex,
    })
}

fn declared_byte(case: &Map<String, Value>, field: &str, id: &str) -> Result<u8, String> {
    let bytes = decode_hex(string(case, field, id)?, &format!("{id}.{field}"))?;
    if bytes.len() != 1 {
        return Err(format!("{id}: {field} must be one byte"));
    }
    Ok(bytes[0])
}

fn validate_sigmsg_metadata(
    case: &Map<String, Value>,
    id: &str,
    control: &[u8],
    annex_present: bool,
    hash_type: u8,
    message: &[u8],
) -> Result<(), String> {
    let epoch = declared_byte(case, "epoch", id)?;
    let spend_type = declared_byte(case, "spendType", id)?;
    let key_version = declared_byte(case, "keyVersion", id)?;
    let leaf_version = declared_byte(case, "leafVersion", id)?;
    if epoch != 0 || message.first() != Some(&epoch) {
        return Err(format!("{id}: epoch mismatch"));
    }
    if message.get(1) != Some(&hash_type) {
        return Err(format!("{id}: hashType does not match signature message"));
    }
    if spend_type != 2 + u8::from(annex_present) {
        return Err(format!("{id}: spendType mismatch"));
    }
    if key_version != 0 || message.get(message.len().saturating_sub(5)) != Some(&key_version) {
        return Err(format!("{id}: keyVersion mismatch"));
    }
    if control.is_empty() || leaf_version != control[0] & 0xfe {
        return Err(format!("{id}: leafVersion mismatch"));
    }
    Ok(())
}

fn validate_leaf_commitment_pair(
    case: &Map<String, Value>,
    id: &str,
    leaf_field: &str,
    output_field: &str,
    control: &[u8],
) -> Result<(), String> {
    let Some(leaf_hex) = case.get(leaf_field).and_then(Value::as_str) else {
        if case.contains_key(output_field) {
            return Err(format!("{id}: {output_field} has no {leaf_field}"));
        }
        return Ok(());
    };
    let leaf = decode_hex(leaf_hex, &format!("{id}.{leaf_field}"))?;
    let output = decode_hex(
        string(case, output_field, id)?,
        &format!("{id}.{output_field}"),
    )?;
    let program = program_from_script_pubkey(&output, id)?;
    if root_from_control(control, &leaf, "P2MRLeaf", "P2MRBranch")? != program {
        return Err(format!("{id}: {leaf_field} commitment mismatch"));
    }
    Ok(())
}

fn validate_checksigadd_fixture(case: &Map<String, Value>, id: &str) -> Result<(), String> {
    let Some(value) = case.get("checkSigAdd") else {
        return Ok(());
    };
    let fixture = object(value, &format!("{id}.checkSigAdd"))?;
    let tx = Transaction::parse(&decode_hex(string(fixture, "spendTx", id)?, id)?)
        .map_err(|error| format!("{id}.checkSigAdd: {error}"))?;
    let input_index: usize = unsigned(fixture, "inputIndex", id)?
        .try_into()
        .map_err(|_| format!("{id}.checkSigAdd: input index overflow"))?;
    if input_index >= tx.inputs.len() {
        return Err(format!("{id}.checkSigAdd: input index out of range"));
    }
    let spent_outputs = parse_spent_outputs(fixture, &format!("{id}.checkSigAdd"))?;
    if spent_outputs.len() != tx.inputs.len() {
        return Err(format!("{id}.checkSigAdd: spent output count mismatch"));
    }
    let parsed = split_witness(tx.inputs[input_index].witness.clone())
        .map_err(|error| format!("{id}.checkSigAdd: {error}"))?;
    if parsed.annex.is_some() || parsed.stack.len() != 1 {
        return Err(format!("{id}.checkSigAdd: unexpected witness shape"));
    }
    let leaf = decode_hex(string(fixture, "leafScript", id)?, id)?;
    let control = decode_hex(string(fixture, "controlBlock", id)?, id)?;
    let signature = decode_hex(string(fixture, "signature", id)?, id)?;
    let pubkey = decode_hex(string(fixture, "pubkey", id)?, id)?;
    if parsed.script != leaf || parsed.control != control || parsed.stack[0] != signature {
        return Err(format!(
            "{id}.checkSigAdd: declared witness fields mismatch"
        ));
    }
    let mut expected_leaf = vec![0x00, PQC_PUBLIC_KEY_SIZE as u8];
    expected_leaf.extend_from_slice(&pubkey);
    expected_leaf.extend_from_slice(&[0xba, 0x51, 0x9c]);
    if leaf != expected_leaf {
        return Err(format!("{id}.checkSigAdd: leaf serialization mismatch"));
    }
    let leaf_version = declared_byte(fixture, "leafVersion", id)?;
    if control.first().map(|byte| byte & 0xfe) != Some(leaf_version) {
        return Err(format!("{id}.checkSigAdd: leaf version mismatch"));
    }
    let leaf_hash_value = leaf_hash(leaf_version, &leaf, "P2MRLeaf");
    if leaf_hash_value != decode_32(string(fixture, "leafHash", id)?, id)? {
        return Err(format!("{id}.checkSigAdd: leaf hash mismatch"));
    }
    let program =
        program_from_script_pubkey(&decode_hex(string(fixture, "scriptPubKey", id)?, id)?, id)?;
    if root_from_control(&control, &leaf, "P2MRLeaf", "P2MRBranch")? != program
        || program_from_script_pubkey(&spent_outputs[input_index].script_pubkey, id)? != program
    {
        return Err(format!("{id}.checkSigAdd: commitment mismatch"));
    }
    let message = p2mr_sigmsg(
        &tx,
        &spent_outputs,
        input_index,
        0,
        None,
        &leaf_hash_value,
        u32::MAX,
    )?
    .ok_or_else(|| format!("{id}.checkSigAdd: missing signature message"))?;
    if message != decode_hex(string(fixture, "p2mrSigMsg", id)?, id)? {
        return Err(format!("{id}.checkSigAdd: signature message mismatch"));
    }
    let digest = tagged_hash("P2MRSighash", &message);
    if digest != decode_32(string(fixture, "p2mrSighash", id)?, id)? {
        return Err(format!("{id}.checkSigAdd: signature digest mismatch"));
    }
    let mut signature_checks = 0usize;
    let mut validation_weight =
        witness_serialized_size(&tx.inputs[input_index].witness) as i64 + VALIDATION_WEIGHT_OFFSET;
    script::evaluate(
        &leaf,
        &parsed.stack,
        |executed_signature, executed_pubkey, codesep| {
            signature_checks += 1;
            if codesep != u32::MAX {
                return Err(format!("{id}.checkSigAdd: unexpected code separator"));
            }
            if executed_signature != signature || executed_pubkey != pubkey {
                return Err(format!("{id}.checkSigAdd: executed stack mismatch"));
            }
            if executed_pubkey.len() != PQC_PUBLIC_KEY_SIZE {
                return Err("SCRIPT_ERR_PUBKEYTYPE".to_string());
            }
            if executed_signature.is_empty() {
                return Ok(false);
            }
            validation_weight -= VALIDATION_WEIGHT_PER_PQC;
            if validation_weight < 0 {
                return Err("SCRIPT_ERR_P2MR_VALIDATION_WEIGHT".to_string());
            }
            check_p2mr_signature(executed_pubkey, &digest, executed_signature, 0)
        },
        |_, _, _| Err(format!("{id}.checkSigAdd: unexpected data signature")),
    )
    .map_err(|error| format!("{id}.checkSigAdd: {error}"))?;
    if signature_checks != 1 {
        return Err(format!(
            "{id}.checkSigAdd: expected exactly one executed signature check"
        ));
    }
    let expected_result = expected(
        fixture
            .get("expected")
            .ok_or_else(|| format!("{id}.checkSigAdd: missing expected"))?,
        id,
    )?;
    if !expected_result.accepted
        || expected_result.stage != "script-complete"
        || expected_result.error != "SCRIPT_ERR_OK"
    {
        return Err(format!("{id}.checkSigAdd: expected result mismatch"));
    }
    Ok(())
}

fn execute_data_signature_script(
    script_bytes: &[u8],
    initial_stack: &[Vec<u8>],
    control: &[u8],
) -> Result<usize, String> {
    let mut witness = initial_stack.to_vec();
    witness.push(script_bytes.to_vec());
    witness.push(control.to_vec());
    let mut validation_weight = witness_serialized_size(&witness) as i64 + VALIDATION_WEIGHT_OFFSET;
    let mut signature_checks = 0usize;
    script::evaluate(
        script_bytes,
        initial_stack,
        |_, _, _| Err("unexpected transaction signature opcode".to_string()),
        |signature, message_hash, pubkey| {
            signature_checks += 1;
            if !signature.is_empty() {
                validation_weight -= VALIDATION_WEIGHT_PER_PQC;
                if validation_weight < 0 {
                    return Err("SCRIPT_ERR_P2MR_VALIDATION_WEIGHT".to_string());
                }
            }
            if pubkey.len() != PQC_PUBLIC_KEY_SIZE {
                return Err("SCRIPT_ERR_PUBKEYTYPE".to_string());
            }
            if message_hash.len() != 32 {
                return Err("SCRIPT_ERR_PUSH_SIZE".to_string());
            }
            if signature.is_empty() {
                return Ok(false);
            }
            if signature.len() != PQC_SIGNATURE_SIZE {
                return Err("SCRIPT_ERR_P2MR_SIG_SIZE".to_string());
            }
            let digest = tagged_hash("QbitDataSigPQC", message_hash);
            if primitive_verify(pubkey, &digest, signature)? {
                Ok(true)
            } else {
                Err("SCRIPT_ERR_P2MR_SIG".to_string())
            }
        },
    )?;
    Ok(signature_checks)
}

fn validate_ancillary_data_signatures(case: &Map<String, Value>, id: &str) -> Result<(), String> {
    let Some(message_hex) = case.get("dataSigMessageHash").and_then(Value::as_str) else {
        return Ok(());
    };
    let message = decode_32(message_hex, &format!("{id}.dataSigMessageHash"))?;
    let digest = tagged_hash("QbitDataSigPQC", &message);
    if decode_32(
        string(case, "dataSigHash", id)?,
        &format!("{id}.dataSigHash"),
    )? != digest
    {
        return Err(format!("{id}: data signature tagged hash mismatch"));
    }
    let pubkey = decode_hex(
        string(case, "dataSigPubkey", id)?,
        &format!("{id}.dataSigPubkey"),
    )?;
    let signature = decode_hex(
        string(case, "dataSigSignature", id)?,
        &format!("{id}.dataSigSignature"),
    )?;
    if !primitive_verify(&pubkey, &digest, &signature)? {
        return Err(format!("{id}: data signature does not verify"));
    }
    let mut expected_leaf = vec![PQC_PUBLIC_KEY_SIZE as u8];
    expected_leaf.extend_from_slice(&pubkey);
    expected_leaf.push(0xbc); // OP_CHECKDATASIGPQC
    if expected_leaf != decode_hex(string(case, "dataSigLeafScript", id)?, id)? {
        return Err(format!("{id}: dataSigLeafScript serialization mismatch"));
    }
    let control = decode_hex(string(case, "dataSigControlBlock", id)?, id)?;
    if execute_data_signature_script(
        &expected_leaf,
        &[signature.clone(), message.to_vec()],
        &control,
    )? != 1
    {
        return Err(format!("{id}: dataSig did not execute exactly one check"));
    }
    let mut wrong_pubkey = pubkey.clone();
    wrong_pubkey[0] ^= 1;
    let mut expected_wrong_leaf = vec![PQC_PUBLIC_KEY_SIZE as u8];
    expected_wrong_leaf.extend_from_slice(&wrong_pubkey);
    expected_wrong_leaf.push(0xbc);
    if expected_wrong_leaf != decode_hex(string(case, "dataSigWrongPubkeyLeafScript", id)?, id)? {
        return Err(format!(
            "{id}: dataSigWrongPubkeyLeafScript serialization mismatch"
        ));
    }
    let wrong_pubkey_error = execute_data_signature_script(
        &expected_wrong_leaf,
        &[signature.clone(), message.to_vec()],
        &control,
    )
    .unwrap_err();
    if wrong_pubkey_error != "SCRIPT_ERR_P2MR_SIG" {
        return Err(format!("{id}: wrong data-signature pubkey error mismatch"));
    }
    let raw_signature = decode_hex(
        string(case, "dataSigRawMessageSignature", id)?,
        &format!("{id}.dataSigRawMessageSignature"),
    )?;
    if !primitive_verify(&pubkey, &message, &raw_signature)?
        || primitive_verify(&pubkey, &digest, &raw_signature)?
    {
        return Err(format!("{id}: raw-message domain separation mismatch"));
    }
    let raw_domain_error = execute_data_signature_script(
        &expected_leaf,
        &[raw_signature.clone(), message.to_vec()],
        &control,
    )
    .unwrap_err();
    if raw_domain_error != "SCRIPT_ERR_P2MR_SIG" {
        return Err(format!("{id}: raw-message execution error mismatch"));
    }
    for (leaf_field, output_field) in [
        ("dataSigLeafScript", "dataSigScriptPubKey"),
        (
            "dataSigWrongPubkeyLeafScript",
            "dataSigWrongPubkeyScriptPubKey",
        ),
    ] {
        let leaf = decode_hex(string(case, leaf_field, id)?, &format!("{id}.{leaf_field}"))?;
        let output = decode_hex(
            string(case, output_field, id)?,
            &format!("{id}.{output_field}"),
        )?;
        let program = program_from_script_pubkey(&output, id)?;
        if root_from_control(&control, &leaf, "P2MRLeaf", "P2MRBranch")? != program {
            return Err(format!("{id}: {leaf_field} commitment mismatch"));
        }
    }
    if let Some(add) = case.get("dataSigAdd") {
        let add = object(add, &format!("{id}.dataSigAdd"))?;
        let add_message = decode_32(string(add, "messageHash", id)?, id)?;
        let add_digest = tagged_hash("QbitDataSigPQC", &add_message);
        if decode_32(string(add, "dataSigHash", id)?, id)? != add_digest {
            return Err(format!("{id}: dataSigAdd tagged hash mismatch"));
        }
        let mut pubkeys = Vec::new();
        let mut signatures = Vec::new();
        for suffix in ["A", "B", "C"] {
            let pubkey = decode_hex(string(add, &format!("pubkey{suffix}"), id)?, id)?;
            let signature = decode_hex(string(add, &format!("signature{suffix}"), id)?, id)?;
            if !primitive_verify(&pubkey, &add_digest, &signature)? {
                return Err(format!(
                    "{id}: dataSigAdd signature {suffix} does not verify"
                ));
            }
            pubkeys.push(pubkey);
            signatures.push(signature);
        }
        let pubkey_a = decode_hex(string(add, "pubkeyA", id)?, id)?;
        let raw_a = decode_hex(string(add, "rawMessageSignatureA", id)?, id)?;
        if !primitive_verify(&pubkey_a, &add_message, &raw_a)?
            || primitive_verify(&pubkey_a, &add_digest, &raw_a)?
        {
            return Err(format!("{id}: dataSigAdd raw signature does not verify"));
        }
        let build_add_script = |message: &[u8; 32], keys: &[Vec<u8>], threshold: u8| {
            let mut script = Vec::new();
            for (index, key) in keys.iter().enumerate() {
                script.push(32);
                script.extend_from_slice(message);
                script.push(if index == 0 { 0x00 } else { 0x7c });
                script.push(32);
                script.extend_from_slice(key);
                script.push(0xbd); // OP_CHECKDATASIGADDPQC
            }
            script.push(0x50 + threshold);
            script.push(0x9c); // OP_NUMEQUAL
            script
        };
        let n_of_n = build_add_script(&add_message, &pubkeys[..2], 2);
        let m_of_n = build_add_script(&add_message, &pubkeys, 2);
        let wrong_message = decode_32(string(add, "wrongMessageHash", id)?, id)?;
        let wrong_message_script = build_add_script(&wrong_message, &pubkeys[..2], 2);
        let mut wrong_keys = pubkeys[..2].to_vec();
        wrong_keys[0][0] ^= 1;
        let wrong_pubkey_script = build_add_script(&add_message, &wrong_keys, 2);
        for (field, expected_script) in [
            ("nOfNLeafScript", &n_of_n),
            ("mOfNLeafScript", &m_of_n),
            ("wrongMessageHashLeafScript", &wrong_message_script),
            ("wrongPubkeyLeafScript", &wrong_pubkey_script),
        ] {
            if decode_hex(string(add, field, id)?, id)? != *expected_script {
                return Err(format!("{id}: dataSigAdd {field} serialization mismatch"));
            }
        }
        for (leaf_field, output_field) in [
            ("nOfNLeafScript", "nOfNScriptPubKey"),
            ("mOfNLeafScript", "mOfNScriptPubKey"),
            ("wrongMessageHashLeafScript", "wrongMessageHashScriptPubKey"),
            ("wrongPubkeyLeafScript", "wrongPubkeyScriptPubKey"),
        ] {
            let leaf = decode_hex(string(add, leaf_field, id)?, id)?;
            let output = decode_hex(string(add, output_field, id)?, id)?;
            let program = program_from_script_pubkey(&output, id)?;
            let control = decode_hex(string(add, "controlBlock", id)?, id)?;
            if root_from_control(&control, &leaf, "P2MRLeaf", "P2MRBranch")? != program {
                return Err(format!("{id}: dataSigAdd {leaf_field} commitment mismatch"));
            }
        }
        let control = decode_hex(string(add, "controlBlock", id)?, id)?;
        if execute_data_signature_script(
            &n_of_n,
            &[signatures[1].clone(), signatures[0].clone()],
            &control,
        )? != 2
        {
            return Err(format!("{id}: dataSigAdd n-of-n execution mismatch"));
        }
        if execute_data_signature_script(
            &m_of_n,
            &[signatures[2].clone(), Vec::new(), signatures[0].clone()],
            &control,
        )? != 3
        {
            return Err(format!("{id}: dataSigAdd m-of-n execution mismatch"));
        }
        for (name, script_bytes) in [
            ("wrong message", &wrong_message_script),
            ("wrong pubkey", &wrong_pubkey_script),
        ] {
            let error = execute_data_signature_script(
                script_bytes,
                &[signatures[1].clone(), signatures[0].clone()],
                &control,
            )
            .unwrap_err();
            if error != "SCRIPT_ERR_P2MR_SIG" {
                return Err(format!("{id}: dataSigAdd {name} execution mismatch"));
            }
        }
    }
    Ok(())
}

pub fn evaluate_witness(case: &Value) -> Result<Observation, String> {
    let case = object(case, "witness case")?;
    let id = string(case, "id", "witness case")?;
    let tx_bytes = decode_hex(string(case, "spendTx", id)?, &format!("{id}.spendTx"))?;
    let tx = Transaction::parse(&tx_bytes).map_err(|error| format!("{id}: {error}"))?;
    let input_index = unsigned(case, "inputIndex", id)? as usize;
    if input_index >= tx.inputs.len() {
        return Err(format!("{id}: inputIndex out of range"));
    }
    let declared_witness = case
        .get("witness")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{id}: witness must be an array"))?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            decode_hex(
                value
                    .as_str()
                    .ok_or_else(|| format!("{id}: witness item is not hex"))?,
                &format!("{id}.witness[{index}]"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    if tx.inputs[input_index].witness != declared_witness {
        return Err(format!(
            "{id}: separately declared witness differs from transaction"
        ));
    }
    let parsed =
        split_witness(declared_witness.clone()).map_err(|error| format!("{id}: {error}"))?;
    let spend_stack = parsed.stack;
    let script_bytes = parsed.script;
    let control = parsed.control;
    let annex = parsed.annex;
    let declared_annex = string(case, "annex", id)?;
    match (&annex, declared_annex) {
        (None, "none") => {}
        (Some(actual), declared) if actual == &decode_hex(declared, &format!("{id}.annex"))? => {}
        _ => return Err(format!("{id}: annex mismatch")),
    }
    if control != decode_hex(string(case, "controlBlock", id)?, id)?
        || script_bytes != decode_hex(string(case, "leafScript", id)?, id)?
    {
        return Err(format!("{id}: witness script/control mismatch"));
    }
    let spent_outputs = parse_spent_outputs(case, id)?;
    if spent_outputs.len() != tx.inputs.len() {
        return Err(format!("{id}: spent output count mismatch"));
    }
    let selected = &spent_outputs[input_index];
    if selected.value
        != case
            .get("prevoutAmount")
            .and_then(Value::as_i64)
            .ok_or_else(|| format!("{id}: missing prevoutAmount"))?
        || selected.script_pubkey != decode_hex(string(case, "prevoutScriptPubKey", id)?, id)?
    {
        return Err(format!("{id}: selected prevout fields mismatch"));
    }
    let program = program_from_script_pubkey(&selected.script_pubkey, id)?;
    let root = root_from_control(&control, &script_bytes, "P2MRLeaf", "P2MRBranch")?;
    if root != program {
        return Err(format!("{id}: P2MR commitment mismatch"));
    }
    let leaf = leaf_hash(control[0] & 0xfe, &script_bytes, "P2MRLeaf");
    if leaf != decode_32(string(case, "leafHash", id)?, id)? {
        return Err(format!("{id}: leafHash mismatch"));
    }
    let hash_type_bytes = decode_hex(string(case, "hashType", id)?, id)?;
    if hash_type_bytes.len() != 1 {
        return Err(format!("{id}: hashType must be one byte"));
    }
    let hash_type = hash_type_bytes[0];
    let signature_field = decode_hex(string(case, "signature", id)?, id)?;
    if spend_stack.first() != Some(&signature_field) {
        return Err(format!(
            "{id}: signature field differs from initial witness item"
        ));
    }
    let declared_codesep_bytes = decode_hex(string(case, "codeSeparatorPosition", id)?, id)?;
    if declared_codesep_bytes.len() != 4 {
        return Err(format!("{id}: code separator position must be four bytes"));
    }
    let declared_codesep = u32::from_le_bytes(declared_codesep_bytes.try_into().unwrap());
    let annex_hash = annex.as_ref().map(|annex| sha256(&serialized_bytes(annex)));
    if let Some(declared) = case.get("annexHash").and_then(Value::as_str) {
        if annex_hash != Some(decode_32(declared, id)?) {
            return Err(format!("{id}: annex hash mismatch"));
        }
    }
    let digest_defined = case
        .get("digest_defined")
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{id}: missing digest_defined"))?;
    let declared_expected = expected(
        case.get("expected")
            .ok_or_else(|| format!("{id}: missing expected"))?,
        id,
    )?;
    if let Some(expected_error) = case.get("expectedError").and_then(Value::as_str) {
        if format!("SCRIPT_ERR_{expected_error}") != declared_expected.error {
            return Err(format!("{id}: expectedError differs from expected.error"));
        }
    }

    let computed_message = p2mr_sigmsg(
        &tx,
        &spent_outputs,
        input_index,
        hash_type,
        annex_hash,
        &leaf,
        declared_codesep,
    )?;
    if computed_message.is_none() {
        if digest_defined || case.contains_key("p2mrSigMsg") || case.contains_key("p2mrSighash") {
            return Err(format!(
                "{id}: missing-output SIGHASH_SINGLE defines a digest"
            ));
        }
        let observed = Expected {
            accepted: false,
            stage: "sighash".to_string(),
            error: "SCRIPT_ERR_P2MR_SIG_HASHTYPE".to_string(),
        };
        return checked_observation(id, "witness", observed, declared_expected);
    }
    if !digest_defined {
        return Err(format!("{id}: digest unexpectedly marked undefined"));
    }
    let computed_message = computed_message.unwrap();
    validate_sigmsg_metadata(
        case,
        id,
        &control,
        annex.is_some(),
        hash_type,
        &computed_message,
    )?;
    if computed_message != decode_hex(string(case, "p2mrSigMsg", id)?, id)? {
        return Err(format!("{id}: serialized P2MR signature message mismatch"));
    }
    let computed_digest = tagged_hash("P2MRSighash", &computed_message);
    if computed_digest != decode_32(string(case, "p2mrSighash", id)?, id)? {
        return Err(format!("{id}: P2MRSighash mismatch"));
    }
    let wrong_domain_digest = tagged_hash("TapSighash", &computed_message);
    if let Some(wrong_domain) = case.get("wrongDomainSighash").and_then(Value::as_str) {
        if wrong_domain_digest != decode_32(wrong_domain, id)? {
            return Err(format!("{id}: TapSighash comparison mismatch"));
        }
    }
    let declared_pubkey = decode_hex(string(case, "pubkey", id)?, id)?;
    let mut validation_weight =
        witness_serialized_size(&declared_witness) as i64 + VALIDATION_WEIGHT_OFFSET;
    let mut signature_checks = 0usize;
    script::evaluate(
        &script_bytes,
        &spend_stack,
        |signature, pubkey, codesep| {
            signature_checks += 1;
            if codesep != declared_codesep {
                return Err(format!("{id}: executed code separator position mismatch"));
            }
            if pubkey != declared_pubkey {
                return Err(format!("{id}: executed pubkey mismatch"));
            }
            if pubkey.len() != PQC_PUBLIC_KEY_SIZE {
                return Err("SCRIPT_ERR_PUBKEYTYPE".to_string());
            }
            if signature.is_empty() {
                return Ok(false);
            }
            validation_weight -= VALIDATION_WEIGHT_PER_PQC;
            if validation_weight < 0 {
                return Err("SCRIPT_ERR_P2MR_VALIDATION_WEIGHT".to_string());
            }
            let message = p2mr_sigmsg(
                &tx,
                &spent_outputs,
                input_index,
                hash_type,
                annex_hash,
                &leaf,
                codesep,
            )?
            .ok_or("SCRIPT_ERR_P2MR_SIG_HASHTYPE")?;
            if message != computed_message {
                return Err(format!("{id}: executed signature message mismatch"));
            }
            check_p2mr_signature(pubkey, &computed_digest, signature, hash_type)
        },
        |_, _, _| Err(format!("{id}: unexpected data signature opcode")),
    )
    .map_err(|error| format!("{id}: {error}"))?;
    if signature_checks != 1 {
        return Err(format!(
            "{id}: expected exactly one executed signature check"
        ));
    }
    validate_leaf_commitment_pair(
        case,
        id,
        "wrongPubkeyLeafScript",
        "wrongPubkeyScriptPubKey",
        &control,
    )?;
    validate_checksigadd_fixture(case, id)?;
    if let Some(signature) = case.get("wrongDomainSignature").and_then(Value::as_str) {
        let signature = decode_hex(signature, &format!("{id}.wrongDomainSignature"))?;
        let raw = parse_signature(&signature, hash_type)?;
        if !primitive_verify(&declared_pubkey, &wrong_domain_digest, raw)?
            || primitive_verify(&declared_pubkey, &computed_digest, raw)?
        {
            return Err(format!("{id}: wrong-domain signature comparison mismatch"));
        }
    }
    if let Some(wrong_codesep_hex) = case
        .get("wrongCodeSeparatorPosition")
        .and_then(Value::as_str)
    {
        let wrong_codesep_bytes = decode_hex(
            wrong_codesep_hex,
            &format!("{id}.wrongCodeSeparatorPosition"),
        )?;
        if wrong_codesep_bytes.len() != 4 {
            return Err(format!(
                "{id}: wrongCodeSeparatorPosition must be four bytes"
            ));
        }
        let wrong_codesep = u32::from_le_bytes(wrong_codesep_bytes.try_into().unwrap());
        if wrong_codesep == declared_codesep {
            return Err(format!(
                "{id}: wrong code separator equals executed position"
            ));
        }
        let wrong_message = p2mr_sigmsg(
            &tx,
            &spent_outputs,
            input_index,
            hash_type,
            annex_hash,
            &leaf,
            wrong_codesep,
        )?
        .ok_or("SCRIPT_ERR_P2MR_SIG_HASHTYPE")?;
        if wrong_message != decode_hex(string(case, "wrongCodeseparatorSigMsg", id)?, id)? {
            return Err(format!("{id}: wrong-code-separator message mismatch"));
        }
        let wrong_digest = tagged_hash("P2MRSighash", &wrong_message);
        if wrong_digest != decode_32(string(case, "wrongCodeseparatorSighash", id)?, id)? {
            return Err(format!("{id}: wrong-code-separator digest mismatch"));
        }
        let signature = decode_hex(string(case, "wrongCodeseparatorSignature", id)?, id)?;
        let raw = parse_signature(&signature, hash_type)?;
        if !primitive_verify(&declared_pubkey, &wrong_digest, raw)?
            || primitive_verify(&declared_pubkey, &computed_digest, raw)?
        {
            return Err(format!("{id}: wrong-code-separator signature mismatch"));
        }
    }
    if let Some(no_annex_hex) = case.get("noAnnexSigMsg").and_then(Value::as_str) {
        if annex.is_none() {
            return Err(format!("{id}: no-annex comparison has no annex"));
        }
        let no_annex_message = p2mr_sigmsg(
            &tx,
            &spent_outputs,
            input_index,
            hash_type,
            None,
            &leaf,
            declared_codesep,
        )?
        .ok_or("SCRIPT_ERR_P2MR_SIG_HASHTYPE")?;
        if no_annex_message != decode_hex(no_annex_hex, id)? {
            return Err(format!("{id}: no-annex message mismatch"));
        }
        let no_annex_digest = tagged_hash("P2MRSighash", &no_annex_message);
        if no_annex_digest != decode_32(string(case, "noAnnexSighash", id)?, id)? {
            return Err(format!("{id}: no-annex digest mismatch"));
        }
        let signature = decode_hex(string(case, "noAnnexSignature", id)?, id)?;
        let raw = parse_signature(&signature, hash_type)?;
        if !primitive_verify(&declared_pubkey, &no_annex_digest, raw)?
            || primitive_verify(&declared_pubkey, &computed_digest, raw)?
        {
            return Err(format!("{id}: no-annex signature mismatch"));
        }
    }
    validate_ancillary_data_signatures(case, id)?;
    let observed = Expected {
        accepted: true,
        stage: "script-complete".to_string(),
        error: "SCRIPT_ERR_OK".to_string(),
    };
    checked_observation(id, "witness", observed, declared_expected)
}

pub fn evaluate_cross_profile(case: &Value) -> Result<Observation, String> {
    let case = object(case, "cross-profile case")?;
    let id = string(case, "id", "cross-profile case")?;
    let script_bytes = decode_hex(string(case, "leaf_script", id)?, id)?;
    let control = decode_hex(string(case, "control_block", id)?, id)?;
    if control.len() != 1 {
        return Err(format!("{id}: depth-zero case must have one-byte control"));
    }
    let tap_root = leaf_hash(control[0] & 0xfe, &script_bytes, "TapLeaf");
    let p2mr_root = leaf_hash(control[0] & 0xfe, &script_bytes, "P2MRLeaf");
    if tap_root != decode_32(string(case, "tapleaf_root", id)?, id)?
        || p2mr_root != decode_32(string(case, "p2mr_leaf_root", id)?, id)?
    {
        return Err(format!("{id}: cross-profile leaf hash mismatch"));
    }
    let script_pubkey = decode_hex(string(case, "scriptPubKey", id)?, id)?;
    let program = program_from_script_pubkey(&script_pubkey, id)?;
    let witness = case
        .get("witness")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{id}: witness must be an array"))?;
    if witness.len() != 2
        || decode_hex(
            witness[0]
                .as_str()
                .ok_or("cross witness script is not hex")?,
            id,
        )? != script_bytes
        || decode_hex(
            witness[1]
                .as_str()
                .ok_or("cross witness control is not hex")?,
            id,
        )? != control
    {
        return Err(format!("{id}: cross-profile witness mismatch"));
    }
    let expected_profiles = object(
        case.get("expected")
            .ok_or_else(|| format!("{id}: missing expected"))?,
        id,
    )?;
    let declared_qbit = expected(
        expected_profiles
            .get("qbit_p2mr_v1")
            .ok_or_else(|| format!("{id}: missing qbit expected result"))?,
        id,
    )?;
    let (other_key, other_value) = if let Some(value) = expected_profiles.get("pinned_bip_360") {
        ("pinned_bip_360", value)
    } else if let Some(value) = expected_profiles.get("bip_style_depth_zero_with_qbit_tags") {
        ("bip_style_depth_zero_with_qbit_tags", value)
    } else {
        return Err(format!("{id}: missing comparison expected result"));
    };
    let other = expected(other_value, id)?;
    let expected_other_root = if other_key == "pinned_bip_360" {
        tap_root
    } else {
        p2mr_root
    };
    if !other.accepted
        || other.stage != "depth-zero-shortcut"
        || other.error != "SCRIPT_ERR_OK"
        || program != expected_other_root
    {
        return Err(format!(
            "{id}: comparison depth-zero result is inconsistent"
        ));
    }
    let observed = commitment_outcome(&control, &script_bytes, &program);
    checked_observation(id, "cross_profile", observed, declared_qbit)
}

fn boundary_fixture<'a>(
    parameters: &Map<String, Value>,
    id: &str,
    witness_cases: &'a [Value],
    artifact: &str,
    extra_fields: &[&str],
) -> Result<&'a Map<String, Value>, String> {
    let mut fields = vec!["kind", "fixture_file", "fixture_id", "artifact"];
    fields.extend_from_slice(extra_fields);
    exact_object_keys(parameters, &fields, id)?;
    if string(parameters, "fixture_file", id)? != "src/test/data/p2mr_pqc_witness_vectors.json"
        || string(parameters, "artifact", id)? != artifact
    {
        return Err(format!("{id}: unsupported boundary fixture reference"));
    }
    let fixture_id = string(parameters, "fixture_id", id)?;
    let fixture = witness_cases
        .iter()
        .find(|case| case.get("id").and_then(Value::as_str) == Some(fixture_id))
        .ok_or_else(|| format!("{id}: boundary fixture id not found: {fixture_id}"))?;
    object(fixture, fixture_id)
}

fn default_ctv_hash() -> [u8; 32] {
    let sequences_hash = sha256(&u32::MAX.to_le_bytes());
    let mut serialized_output = 1000i64.to_le_bytes().to_vec();
    serialized_output.push(0); // Empty scriptPubKey CompactSize.
    let outputs_hash = sha256(&serialized_output);
    let mut message = Vec::new();
    message.extend_from_slice(&1i32.to_le_bytes());
    message.extend_from_slice(&0u32.to_le_bytes());
    message.extend_from_slice(&1u32.to_le_bytes());
    message.extend_from_slice(&sequences_hash);
    message.extend_from_slice(&1u32.to_le_bytes());
    message.extend_from_slice(&outputs_hash);
    message.extend_from_slice(&0u32.to_le_bytes());
    sha256(&message)
}

fn boundary_policy_pair(consensus: Expected) -> (Expected, Expected) {
    (consensus.clone(), consensus)
}

fn boundary_outcome(
    id: &str,
    scenario: &str,
    parameters: &Map<String, Value>,
    witness_cases: &[Value],
) -> Result<(Expected, Expected), String> {
    match scenario {
        "witness-shape" => {
            exact_object_keys(parameters, &["kind"], id)?;
            let witness = match string(parameters, "kind", id)? {
                "empty" => vec![],
                "one-element" => vec![vec![1]],
                "annex-underflow" => vec![vec![1], vec![0x50]],
                other => return Err(format!("{id}: unsupported witness shape {other}")),
            };
            if split_witness(witness).is_ok() {
                return Err(format!(
                    "{id}: malformed boundary witness unexpectedly parsed"
                ));
            }
            Ok(boundary_policy_pair(Expected {
                accepted: false,
                stage: "witness".to_string(),
                error: "SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY".to_string(),
            }))
        }
        "control-path" => {
            exact_object_keys(parameters, &["nodes", "mutation"], id)?;
            let nodes: usize = unsigned(parameters, "nodes", id)?
                .try_into()
                .map_err(|_| format!("{id}: control node count overflow"))?;
            if nodes > 129 {
                return Err(format!("{id}: unsupported control node count"));
            }
            let script = [0x51];
            let mut control = vec![0xc1];
            control.resize(1 + 32 * nodes, 0);
            let leaf = leaf_hash(P2MR_LEAF_VERSION, &script, "P2MRLeaf");
            let mut program = if nodes <= 128 {
                root_from_control(&control, &script, "P2MRLeaf", "P2MRBranch")?
            } else {
                leaf
            };
            match string(parameters, "mutation", id)? {
                "none" => {}
                "append-byte" => control.push(0),
                "clear-marker" => control[0] &= 0xfe,
                "path-node" if nodes == 1 => *control.last_mut().unwrap() ^= 1,
                "program-root" => program[0] ^= 1,
                mutation => return Err(format!("{id}: unsupported control mutation {mutation}")),
            }
            Ok(boundary_policy_pair(commitment_outcome(
                &control, &script, &program,
            )))
        }
        "leaf-version" => {
            exact_object_keys(parameters, &["control_byte", "script"], id)?;
            let control_byte: u8 = unsigned(parameters, "control_byte", id)?
                .try_into()
                .map_err(|_| format!("{id}: control byte overflow"))?;
            if control_byte & 1 == 0 {
                return Err(format!("{id}: boundary control marker is clear"));
            }
            let script = match string(parameters, "script", id)? {
                "true" => [0x51],
                "false" => [0x00],
                other => return Err(format!("{id}: unsupported leaf script {other}")),
            };
            if control_byte & 0xfe == P2MR_LEAF_VERSION {
                let result = script::evaluate(
                    &script,
                    &[],
                    |_, _, _| unreachable!(),
                    |_, _, _| unreachable!(),
                );
                let consensus = match result {
                    Ok(()) => Expected {
                        accepted: true,
                        stage: "script-complete".to_string(),
                        error: "SCRIPT_ERR_OK".to_string(),
                    },
                    Err(error) => Expected {
                        accepted: false,
                        stage: "script".to_string(),
                        error,
                    },
                };
                Ok(boundary_policy_pair(consensus))
            } else {
                Ok((
                    Expected {
                        accepted: true,
                        stage: "upgrade-success".to_string(),
                        error: "SCRIPT_ERR_OK".to_string(),
                    },
                    Expected {
                        accepted: false,
                        stage: "policy".to_string(),
                        error: "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION".to_string(),
                    },
                ))
            }
        }
        "opcode" => {
            let kind = string(parameters, "kind", id)?;
            let consensus = match kind {
                "checksigpqc-valid" | "checksigpqc-invalid" => {
                    let extras = if kind == "checksigpqc-invalid" {
                        &["mutation"][..]
                    } else {
                        &[][..]
                    };
                    let fixture = boundary_fixture(
                        parameters,
                        id,
                        witness_cases,
                        "transaction-checksigpqc",
                        extras,
                    )?;
                    evaluate_witness(&Value::Object(fixture.clone()))?;
                    let pubkey = decode_hex(string(fixture, "pubkey", id)?, id)?;
                    let mut signature = decode_hex(string(fixture, "signature", id)?, id)?;
                    let digest = decode_32(string(fixture, "p2mrSighash", id)?, id)?;
                    if kind == "checksigpqc-invalid" {
                        if string(parameters, "mutation", id)? != "flip-first-signature-byte" {
                            return Err(format!("{id}: unsupported signature mutation"));
                        }
                        signature[0] ^= 1;
                    }
                    let verifies =
                        primitive_verify(&pubkey, &digest, parse_signature(&signature, 0)?)?;
                    if verifies != (kind == "checksigpqc-valid") {
                        return Err(format!("{id}: PQC signature mutation result mismatch"));
                    }
                    if verifies {
                        Expected {
                            accepted: true,
                            stage: "script-complete".to_string(),
                            error: "SCRIPT_ERR_OK".to_string(),
                        }
                    } else {
                        Expected {
                            accepted: false,
                            stage: "script".to_string(),
                            error: "SCRIPT_ERR_P2MR_SIG".to_string(),
                        }
                    }
                }
                "checksigpqc-empty" => {
                    exact_object_keys(parameters, &["kind"], id)?;
                    Expected {
                        accepted: false,
                        stage: "script".to_string(),
                        error: "SCRIPT_ERR_VERIFY".to_string(),
                    }
                }
                "checksigpqc-bad-size" => {
                    exact_object_keys(parameters, &["kind"], id)?;
                    let error = parse_signature(&vec![1; PQC_SIGNATURE_SIZE - 1], 0).unwrap_err();
                    Expected {
                        accepted: false,
                        stage: "script".to_string(),
                        error,
                    }
                }
                "checksigpqc-bad-key" => {
                    exact_object_keys(parameters, &["kind"], id)?;
                    let error =
                        primitive_verify(&[], &[0; 32], &vec![1; PQC_SIGNATURE_SIZE]).unwrap_err();
                    Expected {
                        accepted: false,
                        stage: "script".to_string(),
                        error,
                    }
                }
                "checksigadd-valid" => {
                    let fixture =
                        boundary_fixture(parameters, id, witness_cases, "checkSigAdd", &[])?;
                    validate_checksigadd_fixture(fixture, string(fixture, "id", id)?)?;
                    Expected {
                        accepted: true,
                        stage: "script-complete".to_string(),
                        error: "SCRIPT_ERR_OK".to_string(),
                    }
                }
                "legacy-checksig" => {
                    exact_object_keys(parameters, &["kind"], id)?;
                    Expected {
                        accepted: false,
                        stage: "script".to_string(),
                        error: "SCRIPT_ERR_P2MR_CHECKSIG".to_string(),
                    }
                }
                "legacy-checkmultisig" => {
                    exact_object_keys(parameters, &["kind"], id)?;
                    Expected {
                        accepted: false,
                        stage: "script".to_string(),
                        error: "SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG".to_string(),
                    }
                }
                "ctv-fixed" => {
                    exact_object_keys(
                        parameters,
                        &[
                            "kind",
                            "control_block",
                            "template_hash",
                            "leaf_script",
                            "script_pubkey",
                        ],
                        id,
                    )?;
                    let declared = decode_32(string(parameters, "template_hash", id)?, id)?;
                    let leaf = decode_hex(string(parameters, "leaf_script", id)?, id)?;
                    let mut expected_leaf = vec![32];
                    expected_leaf.extend_from_slice(&declared);
                    expected_leaf.push(0xbb); // OP_CHECKTEMPLATEVERIFY
                    let control = decode_hex(string(parameters, "control_block", id)?, id)?;
                    let program = program_from_script_pubkey(
                        &decode_hex(string(parameters, "script_pubkey", id)?, id)?,
                        id,
                    )?;
                    if leaf != expected_leaf
                        || root_from_control(&control, &leaf, "P2MRLeaf", "P2MRBranch")? != program
                    {
                        return Err(format!("{id}: CTV leaf commitment mismatch"));
                    }
                    if declared == default_ctv_hash() {
                        Expected {
                            accepted: true,
                            stage: "script-complete".to_string(),
                            error: "SCRIPT_ERR_OK".to_string(),
                        }
                    } else {
                        Expected {
                            accepted: false,
                            stage: "script".to_string(),
                            error: "SCRIPT_ERR_TEMPLATE_MISMATCH".to_string(),
                        }
                    }
                }
                "checkdatasigpqc-valid"
                | "checkdatasigpqc-invalid"
                | "checkdatasigpqc-wrong-domain"
                | "checkdatasigaddpqc-valid"
                | "checkdatasigaddpqc-wrong-message"
                | "checkdatasigaddpqc-wrong-pubkey" => {
                    let is_add = kind.starts_with("checkdatasigaddpqc");
                    let extras = if !is_add && kind != "checkdatasigpqc-valid" {
                        &["mutation"][..]
                    } else {
                        &[][..]
                    };
                    let fixture = boundary_fixture(
                        parameters,
                        id,
                        witness_cases,
                        if is_add { "dataSigAdd" } else { "dataSig" },
                        extras,
                    )?;
                    let fixture_id = string(fixture, "id", id)?;
                    validate_ancillary_data_signatures(fixture, fixture_id)?;
                    let result = if is_add {
                        let add = object(
                            fixture
                                .get("dataSigAdd")
                                .ok_or_else(|| format!("{id}: missing dataSigAdd"))?,
                            id,
                        )?;
                        let leaf_field = match kind {
                            "checkdatasigaddpqc-valid" => "nOfNLeafScript",
                            "checkdatasigaddpqc-wrong-message" => "wrongMessageHashLeafScript",
                            "checkdatasigaddpqc-wrong-pubkey" => "wrongPubkeyLeafScript",
                            _ => unreachable!(),
                        };
                        execute_data_signature_script(
                            &decode_hex(string(add, leaf_field, id)?, id)?,
                            &[
                                decode_hex(string(add, "signatureB", id)?, id)?,
                                decode_hex(string(add, "signatureA", id)?, id)?,
                            ],
                            &decode_hex(string(add, "controlBlock", id)?, id)?,
                        )
                    } else {
                        let mut signature =
                            decode_hex(string(fixture, "dataSigSignature", id)?, id)?;
                        if kind == "checkdatasigpqc-invalid" {
                            if string(parameters, "mutation", id)? != "flip-first-signature-byte" {
                                return Err(format!("{id}: unsupported data signature mutation"));
                            }
                            signature[0] ^= 1;
                        } else if kind == "checkdatasigpqc-wrong-domain" {
                            if string(parameters, "mutation", id)? != "raw-message-signature" {
                                return Err(format!("{id}: unsupported data signature mutation"));
                            }
                            signature =
                                decode_hex(string(fixture, "dataSigRawMessageSignature", id)?, id)?;
                        }
                        execute_data_signature_script(
                            &decode_hex(string(fixture, "dataSigLeafScript", id)?, id)?,
                            &[
                                signature,
                                decode_hex(string(fixture, "dataSigMessageHash", id)?, id)?,
                            ],
                            &decode_hex(string(fixture, "dataSigControlBlock", id)?, id)?,
                        )
                    };
                    match result {
                        Ok(_) => Expected {
                            accepted: true,
                            stage: "script-complete".to_string(),
                            error: "SCRIPT_ERR_OK".to_string(),
                        },
                        Err(error) => Expected {
                            accepted: false,
                            stage: "script".to_string(),
                            error,
                        },
                    }
                }
                "op-success" => {
                    exact_object_keys(parameters, &["kind"], id)?;
                    return Ok((
                        Expected {
                            accepted: true,
                            stage: "op-success".to_string(),
                            error: "SCRIPT_ERR_OK".to_string(),
                        },
                        Expected {
                            accepted: false,
                            stage: "policy".to_string(),
                            error: "SCRIPT_ERR_DISCOURAGE_OP_SUCCESS".to_string(),
                        },
                    ));
                }
                "disabled" => {
                    exact_object_keys(parameters, &["kind"], id)?;
                    Expected {
                        accepted: false,
                        stage: "script".to_string(),
                        error: "SCRIPT_ERR_BAD_OPCODE".to_string(),
                    }
                }
                other => return Err(format!("{id}: unsupported boundary opcode {other}")),
            };
            Ok(boundary_policy_pair(consensus))
        }
        "resource" => {
            let kind = string(parameters, "kind", id)?;
            let consensus = match kind {
                "stack-items" | "item-bytes" | "total-bytes" => {
                    exact_object_keys(parameters, &["kind", "value"], id)?;
                    let value: usize = unsigned(parameters, "value", id)?
                        .try_into()
                        .map_err(|_| format!("{id}: resource value overflow"))?;
                    let error = match kind {
                        "stack-items" if value > 1000 => Some("SCRIPT_ERR_STACK_SIZE"),
                        "item-bytes" if value > 16_384 => Some("SCRIPT_ERR_PUSH_SIZE"),
                        "total-bytes" if value > 131_072 => Some("SCRIPT_ERR_PUSH_SIZE"),
                        _ => None,
                    };
                    match error {
                        Some(error) => Expected {
                            accepted: false,
                            stage: "initial-stack".to_string(),
                            error: error.to_string(),
                        },
                        None => Expected {
                            accepted: true,
                            stage: "script-complete".to_string(),
                            error: "SCRIPT_ERR_OK".to_string(),
                        },
                    }
                }
                "validation-weight" => {
                    let checks = unsigned(parameters, "nonempty_checks", id)? as usize;
                    let artifact = if checks == 1 {
                        "transaction-checksigpqc"
                    } else if checks == 2 {
                        "dataSigAdd"
                    } else {
                        return Err(format!("{id}: unsupported validation check count"));
                    };
                    let fixture = boundary_fixture(
                        parameters,
                        id,
                        witness_cases,
                        artifact,
                        &["nonempty_checks"],
                    )?;
                    let fixture_id = string(fixture, "id", id)?;
                    let witness = if checks == 1 {
                        evaluate_witness(&Value::Object(fixture.clone()))?;
                        let tx =
                            Transaction::parse(&decode_hex(string(fixture, "spendTx", id)?, id)?)?;
                        tx.inputs[unsigned(fixture, "inputIndex", id)? as usize]
                            .witness
                            .clone()
                    } else {
                        validate_ancillary_data_signatures(fixture, fixture_id)?;
                        let add = object(
                            fixture
                                .get("dataSigAdd")
                                .ok_or_else(|| format!("{id}: missing dataSigAdd"))?,
                            id,
                        )?;
                        vec![
                            decode_hex(string(add, "signatureB", id)?, id)?,
                            decode_hex(string(add, "signatureA", id)?, id)?,
                            decode_hex(string(add, "nOfNLeafScript", id)?, id)?,
                            decode_hex(string(add, "controlBlock", id)?, id)?,
                        ]
                    };
                    let budget =
                        witness_serialized_size(&witness) + VALIDATION_WEIGHT_OFFSET as usize;
                    if budget < checks * VALIDATION_WEIGHT_PER_PQC as usize
                        || budget >= (checks + 1) * VALIDATION_WEIGHT_PER_PQC as usize
                    {
                        return Err(format!("{id}: validation-weight fixture budget mismatch"));
                    }
                    Expected {
                        accepted: true,
                        stage: "script-complete".to_string(),
                        error: "SCRIPT_ERR_OK".to_string(),
                    }
                }
                "validation-weight-exceeded" => {
                    exact_object_keys(parameters, &["kind", "nonempty_checks"], id)?;
                    let checks = unsigned(parameters, "nonempty_checks", id)? as usize;
                    let synthetic_witness = vec![vec![1]; checks];
                    let budget = witness_serialized_size(&synthetic_witness)
                        + VALIDATION_WEIGHT_OFFSET as usize;
                    if checks != 2 || budget >= VALIDATION_WEIGHT_PER_PQC as usize {
                        return Err(format!("{id}: invalid exceeded-weight construction"));
                    }
                    Expected {
                        accepted: false,
                        stage: "validation-weight".to_string(),
                        error: "SCRIPT_ERR_P2MR_VALIDATION_WEIGHT".to_string(),
                    }
                }
                "empty-signatures" => {
                    exact_object_keys(parameters, &["kind", "nonempty_checks"], id)?;
                    if unsigned(parameters, "nonempty_checks", id)? != 0 {
                        return Err(format!("{id}: empty signatures declare nonempty checks"));
                    }
                    Expected {
                        accepted: true,
                        stage: "script-complete".to_string(),
                        error: "SCRIPT_ERR_OK".to_string(),
                    }
                }
                "clean-stack" | "false-final" => {
                    exact_object_keys(parameters, &["kind", "value"], id)?;
                    let script = if kind == "clean-stack" {
                        vec![0x51, 0x51]
                    } else {
                        vec![0x00]
                    };
                    let error = script::evaluate(
                        &script,
                        &[],
                        |_, _, _| unreachable!(),
                        |_, _, _| unreachable!(),
                    )
                    .expect_err("boundary final-stack script must fail");
                    Expected {
                        accepted: false,
                        stage: "script-complete".to_string(),
                        error,
                    }
                }
                other => return Err(format!("{id}: unsupported boundary resource {other}")),
            };
            Ok(boundary_policy_pair(consensus))
        }
        other => Err(format!("{id}: unsupported boundary scenario {other}")),
    }
}

pub fn evaluate_boundary(case: &Value, witness_cases: &[Value]) -> Result<Observation, String> {
    let case = object(case, "script boundary case")?;
    exact_object_keys(
        case,
        &[
            "id",
            "category",
            "scenario",
            "parameters",
            "consensus",
            "policy",
        ],
        "script boundary case",
    )?;
    let id = string(case, "id", "script boundary case")?;
    let category = string(case, "category", id)?;
    if !matches!(
        category,
        "witness-control" | "leaf-version" | "opcode" | "resource"
    ) {
        return Err(format!("{id}: unsupported boundary category {category}"));
    }
    let scenario = string(case, "scenario", id)?;
    let parameters = object(
        case.get("parameters")
            .ok_or_else(|| format!("{id}: missing parameters"))?,
        id,
    )?;
    let (observed_consensus, observed_policy) =
        boundary_outcome(id, scenario, parameters, witness_cases)?;
    let expected_consensus = expected(
        case.get("consensus")
            .ok_or_else(|| format!("{id}: missing consensus result"))?,
        id,
    )?;
    let expected_policy = expected(
        case.get("policy")
            .ok_or_else(|| format!("{id}: missing policy result"))?,
        id,
    )?;
    if observed_policy.accepted != expected_policy.accepted
        || observed_policy.stage != expected_policy.stage
        || observed_policy.error != expected_policy.error
    {
        return Err(format!(
            "{id}: independently observed policy result mismatch"
        ));
    }
    checked_observation(
        id,
        "script_boundary",
        observed_consensus,
        expected_consensus,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::TxIn;
    use serde_json::json;

    #[test]
    fn branch_order_is_lexicographic_in_both_directions() {
        let low = [1u8; 32];
        let high = [2u8; 32];
        assert_eq!(
            branch_hash(&low, &high, "P2MRBranch"),
            branch_hash(&high, &low, "P2MRBranch")
        );
    }

    #[test]
    fn annex_hash_commits_to_compact_size() {
        let annex = vec![0x50, 1, 2];
        assert_ne!(sha256(&annex), sha256(&serialized_bytes(&annex)));
    }

    #[test]
    fn witness_split_detects_annex_only_in_final_position() {
        let plain = vec![vec![1], vec![0x51], vec![0xc1]];
        let parsed = split_witness(plain).unwrap();
        assert_eq!(parsed.stack, vec![vec![1]]);
        assert_eq!(parsed.script, vec![0x51]);
        assert_eq!(parsed.control, vec![0xc1]);
        assert!(parsed.annex.is_none());

        let with_annex = vec![vec![0x50], vec![0x51], vec![0xc1], vec![0x50, 1]];
        let parsed = split_witness(with_annex).unwrap();
        assert_eq!(parsed.stack, vec![vec![0x50]]);
        assert_eq!(parsed.annex, Some(vec![0x50, 1]));
        assert!(split_witness(vec![vec![0x50]]).is_err());
    }

    fn sighash_test_transaction(outputs: usize) -> (Transaction, Vec<SpentOutput>) {
        let inputs = (0..2)
            .map(|index| TxIn {
                previous_txid: [index as u8; 32],
                previous_vout: index,
                script_sig: Vec::new(),
                sequence: u32::MAX - index,
                witness: Vec::new(),
            })
            .collect();
        let outputs = (0..outputs)
            .map(|index| TxOut {
                value: index as i64 + 1,
                script_pubkey: vec![0x51],
            })
            .collect();
        let spent = (0..2)
            .map(|index| SpentOutput {
                value: index + 10,
                script_pubkey: vec![0x51],
            })
            .collect();
        (
            Transaction {
                version: 2,
                inputs,
                outputs,
                lock_time: 0,
            },
            spent,
        )
    }

    #[test]
    fn accepted_and_invalid_sighash_types_are_independent() {
        let (tx, spent) = sighash_test_transaction(2);
        for hash_type in [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83] {
            assert!(
                p2mr_sigmsg(&tx, &spent, 0, hash_type, None, &[3; 32], u32::MAX)
                    .unwrap()
                    .is_some()
            );
        }
        for hash_type in [0x04, 0x80, 0x84, 0xff] {
            assert!(p2mr_sigmsg(&tx, &spent, 0, hash_type, None, &[3; 32], u32::MAX).is_err());
        }
    }

    #[test]
    fn missing_output_single_has_no_message() {
        let (tx, spent) = sighash_test_transaction(0);
        for hash_type in [0x03, 0x83] {
            assert!(
                p2mr_sigmsg(&tx, &spent, 0, hash_type, None, &[3; 32], u32::MAX)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn control_path_depth_is_capped_at_128() {
        let mut maximum = vec![0xc1];
        maximum.extend_from_slice(&vec![0u8; 32 * 128]);
        assert!(root_from_control(&maximum, &[0x51], "P2MRLeaf", "P2MRBranch").is_ok());
        maximum.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            root_from_control(&maximum, &[0x51], "P2MRLeaf", "P2MRBranch").unwrap_err(),
            "SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE"
        );
    }

    #[test]
    fn upgradeable_leaf_success_does_not_claim_script_execution() {
        let control = [0xc3];
        let script = [0x00];
        let program = root_from_control(&control, &script, "P2MRLeaf", "P2MRBranch").unwrap();
        let outcome = commitment_outcome(&control, &script, &program);
        assert!(outcome.accepted);
        assert_eq!(outcome.stage, "upgrade-success");
        assert_eq!(outcome.error, "SCRIPT_ERR_OK");
    }

    #[test]
    fn data_signature_checks_match_consensus_error_ordering() {
        let data_script = |pubkey_size: usize| {
            let mut script = vec![pubkey_size as u8];
            script.resize(1 + pubkey_size, 2);
            script.push(0xbc);
            script
        };
        let control = [0xc1];

        assert_eq!(
            execute_data_signature_script(
                &data_script(31),
                &[vec![1; PQC_SIGNATURE_SIZE], vec![1; 31]],
                &control,
            )
            .unwrap_err(),
            "SCRIPT_ERR_PUBKEYTYPE"
        );
        assert_eq!(
            execute_data_signature_script(
                &data_script(32),
                &[vec![1; PQC_SIGNATURE_SIZE], vec![1; 31]],
                &control,
            )
            .unwrap_err(),
            "SCRIPT_ERR_PUSH_SIZE"
        );
        assert_eq!(
            execute_data_signature_script(
                &data_script(32),
                &[vec![1; PQC_SIGNATURE_SIZE - 1], vec![1; 32]],
                &control,
            )
            .unwrap_err(),
            "SCRIPT_ERR_P2MR_SIG_SIZE"
        );
        assert_eq!(
            execute_data_signature_script(&data_script(32), &[Vec::new(), vec![1; 32]], &control,)
                .unwrap_err(),
            "SCRIPT_ERR_EVAL_FALSE"
        );
        assert_eq!(
            execute_data_signature_script(&data_script(32), &[vec![1], vec![1; 32]], &control,)
                .unwrap_err(),
            "SCRIPT_ERR_P2MR_VALIDATION_WEIGHT"
        );
    }

    #[test]
    fn missing_cross_profile_comparison_is_a_structured_error() {
        let case = json!({
            "id": "missing-comparison",
            "leaf_script": "00",
            "control_block": "c1",
            "tapleaf_root": "e7e4d593fcb72926eedbe0d1e311f41acd6f6ef161dcba081a75168ec4dcd379",
            "p2mr_leaf_root": "fae97225114b26d9ef3e3bea70f90d08fec30d9833c50b23e4a6cf8c33e6b200",
            "scriptPubKey": "5220fae97225114b26d9ef3e3bea70f90d08fec30d9833c50b23e4a6cf8c33e6b200",
            "witness": ["00", "c1"],
            "expected": {
                "qbit_p2mr_v1": {
                    "accepted": false,
                    "stage": "script-execution",
                    "error": "SCRIPT_ERR_EVAL_FALSE"
                }
            }
        });
        let error = evaluate_cross_profile(&case)
            .err()
            .expect("missing comparison must return an error");
        assert_eq!(
            error,
            "missing-comparison: missing comparison expected result"
        );
    }

    #[test]
    fn witness_v2_addresses_have_embedded_known_answers() {
        let program =
            hex::decode("5c4bb09e52c01be092fe020458a377ba81f004203e232a808f562e248827c7a0")
                .unwrap();
        let program: [u8; 32] = program.try_into().unwrap();
        assert_eq!(
            witness_v2_address("qb", &program),
            "qb1zt39mp8jjcqd7pyh7qgz93gmhh2qlqppq8c3j4qy02chzfzp8c7sqkcq5ga"
        );
        assert_eq!(
            witness_v2_address("qbrt", &program),
            "qbrt1zt39mp8jjcqd7pyh7qgz93gmhh2qlqppq8c3j4qy02chzfzp8c7sqrw52qh"
        );
    }

    #[test]
    fn p2mr_signature_check_hard_fails_invalid_nonempty_signature() {
        let corpus: Value = serde_json::from_str(include_str!(
            "../../../../src/test/data/p2mr_pqc_witness_vectors.json"
        ))
        .unwrap();
        let fixture = corpus["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["id"] == "single_key_default_sighash")
            .unwrap();
        let checksigadd = &fixture["checkSigAdd"];
        let pubkey = hex::decode(checksigadd["pubkey"].as_str().unwrap()).unwrap();
        let digest = hex::decode(checksigadd["p2mrSighash"].as_str().unwrap()).unwrap();
        let mut signature = hex::decode(checksigadd["signature"].as_str().unwrap()).unwrap();

        assert!(check_p2mr_signature(&pubkey, &digest, &signature, 0).unwrap());
        signature[0] ^= 1;
        assert_eq!(
            check_p2mr_signature(&pubkey, &digest, &signature, 0).unwrap_err(),
            "SCRIPT_ERR_P2MR_SIG"
        );
    }
}
