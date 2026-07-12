use bitcoinpqc::{generate_keypair, sign, verify, KeyPair};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_CODESEPARATOR: u8 = 0xab;
const OP_CHECKSIGPQC: u8 = 0xb3;
const P2MR_LEAF_VERSION: u8 = 0xc0;
const P2MR_CONTROL_BYTE: u8 = P2MR_LEAF_VERSION | 1;
const SIGHASH_DEFAULT: u8 = 0x00;
const PREVOUT_AMOUNT: i64 = 1000;
const SPEND_OUTPUT_AMOUNT: i64 = 900;
const SCHEMA_VERSION: u64 = 1;
const PROFILE: &str = "qbit-p2mr-v1";
const PROFILE_VERSION: u64 = 1;
const GENERATOR_VERSION: u64 = 1;
const PYTHON_OWNED_IDS: [&str; 11] = [
    "single_key_default_sighash",
    "single_key_sighash_none",
    "single_key_sighash_single_matching_output",
    "single_key_sighash_all_anyonecanpay",
    "single_key_sighash_none_anyonecanpay",
    "single_key_sighash_single_anyonecanpay",
    "single_key_default_sighash_annex_present",
    "single_key_sighash_single_missing_first",
    "single_key_sighash_single_missing_beyond",
    "single_key_sighash_single_anyonecanpay_missing_first",
    "single_key_sighash_single_anyonecanpay_missing_beyond",
];
const RUST_OWNED_IDS: [&str; 3] = [
    "single_key_leading_codesep",
    "branch_codesep_true",
    "branch_codesep_false",
];

#[derive(Clone)]
struct TxIn {
    prev_txid: [u8; 32],
    vout: u32,
    script_sig: Vec<u8>,
    sequence: u32,
    witness: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct TxOut {
    value: i64,
    script_pubkey: Vec<u8>,
}

#[derive(Clone)]
struct Transaction {
    version: i32,
    lock_time: u32,
    vin: Vec<TxIn>,
    vout: Vec<TxOut>,
}

#[derive(Serialize)]
struct SpentOutput {
    amount: i64,
    #[serde(rename = "scriptPubKey")]
    script_pubkey: String,
}

#[derive(Serialize)]
struct WitnessVector {
    id: String,
    name: String,
    generator: Generator,
    provenance: String,
    annex: String,
    #[serde(rename = "inputIndex")]
    input_index: u32,
    #[serde(rename = "hashType")]
    hash_type: String,
    epoch: String,
    #[serde(rename = "spendType")]
    spend_type: String,
    #[serde(rename = "keyVersion")]
    key_version: String,
    #[serde(rename = "codeSeparatorPosition")]
    code_separator_position: String,
    #[serde(rename = "prevoutAmount")]
    prevout_amount: i64,
    #[serde(rename = "prevoutScriptPubKey")]
    prevout_script_pubkey: String,
    #[serde(rename = "spentOutputs")]
    spent_outputs: Vec<SpentOutput>,
    #[serde(rename = "spendTx")]
    spend_tx: String,
    #[serde(rename = "leafVersion")]
    leaf_version: String,
    #[serde(rename = "leafScript")]
    leaf_script: String,
    #[serde(rename = "controlBlock")]
    control_block: String,
    #[serde(rename = "leafHash")]
    leaf_hash: String,
    pubkey: String,
    signature: String,
    witness: Vec<String>,
    #[serde(rename = "digest_defined")]
    digest_defined: bool,
    expected: Expected,
    #[serde(rename = "p2mrSigMsg")]
    p2mr_sigmsg: String,
    #[serde(rename = "p2mrSighash")]
    p2mr_sighash: String,
    #[serde(rename = "wrongCodeSeparatorPosition")]
    wrong_codeseparator_pos: String,
    #[serde(rename = "wrongCodeseparatorSigMsg")]
    wrong_codeseparator_sigmsg: String,
    #[serde(rename = "wrongCodeseparatorSighash")]
    wrong_codeseparator_sighash: String,
    #[serde(rename = "wrongCodeseparatorSignature")]
    wrong_codeseparator_signature: String,
    #[serde(rename = "wrongDomainSighash")]
    wrong_domain_sighash: String,
    #[serde(rename = "wrongDomainSignature")]
    wrong_domain_signature: String,
    #[serde(rename = "wrongPubkeyLeafScript")]
    wrong_pubkey_leaf_script: String,
    #[serde(rename = "wrongPubkeyScriptPubKey")]
    wrong_pubkey_script_pubkey: String,
}

#[derive(Serialize)]
struct Generator {
    id: String,
    version: u64,
}

#[derive(Serialize)]
struct Expected {
    accepted: bool,
    stage: String,
    error: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (input_path, output_path) = parse_args()?;
    if input_path == output_path {
        return Err("--input and --output must be different paths".into());
    }
    let corpus = merge_existing_fields(&input_path, build_vectors()?)?;
    let json = serde_json::to_string_pretty(&corpus)?;
    fs::write(output_path, format!("{json}\n"))?;
    Ok(())
}

fn parse_args() -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let mut input = None;
    let mut output = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => input = Some(PathBuf::from(args.next().ok_or("--input requires a path")?)),
            "--output" => {
                output = Some(PathBuf::from(
                    args.next().ok_or("--output requires a path")?,
                ))
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    Ok((
        input.ok_or("missing required --input")?,
        output.ok_or("missing required --output")?,
    ))
}

fn build_vectors() -> Result<Vec<WitnessVector>, Box<dyn std::error::Error>> {
    let leading_key = deterministic_keypair(0x21)?;
    let branch_key = deterministic_keypair(0x22)?;

    let leading_codesep_script = leading_codesep_script(&leading_key.public_key.bytes);
    let branch_script = branch_codesep_script(&branch_key.public_key.bytes);

    Ok(vec![
        build_vector(
            "single_key_leading_codesep",
            0x21,
            &leading_key,
            &leading_codesep_script,
            vec![],
            0,
            0xffff_ffff,
            0x10,
            8,
        )?,
        build_vector(
            "branch_codesep_true",
            0x22,
            &branch_key,
            &branch_script,
            vec![vec![1]],
            1,
            4,
            0x20,
            9,
        )?,
        build_vector(
            "branch_codesep_false",
            0x22,
            &branch_key,
            &branch_script,
            vec![vec![]],
            4,
            1,
            0x20,
            9,
        )?,
    ])
}

fn merge_existing_fields(
    input_path: &Path,
    generated: Vec<WitnessVector>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut generated_by_id = HashMap::<String, Map<String, Value>>::new();
    for vector in generated {
        let generated_value = serde_json::to_value(vector)?;
        let generated_object = generated_value
            .as_object()
            .ok_or("generated vector did not serialize to a JSON object")?
            .clone();
        let id = generated_object
            .get("id")
            .and_then(Value::as_str)
            .ok_or("generated vector is missing an id")?
            .to_string();

        if expected_owner(&id) != Some("standalone-rust") {
            return Err(format!("Rust generator produced unowned vector {id}").into());
        }
        if generated_by_id
            .insert(id.clone(), generated_object)
            .is_some()
        {
            return Err(format!("duplicate generated vector {id}").into());
        }
    }
    let generated_ids: HashSet<&str> = generated_by_id.keys().map(String::as_str).collect();
    if generated_ids != RUST_OWNED_IDS.into_iter().collect() {
        return Err("Rust generator did not produce its exact owned ID set".into());
    }

    let mut corpus: Value = serde_json::from_str(&fs::read_to_string(input_path)?)?;
    validate_corpus(&corpus)?;
    let existing_array = corpus
        .get_mut("vectors")
        .and_then(Value::as_array_mut)
        .ok_or("witness corpus vectors is not an array")?;

    let mut merged = Vec::with_capacity(existing_array.len());
    for existing in existing_array.iter() {
        let id = existing
            .get("id")
            .and_then(Value::as_str)
            .ok_or("existing vector is missing an id")?;
        let Some(generated_object) = generated_by_id.remove(id) else {
            merged.push(existing.clone());
            continue;
        };

        let mut object = existing.as_object().cloned().unwrap_or_default();
        for (key, value) in generated_object {
            object.insert(key, value);
        }
        merged.push(Value::Object(object));
    }
    if !generated_by_id.is_empty() {
        return Err(
            format!("Rust-owned vectors missing from input corpus: {generated_by_id:?}").into(),
        );
    }

    *existing_array = merged;
    Ok(corpus)
}

fn validate_corpus(corpus: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let object = corpus
        .as_object()
        .ok_or("witness corpus must be an object")?;
    let expected_keys = ["schema_version", "profile", "profile_version", "vectors"];
    if object.len() != expected_keys.len()
        || expected_keys.iter().any(|key| !object.contains_key(*key))
    {
        return Err("unknown witness corpus top-level field".into());
    }
    if object.get("schema_version").and_then(Value::as_u64) != Some(SCHEMA_VERSION)
        || object.get("profile").and_then(Value::as_str) != Some(PROFILE)
        || object.get("profile_version").and_then(Value::as_u64) != Some(PROFILE_VERSION)
    {
        return Err("unsupported witness corpus schema or profile".into());
    }
    if !object.get("vectors").is_some_and(Value::is_array) {
        return Err("witness corpus vectors must be an array".into());
    }
    let vectors = object["vectors"].as_array().expect("array checked above");
    let mut seen = HashSet::new();
    for vector in vectors {
        let vector_object = vector
            .as_object()
            .ok_or("witness vector must be an object")?;
        let id = vector_object
            .get("id")
            .and_then(Value::as_str)
            .ok_or("witness vector is missing an id")?;
        if vector_object.get("name").and_then(Value::as_str) != Some(id) {
            return Err(format!("witness vector {id} name does not match its stable id").into());
        }
        if !seen.insert(id) {
            return Err(format!("duplicate witness vector id: {id}").into());
        }
        let owner =
            expected_owner(id).ok_or_else(|| format!("unknown witness vector ownership: {id}"))?;
        let generator = vector_object
            .get("generator")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("witness vector {id} is missing generator metadata"))?;
        if generator.len() != 2
            || generator.get("id").and_then(Value::as_str) != Some(owner)
            || generator.get("version").and_then(Value::as_u64) != Some(GENERATOR_VERSION)
        {
            return Err(format!("witness vector {id} generator does not match its owner").into());
        }
    }
    let expected_ids: HashSet<&str> = PYTHON_OWNED_IDS.into_iter().chain(RUST_OWNED_IDS).collect();
    if seen != expected_ids {
        return Err("witness corpus does not contain the exact owned ID set".into());
    }
    Ok(())
}

fn expected_owner(id: &str) -> Option<&'static str> {
    if PYTHON_OWNED_IDS.contains(&id) {
        Some("standalone-python")
    } else if RUST_OWNED_IDS.contains(&id) {
        Some("standalone-rust")
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn build_vector(
    name: &str,
    key_seed: u8,
    keypair: &KeyPair,
    leaf_script: &[u8],
    script_args: Vec<Vec<u8>>,
    codeseparator_pos: u32,
    wrong_codeseparator_pos: u32,
    prevout_seed: u8,
    prevout_vout: u32,
) -> Result<WitnessVector, Box<dyn std::error::Error>> {
    let control_block = vec![P2MR_CONTROL_BYTE];
    let p2mr_root = p2mr_merkle_root(&control_block, &p2mr_leaf_hash(leaf_script));
    let prevout_script_pubkey = p2mr_script_pubkey(&p2mr_root);
    let mut unsigned_tx = build_spend_tx(prevout_seed, prevout_vout);

    let sigmsg = p2mr_sigmsg(
        &unsigned_tx,
        PREVOUT_AMOUNT,
        &prevout_script_pubkey,
        leaf_script,
        codeseparator_pos,
    );
    let p2mr_sighash = tagged_hash("P2MRSighash", &sigmsg);
    let signature = sign(&keypair.secret_key, &p2mr_sighash)?;
    verify(&keypair.public_key, &p2mr_sighash, &signature)?;

    unsigned_tx.vin[0].witness =
        witness_stack(&signature.bytes, &script_args, leaf_script, &control_block);
    let witness = unsigned_tx.vin[0].witness.iter().map(hex::encode).collect();
    let spend_tx = unsigned_tx.serialize(true);

    let wrong_codeseparator_sigmsg = p2mr_sigmsg(
        &unsigned_tx,
        PREVOUT_AMOUNT,
        &prevout_script_pubkey,
        leaf_script,
        wrong_codeseparator_pos,
    );
    let wrong_codeseparator_sighash = tagged_hash("P2MRSighash", &wrong_codeseparator_sigmsg);
    let wrong_codeseparator_signature = sign(&keypair.secret_key, &wrong_codeseparator_sighash)?;
    verify(
        &keypair.public_key,
        &wrong_codeseparator_sighash,
        &wrong_codeseparator_signature,
    )?;

    let wrong_domain_sighash = tagged_hash("TapSighash", &sigmsg);
    let wrong_domain_signature = sign(&keypair.secret_key, &wrong_domain_sighash)?;
    verify(
        &keypair.public_key,
        &wrong_domain_sighash,
        &wrong_domain_signature,
    )?;

    let wrong_pubkey = wrong_pubkey(&keypair.public_key.bytes);
    let wrong_pubkey_leaf_script =
        replace_pubkey(leaf_script, &keypair.public_key.bytes, &wrong_pubkey);
    let wrong_pubkey_script_pubkey = p2mr_script_pubkey(&p2mr_leaf_hash(&wrong_pubkey_leaf_script));

    Ok(WitnessVector {
        id: name.to_string(),
        name: name.to_string(),
        generator: Generator {
            id: "standalone-rust".to_string(),
            version: GENERATOR_VERSION,
        },
        provenance: format!(
            "Generated from deterministic libbitcoinpqc seed {key_seed:#04x} plus the independent Rust P2MR serializer in contrib/testgen/p2mr_checksigpqc_vectors; the vector signs the manually computed P2MRSighash digest with libbitcoinpqc and does not use qbit wallet/signing/sighash helpers."
        ),
        annex: "none".to_string(),
        input_index: 0,
        hash_type: hex::encode([SIGHASH_DEFAULT]),
        epoch: "00".to_string(),
        spend_type: "02".to_string(),
        key_version: "00".to_string(),
        code_separator_position: hex::encode(codeseparator_pos.to_le_bytes()),
        prevout_amount: PREVOUT_AMOUNT,
        prevout_script_pubkey: hex::encode(&prevout_script_pubkey),
        spent_outputs: vec![SpentOutput {
            amount: PREVOUT_AMOUNT,
            script_pubkey: hex::encode(&prevout_script_pubkey),
        }],
        spend_tx: hex::encode(spend_tx),
        leaf_version: hex::encode([P2MR_LEAF_VERSION]),
        leaf_script: hex::encode(leaf_script),
        control_block: hex::encode(control_block),
        leaf_hash: hex::encode(p2mr_leaf_hash(leaf_script)),
        pubkey: hex::encode(&keypair.public_key.bytes),
        signature: hex::encode(signature.bytes),
        witness,
        digest_defined: true,
        expected: Expected {
            accepted: true,
            stage: "script-complete".to_string(),
            error: "SCRIPT_ERR_OK".to_string(),
        },
        p2mr_sigmsg: hex::encode(sigmsg),
        p2mr_sighash: hex::encode(p2mr_sighash),
        wrong_codeseparator_pos: hex::encode(wrong_codeseparator_pos.to_le_bytes()),
        wrong_codeseparator_sigmsg: hex::encode(wrong_codeseparator_sigmsg),
        wrong_codeseparator_sighash: hex::encode(wrong_codeseparator_sighash),
        wrong_codeseparator_signature: hex::encode(wrong_codeseparator_signature.bytes),
        wrong_domain_sighash: hex::encode(wrong_domain_sighash),
        wrong_domain_signature: hex::encode(wrong_domain_signature.bytes),
        wrong_pubkey_leaf_script: hex::encode(wrong_pubkey_leaf_script),
        wrong_pubkey_script_pubkey: hex::encode(wrong_pubkey_script_pubkey),
    })
}

fn deterministic_keypair(seed: u8) -> Result<KeyPair, bitcoinpqc::PqcError> {
    let entropy: Vec<u8> = (0..128)
        .map(|i| seed.wrapping_add(((i * 37) % 256) as u8))
        .collect();
    generate_keypair(&entropy)
}

fn checksig_script(pubkey: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(34);
    script.push(pubkey.len() as u8);
    script.extend_from_slice(pubkey);
    script.push(OP_CHECKSIGPQC);
    script
}

fn leading_codesep_script(pubkey: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(35);
    script.push(OP_CODESEPARATOR);
    script.extend_from_slice(&checksig_script(pubkey));
    script
}

fn branch_codesep_script(pubkey: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(72);
    script.push(OP_IF);
    script.push(OP_CODESEPARATOR);
    script.extend_from_slice(&checksig_script(pubkey));
    script.pop();
    script.push(OP_ELSE);
    script.push(OP_CODESEPARATOR);
    script.extend_from_slice(&checksig_script(pubkey));
    script.pop();
    script.push(OP_ENDIF);
    script.push(OP_CHECKSIGPQC);
    script
}

fn build_spend_tx(prevout_seed: u8, prevout_vout: u32) -> Transaction {
    let mut prev_txid = [0u8; 32];
    for (i, byte) in prev_txid.iter_mut().enumerate() {
        *byte = prevout_seed.wrapping_add(i as u8);
    }
    Transaction {
        version: 2,
        lock_time: 0,
        vin: vec![TxIn {
            prev_txid,
            vout: prevout_vout,
            script_sig: vec![],
            sequence: 0xffff_fffe,
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: SPEND_OUTPUT_AMOUNT,
            script_pubkey: vec![OP_1],
        }],
    }
}

fn witness_stack(
    signature: &[u8],
    script_args: &[Vec<u8>],
    leaf_script: &[u8],
    control_block: &[u8],
) -> Vec<Vec<u8>> {
    let mut stack = Vec::with_capacity(script_args.len() + 3);
    stack.push(signature.to_vec());
    stack.extend(script_args.iter().cloned());
    stack.push(leaf_script.to_vec());
    stack.push(control_block.to_vec());
    stack
}

fn p2mr_script_pubkey(root: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(34);
    script.push(OP_2);
    script.push(32);
    script.extend_from_slice(root);
    script
}

fn wrong_pubkey(pubkey: &[u8]) -> Vec<u8> {
    let mut wrong = pubkey.to_vec();
    wrong[0] ^= 0x01;
    wrong
}

fn replace_pubkey(script: &[u8], pubkey: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut out = script.to_vec();
    for offset in 0..=out.len().saturating_sub(pubkey.len()) {
        if &out[offset..offset + pubkey.len()] == pubkey {
            out[offset..offset + replacement.len()].copy_from_slice(replacement);
        }
    }
    out
}

fn p2mr_leaf_hash(script: &[u8]) -> [u8; 32] {
    let mut msg = vec![P2MR_LEAF_VERSION];
    ser_compact_size(script.len() as u64, &mut msg);
    msg.extend_from_slice(script);
    tagged_hash("P2MRLeaf", &msg)
}

fn p2mr_merkle_root(control_block: &[u8], leaf_hash: &[u8; 32]) -> [u8; 32] {
    let mut root = *leaf_hash;
    for node in control_block[1..].chunks_exact(32) {
        root = p2mr_branch_hash(&root, node);
    }
    root
}

fn p2mr_branch_hash(left: &[u8; 32], right: &[u8]) -> [u8; 32] {
    assert_eq!(right.len(), 32);
    let mut msg = Vec::with_capacity(64);
    if left.as_slice() < right {
        msg.extend_from_slice(left);
        msg.extend_from_slice(right);
    } else {
        msg.extend_from_slice(right);
        msg.extend_from_slice(left);
    }
    tagged_hash("P2MRBranch", &msg)
}

fn p2mr_sigmsg(
    tx: &Transaction,
    prevout_amount: i64,
    prevout_script_pubkey: &[u8],
    leaf_script: &[u8],
    codeseparator_pos: u32,
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.push(0); // epoch
    msg.push(SIGHASH_DEFAULT);
    msg.extend_from_slice(&tx.version.to_le_bytes());
    msg.extend_from_slice(&tx.lock_time.to_le_bytes());
    msg.extend_from_slice(&prevouts_hash(tx));
    msg.extend_from_slice(&spent_amounts_hash(prevout_amount));
    msg.extend_from_slice(&spent_scripts_hash(prevout_script_pubkey));
    msg.extend_from_slice(&sequences_hash(tx));
    msg.extend_from_slice(&outputs_hash(tx));
    msg.push(2); // ext_flag 1, no annex
    msg.extend_from_slice(&0u32.to_le_bytes()); // input index
    msg.extend_from_slice(&p2mr_leaf_hash(leaf_script));
    msg.push(0); // key version
    msg.extend_from_slice(&codeseparator_pos.to_le_bytes());
    msg
}

fn prevouts_hash(tx: &Transaction) -> [u8; 32] {
    let mut data = Vec::new();
    for txin in &tx.vin {
        data.extend_from_slice(&txin.prev_txid);
        data.extend_from_slice(&txin.vout.to_le_bytes());
    }
    sha256(&data)
}

fn spent_amounts_hash(amount: i64) -> [u8; 32] {
    sha256(&amount.to_le_bytes())
}

fn spent_scripts_hash(script_pubkey: &[u8]) -> [u8; 32] {
    let mut data = Vec::new();
    ser_script(script_pubkey, &mut data);
    sha256(&data)
}

fn sequences_hash(tx: &Transaction) -> [u8; 32] {
    let mut data = Vec::new();
    for txin in &tx.vin {
        data.extend_from_slice(&txin.sequence.to_le_bytes());
    }
    sha256(&data)
}

fn outputs_hash(tx: &Transaction) -> [u8; 32] {
    let mut data = Vec::new();
    for txout in &tx.vout {
        txout.serialize(&mut data);
    }
    sha256(&data)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    let mut data = Vec::with_capacity(64 + msg.len());
    data.extend_from_slice(&tag_hash);
    data.extend_from_slice(&tag_hash);
    data.extend_from_slice(msg);
    sha256(&data)
}

impl Transaction {
    fn serialize(&self, with_witness: bool) -> Vec<u8> {
        let include_witness = with_witness && self.vin.iter().any(|txin| !txin.witness.is_empty());
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        if include_witness {
            out.push(0);
            out.push(1);
        }
        ser_compact_size(self.vin.len() as u64, &mut out);
        for txin in &self.vin {
            txin.serialize_non_witness(&mut out);
        }
        ser_compact_size(self.vout.len() as u64, &mut out);
        for txout in &self.vout {
            txout.serialize(&mut out);
        }
        if include_witness {
            for txin in &self.vin {
                ser_compact_size(txin.witness.len() as u64, &mut out);
                for item in &txin.witness {
                    ser_script(item, &mut out);
                }
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }
}

impl TxIn {
    fn serialize_non_witness(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.prev_txid);
        out.extend_from_slice(&self.vout.to_le_bytes());
        ser_script(&self.script_sig, out);
        out.extend_from_slice(&self.sequence.to_le_bytes());
    }
}

impl TxOut {
    fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes());
        ser_script(&self.script_pubkey, out);
    }
}

fn ser_script(bytes: &[u8], out: &mut Vec<u8>) {
    ser_compact_size(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn ser_compact_size(n: u64, out: &mut Vec<u8>) {
    match n {
        0..=252 => out.push(n as u8),
        253..=0xffff => {
            out.push(253);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(254);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(255);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}
