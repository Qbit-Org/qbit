use bitcoinpqc::{generate_keypair, sign, verify, KeyPair};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::Path;

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
    name: String,
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
    pubkey: String,
    signature: String,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "src/test/data/p2mr_pqc_witness_vectors.json".to_string());

    let out_path = Path::new(&out_path);
    let vectors = merge_existing_fields(out_path, build_vectors()?)?;
    let json = serde_json::to_string_pretty(&vectors)?;
    fs::write(out_path, format!("{json}\n"))?;
    Ok(())
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
    out_path: &Path,
    generated: Vec<WitnessVector>,
) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let mut generated_by_name = HashMap::<String, Map<String, Value>>::new();
    let mut generated_names = Vec::with_capacity(generated.len());
    for vector in generated {
        let generated_value = serde_json::to_value(vector)?;
        let generated_object = generated_value
            .as_object()
            .ok_or("generated vector did not serialize to a JSON object")?
            .clone();
        let name = generated_object
            .get("name")
            .and_then(Value::as_str)
            .ok_or("generated vector is missing a name")?
            .to_string();

        if generated_by_name
            .insert(name.clone(), generated_object)
            .is_some()
        {
            return Err(format!("duplicate generated vector {name}").into());
        }
        generated_names.push(name);
    }

    let mut merged = Vec::new();
    let mut emitted_generated_names = HashSet::new();
    if out_path.exists() {
        let existing_json: Value = serde_json::from_str(&fs::read_to_string(out_path)?)?;
        let existing_array = existing_json
            .as_array()
            .ok_or("existing fixture is not a JSON array")?;
        merged.reserve(existing_array.len() + generated_names.len());

        for existing in existing_array {
            let Some(name) = existing.get("name").and_then(Value::as_str) else {
                merged.push(existing.clone());
                continue;
            };
            let Some(generated_object) = generated_by_name.get(name) else {
                merged.push(existing.clone());
                continue;
            };

            let mut object = existing.as_object().cloned().unwrap_or_default();
            for (key, value) in generated_object {
                object.insert(key.clone(), value.clone());
            }
            emitted_generated_names.insert(name.to_string());
            merged.push(Value::Object(object));
        }
    }

    for name in generated_names {
        if emitted_generated_names.contains(&name) {
            continue;
        }
        let generated_object = generated_by_name
            .remove(&name)
            .ok_or_else(|| format!("missing generated vector {name}"))?;
        merged.push(Value::Object(generated_object));
    }

    Ok(merged)
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
        name: name.to_string(),
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
        pubkey: hex::encode(&keypair.public_key.bytes),
        signature: hex::encode(signature.bytes),
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
