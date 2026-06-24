#![no_main]

use bitcoinpqc::{generate_keypair, sign, verify};
use libfuzzer_sys::fuzz_target;

const R_START: usize = 0;
const R_END: usize = 16;
const FORS_START: usize = 16;
const FORS_END: usize = 1920;
const AUTH_START: usize = 1920;
const AUTH_END: usize = 3680;

fn region_bounds(region_selector: u8, signature_len: usize) -> (usize, usize) {
    let (start, end) = match region_selector % 3 {
        0 => (R_START, R_END),
        1 => (FORS_START, FORS_END),
        _ => (AUTH_START, AUTH_END),
    };

    let bounded_start = start.min(signature_len);
    let bounded_end = end.min(signature_len);

    if bounded_start >= bounded_end {
        (0, signature_len)
    } else {
        (bounded_start, bounded_end)
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 132 {
        // 128 bytes keygen entropy + 3 bytes mutation control + at least 1 byte message.
        return;
    }

    let keypair = generate_keypair(&data[..128]).expect("SLH-DSA key generation failed");
    let region_selector = data[128];
    let mutation_index_seed = data[129];
    let mutation_mask = if data[130] == 0 { 1 } else { data[130] };
    let message = &data[131..];

    let signature = sign(&keypair.secret_key, message).expect("SLH-DSA signing failed");

    if signature.bytes.is_empty() {
        return;
    }

    let mut mutated_signature = signature.clone();
    let (region_start, region_end) = region_bounds(region_selector, mutated_signature.bytes.len());
    let region_len = region_end - region_start;
    let index = region_start + (mutation_index_seed as usize % region_len);
    mutated_signature.bytes[index] ^= mutation_mask;

    assert_ne!(
        mutated_signature.bytes, signature.bytes,
        "signature mutation did not change bytes"
    );
    assert!(
        verify(&keypair.public_key, message, &mutated_signature).is_err(),
        "mutated signature unexpectedly verified"
    );
});
