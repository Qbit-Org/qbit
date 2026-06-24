#![no_main]

use std::ptr;
use std::slice;
use std::sync::OnceLock;

use bitcoinpqc::{generate_keypair, sign, signature_size, verify, KeyPair, Signature};
use libfuzzer_sys::fuzz_target;

#[repr(C)]
struct BitcoinPqcSignature {
    signature: *mut u8,
    signature_size: usize,
}

extern "C" {
    fn bitcoin_pqc_sign(
        secret_key: *const u8,
        secret_key_size: usize,
        message: *const u8,
        message_size: usize,
        signature: *mut BitcoinPqcSignature,
    ) -> i32;

    fn bitcoin_pqc_signature_free(signature: *mut BitcoinPqcSignature);

    fn bitcoin_pqc_verify(
        public_key: *const u8,
        public_key_size: usize,
        message: *const u8,
        message_size: usize,
        signature: *const u8,
        signature_size: usize,
    ) -> i32;
}

const BITCOIN_PQC_OK: i32 = 0;
const KEYGEN_SEED: [u8; 128] = [0x42; 128];

fn fixed_keypair() -> &'static KeyPair {
    static KEYPAIR: OnceLock<KeyPair> = OnceLock::new();
    KEYPAIR.get_or_init(|| generate_keypair(&KEYGEN_SEED).expect("fixed keypair generation failed"))
}

fn selected_message_len(data: &[u8]) -> usize {
    let selector = data.first().copied().unwrap_or(0);
    match selector & 0x0f {
        0 => 0,
        1 => 1,
        2 => 55,
        3 => 56,
        4 => 63,
        5 => 64,
        6 => 255,
        7 => 1024,
        8 => 4096,
        9 => 16 * 1024,
        10 => 64 * 1024,
        11 => 256 * 1024,
        12 => 1024 * 1024,
        _ => data.len().saturating_sub(1).min(64 * 1024),
    }
}

fn expanded_message(data: &[u8]) -> Vec<u8> {
    let len = selected_message_len(data);
    let seed = if data.len() > 1 { &data[1..] } else { &[0xA5] };
    let salt = data.first().copied().unwrap_or(0);

    (0..len)
        .map(|i| seed[i % seed.len()].wrapping_add((i as u8).rotate_left((salt & 0x07) as u32)))
        .collect()
}

fn exercise_rust_api(keypair: &KeyPair, message: &[u8]) {
    let signature = sign(&keypair.secret_key, message).expect("Rust API signing failed");
    verify(&keypair.public_key, message, &signature).expect("Rust API verification failed");
}

fn exercise_c_api(keypair: &KeyPair, message: &[u8]) {
    let mut raw_signature = BitcoinPqcSignature {
        signature: ptr::null_mut(),
        signature_size: 0,
    };

    let (c_verify_result, signature_bytes) = unsafe {
        let secret_key_bytes = keypair.secret_key.as_secret_bytes();
        let sign_result = bitcoin_pqc_sign(
            secret_key_bytes.as_ptr(),
            secret_key_bytes.len(),
            message.as_ptr(),
            message.len(),
            &mut raw_signature,
        );
        assert_eq!(sign_result, BITCOIN_PQC_OK, "C API signing failed");
        assert!(
            !raw_signature.signature.is_null(),
            "C API returned a null signature pointer"
        );
        assert_eq!(
            raw_signature.signature_size,
            signature_size(),
            "C API returned an unexpected signature length"
        );

        let signature_slice =
            slice::from_raw_parts(raw_signature.signature, raw_signature.signature_size);
        let signature_bytes = signature_slice.to_vec();
        let c_verify_result = bitcoin_pqc_verify(
            keypair.public_key.bytes.as_ptr(),
            keypair.public_key.bytes.len(),
            message.as_ptr(),
            message.len(),
            signature_slice.as_ptr(),
            signature_slice.len(),
        );
        bitcoin_pqc_signature_free(&mut raw_signature);

        (c_verify_result, signature_bytes)
    };

    assert_eq!(c_verify_result, BITCOIN_PQC_OK, "C API verification failed");
    verify(
        &keypair.public_key,
        message,
        &Signature {
            bytes: signature_bytes,
        },
    )
    .expect("Rust API failed to verify a C API signature");
}

fuzz_target!(|data: &[u8]| {
    let keypair = fixed_keypair();
    let message = expanded_message(data);

    if data.first().copied().unwrap_or(0) & 0x80 == 0 {
        exercise_rust_api(keypair, &message);
    }
    exercise_c_api(keypair, &message);
});
