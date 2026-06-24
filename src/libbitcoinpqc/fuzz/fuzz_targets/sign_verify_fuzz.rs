#![no_main]

use bitcoinpqc::{generate_keypair, sign, verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 128 {
        return;
    }

    let keypair = generate_keypair(&data[..128]).expect("SLH-DSA key generation failed");
    let message = &data[128..];

    let signature = sign(&keypair.secret_key, message).expect("SLH-DSA signing failed");

    verify(&keypair.public_key, message, &signature)
        .expect("SLH-DSA roundtrip verification failed");
});
