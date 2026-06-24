#![no_main]

use bitcoinpqc::{generate_keypair, verify, KeyPair, Signature};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const KEYGEN_SEED: [u8; 128] = [0xA5; 128];
const MESSAGE: &[u8] = b"signature-parsing-fuzz";

fn cached_keypair() -> &'static KeyPair {
    static KP: OnceLock<KeyPair> = OnceLock::new();
    KP.get_or_init(|| {
        generate_keypair(&KEYGEN_SEED)
            .expect("deterministic SLH-DSA key generation failed")
    })
}

fuzz_target!(|data: &[u8]| {
    let keypair = cached_keypair();

    // Exercise parser path directly.
    let _ = Signature::try_from_slice(data);

    // Also verify arbitrary signature bytes against a valid public key.
    let candidate_signature = Signature {
        bytes: data.to_vec(),
    };
    assert!(
        verify(&keypair.public_key, MESSAGE, &candidate_signature).is_err(),
        "arbitrary signature bytes unexpectedly verified"
    );
});
