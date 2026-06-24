#![no_main]

use std::sync::OnceLock;

use bitcoinpqc::{generate_keypair, sign, verify, KeyPair};
use libfuzzer_sys::fuzz_target;

const KEYGEN_SEED: [u8; 128] = [0x5Au8; 128];
const FORS_START: usize = 16;
const FORS_END: usize = 1920;

fn fixed_keypair() -> &'static KeyPair {
    static KEYPAIR: OnceLock<KeyPair> = OnceLock::new();
    KEYPAIR.get_or_init(|| generate_keypair(&KEYGEN_SEED).expect("fixed keypair generation failed"))
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let keypair = fixed_keypair();

    let message_len = data[0] as usize % data.len();
    let message = &data[..message_len];
    let signature = sign(&keypair.secret_key, message).expect("signing failed");

    // This exercises production FORS index extraction in verify.
    verify(&keypair.public_key, message, &signature).expect("roundtrip verification failed");

    let mut modified_message = message.to_vec();
    if modified_message.is_empty() {
        modified_message.push(0x01);
    } else {
        let byte_selector = data[data.len() - 1];
        let message_index = byte_selector as usize % modified_message.len();
        let bit_mask = 1u8 << ((byte_selector >> 5) & 0x07);
        modified_message[message_index] ^= bit_mask;
    }
    assert!(
        verify(&keypair.public_key, &modified_message, &signature).is_err(),
        "signature verified for a modified message"
    );

    // Mutate a byte in the FORS section; verification should reject.
    let mut mutated_signature = signature.clone();
    if mutated_signature.bytes.len() > FORS_START {
        let end = FORS_END.min(mutated_signature.bytes.len());
        let span = (end - FORS_START).max(1);
        let sig_index = FORS_START + (data[0] as usize % span);
        mutated_signature.bytes[sig_index] ^= 0x01;
        assert!(
            verify(&keypair.public_key, message, &mutated_signature).is_err(),
            "signature with a FORS mutation unexpectedly verified"
        );
    }
});
