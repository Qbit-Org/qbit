use bitcoinpqc::{
    generate_keypair, public_key_size, secret_key_size, sign, signature_size, verify, KeyPair,
    PqcError, Signature,
};

const MIN_ENTROPY_LEN: usize = 128;
const MAXIMUM_TEST_MESSAGE_LEN: usize = 1024 * 1024;

fn deterministic_entropy(seed: u8) -> Vec<u8> {
    (0..MIN_ENTROPY_LEN)
        .map(|i| seed.wrapping_add(((i * 37) % 256) as u8))
        .collect()
}

fn deterministic_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add(((i * 29) % 256) as u8))
        .collect()
}

fn deterministic_keypair(seed: u8) -> KeyPair {
    generate_keypair(&deterministic_entropy(seed)).expect("keygen should succeed")
}

fn run_soak_roundtrips(roundtrips: u32, key_seed: u8) -> std::time::Duration {
    let keypair = deterministic_keypair(key_seed);
    let start = std::time::Instant::now();

    for i in 0..roundtrips {
        let msg_len = (i as usize * 53) % 4096;
        let seed_byte = ((i >> 8) ^ (i & 0xFF)) as u8;
        let message = deterministic_bytes(msg_len, seed_byte);

        let signature = sign(&keypair.secret_key, &message)
            .unwrap_or_else(|e| panic!("sign failed at iteration {i}: {e}"));
        verify(&keypair.public_key, &message, &signature)
            .unwrap_or_else(|e| panic!("verify failed at iteration {i}: {e}"));
    }

    start.elapsed()
}

#[test]
fn bounded_mode_size_invariants() {
    assert_eq!(public_key_size(), 32);
    assert_eq!(secret_key_size(), 64);
    assert_eq!(signature_size(), 3680);
}

#[test]
fn bounded_mode_sign_verify_roundtrip() {
    let keypair = deterministic_keypair(0x11);
    let message = b"bounded-mode roundtrip";

    let signature = sign(&keypair.secret_key, message).expect("sign should succeed");
    assert_eq!(signature.bytes.len(), signature_size());
    verify(&keypair.public_key, message, &signature).expect("verify should succeed");
}

#[test]
fn bounded_mode_signing_is_deterministic() {
    let keypair_a = deterministic_keypair(0x22);
    let keypair_b = deterministic_keypair(0x23);
    let message_a = b"determinism check";
    let message_b = b"determinism check variant";

    let signature_a_1 = sign(&keypair_a.secret_key, message_a).expect("first sign should succeed");
    let signature_a_2 = sign(&keypair_a.secret_key, message_a).expect("second sign should succeed");
    assert_eq!(
        signature_a_1, signature_a_2,
        "same key + same message must produce the same signature"
    );

    let signature_b_1 =
        sign(&keypair_b.secret_key, message_a).expect("sign with different key should succeed");
    assert_ne!(
        signature_a_1, signature_b_1,
        "different key + same message must produce different signatures"
    );

    let signature_a_message_b =
        sign(&keypair_a.secret_key, message_b).expect("sign with different message should succeed");
    assert_ne!(
        signature_a_1, signature_a_message_b,
        "same key + different message must produce different signatures"
    );

    verify(&keypair_a.public_key, message_a, &signature_a_1)
        .expect("deterministic signature should verify");
    verify(&keypair_b.public_key, message_a, &signature_b_1)
        .expect("different-key signature should verify");
    verify(&keypair_a.public_key, message_b, &signature_a_message_b)
        .expect("different-message signature should verify");
}

#[test]
fn bounded_mode_multiple_distinct_messages_roundtrip() {
    let keypair = deterministic_keypair(0x24);
    let messages = [
        b"message-1".as_slice(),
        b"message-2".as_slice(),
        b"message-3".as_slice(),
    ];

    for message in messages {
        let signature = sign(&keypair.secret_key, message)
            .expect("sign should succeed for each distinct message");
        verify(&keypair.public_key, message, &signature)
            .expect("verify should succeed for each distinct message");
    }
}

#[test]
fn bounded_mode_empty_message_roundtrip() {
    let keypair = deterministic_keypair(0x25);
    let empty_message: [u8; 0] = [];

    let signature = sign(&keypair.secret_key, &empty_message).expect("empty message should sign");
    verify(&keypair.public_key, &empty_message, &signature)
        .expect("empty message signature should verify");
}

#[test]
fn bounded_mode_minimum_length_message_roundtrip() {
    let keypair = deterministic_keypair(0x26);
    let minimum_message = [0x42u8];

    let signature =
        sign(&keypair.secret_key, &minimum_message).expect("minimum-length message should sign");
    verify(&keypair.public_key, &minimum_message, &signature)
        .expect("minimum-length message signature should verify");
}

#[test]
fn bounded_mode_single_byte_zero_roundtrip() {
    let keypair = deterministic_keypair(0x28);
    let message = [0x00u8];

    let signature = sign(&keypair.secret_key, &message).expect("single-byte zero should sign");
    verify(&keypair.public_key, &message, &signature)
        .expect("single-byte zero signature should verify");
}

#[test]
fn bounded_mode_single_byte_ff_roundtrip() {
    let keypair = deterministic_keypair(0x29);
    let message = [0xFFu8];

    let signature = sign(&keypair.secret_key, &message).expect("single-byte 0xFF should sign");
    verify(&keypair.public_key, &message, &signature)
        .expect("single-byte 0xFF signature should verify");
}

#[test]
fn bounded_mode_all_zeros_256_roundtrip() {
    let keypair = deterministic_keypair(0x2A);
    let message = vec![0u8; 256];

    let signature =
        sign(&keypair.secret_key, &message).expect("all-zero 256-byte message should sign");
    verify(&keypair.public_key, &message, &signature)
        .expect("all-zero 256-byte message signature should verify");
}

#[test]
fn bounded_mode_all_ones_256_roundtrip() {
    let keypair = deterministic_keypair(0x2B);
    let message = vec![0xFFu8; 256];

    let signature =
        sign(&keypair.secret_key, &message).expect("all-one 256-byte message should sign");
    verify(&keypair.public_key, &message, &signature)
        .expect("all-one 256-byte message signature should verify");
}

#[test]
fn bounded_mode_maximum_length_message_roundtrip() {
    let keypair = deterministic_keypair(0x27);
    // The API exposes no formal max message size; this is the practical max test size.
    let maximum_message = deterministic_bytes(MAXIMUM_TEST_MESSAGE_LEN, 0x5A);

    let signature = sign(&keypair.secret_key, &maximum_message)
        .expect("maximum-length test message should sign");
    verify(&keypair.public_key, &maximum_message, &signature)
        .expect("maximum-length test message signature should verify");
}

#[test]
fn bounded_mode_keypair_from_minimum_entropy_works() {
    let minimum_entropy = vec![0u8; MIN_ENTROPY_LEN];
    let keypair =
        generate_keypair(&minimum_entropy).expect("minimum entropy keygen should succeed");

    assert_eq!(keypair.public_key.bytes.len(), public_key_size());
    assert_eq!(
        keypair.secret_key.as_secret_bytes().len(),
        secret_key_size()
    );

    let message = b"minimum-entropy keypair roundtrip";
    let signature =
        sign(&keypair.secret_key, message).expect("minimum entropy key should be able to sign");
    verify(&keypair.public_key, message, &signature)
        .expect("signature from minimum entropy key should verify");
}

#[test]
fn bounded_mode_rejects_invalid_signatures() {
    let signer = deterministic_keypair(0x33);
    let other = deterministic_keypair(0x44);
    let message = b"invalid signature rejection";

    let valid_signature = sign(&signer.secret_key, message).expect("sign should succeed");

    let wrong_message = b"invalid signature rejection with wrong message";
    assert_eq!(
        verify(&signer.public_key, wrong_message, &valid_signature),
        Err(PqcError::BadSignature),
        "signature verified against the wrong message should be rejected"
    );

    let mut tampered_r_bytes = valid_signature.bytes.clone();
    tampered_r_bytes[0] ^= 0x01;
    let tampered_r = Signature {
        bytes: tampered_r_bytes,
    };
    assert_eq!(
        verify(&signer.public_key, message, &tampered_r),
        Err(PqcError::BadSignature),
        "signature with tampered R should be rejected"
    );

    let mut bit_flipped_bytes = valid_signature.bytes.clone();
    let bit_flip_index = bit_flipped_bytes.len() / 2;
    bit_flipped_bytes[bit_flip_index] ^= 0x01;
    let bit_flipped = Signature {
        bytes: bit_flipped_bytes,
    };
    assert_eq!(
        verify(&signer.public_key, message, &bit_flipped),
        Err(PqcError::BadSignature),
        "bit-flipped signature should be rejected"
    );

    let truncated = Signature {
        bytes: valid_signature.bytes[..valid_signature.bytes.len() - 1].to_vec(),
    };
    assert_eq!(
        verify(&signer.public_key, message, &truncated),
        Err(PqcError::BadSignature),
        "truncated signature should be rejected"
    );

    let mut oversized_bytes = valid_signature.bytes.clone();
    oversized_bytes.push(0x00);
    let oversized = Signature {
        bytes: oversized_bytes,
    };
    assert_eq!(
        verify(&signer.public_key, message, &oversized),
        Err(PqcError::BadSignature),
        "oversized signature should be rejected"
    );

    assert_eq!(
        verify(&other.public_key, message, &valid_signature),
        Err(PqcError::BadSignature),
        "signature verified with wrong public key should be rejected"
    );

    let all_zero_signature = Signature {
        bytes: vec![0u8; signature_size()],
    };
    assert_eq!(
        verify(&signer.public_key, message, &all_zero_signature),
        Err(PqcError::BadSignature),
        "all-zero signature should be rejected"
    );

    let random_signature = Signature {
        bytes: deterministic_bytes(signature_size(), 0xA5),
    };
    assert_eq!(
        verify(&signer.public_key, message, &random_signature),
        Err(PqcError::BadSignature),
        "random bytes should not verify as a valid signature"
    );
}

#[test]
#[ignore = "Nightly soak: 10,000 sign/verify roundtrips (~29 min)"]
fn bounded_mode_soak_10k_roundtrips() {
    let elapsed = run_soak_roundtrips(10_000, 0xD0);
    eprintln!("soak test completed 10,000 roundtrips in {elapsed:?}");
}

#[test]
#[ignore = "PR smoke: 100 sign/verify roundtrips (~1-2 min on slower CI VMs)"]
fn bounded_mode_soak_pr_smoke_100_roundtrips() {
    let elapsed = run_soak_roundtrips(100, 0xD1);
    eprintln!("pr soak smoke completed 100 roundtrips in {elapsed:?}");
}
