use bitcoinpqc::{
    generate_keypair, public_key_size, secret_key_size, sign, signature_size, verify, PqcError,
    PublicKey, SecretKey, Signature,
};

fn fixed_random_data() -> Vec<u8> {
    hex::decode(
        "f47e7324fb639d867a35eea3558a54224e7ca5e357c588c136d2d514facd5fc0d93a31a624a7c3d9ba02f8a73bd2e9dac7b2e3a0dcf1900b2c3b8e56c6efec7ef2aa654567e42988f6c1b71ae817db8f7dbf25c5e7f3ddc87f39b8fc9b3c44caacb6fe8f9df68e895f6ae603e1c4db3c6a0e1ba9d52ac34a63426f9be2e2ac16",
    )
    .expect("valid test vector")
}

#[test]
fn test_key_sizes() {
    assert_eq!(public_key_size(), 32);
    assert_eq!(secret_key_size(), 64);
    assert_eq!(signature_size(), 3680);
}

#[test]
fn test_keygen_sign_verify_roundtrip() {
    let keypair = generate_keypair(&fixed_random_data()).expect("keygen should succeed");
    let message = b"SLH-DSA-SHA2-128s bounded30 test message";

    let signature = sign(&keypair.secret_key, message).expect("sign should succeed");
    assert_eq!(signature.bytes.len(), signature_size());

    verify(&keypair.public_key, message, &signature).expect("verify should succeed");

    let tampered = b"SLH-DSA-SHA2-128s bounded30 tampered message";
    assert!(verify(&keypair.public_key, tampered, &signature).is_err());
}

#[test]
fn test_deterministic_signing() {
    let keypair = generate_keypair(&fixed_random_data()).expect("keygen should succeed");
    let message = b"deterministic-signing-check";

    let signature_1 = sign(&keypair.secret_key, message).expect("first sign should succeed");
    let signature_2 = sign(&keypair.secret_key, message).expect("second sign should succeed");

    assert_eq!(signature_1, signature_2);
    assert!(verify(&keypair.public_key, message, &signature_1).is_ok());
}

#[test]
fn test_secret_debug_output_is_redacted() {
    let keypair = generate_keypair(&fixed_random_data()).expect("keygen should succeed");
    let secret_bytes_debug = format!("{:?}", keypair.secret_key.as_secret_bytes());
    let secret_key_debug = format!("{:?}", keypair.secret_key);
    let keypair_debug = format!("{:?}", keypair);

    assert!(secret_key_debug.contains("<redacted>"));
    assert!(!secret_key_debug.contains(&secret_bytes_debug));
    assert!(keypair_debug.contains("<redacted>"));
    assert!(!keypair_debug.contains(&secret_bytes_debug));
}

#[test]
fn test_bad_input_validation() {
    let short_random = vec![7u8; 127];
    assert_eq!(
        generate_keypair(&short_random),
        Err(PqcError::InsufficientData)
    );

    assert_eq!(
        PublicKey::try_from_slice(&vec![0u8; 31]),
        Err(PqcError::BadKey)
    );
    assert_eq!(
        SecretKey::try_from_slice(&vec![0u8; 63]),
        Err(PqcError::BadKey)
    );
    assert_eq!(
        Signature::try_from_slice(&vec![0u8; signature_size() - 1]),
        Err(PqcError::BadSignature)
    );
}
