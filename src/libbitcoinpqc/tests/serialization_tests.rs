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

fn keypair() -> bitcoinpqc::KeyPair {
    generate_keypair(&fixed_random_data()).expect("keygen should succeed")
}

#[test]
fn test_public_key_hex_roundtrip() {
    let keypair = keypair();
    assert_eq!(keypair.public_key.bytes.len(), public_key_size());

    let hex_pk = hex::encode(&keypair.public_key.bytes);
    let reconstructed = PublicKey::from_str(&hex_pk).expect("public key decode should succeed");

    assert_eq!(reconstructed, keypair.public_key);
}

#[test]
fn test_secret_key_hex_roundtrip() {
    let keypair = keypair();
    assert_eq!(
        keypair.secret_key.as_secret_bytes().len(),
        secret_key_size()
    );

    let hex_sk = hex::encode(keypair.secret_key.as_secret_bytes());
    let reconstructed = SecretKey::from_str(&hex_sk).expect("secret key decode should succeed");

    assert_eq!(reconstructed, keypair.secret_key);
}

#[test]
fn test_secret_key_common_debug_formatting_redacts_secret_bytes() {
    let keypair = keypair();
    let secret_vec_debug = format!("{:?}", keypair.secret_key.as_secret_bytes());
    let secret_hex = hex::encode(keypair.secret_key.as_secret_bytes());
    let formatted = [
        format!("{:?}", keypair.secret_key),
        format!("{:#?}", keypair.secret_key),
        format!("{:?}", keypair),
        format!("{:#?}", keypair),
    ];

    for debug in formatted {
        assert!(debug.contains("redacted"));
        assert!(debug.contains(&format!("{} bytes", secret_key_size())));
        assert!(!debug.contains(&secret_vec_debug));
        assert!(!debug.contains(&secret_hex));
    }
}

#[test]
fn test_keypair_debug_redacts_secret_key() {
    let keypair = keypair();
    let debug = format!("{keypair:?}");
    let secret_vec_debug = format!("{:?}", keypair.secret_key.as_secret_bytes());
    let secret_hex = hex::encode(keypair.secret_key.as_secret_bytes());

    assert!(debug.contains("KeyPair"));
    assert!(debug.contains("public_key"));
    assert!(debug.contains("secret_key"));
    assert!(debug.contains("redacted"));
    assert!(debug.contains(&format!("{:?}", keypair.public_key)));
    assert!(!debug.contains(&secret_vec_debug));
    assert!(!debug.contains(&secret_hex));
}

#[test]
fn test_signature_hex_roundtrip() {
    let keypair = keypair();
    let message = b"signature-serialization-roundtrip";
    let signature = sign(&keypair.secret_key, message).expect("sign should succeed");

    assert_eq!(signature.bytes.len(), signature_size());

    let hex_sig = hex::encode(&signature.bytes);
    let reconstructed = Signature::from_str(&hex_sig).expect("signature decode should succeed");

    assert_eq!(reconstructed, signature);
    assert!(verify(&keypair.public_key, message, &reconstructed).is_ok());
}

#[test]
fn test_serialization_consistency_invariants() {
    let keypair = keypair();

    let reconstructed_pk =
        PublicKey::try_from_slice(&keypair.public_key.bytes).expect("public key should parse");
    let reconstructed_sk = SecretKey::try_from_slice(keypair.secret_key.as_secret_bytes())
        .expect("secret key should parse");

    for i in 0..32u8 {
        let mut message = b"serialization consistency iteration: ".to_vec();
        message.push(i);

        let signature = sign(&reconstructed_sk, &message)
            .unwrap_or_else(|_| panic!("Failed to sign at iteration {i}"));

        assert_eq!(signature.bytes.len(), signature_size());
        assert!(verify(&keypair.public_key, &message, &signature).is_ok());
        assert!(verify(&reconstructed_pk, &message, &signature).is_ok());
    }
}

#[cfg(feature = "serde")]
#[test]
fn test_public_material_serde_serializes_as_hex() {
    let keypair = keypair();
    let message = b"serde-public-material";
    let signature = sign(&keypair.secret_key, message).expect("sign should succeed");

    let public_key_json =
        serde_json::to_string(&keypair.public_key).expect("public key should serialize");
    let signature_json = serde_json::to_string(&signature).expect("signature should serialize");

    assert_eq!(
        serde_json::from_str::<PublicKey>(&public_key_json).expect("public key should deserialize"),
        keypair.public_key
    );
    assert_eq!(
        serde_json::from_str::<Signature>(&signature_json).expect("signature should deserialize"),
        signature
    );
    assert!(verify(&keypair.public_key, message, &signature).is_ok());
}

#[cfg(feature = "secret-key-serde")]
#[test]
fn test_secret_key_serde_requires_explicit_feature_and_serializes_as_hex() {
    let keypair = keypair();
    let secret_hex = hex::encode(keypair.secret_key.as_secret_bytes());

    let secret_key_json =
        serde_json::to_string(&keypair.secret_key).expect("secret key should serialize");
    assert_eq!(secret_key_json, format!("{{\"bytes\":\"{secret_hex}\"}}"));

    let reconstructed =
        serde_json::from_str::<SecretKey>(&secret_key_json).expect("secret key should deserialize");
    assert_eq!(reconstructed, keypair.secret_key);

    let keypair_json = serde_json::to_string(&keypair).expect("keypair should serialize");
    assert!(keypair_json.contains(&secret_hex));
    assert_eq!(
        serde_json::from_str::<bitcoinpqc::KeyPair>(&keypair_json)
            .expect("keypair should deserialize"),
        keypair
    );
}

#[test]
fn test_corrupted_signature_fails_verification() {
    let keypair = keypair();
    let message = b"corrupted serialized signature";
    let signature = sign(&keypair.secret_key, message).expect("sign should succeed");

    for position in [0usize, signature.bytes.len() / 2] {
        let mut corrupted_bytes = signature.bytes.clone();
        corrupted_bytes[position] ^= 0x01;

        let corrupted_signature = Signature::try_from_slice(&corrupted_bytes)
            .expect("mutated signature should still have a valid serialized length");

        assert!(
            verify(&keypair.public_key, message, &corrupted_signature).is_err(),
            "verification unexpectedly succeeded for corruption at byte {position}"
        );
    }
}

#[test]
fn test_wrong_length_rejected_for_serialized_types() {
    let pk_short = vec![0u8; public_key_size() - 1];
    let pk_long = vec![0u8; public_key_size() + 1];
    assert_eq!(PublicKey::try_from_slice(&pk_short), Err(PqcError::BadKey));
    assert_eq!(PublicKey::try_from_slice(&pk_long), Err(PqcError::BadKey));
    assert_eq!(
        PublicKey::from_str(&hex::encode(pk_short)),
        Err(PqcError::BadKey)
    );
    assert_eq!(
        PublicKey::from_str(&hex::encode(pk_long)),
        Err(PqcError::BadKey)
    );

    let sk_short = vec![0u8; secret_key_size() - 1];
    let sk_long = vec![0u8; secret_key_size() + 1];
    assert_eq!(SecretKey::try_from_slice(&sk_short), Err(PqcError::BadKey));
    assert_eq!(SecretKey::try_from_slice(&sk_long), Err(PqcError::BadKey));
    assert_eq!(
        SecretKey::from_str(&hex::encode(sk_short)),
        Err(PqcError::BadKey)
    );
    assert_eq!(
        SecretKey::from_str(&hex::encode(sk_long)),
        Err(PqcError::BadKey)
    );

    let sig_short = vec![0u8; signature_size() - 1];
    let sig_long = vec![0u8; signature_size() + 1];
    assert_eq!(
        Signature::try_from_slice(&sig_short),
        Err(PqcError::BadSignature)
    );
    assert_eq!(
        Signature::try_from_slice(&sig_long),
        Err(PqcError::BadSignature)
    );
    assert_eq!(
        Signature::from_str(&hex::encode(sig_short)),
        Err(PqcError::BadSignature)
    );
    assert_eq!(
        Signature::from_str(&hex::encode(sig_long)),
        Err(PqcError::BadSignature)
    );
}
