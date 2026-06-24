#![no_main]

use std::sync::OnceLock;

use bitcoinpqc::{
    generate_keypair, public_key_size, secret_key_size, sign, signature_size, verify, KeyPair,
    PublicKey, SecretKey, Signature,
};
use libfuzzer_sys::fuzz_target;

const KEYGEN_SEED: [u8; 128] = [0x3D; 128];
const MESSAGE: &[u8] = b"malformed-key-signature-fuzz";

struct Fixture {
    keypair: KeyPair,
    signature: Signature,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let keypair = generate_keypair(&KEYGEN_SEED).expect("fixed keypair generation failed");
        let signature = sign(&keypair.secret_key, MESSAGE).expect("fixed signing failed");
        verify(&keypair.public_key, MESSAGE, &signature).expect("fixed signature failed");
        Fixture { keypair, signature }
    })
}

fn interesting_len(selector: u8, exact: usize) -> usize {
    match selector % 8 {
        0 => 0,
        1 => 1,
        2 => exact.saturating_sub(1),
        3 => exact,
        4 => exact + 1,
        5 => exact * 2,
        6 => exact.saturating_add(selector as usize),
        _ => selector as usize % (exact + 2),
    }
}

fn bytes_from_data(data: &[u8], len: usize, salt: u8) -> Vec<u8> {
    if data.is_empty() {
        return vec![salt; len];
    }

    (0..len)
        .map(|i| {
            data[i % data.len()]
                .wrapping_add(salt)
                .wrapping_add((i as u8).rotate_left((salt & 0x07) as u32))
        })
        .collect()
}

fn nonzero_mask(data: &[u8], index: usize) -> u8 {
    let mask = data.get(index).copied().unwrap_or(0x01);
    if mask == 0 {
        0x01
    } else {
        mask
    }
}

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let pk_size = public_key_size();
    let sk_size = secret_key_size();
    let sig_size = signature_size();

    let pk_len = interesting_len(data.first().copied().unwrap_or(0), pk_size);
    let sk_len = interesting_len(data.get(1).copied().unwrap_or(0), sk_size);
    let sig_len = interesting_len(data.get(2).copied().unwrap_or(0), sig_size);

    let _ = PublicKey::try_from_slice(&bytes_from_data(data, pk_len, 0x11));
    let _ = SecretKey::try_from_slice(&bytes_from_data(data, sk_len, 0x29));
    let _ = Signature::try_from_slice(&bytes_from_data(data, sig_len, 0x47));

    let short_signature = Signature {
        bytes: fixture.signature.bytes[..sig_size.saturating_sub(1)].to_vec(),
    };
    assert!(
        verify(&fixture.keypair.public_key, MESSAGE, &short_signature).is_err(),
        "short signature unexpectedly verified"
    );

    let mut oversized_signature = fixture.signature.bytes.clone();
    oversized_signature.extend(bytes_from_data(data, 1 + (data.len() % 64), 0x5E));
    assert!(
        verify(
            &fixture.keypair.public_key,
            MESSAGE,
            &Signature {
                bytes: oversized_signature,
            },
        )
        .is_err(),
        "oversized signature unexpectedly verified"
    );

    let mut mutated_signature = fixture.signature.bytes.clone();
    let sig_index = data.get(3).copied().unwrap_or(0) as usize % mutated_signature.len();
    mutated_signature[sig_index] ^= nonzero_mask(data, 4);
    assert!(
        verify(
            &fixture.keypair.public_key,
            MESSAGE,
            &Signature {
                bytes: mutated_signature,
            },
        )
        .is_err(),
        "mutated valid-length signature unexpectedly verified"
    );

    for fill in [0x00, 0xFF] {
        assert!(
            verify(
                &fixture.keypair.public_key,
                MESSAGE,
                &Signature {
                    bytes: vec![fill; sig_size],
                },
            )
            .is_err(),
            "uniform valid-length signature unexpectedly verified"
        );
    }

    let mut mutated_public_key = fixture.keypair.public_key.clone();
    let pk_index = data.get(5).copied().unwrap_or(0) as usize % mutated_public_key.bytes.len();
    mutated_public_key.bytes[pk_index] ^= nonzero_mask(data, 6);
    assert!(
        verify(&mutated_public_key, MESSAGE, &fixture.signature).is_err(),
        "signature unexpectedly verified under a mutated public key"
    );

    for fill in [0x00, 0xFF] {
        assert!(
            verify(
                &PublicKey {
                    bytes: vec![fill; pk_size],
                },
                MESSAGE,
                &fixture.signature,
            )
            .is_err(),
            "signature unexpectedly verified under a uniform public key"
        );
    }

    let mut mutated_secret_key_bytes = fixture.keypair.secret_key.as_secret_bytes().to_vec();
    let public_half_start = sk_size / 2;
    let sk_index = public_half_start + (data.get(7).copied().unwrap_or(0) as usize % (sk_size / 2));
    mutated_secret_key_bytes[sk_index] ^= nonzero_mask(data, 8);
    let mutated_secret_key =
        SecretKey::try_from_slice(&mutated_secret_key_bytes).expect("mutated key length is valid");
    if let Ok(signature) = sign(&mutated_secret_key, MESSAGE) {
        assert!(
            verify(&fixture.keypair.public_key, MESSAGE, &signature).is_err(),
            "signature from a mutated secret key unexpectedly verified"
        );
    }
});
