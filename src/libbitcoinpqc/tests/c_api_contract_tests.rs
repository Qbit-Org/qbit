use std::ffi::c_void;
use std::ptr;

use bitcoinpqc::{generate_keypair, sign, signature_size};

const BITCOIN_PQC_OK: i32 = 0;
const BITCOIN_PQC_ERROR_BAD_ARG: i32 = -1;
const MIN_ENTROPY_SIZE: usize = 128;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct BitcoinPqcKeypair {
    public_key: *mut c_void,
    secret_key: *mut c_void,
    public_key_size: usize,
    secret_key_size: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct BitcoinPqcSignature {
    signature: *mut u8,
    signature_size: usize,
}

extern "C" {
    fn bitcoin_pqc_public_key_size() -> usize;
    fn bitcoin_pqc_secret_key_size() -> usize;
    fn bitcoin_pqc_signature_size() -> usize;
    fn bitcoin_pqc_keygen(
        keypair: *mut BitcoinPqcKeypair,
        random_data: *const u8,
        random_data_size: usize,
    ) -> i32;
    fn bitcoin_pqc_keypair_free(keypair: *mut BitcoinPqcKeypair);
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

fn entropy(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add(((i * 37) & 0xff) as u8))
        .collect()
}

fn empty_keypair() -> BitcoinPqcKeypair {
    BitcoinPqcKeypair {
        public_key: ptr::null_mut(),
        secret_key: ptr::null_mut(),
        public_key_size: 0,
        secret_key_size: 0,
    }
}

fn empty_signature() -> BitcoinPqcSignature {
    BitcoinPqcSignature {
        signature: ptr::null_mut(),
        signature_size: 0,
    }
}

fn keypair_is_empty(keypair: &BitcoinPqcKeypair) -> bool {
    keypair.public_key.is_null()
        && keypair.secret_key.is_null()
        && keypair.public_key_size == 0
        && keypair.secret_key_size == 0
}

fn signature_is_empty(signature: &BitcoinPqcSignature) -> bool {
    signature.signature.is_null() && signature.signature_size == 0
}

fn assert_c_keygen(keypair: &mut BitcoinPqcKeypair, entropy: &[u8]) {
    let rc = unsafe { bitcoin_pqc_keygen(keypair, entropy.as_ptr(), entropy.len()) };
    assert_eq!(rc, BITCOIN_PQC_OK);

    assert!(!keypair.public_key.is_null());
    assert!(!keypair.secret_key.is_null());
    assert_eq!(keypair.public_key_size, unsafe {
        bitcoin_pqc_public_key_size()
    });
    assert_eq!(keypair.secret_key_size, unsafe {
        bitcoin_pqc_secret_key_size()
    });
}

#[test]
fn c_api_accepts_null_empty_message_and_rejects_null_nonempty() {
    let entropy = entropy(MIN_ENTROPY_SIZE, 0x31);
    let mut keypair = empty_keypair();
    let mut signature = empty_signature();
    let mut rejected_signature = empty_signature();

    assert_c_keygen(&mut keypair, &entropy);

    let sign_rc = unsafe {
        bitcoin_pqc_sign(
            keypair.secret_key.cast(),
            keypair.secret_key_size,
            ptr::null(),
            0,
            &mut signature,
        )
    };
    assert_eq!(sign_rc, BITCOIN_PQC_OK);
    assert_eq!(signature.signature_size, unsafe {
        bitcoin_pqc_signature_size()
    });

    let verify_rc = unsafe {
        bitcoin_pqc_verify(
            keypair.public_key.cast(),
            keypair.public_key_size,
            ptr::null(),
            0,
            signature.signature,
            signature.signature_size,
        )
    };
    assert_eq!(verify_rc, BITCOIN_PQC_OK);

    let bad_sign_rc = unsafe {
        bitcoin_pqc_sign(
            keypair.secret_key.cast(),
            keypair.secret_key_size,
            ptr::null(),
            1,
            &mut rejected_signature,
        )
    };
    assert_eq!(bad_sign_rc, BITCOIN_PQC_ERROR_BAD_ARG);
    assert!(signature_is_empty(&rejected_signature));

    let bad_verify_rc = unsafe {
        bitcoin_pqc_verify(
            keypair.public_key.cast(),
            keypair.public_key_size,
            ptr::null(),
            1,
            signature.signature,
            signature.signature_size,
        )
    };
    assert_eq!(bad_verify_rc, BITCOIN_PQC_ERROR_BAD_ARG);

    unsafe {
        bitcoin_pqc_signature_free(&mut signature);
        bitcoin_pqc_keypair_free(&mut keypair);
    }
}

#[test]
fn c_api_requires_empty_output_structs_without_overwriting() {
    let entropy = entropy(MIN_ENTROPY_SIZE, 0x41);
    let mut sentinel_public = 0xa5u8;
    let mut sentinel_secret = 0x5au8;
    let mut occupied_keypairs = [
        BitcoinPqcKeypair {
            public_key: (&mut sentinel_public as *mut u8).cast(),
            ..empty_keypair()
        },
        BitcoinPqcKeypair {
            secret_key: (&mut sentinel_secret as *mut u8).cast(),
            ..empty_keypair()
        },
        BitcoinPqcKeypair {
            public_key_size: 1,
            ..empty_keypair()
        },
        BitcoinPqcKeypair {
            secret_key_size: 1,
            ..empty_keypair()
        },
    ];

    for keypair in &mut occupied_keypairs {
        let before = *keypair;
        let rc = unsafe { bitcoin_pqc_keygen(keypair, entropy.as_ptr(), entropy.len()) };
        assert_eq!(rc, BITCOIN_PQC_ERROR_BAD_ARG);
        assert_eq!(keypair.public_key, before.public_key);
        assert_eq!(keypair.secret_key, before.secret_key);
        assert_eq!(keypair.public_key_size, before.public_key_size);
        assert_eq!(keypair.secret_key_size, before.secret_key_size);
    }

    let mut keypair = empty_keypair();
    assert_c_keygen(&mut keypair, &entropy);

    let message = b"occupied signature output";
    let mut sentinel_signature = 0x3cu8;
    let mut occupied_signatures = [
        BitcoinPqcSignature {
            signature: &mut sentinel_signature,
            signature_size: 0,
        },
        BitcoinPqcSignature {
            signature: ptr::null_mut(),
            signature_size: 1,
        },
    ];

    for signature in &mut occupied_signatures {
        let before = *signature;
        let rc = unsafe {
            bitcoin_pqc_sign(
                keypair.secret_key.cast(),
                keypair.secret_key_size,
                message.as_ptr(),
                message.len(),
                signature,
            )
        };
        assert_eq!(rc, BITCOIN_PQC_ERROR_BAD_ARG);
        assert_eq!(signature.signature, before.signature);
        assert_eq!(signature.signature_size, before.signature_size);
    }

    unsafe {
        bitcoin_pqc_keypair_free(&mut keypair);
    }
}

#[test]
fn c_api_free_is_idempotent_and_reuse_after_free_succeeds() {
    let entropy = entropy(MIN_ENTROPY_SIZE, 0x51);
    let mut keypair = empty_keypair();
    assert_c_keygen(&mut keypair, &entropy);

    unsafe {
        bitcoin_pqc_keypair_free(&mut keypair);
        assert!(keypair_is_empty(&keypair));
        bitcoin_pqc_keypair_free(&mut keypair);
        assert!(keypair_is_empty(&keypair));
    }

    assert_c_keygen(&mut keypair, &entropy);

    let message = b"reuse after free";
    let mut signature = empty_signature();
    let sign_rc = unsafe {
        bitcoin_pqc_sign(
            keypair.secret_key.cast(),
            keypair.secret_key_size,
            message.as_ptr(),
            message.len(),
            &mut signature,
        )
    };
    assert_eq!(sign_rc, BITCOIN_PQC_OK);

    unsafe {
        bitcoin_pqc_signature_free(&mut signature);
        assert!(signature_is_empty(&signature));
        bitcoin_pqc_signature_free(&mut signature);
        assert!(signature_is_empty(&signature));
    }

    let sign_rc = unsafe {
        bitcoin_pqc_sign(
            keypair.secret_key.cast(),
            keypair.secret_key_size,
            message.as_ptr(),
            message.len(),
            &mut signature,
        )
    };
    assert_eq!(sign_rc, BITCOIN_PQC_OK);

    unsafe {
        bitcoin_pqc_signature_free(&mut signature);
        bitcoin_pqc_keypair_free(&mut keypair);
    }
}

#[test]
fn keygen_uses_entropy_bytes_after_sphincs_seed_length() {
    for (len, mutation_index) in [(128, 48), (128, 127), (160, 159)] {
        let base_entropy = entropy(len, 0x61);
        let mut mutated_entropy = base_entropy.clone();
        mutated_entropy[mutation_index] ^= 0x80;

        let keypair = generate_keypair(&base_entropy).expect("base keygen should succeed");
        let repeated_keypair =
            generate_keypair(&base_entropy).expect("repeat keygen should succeed");
        let mutated_keypair =
            generate_keypair(&mutated_entropy).expect("mutated keygen should succeed");

        assert_eq!(
            keypair, repeated_keypair,
            "same full entropy input should reproduce keypair"
        );
        assert_ne!(
            keypair, mutated_keypair,
            "mutation at byte {mutation_index} of {len} should change keypair"
        );
    }
}

#[test]
fn rust_empty_message_behavior_still_matches_c_signature_size() {
    let keypair = generate_keypair(&entropy(MIN_ENTROPY_SIZE, 0x71)).unwrap();
    let signature = sign(&keypair.secret_key, &[]).unwrap();
    assert_eq!(signature.bytes.len(), signature_size());
}
