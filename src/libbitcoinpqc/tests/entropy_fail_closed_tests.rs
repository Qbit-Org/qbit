use std::ffi::c_void;
#[cfg(feature = "test-helpers")]
use std::os::raw::c_ulonglong;
use std::ptr;

use bitcoinpqc::{generate_keypair, sign, signature_size, verify};

#[cfg(feature = "test-helpers")]
use bitcoinpqc::{public_key_size, secret_key_size, Signature};

const BITCOIN_PQC_ERROR_BAD_ARG: i32 = -1;
const MIN_ENTROPY_SIZE: usize = 128;

#[repr(C)]
#[derive(Debug)]
struct BitcoinPqcKeypair {
    public_key: *mut c_void,
    secret_key: *mut c_void,
    public_key_size: usize,
    secret_key_size: usize,
}

extern "C" {
    fn bitcoin_pqc_keygen(
        keypair: *mut BitcoinPqcKeypair,
        random_data: *const u8,
        random_data_size: usize,
    ) -> i32;
}

#[cfg(feature = "test-helpers")]
extern "C" {
    fn bitcoin_pqc_test_randombytes_without_source(out: *mut u8, out_len: usize) -> i32;
    fn bitcoin_pqc_test_crypto_keypair_without_source(
        pk: *mut u8,
        pk_len: usize,
        sk: *mut u8,
        sk_len: usize,
    ) -> i32;
    fn bitcoin_pqc_test_crypto_signature_without_source(
        sig: *mut u8,
        sig_len: usize,
        actual_sig_len: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
        sk_len: usize,
    ) -> i32;
    fn bitcoin_pqc_test_crypto_combined_sign_without_source(
        sm: *mut u8,
        sm_len: usize,
        smlen: *mut c_ulonglong,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
        sk_len: usize,
    ) -> i32;
}

fn entropy(seed: u8) -> Vec<u8> {
    (0..MIN_ENTROPY_SIZE)
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

fn keypair_is_empty(keypair: &BitcoinPqcKeypair) -> bool {
    keypair.public_key.is_null()
        && keypair.secret_key.is_null()
        && keypair.public_key_size == 0
        && keypair.secret_key_size == 0
}

#[test]
fn exported_keygen_rejects_missing_entropy_without_key_output() {
    let mut keypair = empty_keypair();
    let rc = unsafe { bitcoin_pqc_keygen(&mut keypair, ptr::null(), 0) };
    assert_eq!(rc, BITCOIN_PQC_ERROR_BAD_ARG);
    assert!(keypair_is_empty(&keypair));

    let short_entropy = vec![0x7au8; MIN_ENTROPY_SIZE - 1];
    let rc =
        unsafe { bitcoin_pqc_keygen(&mut keypair, short_entropy.as_ptr(), short_entropy.len()) };
    assert_eq!(rc, BITCOIN_PQC_ERROR_BAD_ARG);
    assert!(keypair_is_empty(&keypair));
}

#[test]
fn deterministic_source_signs_empty_and_normal_messages() {
    let keypair = generate_keypair(&entropy(0x42)).expect("keygen should succeed");

    for message in [&[][..], b"normal deterministic message".as_slice()] {
        let signature_1 = sign(&keypair.secret_key, message).expect("sign should succeed");
        let signature_2 = sign(&keypair.secret_key, message).expect("repeat sign should succeed");

        assert_eq!(signature_1, signature_2);
        assert_eq!(signature_1.bytes.len(), signature_size());
        verify(&keypair.public_key, message, &signature_1).expect("signature should verify");
    }
}

#[cfg(feature = "test-helpers")]
#[test]
fn randombytes_without_active_source_fails_and_zeroes_output() {
    let mut out = [0xa5u8; 32];
    let rc = unsafe { bitcoin_pqc_test_randombytes_without_source(out.as_mut_ptr(), out.len()) };

    assert_ne!(rc, 0);
    assert!(out.iter().all(|&byte| byte == 0));
}

#[cfg(feature = "test-helpers")]
#[test]
fn direct_sphincs_keypair_without_random_source_fails_closed() {
    let mut public_key = vec![0xa5u8; public_key_size()];
    let mut secret_key = vec![0x5au8; secret_key_size()];

    let rc = unsafe {
        bitcoin_pqc_test_crypto_keypair_without_source(
            public_key.as_mut_ptr(),
            public_key.len(),
            secret_key.as_mut_ptr(),
            secret_key.len(),
        )
    };

    assert_ne!(rc, 0);
    assert!(public_key.iter().all(|&byte| byte == 0));
    assert!(secret_key.iter().all(|&byte| byte == 0));
}

#[cfg(feature = "test-helpers")]
#[test]
fn direct_sphincs_signature_without_random_source_fails_closed() {
    let keypair = generate_keypair(&entropy(0x43)).expect("keygen should succeed");
    let message = b"missing source must not yield a usable signature";
    let mut signature = vec![0xa5u8; signature_size()];
    let mut actual_sig_len = usize::MAX;
    let secret_key_bytes = keypair.secret_key.as_secret_bytes();

    let rc = unsafe {
        bitcoin_pqc_test_crypto_signature_without_source(
            signature.as_mut_ptr(),
            signature.len(),
            &mut actual_sig_len,
            message.as_ptr(),
            message.len(),
            secret_key_bytes.as_ptr(),
            secret_key_bytes.len(),
        )
    };

    assert_ne!(rc, 0);
    assert_eq!(actual_sig_len, 0);
    assert!(signature.iter().all(|&byte| byte == 0));

    let zero_signature =
        Signature::try_from_slice(&signature).expect("zero buffer has the signature length only");
    assert!(verify(&keypair.public_key, message, &zero_signature).is_err());
}

#[cfg(feature = "test-helpers")]
#[test]
fn direct_sphincs_combined_sign_without_random_source_fails_closed() {
    let keypair = generate_keypair(&entropy(0x44)).expect("keygen should succeed");
    let message = b"combined sign must propagate detached sign failure";
    let mut signed_message = vec![0xa5u8; signature_size() + message.len()];
    let mut signed_message_len = c_ulonglong::MAX;
    let secret_key_bytes = keypair.secret_key.as_secret_bytes();

    let rc = unsafe {
        bitcoin_pqc_test_crypto_combined_sign_without_source(
            signed_message.as_mut_ptr(),
            signed_message.len(),
            &mut signed_message_len,
            message.as_ptr(),
            message.len(),
            secret_key_bytes.as_ptr(),
            secret_key_bytes.len(),
        )
    };

    assert_ne!(rc, 0);
    assert_eq!(signed_message_len, 0);
    assert!(signed_message[..signature_size()]
        .iter()
        .all(|&byte| byte == 0));
    assert!(signed_message[signature_size()..]
        .iter()
        .all(|&byte| byte == 0xa5));
}
