use std::ffi::c_void;
use std::ptr;

#[repr(C)]
struct BitcoinPqcKeypair {
    public_key: *mut c_void,
    secret_key: *mut c_void,
    public_key_size: usize,
    secret_key_size: usize,
}

#[repr(C)]
struct BitcoinPqcSignature {
    signature: *mut u8,
    signature_size: usize,
}

const OK: i32 = 0;
const BAD_ARG: i32 = -1;
const BAD_KEY: i32 = -2;
const BAD_SIGNATURE: i32 = -3;

#[link(name = "bitcoinpqc", kind = "static")]
unsafe extern "C" {
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

fn fixed_entropy() -> [u8; 128] {
    let mut entropy = [0u8; 128];
    for (i, byte) in entropy.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(17).wrapping_add(23);
    }
    entropy
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

unsafe fn generate_test_keypair() -> BitcoinPqcKeypair {
    let entropy = fixed_entropy();
    let mut keypair = empty_keypair();
    assert_eq!(
        bitcoin_pqc_keygen(&mut keypair, entropy.as_ptr(), entropy.len()),
        OK
    );
    assert!(!keypair.public_key.is_null());
    assert!(!keypair.secret_key.is_null());
    keypair
}

#[test]
fn c_api_accepts_zero_length_message_with_null_pointer() {
    unsafe {
        let mut keypair = generate_test_keypair();
        let mut signature = empty_signature();

        assert_eq!(
            bitcoin_pqc_sign(
                keypair.secret_key as *const u8,
                keypair.secret_key_size,
                ptr::null(),
                0,
                &mut signature,
            ),
            OK
        );
        assert_eq!(signature.signature_size, bitcoin_pqc_signature_size());
        assert!(!signature.signature.is_null());

        assert_eq!(
            bitcoin_pqc_verify(
                keypair.public_key as *const u8,
                keypair.public_key_size,
                ptr::null(),
                0,
                signature.signature,
                signature.signature_size,
            ),
            OK
        );

        bitcoin_pqc_signature_free(&mut signature);
        assert!(signature.signature.is_null());
        assert_eq!(signature.signature_size, 0);
        bitcoin_pqc_signature_free(&mut signature);
        assert!(signature.signature.is_null());
        assert_eq!(signature.signature_size, 0);

        bitcoin_pqc_keypair_free(&mut keypair);
        assert!(keypair.public_key.is_null());
        assert!(keypair.secret_key.is_null());
        assert_eq!(keypair.public_key_size, 0);
        assert_eq!(keypair.secret_key_size, 0);
        bitcoin_pqc_keypair_free(&mut keypair);
        assert!(keypair.public_key.is_null());
        assert!(keypair.secret_key.is_null());
    }
}

#[test]
fn c_api_rejects_invalid_key_and_signature_sizes() {
    unsafe {
        let mut keypair = generate_test_keypair();
        let message = b"c api invalid size coverage";
        let mut signature = empty_signature();

        assert_eq!(
            bitcoin_pqc_sign(
                keypair.secret_key as *const u8,
                keypair.secret_key_size,
                message.as_ptr(),
                message.len(),
                &mut signature,
            ),
            OK
        );

        let mut rejected_signature = empty_signature();
        assert_eq!(
            bitcoin_pqc_sign(
                keypair.secret_key as *const u8,
                keypair.secret_key_size - 1,
                message.as_ptr(),
                message.len(),
                &mut rejected_signature,
            ),
            BAD_KEY
        );
        assert!(rejected_signature.signature.is_null());
        assert_eq!(rejected_signature.signature_size, 0);

        assert_eq!(
            bitcoin_pqc_verify(
                keypair.public_key as *const u8,
                keypair.public_key_size - 1,
                message.as_ptr(),
                message.len(),
                signature.signature,
                signature.signature_size,
            ),
            BAD_KEY
        );

        assert_eq!(
            bitcoin_pqc_verify(
                keypair.public_key as *const u8,
                keypair.public_key_size,
                message.as_ptr(),
                message.len(),
                signature.signature,
                signature.signature_size - 1,
            ),
            BAD_SIGNATURE
        );

        bitcoin_pqc_signature_free(&mut signature);
        bitcoin_pqc_keypair_free(&mut keypair);
    }
}

#[test]
fn c_api_verify_fails_closed_for_malformed_inputs() {
    unsafe {
        let mut keypair = generate_test_keypair();
        let message = b"c api verify fail closed";
        let mut signature = empty_signature();

        assert_eq!(
            bitcoin_pqc_sign(
                keypair.secret_key as *const u8,
                keypair.secret_key_size,
                message.as_ptr(),
                message.len(),
                &mut signature,
            ),
            OK
        );

        let public_key = keypair.public_key as *const u8;
        let signature_bytes =
            std::slice::from_raw_parts(signature.signature, signature.signature_size);

        assert_eq!(
            bitcoin_pqc_verify(
                public_key,
                keypair.public_key_size,
                message.as_ptr(),
                message.len(),
                signature.signature,
                signature.signature_size,
            ),
            OK
        );

        assert_eq!(
            bitcoin_pqc_verify(
                ptr::null(),
                keypair.public_key_size,
                message.as_ptr(),
                message.len(),
                signature.signature,
                signature.signature_size,
            ),
            BAD_ARG
        );
        assert_eq!(
            bitcoin_pqc_verify(
                public_key,
                keypair.public_key_size,
                ptr::null(),
                message.len(),
                signature.signature,
                signature.signature_size,
            ),
            BAD_ARG
        );
        assert_eq!(
            bitcoin_pqc_verify(
                public_key,
                keypair.public_key_size,
                message.as_ptr(),
                message.len(),
                ptr::null(),
                signature.signature_size,
            ),
            BAD_ARG
        );

        assert_eq!(
            bitcoin_pqc_verify(
                public_key,
                0,
                message.as_ptr(),
                message.len(),
                signature.signature,
                signature.signature_size,
            ),
            BAD_KEY
        );
        assert_eq!(
            bitcoin_pqc_verify(
                public_key,
                keypair.public_key_size - 1,
                message.as_ptr(),
                message.len(),
                signature.signature,
                signature.signature_size,
            ),
            BAD_KEY
        );
        let oversized_public_key = vec![0x42u8; keypair.public_key_size + 1];
        assert_eq!(
            bitcoin_pqc_verify(
                oversized_public_key.as_ptr(),
                oversized_public_key.len(),
                message.as_ptr(),
                message.len(),
                signature.signature,
                signature.signature_size,
            ),
            BAD_KEY
        );

        assert_eq!(
            bitcoin_pqc_verify(
                public_key,
                keypair.public_key_size,
                message.as_ptr(),
                message.len(),
                signature.signature,
                0,
            ),
            BAD_SIGNATURE
        );
        assert_eq!(
            bitcoin_pqc_verify(
                public_key,
                keypair.public_key_size,
                message.as_ptr(),
                message.len(),
                signature.signature,
                signature.signature_size - 1,
            ),
            BAD_SIGNATURE
        );
        let mut oversized_signature = signature_bytes.to_vec();
        oversized_signature.push(0x42);
        assert_eq!(
            bitcoin_pqc_verify(
                public_key,
                keypair.public_key_size,
                message.as_ptr(),
                message.len(),
                oversized_signature.as_ptr(),
                oversized_signature.len(),
            ),
            BAD_SIGNATURE
        );
        let malformed_signature = vec![0u8; signature.signature_size];
        assert_eq!(
            bitcoin_pqc_verify(
                public_key,
                keypair.public_key_size,
                message.as_ptr(),
                message.len(),
                malformed_signature.as_ptr(),
                malformed_signature.len(),
            ),
            BAD_SIGNATURE
        );

        bitcoin_pqc_signature_free(&mut signature);
        bitcoin_pqc_keypair_free(&mut keypair);
    }
}

#[test]
fn c_api_rejects_reused_or_nonzero_output_structs() {
    unsafe {
        let entropy = fixed_entropy();
        let mut keypair = empty_keypair();
        assert_eq!(
            bitcoin_pqc_keygen(&mut keypair, entropy.as_ptr(), entropy.len()),
            OK
        );

        let old_public_key = keypair.public_key;
        let old_secret_key = keypair.secret_key;
        assert_eq!(
            bitcoin_pqc_keygen(&mut keypair, entropy.as_ptr(), entropy.len()),
            BAD_ARG
        );
        assert_eq!(keypair.public_key, old_public_key);
        assert_eq!(keypair.secret_key, old_secret_key);

        let mut sentinel_key_byte = 0xA5u8;
        let sentinel_key_ptr = (&mut sentinel_key_byte as *mut u8).cast::<c_void>();
        let mut nonzero_keypair = BitcoinPqcKeypair {
            public_key: sentinel_key_ptr,
            secret_key: ptr::null_mut(),
            public_key_size: 0,
            secret_key_size: 0,
        };
        assert_eq!(
            bitcoin_pqc_keygen(&mut nonzero_keypair, entropy.as_ptr(), entropy.len()),
            BAD_ARG
        );
        assert_eq!(nonzero_keypair.public_key, sentinel_key_ptr);
        assert_eq!(sentinel_key_byte, 0xA5);

        let message = b"output ownership";
        let mut signature = empty_signature();
        assert_eq!(
            bitcoin_pqc_sign(
                keypair.secret_key as *const u8,
                keypair.secret_key_size,
                message.as_ptr(),
                message.len(),
                &mut signature,
            ),
            OK
        );

        let old_signature = signature.signature;
        assert_eq!(
            bitcoin_pqc_sign(
                keypair.secret_key as *const u8,
                keypair.secret_key_size,
                message.as_ptr(),
                message.len(),
                &mut signature,
            ),
            BAD_ARG
        );
        assert_eq!(signature.signature, old_signature);

        let mut sentinel_sig_byte = 0x5Au8;
        let sentinel_sig_ptr = &mut sentinel_sig_byte as *mut u8;
        let mut nonzero_signature = BitcoinPqcSignature {
            signature: sentinel_sig_ptr,
            signature_size: 1,
        };
        assert_eq!(
            bitcoin_pqc_sign(
                keypair.secret_key as *const u8,
                keypair.secret_key_size,
                message.as_ptr(),
                message.len(),
                &mut nonzero_signature,
            ),
            BAD_ARG
        );
        assert_eq!(nonzero_signature.signature, sentinel_sig_ptr);
        assert_eq!(nonzero_signature.signature_size, 1);
        assert_eq!(sentinel_sig_byte, 0x5A);

        bitcoin_pqc_signature_free(&mut signature);
        assert_eq!(
            bitcoin_pqc_sign(
                keypair.secret_key as *const u8,
                keypair.secret_key_size,
                message.as_ptr(),
                message.len(),
                &mut signature,
            ),
            OK
        );

        bitcoin_pqc_signature_free(&mut signature);
        bitcoin_pqc_keypair_free(&mut keypair);
    }
}
