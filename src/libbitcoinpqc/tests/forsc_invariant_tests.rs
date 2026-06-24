#![cfg(feature = "test-helpers")]

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use bitcoinpqc::{
    generate_keypair, sign, signature_size, test_compressed_index, verify, KeyPair, PqcError,
};

const FORS_SIG_TREES: usize = 7;

extern "C" {
    fn bitcoin_pqc_test_message_to_indices(
        indices_out: *mut u32,
        mhash: *const u8,
        mhash_len: usize,
    ) -> i32;

    fn bitcoin_pqc_test_forsc_compressed_index(mhash: *const u8, mhash_len: usize) -> u32;

}

const MIN_ENTROPY_LEN: usize = 128;
const SPX_N: usize = 16;
const FORS_HEIGHT: usize = 16;
const FORS_TREES: usize = 8;
const HASH_BYTES_FOR_FORSC: usize = (FORS_HEIGHT * FORS_TREES + 7) / 8;
const SIGNATURE_R_LEN: usize = SPX_N;
const FORS_COMPRESSED_TREE_INDEX: usize = FORS_SIG_TREES;
const FORS_COMPRESSED_INDEX_BIT_OFFSET: usize = FORS_SIG_TREES * FORS_HEIGHT;
const FORS_TREE_SIG_BYTES: usize = (FORS_HEIGHT + 1) * SPX_N;
const FORS_SIGNATURE_BYTES: usize = FORS_SIG_TREES * FORS_TREE_SIG_BYTES;
const UNCOMPRESSED_FORS_BYTES: usize = FORS_TREES * FORS_TREE_SIG_BYTES;
const WOTS_LEN: usize = 16;
const WOTS_BYTES: usize = WOTS_LEN * SPX_N;
const HYPERTREE_LAYERS: usize = 5;
const FULL_HEIGHT: usize = 30;
const TREE_HEIGHT: usize = FULL_HEIGHT / HYPERTREE_LAYERS;
const TREE_AUTH_BYTES: usize = TREE_HEIGHT * SPX_N;
const BOUNDED30_SIGNATURE_BYTES: usize =
    SIGNATURE_R_LEN + FORS_SIGNATURE_BYTES + HYPERTREE_LAYERS * (WOTS_BYTES + TREE_AUTH_BYTES);
const UNCOMPRESSED_SIGNATURE_BYTES: usize =
    SIGNATURE_R_LEN + UNCOMPRESSED_FORS_BYTES + HYPERTREE_LAYERS * (WOTS_BYTES + TREE_AUTH_BYTES);
const GRIND_BYTE_COUNT: usize = 4;
const PR_SMOKE_MESSAGE_BYTES: usize = 4 * 1024;
const NIGHTLY_BENCHMARK_MESSAGE_BYTES: usize = 64 * 1024;
const PR_SMOKE_TIMEOUT_SECS: u64 = 30;

// We do not test the `ctr == 0` salt-grinding overflow path directly.
// Triggering it requires ~2^32 attempts, which is impractical in CI, and
// forcing it would require invasive hooks that add disproportionate complexity.

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

fn extract_fors_indices(m: &[u8; HASH_BYTES_FOR_FORSC]) -> [u32; FORS_TREES] {
    let mut indices = [0u32; FORS_TREES];
    let mut offset = 0usize;

    for index in &mut indices {
        for j in 0..FORS_HEIGHT {
            let bit = ((m[offset >> 3] >> (offset & 0x7)) & 1u8) as u32;
            *index ^= bit << j;
            offset += 1;
        }
    }

    indices
}

fn set_bit(m: &mut [u8; HASH_BYTES_FOR_FORSC], bit_index: usize) {
    m[bit_index >> 3] |= 1u8 << (bit_index & 0x7);
}

fn byte_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).filter(|(x, y)| x != y).count()
}

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn sign_and_verify_timed(keypair_seed: u8, message_len: usize, message_seed: u8) -> Duration {
    let _lock = test_lock();
    let keypair = deterministic_keypair(keypair_seed);
    let message = deterministic_bytes(message_len, message_seed);

    let start = Instant::now();
    let signature = sign(&keypair.secret_key, &message).expect("sign should succeed");
    let elapsed = start.elapsed();

    verify(&keypair.public_key, &message, &signature).expect("signature should verify");
    elapsed
}

#[test]
fn forsc_invariant_compressed_index_is_zero() {
    let _lock = test_lock();
    let keypair = deterministic_keypair(0x51);

    for i in 0..20usize {
        let message = deterministic_bytes(7 + (i * 31), i as u8);
        let signature = sign(&keypair.secret_key, &message).expect("sign should succeed");

        verify(&keypair.public_key, &message, &signature).expect("valid signature should verify");

        // Extract the actual compressed tree index via the full C pipeline
        let compressed_idx =
            test_compressed_index(&signature.bytes, &keypair.public_key.bytes, &message)
                .expect("compressed index extraction should succeed");
        assert_eq!(
            compressed_idx, 0,
            "compressed tree index must be 0 for message {i}, got {compressed_idx}"
        );

        let mut tampered = signature.clone();
        tampered.bytes[0] ^= 0x01;
        assert_eq!(
            verify(&keypair.public_key, &message, &tampered),
            Err(PqcError::BadSignature),
            "tampering grind byte should break verification"
        );
    }
}

#[test]
fn forsc_invariant_signature_layout_uses_k_minus_one_fors_trees() {
    let _lock = test_lock();

    assert_eq!(
        FORS_SIG_TREES,
        FORS_TREES - 1,
        "bounded30 FORS+C must sign k_sig = k - 1 trees"
    );
    assert_eq!(
        FORS_COMPRESSED_TREE_INDEX, 7,
        "the eighth FORS tree should be the compressed tree"
    );
    assert_eq!(
        FORS_COMPRESSED_INDEX_BIT_OFFSET, 112,
        "the compressed tree index should start after seven 16-bit FORS indices"
    );
    assert_eq!(HASH_BYTES_FOR_FORSC, 16, "bounded30 FORS hash is 128 bits");
    assert_eq!(
        FORS_TREE_SIG_BYTES, 272,
        "each FORS tree signature is one SK element plus a 16-node auth path"
    );
    assert_eq!(
        FORS_SIGNATURE_BYTES, 1904,
        "FORS+C signature should include only seven tree signatures"
    );
    assert_eq!(
        UNCOMPRESSED_FORS_BYTES, 2176,
        "an uncompressed eight-tree FORS signature would be larger"
    );
    assert_eq!(
        UNCOMPRESSED_FORS_BYTES - FORS_SIGNATURE_BYTES,
        FORS_TREE_SIG_BYTES,
        "bounded30 should omit exactly one FORS tree signature"
    );
    assert_eq!(
        signature_size(),
        BOUNDED30_SIGNATURE_BYTES,
        "public signature size should match the k_sig = k - 1 layout"
    );
    assert_eq!(
        signature_size() + FORS_TREE_SIG_BYTES,
        UNCOMPRESSED_SIGNATURE_BYTES,
        "adding the omitted tree would recreate the uncompressed layout"
    );

    let keypair = deterministic_keypair(0x54);
    let message = b"forsc-k-sig-layout";
    let signature = sign(&keypair.secret_key, message).expect("sign should succeed");
    verify(&keypair.public_key, message, &signature).expect("signature should verify");

    assert_eq!(
        signature.bytes.len(),
        BOUNDED30_SIGNATURE_BYTES,
        "actual signature should use the bounded30 FORS+C layout"
    );

    let r_range = 0..SIGNATURE_R_LEN;
    assert_eq!(signature.bytes[r_range.clone()].len(), SIGNATURE_R_LEN);

    let fors_start = r_range.end;
    let fors_end = fors_start + FORS_SIGNATURE_BYTES;
    assert_eq!(
        fors_end, 1920,
        "WOTS section should begin immediately after R plus seven FORS trees"
    );

    for tree_idx in 0..FORS_SIG_TREES {
        let tree_start = fors_start + tree_idx * FORS_TREE_SIG_BYTES;
        let sk_end = tree_start + SPX_N;
        let tree_end = tree_start + FORS_TREE_SIG_BYTES;

        assert_eq!(
            signature.bytes[tree_start..sk_end].len(),
            SPX_N,
            "FORS tree {tree_idx} should start with one SK element"
        );
        assert_eq!(
            signature.bytes[sk_end..tree_end].len(),
            FORS_HEIGHT * SPX_N,
            "FORS tree {tree_idx} should carry a 16-node auth path"
        );
    }

    assert_eq!(
        fors_end + FORS_TREE_SIG_BYTES,
        SIGNATURE_R_LEN + UNCOMPRESSED_FORS_BYTES,
        "an eighth FORS tree would shift the first WOTS section by one tree signature"
    );

    let layer_stride = WOTS_BYTES + TREE_AUTH_BYTES;
    let mut layer_start = fors_end;
    for layer_idx in 0..HYPERTREE_LAYERS {
        let wots_end = layer_start + WOTS_BYTES;
        let auth_end = wots_end + TREE_AUTH_BYTES;

        assert_eq!(
            signature.bytes[layer_start..wots_end].len(),
            WOTS_BYTES,
            "hypertree layer {layer_idx} should contain the bounded30 WOTS section"
        );
        assert_eq!(
            signature.bytes[wots_end..auth_end].len(),
            TREE_AUTH_BYTES,
            "hypertree layer {layer_idx} should contain a 6-node auth path"
        );

        layer_start += layer_stride;
    }

    assert_eq!(
        layer_start,
        signature.bytes.len(),
        "layout walk should consume the whole signature"
    );
}

#[test]
fn forsc_invariant_tamper_r_grind_bytes() {
    let _lock = test_lock();
    let keypair = deterministic_keypair(0x52);
    let message = b"forsc-grind-byte-tamper";
    let signature = sign(&keypair.secret_key, message).expect("sign should succeed");

    for i in 0..GRIND_BYTE_COUNT {
        let mut tampered = signature.clone();
        tampered.bytes[i] ^= 0x01;
        assert_eq!(
            verify(&keypair.public_key, message, &tampered),
            Err(PqcError::BadSignature),
            "tampering R grind byte {i} should fail verification"
        );
    }
}

#[test]
fn forsc_invariant_rejects_nonzero_recomputed_compressed_index() {
    let _lock = test_lock();
    let keypair = deterministic_keypair(0x55);
    let message = b"forsc-targeted-nonzero-compressed-index";
    let signature = sign(&keypair.secret_key, message).expect("sign should succeed");

    assert_eq!(
        test_compressed_index(&signature.bytes, &keypair.public_key.bytes, message),
        Some(0),
        "valid signatures must grind R until the compressed FORS tree index is zero"
    );
    verify(&keypair.public_key, message, &signature).expect("valid signature should verify");

    let mut selected = None;
    'search: for byte_idx in 0..SIGNATURE_R_LEN {
        for bit_idx in 0..8 {
            let mask = 1u8 << bit_idx;
            let mut tampered = signature.clone();
            tampered.bytes[byte_idx] ^= mask;

            let compressed_idx =
                test_compressed_index(&tampered.bytes, &keypair.public_key.bytes, message)
                    .expect("compressed index extraction should succeed");
            if compressed_idx != 0 {
                selected = Some((tampered, compressed_idx, byte_idx, mask));
                break 'search;
            }
        }
    }

    let (tampered, compressed_idx, byte_idx, mask) =
        selected.expect("should find an R mutation with a nonzero compressed index");
    assert_ne!(
        compressed_idx, 0,
        "selected mutation must target the FORS+C compressed-index rejection path"
    );
    assert_eq!(
        verify(&keypair.public_key, message, &tampered),
        Err(PqcError::BadSignature),
        "verification should reject R byte {byte_idx} mask {mask:#04x} because the recomputed compressed FORS tree index is {compressed_idx}"
    );
}

#[test]
fn forsc_invariant_replace_r_entirely() {
    let _lock = test_lock();
    let keypair = deterministic_keypair(0x53);
    let message = b"forsc-replace-r";
    let signature = sign(&keypair.secret_key, message).expect("sign should succeed");

    let mut replacement = deterministic_bytes(SIGNATURE_R_LEN, 0xA7);
    if replacement == signature.bytes[..SIGNATURE_R_LEN] {
        replacement[0] ^= 0x01;
    }

    let mut tampered = signature.clone();
    tampered.bytes[..SIGNATURE_R_LEN].copy_from_slice(&replacement);
    assert_eq!(
        verify(&keypair.public_key, message, &tampered),
        Err(PqcError::BadSignature),
        "replacing R should fail verification"
    );
}

#[test]
fn salt_grinding_many_messages_all_verify() {
    let _lock = test_lock();
    let keypair = deterministic_keypair(0x61);

    for i in 0..100usize {
        let message_len = (i * 41) % 4096;
        let message = deterministic_bytes(message_len, (i as u8).wrapping_mul(13));
        let signature = sign(&keypair.secret_key, &message).expect("sign should succeed");
        verify(&keypair.public_key, &message, &signature)
            .expect("signature should verify for each message");
    }
}

#[test]
fn salt_grinding_pr_smoke_guard() {
    let elapsed = sign_and_verify_timed(0x62, PR_SMOKE_MESSAGE_BYTES, 0x33);

    assert!(
        elapsed < Duration::from_secs(PR_SMOKE_TIMEOUT_SECS),
        "signing took too long: {elapsed:?}"
    );
}

#[test]
#[ignore = "Nightly benchmark: 64 KiB FORS+C salt-grinding runtime"]
fn salt_grinding_64kb_benchmark() {
    let elapsed = sign_and_verify_timed(0x62, NIGHTLY_BENCHMARK_MESSAGE_BYTES, 0x33);
    println!(
        "64 KiB FORS+C salt-grinding sign+verify benchmark elapsed: {:?}",
        elapsed
    );
}

#[test]
fn bit_extraction_all_zeros() {
    let _lock = test_lock();
    let input = [0u8; HASH_BYTES_FOR_FORSC];
    let indices = extract_fors_indices(&input);
    assert_eq!(indices, [0u32; FORS_TREES]);
}

#[test]
fn bit_extraction_all_ones() {
    let _lock = test_lock();
    let input = [0xFFu8; HASH_BYTES_FOR_FORSC];
    let indices = extract_fors_indices(&input);
    assert_eq!(indices, [0xFFFFu32; FORS_TREES]);
}

#[test]
fn bit_extraction_alternating_55() {
    let _lock = test_lock();
    let input = [0x55u8; HASH_BYTES_FOR_FORSC];
    let indices = extract_fors_indices(&input);
    assert_eq!(indices, [0x5555u32; FORS_TREES]);
}

#[test]
fn bit_extraction_alternating_aa() {
    let _lock = test_lock();
    let input = [0xAAu8; HASH_BYTES_FOR_FORSC];
    let indices = extract_fors_indices(&input);
    assert_eq!(indices, [0xAAAAu32; FORS_TREES]);
}

#[test]
fn bit_extraction_single_bit_boundaries() {
    let _lock = test_lock();
    let cases = [
        (0usize, 0usize, 1u32 << 0),
        (15usize, 0usize, 1u32 << 15),
        (16usize, 1usize, 1u32 << 0),
        (111usize, 6usize, 1u32 << 15),
        (112usize, 7usize, 1u32 << 0),
        (127usize, 7usize, 1u32 << 15),
    ];

    for (bit_index, expected_index, expected_value) in cases {
        let mut input = [0u8; HASH_BYTES_FOR_FORSC];
        set_bit(&mut input, bit_index);
        let indices = extract_fors_indices(&input);

        for (idx, value) in indices.iter().enumerate() {
            if idx == expected_index {
                assert_eq!(
                    *value, expected_value,
                    "bit {bit_index} should map to index {expected_index}"
                );
            } else {
                assert_eq!(*value, 0, "bit {bit_index} should not affect index {idx}");
            }
        }
    }
}

#[test]
fn seed_cycling_determinism_across_calls() {
    let _lock = test_lock();
    let keypair = deterministic_keypair(0x71);
    let sizes = [0usize, 1, 16, 64, 255, 256, 1000, 4096, 65535, 1024 * 1024];

    for (i, size) in sizes.iter().enumerate() {
        let message = deterministic_bytes(*size, i as u8);
        let sig_a = sign(&keypair.secret_key, &message).expect("first sign should succeed");
        let sig_b = sign(&keypair.secret_key, &message).expect("second sign should succeed");

        assert_eq!(
            sig_a, sig_b,
            "same key+message should be deterministic for len {size}"
        );
        verify(&keypair.public_key, &message, &sig_a).expect("signature should verify");
    }
}

#[test]
fn seed_cycling_key_independence() {
    let _lock = test_lock();
    let message = deterministic_bytes(512, 0x81);
    let mut unique_signatures = HashSet::new();

    for seed in 0x80u8..0x85u8 {
        let keypair = deterministic_keypair(seed);
        let signature = sign(&keypair.secret_key, &message).expect("sign should succeed");
        verify(&keypair.public_key, &message, &signature).expect("signature should verify");
        unique_signatures.insert(signature.bytes);
    }

    assert_eq!(
        unique_signatures.len(),
        5,
        "different keys should produce distinct signatures for the same message"
    );
}

#[test]
fn seed_cycling_message_sensitivity() {
    let _lock = test_lock();
    let keypair = deterministic_keypair(0x91);
    let base_message = deterministic_bytes(512, 0x33);
    let mut variants = vec![base_message.clone(); 3];
    variants[0][0] ^= 0x01;
    variants[1][17] ^= 0x08;
    variants[2][255] ^= 0x80;

    let base_signature = sign(&keypair.secret_key, &base_message).expect("sign should succeed");
    verify(&keypair.public_key, &base_message, &base_signature).expect("signature should verify");

    let mut seen = HashSet::new();
    seen.insert(base_signature.bytes.clone());

    for variant in variants {
        let signature = sign(&keypair.secret_key, &variant).expect("sign should succeed");
        verify(&keypair.public_key, &variant, &signature).expect("signature should verify");

        assert_ne!(
            signature, base_signature,
            "single-bit message change should alter the signature"
        );
        assert!(
            byte_distance(&signature.bytes, &base_signature.bytes) > 128,
            "single-bit message change should alter many bytes in the signature"
        );
        seen.insert(signature.bytes);
    }

    assert_eq!(seen.len(), 4, "all variant signatures should be distinct");
}

// ---------------------------------------------------------------------------
// FFI tests: exercise the real C message_to_indices and forsc_compressed_index
// ---------------------------------------------------------------------------

#[test]
fn ffi_message_to_indices_known_patterns() {
    let _lock = test_lock();

    let cases: &[([u8; 16], [u32; FORS_SIG_TREES])] = &[
        ([0x00; 16], [0u32; FORS_SIG_TREES]),
        ([0xFF; 16], [0xFFFF; FORS_SIG_TREES]),
        ([0x55; 16], [0x5555; FORS_SIG_TREES]),
        ([0xAA; 16], [0xAAAA; FORS_SIG_TREES]),
    ];

    for (mhash, expected) in cases {
        let mut indices = [0u32; FORS_SIG_TREES];
        let rc = unsafe {
            bitcoin_pqc_test_message_to_indices(indices.as_mut_ptr(), mhash.as_ptr(), mhash.len())
        };
        assert_eq!(rc, 0, "FFI call should succeed");
        assert_eq!(
            &indices, expected,
            "FFI message_to_indices mismatch for pattern {:02x}",
            mhash[0]
        );

        // Cross-check: the first 7 trees of the Rust reimplementation should match
        let rust_indices = extract_fors_indices(mhash);
        assert_eq!(
            &indices[..],
            &rust_indices[..FORS_SIG_TREES],
            "FFI vs Rust mismatch for pattern {:02x}",
            mhash[0]
        );
    }
}

#[test]
fn ffi_message_to_indices_single_bit_boundaries() {
    let _lock = test_lock();

    // Bit positions at FORS tree boundaries within the first 7 trees
    let cases = [
        (0usize, 0usize, 1u32 << 0),    // bit 0 -> tree 0, bit 0
        (15usize, 0usize, 1u32 << 15),  // bit 15 -> tree 0, bit 15
        (16usize, 1usize, 1u32 << 0),   // bit 16 -> tree 1, bit 0
        (111usize, 6usize, 1u32 << 15), // bit 111 -> tree 6, bit 15
    ];

    for (bit_index, expected_tree, expected_value) in cases {
        let mut mhash = [0u8; 16];
        mhash[bit_index >> 3] |= 1u8 << (bit_index & 0x7);

        let mut indices = [0u32; FORS_SIG_TREES];
        let rc = unsafe {
            bitcoin_pqc_test_message_to_indices(indices.as_mut_ptr(), mhash.as_ptr(), mhash.len())
        };
        assert_eq!(rc, 0);

        for (idx, value) in indices.iter().enumerate() {
            if idx == expected_tree {
                assert_eq!(
                    *value, expected_value,
                    "bit {bit_index} should set tree {expected_tree} to {expected_value:#x}"
                );
            } else {
                assert_eq!(*value, 0, "bit {bit_index} should not affect tree {idx}");
            }
        }
    }
}

#[test]
fn ffi_forsc_compressed_index_known_patterns() {
    let _lock = test_lock();

    // All-zero mhash: compressed index (bits 112-127) should be 0
    let zeros = [0x00u8; 16];
    let idx = unsafe { bitcoin_pqc_test_forsc_compressed_index(zeros.as_ptr(), zeros.len()) };
    assert_eq!(idx, 0, "all-zero mhash should yield compressed index 0");

    // All-ones mhash: bits 112-127 are all 1 -> index 0xFFFF
    let ones = [0xFFu8; 16];
    let idx = unsafe { bitcoin_pqc_test_forsc_compressed_index(ones.as_ptr(), ones.len()) };
    assert_eq!(
        idx, 0xFFFF,
        "all-ones mhash should yield compressed index 0xFFFF"
    );

    // Bit 112 set: byte 14 bit 0 -> compressed index bit 0 -> value 1
    let mut bit112 = [0x00u8; 16];
    bit112[14] = 0x01;
    let idx = unsafe { bitcoin_pqc_test_forsc_compressed_index(bit112.as_ptr(), bit112.len()) };
    assert_eq!(idx, 1, "bit 112 should map to compressed index bit 0");

    // Bit 127 set: byte 15 bit 7 -> compressed index bit 15 -> value 0x8000
    let mut bit127 = [0x00u8; 16];
    bit127[15] = 0x80;
    let idx = unsafe { bitcoin_pqc_test_forsc_compressed_index(bit127.as_ptr(), bit127.len()) };
    assert_eq!(idx, 0x8000, "bit 127 should map to compressed index bit 15");

    // Cross-check: the Rust extract_fors_indices tree 7 matches forsc_compressed_index
    let patterns: &[[u8; 16]] = &[[0x00; 16], [0xFF; 16], [0x55; 16], [0xAA; 16]];
    for mhash in patterns {
        let c_idx = unsafe { bitcoin_pqc_test_forsc_compressed_index(mhash.as_ptr(), mhash.len()) };
        let rust_indices = extract_fors_indices(mhash);
        assert_eq!(
            c_idx, rust_indices[7],
            "C forsc_compressed_index should match Rust tree 7 for {:02x}",
            mhash[0]
        );
    }
}
