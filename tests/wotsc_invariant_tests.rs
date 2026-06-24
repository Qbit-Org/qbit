#![cfg(feature = "test-helpers")]

use bitcoinpqc::{
    generate_keypair, sign, sign_with_stats, signature_size,
    test_seed_keypair_with_prefilled_root_tail, test_wotsc_derive, test_wotsc_derive_with_limit,
    test_wotsc_hash_counter, test_wotsc_params, verify, KeyPair, PqcError, Signature, WotscParams,
};

const MIN_ENTROPY_LEN: usize = 128;
const ROOT_ZERO: [u8; 16] = [0u8; 16];
const ROOT_SEQ: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const ROOT_LABEL: [u8; 16] = *b"wotsc-invariant!";

fn deterministic_entropy(seed: u8) -> Vec<u8> {
    (0..MIN_ENTROPY_LEN)
        .map(|i| seed.wrapping_add(((i * 37) % 256) as u8))
        .collect()
}

fn deterministic_keypair(seed: u8) -> KeyPair {
    generate_keypair(&deterministic_entropy(seed)).expect("keygen should succeed")
}

fn params() -> WotscParams {
    test_wotsc_params().expect("WOTS+C params helper should be available")
}

fn signing_cap_overridden() -> bool {
    option_env!("BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS").is_some()
        || option_env!("BITCOINPQC_WOTSC_MAX_COUNTER").is_some()
}

fn assert_pinned_derivation(msg: &[u8], expected_counter: u32, expected_compressed: &[u8]) {
    let p = params();
    let derived = test_wotsc_derive(msg).expect("WOTS+C derivation should succeed");
    let expected_lengths = expected_compressed
        .iter()
        .map(|&value| value as u32)
        .collect::<Vec<_>>();

    assert_eq!(derived.counter, expected_counter);
    assert_eq!(derived.checksum, p.target);
    assert_eq!(derived.compressed_message, expected_compressed);
    assert_eq!(derived.chain_lengths, expected_lengths);

    let direct =
        test_wotsc_hash_counter(msg, expected_counter).expect("counter hash should succeed");
    assert_eq!(direct.checksum, p.target);
    assert_eq!(direct.compressed_message, expected_compressed);
}

fn wots_section_offsets(p: WotscParams) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut offset = (p.n + p.fors_bytes) as usize;
    let stride = (p.wots_bytes + p.auth_path_bytes) as usize;

    for _ in 0..p.d {
        offsets.push(offset);
        offset += stride;
    }

    assert_eq!(offset, p.signature_bytes as usize);
    offsets
}

#[test]
fn wotsc_target_matches_bounded30_profile() {
    let p = params();

    assert_eq!(p.n, 16);
    assert_eq!(p.w, 256);
    assert_eq!(p.logw, 8);
    assert_eq!(p.len1, 16);
    assert_eq!(p.len2, 2);
    assert_eq!(p.len, p.len1);
    assert_eq!(p.target, 2040);
    assert_eq!(p.wots_bytes, 256);
    assert_eq!(p.wots_pk_bytes, 256);
    assert_eq!(p.signature_bytes as usize, signature_size());
}

#[test]
fn seed_keygen_no_sign_mode_records_no_wotsc_layers() {
    let p = params();
    let (public_key, secret_key, keygen_stats) =
        test_seed_keypair_with_prefilled_root_tail(0xA5).expect("test seed keygen should succeed");

    assert_eq!(keygen_stats.forsc_attempts, 0);
    assert!(keygen_stats.wotsc_attempts.is_empty());
    assert_eq!(keygen_stats.wotsc_max_observed_attempts, 0);
    assert_eq!(keygen_stats.cap_exceeded, 0);

    if signing_cap_overridden() {
        return;
    }

    let message = b"keygen no-sign mode stats regression";
    let (signature, sign_stats) =
        sign_with_stats(&secret_key, message).expect("real signing should succeed");
    assert_eq!(sign_stats.wotsc_attempts.len(), p.d as usize);
    assert!(sign_stats
        .wotsc_attempts
        .iter()
        .all(|attempts| *attempts > 0));
    verify(&public_key, message, &signature).expect("signature should verify");
}

#[test]
fn seed_keygen_ignores_prefilled_root_tail() {
    let (public_key_a, secret_key_a, stats_a) = test_seed_keypair_with_prefilled_root_tail(0x00)
        .expect("first test seed keygen should succeed");
    let (public_key_b, secret_key_b, stats_b) = test_seed_keypair_with_prefilled_root_tail(0xFF)
        .expect("second test seed keygen should succeed");

    assert_eq!(public_key_a, public_key_b);
    assert_eq!(secret_key_a, secret_key_b);
    assert!(stats_a.wotsc_attempts.is_empty());
    assert!(stats_b.wotsc_attempts.is_empty());
}

#[test]
fn fixed_roots_have_stable_chain_lengths_and_counters() {
    assert_pinned_derivation(
        &ROOT_ZERO,
        0x0B36,
        &[
            0x1C, 0x36, 0xEC, 0x8C, 0xE4, 0x45, 0x6F, 0xE6, 0x5A, 0x6E, 0x51, 0xBC, 0xA4, 0x17,
            0xEB, 0x35,
        ],
    );
    assert_pinned_derivation(
        &ROOT_SEQ,
        0x08C3,
        &[
            0xC5, 0x29, 0xB3, 0x24, 0xE8, 0x0C, 0xF9, 0x4F, 0xD7, 0x75, 0xFE, 0x63, 0xAC, 0x3C,
            0x25, 0x3D,
        ],
    );
    assert_pinned_derivation(
        &ROOT_LABEL,
        0x017F,
        &[
            0x90, 0xE7, 0xAE, 0x8F, 0xB5, 0xB4, 0x0A, 0x1D, 0xBF, 0x80, 0xFC, 0x0C, 0x2E, 0x5E,
            0x73, 0x6E,
        ],
    );
}

#[test]
fn counter_search_selects_first_matching_counter() {
    let p = params();
    let derived = test_wotsc_derive(&ROOT_LABEL).expect("WOTS+C derivation should succeed");

    assert_eq!(derived.counter, 0x017F);
    assert!(derived.counter > 0);
    for counter in 0..derived.counter {
        let hashed =
            test_wotsc_hash_counter(&ROOT_LABEL, counter).expect("counter hash should succeed");
        assert_ne!(
            hashed.checksum, p.target,
            "counter {counter:#06x} matched before selected counter"
        );
    }

    let selected = test_wotsc_hash_counter(&ROOT_LABEL, derived.counter)
        .expect("selected counter hash should succeed");
    assert_eq!(selected.checksum, p.target);
}

#[test]
fn bounded_counter_failure_returns_none_without_abort() {
    let derived = test_wotsc_derive(&ROOT_LABEL).expect("WOTS+C derivation should succeed");

    assert_eq!(derived.counter, 0x017F);
    assert!(
        test_wotsc_derive_with_limit(&ROOT_LABEL, derived.counter - 1).is_none(),
        "bounded search ending before the first match should fail"
    );

    let at_limit = test_wotsc_derive_with_limit(&ROOT_LABEL, derived.counter)
        .expect("bounded search should succeed when the first match is in range");
    assert_eq!(at_limit, derived);

    assert!(
        test_wotsc_derive_with_limit(&ROOT_LABEL, 0x1_0000).is_none(),
        "test helper should reject counters outside the two-byte search range"
    );
}

#[test]
fn counter_byte_order_is_pinned_to_high_byte_first() {
    let high_byte_first =
        test_wotsc_hash_counter(&ROOT_LABEL, 0x1234).expect("counter hash should succeed");
    let swapped =
        test_wotsc_hash_counter(&ROOT_LABEL, 0x3412).expect("counter hash should succeed");

    assert_eq!(
        high_byte_first.compressed_message,
        [
            0x03, 0x86, 0x16, 0x34, 0xD3, 0x24, 0x20, 0x77, 0x9A, 0xF9, 0x07, 0xFD, 0x10, 0xDA,
            0x26, 0xA7,
        ]
    );
    assert_eq!(high_byte_first.checksum, 2369);
    assert_eq!(
        swapped.compressed_message,
        [
            0x48, 0xF3, 0x54, 0x3A, 0x87, 0x6F, 0x5A, 0x43, 0x3D, 0xF2, 0x31, 0x03, 0x74, 0x30,
            0x33, 0xC8,
        ]
    );
    assert_eq!(swapped.checksum, 2450);
    assert_ne!(high_byte_first, swapped);
}

#[test]
fn bounded30_wots_layout_omits_checksum_chains() {
    let p = params();
    let classic_wots_bytes = (p.len1 + p.len2) * p.n;

    assert_eq!(p.len, p.len1);
    assert_eq!(p.wots_bytes, p.len1 * p.n);
    assert_eq!(classic_wots_bytes, 288);
    assert_eq!(p.wots_bytes + (p.len2 * p.n), classic_wots_bytes);

    let bounded_layout = p.n + p.fors_bytes + p.d * (p.wots_bytes + p.auth_path_bytes);
    let classic_layout = p.n + p.fors_bytes + p.d * (classic_wots_bytes + p.auth_path_bytes);

    assert_eq!(bounded_layout, p.signature_bytes);
    assert_eq!(bounded_layout, 3680);
    assert_eq!(classic_layout, 3840);
    assert_eq!(p.signature_bytes as usize, signature_size());
}

#[test]
fn wots_section_mutations_are_rejected() {
    let p = params();
    let keypair = deterministic_keypair(0xA5);
    let message = b"wotsc-section-mutation";
    let signature = sign(&keypair.secret_key, message).expect("sign should succeed");

    verify(&keypair.public_key, message, &signature).expect("valid signature should verify");

    for (layer, offset) in wots_section_offsets(p).into_iter().enumerate() {
        let mut tampered = Signature {
            bytes: signature.bytes.clone(),
        };
        let mutated = offset + ((layer * 37) % p.wots_bytes as usize);
        tampered.bytes[mutated] ^= 0x80;

        assert_eq!(
            verify(&keypair.public_key, message, &tampered),
            Err(PqcError::BadSignature),
            "WOTS section mutation at layer {layer}, byte {mutated} should be rejected"
        );
    }
}

#[test]
fn root_like_wots_sections_are_rejected() {
    let p = params();
    let keypair = deterministic_keypair(0xC3);
    let message = b"wotsc-root-like-section";
    let signature = sign(&keypair.secret_key, message).expect("sign should succeed");

    verify(&keypair.public_key, message, &signature).expect("valid signature should verify");

    for (layer, offset) in wots_section_offsets(p).into_iter().enumerate() {
        let mut tampered = Signature {
            bytes: signature.bytes.clone(),
        };
        let root_like = &signature.bytes[..p.n as usize];
        for chain in 0..p.len1 as usize {
            let start = offset + chain * p.n as usize;
            let end = start + p.n as usize;
            tampered.bytes[start..end].copy_from_slice(root_like);
        }

        assert_eq!(
            verify(&keypair.public_key, message, &tampered),
            Err(PqcError::BadSignature),
            "root-like WOTS section at layer {layer} should be rejected"
        );
    }
}
