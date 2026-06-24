#![no_main]

use std::sync::OnceLock;

use bitcoinpqc::{
    test_wotsc_derive, test_wotsc_derive_with_limit, test_wotsc_hash_counter,
    test_wotsc_params, WotscDerivation, WotscParams,
};
use libfuzzer_sys::fuzz_target;

const ROOT_LABEL: [u8; 16] = *b"wotsc-invariant!";

struct Fixture {
    params: WotscParams,
    label_derivation: WotscDerivation,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let params = test_wotsc_params().expect("WOTS+C params helper should be available");
        let label_derivation =
            test_wotsc_derive(&ROOT_LABEL).expect("pinned WOTS+C derivation should succeed");
        Fixture {
            params,
            label_derivation,
        }
    })
}

fn read_counter(data: &[u8], offset: usize) -> u32 {
    let hi = data.get(offset).copied().unwrap_or(0) as u32;
    let lo = data.get(offset + 1).copied().unwrap_or(0) as u32;
    (hi << 8) | lo
}

fn root_from_data(data: &[u8], n: usize) -> Vec<u8> {
    if data.is_empty() {
        return vec![0; n];
    }

    (0..n)
        .map(|i| data[i % data.len()].wrapping_add((i as u8).rotate_left((i % 8) as u32)))
        .collect()
}

fn assert_derivation_invariants(params: WotscParams, derivation: &WotscDerivation) {
    assert_eq!(derivation.compressed_message.len(), params.n as usize);
    assert_eq!(derivation.chain_lengths.len(), params.len1 as usize);
    assert!(derivation.counter <= 0xFFFF);
    assert_eq!(derivation.checksum, params.target);

    let checksum = derivation
        .chain_lengths
        .iter()
        .map(|&length| {
            assert!(length < params.w);
            params.w - 1 - length
        })
        .sum::<u32>();
    assert_eq!(checksum, params.target);

    if params.logw == 8 {
        let lengths_from_compressed = derivation
            .compressed_message
            .iter()
            .map(|&byte| byte as u32)
            .collect::<Vec<_>>();
        assert_eq!(derivation.chain_lengths, lengths_from_compressed);
    }
}

fn exercise_root(params: WotscParams, root: &[u8], data: &[u8]) {
    let counter = read_counter(data, 0);
    let swapped_counter = ((counter & 0xFF) << 8) | (counter >> 8);

    let hashed = test_wotsc_hash_counter(root, counter)
        .expect("counter hash should accept valid root-sized input");
    assert_eq!(hashed.compressed_message.len(), params.n as usize);
    assert!(hashed.checksum <= params.len1 * (params.w - 1));

    let swapped = test_wotsc_hash_counter(root, swapped_counter)
        .expect("swapped counter hash should accept valid root-sized input");
    assert_eq!(swapped.compressed_message.len(), params.n as usize);
    assert!(swapped.checksum <= params.len1 * (params.w - 1));

    let limit = read_counter(data, 2) & 0x0FFF;
    if let Some(derived) = test_wotsc_derive_with_limit(root, limit) {
        assert!(derived.counter <= limit);
        assert_derivation_invariants(params, &derived);

        let selected = test_wotsc_hash_counter(root, derived.counter)
            .expect("selected counter hash should accept valid root-sized input");
        assert_eq!(selected.compressed_message, derived.compressed_message);
        assert_eq!(selected.checksum, params.target);

        if derived.counter > 0 {
            assert!(
                test_wotsc_derive_with_limit(root, derived.counter - 1).is_none(),
                "bounded search before selected counter should fail"
            );
        }
    }

    assert!(
        test_wotsc_hash_counter(root, 0x1_0000).is_none(),
        "counter helper should reject values outside the two-byte range"
    );
    assert!(
        test_wotsc_derive_with_limit(root, 0x1_0000).is_none(),
        "bounded derive helper should reject values outside the two-byte range"
    );
}

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let params = fixture.params;
    let n = params.n as usize;

    assert_derivation_invariants(params, &fixture.label_derivation);
    let selected = test_wotsc_hash_counter(&ROOT_LABEL, fixture.label_derivation.counter)
        .expect("pinned selected counter should hash");
    assert_eq!(
        selected.compressed_message,
        fixture.label_derivation.compressed_message
    );
    assert_eq!(selected.checksum, params.target);

    if fixture.label_derivation.counter > 0 {
        assert!(
            test_wotsc_derive_with_limit(&ROOT_LABEL, fixture.label_derivation.counter - 1)
                .is_none(),
            "pinned bounded search before selected counter should fail"
        );
    }

    let root = root_from_data(data, n);
    exercise_root(params, &root, data);

    let uniform = vec![data.first().copied().unwrap_or(0xA5); n];
    exercise_root(params, &uniform, data);

    let short_root = vec![0x5Au8; n.saturating_sub(1)];
    assert!(test_wotsc_hash_counter(&short_root, 0).is_none());
    assert!(test_wotsc_derive_with_limit(&short_root, 0).is_none());

    let mut long_root = root;
    long_root.push(data.get(4).copied().unwrap_or(0xC3));
    assert!(test_wotsc_hash_counter(&long_root, 0).is_none());
    assert!(test_wotsc_derive_with_limit(&long_root, 0).is_none());
});
