use bitcoinpqc as _;
use std::os::raw::{c_uint, c_ulonglong};

#[link(name = "bitcoinpqc", kind = "static")]
unsafe extern "C" {
    fn sha256(out: *mut u8, input: *const u8, inlen: usize);
    fn sha256_inc_init(state: *mut u8);
    fn sha256_inc_blocks(state: *mut u8, input: *const u8, inblocks: usize);
    fn sha256_inc_finalize(out: *mut u8, state: *mut u8, input: *const u8, inlen: usize);
    fn sha512(out: *mut u8, input: *const u8, inlen: usize);
    fn sha512_inc_init(state: *mut u8);
    fn sha512_inc_blocks(state: *mut u8, input: *const u8, inblocks: usize);
    fn sha512_inc_finalize(out: *mut u8, state: *mut u8, input: *const u8, inlen: usize);
    #[link_name = "SPX_ull_to_bytes"]
    fn spx_ull_to_bytes(out: *mut u8, outlen: c_uint, input: c_ulonglong);
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn sha256_oneshot(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        sha256(out.as_mut_ptr(), input.as_ptr(), input.len());
    }
    out
}

fn sha256_incremental(input: &[u8]) -> [u8; 32] {
    let mut state = [0u8; 40];
    let mut out = [0u8; 32];
    let blocks = input.len() / 64;
    let rem = input.len() % 64;

    unsafe {
        sha256_inc_init(state.as_mut_ptr());
        if blocks > 0 {
            sha256_inc_blocks(state.as_mut_ptr(), input.as_ptr(), blocks);
        }
        let tail = &input[(blocks * 64)..(blocks * 64 + rem)];
        sha256_inc_finalize(
            out.as_mut_ptr(),
            state.as_mut_ptr(),
            tail.as_ptr(),
            tail.len(),
        );
    }

    out
}

fn sha512_oneshot(input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    unsafe {
        sha512(out.as_mut_ptr(), input.as_ptr(), input.len());
    }
    out
}

fn sha512_incremental(input: &[u8]) -> [u8; 64] {
    let mut state = [0u8; 72];
    let mut out = [0u8; 64];
    let blocks = input.len() / 128;
    let rem = input.len() % 128;

    unsafe {
        sha512_inc_init(state.as_mut_ptr());
        if blocks > 0 {
            sha512_inc_blocks(state.as_mut_ptr(), input.as_ptr(), blocks);
        }
        let tail = &input[(blocks * 128)..(blocks * 128 + rem)];
        sha512_inc_finalize(
            out.as_mut_ptr(),
            state.as_mut_ptr(),
            tail.as_ptr(),
            tail.len(),
        );
    }

    out
}

#[test]
fn sha256_known_answer_vectors() {
    let vectors = [
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];

    for (input, expected_hex) in vectors {
        let digest = sha256_oneshot(input.as_bytes());
        assert_eq!(digest.as_slice(), hex_to_bytes(expected_hex));
    }
}

#[test]
fn sha256_incremental_matches_oneshot() {
    let mut msg = vec![0u8; 4096 + 37];
    for (i, byte) in msg.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(31).wrapping_add(7);
    }

    let one_shot = sha256_oneshot(&msg);
    let incremental = sha256_incremental(&msg);
    assert_eq!(one_shot, incremental);
}

#[test]
fn sha512_known_answer_vectors() {
    let vectors = [
        (
            "",
            concat!(
                "cf83e1357eefb8bdf1542850d66d8007",
                "d620e4050b5715dc83f4a921d36ce9ce",
                "47d0d13c5d85f2b0ff8318d2877eec2f",
                "63b931bd47417a81a538327af927da3e"
            ),
        ),
        (
            "abc",
            concat!(
                "ddaf35a193617abacc417349ae204131",
                "12e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd",
                "454d4423643ce80e2a9ac94fa54ca49f"
            ),
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
             hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            concat!(
                "8e959b75dae313da8cf4f72814fc143f",
                "8f7779c6eb9f7fa17299aeadb6889018",
                "501d289e4900f7e4331b99dec4b5433a",
                "c7d329eeb6dd26545e96e55b874be909"
            ),
        ),
    ];

    for (input, expected_hex) in vectors {
        let digest = sha512_oneshot(input.as_bytes());
        assert_eq!(digest.as_slice(), hex_to_bytes(expected_hex));
    }
}

#[test]
fn sha512_incremental_matches_oneshot() {
    let mut msg = vec![0u8; 8192 + 73];
    for (i, byte) in msg.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(43).wrapping_add(11);
    }

    let one_shot = sha512_oneshot(&msg);
    let incremental = sha512_incremental(&msg);
    assert_eq!(one_shot, incremental);
}

fn legacy_msglen_bytes(msglen: u64) -> [u8; 8] {
    [
        (msglen >> 56) as u8,
        (msglen >> 48) as u8,
        (msglen >> 40) as u8,
        (msglen >> 32) as u8,
        (msglen >> 24) as u8,
        (msglen >> 16) as u8,
        (msglen >> 8) as u8,
        msglen as u8,
    ]
}

fn helper_msglen_bytes(msglen: u64) -> [u8; 8] {
    let mut out = [0u8; 8];
    unsafe {
        spx_ull_to_bytes(out.as_mut_ptr(), 8, msglen as c_ulonglong);
    }
    out
}

#[test]
fn ull_to_bytes_matches_legacy_msglen_layout() {
    let edge_cases = [
        0u64,
        1u64,
        7u64,
        8u64,
        55u64,
        56u64,
        63u64,
        64u64,
        511u64,
        512u64,
        1024u64,
        u32::MAX as u64,
        (u32::MAX as u64) + 1,
        u64::MAX - 1,
        u64::MAX,
    ];

    for value in edge_cases {
        assert_eq!(helper_msglen_bytes(value), legacy_msglen_bytes(value));
    }

    // Deterministic corpus to catch accidental layout regressions.
    let mut x = 0x9e3779b97f4a7c15u64;
    for _ in 0..10_000 {
        assert_eq!(helper_msglen_bytes(x), legacy_msglen_bytes(x));
        x = x
            .wrapping_mul(6364136223846793005u64)
            .wrapping_add(1442695040888963407u64);
    }
}
