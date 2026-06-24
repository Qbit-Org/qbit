#![cfg(feature = "test-bench-env-knobs")]

use std::env;
use std::process::Command;

use bitcoinpqc::{generate_keypair, sign, verify, PublicKey, Signature};

const MIN_ENTROPY_LEN: usize = 128;
const DEFAULT_DIFFERENTIAL_CASES: u8 = 10;
const MAX_DIFFERENTIAL_CASES: u8 = 10;

#[derive(Clone, Copy, PartialEq, Eq)]
enum BackendMode {
    Auto,
    Scalar,
    X86,
    CommonCrypto,
}

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

fn differential_case_count() -> u8 {
    match env::var("BACKEND_DIFFERENTIAL_CASES") {
        Ok(raw) => {
            let cases = raw
                .parse::<u8>()
                .expect("BACKEND_DIFFERENTIAL_CASES must be a u8");
            assert!(
                (1..=MAX_DIFFERENTIAL_CASES).contains(&cases),
                "BACKEND_DIFFERENTIAL_CASES must be between 1 and {MAX_DIFFERENTIAL_CASES}"
            );
            cases
        }
        Err(_) => DEFAULT_DIFFERENTIAL_CASES,
    }
}

fn backend_name(mode: BackendMode) -> &'static str {
    match mode {
        BackendMode::Auto => "auto",
        BackendMode::Scalar => "scalar",
        BackendMode::X86 => "x86",
        BackendMode::CommonCrypto => "commoncrypto",
    }
}

fn backend_available(mode: BackendMode) -> bool {
    match mode {
        BackendMode::Auto | BackendMode::Scalar => true,
        // x86 SHA-NI excluded on Apple (sha2_x86_shani.c:6)
        BackendMode::X86 => cfg!(target_arch = "x86_64") && !cfg!(target_os = "macos"),
        BackendMode::CommonCrypto => cfg!(target_os = "macos"),
    }
}

fn clear_backend_env(cmd: &mut Command) {
    for name in [
        "SPX_DISABLE_SHA_ACCEL",
        "SPX_DISABLE_SIMD",
        "SPX_OPT_PROFILE",
        "SPX_SHA_BACKEND",
        "SPX_FORS_THREADS",
    ] {
        cmd.env_remove(name);
    }
}

fn apply_backend_env(cmd: &mut Command, mode: BackendMode) {
    clear_backend_env(cmd);

    match mode {
        BackendMode::Auto => {
            cmd.env("SPX_SHA_BACKEND", "auto");
        }
        BackendMode::Scalar => {
            cmd.env("SPX_DISABLE_SIMD", "1");
            cmd.env("SPX_SHA_BACKEND", "scalar");
        }
        BackendMode::X86 => {
            cmd.env("SPX_SHA_BACKEND", "x86");
        }
        BackendMode::CommonCrypto => {
            cmd.env("SPX_SHA_BACKEND", "commoncrypto");
        }
    }
}

fn extract_line(output: &str, prefix: &str) -> String {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix).map(ToString::to_string))
        .unwrap_or_else(|| panic!("missing line with prefix `{prefix}` in output:\n{output}"))
}

fn run_sign_helper(mode: BackendMode, seed: u8, message: &[u8]) -> (String, String) {
    let mut command = Command::new("cargo");
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "test",
            "--color",
            "never",
            "--test",
            "backend_differential_tests",
            "--features",
            "test-bench-env-knobs",
            "backend_sign_helper",
            "--",
            "--ignored",
            "--nocapture",
        ])
        .env("BACKEND_HELPER_MODE", "sign")
        .env("BACKEND_TEST_SEED", seed.to_string())
        .env("BACKEND_TEST_MSG_HEX", hex::encode(message));
    apply_backend_env(&mut command, mode);

    let output = command.output().expect("failed to run backend sign helper");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        output.status.success(),
        "backend sign helper failed:\n{combined}"
    );

    let payload = extract_line(&combined, "BACKEND_SIGN_RESULT:");
    let mut fields = payload.split(':');
    let pk = fields
        .next()
        .expect("missing public key field in helper output")
        .to_string();
    let sig = fields
        .next()
        .expect("missing signature field in helper output")
        .to_string();
    assert!(
        fields.next().is_none(),
        "unexpected extra fields in helper output"
    );
    (pk, sig)
}

fn run_verify_helper(mode: BackendMode, pk_hex: &str, message: &[u8], sig_hex: &str) -> bool {
    let mut command = Command::new("cargo");
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "test",
            "--color",
            "never",
            "--test",
            "backend_differential_tests",
            "--features",
            "test-bench-env-knobs",
            "backend_sign_helper",
            "--",
            "--ignored",
            "--nocapture",
        ])
        .env("BACKEND_HELPER_MODE", "verify")
        .env("BACKEND_VERIFY_PK_HEX", pk_hex)
        .env("BACKEND_VERIFY_MSG_HEX", hex::encode(message))
        .env("BACKEND_VERIFY_SIG_HEX", sig_hex);
    apply_backend_env(&mut command, mode);

    let output = command
        .output()
        .expect("failed to run backend verify helper");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        output.status.success(),
        "backend verify helper failed:\n{combined}"
    );

    extract_line(&combined, "BACKEND_VERIFY_RESULT:") == "ok"
}

#[test]
fn backend_scalar_vs_auto_deterministic() {
    for i in 0..differential_case_count() {
        let msg_len = 32 + (i as usize * 97) % 4096;
        let message = deterministic_bytes(msg_len, 0x31u8.wrapping_add(i));
        let seed = 0x41u8.wrapping_add(i);

        let (pk_scalar, sig_scalar) = run_sign_helper(BackendMode::Scalar, seed, &message);
        let (pk_auto, sig_auto) = run_sign_helper(BackendMode::Auto, seed, &message);

        assert_eq!(
            pk_scalar, pk_auto,
            "public keys should match across backend selection (msg {i})"
        );
        assert_eq!(
            sig_scalar, sig_auto,
            "signatures should be byte-identical across scalar/auto backends (msg {i})"
        );
    }
}

#[test]
fn backend_scalar_sign_auto_verify() {
    for i in 0..differential_case_count() {
        let msg_len = 64 + (i as usize * 83) % 2048;
        let message = deterministic_bytes(msg_len, 0x51u8.wrapping_add(i));
        let seed = 0x52u8.wrapping_add(i);

        let (pk_hex, sig_hex) = run_sign_helper(BackendMode::Scalar, seed, &message);
        assert!(
            run_verify_helper(BackendMode::Auto, &pk_hex, &message, &sig_hex),
            "auto backend should verify scalar-generated signature (msg {i})"
        );
    }
}

#[test]
fn backend_auto_sign_scalar_verify() {
    for i in 0..differential_case_count() {
        let msg_len = 128 + (i as usize * 71) % 2048;
        let message = deterministic_bytes(msg_len, 0x61u8.wrapping_add(i));
        let seed = 0x62u8.wrapping_add(i);

        let (pk_hex, sig_hex) = run_sign_helper(BackendMode::Auto, seed, &message);
        assert!(
            run_verify_helper(BackendMode::Scalar, &pk_hex, &message, &sig_hex),
            "scalar backend should verify auto-generated signature (msg {i})"
        );
    }
}

#[test]
fn backend_all_pairs_cross_verify() {
    let all_backends = [
        BackendMode::Scalar,
        BackendMode::Auto,
        BackendMode::X86,
        BackendMode::CommonCrypto,
    ];

    let available: Vec<BackendMode> = all_backends
        .iter()
        .copied()
        .filter(|b| backend_available(*b))
        .collect();

    // Need at least 2 backends for cross-verification
    if available.len() < 2 {
        return;
    }

    for i in 0..differential_case_count() {
        let msg_len = 50 + (i as usize * 61) % 2048;
        let message = deterministic_bytes(msg_len, 0xA0u8.wrapping_add(i));
        let seed = 0xB0u8.wrapping_add(i);

        // Sign with each available backend
        let results: Vec<(BackendMode, String, String)> = available
            .iter()
            .map(|&mode| {
                let (pk, sig) = run_sign_helper(mode, seed, &message);
                (mode, pk, sig)
            })
            .collect();

        // All public keys must match
        for pair in results.windows(2) {
            assert_eq!(
                pair[0].1,
                pair[1].1,
                "public key mismatch between {} and {} for msg {i}",
                backend_name(pair[0].0),
                backend_name(pair[1].0)
            );
        }

        // All signatures must be byte-identical (deterministic signing)
        for pair in results.windows(2) {
            assert_eq!(
                pair[0].2,
                pair[1].2,
                "signature mismatch between {} and {} for msg {i}",
                backend_name(pair[0].0),
                backend_name(pair[1].0)
            );
        }

        // Cross-verify: each backend verifies every other backend's signature
        for signer in &results {
            for &verifier_mode in &available {
                assert!(
                    run_verify_helper(verifier_mode, &signer.1, &message, &signer.2),
                    "{} should verify {}-signed signature for msg {i}",
                    backend_name(verifier_mode),
                    backend_name(signer.0)
                );
            }
        }
    }
}

#[test]
#[ignore = "Invoked by backend differential tests in a subprocess"]
fn backend_sign_helper() {
    let mode = env::var("BACKEND_HELPER_MODE").unwrap_or_else(|_| "sign".to_string());

    match mode.as_str() {
        "sign" => {
            let seed = env::var("BACKEND_TEST_SEED")
                .ok()
                .and_then(|v| v.parse::<u8>().ok())
                .expect("BACKEND_TEST_SEED must be a u8");
            let message_hex =
                env::var("BACKEND_TEST_MSG_HEX").expect("BACKEND_TEST_MSG_HEX must be set");
            let message = hex::decode(message_hex).expect("BACKEND_TEST_MSG_HEX must be valid hex");

            let keypair =
                generate_keypair(&deterministic_entropy(seed)).expect("keygen should succeed");
            let signature = sign(&keypair.secret_key, &message).expect("sign should succeed");
            println!(
                "BACKEND_SIGN_RESULT:{}:{}",
                hex::encode(&keypair.public_key.bytes),
                hex::encode(&signature.bytes)
            );
        }
        "verify" => {
            let pk_hex =
                env::var("BACKEND_VERIFY_PK_HEX").expect("BACKEND_VERIFY_PK_HEX must be set");
            let message_hex =
                env::var("BACKEND_VERIFY_MSG_HEX").expect("BACKEND_VERIFY_MSG_HEX must be set");
            let sig_hex =
                env::var("BACKEND_VERIFY_SIG_HEX").expect("BACKEND_VERIFY_SIG_HEX must be set");

            let public_key = PublicKey::from_str(&pk_hex).expect("invalid BACKEND_VERIFY_PK_HEX");
            let signature = Signature::from_str(&sig_hex).expect("invalid BACKEND_VERIFY_SIG_HEX");
            let message = hex::decode(message_hex).expect("invalid BACKEND_VERIFY_MSG_HEX");

            let result = verify(&public_key, &message, &signature).is_ok();
            println!(
                "BACKEND_VERIFY_RESULT:{}",
                if result { "ok" } else { "err" }
            );
        }
        _ => panic!("BACKEND_HELPER_MODE must be `sign` or `verify`"),
    }
}
