#![cfg(all(feature = "test-helpers", not(feature = "test-bench-env-knobs")))]

use std::env;
use std::process::Command;

use bitcoinpqc::{generate_keypair, sign, verify};

const KNOBS: &[&str] = &[
    "SPX_DISABLE_SHA_ACCEL",
    "SPX_DISABLE_SIMD",
    "SPX_OPT_PROFILE",
    "SPX_SHA_BACKEND",
    "SPX_FORS_THREADS",
];

const SPX_SHA_BACKEND_SCALAR: i32 = 1;

extern "C" {
    fn bitcoin_pqc_test_runtime_env_knobs_enabled() -> i32;
    fn bitcoin_pqc_test_sha_backend_mode() -> i32;
    fn bitcoin_pqc_test_disable_sha_accel() -> i32;
    fn bitcoin_pqc_test_disable_simd() -> i32;
    fn bitcoin_pqc_test_profile_scalar() -> i32;
}

#[derive(Debug, PartialEq, Eq)]
struct RuntimePolicy {
    runtime_env_knobs_enabled: bool,
    sha_backend_mode: i32,
    disable_sha_accel: bool,
    disable_simd: bool,
    profile_scalar: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct HelperResult {
    public_key_hex: String,
    secret_key_hex: String,
    signature_hex: String,
    verify_ok: bool,
    tampered_rejected: bool,
    policy: RuntimePolicy,
}

fn deterministic_entropy() -> Vec<u8> {
    (0..128)
        .map(|i| 0x35u8.wrapping_add(((i * 41) % 251) as u8))
        .collect()
}

fn extract_line(output: &str, prefix: &str) -> String {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix).map(ToString::to_string))
        .unwrap_or_else(|| panic!("missing line with prefix `{prefix}` in output:\n{output}"))
}

fn parse_helper_result(output: &str) -> HelperResult {
    let payload = extract_line(output, "PRODUCTION_ENV_RESULT:");
    let fields: Vec<&str> = payload.split(':').collect();
    assert_eq!(
        fields.len(),
        10,
        "unexpected helper result field count in `{payload}`"
    );

    HelperResult {
        public_key_hex: fields[0].to_string(),
        secret_key_hex: fields[1].to_string(),
        signature_hex: fields[2].to_string(),
        verify_ok: fields[3] == "true",
        tampered_rejected: fields[4] == "true",
        policy: RuntimePolicy {
            runtime_env_knobs_enabled: fields[5] == "true",
            sha_backend_mode: fields[6]
                .parse()
                .expect("sha backend mode should be an integer"),
            disable_sha_accel: fields[7] == "true",
            disable_simd: fields[8] == "true",
            profile_scalar: fields[9] == "true",
        },
    }
}

fn run_helper(with_polluted_env: bool) -> HelperResult {
    let mut command = Command::new(env::current_exe().expect("current test binary path"));
    command
        .arg("production_env_knobs_helper")
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .env("PRODUCTION_ENV_HELPER", "1");

    for knob in KNOBS {
        command.env_remove(knob);
    }

    if with_polluted_env {
        command
            .env("SPX_DISABLE_SHA_ACCEL", "1")
            .env("SPX_DISABLE_SIMD", "1")
            .env("SPX_OPT_PROFILE", "scalar")
            .env("SPX_SHA_BACKEND", "arm")
            .env("SPX_FORS_THREADS", "8");
    }

    let output = command
        .output()
        .expect("failed to run production env helper");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        output.status.success(),
        "production env helper failed:\n{combined}"
    );

    parse_helper_result(&combined)
}

fn assert_production_policy(policy: &RuntimePolicy) {
    assert!(
        !policy.runtime_env_knobs_enabled,
        "production build must compile out runtime env knobs, including SPX_FORS_THREADS"
    );
    assert_eq!(
        policy.sha_backend_mode, SPX_SHA_BACKEND_SCALAR,
        "production build must ignore SPX_SHA_BACKEND and pin backend mode to scalar"
    );
    assert!(
        !policy.disable_sha_accel,
        "production build must ignore SPX_DISABLE_SHA_ACCEL and SPX_OPT_PROFILE=scalar"
    );
    assert!(
        !policy.disable_simd,
        "production build must ignore SPX_DISABLE_SIMD and SPX_OPT_PROFILE=scalar"
    );
    assert!(
        !policy.profile_scalar,
        "production build must ignore SPX_OPT_PROFILE=scalar"
    );
}

#[test]
fn production_build_ignores_runtime_crypto_env_knobs() {
    let baseline = run_helper(false);
    let polluted = run_helper(true);

    assert_production_policy(&baseline.policy);
    assert_production_policy(&polluted.policy);
    assert_eq!(
        baseline.policy, polluted.policy,
        "runtime crypto env knobs changed the compiled C backend policy in production mode"
    );
    assert_eq!(
        baseline, polluted,
        "production keygen/sign/verify results changed when runtime crypto env knobs were set"
    );
    assert!(baseline.verify_ok, "baseline signature should verify");
    assert!(
        baseline.tampered_rejected,
        "baseline tampered message should be rejected"
    );
}

#[test]
#[ignore = "Invoked by production_build_ignores_runtime_crypto_env_knobs in a subprocess"]
fn production_env_knobs_helper() {
    assert_eq!(
        env::var("PRODUCTION_ENV_HELPER").as_deref(),
        Ok("1"),
        "helper must be invoked by the parent test"
    );

    let keypair = generate_keypair(&deterministic_entropy()).expect("keygen should succeed");
    let message = b"production runtime env knob stability check";
    let signature = sign(&keypair.secret_key, message).expect("sign should succeed");
    let verify_ok = verify(&keypair.public_key, message, &signature).is_ok();
    let tampered_rejected = verify(&keypair.public_key, b"tampered message", &signature).is_err();
    let runtime_env_knobs_enabled = unsafe { bitcoin_pqc_test_runtime_env_knobs_enabled() != 0 };
    let sha_backend_mode = unsafe { bitcoin_pqc_test_sha_backend_mode() };
    let disable_sha_accel = unsafe { bitcoin_pqc_test_disable_sha_accel() != 0 };
    let disable_simd = unsafe { bitcoin_pqc_test_disable_simd() != 0 };
    let profile_scalar = unsafe { bitcoin_pqc_test_profile_scalar() != 0 };

    println!(
        "PRODUCTION_ENV_RESULT:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        hex::encode(&keypair.public_key.bytes),
        hex::encode(keypair.secret_key.as_secret_bytes()),
        hex::encode(&signature.bytes),
        verify_ok,
        tampered_rejected,
        runtime_env_knobs_enabled,
        sha_backend_mode,
        disable_sha_accel,
        disable_simd,
        profile_scalar
    );
}
