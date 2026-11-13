#![cfg(feature = "test-bench-env-knobs")]

#[cfg(not(feature = "test-helpers"))]
compile_error!(
    "backend_differential_tests requires both `test-bench-env-knobs` and `test-helpers`; \
     rerun with `--features test-bench-env-knobs,test-helpers`"
);

use std::env;
use std::fmt;
use std::process::{Command, Output};
use std::sync::OnceLock;

use bitcoinpqc::{generate_keypair, sign, verify, PublicKey, Signature};

const MIN_ENTROPY_LEN: usize = 128;
const DEFAULT_DIFFERENTIAL_CASES: u8 = 10;
const MAX_DIFFERENTIAL_CASES: u8 = 10;
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SHA512_ABC: &str = concat!(
    "ddaf35a193617abacc417349ae204131",
    "12e6fa4e89a97ea20a9eeee64b55d39a",
    "2192992a274fc1a836ba3c23a3feebbd",
    "454d4423643ce80e2a9ac94fa54ca49f"
);

#[link(name = "bitcoinpqc", kind = "static")]
unsafe extern "C" {
    fn sha256(out: *mut u8, input: *const u8, inlen: usize);
    fn sha512(out: *mut u8, input: *const u8, inlen: usize);
    fn bitcoin_pqc_test_sha256_impl() -> i32;
    fn bitcoin_pqc_test_sha512_impl() -> i32;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackendMode {
    Auto,
    Scalar,
    X86,
    CommonCrypto,
}

impl BackendMode {
    const ALL: [Self; 4] = [Self::Scalar, Self::Auto, Self::X86, Self::CommonCrypto];

    fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Scalar => "scalar",
            Self::X86 => "x86",
            Self::CommonCrypto => "commoncrypto",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|mode| mode.name() == raw)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShaImplementation {
    Uninitialized,
    Scalar,
    X86ShaNi,
    ArmSha,
    CommonCrypto,
    Unknown(i32),
}

impl ShaImplementation {
    fn from_id(id: i32) -> Self {
        match id {
            0 => Self::Uninitialized,
            1 => Self::Scalar,
            2 => Self::X86ShaNi,
            3 => Self::ArmSha,
            4 => Self::CommonCrypto,
            other => Self::Unknown(other),
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "uninitialized" => Some(Self::Uninitialized),
            "scalar" => Some(Self::Scalar),
            "x86-sha-ni" => Some(Self::X86ShaNi),
            "arm-sha" => Some(Self::ArmSha),
            "commoncrypto" => Some(Self::CommonCrypto),
            _ => raw
                .strip_prefix("unknown(")
                .and_then(|value| value.strip_suffix(')'))
                .and_then(|value| value.parse::<i32>().ok())
                .map(Self::Unknown),
        }
    }

    fn is_initialized_and_known(self) -> bool {
        !matches!(self, Self::Uninitialized | Self::Unknown(_))
    }
}

impl fmt::Display for ShaImplementation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized => formatter.write_str("uninitialized"),
            Self::Scalar => formatter.write_str("scalar"),
            Self::X86ShaNi => formatter.write_str("x86-sha-ni"),
            Self::ArmSha => formatter.write_str("arm-sha"),
            Self::CommonCrypto => formatter.write_str("commoncrypto"),
            Self::Unknown(id) => write!(formatter, "unknown({id})"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BackendSelection {
    requested: BackendMode,
    sha256: ShaImplementation,
    sha512: ShaImplementation,
}

impl BackendSelection {
    fn supports_requested_backend(self) -> bool {
        match self.requested {
            BackendMode::Auto => {
                self.sha256.is_initialized_and_known() && self.sha512.is_initialized_and_known()
            }
            BackendMode::Scalar => {
                self.sha256 == ShaImplementation::Scalar && self.sha512 == ShaImplementation::Scalar
            }
            // bounded30 signs and verifies through SHA-256 only (SPX_SHA512=0),
            // and SHA-512 SHA-NI is far rarer than SHA-256 SHA-NI, so x86
            // coverage requires SHA-256 SHA-NI and accepts the scalar SHA-512
            // fallback. The SHA-512 selection is still reported.
            BackendMode::X86 => {
                self.sha256 == ShaImplementation::X86ShaNi
                    && matches!(
                        self.sha512,
                        ShaImplementation::X86ShaNi | ShaImplementation::Scalar
                    )
            }
            BackendMode::CommonCrypto => {
                self.sha256 == ShaImplementation::CommonCrypto
                    && self.sha512 == ShaImplementation::CommonCrypto
            }
        }
    }

    fn encoded(self) -> String {
        format!(
            "requested={}:sha256={}:sha512={}",
            self.requested.name(),
            self.sha256,
            self.sha512
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct BackendCapability {
    selection: BackendSelection,
    available: bool,
}

#[derive(Debug)]
struct SignResult {
    public_key: String,
    signature: String,
    selection: BackendSelection,
}

#[derive(Debug)]
struct VerifyResult {
    valid: bool,
    selection: BackendSelection,
}

static CAPABILITIES: OnceLock<Vec<BackendCapability>> = OnceLock::new();

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
    cmd.env("BACKEND_REQUESTED_MODE", mode.name());

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

fn helper_command(mode: BackendMode, operation: &str) -> Command {
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
            "test-bench-env-knobs,test-helpers",
            "backend_subprocess_helper",
            "--",
            "--ignored",
            "--nocapture",
        ])
        .env("BACKEND_HELPER_MODE", operation);
    apply_backend_env(&mut command, mode);
    command
}

fn run_helper(mut command: Command, description: &str) -> String {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("failed to run {description}: {error}"));
    successful_output(output, description)
}

fn successful_output(output: Output, description: &str) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(output.status.success(), "{description} failed:\n{combined}");
    combined
}

fn extract_line(output: &str, prefix: &str) -> String {
    let matches: Vec<_> = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix(prefix).map(ToString::to_string))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one line with prefix `{prefix}` in output:\n{output}"
    );
    matches.into_iter().next().expect("one matching line")
}

fn parse_selection(output: &str) -> BackendSelection {
    let payload = extract_line(output, "BACKEND_SELECTED:");
    let mut requested = None;
    let mut sha256_impl = None;
    let mut sha512_impl = None;

    for field in payload.split(':') {
        let (name, value) = field
            .split_once('=')
            .unwrap_or_else(|| panic!("malformed backend selection field `{field}`"));
        match name {
            "requested" => {
                assert!(requested.is_none(), "duplicate requested field");
                requested = Some(
                    BackendMode::parse(value)
                        .unwrap_or_else(|| panic!("unknown requested backend `{value}`")),
                );
            }
            "sha256" => {
                assert!(sha256_impl.is_none(), "duplicate sha256 field");
                sha256_impl = Some(
                    ShaImplementation::parse(value)
                        .unwrap_or_else(|| panic!("unknown SHA-256 implementation `{value}`")),
                );
            }
            "sha512" => {
                assert!(sha512_impl.is_none(), "duplicate sha512 field");
                sha512_impl = Some(
                    ShaImplementation::parse(value)
                        .unwrap_or_else(|| panic!("unknown SHA-512 implementation `{value}`")),
                );
            }
            _ => panic!("unknown backend selection field `{name}`"),
        }
    }

    BackendSelection {
        requested: requested.expect("missing requested field"),
        sha256: sha256_impl.expect("missing sha256 field"),
        sha512: sha512_impl.expect("missing sha512 field"),
    }
}

fn run_probe_helper(mode: BackendMode) -> BackendSelection {
    let output = run_helper(helper_command(mode, "probe"), "backend capability helper");
    let selection = parse_selection(&output);
    assert_eq!(
        selection.requested, mode,
        "capability helper reported a different requested backend"
    );
    selection
}

fn capabilities() -> &'static [BackendCapability] {
    CAPABILITIES.get_or_init(|| {
        BackendMode::ALL
            .iter()
            .copied()
            .map(|mode| {
                let selection = run_probe_helper(mode);
                let available = selection.supports_requested_backend();
                println!(
                    "BACKEND_CAPABILITY:{}:status={}",
                    selection.encoded(),
                    if available {
                        "available"
                    } else {
                        "unavailable"
                    }
                );
                BackendCapability {
                    selection,
                    available,
                }
            })
            .collect()
    })
}

fn capability(mode: BackendMode) -> BackendCapability {
    capabilities()
        .iter()
        .copied()
        .find(|capability| capability.selection.requested == mode)
        .expect("all backend modes must have capability results")
}

fn available_backend_modes() -> Vec<BackendMode> {
    capabilities()
        .iter()
        .filter(|capability| capability.available)
        .map(|capability| capability.selection.requested)
        .collect()
}

fn assert_operation_selection(
    actual: BackendSelection,
    expected: BackendSelection,
    operation: &str,
) {
    assert_eq!(
        actual, expected,
        "{operation} backend selection changed from the proven capability"
    );
}

fn run_sign_helper(mode: BackendMode, seed: u8, message: &[u8]) -> SignResult {
    let mut command = helper_command(mode, "sign");
    command
        .env("BACKEND_TEST_SEED", seed.to_string())
        .env("BACKEND_TEST_MSG_HEX", hex::encode(message));
    let output = run_helper(command, "backend sign helper");
    let selection = parse_selection(&output);

    let payload = extract_line(&output, "BACKEND_SIGN_RESULT:");
    let mut fields = payload.split(':');
    let result = SignResult {
        public_key: fields
            .next()
            .expect("missing public key field in helper output")
            .to_string(),
        signature: fields
            .next()
            .expect("missing signature field in helper output")
            .to_string(),
        selection,
    };
    assert!(
        fields.next().is_none(),
        "unexpected extra fields in helper output"
    );
    assert_operation_selection(result.selection, capability(mode).selection, "sign");
    result
}

fn run_verify_helper(
    mode: BackendMode,
    public_key: &str,
    message: &[u8],
    signature: &str,
) -> VerifyResult {
    let mut command = helper_command(mode, "verify");
    command
        .env("BACKEND_VERIFY_PK_HEX", public_key)
        .env("BACKEND_VERIFY_MSG_HEX", hex::encode(message))
        .env("BACKEND_VERIFY_SIG_HEX", signature);
    let output = run_helper(command, "backend verify helper");
    let selection = parse_selection(&output);

    let result = VerifyResult {
        valid: match extract_line(&output, "BACKEND_VERIFY_RESULT:").as_str() {
            "ok" => true,
            "err" => false,
            value => panic!("unknown backend verify result `{value}`"),
        },
        selection,
    };
    assert_operation_selection(result.selection, capability(mode).selection, "verify");
    result
}

fn exercise_sha2_dispatchers() {
    let input = b"abc";
    let mut sha256_digest = [0u8; 32];
    let mut sha512_digest = [0u8; 64];
    unsafe {
        sha256(sha256_digest.as_mut_ptr(), input.as_ptr(), input.len());
        sha512(sha512_digest.as_mut_ptr(), input.as_ptr(), input.len());
    }
    assert_eq!(hex::encode(sha256_digest), SHA256_ABC);
    assert_eq!(hex::encode(sha512_digest), SHA512_ABC);
}

fn observe_selection(requested: BackendMode) -> BackendSelection {
    BackendSelection {
        requested,
        sha256: ShaImplementation::from_id(unsafe { bitcoin_pqc_test_sha256_impl() }),
        sha512: ShaImplementation::from_id(unsafe { bitcoin_pqc_test_sha512_impl() }),
    }
}

fn print_selection(selection: BackendSelection) {
    println!("BACKEND_SELECTED:{}", selection.encoded());
}

#[test]
fn backend_introspection_is_passive() {
    let mode = BackendMode::Scalar;
    let output = run_helper(
        helper_command(mode, "introspect"),
        "passive backend introspection helper",
    );
    let selection = parse_selection(&output);
    assert_eq!(selection.requested, mode);
    assert_eq!(selection.sha256, ShaImplementation::Uninitialized);
    assert_eq!(selection.sha512, ShaImplementation::Uninitialized);
}

#[test]
fn backend_capabilities_are_reported() {
    let results = capabilities();
    assert!(
        capability(BackendMode::Scalar).available,
        "scalar must select the scalar implementation for both SHA variants"
    );
    assert!(
        capability(BackendMode::Auto).available,
        "auto must select known implementations for both SHA variants"
    );
    assert_eq!(results.len(), BackendMode::ALL.len());
}

#[test]
fn backend_required_coverage_policy() {
    let Ok(raw) = env::var("BACKEND_DIFFERENTIAL_REQUIRE") else {
        return;
    };
    let required = BackendMode::parse(&raw).unwrap_or_else(|| {
        panic!(
            "BACKEND_DIFFERENTIAL_REQUIRE must be one of `scalar`, `x86`, or `commoncrypto`; got `{raw}`"
        )
    });
    assert_ne!(
        required,
        BackendMode::Auto,
        "BACKEND_DIFFERENTIAL_REQUIRE must name a concrete implementation, not `auto`"
    );

    let required_capability = capability(required);
    assert!(
        required_capability.available,
        "required backend `{}` was unavailable: SHA-256 selected {}, SHA-512 selected {}",
        required.name(),
        required_capability.selection.sha256,
        required_capability.selection.sha512
    );
}

#[test]
fn backend_scalar_vs_auto_deterministic() {
    for i in 0..differential_case_count() {
        let msg_len = 32 + (i as usize * 97) % 4096;
        let message = deterministic_bytes(msg_len, 0x31u8.wrapping_add(i));
        let seed = 0x41u8.wrapping_add(i);

        let scalar = run_sign_helper(BackendMode::Scalar, seed, &message);
        let auto = run_sign_helper(BackendMode::Auto, seed, &message);

        assert_eq!(
            scalar.public_key, auto.public_key,
            "public keys should match across backend selection (msg {i})"
        );
        assert_eq!(
            scalar.signature, auto.signature,
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

        let signed = run_sign_helper(BackendMode::Scalar, seed, &message);
        assert!(
            run_verify_helper(
                BackendMode::Auto,
                &signed.public_key,
                &message,
                &signed.signature
            )
            .valid,
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

        let signed = run_sign_helper(BackendMode::Auto, seed, &message);
        assert!(
            run_verify_helper(
                BackendMode::Scalar,
                &signed.public_key,
                &message,
                &signed.signature
            )
            .valid,
            "scalar backend should verify auto-generated signature (msg {i})"
        );
    }
}

#[test]
fn backend_all_pairs_cross_verify() {
    let available = available_backend_modes();
    assert!(
        available.len() >= 2,
        "scalar and auto must always provide two backend modes"
    );

    for i in 0..differential_case_count() {
        let msg_len = 50 + (i as usize * 61) % 2048;
        let message = deterministic_bytes(msg_len, 0xA0u8.wrapping_add(i));
        let seed = 0xB0u8.wrapping_add(i);

        let results: Vec<_> = available
            .iter()
            .copied()
            .map(|mode| (mode, run_sign_helper(mode, seed, &message)))
            .collect();

        for pair in results.windows(2) {
            assert_eq!(
                pair[0].1.public_key,
                pair[1].1.public_key,
                "public key mismatch between {} and {} for msg {i}",
                pair[0].0.name(),
                pair[1].0.name()
            );
            assert_eq!(
                pair[0].1.signature,
                pair[1].1.signature,
                "signature mismatch between {} and {} for msg {i}",
                pair[0].0.name(),
                pair[1].0.name()
            );
        }

        for (signer_mode, signed) in &results {
            for verifier_mode in &available {
                assert!(
                    run_verify_helper(
                        *verifier_mode,
                        &signed.public_key,
                        &message,
                        &signed.signature
                    )
                    .valid,
                    "{} should verify {}-signed signature for msg {i}",
                    verifier_mode.name(),
                    signer_mode.name()
                );
            }
        }
    }
}

#[test]
#[ignore = "Invoked by backend differential tests in a subprocess"]
fn backend_subprocess_helper() {
    let requested_raw = env::var("BACKEND_REQUESTED_MODE")
        .expect("BACKEND_REQUESTED_MODE must be set by the parent test");
    let requested = BackendMode::parse(&requested_raw)
        .unwrap_or_else(|| panic!("unknown BACKEND_REQUESTED_MODE `{requested_raw}`"));
    let operation = env::var("BACKEND_HELPER_MODE").unwrap_or_else(|_| "sign".to_string());

    if operation == "introspect" {
        print_selection(observe_selection(requested));
        return;
    }

    exercise_sha2_dispatchers();

    match operation.as_str() {
        "probe" => {}
        "sign" => {
            let seed = env::var("BACKEND_TEST_SEED")
                .ok()
                .and_then(|value| value.parse::<u8>().ok())
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
            let public_key_hex =
                env::var("BACKEND_VERIFY_PK_HEX").expect("BACKEND_VERIFY_PK_HEX must be set");
            let message_hex =
                env::var("BACKEND_VERIFY_MSG_HEX").expect("BACKEND_VERIFY_MSG_HEX must be set");
            let signature_hex =
                env::var("BACKEND_VERIFY_SIG_HEX").expect("BACKEND_VERIFY_SIG_HEX must be set");

            let public_key =
                PublicKey::from_str(&public_key_hex).expect("invalid BACKEND_VERIFY_PK_HEX");
            let signature =
                Signature::from_str(&signature_hex).expect("invalid BACKEND_VERIFY_SIG_HEX");
            let message = hex::decode(message_hex).expect("invalid BACKEND_VERIFY_MSG_HEX");
            println!(
                "BACKEND_VERIFY_RESULT:{}",
                if verify(&public_key, &message, &signature).is_ok() {
                    "ok"
                } else {
                    "err"
                }
            );
        }
        _ => panic!("BACKEND_HELPER_MODE must be `introspect`, `probe`, `sign`, or `verify`"),
    }

    let selection = observe_selection(requested);
    assert!(
        selection.sha256.is_initialized_and_known(),
        "SHA-256 dispatcher was not initialized to a known implementation"
    );
    assert!(
        selection.sha512.is_initialized_and_known(),
        "SHA-512 dispatcher was not initialized to a known implementation"
    );
    print_selection(selection);
}
