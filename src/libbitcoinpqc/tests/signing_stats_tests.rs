use bitcoinpqc::{generate_keypair, sign, sign_with_stats, verify, PqcError};

const DEFAULT_FORSC_MAX_ATTEMPTS: u32 = 1_835_008;
const FORSC_SUCCESS_DENOMINATOR: u32 = 65_536;
const FORSC_TARGET_EXPONENT: u32 = 28;
const SIGN_LIMIT_FORSC: u32 = 1;
const SIGN_LIMIT_WOTSC: u32 = 2;

fn entropy(seed: u8) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(((idx * 37) & 0xff) as u8);
    }
    bytes
}

fn expected_forsc_max_attempts() -> u32 {
    option_env!("BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS")
        .map(|value| {
            value
                .parse()
                .expect("BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS should fit in u32")
        })
        .unwrap_or(DEFAULT_FORSC_MAX_ATTEMPTS)
}

fn signing_cap_overridden() -> bool {
    option_env!("BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS").is_some()
        || option_env!("BITCOINPQC_WOTSC_MAX_COUNTER").is_some()
}

#[test]
fn sign_with_stats_reports_bounded30_grind_attempts() {
    let keypair = generate_keypair(&entropy(0x70)).expect("keygen should succeed");
    let message = b"signing stats contract";

    let (signature, stats) = match sign_with_stats(&keypair.secret_key, message) {
        Ok(result) => result,
        Err(err) if signing_cap_overridden() && err.error == PqcError::SigningLimitExceeded => {
            let stats = err
                .stats
                .expect("signing limit errors should include stats");
            assert_eq!(stats.forsc_max_attempts, expected_forsc_max_attempts());
            assert!(stats.limit_exceeded());
            return;
        }
        Err(err) => panic!("signing should succeed, got {err:?}"),
    };

    assert!(stats.forsc_attempts > 0);
    assert_eq!(stats.forsc_max_attempts, expected_forsc_max_attempts());
    assert!(stats.forsc_attempts <= stats.forsc_max_attempts);
    assert_eq!(stats.wotsc_attempts.len(), 5);
    assert!(stats.wotsc_attempts.iter().all(|attempts| *attempts > 0));
    assert!(stats
        .wotsc_attempts
        .iter()
        .all(|attempts| *attempts <= stats.wotsc_max_attempts));
    assert_eq!(
        stats.wotsc_max_observed_attempts,
        stats.wotsc_attempts.iter().copied().max().unwrap()
    );
    assert_eq!(stats.cap_exceeded, 0);
    assert!(!stats.limit_exceeded());

    verify(&keypair.public_key, message, &signature).expect("signature should verify");
}

#[test]
fn default_forsc_cap_matches_roughly_2_to_minus_40_failure_target() {
    assert_eq!(
        DEFAULT_FORSC_MAX_ATTEMPTS,
        FORSC_TARGET_EXPONENT * FORSC_SUCCESS_DENOMINATOR
    );

    let success_probability = 1.0f64 / f64::from(FORSC_SUCCESS_DENOMINATOR);
    let failure_probability = (1.0 - success_probability).powi(DEFAULT_FORSC_MAX_ATTEMPTS as i32);
    let failure_bits = -failure_probability.log2();
    let e_minus_28 = (-f64::from(FORSC_TARGET_EXPONENT)).exp();
    let relative_error = ((failure_probability - e_minus_28) / e_minus_28).abs();

    assert!((40.3..40.5).contains(&failure_bits));
    assert!(relative_error < 0.001);
}

#[test]
fn low_fors_cap_maps_to_signing_limit_error_when_compiled() {
    if option_env!("BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS") != Some("1") {
        return;
    }

    let keypair = generate_keypair(&entropy(0x71)).expect("keygen should succeed");
    for counter in 0u64..256 {
        let message = counter.to_le_bytes();
        match sign(&keypair.secret_key, &message) {
            Err(PqcError::SigningLimitExceeded) => return,
            Ok(_) => continue,
            Err(err) => panic!("expected signing limit error, got {err}"),
        }
    }

    panic!("cap=1 unexpectedly signed the deterministic corpus without a limit error");
}

#[test]
fn low_fors_cap_sign_with_stats_returns_error_stats_when_compiled() {
    if option_env!("BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS") != Some("1") {
        return;
    }

    let keypair = generate_keypair(&entropy(0x72)).expect("keygen should succeed");
    for counter in 0u64..256 {
        let message = counter.to_le_bytes();
        match sign_with_stats(&keypair.secret_key, &message) {
            Err(err) if err.error == PqcError::SigningLimitExceeded => {
                let stats = err
                    .stats
                    .expect("signing limit errors should include stats");
                assert!(stats.limit_exceeded());
                assert_ne!(stats.cap_exceeded & SIGN_LIMIT_FORSC, 0);
                assert_eq!(stats.forsc_attempts, stats.forsc_max_attempts);
                return;
            }
            Ok(_) => continue,
            Err(err) => panic!("expected signing limit error, got {err}"),
        }
    }

    panic!("FORS cap=1 unexpectedly signed the deterministic corpus without stats");
}

#[test]
fn low_wots_cap_maps_to_signing_limit_error_when_compiled() {
    if option_env!("BITCOINPQC_WOTSC_MAX_COUNTER") != Some("0") {
        return;
    }

    let keypair = generate_keypair(&entropy(0x72)).expect("keygen should succeed");
    for counter in 0u64..32 {
        let message = counter.to_le_bytes();
        match sign(&keypair.secret_key, &message) {
            Err(PqcError::SigningLimitExceeded) => return,
            Ok(_) => continue,
            Err(err) => panic!("expected signing limit error, got {err}"),
        }
    }

    panic!("WOTS cap=0 unexpectedly signed the deterministic corpus without a limit error");
}

#[test]
fn low_wots_cap_sign_with_stats_returns_error_stats_when_compiled() {
    if option_env!("BITCOINPQC_WOTSC_MAX_COUNTER") != Some("0") {
        return;
    }

    let keypair = generate_keypair(&entropy(0x73)).expect("keygen should succeed");
    for counter in 0u64..32 {
        let message = counter.to_le_bytes();
        match sign_with_stats(&keypair.secret_key, &message) {
            Err(err) if err.error == PqcError::SigningLimitExceeded => {
                let stats = err
                    .stats
                    .expect("signing limit errors should include stats");
                assert!(stats.limit_exceeded());
                assert_ne!(stats.cap_exceeded & SIGN_LIMIT_WOTSC, 0);
                assert!(stats.wotsc_attempts.iter().any(|attempts| *attempts > 0));
                return;
            }
            Ok(_) => continue,
            Err(err) => panic!("expected signing limit error, got {err}"),
        }
    }

    panic!("WOTS cap=0 unexpectedly signed the deterministic corpus without stats");
}
