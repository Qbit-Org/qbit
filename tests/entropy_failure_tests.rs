#![cfg(feature = "test-helpers")]

extern "C" {
    fn bitcoin_pqc_test_raw_slh_keypair_without_random_source() -> i32;
    fn bitcoin_pqc_test_raw_slh_sign_without_random_source() -> i32;
}

fn ensure_native_library_is_linked() {
    let _ = bitcoinpqc::public_key_size();
}

#[test]
fn raw_slh_keypair_without_entropy_does_not_report_success() {
    ensure_native_library_is_linked();

    let rc = unsafe { bitcoin_pqc_test_raw_slh_keypair_without_random_source() };
    assert_ne!(rc, 0, "raw SLH-DSA keypair must fail without entropy");
}

#[test]
fn raw_slh_sign_without_entropy_does_not_report_success() {
    ensure_native_library_is_linked();

    let rc = unsafe { bitcoin_pqc_test_raw_slh_sign_without_random_source() };
    assert_ne!(rc, 0, "raw SLH-DSA signing must fail without entropy");
}
