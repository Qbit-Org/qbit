#![no_main]

use bitcoinpqc::{PublicKey, SecretKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split input so we always exercise both public and secret key parsing paths.
    let midpoint = data.len() / 2;
    let public_key_data = &data[..midpoint];
    let secret_key_data = &data[midpoint..];

    let _ = PublicKey::try_from_slice(public_key_data);
    let _ = SecretKey::try_from_slice(secret_key_data);
});
