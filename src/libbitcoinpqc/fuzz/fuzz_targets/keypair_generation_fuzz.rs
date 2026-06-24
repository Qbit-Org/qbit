#![no_main]

use bitcoinpqc::generate_keypair;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 128 {
        // SLH-DSA key generation requires at least 128 bytes of entropy.
        return;
    }

    let _ = generate_keypair(data)
        .expect("SLH-DSA keypair generation failed with >=128 bytes of entropy");
});
