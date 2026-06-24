#![no_main]

use libfuzzer_sys::fuzz_target;

use bitcoinpqc::{test_forsc_compressed_index, test_message_to_indices};

const SPX_FORS_MSG_BYTES: usize = 16;
const SPX_FORS_HEIGHT: u32 = 16;

fuzz_target!(|data: &[u8]| {
    if data.len() < SPX_FORS_MSG_BYTES {
        return;
    }

    let mhash = &data[..SPX_FORS_MSG_BYTES];
    let max_index = 1u32 << SPX_FORS_HEIGHT;

    // Exercise message_to_indices via FFI
    let indices = test_message_to_indices(mhash).expect("should not fail for valid 16-byte input");
    assert_eq!(indices.len(), 7);

    // Invariant: all indices must be < 2^FORS_HEIGHT
    for (i, &idx) in indices.iter().enumerate() {
        assert!(idx < max_index, "index {i} = {idx} exceeds 2^{SPX_FORS_HEIGHT}");
    }

    // Exercise forsc_compressed_index via FFI
    let compressed =
        test_forsc_compressed_index(mhash).expect("should not fail for valid 16-byte input");
    assert!(
        compressed < max_index,
        "compressed index {compressed} exceeds 2^{SPX_FORS_HEIGHT}"
    );

    // Cross-check: 7 indices + compressed index fully partition the 128-bit mhash.
    // Reconstruct the mhash from extracted values and verify bitwise equality.
    let mut reconstructed = [0u8; SPX_FORS_MSG_BYTES];
    let mut offset = 0usize;
    for &idx in indices.iter() {
        for j in 0..SPX_FORS_HEIGHT {
            let bit = (idx >> j) & 1;
            reconstructed[offset >> 3] |= (bit as u8) << (offset & 0x7);
            offset += 1;
        }
    }
    for j in 0..SPX_FORS_HEIGHT {
        let bit = (compressed >> j) & 1;
        reconstructed[offset >> 3] |= (bit as u8) << (offset & 0x7);
        offset += 1;
    }
    assert_eq!(
        &reconstructed, mhash,
        "reconstructed mhash from extracted indices must match original"
    );
});
