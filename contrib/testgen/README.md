### TestGen ###

Utilities to generate test vectors for the data-driven Bitcoin tests.

To use inside a scripted-diff (or just execute directly):

    ./gen_key_io_test_vectors.py valid 70 > ../../src/test/data/key_io_valid.json
    ./gen_key_io_test_vectors.py invalid 70 > ../../src/test/data/key_io_invalid.json

To regenerate the independent P2MR `OP_CHECKSIGPQC` witness vectors:

    cargo run --manifest-path p2mr_checksigpqc_vectors/Cargo.toml -- ../../src/test/data/p2mr_pqc_witness_vectors.json
