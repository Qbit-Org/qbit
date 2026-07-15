# qbit P2MR v1 conformance oracle

This standalone Rust program validates the versioned P2MR v1 corpus without
linking qbit consensus, wallet, signing, descriptor, RPC, or test-framework
code. It locally implements the encodings, transaction parser, commitment
domains, witness parsing, signature message, and the small script subset used
by the corpus. `libbitcoinpqc` is used only for the SLH-DSA verification
primitive.

The evaluator is deliberately not a general qbit script engine. An opcode or
fixture shape outside the documented corpus subset fails as unsupported.

```sh
cargo run --locked --manifest-path contrib/testgen/p2mr_v1_oracle/Cargo.toml -- \
  check-manifest --manifest src/test/data/p2mr_v1_manifest.json --source-root .

cargo run --locked --manifest-path contrib/testgen/p2mr_v1_oracle/Cargo.toml -- \
  verify --manifest src/test/data/p2mr_v1_manifest.json --source-root . \
  --report /tmp/p2mr-v1-report.json
```

Release evidence must also pass `--release --oracle-commit <40-hex-commit>`.
Release mode resolves the source checkout's Git `HEAD`, requires a clean
checkout, and rejects a caller-provided commit that does not match `HEAD`.
The canonical report has no timestamp or machine-specific path.

The oracle covers every operation in the versioned corpus: direct pushes,
conditionals and code separators, `OP_CHECKSIGPQC`, `OP_CHECKSIGADD`,
`OP_CHECKTEMPLATEVERIFY`, `OP_CHECKDATASIGPQC`,
`OP_CHECKDATASIGADDPQC`, legacy-signature rejection, OP_SUCCESS and policy
handling, leaf-version behavior, witness/control parsing, clean-stack, and the
declared resource boundaries. Fixture references use exact file, case ID, and
artifact names and are independently revalidated. Adding an unknown operation
or fixture shape makes the oracle fail as unsupported.
