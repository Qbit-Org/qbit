# Versioning And Supply Chain

## Version Values

Current metadata values:

- Rust package (`Cargo.toml`): `qbit-libbitcoinpqc` `0.3.0`
- CMake project variables (`CMakeLists.txt`): `0.3.0`

Rust and CMake track the core single-profile library version.

Follow-up TODO: add a generated single source of truth for core library version
metadata before the first production release.

## Dependency Audit

Run Rust advisory checks before release:

```bash
cargo install cargo-audit --version 0.22.1 --locked
cargo audit --deny warnings
```

Any advisory output must be triaged and resolved or explicitly documented before
release.

## GitHub Actions Pinning Policy

Active workflow `uses:` references for external GitHub Actions must be pinned
to full commit SHAs. Keep a trailing comment with the human-readable tag or
branch used to select the SHA, such as `# v4` or `# master`.

CI enforces this policy with:

```bash
ruby scripts/check-workflow-action-pins.rb
```

The guard parses workflow YAML, so comments and YAML block scalar text are not
treated as release inputs. Local actions and `docker://` refs are outside this
GitHub Action pinning policy.

Any exception must be documented in `docs/release-checklist.md` and paired with
a reviewed guard allowlist in the same PR. There are no approved exceptions in
the current release branch.

Toolchains may still intentionally track channels such as Rust `stable` or
`nightly`; capture `rustc -Vv`, `cargo -V`, and the build host details in the
release evidence bundle.
