# Contributing to qbit

qbit is developed as its own project. Do not use Bitcoin Core issue lists, IRC
channels, mailing lists, GUI repository process, release process, or maintainer
tools as the public contribution path for qbit.

The public contribution process is owned by the official qbit GitHub
repository: https://github.com/Qbit-Org/qbit.

## Before You Start

- Read the public docs index in [doc/README.md](doc/README.md).
- For qbit-specific behavior, start with
  [doc/user/bitcoin-core-differences.md](doc/user/bitcoin-core-differences.md).
- Keep mainnet-facing docs gated behind "when launched" until qbit.org
  announces the public network and resource set.
- Do not introduce Bitcoin Core security contacts, lifecycle links, issue
  links, IRC channels, mailing lists, or release-key references into qbit
  public docs.

## Branch and PR Scope

Target `main` for public pull requests unless a maintainer tells you otherwise.
Use maintenance branches such as `0.1.x` only when a maintainer requests a
backport or when the change is clearly limited to that release line. Release
identity lives in signed `v*` tags rather than long-lived release branches.

Keep changes focused on one layer or topic, and avoid mixing public docs,
consensus behavior, wallet behavior, release tooling, and unrelated cleanup in
the same pull request.

Fresh external pull requests into `main` are not auto-closed, auto-commented,
or auto-labeled. `Core Checks` run first; self-hosted `Full Validation` waits
for a maintainer to apply the `ci:qbit-trusted` label.

Use qbit names and paths in public-facing changes:

- binaries such as `qbitd`, `qbit-cli`, `qbit-qt`, `qbit-wallet`
- the `qbit.conf` config file
- qbit data directories
- qbit network flags and ports
- qbit addresses and the `qbit:` payment URI scheme

## Local Validation

For non-trivial changes, build and run the smallest relevant checks before
opening or updating a pull request:

```bash
cmake --build build -j"$(sysctl -n hw.ncpu)"
RUST_BACKTRACE=1 cargo run --manifest-path ./test/lint/test_runner/Cargo.toml
```

Run focused unit and functional tests for the area you touched. For
documentation-only public surface changes, also run targeted link/path audits
and the public-source sanitizer dry run when sanitizer behavior changes.

## Public Documentation Rules

- Public docs must direct current release, network, support, faucet, explorer,
  and security-status questions to https://qbit.org unless a more specific
  qbit-owned public page has been finalized.
- Mainnet examples must say they apply only when qbit mainnet is launched.
- Testnet resource values must be tied to the relevant release candidate or
  network reset, not presented as permanent launch values.
- Mainnet launch values become authoritative only after a qbit launch
  announcement freezes them.
- Public docs should reference finalized qbit-owned public resources only.
- Unvalidated inherited docs should be unlisted, clearly labeled technical
  reference only, or stripped from sanitized public source snapshots.

## Security Issues

Do not file security-sensitive qbit reports in public issues. To report
security issues, email contact@qbit.org (not for support).
