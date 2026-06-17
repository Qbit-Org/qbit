Benchmarking
============

Bitcoin Core has an internal benchmarking framework, with benchmarks
for cryptographic algorithms (e.g. SHA1, SHA256, SHA512, RIPEMD160, Poly1305, ChaCha20), rolling bloom filter, coins selection,
thread queue, wallet balance.

Running
---------------------

For benchmarking, you only need to compile `bench_bitcoin`.  The bench runner
warns if you configure with `-DCMAKE_BUILD_TYPE=Debug`, but consider if building without
it will impact the benchmark(s) you are interested in by unlatching log printers
and lock analysis.

    cmake -B build -DBUILD_BENCH=ON
    cmake --build build -t bench_bitcoin

After compiling bitcoin-core, the benchmarks can be run with:

    build/bin/bench_bitcoin

The output will look similar to:
```
|               ns/op |                op/s |    err% |     total | benchmark
|--------------------:|--------------------:|--------:|----------:|:----------
|       57,927,463.00 |               17.26 |    3.6% |      0.66 | `AddrManAdd`
|          677,816.00 |            1,475.33 |    4.9% |      0.01 | `AddrManGetAddr`

...

|             ns/byte |              byte/s |    err% |     total | benchmark
|--------------------:|--------------------:|--------:|----------:|:----------
|              127.32 |        7,854,302.69 |    0.3% |      0.00 | `Base58CheckEncode`
|               31.95 |       31,303,226.99 |    0.2% |      0.00 | `Base58Decode`

...
```

Help
---------------------

    build/bin/bench_bitcoin -h

To print the various options, like listing the benchmarks without running them
or using a regex filter to only run certain benchmarks.

Notes
---------------------

Benchmarks help with monitoring for performance regressions and can act as a
scope for future performance improvements. They should cover components that
impact performance critical functions of the system. Functions are performance
critical if their performance impacts users and the cost associated with a
degradation in performance is high. A non-exhaustive list:

- Initial block download (Cost: slow IBD results in full node operation being
  less accessible)
- Block template creation (Cost: slow block template creation may result in
  lower fee revenue for miners)
- Block propagation (Cost: slow block propagation may increase the rate of
  orphaned blocks and mining centralization)

A change aiming to improve the performance may be rejected when a clear
end-to-end performance improvement cannot be demonstrated. The change might
also be rejected if the code bloat or review/maintenance burden is too high to
justify the improvement.

Benchmarks are ill-suited for testing denial-of-service issues as they are
restricted to the same input set (introducing bias). Fuzz testing is better
suited for this purpose because it explores the possible input space.

For qbit, `bench_qbit` covers hotspot microbenchmarks, while report-only replay
harnesses under `test/functional/` can cover end-to-end reindex or replay
workloads across archive and witness-pruned lanes. The current replay harness
supports both the `W1-replay-floor` proxy workload and a `W2-replay-mixed`
proxy + P2MR-spend workload. Those replay harnesses complement correctness
tests: they emit artifacts and measurements, but they do not enforce
performance thresholds in the default test suite. A sibling manual harness,
`feature_ibd_perf_network.py`, covers `W3` localhost network IBD against the
same deterministic history recipes.
Archive/full-history retention is the default lane. Witness-pruned runs are
explicit opt-in and should be treated as operator/perf experiments rather than
the baseline node profile.
After a manual IBD workflow run, download and merge the split artifacts back
into the historical artifact-root layout before summarizing them:

```sh
run_id=<run_id>
download_dir="build-perf-artifacts/ibd-perf-${run_id}-download"
artifact_root="build-perf-artifacts/ibd-perf-${run_id}"
rm -rf "$download_dir" "$artifact_root"
mkdir -p "$artifact_root"
gh run download "$run_id" \
  -p "ibd-perf-${run_id}-*" \
  -D "$download_dir"
for artifact_dir in "$download_dir"/ibd-perf-"$run_id"-*; do
  [ -d "$artifact_dir" ] || continue
  cp -a "$artifact_dir"/. "$artifact_root"/
done
contrib/devtools/summarize_ibd_perf.py "$artifact_root"
```

Artifact uploads are best-effort so GitHub artifact storage stalls do not fail
otherwise completed benchmark runs. If artifacts are missing, use the workflow
job summary and `Record perf artifact manifest` log section as the preserved
benchmark evidence.

The generated `summary/ibd-baseline-summary.{md,json}` files include replay,
network IBD, hotspot, disk, ConnectBlock, UTXO/flush, and missing-evidence
sections without adding performance pass/fail thresholds.

The same report-only pattern now also applies to RPC benchmarking via
`test/functional/feature_rpc_perf.py`, which uses a checked-in manifest and
stores repeatable latency artifacts without turning performance variance into a
default CI gate.

For qbit wallet UX work, `contrib/devtools/bench_wallet_create.py` measures
create-time P2MR wallet latency and `contrib/devtools/bench_wallet_recovery.py`
measures descriptor-backed signer recovery plus watch-only `importpubkeydb`
recovery on deterministic sparse-wallet fixtures. Like the replay and RPC
perf harnesses, these scripts are intended to emit baseline artifacts for
local or release engineering review rather than enforce CI thresholds.

Going Further
--------------------

To monitor Bitcoin Core performance more in depth (like reindex or IBD): https://github.com/bitcoin-dev-tools/benchcoin
