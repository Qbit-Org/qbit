RPC Benchmarking
================

`test/functional/feature_rpc_perf.py` is qbit's report-only RPC benchmark
harness. It is designed for repeatable local measurement and stored artifacts,
not for pass/fail CI gating.

Goals
-----

- Benchmark qbit's public RPC surface with one repo-owned harness.
- Compare shared RPC latency against a clean Bitcoin Core `v30.2` reference
  when that comparison is meaningful.
- Keep qbit-only public RPCs in the same artifact/reporting flow, even when no
  upstream comparison exists.
- Store raw artifacts locally and promote only reviewed summaries into the repo.

Lane Model
----------

- `shared_deterministic_read_only`: shared endpoints that can be timed on both
  qbit and Bitcoin Core without fixture reset per sample.
- `shared_stateful_mutating`: shared endpoints that need explicit reset or
  rebuild between samples.
- `shared_name_qbit_modified`: shared endpoint names whose semantics or shape
  diverge on qbit.
- `qbit_only_public`: qbit-specific public RPCs with independent baselines.

Comparison Policy
-----------------

The harness does not require strict JSON equality across qbit and Bitcoin Core.
For shared endpoints it records:

- per-target median and p95 latency
- success/error class
- serialized response size in bytes
- response-shape metadata

This is deliberate. Some RPCs share a name while differing in semantics or
response shape, and even comparable endpoints can drift in non-performance
fields that are irrelevant to latency regression tracking.

Reference Target
----------------

Use a clean Bitcoin Core `v30.2` build for the reference target. In this repo,
`main` tracks that clean reference, but any separate checkout of upstream
Bitcoin Core `v30.2` works as long as you point the harness at its `build/bin`
directory.

Build qbit:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

Build the reference checkout:

```sh
cmake -S /path/to/bitcoin-core-v30.2 -B /path/to/bitcoin-core-v30.2/build -DCMAKE_BUILD_TYPE=Release
cmake --build /path/to/bitcoin-core-v30.2/build -j"$(nproc)"
```

Running
-------

For fixed-host Linux benchmarking on GitHub Actions self-hosted runners, use
the manual RPC performance workflow. It builds qbit, optionally builds a clean
Bitcoin Core `v30.2` reference checkout, runs the same harness, and uploads the
resulting artifacts.

Run qbit only:

```sh
test/functional/feature_rpc_perf.py \
  --configfile="$(pwd)/build/test/config.ini" \
  --report-file="$(pwd)/build/reports/feature-rpc-perf-report.json" \
  --summary-file="$(pwd)/build/reports/feature-rpc-perf-summary.md" \
  --inventory-file="$(pwd)/build/reports/feature-rpc-perf-inventory.json" \
  --coverage-file="$(pwd)/build/reports/feature-rpc-perf-coverage.json"
```

Run qbit vs Bitcoin Core `v30.2`:

```sh
test/functional/feature_rpc_perf.py \
  --configfile="$(pwd)/build/test/config.ini" \
  --reference-bin-dir="/path/to/bitcoin-core-v30.2/build/bin" \
  --reference-srcdir="/path/to/bitcoin-core-v30.2" \
  --report-file="$(pwd)/build/reports/feature-rpc-perf-report.json" \
  --summary-file="$(pwd)/build/reports/feature-rpc-perf-summary.md" \
  --inventory-file="$(pwd)/build/reports/feature-rpc-perf-inventory.json" \
  --coverage-file="$(pwd)/build/reports/feature-rpc-perf-coverage.json"
```

Useful options:

- `--benchmark-filter=<regex>`: run only a subset of benchmark ids.
- `--run-scale=<factor>`: scale manifest run counts for smoke runs or deeper
  sampling.
- `--no-reference`: ignore the reference target even if `--reference-bin-dir`
  is set.
- `--coverage-file=<path>`: write per-command coverage status for qbit's
  public `help()` inventory.

Artifacts
---------

The default manifest is `test/functional/data/rpc_perf_manifest.json`.

Each run records at least:

- target branch/commit metadata when discoverable
- endpoint
- fixture id
- cold or warm mode
- run count
- median and p95 latency
- success/error class
- response size in bytes

The JSON report also includes raw latency samples, response-size samples,
response-shape metadata, active target metadata, and a mechanically seeded RPC
inventory from `help()`.

The coverage artifact classifies every qbit public RPC command as benchmarked,
planned, or unclassified. Manifest and harness schema mistakes fail the run;
latency variance remains informational.

Baseline Promotion
------------------

Reviewed fixed-host baseline summaries live under
`doc/performance/baselines/rpc/`. Promote only human-reviewed summaries and the
small index metadata needed to find the source run. Do not check in raw per-run
reports or sample-heavy JSON artifacts.

Before promoting a baseline:

- Use one fixed Linux host and record the runner name, architecture, kernel,
  qbit commit, qbit version, reference version, manifest hash, run scale, and
  source Actions run id.
- Confirm the run completed with the intended qbit-only and comparison lanes.
- Review the Markdown summary for fixture errors, unexpected RPC error classes,
  and coverage regressions.
- Add or update the baseline index entry, then commit the reviewed summary with
  notes explaining why it is the current baseline.

Storage
-------

- Raw per-run artifacts belong in `build/reports/` or another ignored path.
- Checked-in summaries should come from one fixed Linux host and be indexed in
  `doc/performance/baselines/rpc/index.json`.
- Do not turn the harness into a blocking CI regression gate until variance is
  understood.
