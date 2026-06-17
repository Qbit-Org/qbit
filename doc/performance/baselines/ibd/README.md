IBD Baselines
=============

This directory stores reviewed IBD performance baseline summaries for fixed-host
Linux runs of the qbit IBD performance harnesses:

- `test/functional/feature_ibd_perf_replay.py` for `W1` / `W2` replay lanes.
- `test/functional/feature_ibd_perf_network.py` for `W3` localhost network IBD.
- The manual IBD performance workflow for self-hosted Linux collection.

Promotion Rules
---------------

- Promote reviewed Markdown and JSON summaries, not huge raw traces or
  sample-heavy per-run artifacts.
- Keep raw artifacts in GitHub Actions or another durable artifact store that
  can preserve large CSV, JSON, and trace outputs outside this repository.
- Record source metadata in `index.json`: date, run id, branch, commit, host
  identity, kernel, CPU/RAM/disk summary, build flags, workflow profile,
  artifact digest/link, and notes.
- Keep replay and network IBD results in separate promoted summaries.
- Keep all results informational until repeated fixed-host runs show acceptable
  variance and the review thread explicitly agrees on any threshold policy.

Expected Phase 1 Package
------------------------

The Phase 1 replay baseline package should include:

- `W1-replay-floor` and `W2-replay-mixed` replay workloads.
- 262,800 measured blocks per run.
- 5 fresh-datadir runs per lane.
- Archive and witness-pruned lanes.
- No `-fastprune`; fastprune is only for smoke runs.

Expected Phase 2 Package
------------------------

The Phase 2 network IBD package should include:

- `W3-network-mixed` localhost network IBD.
- 43,200 measured blocks per run.
- 5 fresh-datadir runs.
- Network IBD results reported separately from replay/reindex results.

Closeout Checklist
------------------

Before closing the IBD baseline workstream, the promoted summary should include:

- Workflow run links for every baseline campaign run.
- Durable artifact links and digests for raw reports, CSVs, traces, and host
  metadata.
- Median and p95 replay timing for each Phase 1 lane.
- PQC and P2MR hotspot throughput from `bench_qbit`.
- ConnectBlock timing distribution or trace-derived evidence for representative
  lanes.
- UTXO cache and flush evidence from reports, logs, or traces.
- Disk footprint before, after, and peak for replay and network lanes.
- Bottleneck ranking that identifies the dominant validation, storage, or
  networking costs.
- Explicit rationale for keeping IBD performance informational instead of a CI
  pass/fail gate.

Current State
-------------

No closure-quality IBD baseline has been promoted yet. The first reviewed
fixed-host Phase 1 or Phase 2 package should update `index.json` and add the
corresponding reviewed summary file.
