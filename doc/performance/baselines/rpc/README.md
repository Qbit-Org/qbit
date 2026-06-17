RPC Baselines
=============

This directory stores reviewed RPC performance baseline summaries for fixed-host
Linux runs of `test/functional/feature_rpc_perf.py`.

Promotion Rules
---------------

- Promote reviewed Markdown summaries, not raw sample-heavy report JSON.
- Keep source artifacts in GitHub Actions or another ignored artifact store.
- Use one stable runner identity for comparable baseline updates.
- Record source metadata in `index.json`: date, run id, branch, commit, qbit
  version, reference version, manifest hash, run scale, and notes.
- Keep latency comparisons informational until variance is understood.

Current State
-------------

No expanded Phase 2 baseline has been promoted yet. The first post-merge
fixed-host run should update `index.json` and add the reviewed summary file.
