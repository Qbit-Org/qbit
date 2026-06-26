---
name: qbit-single-pr-review
description: Review one qbit pull request against its backing issue, Bitcoin Core review standards, qbit-specific consensus and networking risks, and historical qbit review expectations. Draft a GitHub-ready review comment for the user; never publish it automatically.
---

# qbit Single PR Review

Use this skill when the user asks for a focused review of exactly one qbit pull request, especially when one issue is intended to back that PR exactly. The result is a well-structured GitHub comment draft that the user can choose to publish.

Do not publish, submit, approve, request changes, resolve threads, push code, or mutate GitHub state unless the user explicitly asks after seeing the draft. If publication is requested later, confirm the target PR and post only the approved comment text.

## Review Contract

Treat the backing issue as the contract for the PR.

Before reviewing code, identify:

- The PR number, title, author, base branch, head branch, current status, CI status, commit list, changed files, and diff.
- The exact backing issue. Prefer explicit links such as "Fixes #N", "Closes #N", issue cross-links, or issue comments that name the PR.
- The issue's acceptance criteria, threat model, non-goals, requested validation, and any comments that narrow or expand scope.
- Prior review comments, unresolved threads, requested changes, and follow-up issues.

If no exact backing issue exists, say that clearly in the draft and review the PR as underspecified. Do not invent acceptance criteria.

## Historical qbit Issue Classes

Use these recurring historical classes to decide which checks deserve extra attention. A PR can belong to several classes.

- Consensus and economic rules: chain parameters, activation heights/times, ASERT, Cadence, AuxPoW, mining commitments, subsidy or reward logic, coinbase handling, serialization that affects block or transaction validity.
- Post-quantum cryptography and P2MR: SLH-DSA/libbitcoinpqc integration, signature hashing, script paths, P2MR commitments, wallet signing, key import/export, provider behavior, and timing-sensitive key operations.
- Validation and indexing: block validation, headers, reorgs, assumeutxo, pruning, witness/archive behavior, cache invalidation, chainstate persistence, and restart or resync behavior.
- Wallet, RPC, and GUI behavior: address helpers, imported keys, PSBT flows, watch-only behavior, restore/rescan, GUI progress, RPC error surfaces, and backward compatibility.
- P2P and archive serving: service flags, peer negotiation, witness or archival data serving, DoS boundaries, inventory behavior, and stale peer state.
- PHOTON relay: authenticated UDP message parsing, session identity, counters, liveness, FEC reconstruction, resource bounds, peer isolation, ZMQ/RPC block transfer, and operational runbooks.
- Release, signing, and public-surface hardening: Guix, notarization/signing, key rotation, artifact attestations, CI gates, public repository cutover, sanitization, and documentation.
- Test, fuzz, and CI hardening: deterministic tests, fuzz targets, sanitizer coverage, platform matrix changes, flake fixes, and performance-sensitive changes.
- Future protocol or bridge work: CTV, vaults, attestations, nullifiers, withdrawal flows, or any feature whose partial implementation could be mistaken for activated behavior.

## Bitcoin Core Review Standards

Apply Bitcoin Core-style review expectations:

- Prefer minimal, reviewable, well-scoped changes that match the stated issue.
- Separate consensus changes from refactors, UI changes, documentation, and test-only changes.
- Treat consensus, serialization, cryptography, validation, P2P DoS, wallet fund safety, and release signing as high-risk surfaces.
- Check whether behavior is deterministic across platforms, restarts, reorgs, pruning modes, indexes, and mempool or wallet state.
- Look for deployment and activation safety: defaults, network parameters, version gates, feature flags, rollback behavior, and compatibility with old nodes.
- Require negative tests, boundary tests, reorg/restart tests, and cross-implementation or vector-based tests for consensus or serialization changes.
- Prefer explicit error handling and observable failures over silent fallbacks.
- Check that tests would fail on the old bug and are not just exercising the new implementation's happy path.
- Avoid relying on generated artifacts, snapshots, or mocks that duplicate the implementation bug.
- Treat missing release notes, runbook updates, migration notes, or RPC help updates as review issues when user-visible behavior changes.

## Consensus Impact Classification

Every review draft must include a consensus-impact section with one of these labels:

- `Consensus-changing`: changes block or transaction validity, script/signature checks, activation logic, chain parameters, subsidy, difficulty, AuxPoW commitment rules, serialization committed to chain history, or deployment state.
- `Consensus-adjacent`: changes mining, mempool policy, wallet signing, RPCs used for block construction, test framework consensus assumptions, release defaults, pruning/archive behavior, or code that can mask consensus regressions.
- `Non-consensus`: no plausible path to block or transaction validity, chain selection, activation, or committed serialization.
- `Unclear`: the review could not prove the impact. Explain what must be inspected next.

For any label except `Non-consensus`, state the exact files and code paths that justify the label, the required tests or vectors, and whether the backing issue explicitly authorized the risk.

## qbit-Specific Review Criteria

Check these qbit surfaces whenever relevant:

- P2MR and post-quantum paths: domain separation, signature hash inputs, address encoding, witness/script layout, key origin metadata, provider selection, and fallback behavior.
- AuxPoW and mining: byte order, parent/child chain IDs, coinbase commitment construction, version rolling masks, aux payload persistence, reorg behavior, restart behavior, and compatibility with known merge-mining conventions.
- ASERT and Cadence: activation boundaries, median-time-past assumptions, difficulty transition points, cached state, and test vector coverage around edges.
- Validation state: invalidity caching, block index flags, assumeutxo interaction, pruning, archive serving, and replay after restart.
- Wallet safety: imported PQC secret handling, plaintext validation, rescan/restore correctness, PSBT compatibility, watch-only semantics, multi-input signing counters, and error messages that prevent unsafe user action.
- RPC and GUI surfaces: stable response shapes, help text, argument validation, progress reporting, privacy-sensitive logs, and compatibility with scripts or release workflows.
- Build, packaging, and release: Guix determinism, platform-specific signing, artifact naming, key ownership, attestation verification, CI gates, and public/private boundary hygiene.
- Documentation: update user-visible docs, runbooks, release notes, and operator procedures when behavior, defaults, or operational expectations change.

## PHOTON Relay Review Criteria

When a PR touches `contrib/photon` or relay behavior, explicitly review:

- Message format: fixed datagram size, magic/version/type fields, reserved bits, MAC placement, counter width, payload length, chunk IDs, and strict parse errors.
- Authentication: HMAC input coverage, key length handling, session-bound MAC contexts, old session rejection, invalid MAC counters, and no liveness refresh from unauthenticated traffic.
- Replay and counters: zero counters, monotonic inbound counters, wrap behavior, replay rejection, restart/reset windows, and stale/disconnected peer behavior.
- Session identity: local and remote session IDs, peer IDs, configured endpoint matching, deterministic replacement on valid restart handshakes, retired identity history bounds, and IPv4-mapped address behavior.
- Liveness and reconnects: keepalive cadence, stale timeout, disconnect timeout, retry backoff, DNS re-resolution, and state transitions.
- FEC and decoder safety: maximum original size, data/chunk counts, corrupted chunk handling, duplicate chunks, partial groups, decoder memory caps, pre-header buffering caps, entry-count caps, and age eviction.
- Relay isolation: inbound entries keyed by hash prefix, slot, remote session, and remote peer; conflicting headers; same-prefix poisoning; stale traffic drops; and cleanup after decode failure.
- RPC/ZMQ integration: hashblock subscription, full block fetch, submitblock handling, cookie authentication, timeout behavior, duplicate block handling, and observable stats.
- Operational surface: runbook updates, metric names, alertable counters, logging rate limits, and compatibility with release packaging.

PHOTON relay is normally non-consensus, but it can be consensus-adjacent if it changes block propagation, mining relay, archive behavior, or operational assumptions that could hide validation failures.

## Review Process

Prefer depth over speed. For a single-PR review, read the full diff and relevant surrounding code instead of sampling hunks. If time, tooling, or repository access prevents a full pass, say exactly what was not inspected and lower confidence accordingly.

Follow this sequence:

1. Read the backing issue first. Extract scope, acceptance criteria, non-goals, and validation requirements.
2. Read the PR body, changed file list, commit list, full diff, CI status, reviews, and comments.
3. Build a change map: changed files, changed public APIs, changed global state, new/removed flags, new persistence fields, new tests, and touched user-visible behavior.
4. Map changed files to the historical issue classes and qbit-specific surfaces above.
5. Classify consensus impact and explain the classification from the actual diff.
6. Review the implementation with the deep-review protocol below.
7. Build a validation inventory from the issue, PR body, comments, status checks, CI logs, artifacts, and any local commands run during review. Then check whether tests prove the issue contract, fail on the previous bug, and cover negative and boundary cases.
8. Check documentation, runbook, release, RPC help, and migration requirements when user-visible behavior changes.
9. Check unresolved review-thread state.
10. Draft a GitHub-ready comment. Include only findings you can support from the issue, PR, code, or tests.

When tooling is available, prefer structured GitHub APIs or `gh` over scraping. If thread-level review state is unavailable, state that the review used only the visible flat timeline.

## Deep-Review Protocol

Use multiple passes. Do not stop after finding the first concern, and do not infer correctness from passing CI alone.

### Pass 1: Contract and Invariants

- Convert the issue into an explicit checklist: behavior required, behavior forbidden, non-goals, validation requested, compatibility promises, and expected error cases.
- Identify invariants that must remain true after the patch. Examples: no address before key material is durable, no consensus-rule drift without explicit authorization, no locked-wallet private-key access, no change to explicit operator commands unless requested.
- For each invariant, record where the code enforces it and which test or CI evidence covers it.

### Pass 2: Diff and Call-Graph Trace

- Read every changed hunk and enough surrounding code to understand preconditions, postconditions, and ownership.
- Trace each changed function to callers and callees. For renamed or split helpers, inspect both old and new paths.
- Check lock ordering, scheduler handoff, background work, database transactions, rollback behavior, object lifetime, and error propagation.
- Check both positive and negative branches, including feature-disabled, wallet-disabled, no-scheduler, locked-wallet, empty-keypool, restart, reorg, and persistence-failure paths when relevant.
- For RPC/interface changes, inspect argument parsing, default behavior, help text, response shape, errors, logging, and backward compatibility.

### Pass 3: Risk-Surface Audit

- Consensus or consensus-adjacent code: verify activation boundaries, serialization, script/signature checks, chain parameters, mining/RPC construction paths, mempool policy, and tests around edge heights or edge states.
- Wallet/funds safety: verify durable key material before address exposure, encryption state, watch-only/imported/blank wallet behavior, PSBT compatibility, change handling, backup/restore, rescan, and failure messages.
- P2P/DoS: verify resource bounds, parse rejection, counters, stale state cleanup, peer isolation, and adversarial input behavior.
- Persistence and restart: verify new state is written atomically, old state loads safely, partial writes roll back, and restart resumes or clears pending work correctly.
- Build/release/public surface: verify artifact, signing, CI, docs, and public metadata changes do not weaken release integrity.

### Pass 4: Test Adequacy and Adversarial Cases

- Match each issue acceptance criterion to at least one test, CI job, local command, benchmark, or explicit residual risk.
- Ask whether tests would have failed on the old bug. If not, mark the test as weak even if it exercises the new path.
- Look for missing negative tests, boundary tests, restart tests, lock/error-path tests, and old-behavior compatibility tests.
- Prefer deterministic tests. Treat sleeps, timing-only assertions, broad mocks, and duplicated implementation logic as lower confidence.
- If performance is part of the issue, require local or CI evidence with method, sample count, before/after refs, and caveats.

### Pass 5: Attempted Disproof

- For each likely finding, try to disprove it by checking caller context, tests, CI logs, existing invariants, and prior comments.
- Drop findings that are speculative, already covered by clear evidence, or only reflect personal preference.
- Keep residual risks separate from actionable findings.

## Evidence Ledger

Maintain a private ledger while reviewing, even if it is summarized in the final comment:

- Claim or concern.
- Evidence checked: file/line, issue text, test name, CI job, command output, comment, or log.
- Result: confirmed, disproved, partially covered, or not inspectable.
- Confidence and remaining gap.

Use the ledger to avoid false missing-validation findings and to make the final comment auditable. Do not paste raw logs unless a short excerpt is necessary.

## Local Validation

When the issue contract depends on behavior that cannot be proven from code and CI alone, prefer a small local reproduction or benchmark if the environment allows it. Keep local validation targeted:

- Use exact base and head refs when comparing behavior.
- Record build mode, platform, command, sample count, node/wallet arguments, and artifacts produced.
- Keep temporary scripts or reports outside tracked source unless the user asks to add them.
- Do not treat a local pass as a substitute for CI on high-risk changes; use it as additional evidence.
- If local validation is too expensive or blocked, describe the command that should be run and why it matters.

## Validation Evidence Rules

Treat validation findings as evidence-sensitive. Do not report a requested test, script, lint, or benchmark as missing solely because it is absent from the PR body.

Before surfacing a missing-validation finding:

- Extract the exact requested commands and likely aliases from the backing issue, including wildcard suites and functional test names.
- Check PR body validation, comments, review replies, status-check names, CI run logs, test summaries, and artifacts when available.
- Search for exact script names, exact test names, relevant wildcard expansions, CTest suite names, functional test-runner summaries, and matrix jobs that run full unit or functional suites.
- Treat a CI matrix job as coverage when its logs show the requested script or suite ran successfully, even if the PR body omitted it.
- If a required command is only absent from the PR body but present in CI, mention that in `Validation Reviewed`; do not make it a finding.
- If the available tooling cannot inspect CI logs or artifacts, phrase the gap as an uncertainty in `Residual Risk` unless the PR itself clearly lacks required validation evidence.

A validation finding is appropriate only when the requested validation appears absent from the PR body, comments, visible checks, CI logs/artifacts, and local review runs, or when the validation that ran does not cover the issue contract.

## Finding Rules

Lead with actionable findings. Use these severities:

- `blocking`: must be fixed before merge because it can break correctness, consensus safety, funds safety, release integrity, or the issue contract.
- `high`: likely bug, security/DoS risk, missing required validation, or serious review-process gap.
- `medium`: plausible bug, incomplete edge coverage, unclear behavior, or documentation/runbook gap that should be addressed.
- `low`: small maintainability, clarity, or test-quality issue that does not block correctness.

Each finding should include:

- A severity.
- File and line reference when possible.
- The observed behavior.
- Why it matters in qbit or Bitcoin Core terms.
- The concrete fix or evidence needed.

Do not pad the comment with speculative findings. If no actionable issues are found, say that and list remaining residual risks or validation gaps.

## Output Format

Present the result to the user as a proposed comment, not as a posted comment. Do not use a separate non-publication disclaimer preamble.

The comment should be a polished review comment, not a raw audit log. Be explicit about what was checked and validated, but keep the pacing tight: concise paragraphs by default, with bullets only where they improve scanability or support a concrete finding.

Aim for a good compromise:

- Include enough evidence that another reviewer can tell what was checked, which issue contract was used, which code paths mattered, and what validation was reviewed.
- Do not paste the full private checklist, evidence ledger, or every searched CI log line into the comment.
- Prefer short paragraphs for `Review Scope`, `Issue Fit`, `qbit-Specific Checks`, `Validation Reviewed`, and `Residual Risk`.
- Use bullets for actionable findings, changed-file summaries when helpful, exact acceptance criteria when the issue is broad, or validation inventories when CI evidence is important.
- Keep `Deep Checks Performed` concise. It should summarize the most important review passes and attempted-disproof checks, not enumerate every generic skill step.
- If the PR has no findings and CI is straightforward, keep the whole comment short and reviewer-like.
- If the PR touches consensus, serialization, mining, wallet fund safety, cryptography, P2P/DoS, release signing, or has incomplete/failing validation, expand with enough concrete evidence to make the conclusion auditable.
- Never let verbosity imply a stronger review than was actually performed. State local validation gaps plainly.

The final answer should include:

```markdown
Proposed GitHub comment:

<comment body>

Publication requires explicit confirmation of the target PR and final comment text.
```

The proposed GitHub comment should use this structure:

```markdown
## PR Review

### Findings
- [severity] `path:line` - Finding title. Explanation and requested change.

If there are no findings:
No blocking findings from this review pass.

### Consensus Impact
`Consensus-changing|Consensus-adjacent|Non-consensus|Unclear`

Short explanation grounded in the diff.

### Review Scope
What was reviewed: backing issue, PR body, changed files, relevant code paths, comments/reviews, unresolved thread state, and CI/status checks inspected. Summarize in one paragraph unless a changed-file list materially improves clarity.

### Deep Checks Performed
Summarize the substantive passes performed and the strongest attempted-disproof checks. Keep this to a short paragraph or a small targeted bullet list. Do not list generic checks that were irrelevant to the diff.

### Issue Fit
How the PR does or does not satisfy the backing issue. Note scope drift and missing acceptance criteria. Use bullets only when mapping several acceptance criteria.

### qbit-Specific Checks
Relevant checks performed for consensus, PQC/P2MR, AuxPoW/mining, wallet/RPC, PHOTON, or release surfaces. Mention untouched high-risk qbit surfaces only when that helps bound review scope.

### Validation Reviewed
Tests, CI workflows/jobs, manual commands, vectors, benchmark/log evidence, or missing validation evidence. Distinguish tests listed by the author from tests found in CI logs. Summarize green CI; expand when a required validation command was located in logs, when checks are failing/skipped, or when a validation gap remains.

### Residual Risk
Short list of what this review did not prove.
```

When no blocking findings are found, the comment should still explain the strongest evidence for that conclusion and the main things that remain unproven. Keep the comment suitable for GitHub: factual, directly actionable, and detailed enough to be auditable without raw tool dumps. Avoid internal workspace paths, private repository owner names, or unrelated implementation notes.
