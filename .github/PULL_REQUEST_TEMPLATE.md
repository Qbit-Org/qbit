## Summary

<!-- Explain what changed and why. Link the public issue if one exists. -->

## Testing

<!-- List the exact local tests, linters, or manual checks you ran. If a check was not run, say why. -->

- [ ] Built locally.
- [ ] Ran focused unit or functional tests for the changed area.
- [ ] Ran lint or formatting checks relevant to this change.
- [ ] Not run. Reason:

## Target Branch

- [ ] This PR targets `main` or a maintainer-requested release branch such as `0.1.x`.

## Risk / Review Notes

- [ ] Consensus, script, crypto, wallet, P2P, release, CI, or security-sensitive behavior changed.
- [ ] No consensus, script, crypto, wallet, P2P, release, CI, or security-sensitive behavior changed.

Notes:

## Docs / Process Impact

Choose exactly one:

- [ ] I updated public docs because this PR changes user-visible behavior, integration guidance, release/process guidance, or expected validation.
- [ ] No public docs update needed. Reason:

## libbitcoinpqc Subtree Checklist (if `src/libbitcoinpqc` changed)

- [ ] Upstream fix is merged into the maintained libbitcoinpqc branch used by qbit.
- [ ] Curated branch `qbit-subtree` was refreshed with prune.
- [ ] Subtree update was done with `contrib/devtools/update-libbitcoinpqc-subtree.sh`.
- [ ] `test/lint/git-subtree-check.sh -r src/libbitcoinpqc` passes locally.
- [ ] Followed `doc/subtrees/libbitcoinpqc.md`.
