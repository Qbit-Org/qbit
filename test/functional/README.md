# Functional tests

### Writing Functional Tests

#### Example test

The file [test/functional/example_test.py](example_test.py) is a heavily commented example
of a test case that uses both the RPC and P2P interfaces. If you are writing your first test, copy
that file and modify to fit your needs.

#### Coverage

Assuming the build directory is `build`,
running `build/test/functional/test_runner.py` with the `--coverage` argument tracks which RPCs are
called by the tests and prints a report of uncovered RPCs in the summary. This
can be used (along with the `--extended` argument) to find out which RPCs we
don't have test cases for.

#### Style guidelines

- Where possible, try to adhere to [PEP-8 guidelines](https://www.python.org/dev/peps/pep-0008/)
- Use a python linter like flake8 before submitting PRs to catch common style
  nits (eg trailing whitespace, unused imports, etc)
- The oldest supported Python version is specified in [doc/build/dependencies.md](/doc/build/dependencies.md).
  Consider using [pyenv](https://github.com/pyenv/pyenv), which checks [.python-version](/.python-version),
  to prevent accidentally introducing modern syntax from an unsupported Python version.
  The CI linter job also checks this, but [possibly not in all cases](https://github.com/bitcoin/bitcoin/pull/14884#discussion_r239585126).
- See [the python lint script](/test/lint/lint-python.py) that checks for violations that
  could lead to bugs and issues in the test code.
- Use [type hints](https://docs.python.org/3/library/typing.html) in your code to improve code readability
  and to detect possible bugs earlier.
- Avoid wildcard imports.
- If more than one name from a module is needed, use lexicographically sorted multi-line imports
  in order to reduce the possibility of potential merge conflicts.
- Use a module-level docstring to describe what the test is testing, and how it
  is testing it.
- When subclassing the BitcoinTestFramework, place overrides for the
  `set_test_params()`, `add_options()` and `setup_xxxx()` methods at the top of
  the subclass, then locally-defined helper methods, then the `run_test()` method.
- Use `f'{x}'` for string formatting in preference to `'{}'.format(x)` or `'%s' % x`.
- Use `platform.system()` for detecting the running operating system and `os.name` to
  check whether it's a POSIX system (see also the `skip_if_platform_not_{linux,posix}`
  methods in the `BitcoinTestFramework` class, which can be used to skip a whole test
  depending on the platform).

#### Naming guidelines

- Name the test `<area>_test.py`, where area can be one of the following:
    - `feature` for tests for full features that aren't wallet/mining/mempool, eg `feature_rbf.py`
    - `interface` for tests for other interfaces (REST, ZMQ, etc), eg `interface_rest.py`
    - `mempool` for tests for mempool behaviour, eg `mempool_reorg.py`
    - `mining` for tests for mining features, eg `mining_prioritisetransaction.py`
    - `p2p` for tests that explicitly test the p2p interface, eg `p2p_disconnect_ban.py`
    - `rpc` for tests for individual RPC methods or features, eg `rpc_listtransactions.py`
    - `tool` for tests for tools, eg `tool_wallet.py`
    - `wallet` for tests for wallet features, eg `wallet_keypool.py`
- Use an underscore to separate words
    - exception: for tests for specific RPCs or command line options which don't include underscores, name the test after the exact RPC or argument name, eg `rpc_decodescript.py`, not `rpc_decode_script.py`
- Don't use the redundant word `test` in the name, eg `interface_zmq.py`, not `interface_zmq_test.py`

#### General test-writing advice

- Instead of inline comments or no test documentation at all, log the comments to the test log, e.g.
  `self.log.info('Create enough transactions to fill a block')`. Logs make the test code easier to read and the test
  logic easier [to debug](/test/README.md#test-logging).
- Set `self.num_nodes` to the minimum number of nodes necessary for the test.
  Having additional unrequired nodes adds to the execution time of the test as
  well as memory/CPU/disk requirements (which is important when running tests in
  parallel).
- Avoid stop-starting the nodes multiple times during the test if possible. A
  stop-start takes several seconds, so doing it several times blows up the
  runtime of the test.
- Set the `self.setup_clean_chain` variable in `set_test_params()` to `True` to
  initialize an empty blockchain and start from the Genesis block, rather than
  load a premined blockchain from cache with the default value of `False`. The
  cached data directories contain a 200-block pre-mined blockchain with the
  spendable mining rewards being split between four nodes. Each node has 25
  mature block subsidies (25x50=1250 BTC) in its wallet. Using them is much more
  efficient than mining blocks in your test.
- When calling RPCs with lots of arguments, consider using named keyword
  arguments instead of positional arguments to make the intent of the call
  clear to readers.
- Many of the core test framework classes such as `CBlock` and `CTransaction`
  don't allow new attributes to be added to their objects at runtime like
  typical Python objects allow. This helps prevent unpredictable side effects
  from typographical errors or usage of the objects outside of their intended
  purpose.

#### RPC and P2P definitions

Test writers may find it helpful to refer to the definitions for the RPC and
P2P messages. These can be found in the following source files:

- `/src/rpc/*` for RPCs
- `/src/wallet/rpc*` for wallet RPCs
- `ProcessMessage()` in `/src/net_processing.cpp` for parsing P2P messages

#### Using the P2P interface

- `P2P`s can be used to test specific P2P protocol behavior.
[p2p.py](test_framework/p2p.py) contains test framework p2p objects and
[messages.py](test_framework/messages.py) contains all the definitions for objects passed
over the network (`CBlock`, `CTransaction`, etc, along with the network-level
wrappers for them, `msg_block`, `msg_tx`, etc).

- P2P tests have two threads. One thread handles all network communication
with the bitcoind(s) being tested in a callback-based event loop; the other
implements the test logic.

- `P2PConnection` is the class used to connect to a bitcoind.  `P2PInterface`
contains the higher level logic for processing P2P payloads and connecting to
the Bitcoin Core node application logic. For custom behaviour, subclass the
P2PInterface object and override the callback methods.

`P2PConnection`s can be used as such:

```python
p2p_conn = node.add_p2p_connection(P2PInterface())
p2p_conn.send_and_ping(msg)
```

They can also be referenced by indexing into a `TestNode`'s `p2ps` list, which
contains the list of test framework `p2p` objects connected to itself
(it does not include any `TestNode`s):

```python
node.p2ps[0].sync_with_ping()
```

More examples can be found in [p2p_unrequested_blocks.py](p2p_unrequested_blocks.py),
[p2p_compactblocks.py](p2p_compactblocks.py).

#### Prototyping tests

The [`TestShell`](test-shell.md) class exposes the BitcoinTestFramework
functionality to interactive Python3 environments and can be used to prototype
tests. This may be especially useful in a REPL environment with session logging
utilities, such as
[IPython](https://ipython.readthedocs.io/en/stable/interactive/reference.html#session-logging-and-restoring).
The logs of such interactive sessions can later be adapted into permanent test
cases.

### Test framework modules
The following are useful modules for test developers. They are located in
[test/functional/test_framework/](test_framework).

#### [authproxy.py](test_framework/authproxy.py)
Taken from the [python-bitcoinrpc repository](https://github.com/jgarzik/python-bitcoinrpc).

#### [test_framework.py](test_framework/test_framework.py)
Base class for functional tests.

#### [util.py](test_framework/util.py)
Generally useful functions.

#### [p2p.py](test_framework/p2p.py)
Test objects for interacting with a bitcoind node over the p2p interface.

#### [script.py](test_framework/script.py)
Utilities for manipulating transaction scripts (originally from python-bitcoinlib)

#### [key.py](test_framework/key.py)
Test-only secp256k1 elliptic curve implementation

#### [blocktools.py](test_framework/blocktools.py)
Helper functions for creating blocks and transactions.

### Benchmarking with perf

An easy way to profile node performance during functional tests is provided
for Linux platforms using `perf`.

Perf will sample the running node and will generate profile data in the node's
datadir. The profile data can then be presented using `perf report` or a graphical
tool like [hotspot](https://github.com/KDAB/hotspot).

There are two ways of invoking perf: one is to use the `--perf` flag when
running tests, which will profile each node during the entire test run: perf
begins to profile when the node starts and ends when it shuts down. The other
way is the use the `profile_with_perf` context manager, e.g.

```python
with node.profile_with_perf("send-big-msgs"):
    # Perform activity on the node you're interested in profiling, e.g.:
    for _ in range(10000):
        node.p2ps[0].send_without_ping(some_large_message)
```

To see useful textual output, run

```sh
perf report -i /path/to/datadir/send-big-msgs.perf.data.xxxx --stdio | c++filt | less
```

#### See also:

- [Installing perf](https://askubuntu.com/q/50145)
- [Perf examples](https://www.brendangregg.com/perf.html)
- [Hotspot](https://github.com/KDAB/hotspot): a GUI for perf output analysis

### Report-only replay benchmarks

Replay benchmark harnesses such as
[feature_ibd_perf_replay.py](feature_ibd_perf_replay.py) must be run
explicitly. They are not part of the default functional regression suite and
they emit measurement artifacts rather than asserting performance thresholds.

These scripts can be combined with `--perf` when startup or replay profiling is
needed.

`W1-replay-floor` is the lower-bound witness-bearing proxy workload:

```sh
test/functional/feature_ibd_perf_replay.py \
  --configfile="$(pwd)/build/test/config.ini" \
  --workload=w1-replay-floor \
  --blocks=300 \
  --txs-per-block=1 \
  --history-mode=archive \
  --report-file="$(pwd)/build/reports/feature-ibd-perf-replay-archive-chainstate.json"
```

`W2-replay-mixed` adds deterministic P2MR wallet spends on top of the proxy
traffic:

```sh
test/functional/feature_ibd_perf_replay.py \
  --configfile="$(pwd)/build/test/config.ini" \
  --workload=w2-replay-mixed \
  --blocks=300 \
  --txs-per-block=1 \
  --p2mr-spends-per-block=1 \
  --history-mode=archive \
  --report-file="$(pwd)/build/reports/feature-ibd-perf-replay-w2-archive-chainstate.json"
```

Witness-pruned replay lanes require `--reindex-mode=chainstate`. For smaller
smoke runs, use `--tail-blocks` so the measured history actually falls outside
the witness retention window before replay. Archive/full-history replay is the
default lane; witness-pruned replay is the explicit opt-in alternative:

```sh
test/functional/feature_ibd_perf_replay.py \
  --configfile="$(pwd)/build/test/config.ini" \
  --workload=w2-replay-mixed \
  --history-mode=witness-pruned \
  --reindex-mode=chainstate \
  --blocks=5 \
  --txs-per-block=1 \
  --p2mr-spends-per-block=1 \
  --tail-blocks=1002 \
  --fastprune \
  --report-file="$(pwd)/build/reports/feature-ibd-perf-replay-w2-witness-pruned-chainstate.json"
```

By default, the replay benchmark writes its JSON report to
`build/reports/feature-ibd-perf-replay-<lane>-<workload>.json` under the repo root.
The report includes the lane/workload labels, git commit, host metadata,
storage footprint, witness-pruning / assumevalid details when applicable, and
the measured proxy / P2MR transaction counts used to build the workload.
Manual workflow split artifacts can be downloaded, merged back into the
historical artifact-root layout, and summarized with:

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

The summarizer writes canonical Markdown and JSON summaries to the artifact
bundle's `summary/` directory and also reports missing optional trace or
UTXO/flush evidence explicitly.

Reviewed fixed-host IBD baseline summaries should be promoted under
`doc/performance/baselines/ibd/`.

### Report-only localhost network IBD benchmarks

`W3` localhost IBD uses a separate report-only harness:

```sh
test/functional/feature_ibd_perf_network.py \
  --configfile="$(pwd)/build/test/config.ini" \
  --workload=w2-replay-mixed \
  --blocks=300 \
  --txs-per-block=1 \
  --p2mr-spends-per-block=1 \
  --report-file="$(pwd)/build/reports/feature-ibd-perf-network-w3-network-mixed.json"
```

This harness builds the same deterministic source history on one node, then
measures a second clean node syncing it over localhost until
`initialblockdownload=false`. The report includes headers-sync, tip-sync, and
IBD-exit timing along with peer snapshots and final disk footprint.

### Perf harness validation

`feature_ibd_perf_validation.py` is a zero-node self-check for the perf
harnesses. It validates workload naming/recipe/count determinism and the
replay / network JSON schemas without asserting performance thresholds.
Pass `--run-history-determinism` for an explicit two-node smoke that builds
tiny W1/W2 histories and compares stable construction metadata. That smoke
does not assert full chain hash equality because the production harness does
not currently fix node mining time or wallet key entropy.

### Mempool simulation smoke and reports

[`feature_mempool_sim.py`](feature_mempool_sim.py) is part of the default
functional suite through its bounded `--ci-smoke` profile. It drives a real
regtest qbit node through deterministic mempool workloads and fails only on
correctness-oriented policy invariants, not latency or throughput thresholds.

The CI smoke profile covers three lanes:

- `steady-default`: min-relay boundaries, P2MR-sized witness data, and next-round
  block inclusion.
- `constrained-saturation`: a minimum-size mempool pressure run that checks eviction and
  floating minimum fee behavior.
- `package-rbf-boundary`: 25/26 ancestor-package behavior and RBF fee-delta
  boundaries.

`--ci-smoke` uses one steady-default round and 32 saturation transactions. Manual
runs without `--ci-smoke` use three steady-default rounds and 64 saturation
transactions by default; both counts can be overridden with `--steady-rounds`
and `--saturation-txs`. Low `--saturation-txs` overrides remain valid pressure
samples, but the harness only asserts eviction when the accepted transaction
vbytes exceed the constrained mempool cap.

The harness also writes JSON and Markdown reports with qbit-specific assumptions,
lane steps, mempool snapshots, and red-flag classifications:

```sh
test/functional/feature_mempool_sim.py \
  --configfile="$(pwd)/build/test/config.ini" \
  --ci-smoke \
  --report-file="$(pwd)/build/reports/feature-mempool-sim-report.json" \
  --summary-file="$(pwd)/build/reports/feature-mempool-sim-summary.md"
```

### Report-only RPC benchmarks

The RPC harness in
[feature_rpc_perf.py](feature_rpc_perf.py) follows the same report-only model:
it is not part of the default functional suite and it emits artifacts instead
of enforcing pass/fail thresholds.

The checked-in manifest lives at
[`test/functional/data/rpc_perf_manifest.json`](data/rpc_perf_manifest.json).
Raw per-run JSON artifacts and Markdown summaries should normally be written to
`build/reports/`, while checked-in baseline summaries should only come from a fixed
Linux benchmark host once the methodology is stable.

For manual fixed-host runs on GitHub Actions self-hosted Linux runners, use
the manual RPC performance workflow.

Example qbit-only run:

```sh
test/functional/feature_rpc_perf.py \
  --configfile="$(pwd)/build/test/config.ini" \
  --run-scale=0.25 \
  --report-file="$(pwd)/build/reports/feature-rpc-perf-report.json" \
  --summary-file="$(pwd)/build/reports/feature-rpc-perf-summary.md"
```

Example qbit vs Bitcoin Core `v30.2` comparison run:

```sh
test/functional/feature_rpc_perf.py \
  --configfile="$(pwd)/build/test/config.ini" \
  --reference-bin-dir="/path/to/bitcoin-core-v30.2/build/bin" \
  --reference-srcdir="/path/to/bitcoin-core-v30.2" \
  --report-file="$(pwd)/build/reports/feature-rpc-perf-report.json" \
  --summary-file="$(pwd)/build/reports/feature-rpc-perf-summary.md" \
  --inventory-file="$(pwd)/build/reports/feature-rpc-perf-inventory.json"
```
