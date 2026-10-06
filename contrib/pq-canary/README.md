# PQ canary sampler and evaluator

Scripted evidence for the mainnet canary of the hybrid post-quantum v2
transport (#184, release gate R5, with the R0 baseline before it). Two team
mainnet nodes run the release candidate: an archive node and a pool node pinned
to it with `-addnode`. A third team archive node stays on v1.0.0 as the
control. Every 5 minutes each of them records one sample, and
`pq-canary-eval.py` turns the samples into the canary figures.

The tools work against nodes without the new RPCs (v1.0.0, and the R0 baseline):
whatever a node cannot report is recorded as `NA`.

## Files

| File | Purpose |
|---|---|
| `pq-canary-sample.sh` | Records one sample; run it from cron or a systemd timer. |
| `pq_canary.py` | The sample format, shared by the sampler and the evaluator. |
| `pq-canary-eval.py` | Prints the canary figures with their sample counts. |
| `test/test_pq_canary.py` | Tests, with RPC fixtures in the `getpqtransportinfo` schema of #184. |

## Install

Requirements: bash, Python 3.10 or later, and `qbit-cli` able to reach the node.

1. Copy this directory to the node, for example to `/opt/qbit/pq-canary`, or use
   a checkout of the repository.
2. Pick an output directory owned by the user that runs the sampler, for example
   `/var/lib/qbit-canary`.
3. Add a cron line (`crontab -e`) for that user. Use a short `--host` label,
   other than `NA`; the evaluator tells nodes apart by it.

Canary archive node:

```
*/5 * * * * /opt/qbit/pq-canary/pq-canary-sample.sh --host archive --out /var/lib/qbit-canary -- /usr/local/bin/qbit-cli -datadir=/var/lib/qbit -rpcclienttimeout=30
```

Pool node, pinned to the archive node with `-addnode=<archive address:port>`;
`--pinned` takes the same `address:port`, as `getpeerinfo` shows it:

```
*/5 * * * * /opt/qbit/pq-canary/pq-canary-sample.sh --host pool --pinned 203.0.113.5:8333 --out /var/lib/qbit-canary -- /usr/local/bin/qbit-cli -datadir=/var/lib/qbit -rpcclienttimeout=30
```

Control node (v1.0.0): the archive line with `--host control`.

With a systemd timer instead of cron, run the same command from a oneshot
service and set `OnCalendar=*:0/5` on the timer.

Each RPC call is also bounded by `timeout 60` when `timeout(1)` is installed, so
a hung node cannot pile up sampler runs. The sampler exits 0 for a complete
sample, 2 when `sample_ok=0`, and 1 on a usage error.

## What a sample contains

Each run appends one row to `samples.csv` (the header is written once) and,
when `getpqtransportinfo` answers, one line to `failures.jsonl`.

`samples.csv` columns:

- `time` (Unix seconds), `utc`, `host`, `uptime`, `version` (from `getnetworkinfo`);
- `sample_ok`: 1 when `uptime`, `getnetworkinfo` and, on the pool node,
  `getpeerinfo` answered, else 0;
- from `getpqtransportinfo`: `pq_enabled`, `instance_id`, `arith_backend`,
  `keccak_backend`, `since`, the inbound counters `in_switched` ...
  `in_shed`, the outbound counters `out_switched` ... `out_fallback`,
  `load_shedding_active`, and each ring's `*_ring_last_sequence` and
  `*_ring_dropped`;
- `connections_in` and `connections_pq` from `getnetworkinfo`;
- on the pool node, from the `getpeerinfo` entry for the pinned address:
  `pinned_present` (1 or 0), `pinned_connection_type`, `pinned_transport_pq`
  and `pinned_transport_pq_status`.

Booleans are written as 1 or 0. A failed call, or a field the node does not
report, is `NA`, never 0; a real 0 stays 0. So is a value of the wrong type: a
count that is not a non-negative integer (`true` is never written as 1), a flag
that is not a boolean, or an `instance_id` that is not 64 lowercase hex digits. A v1.0.0 node therefore writes `NA`
for every `getpqtransportinfo` column and for `connections_pq`, with
`sample_ok=1`. The CSV holds no peer addresses.

`failures.jsonl` holds each sample's raw `recent_failures` and `fallback_set`,
with the sample time, host label, `instance_id` and `since`. It contains peer
addresses: keep it on the node, and run the evaluator there.

## Known-good endpoints

The failure figures only count entries between known-good endpoints: the canary
nodes and their pinned peers. Keep the list in a file on the evaluating node,
one entry per line: the endpoint, then an optional label (letters, digits, `.`,
`_`, `-`). `#` starts a comment.

```
# The archive node, as the pool node dials it.
203.0.113.5:8333 archive
# The pool node, as the archive node sees it: inbound entries carry the
# peer's source port, so list the address alone to match any port.
198.51.100.7 pool
# IPv6 entries go in brackets. Without a label this one is known-good-3.
[2001:db8::5]:8333
```

The report names a known-good peer by its label and never prints an address,
so it can be posted. Unlabeled entries are `known-good-1`, `known-good-2`, ...
in file order. Errors about the list name the line, not the address.

## Running the evaluator

Figure 2 needs the failures of every monitored canary node, by default the
hosts of `--pool` and `--archive`: one node's file cannot pass it. Copy the
pool node's `failures.jsonl` to the archive node, or the other way round, over
a private channel between the two team nodes (for example `scp`), and run the
evaluator there. The CSV files hold no addresses. For example, on the archive
node:

```
pq-canary-eval.py --canary-start 2026-11-02T00:00:00Z \
  --pool pool/samples.csv --archive /var/lib/qbit-canary/samples.csv --control control/samples.csv \
  --failures pool/failures.jsonl --failures /var/lib/qbit-canary/failures.jsonl \
  --known-good /etc/qbit-canary/known-good.txt
```

Samples before `--canary-start` are the baseline (R0); the canary window runs
from there to `--end`, or to the latest sample. Other options:

- `--baseline-ratio R` sets the archive/control connection ratio instead of
  measuring it from the baseline.
- `--min-coverage S` (default 0.9) is the share of the expected 5-minute samples
  that a figure, node or day needs before it is judged.
- `--monitored HOST,...` names the nodes whose failures must be present, instead
  of the hosts of `--pool` and `--archive`.
- `--interval` (default 300 s) and `--restart-grace` (default 600 s).

Unknown, misspelled or abbreviated options, malformed times or numbers, missing
files, `--failures` without `--known-good` (or the reverse) and an `--end`
before `--canary-start` are rejected with exit status 2 and a message. So are
samples that would compare a node with itself: `--pool`, `--archive` and
`--control` must each be one node, so a file given for two roles, two roles
with the same host label or `instance_id`, or a file whose rows carry more than
one host label (or none) is rejected.

Output: one line per figure, `<result> <figure>: samples=<n> coverage=<c> <details>`,
where the result is `pass`, `fail` or `unknown`, followed by indented details,
then the verdict over figures 1, 2 and 4:

1. **Pinned link**: the pool node's pinned peer is connected as `manual` with
   `transport_pq` true in at least 99% of samples, excluding restarts.
2. **Failure entries**: no `malformed_record` or `first_packet_failed` entry,
   no `fallback` entry and no fallback-set entry between known-good endpoints,
   on every monitored node. Its details give each node's coverage.
3. **closed_after_switch**: such entries between known-good endpoints, listed
   for triage; not part of the verdict.
4. **Inbound connections**: per UTC day, the archive node's `connections_in`
   divided by the control's stays within ±20% of the baseline ratio, excluding
   the 48 hours after a restart of either node. Each day shows its coverage. A
   baseline in which either node's `connections_in` sums to 0 gives no usable
   ratio, so the figure is unknown unless `--baseline-ratio` is given.

The exit status is 0 when the verdict is pass, 1 on fail, 3 on unknown and 2 for
bad arguments or input.

### How evidence is judged

- **Restarts.** A jump in a node's boot time (`time - uptime`), or a new
  `instance_id`, is a restart. For the pinned link, the samples from the last
  sample before the restart to 10 minutes after it (`--restart-grace`) are a
  gap: neither pass nor fail. The restarts are listed at the top of the report.
  An uptime whose boot time differs from the one already seen for the same
  `instance_id` contradicts it: that uptime is unknown, not a restart.
- **Coverage.** Coverage is the share of the expected 5-minute samples that are
  present and usable. Below `--min-coverage`, the pinned link, a monitored
  node's failure evidence and an inbound-connections day are unknown, not
  judged.
- **Unknown, never clean.** A sample with `sample_ok=0`, an `NA` where the
  figure needs a value, or a missing sample (for example while cron was not
  running) is unknown. So is a malformed value: a `time`, `uptime` or
  `connections_in` that is not a plain non-negative integer (a row without a
  usable `time` counts as missing), a row with more or fewer fields than the
  header (such as a line cut short by a crash), and a connected pinned peer
  whose connection type, `transport_pq` or `transport_pq_status` is missing or
  malformed, or whose `transport_pq` is not 1 exactly when the status is
  `hybrid`. The pinned link passes only if it would pass with every
  unknown sample counted as a failure, and fails only if it would fail with
  every unknown sample counted as a success; otherwise it is unknown.
- **Rings.** Failure entries are read from each ring (`inbound`, `outbound`) by
  its per-ring sequence. A ring holds the latest 256 entries, so it wraps: that
  is fine as long as the entries read reach back to the sequence after the last
  one already processed, and the ring stays judged. Entries are lost, and that
  stretch is unknown for that ring, when a wrap between two samples evicted
  entries never read (the oldest entry read is past that point), across a
  changed `instance_id`, or when a ring is malformed or goes backwards. A flood
  of inbound failures therefore cannot hide an outbound one: the rings are
  separate. Unrelated endpoints never fail the canary, but only a well-formed
  endpoint is unrelated: a `malformed_record`, `first_packet_failed`,
  `fallback` or `closed_after_switch` entry whose endpoint is missing or
  malformed makes its figure unknown.
- **Malformed evidence is unknown.** Only values of the `getpqtransportinfo`
  types count as evidence. A record whose `instance_id` or `since` is missing
  or malformed, whose `since` is after the sample, or whose `since` changed
  within one `instance_id`; a ring that is not an object with non-negative
  integer counters; a failure entry whose `outcome` is outside the vocabulary,
  or whose `time` is missing, malformed, before its process started or more
  than 5 minutes after the sample that read it; and a fallback-set entry
  without a well-formed endpoint: each makes that stretch unknown. A
  `failures.jsonl` line without a time in Unix seconds and a valid host label
  is bad input (exit status 2). A known-good failure whose other fields are
  malformed is still a failure, and those fields print as `malformed`, so a
  malformed field can never put an address in the report.

### When the pinned link is not manual

If the pool node already has an automatic connection to the archive node's
address, `GetAddedNodeInfo` skips the address and the `-addnode` thread does
not open its manual connection, so the figure fails and the report says so. The
remedy: run `qbit-cli disconnectnode <archive address:port>` once on the pool
node; the `-addnode` thread reconnects it as manual within about 60 seconds.

## Tests

```
python3 contrib/pq-canary/test/test_pq_canary.py
```

The Required Merge Gate runs them, and `test/functional/tool_pq_canary.py` runs
the sampler against a regtest node, and against v1.0.0 when previous releases
are downloaded.
