# Hybrid Post-Quantum v2 Transport

<!-- Interface names quoted in this guide are marked for test/lint/lint-pq-doc-tokens.py, and
     test/functional/feature_pq_quickstart.py runs the quick start; see test/lint/README.md. -->

qbit nodes can add a post-quantum key exchange, ML-KEM-1024, to the encrypted
v2 P2P transport. This guide shows how to try it on your own machine, switch it
off or on for a real node, check that it works and troubleshoot it. The wire
format is specified in
[Hybrid post-quantum v2 transport](../../design/pq-transport.md), and the
[release note](../../release-notes-1.1.0.md#hybrid-post-quantum-v2-transport) summarizes the change.

In this release the feature is **on by default**: a node with v2 transport,
also on by default, uses hybrid keys with every upgraded peer that has it on
too. Switch it off with <!--pq:opt-->`-v2pqtransport=0`.

## BIP324 in Two Lines

[BIP324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki), the
"v2" transport that qbit uses by default, encrypts every connection between two
nodes with keys the two sides agree on by elliptic-curve Diffie-Hellman (ECDH),
so an eavesdropper sees only random-looking bytes. A large enough quantum
computer could break ECDH, so traffic recorded today could be decrypted later.

Hybrid v2 transport mixes an ML-KEM-1024 secret into those keys: a recording
stays unreadable unless both ECDH and ML-KEM-1024 are broken. It needs no extra
round trip, and costs 3,184 bytes per connection and, on a current x86_64 CPU,
about 0.1 ms of CPU time for the two nodes together.

## Try It

Two nodes on a private test network (regtest) on your own machine: no chain
sync, no wallet, nothing sent to the internet. It takes about five minutes.

You need `qbitd` and `qbit-cli` from this release on your `PATH`, and a Linux
or macOS shell (on Windows, use WSL). Run the three steps in the same terminal.
The nodes listen on 127.0.0.1 ports 18501 and 18511 and answer RPC on 18502 and
18512; if one of those is taken, change it everywhere it appears.

Using qbit-qt? The feature is on there too: type `getpqtransportinfo` in
**Window → Console**, and see [Verify](#verify). To change the setting, open
**Settings → Options → Open Configuration File** (on macOS, Options is in the
application menu), add a line as shown in
[Switch It On or Off](#switch-it-on-or-off), save, and restart qbit-qt.

### Step 1: start two nodes

<!-- quickstart: step 1 -->
```sh
Q=~/qbit-pq-quickstart
mkdir -p "$Q/a" "$Q/b"
qbitd -regtest -datadir="$Q/a" -bind=127.0.0.1:18501 -rpcport=18502 -daemon
qbitd -regtest -datadir="$Q/b" -bind=127.0.0.1:18511 -rpcport=18512 -daemon
a() { qbit-cli -regtest -datadir="$Q/a" -rpcport=18502 -rpcwait -rpcwaittimeout=60 "$@"; }
b() { qbit-cli -regtest -datadir="$Q/b" -rpcport=18512 -rpcwait -rpcwaittimeout=60 "$@"; }
a getpqtransportinfo | grep '"status"'
b getpqtransportinfo | grep '"status"'
```

The nodes start with the feature on, the default, so no option is needed. `a`
and `b` are shorthands for asking each node; they wait up to 60 seconds for it
to answer. You should see:

<!-- quickstart: step 1 output -->
```text
qbit starting
qbit starting
  "status": "enabled",
  "status": "enabled",
```

### Step 2: connect them and check

<!-- quickstart: step 2 -->
```sh
a addnode 127.0.0.1:18511 onetry
for i in $(seq 30); do a getpeerinfo | grep -q '"pingtime"' && break; sleep 1; done
a getpeerinfo | grep '"transport_pq'
a -netinfo 1 | grep -E '^<->|^out +manual'
grep 'v2 pq: enabled' "$Q/a/regtest/debug.log"
```

The loop waits up to 30 seconds for the nodes to finish connecting and exchange
a first ping, which normally takes well under a second. You should see:

<!-- quickstart: step 2 output -->
```text
    "transport_pq": true,
    "transport_pq_status": "hybrid"
<->   type   net   serv  v  mping   ping send recv  txn  blk  hb addrp addrl  age id
out manual   npr  nwl2a 2p      0      0    0    0                              0  0
2026-10-21T17:26:21Z v2 pq: enabled arith=x86_64-avx2 keccak=x86_64-avx2
```

`2p` in the `v` column means v2 with hybrid keys. The numbers and the date will
differ, and so may the `arith=` and `keccak=` names, which say which ML-KEM-1024
code runs on your CPU. If `transport_pq` is `false`, see
[Troubleshooting](#troubleshooting), then clean up anyway.

### Step 3: clean up

<!-- quickstart: step 3 -->
```sh
a stop
b stop
for i in $(seq 60); do [ -e "$Q/a/regtest/qbitd.pid" ] || [ -e "$Q/b/regtest/qbitd.pid" ] || break; sleep 1; done
rm -rf "$Q"
unset -f a b
```

This stops both nodes, waits up to 60 seconds for them to exit and deletes their
data directories. You should see:

<!-- quickstart: step 3 output -->
```text
qbit stopping
qbit stopping
```

## Switch It On or Off

The feature is on by default. To switch it off, add this line to `qbit.conf`
and restart the node:

```ini
v2pqtransport=0
```

To switch it back on, delete the line, or set `v2pqtransport=1` to say so
explicitly, and restart. On the command line, `-v2pqtransport=0` (or
<!--pq:opt-->`-nov2pqtransport`) switches it off and
<!--pq:opt-->`-v2pqtransport=1` on, and either overrides `qbit.conf`. The
setting is read once, at startup, and has no effect when
<!--pq:opt-->`-v2transport` is 0; v2 transport is on by default.

The value must be a number. `v2pqtransport=true` (or `yes`, or `on`) is read as
0, which switches the feature off, and a double negative such as
<!--pq:opt-->`-nov2pqtransport=0` is read as 1, which leaves it on. In both
cases, and when `-v2pqtransport=1` has no effect because v2 transport is off,
the node warns at startup and says what it did; the default and
`-v2pqtransport=0` never warn:

```text
Warning: -v2pqtransport=true is not a number and was read as -v2pqtransport=0: hybrid transport is OFF. Use -v2pqtransport=1 or -v2pqtransport=0.
Warning: -nov2pqtransport was given 0 or a non-numeric value, so it was read as -v2pqtransport=1: hybrid transport is ON. Use -v2pqtransport=0 to switch it off.
Warning: -v2pqtransport=1 has no effect because -v2transport=0. Set -v2transport=1 to use hybrid post-quantum v2 transport.
```

`qbitd` prints these warnings in the terminal it was started from, and
`debug.log` records them with a `[warning]` prefix; qbit-qt shows them in a
dialog. Check the result with `getpqtransportinfo` (see [Verify](#verify)).

## Verify

**The startup line.** At every start, `debug.log` (see [Logs](#logs)) gets one
line, <!--pq:log-->`v2 pq: … arith=… keccak=…`, which says whether the feature
is <!--pq:value-->`enabled`, <!--pq:value-->`disabled (-v2pqtransport=0)` or
<!--pq:value-->`disabled (-v2transport=0)`, and names the ML-KEM-1024 code that
runs: `arith=` is <!--pq:value-->`x86_64-avx2`, <!--pq:value-->`aarch64-neon`
or <!--pq:value-->`portable`, and `keccak=` is `x86_64-avx2`,
<!--pq:value-->`aarch64` or `portable`.

**`getpqtransportinfo`.** <!--pq:rpc-->`getpqtransportinfo` reports the
configuration and what happened since startup:

- <!--pq:field-->`enabled` is true when new v2 connections negotiate hybrid
  keys, and <!--pq:field-->`status` is <!--pq:value-->`enabled`,
  <!--pq:value-->`disabled_v2pqtransport` or <!--pq:value-->`disabled_v2transport`.
- <!--pq:field-->`arith_backend` and <!--pq:field-->`keccak_backend` name the
  ML-KEM-1024 code, as the startup line does.
- <!--pq:field-->`handshakes` counts negotiation events for
  <!--pq:field-->`inbound` and <!--pq:field-->`outbound` connections since
  <!--pq:field-->`since`. They count events, not final states: a connection
  that switched to hybrid keys and then failed its key confirmation counts
  <!--pq:field-->`switched` and <!--pq:field-->`first_packet_failed`.
- <!--pq:field-->`load_shedding`, <!--pq:field-->`fallback_set`,
  <!--pq:field-->`failure_streaks` and <!--pq:field-->`recent_failures` are
  described under [Fallback and load shedding](#fallback-and-load-shedding).

Everything here is kept in memory only and starts over when the node restarts;
a new <!--pq:field-->`instance_id` tells you it did. Every field is always
present. `qbit-cli help getpqtransportinfo` describes each one, with the reason
words of every outcome.

**`getpeerinfo`.** <!--pq:rpc-->`getpeerinfo` gives each peer
<!--pq:field-->`transport_pq`, true only once the peer's key confirmation has
verified, and <!--pq:field-->`transport_pq_status`:

| `transport_pq_status` | Meaning |
|---|---|
| <!--pq:value-->`pending` | Still negotiating. A connection that is closing after a hybrid failure also stays `pending` until it is removed: there is no failed status, and the failure is counted in `getpqtransportinfo`. A handshake that doesn't finish within 60 seconds (`-peertimeout`) is closed. |
| <!--pq:value-->`hybrid` | The session keys are hybrid. |
| <!--pq:value-->`legacy_peer` | The peer's handshake carried no hybrid offer or accept, so the connection keeps the ECDH keys, as before. Peers running v1.0.0, or with the feature off, show this. |
| <!--pq:value-->`fallback` | Plain v2 to an address in the fallback set (automatic outbound connections only). |
| <!--pq:value-->`off` | Plain v2 because the feature is off on this node, the offer was shed under load, or a local ML-KEM fault happened before anything was committed. |
| <!--pq:value-->`v1` | An unencrypted v1 connection. |

With hybrid keys, <!--pq:field-->`session_id` is the hybrid session id, which
two operators can compare out of band.

**`-netinfo`.** `qbit-cli -netinfo 1` lists peers; in its `v` column,
<!--pq:value-->`2p` marks v2 with hybrid keys, `2` plain v2 and `1` v1. The
<!--pq:opt-->`-netinfo` help describes every column.

**`getnetworkinfo`.** <!--pq:rpc-->`getnetworkinfo` reports
<!--pq:field-->`connections_pq`, the number of peers whose `transport_pq` is
true.

With the feature on, the default, but no upgraded peers yet, the `legacy_peer`
counters grow and `connections_pq` stays 0, which is expected while the network
upgrades. With it switched off, `enabled` is false, every counter stays 0, v2
peers show `off` and `connections_pq` is 0.

## Fallback and Load Shedding

**Fallback.** If hybrid handshakes of automatic outbound connections with the
same address fail three times in a row, the node stops trying hybrid keys with
that address for an hour, and connects to it with plain v2 instead, so that a
broken peer or a middlebox that mangles the handshake can't keep the connection
from working. The second time the address falls back it stays out for 4 hours,
and from then on for 24 hours. Each window is also measured on the node's
monotonic clock, so setting the clock back can't lengthen it. Only failures the
peer side can cause count: <!--pq:value-->`malformed_record`,
<!--pq:value-->`first_packet_failed` and <!--pq:value-->`closed_after_switch`.
An address that completed a hybrid handshake since startup never falls back
(the node remembers the 1,000 that did so most recently), inbound connections
never fall back, and a restart forgets the whole history. `getpqtransportinfo`
lists the addresses in <!--pq:field-->`fallback_set`, with
<!--pq:field-->`expires`, and those on their way there in
<!--pq:field-->`failure_streaks`.

**Manual peers never fall back.** Someone on the network path between you and
a peer can cause those failures without breaking any keys, by damaging or
dropping packets, and so keep an automatic peer on ECDH keys. Connections you
make yourself, with <!--pq:rpc-->`addnode` or <!--pq:opt-->`-connect` (also
<!--pq:opt-->`-addnode`), always negotiate hybrid keys, even to an address in
the fallback set, and their failures never count toward it; they are still
counted, listed in `recent_failures` and logged. If hybrid keys with particular
peers matter to you, add them with `addnode`.

**Load shedding.** An offer costs the responding node an ML-KEM key generation,
and a decapsulation when the peer accepts. If more inbound v2 connections than
the threshold, currently 1,000, reach that point within one second, the node
stops offering, and those connections continue as plain v2 (status `off`,
counted as <!--pq:field-->`shed`). It offers again after 10 seconds in a row
with fewer than half the threshold's connections per second, counted on the
node's monotonic clock. Outbound connections are not affected.
`getpqtransportinfo` shows the state in `load_shedding`:
<!--pq:field-->`active`, <!--pq:field-->`threshold_per_s` and `since`, which is
0 when shedding is not active.

Both are local policy: a peer can't tell them from a node that has the feature
off.

## What It Protects and What It Doesn't

It protects the confidentiality of traffic between two upgraded nodes that
both have the feature on and whose connection shows `"transport_pq": true`:
someone who records that traffic can't decrypt it later, even with a quantum
computer, unless ML-KEM-1024 is broken too.

It does not:

- **Authenticate peers.** Like BIP324, it doesn't tell you who is on the other
  end. A spy peer sees everything you send it, and an active man-in-the-middle
  can still relay two separate sessions, each of which may be hybrid. Comparing
  `session_id` out of band detects that.
- **Protect traffic to v1.0.0 nodes,** or to any peer that has the feature off:
  those connections use ECDH keys (v2) or no encryption (v1), as before. The
  fallback, which someone on the network path can trigger for automatic peers,
  load shedding and local faults also leave some connections on ECDH keys;
  `transport_pq` reports which.
- **Hide where transactions come from.** Your peers see which transactions you
  announce, and when, as before, which can reveal that one started at your node.
- **Hide that you use it.** Hybrid sessions can be told apart from plain v2 by
  their packet sizes: a hybrid initiator's first send ends at its garbage
  terminator, without the version packet other v2 initiators send right after
  it, and each side's version packet is 1,592 bytes. If being recognized
  matters, for example to avoid censorship, use [Tor](tor.md) or [I2P](i2p.md),
  which also help with transaction origin.

The [security notes](../../design/pq-transport.md#security-notes) of the
specification cover downgrades and transcript binding.

## Logs

The log is `debug.log` in the data directory: `~/.qbit/debug.log` on Linux,
`~/Library/Application Support/Qbit/debug.log` on macOS, and
`%LOCALAPPDATA%\Qbit\debug.log` on Windows, with the network's subdirectory
for test networks (for example `~/.qbit/testnet4/debug.log`). With the systemd
unit in `contrib/init`, the data directory is `/var/lib/qbit`, and the same
lines also go to the journal: `journalctl -u qbitd`.

- The startup line and load shedding are logged at info level.
- Failures of outbound handshakes are logged at info level, and an address
  entering the fallback set or a suspected local fault at warning level
  (`[warning]` in `debug.log`).
- Inbound outcomes and successful handshakes are logged only with
  `-debug=net`, for example <!--pq:log-->`v2 pq: switched role=initiator` and
  <!--pq:log-->`v2 pq: switched role=responder`. Anyone can cause inbound
  failures at will, so they are not logged by default.

## Troubleshooting

Look for the log line or counter in the first column. Log lines are followed by
details such as `role=`, `peer=` and the ML-KEM-1024 backends; counters are in
`getpqtransportinfo`.

| Log line or counter | Meaning | Likely causes | What to do |
|---|---|---|---|
| The startup line says `disabled (-v2pqtransport=0)` | The feature is off. | `v2pqtransport=0` in `qbit.conf`; set to `true`, which reads as 0; `-v2pqtransport=0` or `-nov2pqtransport` on the command line. | Delete the setting or set `v2pqtransport=1`, restart, and read the startup warnings. |
| The startup line says `disabled (-v2transport=0)` | v2 transport is off, so hybrid keys can't be used. | `-v2transport=0`. | Remove it. Only with `-v2pqtransport=1` also set did the node warn <!--pq:log-->`has no effect because -v2transport=0`. |
| <!--pq:log-->`is not a number and was read as` | A non-numeric value, such as `true`, was read as 0 or 1. | `true`, `yes`, `on` or a typo. | Use 1 or 0. |
| <!--pq:log-->`was given 0 or a non-numeric value, so it was read as` | A double negative switched the feature on. | `-nov2pqtransport=0` or `nov2pqtransport=true`. | Use `v2pqtransport=0` to switch it off. |
| <!--pq:field-->`legacy_peer` (counter and status) | The peer sent no hybrid offer or accept (reason <!--pq:value-->`no_features`), or contents qbit can't parse (<!--pq:value-->`parse_error`). | The peer runs v1.0.0 or has the feature off. `parse_error`: another implementation or a bug. | Nothing for `no_features`; it is normal while the network upgrades. `parse_error` from many peers: open an issue. |
| <!--pq:log-->`v2 pq: load_shedding started threshold_per_s=…`, <!--pq:log-->`v2 pq: load_shedding stopped`, counter `shed` | Load shedding started or stopped. | A connection flood, or many peers reconnecting at once. | Nothing; those connections continue as plain v2. If it stays on, check where inbound connections come from (`qbit-cli -netinfo 4`), and consider firewall rules or `-maxconnections`. |
| <!--pq:log-->`v2 pq: malformed_record reason=…`, counter <!--pq:field-->`malformed_record` | The peer's offer (<!--pq:value-->`ek_length`, <!--pq:value-->`ek_modulus`) or accept (<!--pq:value-->`ct_length`) was malformed. The connection closes; on an automatic outbound connection, it counts toward the fallback. | A non-conforming implementation, or tampering in transit. | One-off: nothing. From many peers: report it. |
| <!--pq:log-->`v2 pq: first_packet_failed reason=…`, counter `first_packet_failed` | The peer's key confirmation failed (<!--pq:value-->`length`, <!--pq:value-->`tag` or <!--pq:value-->`not_decoy`): the two sides derived different keys. The connection closes; on an automatic outbound connection, it counts toward the fallback. | Tampering in transit, a peer bug, or this node's ML-KEM code (see `local_fault`). | One-off: nothing. From many peers: report it. |
| <!--pq:log-->`v2 pq: closed_after_switch cause=…`, counter <!--pq:field-->`closed_after_switch` | After this node switched to hybrid keys, the peer closed (<!--pq:value-->`eof`), reset (<!--pq:value-->`reset`) or timed out (<!--pq:value-->`timeout`) before its key confirmation arrived. On an automatic connection, it counts toward the fallback. | The peer restarted, the network dropped, or the peer's check of our confirmation failed. | One-off: nothing. Often with one peer: ask its operator for their side's log. |
| <!--pq:log-->`v2 pq: internal_error reason=…`, counter <!--pq:field-->`internal_error` | A local ML-KEM or cipher-state error (<!--pq:value-->`keygen`, <!--pq:value-->`check_public_key`, <!--pq:value-->`encaps`, <!--pq:value-->`decaps`, <!--pq:value-->`cipher_state`). Peer data never causes it. | A fault in this node's ML-KEM code or its CPU. | Report it. Try <!--pq:opt-->`-mlkemportable`. If a peer can trigger it, use `SECURITY.md`. |
| <!--pq:log-->`v2 pq: fallback cause=… until=…`, counter <!--pq:field-->`fallback` | An address failed three times in a row on automatic outbound connections, and gets plain v2 on them until the time given (UTC). | See the failure it names. | Usually nothing: the window ends by itself, and a restart clears it. To keep hybrid keys with a peer, add it with `addnode`. Many addresses: see `local_fault`. |
| <!--pq:log-->`v2 pq: local_fault` | Hybrid handshakes failed with 8 different outbound addresses, in ways this node's own ML-KEM code can cause (`ek_modulus`, `length`, `tag`, or `closed_after_switch` with `eof` or `reset`), and none succeeded since startup, so that code may be at fault. Failures only the peer can cause (`ek_length`, `not_decoy`) and `timeout` don't count. | A miscompiled or misbehaving native ML-KEM path, or a broken CPU. | If the line names native code, restart with `-mlkemportable`, as it suggests. Report it either way. |
| <!--pq:field-->`abandoned` (inbound) | This node offered, and the connection closed before the initiator's version packet authenticated, whichever side closed it. The reason is the close cause, or what failed (<!--pq:value-->`garbage_terminator`, <!--pq:value-->`version_length`, <!--pq:value-->`version_tag`); <!--pq:value-->`local` is this node's own close, such as an eviction. Closes because the network was switched off, or at shutdown, aren't counted. | Port scanners, peers giving up, flaky links; with `local`, evictions when the inbound slots are full. | Nothing at low rates. Many, together with `shed`: a flood. |
| `transport_pq_status` stays `pending` | The handshake is still running, or the connection is closing after a failure. | A slow link, or a failure counted above. | It ends within 60 seconds. Look for the peer's `peer_id` in `recent_failures`. |
| `transport_pq_status` is `off` while `enabled` is true | This connection is plain v2. | The offer was shed, or a local fault (`internal_error`) before anything was committed. | Check `shed` and `internal_error`. |

**What to attach to a report:** the first line of `qbitd -version`, your
operating system and CPU model, the startup line, the output of
`getpqtransportinfo` and the matching log lines, if possible with `-debug=net`.
These contain peer addresses; remove them before posting in public.

**When to use [`SECURITY.md`](../../../SECURITY.md) instead:** report privately,
as it describes, rather than in a public issue, if you see a crash, a hang or
growing memory use around these log lines; an `internal_error` that a peer can
trigger; failures that suggest someone tampers with or downgrades hybrid
connections, such as `first_packet_failed` or `malformed_record` from many
unrelated peers behind one network path; or anything that suggests the session
keys are not what `transport_pq` reports.

## Upgrading and Rolling Back

- **Upgrading.** An upgrade switches the feature on: with v2 transport on, also
  the default, the upgraded node offers and accepts hybrid keys on new v2
  connections, and keeps the ECDH keys with peers that don't have it. It also
  gains the RPC fields and the startup line. Check `getpqtransportinfo` after
  the upgrade.
- **Upgrading with the feature off.** Before upgrading, add `v2pqtransport=0`
  to `qbit.conf`. v1.0.0 ignores the line, logging
  `Ignoring unknown configuration value v2pqtransport`, so it can be added
  while the node still runs v1.0.0, and the upgraded node starts with the
  feature off. Don't put `-v2pqtransport=0` on v1.0.0's command line: it
  refuses to start (see below). Add it to command lines only after the upgrade.
- **Mixed versions.** Peers running v1.0.0 keep connecting in both directions:
  over v2 they show `legacy_peer` (with the feature on, the default) or `off`
  (with it switched off), and over v1 `v1`. Between two upgraded nodes, the
  connection is hybrid unless one of them switched the feature off; the side
  that has it on then shows `legacy_peer`.
- **Nothing persists.** The counters, failure history and fallback set live in
  memory and start over at every restart. The feature changes no file in the
  data directory.
- **Rolling back to v1.0.0.** If you never set the option, there is nothing to
  remove. v1.0.0 doesn't know it: it ignores `v2pqtransport=0` or
  `v2pqtransport=1` in `qbit.conf`, logging
  `Ignoring unknown configuration value v2pqtransport`, but refuses to start
  with any form of it on the command line, `-nov2pqtransport` included:
  `Error: Error parsing command line arguments: Invalid parameter -v2pqtransport=0`.
  Remove it from command lines, service files and scripts before downgrading.
- **The escape hatch.** If the native ML-KEM-1024 code misbehaves on your CPU,
  for example with `local_fault` in the log, restart with
  <!--pq:opt-->`-mlkemportable` (`mlkemportable=1` in `qbit.conf`). It is
  hidden from `-help`; `qbitd -help-debug` lists it. The node then runs the
  portable code, as the startup line and `getpqtransportinfo` show, at a cost
  of about 0.1 ms more CPU time per hybrid handshake. Its value must be a
  number too, and it warns the same way.

## See Also

- [Hybrid post-quantum v2 transport](../../design/pq-transport.md), the
  specification.
- The [release note](../../release-notes-1.1.0.md#hybrid-post-quantum-v2-transport).
- [Tor](tor.md) and [I2P](i2p.md) support.
