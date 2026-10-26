Qbit v1.1.0 Release Notes
=========================

Qbit: Post-quantum peer to peer digital value

Qbit version v1.1.0 is available from the release page for that version.
Release candidates carry an `-rc<N>` suffix, for example `v1.1.0-rc1`, and are
published as pre-releases.

<!-- Interface names quoted in these notes are marked for test/lint/lint-pq-doc-tokens.py;
     see test/lint/README.md. -->

This is a mainnet feature release built from the reviewed `1.1.0` branch. It
adds a post-quantum key exchange, ML-KEM-1024, to the encrypted v2 P2P
transport and switches it on by default, asks I2P routers for post-quantum
leasesets, and builds `qbit-photon` with OpenSSL 3.5. It also contains every
change in v1.0.1. It contains no consensus rule change, no scheduled network
activation, no change to the mainnet or testnet4 network identity, and no
wallet database or data directory format change.

Please report bugs using the Qbit issue tracker.

How to Upgrade
==============

Shut down the older qbit process and wait until it exits completely before
installing v1.1.0. Then install the new binaries from the GitHub Release page.

Existing v1.0.0 and v1.0.1 mainnet and testnet4 data directories, wallets, and
wallet backups continue to work without a reindex, chain reset, or wallet
migration.

On Linux, replace the existing `qbitd`, `qbit-cli`, `qbit-tx`, `qbit-util`,
and `qbit-wallet` binaries with the new versions.

On macOS, replace the installed Qbit application bundle or unpack the updated
archive into the desired location.

On Windows, run the installer if one is provided for the release, or replace
the unpacked binaries with the new release artifacts.

To upgrade with the hybrid transport switched off, add `v2pqtransport=0` to
`qbit.conf` before upgrading. v1.0.0 ignores the line there, logging
`Ignoring unknown configuration value v2pqtransport`, so it can be added while
the old version still runs. Don't put `-v2pqtransport` on an older version's
command line in any form: v1.0.0 refuses to start with it. Add it to command
lines only after the upgrade.

Before downgrading to an older version, remove `-v2pqtransport`, and
`-mlkemportable` if you used it, from command lines, service files and
scripts. Older versions refuse to start with either on the command line, and
ignore both in `qbit.conf`.

Behavior changes to review before upgrading
-------------------------------------------

- The hybrid post-quantum v2 transport is on by default. A node with v2
  transport, which is also on by default, offers and accepts an ML-KEM-1024
  key exchange on new v2 connections and uses hybrid session keys with every
  peer that has it on too. Peers without it, including v1.0.0 nodes, keep
  connecting as before. To switch it off, set <!--pq:opt-->`-v2pqtransport=0`,
  or `v2pqtransport=0` in `qbit.conf`, and restart (#241). See
  [Hybrid post-quantum v2 transport](#hybrid-post-quantum-v2-transport).
- `-v2pqtransport` takes a number. `v2pqtransport=true` (or `yes`, or `on`) is
  read as 0, which switches the feature off, and a double negative such as
  <!--pq:opt-->`-nov2pqtransport=0` is read as 1, which leaves it on. In both
  cases the node warns at startup and says how it read the value. A JSON
  `true` in `settings.json` is read as on, without a warning (#236, #241,
  #248).
- I2P sessions ask the router for post-quantum leasesets, and creating an I2P
  session now has a single 3-minute limit for all of its steps, where each SAM
  request used to have its own 3-minute timeout. See
  [I2P post-quantum leasesets](#i2p-post-quantum-leasesets) (#223, #246).
- The release build of `qbit-photon` no longer loads OpenSSL engines or
  provider modules named by `OPENSSL_CONF` or `OPENSSL_MODULES` (#249).

Compatibility
=============

qbit is not wire-, consensus-, address-, wallet-, or data-directory-compatible
with Bitcoin Core. Bitcoin addresses and Bitcoin payment URIs are not valid
qbit payment destinations.

Mainnet remains the default chain for a standard build. The mainnet network
identity is unchanged from v1.0.0:

| Item | Value |
|---|---|
| Chain option | default, or `-chain=main` |
| Default P2P port | `8355` |
| Default RPC/REST port | `8352` |
| Address HRP | `qb` |
| AuxPoW chain ID | `47` |
| Genesis block | `0000000000004d60aa5d46013991d0a0e2995d89ee98e53068ae196d763e79f2` |

Public testnet4 remains available with:

```bash
qbitd -testnet4
qbit-cli -testnet4 getblockchaininfo
```

Mainnet-capable binaries are the build default. A binary that rejects mainnet
must be built with `-DQBIT_TESTNET_ONLY_RELEASE=ON`; the distribution archive
name does not enable that restriction.

Supported and tested platforms for this release are the artifacts attached to
the GitHub Release page. The release page is the source of truth for available
platform builds, checksums, signatures, and attestations.

Peers running other versions
----------------------------

The hybrid transport carries its key exchange in the contents of the BIP324
version packet, which BIP324 receivers, v1.0.0 included, ignore. It adds no
service flag and no message. Nodes running v1.0.0 or v1.0.1, which have no
hybrid transport, keep connecting with v1.1.0 nodes in both directions, with
no disconnect:

| Connection | Session keys | <!--pq:field-->`transport_pq_status` |
|---|---|---|
| Two v1.1.0 nodes with the feature on, over v2 | hybrid | <!--pq:value-->`hybrid` on both sides |
| v1.1.0 with the feature on, and v1.0.0 or v1.0.1, over v2 | ECDH only, as before | <!--pq:value-->`legacy_peer` on the v1.1.0 node |
| v1.1.0 with the feature on, and v1.1.0 with it off, over v2 | ECDH only | `legacy_peer` on the side with it on, <!--pq:value-->`off` on the side with it off |
| v1.1.0 with the feature off, and v1.0.0 or v1.0.1, over v2 | ECDH only, as before | `off` on the v1.1.0 node |
| Any versions over v1, including with `-v2transport=0` | none, as before | <!--pq:value-->`v1` on a v1.1.0 node |

- Either side may initiate. A v1.1.0 initiator with the feature on waits for
  the responder's version packet before it sends its own. Every BIP324
  responder, v1.0.0 included, sends its version packet without waiting for
  the initiator's, so the handshake completes with peers that don't have the
  feature.
- This was tested against the v1.0.0 release binary in both directions, over
  v2 and over v1. Over v2 both sides derive the same plain BIP324 session id.
- `getpeerinfo` and `getnetworkinfo` only gain fields. One existing field
  changes meaning: on a hybrid connection, `getpeerinfo`'s `session_id` is
  the hybrid session id. A v1.0.0 node returns none of the new fields, and
  this release's `qbit-cli -netinfo` treats a missing `transport_pq` as false.
- The node keeps no hybrid transport state on disk. Its counters, failure
  history and fallback set live in memory and start over at every restart.

Changes in v1.1.0
=================

This release contains every change in v1.0.1, and all changes merged to
`1.1.0` after it branched from `1.x.x`. Pull request numbers refer to the
Qbit-Org/qbit repository. The hybrid transport (#184) was merged as #233,
which contains its parts (#223 to #241) and the fixes made along the way (#228
to #254).

### Hybrid post-quantum v2 transport

- BIP324's v2 transport encrypts each connection with keys from an ECDH
  exchange, which a large enough quantum computer could break, so that traffic
  recorded today could be decrypted later. Two nodes with the hybrid transport
  on now also run an ML-KEM-1024 key exchange inside the v2 handshake and mix
  both secrets into the session keys. A recording stays confidential unless
  both secp256k1 ECDH and ML-KEM-1024 are broken. The responder puts its
  encapsulation key in its version packet and the initiator answers with a
  ciphertext in its own, so there is no extra round trip. Each side's first
  packet under the new keys is a key confirmation, and application messages
  are delivered only after the peer's confirmation verifies (#230). The wire
  format and key schedule are specified in
  [Hybrid post-quantum v2 transport](design/pq-transport.md).
- A hybrid connection costs 3,184 more bytes than a plain v2 connection, and
  one ML-KEM-1024 key generation, encapsulation and decapsulation. On the
  handshake benchmark added in #240, run on one x86_64 machine with both sides
  on one thread, a complete hybrid handshake took 192.0 µs with native code
  and 290.4 µs with portable code, against 110.7 µs for plain v2. No other
  performance measurement accompanies this release.
- <!--pq:opt-->`-v2pqtransport` switches the feature, which is on by default
  (#236, #241). It has no effect with <!--pq:opt-->`-v2transport` set to 0. The
  setting is read once, at startup. The node warns at startup when the value
  is not a number, when a double negative switches the feature on, and when
  `-v2pqtransport=1` has no effect because v2 transport is off. The default
  and `-v2pqtransport=0` never warn.
- What it protects: the confidentiality of traffic between two upgraded nodes
  that both have the feature on, on connections whose
  <!--pq:field-->`transport_pq` is true.
- What it does not protect:
  - It does not authenticate peers. A spy peer sees everything sent to it, and
    an active man-in-the-middle can still relay two separate sessions, each of
    which may be hybrid. Comparing `session_id` out of band detects that.
  - It does nothing for traffic with v1.0.0 nodes or any other peer without
    the feature on: those connections keep ECDH keys over v2, or no encryption
    over v1.
  - It does not hide where transactions come from.
  - Hybrid sessions can be told apart from plain v2 by their packet sizes. If
    being recognized matters, use Tor or I2P.
  - The version packets that carry the key exchange are protected by the ECDH
    keys only.
  - Fallback, load shedding and a local ML-KEM fault also leave some
    connections on ECDH keys; `transport_pq` reports which.
- Fallback: when hybrid handshakes of automatic outbound connections to the
  same address fail three times in a row in ways the peer side can cause
  (<!--pq:value-->`malformed_record`, <!--pq:value-->`first_packet_failed` or
  <!--pq:value-->`closed_after_switch`), the node connects to that address
  with plain v2 for an hour, the second time for 4 hours, and then for 24
  hours. An address that completed a hybrid handshake since startup never
  falls back (the node remembers the 1,000 most recent), inbound connections
  never fall back, and a restart forgets the history (#235, #250).
- Manual peers never fall back. Someone on the network path can cause those
  failures without breaking any keys, by damaging, resetting or dropping the
  connection, and so keep an automatic peer on ECDH keys. Connections made
  with <!--pq:rpc-->`addnode` or <!--pq:opt-->`-connect` always negotiate
  hybrid keys, even to an address in the fallback set, and their failures
  never count toward it; they are still counted and logged (#250).
- Load shedding: an offer costs the responder an ML-KEM key generation. When
  more than 1,000 inbound v2 connections reach that point within one second,
  the node stops offering, and those connections continue as plain v2. It
  offers again after 10 seconds in a row below half that rate. Outbound
  connections are not affected. Shedding and the fallback windows are timed
  on the monotonic clock, so a change to the system clock can't trigger
  shedding or stretch either (#235, #250).
- The new <!--pq:rpc-->`getpqtransportinfo` RPC reports the configuration,
  the ML-KEM-1024 code in use (<!--pq:field-->`arith_backend`,
  <!--pq:field-->`keccak_backend`), handshake outcome counters for each
  direction, the load-shedding state, the <!--pq:field-->`fallback_set`, the
  <!--pq:field-->`failure_streaks` and the most recent failures. Its state is
  kept in memory, and a new <!--pq:field-->`instance_id` marks a restart
  (#236).
- <!--pq:rpc-->`getpeerinfo` gains `transport_pq`, true once the peer's key
  confirmation verified, and `transport_pq_status`:
  <!--pq:value-->`pending`, `hybrid`, `legacy_peer`,
  <!--pq:value-->`fallback`, `off` or `v1`. <!--pq:rpc-->`getnetworkinfo`
  gains <!--pq:field-->`connections_pq`, the number of hybrid peers.
  `qbit-cli -netinfo` marks hybrid peers <!--pq:value-->`2p` in its `v`
  column, and qbit-qt's peer details show their transport as "v2 (hybrid
  post-quantum)" (#236).
- At every start, `debug.log` gets one line,
  <!--pq:log-->`v2 pq: … arith=… keccak=…`, which says whether the feature is
  `enabled`, <!--pq:value-->`disabled (-v2pqtransport=0)` or
  <!--pq:value-->`disabled (-v2transport=0)`, and which ML-KEM-1024 code runs
  (#236). Failed outbound handshakes are logged at info level. An address
  entering the fallback set, and handshakes failing with 8 different outbound
  addresses in ways this node's own ML-KEM code could cause with none
  succeeding since startup, are logged as warnings. Inbound outcomes are
  logged only with `-debug=net` (#235, #250).
- ML-KEM-1024 comes from mlkem-native v2.0.0, vendored unmodified in
  `src/mlkem-native` (#225). Native code runs on x86_64 CPUs that have AVX2,
  SSSE3, SSE4.1, POPCNT and BMI2, and on macOS AArch64; portable C runs
  everywhere else. If the native code misbehaves on a CPU, the hidden option
  <!--pq:opt-->`-mlkemportable`, listed by `-help-debug`, selects the portable
  code (#236).
- The [operator guide](user/network/pq-transport.md) shows how to try the
  feature on regtest, switch it on or off, check it and troubleshoot it, and
  covers upgrading and rolling back (#240, #241).

### I2P post-quantum leasesets

- qbit now asks the I2P router for post-quantum hybrid session encryption,
  MLKEM768-X25519 with ECIES-X25519 for peers without it
  (`i2cp.leaseSetEncType=6,4`), as Bitcoin Core does. Java I2P 2.10.0 or
  newer, and i2pd 2.58.0 or newer built with OpenSSL 3.5 or newer, use it;
  other i2pd versions ignore it (#223).
- Java I2P older than 2.10.0 rejects the request, naming the encryption type
  in its reply. qbit then retries once with the previous setting, `4,0`, and
  warns the first time this happens with a router. After two sessions in a
  row in which the router rejects the post-quantum type this way and accepts
  `4,0`, qbit uses `4,0` with that router until qbit restarts. A session that
  gets the post-quantum type starts the count anew, so one passing router
  error does not turn it off. Other rejections, such as a failure to build
  tunnels or a SAM `RESULT=TIMEOUT` reply, are retried the same way but do not
  count and do not warn. A rejection of the session id or the destination is
  not retried, and neither is no reply from the router (a timeout while
  waiting for it, or a closed or broken connection). Upgrade the router to get
  the post-quantum type, then restart qbit (#223).
- Creating an I2P session has a single 3-minute limit that covers every step,
  and stops promptly when qbit shuts down. The limit is measured in elapsed
  time, so a change to the system clock does not extend it (#223, #246).
- The `SESSION CREATE` request, which carries the private key, no longer
  appears in error messages (#223).

### Build

- Release builds of `qbit-photon` now link OpenSSL 3.5.9, the current 3.5
  long-term support release, instead of OpenSSL 3.0.15. The OpenSSL 3.0 series
  reached end of life on 2026-09-07 and no longer receives security fixes. The
  statically linked OpenSSL is built without features that `qbit-photon` does
  not use, including QUIC, Argon2, the thread pool, the ML-KEM, ML-DSA and
  SLH-DSA algorithms, engines, socket BIOs and runtime loading of shared
  objects, so `qbit-photon` no longer loads OpenSSL engines or provider
  modules named by `OPENSSL_CONF` or `OPENSSL_MODULES`. Relay packet
  authentication (HMAC-SHA256) and the relay configuration format are
  unchanged. `qbitd` and the other qbit binaries do not link OpenSSL and are
  not affected (#249).
- qbit builds with Boost 1.91 or newer, which no longer accepts the
  multi-index container definitions inherited from Bitcoin Core. This is a
  backport of bitcoin/bitcoin#35175 and changes no behavior. Release builds use
  the Boost version from depends (#237).
- The new CMake option `WITH_MLKEM_NATIVE` (`AUTO`, the default, `ON` or
  `OFF`) chooses whether the native ML-KEM-1024 code is built, and the
  configure summary names the result. Native code is built for x86_64 with
  GCC or Clang and for macOS AArch64; MSan and MSVC builds use portable C
  only (#225).
- `bench_qbit` builds without the wallet (#244), and the two Cadence
  benchmarks no longer build an unbounded header chain when run without
  `-asymptote` (#229).

### Hardening

- The ML-KEM-1024 decapsulation key and the ECDH secret a hybrid handshake
  keeps until the peer's version packet arrives now live in locked memory,
  which is excluded from core dumps, as private keys are. They are wiped on
  every disconnect path (#230, #235, #248).
- SHA-256 CPU detection now checks the highest CPUID leaf the CPU supports
  before reading leaf 7. In a virtual machine limited to leaf 1, the node used
  to read unrelated data that could claim SHA-NI, and then stopped with an
  illegal instruction in its startup self-test (#248).
- The SSE4, SSE4.1 and SHA-NI SHA-256 code is used only on CPUs that also
  report SSSE3, whose instructions that code executes. A CPU or virtual
  machine that reported SSE4.1 without SSSE3 used to stop with an illegal
  instruction in the startup self-test (#225).
- Native ML-KEM-1024 code runs only when the CPU has every instruction set
  extension it uses, so a virtual machine that exposes AVX2 but masks BMI2 or
  POPCNT runs portable C instead of stopping with an illegal instruction.
  AArch64 Linux builds use portable C only, because the upstream AArch64
  assembly has no BTI landing pads and linking it would remove the binaries'
  BTI, PAC and GCS marking (#225).

### Tests, CI, and documentation

- New unit, functional and fuzz tests cover the hybrid transport: an
  independent Python ML-KEM-1024 and a hybrid Python v2 peer (#224, #239),
  interoperability with the v1.0.0 release binary (#224, #241), misbehaving
  peers, fallback and load shedding (#239), and the fuzz targets `mlkem`,
  `mlkem_backend_diff`, `pq_records` and `p2p_v2_pq_malicious_peer`, with
  seeds in the required corpus (#225, #230, #248). The functional test runner's
  `--v2pqtransport` mode runs the whole suite over the hybrid transport
  (#239, #241). Two regtest-only `-test` options make load shedding testable
  (#239).
- Full Validation runs the ML-KEM-1024 unit tests on AArch64 Linux and on
  macOS, and the whole functional suite over the hybrid transport, for changes
  that can affect them, through a new reusable PQ workflow (#224, #225, #239,
  #241). The previous-release
  tooling now resolves qbit releases (#224), and `contrib/pq-canary` adds
  tools that sample and evaluate a node's hybrid transport state (#224).
- The Required Merge Gate waits for a newer run instead of failing on an
  earlier event's result (#231). The merge gates list both sides of a renamed
  file, and documentation-only changes to the specification and operator
  guide run the checks that read them (#247). The pull request RPC docs build
  checks out the event's commit (#228), and Core Checks' build smoke job
  avoids a slow regional package mirror and caches its packages (#253). The
  `1.1.0` branch is validated like `1.x.x`, and the integration branch's own
  CI entries were removed before it merged (#245).
- `test/lint/lint-pq-doc-tokens.py` checks that every option, RPC, field,
  value and log text marked in the hybrid transport's documents exists, and
  `feature_pq_quickstart.py` runs the operator guide's quick start (#240,
  #247).
- Stabilized `wallet_listtransactions.py` on loaded machines (#243) and the
  Python test peer's handshake and disconnect handling (#246, #251, #254).
- Added the [operator guide](user/network/pq-transport.md) and the
  [specification](design/pq-transport.md), and updated the I2P guide, the
  Bitcoin Core differences page, the RPC delta reference, the fuzzing guide
  and the mlkem-native subtree runbook (#223, #225, #230, #240, #241).

### Changes in v1.0.1

v1.1.0 contains every change in v1.0.1, which the v1.0.1 release notes
describe.

Release verification
====================

Download artifacts only from the release page linked through qbit.org. Verify
`SHA256SUMS.asc` against `SHA256SUMS`, then verify each downloaded artifact
against `SHA256SUMS`. The release page is the source of truth for supported
platform artifacts, signer policy, builder attestations, and the final release
state.

Mainnet publication requires completed qbit P2MR v1 conformance evidence for
the exact signed tag target. The release page states the corpus digest, source
commit, and independent oracle report digest. Those values are produced from the
tagged commit, so they cannot be recorded in this file. Each release candidate
and the final release have their own tag target and their own statement.

Known limitations
=================

- Fuzz evidence for the hybrid transport: a campaign ran 504.6 CPU-hours, 24
  CPU-hours for each of seven targets (`mlkem`, `mlkem_backend_diff`,
  `pq_records`, `p2p_v2_pq_malicious_peer`, `bip324_cipher_roundtrip`,
  `p2p_transport_bidirectional_v2` and `p2p_transport_bidirectional_v1v2`) in
  each of three configurations: ASan and UBSan with native ML-KEM code, the
  same with portable code forced, and MSan with portable code. It ran with
  clang 21 and libFuzzer on one x86_64 machine with AVX2, and found no crash,
  leak, timeout or out-of-memory input. The campaign's builds left out UBSan's
  integer checks, which slowed the transport targets down many times; every
  grown corpus was then replayed cleanly with CI's fuzz flags, which include
  them. The campaign ran on source from before the
  last changes to the fuzzed code: the default turning on, the secrets moving
  to locked memory, the CPUID leaf check and a test-only change. None of them
  touches the wire format, the key derivation or the transport state machine,
  and every grown corpus was replayed once more on later source, without a
  failure. Its limits: only x86_64 was fuzzed, not the AArch64 NEON code,
  which CI's unit tests run on macOS on Apple Silicon; and in the two portable
  configurations `mlkem_backend_diff` compared portable code with itself, so
  the comparison of native against portable code ran only in the native
  configuration ([report](https://github.com/Qbit-Org/qbit/issues/222#issuecomment-6418128043)).
- The load-shedding threshold, 1,000 offers per second, was settled with CPU
  benchmarks. No measurement of block propagation under a handshake flood
  accompanies this release (#215, #222).
- Native ML-KEM-1024 code runs only on x86_64 and on macOS AArch64. AArch64
  Linux, and x86_64 CPUs without the required extensions, run portable C. On
  the x86_64 benchmark in #240, a hybrid handshake with portable C took about
  1.5 times as long as with native code (#225).
- Unsigned-platform waiver: the macOS and Windows artifacts for this release
  are not code-signed or notarized. They are published with `-unsigned` in
  their names, and codesigning payloads are not published. macOS Gatekeeper
  and Windows SmartScreen may warn when they are first opened. The signed
  release tag, the signed `SHA256SUMS`, and the builder attestations still
  apply to every artifact; verify downloads as described in "Release
  verification". This waiver remains until macOS and Windows signing accounts
  are available (#70).

Credits and acknowledgements
============================

Thanks to everyone who contributed code, testing, review, infrastructure, and
release coordination for this release.
