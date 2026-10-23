Hybrid post-quantum v2 transport
--------------------------------

qbit can now add an ML-KEM-1024 key exchange to the BIP324 v2 transport, so
that the session keys of a connection between two upgraded nodes stay
confidential unless both secp256k1 ECDH and ML-KEM-1024 are broken. This
protects traffic recorded today from decryption by a future quantum computer.
It needs no extra round trip, and costs 3,184 bytes and one ML-KEM key
generation, encapsulation and decapsulation per connection.

It is on by default in this release, so upgrading switches it on. To switch
it off, set <!--pq:opt-->`-v2pqtransport=0` (or `v2pqtransport=0` in
`qbit.conf`) and restart; to switch it back on, remove the setting or set
`-v2pqtransport=1`, and restart. It has no effect with `-v2transport=0`. The
value must be a number: `v2pqtransport=true` is read as 0, which switches it
off, and qbit warns at startup and says how it read such a value. If native
ML-KEM-1024 code misbehaves on a CPU, the hidden option
<!--pq:opt-->`-mlkemportable` selects portable code.

It does not authenticate peers, or protect against spy peers or an active
man-in-the-middle, and it does nothing for traffic with v1.0.0 nodes or any
peer without it, nor for transaction-origin privacy. Hybrid sessions can be
recognized by their packet sizes; where that matters, use Tor or I2P. Peers
without it, including v1.0.0 nodes, keep connecting as before. Nothing it
records persists across a restart. To upgrade with it off, add
`v2pqtransport=0` to `qbit.conf` first: v1.0.0 ignores the line there. v1.0.0
refuses to start with `-v2pqtransport` in any form on its command line, so
don't add it there before upgrading, and remove it before downgrading.

The new <!--pq:rpc-->`getpqtransportinfo` RPC reports the configuration,
handshake outcomes, load shedding and the fallback set. `getpeerinfo` gains
<!--pq:field-->`transport_pq` and <!--pq:field-->`transport_pq_status`,
`getnetworkinfo` gains <!--pq:field-->`connections_pq`, `qbit-cli -netinfo`
marks hybrid peers <!--pq:value-->`2p`, and the log states the setting at
startup in a <!--pq:log-->`v2 pq: … arith=… keccak=…` line. Automatic
outbound connections to an address whose hybrid handshakes keep failing fall
back to plain v2 for a while. Someone on the network path can cause such
failures, so peers added with `addnode` or `-connect` never fall back. A node
under an inbound connection flood stops offering hybrid keys until it
subsides.

See the [operator guide](user/network/pq-transport.md) to try it, check it and
troubleshoot it, and the [specification](design/pq-transport.md). (#240)
