# Hybrid post-quantum v2 transport

This document specifies how two qbit nodes add an ML-KEM-1024 key exchange to
the [BIP324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki) v2
P2P transport, so that their session keys stay confidential unless both
secp256k1 ECDH and ML-KEM-1024 are broken. It is written so that another
implementation can interoperate, and it is the starting point for outside
review. The tracking issue is
[Qbit-Org/qbit#184](https://github.com/Qbit-Org/qbit/issues/184).

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described
in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they
appear in all capitals.

## Overview

- **Threat.** A passive observer can record v2 traffic today and, with a
  cryptographically relevant quantum computer, later recover the ECDH secret
  from the two 64-byte ElligatorSwift keys at the start of each connection.
  Hybrid keys protect such recordings. The symmetric layer (ChaCha20-Poly1305
  with FSChaCha20 rekeying every 224 packets) is unchanged.
- **Hybrid, and ECDH stays.** Session keys come from HKDF-SHA256 over the BIP324
  ECDH secret, an ML-KEM-1024 shared secret
  ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), NIST category 5) and
  a hash of the negotiation transcript.
- **No extra round trip.** The responder puts its ML-KEM encapsulation key in
  its BIP324 version packet. The initiator waits for that packet, which arrives
  in the same flight as today, and puts the ciphertext in its own version
  packet. Both sides switch keys right after the version packets, and each
  side's first packet under the new keys is a 20-byte key confirmation.
- **Compatible.** Version packet contents are ignored by BIP324 receivers, so
  legacy v2 peers keep today's ECDH-only keys with no disconnect, and v1 peers
  are unaffected. No consensus rule changes.
- **Cost.** 3,184 extra bytes per hybrid connection (two 1,572-byte records and
  two 20-byte confirmations), and one ML-KEM key generation, encapsulation and
  decapsulation.

```text
Initiator                                           Responder
ellswift_I || garbage_I             ---------->
                                    <----------     ellswift_R || garbage_R
                                    <----------     terminator_R || version_R{F0 || ek}    then holds
terminator_I                        ---------->
holds its version until version_R arrives
version_I{F0 || ct}, ECDH keys      ---------->
switch to hybrid keys                               decapsulate; switch to hybrid keys
confirmation, hybrid keys           ---------->
                                    <----------     confirmation, hybrid keys
application packets                 <---------->    application packets
```

Neither side waits for the other's confirmation before sending. A receiver
delivers application messages only after the peer's confirmation verifies.

## Terms

- **Contents**: the plaintext contents of a BIP324 version packet, which
  BIP324 reserves for future versions.
- **Record**: one entry in the contents, as defined below.
- **Own record**: a record with header `0xF0`.
- **Offer**: the responder's own record, carrying an ML-KEM-1024 encapsulation
  key `ek` (1,568 bytes).
- **Accept**: the initiator's own record, carrying an ML-KEM-1024 ciphertext
  `ct` (1,568 bytes).
- **ECDH keys**: the four BIP324 packet ciphers derived from the ECDH secret
  alone. **Hybrid keys**: the four packet ciphers derived by the recipe below.
- **Switch on**: a node configured to offer (as responder) and accept (as
  initiator). With the switch off, a node behaves exactly as BIP324 does today.

## Wire format

### Records

Version packet contents are zero or more records:

```text
contents = record*
record   = CompactSize(len) || header (1 byte) || payload (len - 1 bytes)
```

`len` counts the header plus the payload and MUST be at least 1. `CompactSize`
is Bitcoin's variable-length integer, and a receiver MUST reject non-canonical
encodings as a parse failure. The shape follows the bitcoin-dev
[Transport Feature Negotiation](https://gnusha.org/pi/bitcoindev/29174459-1523-4cf8-a20f-5ce1abc302c3n@googlegroups.com/)
draft.

### Header registry

| Header | Meaning |
|---|---|
| `0x00` | Reserved. |
| `0xF0` | `PQ_MLKEM1024`: the ML-KEM-1024 offer (sent by the responder) and accept (sent by the initiator). The sender's role says which one a record is. |

qbit assigns its own header values from `0xF0` upward, far from the low values
a Transport Feature Negotiation table would assign first. Every other value is
unassigned, and a receiver ignores records with headers it doesn't know.

### Offer and accept

- The responder sends an offer only when its switch is on. The offer's payload
  is the 1,568-byte encapsulation key `ek`.
- The initiator sends an accept only after it received a valid offer and its
  switch is on. The accept's payload is the 1,568-byte ciphertext `ct`.
  Otherwise the initiator sends empty contents.
- qbit sends the offer and the accept as the entire contents, but a receiver
  MUST handle other records alongside them as the parse rules below say.

| Object | Layout | Bytes |
|---|---|---:|
| Offer contents | `fd 21 06 f0 ‖ ek` | 1,572 |
| Accept contents | `fd 21 06 f0 ‖ ct` | 1,572 |
| Record length | CompactSize 1,569 (header plus payload) | `fd 21 06` |
| Encrypted version packet | encrypted length 3 ‖ encrypted payload (header `00` ‖ contents) 1,573 ‖ tag 16 | 1,592 |
| Encrypted confirmation | encrypted length 3 (plaintext `00 00 00`) ‖ encrypted header 1 (plaintext `80`) ‖ tag 16 | 20 |

**AAD.** Both version packets travel under the ECDH keys, with BIP324's
associated data rule: a sender's first packet in its direction authenticates
its garbage, so if a decoy already consumed the garbage, the version packet
uses empty AAD. Confirmations always use empty AAD.

### Parse rules

A receiver parses the contents in one pass:

1. **The whole contents must parse as records.** Empty contents, or a parse
   failure anywhere (truncation, a zero length, a non-canonical or oversized
   length, trailing bytes), mean "no features": the connection continues with
   ECDH keys and MUST NOT be dropped for it. This deliberately differs from the
   Transport Feature Negotiation draft, which disconnects on unparseable
   contents: BIP324 receivers ignore version contents today, and qbit v1.0.0
   relies on that.
2. **The first own record wins.** Later `0xF0` records and records with unknown
   headers are ignored, but the transcript still covers them.
3. **Only after the whole grammar validates** is the first own record checked.
   An offer's payload MUST be exactly 1,568 bytes and MUST pass the FIPS 203
   section 7.2 encapsulation key check (every encoded coefficient below q). An
   accept's payload MUST be exactly 1,568 bytes. A malformed first own record
   disconnects the connection.
4. **A corrupted `ct` of the right length can't be detected**, because ML-KEM
   decapsulation rejects implicitly. The two sides derive different keys, and
   the key confirmation fails at once.

A responder that sent no offer MUST ignore an own record in the initiator's
contents and never decapsulate. A node whose switch is off MUST NOT parse or
validate the peer's contents. qbit's receive limit for any packet, 4,000,013
bytes of contents, bounds the parser's work.

## Message rules

### Responder

- It MUST send its version packet after its garbage terminator without waiting
  to receive anything more from the initiator, such as the initiator's garbage
  terminator or version packet. It MAY send decoy packets before the version
  packet, as BIP324 allows. BIP324 implementations already behave this way.
- After sending an offer, it MUST send nothing more, decoys included, until it
  has processed the initiator's version packet.
- On the initiator's version packet: with no own record, or contents that fail
  to parse, it keeps the ECDH keys and discards its ML-KEM state. With a
  malformed accept, it disconnects. With a valid-length accept, it decapsulates
  and switches.

### Initiator

- With its switch on, it MAY hold its version packet until the responder's
  version packet arrives, and then sends the ciphertext in it. With its switch
  off, it sends its version packet at once, as today.
- On the responder's version packet: with no own record, or contents that fail
  to parse, it sends empty contents and keeps the ECDH keys. With a malformed
  offer, it disconnects. With a valid offer, it encapsulates, sends the accept
  under the ECDH keys and switches.
- It MAY send decoy packets before its version packet, under the ECDH keys.

### Why progress still holds

BIP324's version negotiation phase lists the initiator's steps as receiving a
packet and then sending its own version packet, and notes that version packets
*can* be sent right after the garbage terminator. Deployed initiators send at
once; a hybrid qbit initiator forgoes that optional immediate send and uses the
listed order. All of the progress conditions BIP324 sets for handshake
upgrades still hold: in particular, after sending its garbage terminator each
party moves to version negotiation without waiting for more bytes. The
initiator's wait always ends, because every responder, legacy or hybrid, MUST
send its version packet without waiting to receive anything more from the
initiator. Responders never hold before their own version packet.

BIP324 names post-quantum cryptography upgrades to the handshake among the
features its version negotiation phase is meant to carry.

## Key schedule

### Retained secret

Each side keeps the raw 32-byte BIP324 ECDH secret `ss_ECDH` (the tagged hash
`bip324_ellswift_xonly_ecdh` that BIP324's HKDF consumes) past its normal
lifetime, until it either switches or decides to stay on the ECDH keys. An
implementation SHOULD wipe it on every path.

### Transcript

```text
TH = SHA256( ellswift_I (64) || ellswift_R (64)
           || CompactSize(len(contents_R)) || contents_R
           || CompactSize(len(contents_I)) || contents_I )
```

- `ellswift_I` and `ellswift_R` are the 64-byte ElligatorSwift keys the
  initiator and the responder sent, in that order, whatever the local role.
- `contents_R` and `contents_I` are the full version packet contents each side
  sent, responder first, including unknown and duplicate records.
- Packet framing, garbage, terminators, tags, decoys and confirmations are not
  hashed.
- For the ordinary one-record exchange, the TH input is 3,278 bytes.

### Derivation

HKDF-SHA256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)), with one
32-byte output block per label:

```text
salt = ASCII("qbit_v2_hybrid_mlkem1024") || network_magic      24 + 4 = 28 bytes, no NUL
IKM  = ss_ECDH (32) || ss_MLKEM (32) || TH (32)                  96 bytes
PRK  = HMAC-SHA256(key = salt, msg = IKM)
initiator_L, initiator_P, responder_L, responder_P, session_id
     = HMAC-SHA256(PRK, ASCII(label) || 0x01)                    32 bytes each
```

The network magic is the chain's 4-byte message start in wire order, the same
bytes BIP324's salt uses: mainnet `44 4f 24 a8`, regtest `a6 6b 1f da`.
`ss_MLKEM` is the 32-byte ML-KEM-1024 shared secret: the output of
encapsulation at the initiator and of decapsulation at the responder.

### Switch

- Switching replaces all four packet ciphers at once: the initiator sends with
  `initiator_L` and `initiator_P` and receives with `responder_L` and
  `responder_P`, and the responder the reverse. Each new cipher starts with its
  packet counter at 0, and BIP324's rekeying every 224 packets then derives
  from the hybrid keys.
- The session id becomes the hybrid `session_id`.
- The garbage terminators are not re-derived.
- The initiator switches right after queuing its version packet, and the
  responder right after processing the initiator's version packet.

### Recipe changes

The recipe, its labels, salt and transcript layout are a wire contract between
releases. Any change takes a new header with its own salt label. A label-only
change under the same header would let two adjacent releases both accept the
offer, derive different keys and disconnect at the first hybrid packet.

## The switch boundary

| Direction | Packets | Keys |
|---|---|---|
| Initiator to responder | ElligatorSwift key, garbage, garbage terminator | none (plaintext) |
| Initiator to responder | decoys before the version packet; the version packet (accept or empty) | ECDH |
| Initiator to responder | after a switch: confirmation (hybrid packet 0), then decoys and application packets | hybrid |
| Responder to initiator | ElligatorSwift key, garbage, garbage terminator | none (plaintext) |
| Responder to initiator | decoys before the version packet; the version packet (offer or empty) | ECDH |
| Responder to initiator | after a switch: confirmation (hybrid packet 0), then decoys and application packets | hybrid |

Without a switch, every packet after the garbage terminators uses the ECDH
keys, exactly as in BIP324.

## Key confirmation

**Sending.** Right after switching, a node MUST send a key confirmation as its
first packet under the hybrid keys: an empty decoy packet with header `0x80`
and empty AAD, 20 bytes on the wire. It consumes hybrid packet 0 in that
direction. A node MUST NOT wait for the peer's confirmation before sending
application packets.

**Receiving.** The first packet a node receives under the hybrid keys MUST meet
all of the following, and otherwise the node MUST disconnect at once:

- its decrypted length is 0, checked as soon as the 3 length bytes arrive,
  before waiting for or allocating a body;
- its tag verifies;
- its ignore bit is set. Other header bits are ignored, as BIP324 specifies.

A node MUST NOT deliver application messages, or report the connection as
hybrid, until the peer's confirmation verifies. Without this check, a key
mismatch decrypts to a random length, and about 24% of the time the receiver
would wait until its handshake timeout for bytes that never arrive.

## Failure handling

- Internal ML-KEM errors not caused by the peer never crash the node. A
  responder that can't generate a key sends no offer. An initiator that can't
  check the key or encapsulate continues as if its switch were off for that
  connection. A responder whose decapsulation fails internally closes the
  connection, because the initiator has already switched.
- Key generation draws two independent 32-byte strong random values for the
  64-byte seed, and encapsulation draws one 32-byte value.
- The decapsulation key, the retained ECDH secret, ML-KEM temporaries and
  derived keys are wiped on switch, on staying with ECDH keys, at disconnect
  and timeout, and in destructors.

How qbit counts, logs and reports these outcomes, its fallback after repeated
failures and its load shedding are local policy, described in
[#184](https://github.com/Qbit-Org/qbit/issues/184); they don't change the wire
behavior above.

qbit reports each v2 connection's negotiation status as one of these values:

- `pending` from the start of the handshake until one of the outcomes below;
- `hybrid` once the peer's confirmation verifies;
- `legacy_peer` when the peer's version packet carries no usable offer or
  accept, so the ECDH keys stay;
- `off` when the switch is off, or after a local key generation, key check or
  encapsulation fault that left the connection on plain v2;
- `fallback` for an outbound connection that runs plain v2 because of earlier
  failures; inbound connections never fall back.

There is no failed status. A connection that closes on any failure above or
in key confirmation, local faults included, reports `pending` until it is
removed.

## Security notes

- **Version contents have ECDH-only protection.** The EK, the CT and any future
  record travel under the ECDH keys. A future attacker who breaks ECDH learns
  them, which is fine for ML-KEM's public values but matters for any future
  record that carries secrets.
- **The guarantee holds for confirmed hybrid connections.** A switch that is
  off on either side, a local fault, load shedding and fallback all permit
  ECDH-only sessions. `getpeerinfo` reports `transport_pq` only once the peer's
  confirmation verified.
- **This is not authentication.** BIP324 stays unauthenticated, and an active
  man-in-the-middle can still relay two separate sessions. The hybrid session
  id can be compared out of band the same way BIP324's can.
- **Downgrade.** Stripping an offer or an accept means forging packets under
  the ECDH keys, so it takes an active attacker who breaks ECDH in real time
  or sits in the middle, and an unauthenticated session can't stop the latter
  anyway. A passive recorder can't downgrade a connection.
- **Transcript binding.** Both keys, both contents and the network magic feed
  the derivation, so two sides that saw different negotiation bytes derive
  different keys and fail the confirmation instead of continuing.
- **Distinguishability.** Hybrid sessions are distinguishable from legacy v2
  by packet sizes. Users who need to hide that should use Tor or I2P.
- **Forward secrecy.** Each connection uses a fresh ML-KEM key pair, and the
  decapsulation key is wiped after the switch.

## Interop recipe

The vectors file
[`src/test/data/pq_transport_vectors.json`](../../src/test/data/pq_transport_vectors.json)
holds every input and intermediate. All byte strings are lowercase hex. To
check an implementation against vector 0:

1. Select the chain in `chain` and check that its message start is `magic`.
2. Take `initiator_privkey` with `initiator_ellswift` and `responder_privkey`
   with `responder_ellswift`. Each side's BIP324 ECDH gives `ss_ecdh`; BIP324's
   own HKDF gives `ecdh_session_id` and the two garbage terminators, which the
   switch leaves alone.
3. Run ML-KEM-1024 KeyGen on `mlkem_keygen_seed` (`d || z`) to get `ek`, and
   Encaps on `ek` with `mlkem_encaps_m` to get `ct` and `ss_mlkem`.
   Decapsulating `ct` with the decapsulation key gives `ss_mlkem` too.
4. Build `contents_responder` (`fd 21 06 f0 || ek`) and `contents_initiator`
   (`fd 21 06 f0 || ct`). In vector 2 the responder's offer is followed by a
   second `0xF0` record with a different valid `ek` and an unknown `0xF1`
   record, and the initiator's accept is preceded by an unknown `0x01` record:
   the KEM uses the first `0xF0` record of each contents, and the transcript
   covers every record. Vector 3 appends a 65,535-byte unknown record to the
   offer, so that record's length and the responder's contents length in the
   transcript both take the `0xfe` CompactSize form.
5. Concatenate the transcript input and compare it with `transcript_input`, and
   its SHA256 with `transcript_hash`.
6. Compare `salt`, `ikm`, `prk` and the five derived values.
7. Encrypt the initiator's confirmation (empty contents, header `0x80`, empty
   AAD) with fresh ciphers keyed by `initiator_L` and `initiator_P`; it must
   equal `initiator_confirmation`. Hybrid packet 1 with
   `initiator_first_contents` (a short-id `ping`) must equal
   `initiator_first_packet`. Do the same for the responder.
8. For each entry in `negative_vectors`, the side named by `role` derives from
   `transcript_contents` and `ss_mlkem` instead of the honest values of vector
   `vector`. It must
   get `session_id` and send `confirmation`, and decrypting the honest peer's
   confirmation must fail with `decrypted_length` (reason `length` when nonzero,
   else `tag`); the honest peer fails on its confirmation with
   `peer_decrypted_length`.
9. Each entry in `confirmation_failures` is a first hybrid packet that the side
   named by `receiver` must reject under the honest keys of vector `vector`:
   the length decrypts to `decrypted_length`, and the check fails with
   `failure`, one of `length`, `tag` (a zero length with a damaged tag) and
   `not_decoy`.

### Vector 0

<!-- pq-transport-vectors: vector 0 -->
```text
magic = 444f24a8
initiator_ellswift = 6b5fb320cab84c788ef6393262172b222facedee5e55f4e2fa44bae00b1f36102dd8739200e025a0443a6c6d3d52f003e4b94d296ed3a68e9dacc567f0c7bd09
responder_ellswift = 3d3449542df2dc02aedca2a14e5c6b22f2b797b3191488cdbdc1ff6ad3ef40a77e62023395a490bbacc9de3da7fd37f70592ec361e34c01c761ad4ea2029712c
ss_ecdh = 7e8dd0eda7d613290fcfc7919af8675a2405e6585378777b9d2f02e592f1fb1d
ecdh_session_id = ab8e9ae6fe9d33e2e10f847855298fbe295ed45625608b425ca118d09dbfd0a4
ss_mlkem = 22c8bf5c4858ac2e5f94b6e945ca142ccc28b98e7b954a78899630a7bfa3135f
transcript_hash = 66f0655505928bdeec6ce4cf2b1de08ff16c2cb1cf04b781011e30ca6687c240
salt = 716269745f76325f6879627269645f6d6c6b656d31303234444f24a8
prk = cacbbffc106ea035465bc498d22562e83989c039390ddc1ea36e0fe7ba0ac6b4
initiator_L = d723af332d033d229fe91db011f04cd005657fcc35d59b93b6771e77dc9bd572
initiator_P = 72462d2ed71f2b6b9c7435745166155bbd61ab04e2e21798945d1282f690e7d2
responder_L = 167756b477acb286099da2a866ad9e2d94ec719236dc61836f2956451148ec12
responder_P = 95eb7e61e0e575bd36db2a0b589553984942db0da9f43f8d8bc48012f2323d21
session_id = c749d7dadf82b12615fa4ccdeef8cbce4ffb935ad22a7eac1fbc52d8d1394ea4
initiator_confirmation = 69abb2b1c9601dad7baf8038bc3601eaa42527de
responder_confirmation = a634faec713fb192a52b9e810216b8a36d39516b
initiator_first_packet = 4bbe69dca55d32377b3cee47741171e83115bae7d56d7a9a81dd94394a
responder_first_packet = be28dfc2f7f52321d961b644a0ff9fb473d4f9055c6e9523c696751721
```

The generator's `--check` mode fails if any value above differs from the file.

## Convergence policy and recipe retirement

- qbit tracks bitcoin-dev, bitcoin/bips and upstream transport changes such as
  [bitcoin/bitcoin#36376](https://github.com/bitcoin/bitcoin/issues/36376)
  (rare BIP324 decoys). The rule against decoys between an offer and the
  initiator's version packet binds only offering qbit responders, so upstream
  decoys from legacy peers stay compatible.
- If a Bitcoin standard for post-quantum transport ships, qbit implements it as
  a new header. At most two post-quantum recipes are supported at once, and
  while two exist, `getpeerinfo` reports which one each hybrid peer uses.
- The `0xF0` recipe stays for at least two major releases after that standard
  ships. The release before its removal announces it in its release notes and
  warns at startup while `0xF0` connections are still in use.

## Discussion

This specification, its Python reference and the vectors are to be posted to
the bitcoin-dev threads
[Transport Feature Negotiation](https://gnusha.org/pi/bitcoindev/29174459-1523-4cf8-a20f-5ce1abc302c3n@googlegroups.com/)
and
[A Post-Quantum Path for BIP 324](https://groups.google.com/g/bitcoindev/c/n_5WuKVYqwI/),
asking for a reserved private-use header range and discussing ML-KEM-768
against ML-KEM-1024. Links to those posts will be added here.

## For contributors

### Build and test

```sh
cmake -B build
cmake --build build -j 8 --target test_bitcoin   # builds build/bin/test_qbit
ctest --test-dir build -R bip324_tests
build/bin/test_qbit --run_test=bip324_tests
```

`bip324_tests` replays the vectors file (`hybrid_vectors`) and checks
transcript binding, API misuse and rekey boundaries. The Python reference has
its own unit tests:

```sh
build/test/functional/test_runner.py feature_framework_unit_tests.py
```

The `bip324_cipher_roundtrip` fuzz target covers the switch, mismatched
transcripts, damaged packets and rekeys:

```sh
cmake -B build_fuzz -DBUILD_FOR_FUZZING=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DSANITIZERS=fuzzer,address,undefined
cmake --build build_fuzz --target fuzz
FUZZ=bip324_cipher_roundtrip build_fuzz/bin/fuzz
```

### ML-KEM backends

qbit uses native ML-KEM code on x86_64 with AVX2, detected at run time, and on
macOS arm64, and portable C everywhere else. That includes AArch64 Linux and
every other AArch64 ELF build: upstream's AArch64 assembly has no BTI landing
pads or GNU property note, so linking it would drop BTI/PAC/GCS marking from the
whole binary, and hardening wins. The CMake option
`WITH_MLKEM_NATIVE=AUTO|ON|OFF` controls the build: `OFF` builds portable C
only, and `ON` makes missing native support a configure error, as on AArch64
ELF. At runtime, the hidden `-mlkemportable` option, and
`-test=mlkem_portable` on regtest, force portable C; they arrive with the
operator options ([#209](https://github.com/Qbit-Org/qbit/issues/209)).

### Regenerating the vectors

```sh
contrib/devtools/generate-pq-transport-vectors.py          # rewrite the vectors file
contrib/devtools/generate-pq-transport-vectors.py --check  # what the lint runs
```

The generator imports the Python reference from
`test/functional/test_framework/crypto` (`bip324_cipher.py` for the recipe,
`mlkem.py` for ML-KEM-1024) and never calls the C++ code. Every input comes
from a fixed label, so the output is byte-for-byte reproducible. Changing the
recipe changes the vectors, and both `--check` and `bip324_tests` fail; a
deliberate recipe change needs a new header.

## References

- [BIP324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki),
  the v2 P2P transport, and its version negotiation phase.
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), ML-KEM.
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), HKDF.
- [mlkem-native v2.0.0](https://github.com/pq-code-package/mlkem-native/tree/v2.0.0),
  the C library qbit uses.
- bitcoin-dev,
  [Transport Feature Negotiation](https://gnusha.org/pi/bitcoindev/29174459-1523-4cf8-a20f-5ce1abc302c3n@googlegroups.com/)
  (2026-09-17), and
  [A Post-Quantum Path for BIP 324](https://groups.google.com/g/bitcoindev/c/n_5WuKVYqwI/).
