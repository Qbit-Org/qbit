PQC signing no longer leaves secret key material on the stack
=============================================================

The vendored libbitcoinpqc library is updated from v0.3.0 to v0.3.2.
Generating, importing or signing with a PQC key previously left copies of the
secret SLH-DSA seeds, and hashing scratch derived from them, in stack memory
the library had released. Key generation, secret-key validation and signing
now wipe those copies and overwrite the stack they used before returning.

The library now reports a failed memory allocation during key generation or
signing as a distinct out-of-memory error, and reports signing with a secret
key that fails validation as a key error rather than a signature error. qbit
treats every library error as a failed operation, as before, so wallet and RPC
behaviour does not change.

Consensus rules are unchanged. Keys and signatures are byte-identical to
those produced by v1.0.0, and verification accepts and rejects the same
signatures. Signing is about 10% slower and verification a few percent
slower, and each signing call now needs about 17 KiB of free stack.
