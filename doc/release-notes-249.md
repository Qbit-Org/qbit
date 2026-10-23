qbit-photon OpenSSL
-------------------

Release builds of `qbit-photon` now link OpenSSL 3.5.9, the current 3.5
long-term support release, instead of OpenSSL 3.0.15. The OpenSSL 3.0 series
reached end of life on 2026-09-07 and no longer receives security fixes.

The statically linked OpenSSL is built without features that `qbit-photon`
does not use, including QUIC, Argon2, the thread pool, the ML-KEM, ML-DSA and
SLH-DSA algorithms, engines, socket BIOs and runtime loading of shared
objects. `qbit-photon` therefore no longer loads OpenSSL engines or provider
modules named by `OPENSSL_CONF` or `OPENSSL_MODULES`. Relay packet
authentication (HMAC-SHA256) and the relay configuration format are
unchanged. `qbitd` and the other qbit binaries do not link OpenSSL and are
not affected. (#249)
