# Side-Channel Policy

This document defines the reviewed side-channel scope for
`qbit-libbitcoinpqc`. It is intentionally narrow: this scope covers the bounded
SLH-DSA profile used by qbit, not a general side-channel certification effort.

This scope and production signing posture are tracked in downstream integration
notes.

## Reviewed Scope

The reviewed hardening scope covers:

- functional correctness of key generation, signing, and verification;
- rejection of malformed public keys, secret keys, signatures, and sizes;
- memory-safety defects detectable by tests, fuzzing, and sanitizer-backed
  runs;
- deterministic verification behavior across supported backends;
- avoiding obvious secret leaks through logs, debug output, mock fallbacks, and
  unsafe serialization.

Verification is the primary consensus-reachable path and operates mostly on
public data. This policy treats verification determinism, malformed input
rejection, and backend agreement as consensus-facing requirements.

Signing handles private key material. The reviewed hardening scope checks
ordinary functional behavior and obvious accidental disclosure paths, but it
does not treat the signing implementation as side-channel hardened.

## Production Signing Threat Model

For the current qbit launch posture, production signing is suitable only for
trusted signing environments such as a local wallet process, a dedicated signing
host, or comparably isolated key-custody infrastructure. This repository does
not claim that signing is safe on hostile shared hardware or in physical
attacker settings.

| Threat class | Current launch posture |
|---|---|
| Remote timing observer | Not a formal leakage-analysis target. Do not expose signing latency as a security boundary or describe the signer as constant-time. |
| Local co-resident timing or cache attacker | Out of scope unless a separate signing hardening review is completed. |
| Hostile shared hardware | Out of scope. Do not claim production signing support for hostile multi-tenant hosts from this repository alone. |
| Physical, power, or electromagnetic attacker | Out of scope. |
| Fault injection | Out of scope. |
| Accidental disclosure through logs, debug output, mock fallback, or unsafe serialization | In scope for ordinary review and tests. |

Downstream qbit release notes and wallet/operator guidance should carry this
deployment restriction forward until a separate signing hardening track changes
the accepted threat model.

## Out of Scope Unless Separately Reviewed

The following are not guaranteed unless they go through a separate
implementation and review track:

- strong constant-time signing guarantees;
- cache, timing, power, or electromagnetic side-channel resistance;
- signing on hostile shared hardware;
- physical attacker resistance;
- formal leakage analysis of SPHINCS+, WOTS+, or FORS internals.

Deployments that require local side-channel-resistant signing should treat that
as a separate hardening project with explicit implementation requirements,
platform assumptions, tests, and review.

## Deterministic Signing Policy

Deterministic signing is intentional under this policy. The bounded30 signing
path derives signing randomization from the secret key and message, which keeps
KATs, golden vectors, backend differential tests, and wallet/signing
reproducibility stable. It also avoids adding signing-time operating-system
entropy failure behavior to the current API.

Key generation is different: callers must provide at least 128 bytes of entropy,
which are domain-separated and mixed into the bounded30 seed. The internal
SPHINCS+ `randombytes` hook exists for upstream routines that still request
random bytes. If that hook is invoked without configured deterministic or
caller-provided randomness and operating-system entropy is unavailable, the
process aborts with a fatal diagnostic instead of returning zero-filled bytes.

Deterministic signing is not a side-channel-hardening guarantee. In particular,
it should not be described as a mitigation for timing, cache, power,
electromagnetic, physical, or hostile shared-hardware attacks.

This policy does not introduce randomized or hedged signing, hidden runtime
knobs, or environment-variable switches for signing behavior. Randomized or
hedged signing is deferred for a separate explicit API and review track, while
preserving deterministic signing for tests and reproducibility.
