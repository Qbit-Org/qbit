# Reduced SPHINCS+ Snapshot

This directory contains a reduced vendored SPHINCS+ snapshot used by
`qbit-libbitcoinpqc` for the bounded `sphincs-sha2-128s-bounded30` profile.

The public source tree intentionally keeps only the files needed by the
repo-owned CMake target and its conditional SHA2 AVX2 helper path. It does not
carry the upstream standalone KAT generators, upstream Makefiles, inactive
Haraka/SHAKE implementation families, inactive parameter sets, or default
upstream RNG entry points.

Production builds are driven by the repository root `CMakeLists.txt`, not by
upstream SPHINCS+ standalone build files. The exact compiled inventory is
documented in `docs/compiled-code-inventory.md`.

The upstream SPHINCS+ project is available at:

https://github.com/sphincs/sphincsplus

Licensing metadata retained from the vendored tree is in `LICENSE` and
`LICENSES/`.
