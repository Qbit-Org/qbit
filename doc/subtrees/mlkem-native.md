# mlkem-native Vendoring Runbook

This runbook defines how qbit vendors and updates
[mlkem-native](https://github.com/pq-code-package/mlkem-native), the ML-KEM
(FIPS 203) library behind the hybrid post-quantum BIP324 transport.

mlkem-native's C code is CBMC-proved memory-safe, and its x86_64 and AArch64
assembly is HOL-Light-proved correct and constant-time wherever it handles
secret data. Editing any vendored file voids those proofs, so qbit never edits
`src/mlkem-native`. All qbit-owned glue (configuration, backend selection,
the C++ wrapper and the build rules) lives outside it.

## Current Pin

- Source repository: `https://github.com/pq-code-package/mlkem-native.git`
- Source tag: `v2.0.0`
- Commit: `d1b2fe782888bdb761a50336012923180be7f502`
- Tree id of upstream `mlkem/`: `d9d581290ea1e6fa37462bfbc61b9b4266a2e9e5`
- Blob id of upstream `LICENSE`: `79c71b1fdcc53cc17b1df99a0f4d4d48121ac174`
- qbit path: `src/mlkem-native` (`mlkem/` and `LICENSE`, nothing else)

The machine-readable pin is
[`contrib/devtools/mlkem-native.pin`](../../contrib/devtools/mlkem-native.pin).
Keep this section in sync with it.

The whole upstream `mlkem/` directory is vendored, including backends qbit does
not build, so the identity check stays a single tree id and every file that
upstream's single-compilation-unit build (`mlkem_native.c`,
`mlkem_native_asm.S`) includes is present.

## How qbit Builds It

`cmake/mlkem-native.cmake` compiles upstream's single compilation unit
(`mlkem/mlkem_native.c`) and, when native code is enabled, its assembly unit
(`mlkem/mlkem_native_asm.S`) into the `mlkem_native` library, linked privately
into `bitcoin_node` only. Never into `bitcoin_crypto`, `bitcoin_common` or
`bitcoin_consensus`; tests, fuzzers and benchmarks reach it through their node
linkage. All qbit-owned glue lives outside the vendored tree:

- `src/crypto/mlkem_config.h`: the configuration, selected with
  `MLK_CONFIG_FILE`. ML-KEM-1024, the `qbit_mlkem1024` symbol prefix,
  deterministic APIs only, zeroization through `memory_cleanse`, and the
  capability hook.
- `src/crypto/mlkem_arith_backend.h` and `src/crypto/mlkem_fips202_backend.h`:
  the native backends, chosen by qbit rather than by upstream's
  compile-time defaults (which enable x86_64 only for AVX2 compilers).
- `src/crypto/mlkem_shim.h` and `src/crypto/mlkem_backend.c`: the C ABI
  between the library and qbit's C++.
- `src/crypto/mlkem.{h,cpp}`: the `mlkem::` wrapper.

Native code is selected at run time. No source is compiled with `-mavx2` or
another ISA flag: every native entry point asks the capability hook first, and
the hook reads only cached CPU detection plus the portable override. The
`WITH_MLKEM_NATIVE` CMake option (`AUTO`, `ON`, `OFF`) decides whether native
code is built at all, and the configure summary's `ML-KEM-1024 backend` line
says what was chosen and why:

| Target | `AUTO` | `ON` |
|---|---|---|
| x86_64 with GCC or Clang (Linux, macOS, MinGW) | native x86_64 AVX2, used when the CPU has every extension it needs (below) | native |
| macOS arm64 | native AArch64 | native |
| AArch64 ELF (Linux, BSD) | portable (see below) | configure error |
| MSVC | portable, no assembly at all | configure error |
| `SANITIZERS` contains `memory` | portable (MSan cannot see assembly writes) | configure error |
| anything else (riscv64, powerpc64, armv7, s390x, i686, ...) | portable | configure error |

`ci/checks/test_mlkem_build_policy.py` also links the glue with every
assembly routine wrapped by a call counter, and fails if any of them runs while
portable C is forced, or when an entry point run alone on a new thread uses
assembly although portable C is forced (it entered the library without taking
the override). It checks the x86_64 backend natively and the AArch64 backend
as a static binary under `qemu-aarch64`, built from a copy of
`src/crypto/mlkem_config.h` without its AArch64 ELF refusal. CI's build smoke
job requires both.

### x86_64 instruction set

The x86_64 backend runs only where the CPU has every extension its assembly
executes; `cpu_features::HasMlkemX86Native()` checks them once and caches the
answer, and the capability hook answers upstream's single
`MLK_SYS_CAP_X86_64_AVX2` query with it. Upstream annotates its routines
`Features: [AVX2]`, but an audit of the assembled `mlkem_native_asm.S.o`
(v2.0.0) found:

| Extension | Instructions | Where |
|---|---|---|
| AVX2 (with AVX, and the OS saving YMM state) | 256-bit integer ops such as `vpmulhw`, `vperm2i128`, `vpblendd`, `vpsrlvq`, `vpbroadcastq`, `vinserti128` | every routine |
| AVX | `vmovdqa`, `vmovsldup`, `vmovhpd`, `vpinsrq`, `vpinsrw`, `vpextrw` | every routine |
| SSSE3 | `pshufb` | `rej_uniform` |
| SSE4.1 | `pinsrd`, `pinsrq`, `pblendw` | `rej_uniform` |
| POPCNT | `popcnt` | `rej_uniform` |
| BMI2 | `pext` | `rej_uniform` |
| baseline x86-64 | SSE2, `cmov`, `rep movsb`; `endbr64` is a no-op without CET | |

No FMA, AVX-512, BMI1, LZCNT, MOVBE, AES, PCLMUL or SHA instruction occurs.
A virtual machine can show AVX2 while hiding the others; a check of AVX2 alone
would then die with SIGILL on the first ML-KEM operation. qbit's C code is
compiled for baseline x86-64 and uses only SSE2.

Repeat the audit on every library update, with native code built:

```bash
objdump -d --no-show-raw-insn build/src/CMakeFiles/mlkem_native.dir/mlkem-native/mlkem/mlkem_native_asm.S.o \
  | awk -F'\t' 'NF >= 2 && $1 ~ /:$/ { split($2, a, " "); print a[1] }' | sort | uniq -c
```

Classify every mnemonic, and extend `HasMlkemX86Native` and its tests for a
new extension. Then check masked CPUs: under
`qemu-x86_64 -cpu Haswell,-bmi2` (and `-popcnt`, `-sse4.1`, `-ssse3`) a
program using `mlkem::` must report portable and finish without SIGILL.
`test_qbit` itself runs under all four masks.

### MinGW assembly encoding

Windows builds run the x86_64 backend natively too: with GCC or Clang,
upstream declares its SysV-ABI routines `__attribute__((sysv_abi))`, and
`mlkem_native_asm.S` assembles all 15 of them. On MinGW, `core_interface`
passes `-Wa,-muse-unaligned-vector-move` (GCC bug 54412: on 64-bit Windows,
GCC does not keep the stack 32-byte aligned for AVX code). On the assembly,
that flag would make gas encode each of its 632 aligned vector moves
(`vmovdqa`) as an unaligned one (`vmovdqu`): object bytes the HOL-Light proofs
do not cover. `add_mlkem_native` therefore passes the flag to the C sources
only, and `ci/checks/test_mlkem_build_policy.py` checks that it does.

The assembly needs no such protection, because its aligned moves touch only
32-byte aligned data:

- `MLK_ALIGN` stack buffers, which MinGW GCC aligns by over-allocating and
  rounding the address, since it cannot realign the stack pointer (14 sites in
  `mlkem_native.c`, as many as the stack realignments on Linux);
- constant tables, in a 32-byte aligned `.rdata` section.

No aligned move addresses the stack pointer or RIP-relative data, and the
vendored C is compiled without AVX, so it has no AVX spills. A misaligned
buffer would fault rather than give a wrong result. Recheck this on every
library update, by disassembling both objects built for MinGW.

### AArch64 ELF builds are portable only

mlkem-native v2.0.0's AArch64 assembly has no BTI landing pads (`bti c`) and
no GNU property note. A linker keeps an ELF binary's BTI and PAC marking only if
every input object carries it, so linking the native backend would strip the
marking from the whole binary. Hardening wins: AArch64 ELF targets build
portable C. Measured with Ubuntu's `aarch64-linux-gnu-gcc` 15.2.0 and
`-mbranch-protection=standard`, as qbit builds aarch64 Linux:

```text
mlkem_native.c.o, qbit's C and C++ objects   AArch64 feature: BTI, PAC, GCS
mlkem_native_asm.S.o                          (no GNU property note)
binary with portable ML-KEM                   AArch64 feature: BTI, PAC, GCS
same binary with the native backend           (no AArch64 feature note)
ld -z force-bti: asm.o: warning: BTI is required by -z force-bti, but this
  input object file lacks the necessary property note.
```

Revisit when an upstream release ships AArch64 assembly with BTI landing pads
and the GNU property note: then re-run the property comparison below on
aarch64 and, if no marking is lost, drop the `aarch64-elf` rule in
`cmake/mlkem-native.cmake` and `src/crypto/mlkem_config.h`. Never restore the
marking by force-marking objects that lack landing pads. macOS arm64 (Mach-O,
no GNU property notes) keeps the native backend.

### The AArch64 single-lane Keccak mirror

Upstream's `fips202/native/aarch64/x1_scalar.h` runs its scalar assembly
without asking the capability hook, so qbit's portable override could not reach
it and `mlkem::GetBackendNames()` would report portable Keccak while assembly
ran. `src/crypto/mlkem_fips202_backend.h` therefore mirrors that header's
dispatch glue (the same macros and the same proved assembly routine) with a
capability check added. Every other native entry point in the x86_64 and
AArch64 backends checks the hook itself.

The build-policy test's AArch64 case shows the mirror at work: the harness
makes 252 assembly calls natively and none with portable C forced. Its negative
control builds upstream's `x1_scalar.h` in place of the mirror, and then 221
assembly calls leak into a forced-portable run.

## Update Procedure

Run in a qbit worktree:

```bash
contrib/devtools/update-mlkem-native.sh            # the pinned tag
contrib/devtools/update-mlkem-native.sh v2.0.1     # a new release
```

The script fetches the tag or commit from `REMOTE_URL` (default: the pinned
repository) into a temporary repository, so the qbit clone does not become
shallow, replaces `src/mlkem-native` with upstream's `mlkem/` and
`LICENSE` byte for byte, rewrites the pin from the object ids of the fetched
upstream commit, stages both, and checks that the staged tree has exactly those
ids. `REMOTE_REF` selects the ref when no argument is given. It refuses to
follow the pinned tag if upstream moved it to another commit.

Vendor only tagged releases. Read the upstream release notes and changelog
before updating, then work through the PR checklist below: qbit's backend
headers include upstream paths, so an update can need qbit-side changes even
though no vendored file is edited.

## Verify Integrity

```bash
test/lint/mlkem-native-check.sh
```

The check runs offline as part of the lint runner's `subtree` lint. It prints
`GOOD` when `HEAD:src/mlkem-native/mlkem` has the pinned tree id,
`HEAD:src/mlkem-native/LICENSE` has the pinned blob id, `src/mlkem-native`
holds nothing else, and the work tree has no changes under it. Otherwise it
prints `FAIL` with the signature, cause and fix.

## PR Checklist For Library Updates

When a PR touches `src/mlkem-native` or `contrib/devtools/mlkem-native.pin`,
confirm:

- [ ] The new commit is an upstream release tag, and its release notes and
  security advisories were read.
- [ ] The tree was produced by `contrib/devtools/update-mlkem-native.sh`, and
  this runbook's Current Pin matches the pin file.
- [ ] `test/lint/mlkem-native-check.sh` prints `GOOD`, and the full lint runner
  passes.
- [ ] Running the update script again at the new tag leaves no diff.
- [ ] The options `src/crypto/mlkem_config.h` sets, the `MLK_SYS_*` macros it
  reads and the upstream paths the backend headers include still exist with
  the same meaning (upstream `mlkem/mlkem_native_config.h`, `mlkem/src/sys.h`,
  `mlkem/src/native/*/meta.h`).
- [ ] Upstream's `mlkem/src/fips202/native/aarch64/x1_scalar.h` was diffed
  against the mirror in `src/crypto/mlkem_fips202_backend.h`, and the mirror
  still differs only by its capability check.
- [ ] Every native entry point compiled in still asks the capability hook:
  `grep -n "static MLK_INLINE\|mlk_sys_check_capability"` over
  `mlkem/src/native/x86_64/meta.h`, `mlkem/src/native/aarch64/meta.h`,
  `mlkem/src/fips202/native/x86_64/keccak_f1600_x4_avx2.h` and
  `mlkem/src/fips202/native/aarch64/x4_v8a_scalar.h` pairs each function with a
  check. A new unchecked entry point needs a mirror like the x1 one.
- [ ] The x86_64 instruction-set audit above was repeated, and
  `HasMlkemX86Native` still requires every extension the assembly executes.
- [ ] `test_qbit --run_test=mlkem_tests` passes (every case runs on the native
  backend and with portable C forced), and so do
  `ci/checks/test_mlkem_build_policy.py`, the `mlkem` and `mlkem_backend_diff`
  fuzz targets, and `bench_qbit -filter='MLKEM.*'`.
- [ ] The GNU property notes of the release ELF binaries did not lose a
  marking. Build the base and the change with the release hardening flags
  (Guix for release evidence) and compare, for each binary (`qbitd`,
  `qbit-cli`, `qbit-qt`, `test_qbit`, ...):

  ```bash
  readelf -n <binary> | grep -E 'x86 feature|AArch64 feature'
  ```

  x86_64 must keep `IBT, SHSTK`; aarch64 must keep `BTI, PAC` (and `GCS` where
  present). A lost marking blocks the update; see the AArch64 section above.
- [ ] Guix builds of every release host reproduce (two independent builds,
  identical hashes).

## Common Failures

1. Signature:
   `FAIL: src/mlkem-native/mlkem tree <id> differs from pinned tree <id>`
   (or the same for `LICENSE`)
   Cause:
   A vendored file was edited, added, removed or changed mode, or the pin was
   changed without re-vendoring.
   Fix:
   Never edit `src/mlkem-native`. Restore it with
   `contrib/devtools/update-mlkem-native.sh`. Changes belong upstream, or in
   qbit's glue outside the vendored directory.

2. Signature:
   `FAIL: uncommitted changes under src/mlkem-native`
   Cause:
   The work tree or index has edits, new files or deletions under the vendored
   directory.
   Fix:
   `git checkout HEAD -- src/mlkem-native && git clean -fdx -- src/mlkem-native`.

3. Signature:
   `FAIL: src/mlkem-native in HEAD holds entries other than LICENSE and mlkem`
   Cause:
   A qbit file was added next to the vendored tree.
   Fix:
   Move it out; qbit's ML-KEM glue lives in `src/crypto/mlkem*`.

4. Signature:
   `FAIL: <tag> resolves to <commit>, but contrib/devtools/mlkem-native.pin pins <commit>`
   Cause:
   Upstream moved the tag, or `REMOTE_URL` points at a different repository.
   Fix:
   Stop and investigate upstream before vendoring anything. To vendor a
   different commit deliberately, pass it to the script explicitly.

5. Signature:
   `FAIL: staged src/mlkem-native (...) differs from upstream (...)`
   Cause:
   A git attribute, filter or line-ending setting (for example
   `core.autocrlf`) rewrote vendored bytes on staging.
   Fix:
   Remove the setting that applies to `src/mlkem-native` and re-run the update
   script.

## Review Cadence

At least quarterly, check
[upstream releases](https://github.com/pq-code-package/mlkem-native/releases)
and [security advisories](https://github.com/pq-code-package/mlkem-native/security/advisories).
Update promptly for a security fix; otherwise update when a release brings a
proved improvement qbit uses.
