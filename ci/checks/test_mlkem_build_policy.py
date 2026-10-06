#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regression tests for qbit's mlkem-native build policy (cmake/mlkem-native.cmake).

Three layers:
- the WITH_MLKEM_NATIVE decision across the architecture, toolchain and
  sanitizer matrix, run in CMake script mode, so every target is covered on
  any host;
- configure and build of the mlkem_native library with each compiler found on
  this host (cross compilers included), checking which sources and flags are
  used;
- the guards in src/crypto/mlkem_config.h that stop a build from compiling
  native code where the policy forbids it.

Cases that need a missing compiler are skipped, unless the compiler is listed
in MLKEM_POLICY_REQUIRED_COMPILERS (space-separated), as CI does for the ones
it installs: then a missing one fails. "cc-m32" stands for cc -m32 with 32-bit
headers. Failures print the signature, cause and fix.

A fourth layer links qbit's glue and wrapper with every assembly routine
wrapped by a call counter, and checks that the portable override reaches each
of them: the x86_64 backend on x86_64 hosts, the AArch64 backend under
qemu-aarch64 (listed as qemu-aarch64 and aarch64-linux-gnu-g++ in
MLKEM_POLICY_REQUIRED_COMPILERS when required).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = REPO_ROOT / "cmake" / "mlkem-native.cmake"
REQUIRED_COMPILERS = frozenset(os.environ.get("MLKEM_POLICY_REQUIRED_COMPILERS", "").split())


def skip_missing_compiler(test: unittest.TestCase, executable: str, problem: str = "not found") -> None:
    if executable in REQUIRED_COMPILERS:
        test.fail(f"FAIL: {executable} {problem}\nCause: MLKEM_POLICY_REQUIRED_COMPILERS lists it\n"
                  f"Fix: install it, or drop it from MLKEM_POLICY_REQUIRED_COMPILERS")
    test.skipTest(f"{executable} {problem}")

SUPPORTED_ARCHS = ("x86_64", "aarch64-macho")
UNSUPPORTED_ARCHS = (
    "aarch64-elf",
    "this target (riscv64)",
    "this target (ppc64)",
    "this target (powerpc64le)",
    "this target (armv7)",
    "this target (s390x)",
    "this target (i686)",
)
SANITIZER_SETTINGS = ("", "address,undefined", "thread", "memory", "fuzzer,memory", "memory,undefined")

POLICY_SCRIPT = r"""
include("${MODULE}")
mlkem_native_policy("${MODE}" "${ARCH}" "${MSVC}" "${SANITIZERS}")
message(NOTICE "RESULT enabled=${MLKEM_NATIVE_ENABLED} no_asm=${MLKEM_NATIVE_NO_ASM} reason=${MLKEM_NATIVE_REASON}")
"""

FIXTURE_CMAKELISTS = r"""
cmake_minimum_required(VERSION 3.22)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
project(qbit_mlkem_policy LANGUAGES NONE)

if(NOT DEFINED QBIT_SOURCE_DIR)
  message(FATAL_ERROR "QBIT_SOURCE_DIR is required")
endif()
set(PROJECT_SOURCE_DIR "${QBIT_SOURCE_DIR}")
set(WITH_MLKEM_NATIVE "AUTO" CACHE STRING "")

# Stand-ins for qbit's interface libraries: the hardening marker must reach
# mlkem_native, the C++-only warning must not.
add_library(core_interface INTERFACE)
# Like core_interface's -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3, which the MSan
# jobs undo with APPEND_CPPFLAGS=-U_FORTIFY_SOURCE.
target_compile_options(core_interface INTERFACE -DQBIT_POLICY_CORE_FLAG -UQBIT_POLICY_FORTIFY -DQBIT_POLICY_FORTIFY=3)
add_library(warn_interface INTERFACE)
target_compile_options(warn_interface INTERFACE -Wsuggest-override)
target_link_libraries(core_interface INTERFACE warn_interface)
add_library(sanitize_interface INTERFACE)

include("${QBIT_SOURCE_DIR}/cmake/mlkem-native.cmake")
mlkem_native_configure()
# Like CMakeLists.txt on MinGW, where the compiler accepts it (GCC's assembler
# does, Clang's integrated one does not).
if(MINGW AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
  target_compile_options(core_interface INTERFACE -Wa,-muse-unaligned-vector-move)
  message(NOTICE "CORE_UNALIGNED_VECTOR_MOVE")
endif()
message(NOTICE "SUMMARY ${MLKEM_NATIVE_SUMMARY}")
message(NOTICE "ENABLE_MLKEM_NATIVE=${ENABLE_MLKEM_NATIVE}")
add_mlkem_native()
"""

# Compiler setups for the configure-and-build layer: (name, executable,
# extra CMake definitions, target architecture, whether AUTO builds native code).
# A setup without extra definitions targets this host. AArch64 ELF is portable
# only (no BTI landing pads in the assembly); macOS arm64, which builds native
# code, needs an SDK and is covered by the CI job on Apple hardware.
COMPILERS = (
    ("host cc", "cc", (), "x86_64", True),
    ("clang-21", "clang-21", (), "x86_64", True),
    ("aarch64 gcc", "aarch64-linux-gnu-gcc", ("-DCMAKE_SYSTEM_NAME=Linux", "-DCMAKE_SYSTEM_PROCESSOR=aarch64"), "aarch64", False),
    ("clang-21 --target=aarch64-linux-gnu", "clang-21",
     ("-DCMAKE_SYSTEM_NAME=Linux", "-DCMAKE_SYSTEM_PROCESSOR=aarch64", "-DCMAKE_C_COMPILER_TARGET=aarch64-linux-gnu"), "aarch64", False),
    ("mingw-w64 gcc", "x86_64-w64-mingw32-gcc-posix", ("-DCMAKE_SYSTEM_NAME=Windows", "-DCMAKE_SYSTEM_PROCESSOR=x86_64"), "x86_64", True),
    ("clang-21 --target=x86_64-w64-mingw32", "clang-21",
     ("-DCMAKE_SYSTEM_NAME=Windows", "-DCMAKE_SYSTEM_PROCESSOR=x86_64", "-DCMAKE_C_COMPILER_TARGET=x86_64-w64-mingw32"), "x86_64", True),
)


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def host_arch() -> str:
    machine = run(["uname", "-m"]).stdout.strip()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)


class MlkemPolicyMatrixTest(unittest.TestCase):
    """WITH_MLKEM_NATIVE decisions, in CMake script mode."""

    def policy(self, mode: str, arch: str, msvc: bool, sanitizers: str) -> subprocess.CompletedProcess[str]:
        cmake = shutil.which("cmake")
        self.assertIsNotNone(cmake, "cmake is required")
        assert cmake is not None
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "policy.cmake"
            script.write_text(POLICY_SCRIPT, encoding="utf8")
            return run([
                cmake,
                f"-DMODULE={MODULE}",
                f"-DMODE={mode}",
                f"-DARCH={arch}",
                f"-DMSVC={'TRUE' if msvc else 'FALSE'}",
                f"-DSANITIZERS={sanitizers}",
                "-P", str(script),
            ])

    def expect(self, mode: str, arch: str, msvc: bool, sanitizers: str) -> tuple[bool, bool, str | None]:
        """The policy as documented in cmake/mlkem-native.cmake: (enabled, no_asm, configure error)."""
        no_asm = msvc
        blocked = msvc or arch not in SUPPORTED_ARCHS or re.search(r"(^|,)memory($|,)", sanitizers) is not None
        if mode.upper() == "OFF":
            return False, no_asm, None
        if blocked:
            if mode.upper() == "ON":
                return False, no_asm, "WITH_MLKEM_NATIVE=ON, but"
            return False, no_asm, None
        return True, no_asm, None

    def test_matrix(self) -> None:
        for mode in ("AUTO", "ON", "OFF", "auto"):
            for arch in SUPPORTED_ARCHS + UNSUPPORTED_ARCHS:
                for msvc in (False, True):
                    for sanitizers in SANITIZER_SETTINGS:
                        with self.subTest(mode=mode, arch=arch, msvc=msvc, sanitizers=sanitizers):
                            result = self.policy(mode, arch, msvc, sanitizers)
                            combined = result.stdout + result.stderr
                            enabled, no_asm, error = self.expect(mode, arch, msvc, sanitizers)
                            if error:
                                self.assertNotEqual(result.returncode, 0,
                                    f"FAIL: WITH_MLKEM_NATIVE={mode} configured for {arch}, msvc={msvc}, "
                                    f"SANITIZERS={sanitizers!r}\nCause: ON must refuse targets without native code\n"
                                    f"Fix: mlkem_native_policy in {MODULE}\n{combined}")
                                self.assertIn(error, combined)
                                continue
                            self.assertEqual(result.returncode, 0, combined)
                            match = re.search(r"RESULT enabled=(\w+) no_asm=(\w+) reason=(.*)", combined)
                            self.assertIsNotNone(match, combined)
                            assert match is not None
                            self.assertEqual(match.group(1) == "TRUE", enabled,
                                f"FAIL: native={match.group(1)} for {mode}/{arch}/msvc={msvc}/{sanitizers!r}\n"
                                f"Cause: policy disagrees with the documented matrix\nFix: mlkem_native_policy in {MODULE}")
                            self.assertEqual(match.group(2) == "TRUE", no_asm, combined)
                            self.assertTrue(match.group(3).strip(), "every decision states its reason")

    def test_invalid_mode_fails(self) -> None:
        for mode in ("YES", "1", "native", ""):
            with self.subTest(mode=mode):
                result = self.policy(mode, "x86_64", False, "")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("WITH_MLKEM_NATIVE must be AUTO, ON or OFF", result.stdout + result.stderr)


class MlkemBuildTest(unittest.TestCase):
    """Configure and build mlkem_native with the compilers on this host."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)
        self.source = self.tmp_path / "source"
        self.source.mkdir()
        (self.source / "CMakeLists.txt").write_text(FIXTURE_CMAKELISTS, encoding="utf8")
        self.cmake = shutil.which("cmake")
        self.assertIsNotNone(self.cmake, "cmake is required")
        self.assertIsNotNone(shutil.which("ninja"), "ninja is required")

    def configure(self, name: str, compiler: str, *definitions: str,
                  env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        assert self.cmake is not None
        return run([
            self.cmake, "-S", str(self.source), "-B", str(self.tmp_path / name), "-G", "Ninja",
            f"-DQBIT_SOURCE_DIR={REPO_ROOT}", f"-DCMAKE_C_COMPILER={compiler}", "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
            *definitions,
        ], env=env)

    def compile_flags(self, name: str) -> dict[str, list[str]]:
        """The flags of mlkem_native's compile commands by source name, without the file arguments."""
        commands = run(["ninja", "-C", str(self.tmp_path / name), "-t", "commands", "mlkem_native"])
        self.assertEqual(commands.returncode, 0, commands.stdout + commands.stderr)
        flags: dict[str, list[str]] = {}
        for line in commands.stdout.splitlines():
            words = line.split()
            if "-c" not in words:
                continue
            kept = []
            skip = False
            for word in words[1:]:
                if skip:
                    skip = False
                elif word in ("-MT", "-MF", "-o", "-c"):
                    skip = True
                elif word != "-MD":
                    kept.append(word)
            flags[Path(words[-1]).name] = kept
        return flags

    def build(self, name: str) -> subprocess.CompletedProcess[str]:
        assert self.cmake is not None
        return run([self.cmake, "--build", str(self.tmp_path / name), "--target", "mlkem_native", "--verbose"])

    def check_build(self, label: str, compiler: str, extra: tuple[str, ...], mode: str, expect_native: bool) -> str:
        name = re.sub(r"\W+", "_", f"{label}_{mode}")
        configured = self.configure(name, compiler, f"-DWITH_MLKEM_NATIVE={mode}",
                                    "-DAPPEND_CPPFLAGS=-UQBIT_POLICY_FORTIFY", "-DAPPEND_CFLAGS=-DQBIT_POLICY_APPEND_CFLAG", *extra)
        self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)
        self.assertIn("SUMMARY native" if expect_native else "SUMMARY portable", configured.stdout + configured.stderr)
        self.assertIn(f"ENABLE_MLKEM_NATIVE={'TRUE' if expect_native else 'FALSE'}", configured.stdout + configured.stderr)
        unaligned_moves = "CORE_UNALIGNED_VECTOR_MOVE" in configured.stdout + configured.stderr
        if "-DCMAKE_SYSTEM_NAME=Windows" in extra and Path(compiler).name.endswith(("gcc", "gcc-posix")):
            self.assertTrue(unaligned_moves, "the fixture must pass -Wa,-muse-unaligned-vector-move for MinGW GCC, as CMakeLists.txt does")
        built = self.build(name)
        log = built.stdout + built.stderr
        self.assertEqual(built.returncode, 0,
            f"FAIL: mlkem_native does not build with {label}, WITH_MLKEM_NATIVE={mode}\n{log}")
        compile_lines = [line for line in log.splitlines() if " -c " in line]
        self.assertTrue(compile_lines, log)
        for line in compile_lines:
            self.assertNotRegex(line, r"(^|\s)-m(avx|avx2|arch=|cpu=)",
                f"FAIL: an ISA flag reached an mlkem_native source with {label}\n"
                f"Cause: native code must be selected at run time\nFix: remove the flag from {MODULE}\n{line}")
            self.assertIn("-DQBIT_POLICY_CORE_FLAG", line, "core_interface's own options must apply to C and assembly")
            self.assertNotIn("-Wsuggest-override", line, "qbit's C++ warning set must not reach the vendored C")
            # APPEND_CPPFLAGS and APPEND_CFLAGS come after core_interface's options, so they can undo one
            # (the MSan jobs pass -U_FORTIFY_SOURCE against core_interface's -D_FORTIFY_SOURCE=3).
            words = line.split()
            last_undefine = len(words) - 1 - words[::-1].index("-UQBIT_POLICY_FORTIFY")
            self.assertGreater(last_undefine, words.index("-DQBIT_POLICY_FORTIFY=3"),
                f"FAIL: APPEND_CPPFLAGS did not reach an mlkem_native compile after core_interface's options with {label}\n"
                f"Cause: the C and assembly sources do not get the APPEND flags, or CMake de-duplicated them\n"
                f"Fix: add_mlkem_native in {MODULE}\n{line}")
            self.assertIn("-DQBIT_POLICY_APPEND_CFLAG", words, line)
        asm_lines = [line for line in compile_lines if "mlkem_native_asm.S" in line]
        if unaligned_moves:
            # The flag would re-encode the proved assembly; the C sources keep it.
            for line in compile_lines:
                self.assertEqual("-Wa,-muse-unaligned-vector-move" in line.split(), line not in asm_lines,
                    f"FAIL: -Wa,-muse-unaligned-vector-move must reach mlkem_native's C sources and not its assembly ({label})\n"
                    f"Cause: gas would encode the assembly's vmovdqa as vmovdqu, which the HOL-Light proofs do not cover\n"
                    f"Fix: add_mlkem_native in {MODULE}\n{line}")
        if expect_native:
            self.assertEqual(len(asm_lines), 1, log)
            for line in compile_lines:
                self.assertIn("-DQBIT_MLKEM_NATIVE", line, line)
        else:
            self.assertEqual(asm_lines, [], log)
            for line in compile_lines:
                self.assertNotIn("-DQBIT_MLKEM_NATIVE", line, line)
        return log

    def test_compilers(self) -> None:
        found = 0
        for label, executable, extra, arch, native in COMPILERS:
            compiler = shutil.which(executable)
            with self.subTest(compiler=label):
                if compiler is None:
                    skip_missing_compiler(self, executable)
                if not extra and arch != host_arch():
                    self.skipTest(f"{label} targets {arch}, not this host")
                assert compiler is not None
                found += 1
                self.check_build(label, compiler, extra, "OFF", False)
                log = self.check_build(label, compiler, extra, "AUTO", native)
                target = next((d.split("=", 1)[1] for d in extra if d.startswith("-DCMAKE_C_COMPILER_TARGET=")), None)
                if native:
                    self.check_build(label, compiler, extra, "ON", True)
                    if target:
                        asm_line = next(line for line in log.splitlines() if "mlkem_native_asm.S" in line)
                        self.assertRegex(asm_line, rf"(--target=|-target ){re.escape(target)}\b",
                            "FAIL: assembly built without the C compiler's target\n"
                            "Cause: CMAKE_ASM_COMPILER_TARGET not propagated\nFix: mlkem_native_configure")
                else:
                    on = self.configure(re.sub(r"\W+", "_", f"{label}_ON"), compiler, "-DWITH_MLKEM_NATIVE=ON", *extra)
                    combined = re.sub(r"\s+", " ", on.stdout + on.stderr)
                    self.assertNotEqual(on.returncode, 0, combined)
                    self.assertIn("WITH_MLKEM_NATIVE=ON, but", combined)
                    if arch == "aarch64":
                        self.assertIn("no BTI landing pads", combined)
        self.assertGreater(found, 0, "no usable C compiler found")

    def test_append_flags_change_the_detected_target(self) -> None:
        """APPEND_CPPFLAGS/APPEND_CFLAGS reach the library, so the target probes must see them: -m32 is not x86_64."""
        if host_arch() != "x86_64":
            self.skipTest("needs an x86_64 host")
        compiler = shutil.which("cc")
        assert compiler is not None
        if run([compiler, "-m32", "-x", "c", "-c", "-o", os.devnull, "-"], input="#include <stdint.h>\nint x;\n").returncode != 0:
            skip_missing_compiler(self, "cc-m32", "has no 32-bit headers")
        name = "append_m32"
        configured = self.configure(name, compiler, "-DWITH_MLKEM_NATIVE=AUTO", "-DAPPEND_CPPFLAGS=-m32", "-DAPPEND_CFLAGS=-m32")
        output = configured.stdout + configured.stderr
        self.assertEqual(configured.returncode, 0, output)
        self.assertIn("SUMMARY portable", output,
            f"FAIL: APPEND_CFLAGS=-m32 still detected x86_64\nCause: the target probes ran without the appended flags\nFix: mlkem_native_detect_arch in {MODULE}")
        built = self.build(name)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        # A reconfigure without the flag probes again and goes back to native.
        configured = self.configure(name, compiler, "-DWITH_MLKEM_NATIVE=AUTO", "-DAPPEND_CPPFLAGS=", "-DAPPEND_CFLAGS=")
        self.assertIn("SUMMARY native", configured.stdout + configured.stderr, configured.stdout + configured.stderr)

    def test_memory_sanitizer(self) -> None:
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler)
        assert compiler is not None
        auto = self.configure("msan_auto", compiler, "-DSANITIZERS=memory")
        self.assertEqual(auto.returncode, 0, auto.stdout + auto.stderr)
        self.assertIn("ENABLE_MLKEM_NATIVE=FALSE", auto.stdout + auto.stderr)
        self.assertIn("MemorySanitizer", auto.stdout + auto.stderr)
        built = self.build("msan_auto")
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        self.assertNotIn("mlkem_native_asm.S", built.stdout + built.stderr)

        on = self.configure("msan_on", compiler, "-DSANITIZERS=fuzzer,memory", "-DWITH_MLKEM_NATIVE=ON")
        self.assertNotEqual(on.returncode, 0, on.stdout + on.stderr)
        self.assertIn("WITH_MLKEM_NATIVE=ON, but MemorySanitizer", re.sub(r"\s+", " ", on.stdout + on.stderr))

    def test_asm_flags_keep_explicit_configuration(self) -> None:
        """The assembly gets the C flags, followed by the ASM flags the user, the
        environment or the toolchain set; per configuration, only CMake's own
        default gives way to the C flags."""
        if host_arch() != "x86_64":
            self.skipTest("the host compiler builds no native ML-KEM code on this host")
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler)
        assert compiler is not None
        toolchain = self.tmp_path / "asm-toolchain.cmake"
        toolchain.write_text('set(CMAKE_ASM_FLAGS_INIT "-DTOOLCHAIN_ASM_FLAG")\n'
                             'set(CMAKE_ASM_FLAGS_RELWITHDEBINFO_INIT "-DTOOLCHAIN_ASM_RELWITHDEBINFO")\n', encoding="utf8")
        c_flags = ("-DCMAKE_C_FLAGS=-DQBIT_POLICY_C_FLAG", "-DCMAKE_C_FLAGS_RELWITHDEBINFO=-O2 -g -DQBIT_POLICY_C_RELWITHDEBINFO")
        clean_env = {key: value for key, value in os.environ.items() if key != "ASMFLAGS"}
        # (name, definitions, ASMFLAGS, flags the assembly gets after the C flags, RelWithDebInfo flag)
        cases = (
            ("default", (), None, (), "-DQBIT_POLICY_C_RELWITHDEBINFO"),
            ("user", ("-DCMAKE_ASM_FLAGS=-DUSER_ASM_FLAG",), None, ("-DUSER_ASM_FLAG",), "-DQBIT_POLICY_C_RELWITHDEBINFO"),
            ("environment", (), "-DENV_ASM_FLAG", ("-DENV_ASM_FLAG",), "-DQBIT_POLICY_C_RELWITHDEBINFO"),
            ("toolchain", (f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",), None, ("-DTOOLCHAIN_ASM_FLAG",), "-DTOOLCHAIN_ASM_RELWITHDEBINFO"),
            ("user per-config", ("-DCMAKE_ASM_FLAGS_RELWITHDEBINFO=-DUSER_ASM_RELWITHDEBINFO",), None, (), "-DUSER_ASM_RELWITHDEBINFO"),
        )
        for label, definitions, asmflags, asm_only, config_flag in cases:
            with self.subTest(case=label):
                name = re.sub(r"\W+", "_", f"asm_flags_{label}")
                env = dict(clean_env, ASMFLAGS=asmflags) if asmflags else clean_env
                configured = self.configure(name, compiler, *c_flags, *definitions, env=env)
                self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)
                flags = self.compile_flags(name)
                asm = flags["mlkem_native_asm.S"]
                for flag in ("-DQBIT_POLICY_C_FLAG", *asm_only, config_flag):
                    self.assertEqual(asm.count(flag), 1,
                        f"FAIL: {flag} reaches mlkem_native_asm.S {asm.count(flag)} times ({label})\n"
                        f"Cause: mlkem_native_configure replaced or repeated the ASM flags\nFix: {MODULE}\n{asm}")
                for flag in asm_only:
                    self.assertGreater(asm.index(flag), asm.index("-DQBIT_POLICY_C_FLAG"),
                        f"FAIL: {flag} comes before the C flags ({label})\n"
                        f"Cause: explicit ASM flags must win on conflict\nFix: {MODULE}\n{asm}")
                if config_flag != "-DQBIT_POLICY_C_RELWITHDEBINFO":
                    self.assertNotIn("-DQBIT_POLICY_C_RELWITHDEBINFO", asm,
                        f"FAIL: the C RelWithDebInfo flags replaced an explicit ASM value ({label})\nFix: {MODULE}\n{asm}")
                else:
                    # Apart from explicit ASM flags, the assembly compiles exactly like the C.
                    self.assertEqual([word for word in asm if word not in asm_only], flags["mlkem_native.c"])
                # A reconfigure, with or without the environment, must not accumulate flags.
                for again in (env, clean_env):
                    reconfigured = self.configure(name, compiler, *c_flags, *definitions, env=again)
                    self.assertEqual(reconfigured.returncode, 0, reconfigured.stdout + reconfigured.stderr)
                    self.assertEqual(self.compile_flags(name), flags,
                        f"FAIL: a reconfigure changed the mlkem_native compile commands ({label})\n"
                        f"Cause: mlkem_native_configure wrote the ASM flags back to the cache\nFix: {MODULE}")

    def test_asm_flags_with_depends_toolchain(self) -> None:
        """A toolchain rendered from depends/toolchain.cmake.in, as depends/Makefile
        does, assembles with exactly the flags of the C sources."""
        # (name, C compiler, tool prefix, cross: (system name, arch, host), whether AUTO builds native code)
        setups = (
            ("native", "cc", "", None, True),
            ("mingw-w64", "x86_64-w64-mingw32-gcc-posix", "x86_64-w64-mingw32-", ("Windows", "x86_64", "x86_64-w64-mingw32"), True),
            ("aarch64 linux", "aarch64-linux-gnu-gcc", "aarch64-linux-gnu-", ("Linux", "aarch64", "aarch64-linux-gnu"), False),
        )
        template = (REPO_ROOT / "depends" / "toolchain.cmake.in").read_text(encoding="utf8")
        clean_env = {key: value for key, value in os.environ.items() if key not in ("ASMFLAGS", "CFLAGS")}
        for label, executable, prefix, cross, native in setups:
            with self.subTest(toolchain=label):
                compiler = shutil.which(executable)
                if compiler is None:
                    skip_missing_compiler(self, executable)
                assert compiler is not None
                if cross is None and host_arch() != "x86_64":
                    self.skipTest("the host compiler builds no native ML-KEM code on this host")
                system, arch, host = cross or ("", "", "")
                values = {
                    "depends_crosscompiling": "TRUE" if cross else "FALSE", "host": host,
                    "host_system_name": system, "host_system_version": "", "host_arch": arch,
                    "CC": compiler, "CXX": compiler, "OSX_SDK": "",
                    "CFLAGS": "-pipe -DQBIT_DEPENDS_CFLAG", "CFLAGS_RELEASE": "-O2 -DQBIT_DEPENDS_RELEASE_CFLAG",
                    "CFLAGS_DEBUG": "-O1", "CXXFLAGS": "", "CXXFLAGS_RELEASE": "", "CXXFLAGS_DEBUG": "",
                    "CPPFLAGS": "", "CPPFLAGS_RELEASE": "", "CPPFLAGS_DEBUG": "",
                    "LDFLAGS": "", "LDFLAGS_RELEASE": "", "LDFLAGS_DEBUG": "",
                    **{tool.upper(): shutil.which(prefix + tool) or prefix + tool
                       for tool in ("ar", "ranlib", "strip", "objcopy", "objdump")},
                }
                rendered = re.sub(r"@(\w+)@", lambda match: values.get(match.group(1), ""), template)
                name = re.sub(r"\W+", "_", f"depends_{label}")
                toolchain_dir = self.tmp_path / f"{name}_prefix"
                toolchain_dir.mkdir()
                (toolchain_dir / "toolchain.cmake").write_text(rendered, encoding="utf8")
                configured = self.configure(name, compiler, f"-DCMAKE_TOOLCHAIN_FILE={toolchain_dir / 'toolchain.cmake'}",
                                            env=clean_env)
                self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)
                self.assertIn(f"ENABLE_MLKEM_NATIVE={'TRUE' if native else 'FALSE'}", configured.stdout + configured.stderr)
                flags = self.compile_flags(name)
                for flag in ("-DQBIT_DEPENDS_CFLAG", "-DQBIT_DEPENDS_RELEASE_CFLAG"):
                    self.assertIn(flag, flags["mlkem_native.c"], flags)
                if not native:
                    self.assertNotIn("mlkem_native_asm.S", flags)
                    continue
                # Except the MinGW flag that would re-encode the proved assembly (check_build).
                c_flags = [flag for flag in flags["mlkem_native.c"] if flag != "-Wa,-muse-unaligned-vector-move"]
                self.assertEqual(flags["mlkem_native_asm.S"], c_flags,
                    f"FAIL: with the {label} depends toolchain the assembly flags differ from the C flags\n"
                    f"Cause: mlkem_native_configure changed what depends builds pass to the assembler\nFix: {MODULE}")


class MlkemConfigHeaderTest(unittest.TestCase):
    """src/crypto/mlkem_config.h refuses native code the policy forbids."""

    def compile_backend(self, compiler: str, *flags: str) -> subprocess.CompletedProcess[str]:
        return run([
            compiler, "-fsyntax-only", '-DMLK_CONFIG_FILE="crypto/mlkem_config.h"',
            f"-I{REPO_ROOT / 'src'}", f"-I{REPO_ROOT / 'src' / 'mlkem-native'}",
            *flags, str(REPO_ROOT / "src" / "crypto" / "mlkem_backend.c"),
        ])

    def test_guards(self) -> None:
        cc = shutil.which("cc")
        self.assertIsNotNone(cc)
        assert cc is not None
        self.assertEqual(self.compile_backend(cc).returncode, 0)
        both = self.compile_backend(cc, "-DQBIT_MLKEM_NATIVE", "-DMLK_CONFIG_NO_ASM")
        self.assertNotEqual(both.returncode, 0)
        self.assertIn("QBIT_MLKEM_NATIVE and MLK_CONFIG_NO_ASM", both.stderr)

        cases = (
            ("clang-21", ("-fsanitize=memory", "-DQBIT_MLKEM_NATIVE"), "MemorySanitizer cannot see writes"),
            ("aarch64-linux-gnu-gcc", ("-DQBIT_MLKEM_NATIVE",), "no BTI landing pads"),
            ("cc", ("-m32", "-DQBIT_MLKEM_NATIVE"), "no native ML-KEM backend"),
        )
        for executable, flags, message in cases:
            compiler = shutil.which(executable)
            with self.subTest(compiler=executable, flags=flags):
                if compiler is None:
                    skip_missing_compiler(self, executable)
                assert compiler is not None
                if flags[0] == "-m32" and self.compile_backend(compiler, "-m32").returncode != 0:
                    skip_missing_compiler(self, "cc-m32", "has no 32-bit headers")
                result = self.compile_backend(compiler, *flags)
                self.assertNotEqual(result.returncode, 0, f"FAIL: {executable} {flags} compiled native code")
                self.assertIn(message, result.stderr)



COVERAGE_HARNESS = r"""
#include <crypto/mlkem.h>
#include <array>
#include <cstdio>
#include <functional>
#include <thread>
#include <vector>
unsigned long AsmCalls();
using namespace mlkem;
static std::array<uint8_t, KEYGEN_SEED_BYTES> Seed()
{
    std::array<uint8_t, KEYGEN_SEED_BYTES> seed{};
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = uint8_t(i * 7 + 1);
    return seed;
}
static const std::array<uint8_t, ENCAPS_COINS_BYTES> COINS{};
static std::vector<uint8_t> RoundTrip()
{
    PublicKey ek; DecapsulationKey dk; Ciphertext ct; SharedSecret sent, received;
    if (KeyGen(Seed(), ek, dk) != Error::NONE || CheckPublicKey(ek) != Error::NONE ||
        Encaps(ek, COINS, ct, sent) != Error::NONE || Decaps(dk, ct, received) != Error::NONE) return {};
    std::vector<uint8_t> out(ek.begin(), ek.end());
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), received.Bytes().begin(), received.Bytes().end());
    return out;
}
// The assembly calls of each entry point, run alone on a new thread, whose
// copy of the override is unset until the entry point takes it.
static std::array<unsigned long, 4> EachOperationOnAFreshThread(const PublicKey& ek, const DecapsulationKey& dk, const Ciphertext& ct)
{
    const std::function<void()> operations[4]{
        [] { PublicKey e; DecapsulationKey d; (void)KeyGen(Seed(), e, d); },
        [&] { (void)CheckPublicKey(ek); },
        [&] { Ciphertext c; SharedSecret s; (void)Encaps(ek, COINS, c, s); },
        [&] { SharedSecret s; (void)Decaps(dk, ct, s); },
    };
    std::array<unsigned long, 4> calls{};
    for (size_t i = 0; i < calls.size(); ++i) {
        AsmCalls();
        std::thread{operations[i]}.join();
        calls[i] = AsmCalls();
    }
    return calls;
}
int main()
{
    const auto detected{RoundTrip()};
    const unsigned long detected_calls{AsmCalls()};
    const auto active{GetBackendNames().arith};
    PublicKey ek; DecapsulationKey dk; Ciphertext ct; SharedSecret ss;
    const bool inputs{KeyGen(Seed(), ek, dk) == Error::NONE && Encaps(ek, COINS, ct, ss) == Error::NONE};
    const auto fresh_detected{EachOperationOnAFreshThread(ek, dk, ct)};
    std::vector<uint8_t> portable;
    unsigned long portable_calls;
    std::array<unsigned long, 4> fresh_portable;
    {
        ForcePortableForTesting force;
        AsmCalls();
        portable = RoundTrip();
        portable_calls = AsmCalls();
        fresh_portable = EachOperationOnAFreshThread(ek, dk, ct);
    }
    std::printf("active=%.*s detected_calls=%lu portable_calls=%lu equal=%d ok=%d "
                "fresh_detected=%lu,%lu,%lu,%lu fresh_portable=%lu,%lu,%lu,%lu\n",
                int(active.size()), active.data(), detected_calls, portable_calls, int(detected == portable),
                int(!detected.empty() && inputs), fresh_detected[0], fresh_detected[1], fresh_detected[2], fresh_detected[3],
                fresh_portable[0], fresh_portable[1], fresh_portable[2], fresh_portable[3]);
}
"""

# The entry points EachOperationOnAFreshThread runs, in its order.
OPERATIONS = ("KeyGen", "CheckPublicKey", "Encaps", "Decaps")

# Test-only edits that let qbit's AArch64 glue build for AArch64 ELF, which
# release builds refuse (src/crypto/mlkem_config.h: no BTI landing pads), so
# that it can run under qemu-aarch64 on a Linux host. Each must match exactly once.
AARCH64_ELF_CONFIG_EDITS = (
    ("#if defined(MLK_SYS_AARCH64) && defined(__ELF__)\n"
     "#error \"mlkem-native AArch64 assembly has no BTI landing pads or GNU property note; AArch64 ELF builds are portable only.\"\n"
     "#endif\n", ""),
    ("(defined(MLK_SYS_AARCH64) && defined(MLK_SYS_AARCH64_NEON) && defined(MLK_SYS_APPLE))",
     "(defined(MLK_SYS_AARCH64) && defined(MLK_SYS_AARCH64_NEON))"),
)
# The negative control: upstream's single-lane Keccak glue, which runs its
# assembly without asking the capability hook, in place of qbit's mirror.
UPSTREAM_X1_EDIT = (
    re.compile(r"#define MLK_USE_NATIVE_FIPS202_X1\n.*?#endif // !__ASSEMBLER__\n", re.S),
    "#include <mlkem/src/fips202/native/aarch64/x1_scalar.h>\n",
)


def edited(source: Path, edits: tuple) -> str:
    text = source.read_text(encoding="utf8")
    for old, new in edits:
        count = len(old.findall(text)) if isinstance(old, re.Pattern) else text.count(old)
        if count != 1:
            raise AssertionError(
                f"FAIL: test edit matched {count} times in {source}\n"
                f"Cause: {source.name} changed, so the test can no longer derive its AArch64 ELF build\n"
                f"Fix: update the edits in {Path(__file__).name} to the new text: {old if isinstance(old, str) else old.pattern!r}")
        text = old.sub(new, text) if isinstance(old, re.Pattern) else text.replace(old, new)
    return text


class MlkemOverrideCoverageTest(unittest.TestCase):
    """The portable override reaches every assembly routine of each native backend.

    Every global symbol the assembly object defines is wrapped (ld --wrap) by a
    counter. A missed entry point would still give identical outputs, so only
    counting the calls can show it. Each wrapper entry point is also run alone
    on a fresh thread, which shows one that runs the library without taking
    the override first.

    x86_64 runs on x86_64 hosts. AArch64 is cross-built as a static Linux
    binary and run under qemu-aarch64; release builds enable it only on macOS,
    so the test builds a copy of src/crypto/mlkem_config.h without its AArch64
    ELF refusal. CI requires the AArch64 tools through
    MLKEM_POLICY_REQUIRED_COMPILERS (aarch64-linux-gnu-g++ and qemu-aarch64).
    """

    def build_harness(self, out: Path, *, cc: str, cxx: str, nm: str, args: int, overrides: dict[str, str],
                      link_flags: tuple[str, ...] = ()) -> Path:
        """Compile the library, qbit's glue and the counting harness; return the binary."""
        src = REPO_ROOT / "src"
        include = out / "include"
        for name, text in overrides.items():
            (include / "crypto").mkdir(parents=True, exist_ok=True)
            (include / "crypto" / name).write_text(text, encoding="utf8")
        # Overridden glue headers come first; qbit's own files fill in the rest.
        flags = ['-DMLK_CONFIG_FILE="crypto/mlkem_config.h"', "-DQBIT_MLKEM_NATIVE", f"-I{include}", f"-I{src}",
                 f"-I{src / 'mlkem-native'}", "-O1"]

        def compile_(compiler: str, source: Path, *extra: str) -> Path:
            obj = out / (source.name + ".o")
            result = run([compiler, *flags, *extra, "-c", str(source), "-o", str(obj)])
            self.assertEqual(result.returncode, 0, result.stderr)
            return obj

        objects = [
            compile_(cc, src / "mlkem-native" / "mlkem" / "mlkem_native.c"),
            compile_(cc, src / "mlkem-native" / "mlkem" / "mlkem_native_asm.S"),
            compile_(cc, src / "crypto" / "mlkem_backend.c"),
        ]
        asm_symbols = sorted(line.split()[2] for line in run([nm, "--defined-only", "-g", str(objects[1])]).stdout.splitlines()
                             if len(line.split()) == 3 and line.split()[1] == "T")
        self.assertGreater(len(asm_symbols), 0, "no assembly routines: is the native backend compiled?")
        # Every routine takes only integer or pointer arguments, at most as many
        # as the ABI passes in registers (args), so a generic forwarder keeps them.
        params = ", ".join("void*" for _ in range(args))
        named = ", ".join(f"void* a{i}" for i in range(args))
        forwarded = ", ".join(f"a{i}" for i in range(args))
        wrappers = ["#include <atomic>", "#include <cstdint>", "static std::atomic<unsigned long> g_calls{0};", 'extern "C" {']
        for symbol in asm_symbols:
            wrappers.append(f"uint64_t __real_{symbol}({params});")
            wrappers.append(f"uint64_t __wrap_{symbol}({named}) {{ ++g_calls; return __real_{symbol}({forwarded}); }}")
        wrappers += ["}", "unsigned long AsmCalls() { return g_calls.exchange(0); }"]
        (out / "wrap.cpp").write_text("\n".join(wrappers) + "\n", encoding="utf8")
        (out / "harness.cpp").write_text(COVERAGE_HARNESS, encoding="utf8")
        for source in (src / "crypto" / "mlkem.cpp", src / "compat" / "cpu_features.cpp", src / "support" / "cleanse.cpp",
                       out / "harness.cpp", out / "wrap.cpp"):
            objects.append(compile_(cxx, source, "-std=c++20", "-pthread"))
        binary = out / "harness"
        link = run([cxx, "-pthread", *link_flags, "-o", str(binary), *map(str, objects),
                    *(f"-Wl,--wrap={symbol}" for symbol in asm_symbols)])
        self.assertEqual(link.returncode, 0, link.stderr)
        return binary

    def run_harness(self, command: list[str]) -> dict[str, str]:
        result = run(command)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        values = dict(item.split("=", 1) for item in result.stdout.split())
        self.assertEqual(values["ok"], "1", result.stdout)
        self.assertEqual(values["equal"], "1", "the backends disagree")
        return values

    def check_coverage(self, values: dict[str, str], native: str, mirror_hint: str) -> None:
        self.assertEqual(values["active"], native, values)
        self.assertGreater(int(values["detected_calls"]), 0, values)
        self.assertEqual(values["portable_calls"], "0",
            f"FAIL: assembly ran {values['portable_calls']} times with portable C forced\n"
            "Cause: a native entry point does not ask mlk_sys_check_capability\n"
            f"Fix: mirror its dispatch glue with a capability check, {mirror_hint}")
        fresh_detected = [int(count) for count in values["fresh_detected"].split(",")]
        fresh_portable = [int(count) for count in values["fresh_portable"].split(",")]
        for operation, native_calls, portable_calls in zip(OPERATIONS, fresh_detected, fresh_portable):
            # Without native calls of its own, an operation's portable count proves nothing.
            self.assertGreater(native_calls, 0, f"{operation} runs no assembly natively: {values}")
            self.assertEqual(portable_calls, 0,
                f"FAIL: mlkem::{operation} ran assembly {portable_calls} times on a fresh thread with portable C forced\n"
                "Cause: it enters the library without BeginOperation(), so this thread's copy of the override is stale\n"
                "Fix: call BeginOperation() first in every entry point of src/crypto/mlkem.cpp")

    def test_x86_64_override_reaches_every_assembly_routine(self) -> None:
        if host_arch() != "x86_64":
            self.skipTest("the x86_64 backend runs only on x86_64 hosts")
        cc, cxx, nm = shutil.which("cc"), shutil.which("c++"), shutil.which("nm")
        if not (cc and cxx and nm):
            self.skipTest("cc, c++ and nm are required")
        assert cc is not None and cxx is not None and nm is not None
        with tempfile.TemporaryDirectory() as tmp:
            binary = self.build_harness(Path(tmp), cc=cc, cxx=cxx, nm=nm, args=6, overrides={})
            values = self.run_harness([str(binary)])
        if values["active"] != "x86_64-avx2":
            # A CPU without the extensions runs portable C only: nothing to count.
            self.assertEqual(values["detected_calls"], "0", values)
            self.assertEqual(values["portable_calls"], "0", values)
            self.skipTest("this CPU cannot run the x86_64 backend")
        self.check_coverage(values, "x86_64-avx2", "as for AArch64's x1 Keccak in src/crypto/mlkem_fips202_backend.h")

    def aarch64_tools(self) -> tuple[str, str, str, str]:
        tools = []
        for executable in ("aarch64-linux-gnu-gcc", "aarch64-linux-gnu-g++", "aarch64-linux-gnu-nm", "qemu-aarch64"):
            path = shutil.which(executable)
            if path is None:
                skip_missing_compiler(self, executable)
            assert path is not None
            tools.append(path)
        return tools[0], tools[1], tools[2], tools[3]

    def test_aarch64_override_reaches_every_assembly_routine(self) -> None:
        cc, cxx, nm, qemu = self.aarch64_tools()
        src = REPO_ROOT / "src"
        config = edited(src / "crypto" / "mlkem_config.h", AARCH64_ELF_CONFIG_EDITS)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "qbit"
            out.mkdir()
            binary = self.build_harness(out, cc=cc, cxx=cxx, nm=nm, args=8, overrides={"mlkem_config.h": config},
                                        link_flags=("-static",))
            values = self.run_harness([qemu, str(binary)])
            self.check_coverage(values, "aarch64-neon",
                                "as src/crypto/mlkem_fips202_backend.h does for upstream's x1_scalar.h")

            # Negative control: with upstream's x1 glue in place of qbit's
            # mirror, forced portable runs leak assembly calls, and the count sees them.
            upstream = Path(tmp) / "upstream-x1"
            upstream.mkdir()
            fips202 = edited(src / "crypto" / "mlkem_fips202_backend.h", (UPSTREAM_X1_EDIT,))
            binary = self.build_harness(upstream, cc=cc, cxx=cxx, nm=nm, args=8,
                                        overrides={"mlkem_config.h": config, "mlkem_fips202_backend.h": fips202},
                                        link_flags=("-static",))
            control = self.run_harness([qemu, str(binary)])
            self.assertGreater(int(control["portable_calls"]), 0,
                f"FAIL: upstream's x1 glue leaked no assembly calls with portable C forced: {control}\n"
                "Cause: the counter no longer sees the x1 Keccak routine, so this test cannot catch a missing capability check\n"
                "Fix: check that the --wrap list covers every global symbol of mlkem_native_asm.S")


if __name__ == "__main__":
    unittest.main()
