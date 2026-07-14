#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Fail closed unless a signed-tag source is ready for mainnet publication."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATHS = (
    "CMakeLists.txt",
    "contrib/guix/libexec/build.sh",
    "contrib/guix/test_build_config.py",
    "contrib/seeds/nodes_main.txt",
    "src/chainparamsseeds.h",
    "src/kernel/chainparams.cpp",
    "src/test/argsman_chain_tests.cpp",
    "src/test/data/mainnet_launch_difficulty.json",
    "src/test/pow_tests.cpp",
)
DRAFT_MARKER_RE = re.compile(
    r"(?<![A-Za-z])(?:draft|placeholder|temporary)(?![A-Za-z])|"
    r"MAINNET LAUNCH BLOCKER|"
    r"\breplace\b.{0,120}\b(?:final|launch|mainnet)\b|"
    r"\bwill be (?:mined|finalized|replaced)\b",
    re.IGNORECASE | re.DOTALL,
)


class MainnetPostureError(RuntimeError):
    """Raised when mainnet source is not publication-ready."""


def git_stdout(source_root: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(source_root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise MainnetPostureError(detail)
    return result.stdout.strip()


def resolve_release_commit(source_root: Path, release_tag: str) -> str:
    if not re.fullmatch(r"v[A-Za-z0-9][A-Za-z0-9._-]*", release_tag):
        raise MainnetPostureError(f"Invalid release tag: {release_tag}")
    return git_stdout(
        source_root,
        ["rev-parse", "--verify", f"refs/tags/{release_tag}^{{commit}}"],
    )


def read_sources(
    source_root: Path, release_tag: str | None
) -> tuple[dict[str, str], str | None]:
    source_commit = (
        resolve_release_commit(source_root, release_tag) if release_tag else None
    )
    sources: dict[str, str] = {}
    for relative_path in SOURCE_PATHS:
        if source_commit:
            sources[relative_path] = git_stdout(
                source_root, ["show", f"{source_commit}:{relative_path}"]
            )
            continue
        path = source_root / relative_path
        try:
            sources[relative_path] = path.read_text(encoding="utf8")
        except FileNotFoundError as exc:
            raise MainnetPostureError(
                f"Missing source file for mainnet posture check: {relative_path}"
            ) from exc
    return sources, source_commit


def strip_cpp_comments(text: str) -> str:
    result: list[str] = []
    index = 0
    state = "code"
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                state = "block_comment"
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            result.append(char)
            index += 1
            continue
        if state == "line_comment":
            if char == "\n":
                result.append(char)
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if char == "\n":
                result.append(char)
            if char == "*" and next_char == "/":
                state = "code"
                index += 2
                continue
            index += 1
            continue
        result.append(char)
        if char == "\\" and next_char:
            result.append(next_char)
            index += 2
            continue
        if state == "string" and char == '"':
            state = "code"
        elif state == "char" and char == "'":
            state = "code"
        index += 1
    return "".join(result)


def extract_braced_region(text: str, marker: str, description: str) -> str:
    start = text.find(marker)
    if start == -1:
        raise MainnetPostureError(f"Missing {description}: {marker}")
    brace = text.find("{", start + len(marker))
    if brace == -1:
        raise MainnetPostureError(f"Missing body for {description}: {marker}")
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1 : index]
    raise MainnetPostureError(f"Unterminated body for {description}: {marker}")


def extract_class_body(text: str, class_name: str) -> str:
    return extract_braced_region(text, f"class {class_name}", f"{class_name} class")


def extract_test_body(text: str, test_name: str) -> str:
    return extract_braced_region(
        text,
        f"BOOST_AUTO_TEST_CASE({test_name})",
        f"{test_name} test",
    )


def parse_cpp_int_constants(text: str) -> dict[str, str]:
    return dict(
        re.findall(
            r"static\s+constexpr\s+int\s+([A-Za-z_][A-Za-z0-9_]*)\s*"
            r"\{\s*([A-Za-z_0-9xXa-fA-F'+-]+)\s*\}\s*;",
            strip_cpp_comments(text),
        )
    )


def resolve_cpp_int(
    token: str, constants: dict[str, str], stack: tuple[str, ...] = ()
) -> int:
    cleaned = token.replace("'", "")
    if re.fullmatch(r"[+-]?(?:0[xX][0-9A-Fa-f]+|[0-9]+)", cleaned):
        return int(cleaned, 0)
    if cleaned in stack:
        raise MainnetPostureError(
            f"Recursive integer constant: {' -> '.join((*stack, cleaned))}"
        )
    try:
        expression = constants[cleaned]
    except KeyError as exc:
        raise MainnetPostureError(f"Unresolved integer constant: {cleaned}") from exc
    return resolve_cpp_int(expression, constants, (*stack, cleaned))


def assigned_auxpow_chain_id(
    class_body: str, constants: dict[str, str]
) -> tuple[str, int]:
    match = re.search(
        r"consensus\.nAuxpowChainId\s*=\s*([A-Za-z_0-9xXa-fA-F']+)\s*;", class_body
    )
    if match is None:
        raise MainnetPostureError("Missing consensus.nAuxpowChainId assignment")
    token = match.group(1)
    return token, resolve_cpp_int(token, constants)


def validate_chain_id(sources: dict[str, str]) -> None:
    chainparams = sources["src/kernel/chainparams.cpp"]
    constants = parse_cpp_int_constants(chainparams)
    main_token, main_id = assigned_auxpow_chain_id(
        extract_class_body(strip_cpp_comments(chainparams), "CMainParams"), constants
    )
    _, testnet4_id = assigned_auxpow_chain_id(
        extract_class_body(strip_cpp_comments(chainparams), "CTestNet4Params"),
        constants,
    )
    failures: list[str] = []
    if "PLACEHOLDER" in main_token.upper():
        failures.append(f"still uses placeholder constant {main_token}")
    if not 1 <= main_id <= 0xFFFF:
        failures.append(f"value {main_id} is outside the 16-bit AuxPoW chain-ID range")
    if main_id == testnet4_id:
        failures.append(
            f"value {main_id} must differ from testnet4 chain ID {testnet4_id}"
        )

    try:
        test_body = extract_test_body(
            sources["src/test/pow_tests.cpp"],
            "ChainParams_MAIN_auxpow_chain_id_is_distinct",
        )
        required = (
            "BOOST_CHECK_NE",
            "main_consensus.nAuxpowChainId",
            "testnet4_consensus.nAuxpowChainId",
        )
        missing = [token for token in required if token not in test_body]
        if missing:
            failures.append(
                "distinctness test is missing assertion token(s): " + ", ".join(missing)
            )
    except MainnetPostureError as exc:
        failures.append(str(exc))
    if failures:
        raise MainnetPostureError("; ".join(failures))


def json_strings(value: Any, path: str = "$") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            found.append((child_path, str(key)))
            found.extend(json_strings(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(json_strings(child, f"{path}[{index}]"))
    elif isinstance(value, str):
        found.append((path, value))
    return found


def validate_launch_difficulty(sources: dict[str, str]) -> None:
    artifact_path = "src/test/data/mainnet_launch_difficulty.json"
    try:
        artifact = json.loads(sources[artifact_path])
    except json.JSONDecodeError as exc:
        raise MainnetPostureError(f"Invalid {artifact_path}: {exc}") from exc
    if not isinstance(artifact, dict) or artifact.get("network") != "main":
        raise MainnetPostureError(f"{artifact_path} must describe network 'main'")
    failures: list[str] = []
    for section in ("genesis", "permissionless", "auxpow"):
        value = artifact.get(section)
        if not isinstance(value, dict):
            failures.append(f"{artifact_path} is missing object {section!r}")
            continue
        source = value.get("source")
        if not isinstance(source, str) or not source.strip():
            failures.append(
                f"{artifact_path}.{section}.source must record final source provenance"
            )

    markers: list[str] = []
    for path, value in json_strings(artifact):
        match = DRAFT_MARKER_RE.search(value)
        if match:
            markers.append(f"{path}: {match.group(0)!r}")

    chainparams = sources["src/kernel/chainparams.cpp"]
    main_body = extract_class_body(chainparams, "CMainParams")
    for match in DRAFT_MARKER_RE.finditer(main_body):
        markers.append(f"src/kernel/chainparams.cpp: {match.group(0)!r}")

    pow_tests = sources["src/test/pow_tests.cpp"]
    for test_name in (
        "ChainParams_MAIN_auxpow_chain_id_is_placeholder",
        "ChainParams_MAIN_launch_difficulty_config",
    ):
        if f"BOOST_AUTO_TEST_CASE({test_name})" not in pow_tests:
            continue
        body = extract_test_body(pow_tests, test_name)
        for match in DRAFT_MARKER_RE.finditer(body):
            markers.append(f"src/test/pow_tests.cpp:{test_name}: {match.group(0)!r}")

    if markers:
        failures.append(
            "mainnet genesis/difficulty source still contains draft marker(s): "
            + "; ".join(markers)
        )

    main_code = strip_cpp_comments(main_body)
    required_main_assertions = (
        "genesis = CreateGenesisBlock(",
        "assert(consensus.hashGenesisBlock == uint256{",
        "assert(genesis.hashMerkleRoot == uint256{",
        "consensus.asertAnchorParams = Consensus::ASERTAnchor{",
    )
    missing_main = [
        token for token in required_main_assertions if token not in main_code
    ]
    if missing_main:
        failures.append(
            "CMainParams is missing final genesis/ASERT assertion(s): "
            + ", ".join(missing_main)
        )

    difficulty_test = extract_test_body(
        pow_tests, "ChainParams_MAIN_launch_difficulty_config"
    )
    required_test_assertions = (
        "chain_params->GenesisBlock().nBits",
        "consensus.asertAnchorParams.nBits",
        "consensus.asertAnchorParams.nBitsLegacy",
        "consensus.asertAnchorParams.nBitsAuxPow",
    )
    missing_test = [
        token for token in required_test_assertions if token not in difficulty_test
    ]
    if missing_test:
        failures.append(
            "mainnet launch-difficulty test is missing assertion(s): "
            + ", ".join(missing_test)
        )
    if failures:
        raise MainnetPostureError("; ".join(failures))


def parse_mainnet_nodes(
    text: str,
) -> list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]:
    nodes: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            closing = line.find("]")
            if closing == -1 or closing + 1 >= len(line) or line[closing + 1] != ":":
                raise MainnetPostureError(
                    f"Invalid fixed seed at nodes_main.txt:{line_number}"
                )
            host, port_text = line[1:closing], line[closing + 2 :]
        else:
            try:
                host, port_text = line.rsplit(":", 1)
            except ValueError as exc:
                raise MainnetPostureError(
                    f"Invalid fixed seed at nodes_main.txt:{line_number}"
                ) from exc
        try:
            address = ipaddress.ip_address(host)
            port = int(port_text)
        except ValueError as exc:
            raise MainnetPostureError(
                f"Invalid fixed seed at nodes_main.txt:{line_number}: {line}"
            ) from exc
        if not 1 <= port <= 65535:
            raise MainnetPostureError(
                f"Invalid fixed-seed port at nodes_main.txt:{line_number}"
            )
        nodes.append((address, port))
    if len(nodes) < 2 or len(set(nodes)) != len(nodes):
        raise MainnetPostureError(
            "Mainnet requires at least two unique numeric fixed seeds"
        )
    return nodes


def bip155_fixed_seed_bytes(
    nodes: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]],
) -> bytes:
    encoded = bytearray()
    for address, port in nodes:
        network_id = 1 if address.version == 4 else 2
        encoded.extend((network_id, len(address.packed)))
        encoded.extend(address.packed)
        encoded.extend(port.to_bytes(2, "big"))
    return bytes(encoded)


def parse_seed_array(text: str) -> tuple[int, bytes]:
    match = re.search(
        r"std::array\s*<\s*uint8_t\s*,\s*(\d+)\s*>\s+chainparams_seed_main\s*"
        r"\{\{(.*?)\}\};",
        strip_cpp_comments(text),
        re.DOTALL,
    )
    if match is None:
        raise MainnetPostureError("Missing chainparams_seed_main byte array")
    declared_size = int(match.group(1))
    values = [
        int(token, 0) for token in re.findall(r"0[xX][0-9A-Fa-f]+|\d+", match.group(2))
    ]
    if any(value > 255 for value in values) or len(values) != declared_size:
        raise MainnetPostureError(
            "chainparams_seed_main has an invalid declared size or byte"
        )
    return declared_size, bytes(values)


def validate_bootstrap(sources: dict[str, str]) -> None:
    chainparams = sources["src/kernel/chainparams.cpp"]
    main_code = strip_cpp_comments(extract_class_body(chainparams, "CMainParams"))
    dns_seeds = re.findall(
        r'vSeeds\.emplace_back\(\s*"([A-Za-z0-9.-]+)"\s*\)', main_code
    )
    if len(dns_seeds) < 2 or len(set(dns_seeds)) != len(dns_seeds):
        raise MainnetPostureError("CMainParams requires at least two unique DNS seeds")
    invalid_dns = [seed for seed in dns_seeds if not seed.endswith(".qbit.org")]
    if invalid_dns:
        raise MainnetPostureError(
            "Mainnet DNS seeds must use qbit.org names: " + ", ".join(invalid_dns)
        )
    if not re.search(
        r"vFixedSeeds\s*=\s*std::vector<uint8_t>\s*\(\s*"
        r"chainparams_seed_main\.begin\(\)\s*,\s*chainparams_seed_main\.end\(\)\s*\)",
        main_code,
    ):
        raise MainnetPostureError("CMainParams does not load chainparams_seed_main")
    port_match = re.search(r"nDefaultPort\s*=\s*(\d+)\s*;", main_code)
    if port_match is None:
        raise MainnetPostureError("CMainParams is missing nDefaultPort")
    default_port = int(port_match.group(1))
    required_zero_size_hints = (
        "m_assumed_blockchain_size = 0;",
        "m_assumed_chain_state_size = 0;",
    )
    missing_size_hints = [
        token for token in required_zero_size_hints if token not in main_code
    ]
    if missing_size_hints:
        raise MainnetPostureError(
            "CMainParams launch-size hints must be zero: "
            + ", ".join(missing_size_hints)
        )

    nodes = parse_mainnet_nodes(sources["contrib/seeds/nodes_main.txt"])
    wrong_ports = [str(port) for _, port in nodes if port != default_port]
    if wrong_ports:
        raise MainnetPostureError(
            f"Mainnet fixed seeds must use default P2P port {default_port}"
        )
    expected_bytes = bip155_fixed_seed_bytes(nodes)
    declared_size, actual_bytes = parse_seed_array(sources["src/chainparamsseeds.h"])
    if actual_bytes != expected_bytes:
        raise MainnetPostureError(
            "chainparams_seed_main does not exactly match contrib/seeds/nodes_main.txt"
        )

    test_body = extract_test_body(
        sources["src/test/pow_tests.cpp"], "ChainParams_MAIN_launch_bootstrap"
    )
    required = ["DNSSeeds()", "FixedSeeds()"]
    required.extend(f'"{seed}"' for seed in dns_seeds)
    required.extend(
        (
            f"dns_seeds.size(), {len(dns_seeds)}U",
            f"FixedSeeds().size(), {declared_size}U",
            "AssumedBlockchainSize(), 0U",
            "AssumedChainStateSize(), 0U",
        )
    )
    missing = [token for token in required if token not in test_body]
    if missing:
        raise MainnetPostureError(
            "Mainnet bootstrap test is missing assertion token(s): "
            + ", ".join(missing)
        )


def validate_default_chain(sources: dict[str, str]) -> None:
    cmake = sources["CMakeLists.txt"]
    if not re.search(
        r"option\(QBIT_TESTNET_ONLY_RELEASE\s+\"[^\"]*\"\s+OFF\s*\)", cmake
    ):
        raise MainnetPostureError(
            "QBIT_TESTNET_ONLY_RELEASE must default to OFF in CMake"
        )

    guix = sources["contrib/guix/libexec/build.sh"]
    if 'QBIT_TESTNET_ONLY_RELEASE="${QBIT_TESTNET_ONLY_RELEASE:-OFF}"' not in guix:
        raise MainnetPostureError("Guix QBIT_TESTNET_ONLY_RELEASE must default to OFF")
    if "qbit-*-testnet" in guix:
        raise MainnetPostureError(
            "Guix must not infer testnet-only posture from DISTNAME"
        )

    guix_test = sources["contrib/guix/test_build_config.py"]
    required_guix_test = (
        "test_release_builds_default_mainnet_guard_off",
        'QBIT_TESTNET_ONLY_RELEASE="${QBIT_TESTNET_ONLY_RELEASE:-OFF}"',
        "assertNotRegex",
    )
    missing_guix = [token for token in required_guix_test if token not in guix_test]
    if missing_guix:
        raise MainnetPostureError(
            "Guix default-mainnet test is missing assertion token(s): "
            + ", ".join(missing_guix)
        )

    args_test = extract_test_body(
        sources["src/test/argsman_chain_tests.cpp"],
        "testnet_only_release_mainnet_guard",
    )
    required_args = (
        "argv_default",
        "ParseParameters(1, argv_default",
        "argv_main",
        "ParseParameters(2, argv_main",
        "GetChainType() == ChainType::MAIN",
    )
    missing_args = [token for token in required_args if token not in args_test]
    if (
        missing_args
        or args_test.count("BOOST_CHECK_NO_THROW(CheckTestnetOnlyReleaseChain") < 2
    ):
        details = missing_args or [
            "two mainnet CheckTestnetOnlyReleaseChain no-throw assertions"
        ]
        raise MainnetPostureError(
            "Default-mainnet chain-selection test is missing assertion(s): "
            + ", ".join(details)
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", default=REPO_ROOT, type=Path)
    parser.add_argument(
        "--release-tag",
        help="release tag whose peeled commit supplies every checked source file",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        sources, source_commit = read_sources(
            args.source_root.resolve(), args.release_tag
        )
    except MainnetPostureError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 1

    failures: list[str] = []
    for name, check in (
        ("AuxPoW chain ID", validate_chain_id),
        ("genesis and ASERT launch data", validate_launch_difficulty),
        ("mainnet bootstrap", validate_bootstrap),
        ("default-mainnet build posture", validate_default_chain),
    ):
        try:
            check(sources)
        except MainnetPostureError as exc:
            failures.append(f"{name}: {exc}")
    if failures:
        print("ERR: Mainnet release posture is not publication-ready:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    source_description = source_commit or "working tree"
    print(f"Validated fail-closed mainnet release posture for {source_description}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
