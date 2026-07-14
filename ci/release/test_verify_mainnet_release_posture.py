#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for verify_mainnet_release_posture.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).with_name("verify_mainnet_release_posture.py")
CORE_CHECKS = REPO_ROOT / ".github" / "workflows" / "core-checks.yml"

VALID_CHAINPARAMS = """\
static constexpr int QBIT_PUBLIC_TESTNET_AUXPOW_CHAIN_ID{31430};
static constexpr int QBIT_MAINNET_AUXPOW_CHAIN_ID{4919};

class CMainParams : public CChainParams {
public:
    CMainParams() {
        consensus.nAuxpowChainId = QBIT_MAINNET_AUXPOW_CHAIN_ID;
        consensus.asertAnchorParams = Consensus::ASERTAnchor{0, 0x18109c29, 0x18109c29, 0x1801ca70, 0, 1};
        nDefaultPort = 8355;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;
        genesis = CreateGenesisBlock(1, 2, 0x1a7f1ab5, 4, 5);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"0000000000000000000000000000000000000000000000000000000000000001"});
        assert(genesis.hashMerkleRoot == uint256{"0000000000000000000000000000000000000000000000000000000000000002"});
        vSeeds.emplace_back("flux-mainnet.qbit.org");
        vSeeds.emplace_back("phase-mainnet.qbit.org");
        vFixedSeeds = std::vector<uint8_t>(chainparams_seed_main.begin(), chainparams_seed_main.end());
    }
};

class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        genesis = CreateGenesisBlock(1, 2, 0x1f00ffff, 4, 5);
    }
};

class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        consensus.nAuxpowChainId = QBIT_PUBLIC_TESTNET_AUXPOW_CHAIN_ID;
        genesis = CreateTestNet4GenesisBlock(1, 2, 0x1a7f1ab5, 4, 5);
    }
};
"""

VALID_POW_TESTS = """\
BOOST_AUTO_TEST_CASE(ChainParams_MAIN_launch_bootstrap)
{
    const auto chain_params = CreateChainParams(args, ChainType::MAIN);
    const auto& dns_seeds = chain_params->DNSSeeds();
    BOOST_REQUIRE_EQUAL(dns_seeds.size(), 2U);
    BOOST_CHECK_EQUAL(dns_seeds[0], "flux-mainnet.qbit.org");
    BOOST_CHECK_EQUAL(dns_seeds[1], "phase-mainnet.qbit.org");
    BOOST_CHECK_EQUAL(chain_params->FixedSeeds().size(), 16U);
    BOOST_CHECK_EQUAL(chain_params->AssumedBlockchainSize(), 0U);
    BOOST_CHECK_EQUAL(chain_params->AssumedChainStateSize(), 0U);
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_auxpow_chain_id_is_distinct)
{
    const auto main_consensus = CreateChainParams(args, ChainType::MAIN)->GetConsensus();
    const auto testnet4_consensus = CreateChainParams(args, ChainType::TESTNET4)->GetConsensus();
    BOOST_CHECK_NE(main_consensus.nAuxpowChainId, testnet4_consensus.nAuxpowChainId);
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_launch_difficulty_config)
{
    BOOST_CHECK_EQUAL(chain_params->GenesisBlock().nBits, genesis_bits);
    BOOST_CHECK(CheckProofOfWork(chain_params->GenesisBlock().GetHash(), genesis_bits, consensus));
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBits, permissionless_bits);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBitsLegacy, permissionless_bits);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBitsAuxPow, auxpow_bits);
}
"""

VALID_ARGS_TESTS = """\
BOOST_AUTO_TEST_CASE(testnet_only_release_mainnet_guard)
{
    const char* argv_default[] = {"cmd"};
    const char* argv_main[] = {"cmd", "-chain=main"};
    BOOST_CHECK(args.ParseParameters(1, argv_default, error));
    BOOST_CHECK(args.GetChainType() == ChainType::MAIN);
    BOOST_CHECK_NO_THROW(CheckTestnetOnlyReleaseChain(args.GetChainType()));
    BOOST_CHECK(args.ParseParameters(2, argv_main, error));
    BOOST_CHECK(args.GetChainType() == ChainType::MAIN);
    BOOST_CHECK_NO_THROW(CheckTestnetOnlyReleaseChain(args.GetChainType()));
}
"""

VALID_SEED_HEADER = """\
#include <array>
#include <cstdint>
static constexpr std::array<uint8_t, 16> chainparams_seed_main{{
    0x01,0x04,0x39,0x81,0x69,0x5a,0x20,0xa3,
    0x01,0x04,0x28,0xa0,0x48,0x7b,0x20,0xa3,
}};
"""

VALID_DIFFICULTY: dict[str, Any] = {
    "schema": 1,
    "network": "main",
    "pow_limit_bits": "0x1f00ffff",
    "genesis": {
        "model": "fixed_bits",
        "bits": "0x1a7f1ab5",
        "expected_bits": "0x1a7f1ab5",
        "reference_network": "testnet4",
        "source": "Approved genesis mining record and launch signoff",
    },
    "permissionless": {
        "model": "fdv_hashprice",
        "fdv_usd": "100000000",
        "total_supply_qbt": "210000000",
        "subsidy_qbt": "210",
        "expected_fees_qbt": "0",
        "hashprice_usd_per_ph_day": "30.39",
        "expected_bits": "0x18109c29",
        "source": "Dated hashprice observation with archived evidence",
    },
    "auxpow": {
        "model": "bitcoin_hashrate_share",
        "bitcoin_global_hashrate_eh_s": "879",
        "hashrate_share": "0.01",
        "target_spacing_sec": "300",
        "expected_bits": "0x1801ca70",
        "source": "Dated Bitcoin hashrate observation with archived evidence",
    },
}


class VerifyMainnetReleasePostureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.write("CMakeLists.txt", 'option(QBIT_TESTNET_ONLY_RELEASE "guard" OFF)\n')
        self.write(
            "contrib/guix/libexec/build.sh",
            'QBIT_TESTNET_ONLY_RELEASE="${QBIT_TESTNET_ONLY_RELEASE:-OFF}"\n',
        )
        self.write(
            "contrib/guix/test_build_config.py",
            """\
def test_release_builds_default_mainnet_guard_off():
    assertNotRegex(script, r'qbit-\\*-testnet')
    assert 'QBIT_TESTNET_ONLY_RELEASE="${QBIT_TESTNET_ONLY_RELEASE:-OFF}"' in script
""",
        )
        self.write(
            "contrib/seeds/nodes_main.txt",
            "57.129.105.90:8355\n40.160.72.123:8355\n",
        )
        self.write("src/chainparamsseeds.h", VALID_SEED_HEADER)
        self.write("src/kernel/chainparams.cpp", VALID_CHAINPARAMS)
        self.write("src/test/argsman_chain_tests.cpp", VALID_ARGS_TESTS)
        self.write(
            "src/test/data/mainnet_launch_difficulty.json",
            json.dumps(VALID_DIFFICULTY, indent=2) + "\n",
        )
        self.write("src/test/pow_tests.cpp", VALID_POW_TESTS)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, relative_path: str, text: str) -> None:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf8")

    def run_validator(
        self,
        *,
        source_root: Path | None = None,
        release_tag: str | None = None,
        result_json: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = [
            sys.executable,
            str(SCRIPT),
            "--source-root",
            str(source_root or self.root),
        ]
        if release_tag:
            args.extend(("--release-tag", release_tag))
        if result_json:
            args.extend(("--result-json", str(result_json)))
        return subprocess.run(args, check=False, capture_output=True, text=True)

    def git(self, *args: str) -> str:
        result = subprocess.run(
            [
                "git",
                "-c",
                "user.name=qbit mainnet posture test",
                "-c",
                "user.email=mainnet-posture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
                "-C",
                str(self.root),
                *args,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def test_valid_final_posture_succeeds(self) -> None:
        result_path = self.root / "result.json"
        result = self.run_validator(result_json=result_path)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Validated fail-closed mainnet release posture", result.stdout)
        self.assertEqual(
            json.loads(result_path.read_text(encoding="utf8")),
            {
                "schema": 1,
                "ready": True,
                "source": "working tree",
                "failures": [],
            },
        )

    def test_matching_auxpow_chain_id_fails(self) -> None:
        path = self.root / "src/kernel/chainparams.cpp"
        path.write_text(
            path.read_text(encoding="utf8").replace(
                "QBIT_MAINNET_AUXPOW_CHAIN_ID{4919}",
                "QBIT_MAINNET_AUXPOW_CHAIN_ID{31430}",
            ),
            encoding="utf8",
        )

        result_path = self.root / "result.json"
        result = self.run_validator(result_json=result_path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("must differ from testnet4", result.stderr)
        failures = json.loads(result_path.read_text(encoding="utf8"))["failures"]
        self.assertEqual([failure["id"] for failure in failures], ["auxpow_chain_id"])

    def test_final_chain_id_without_distinctness_regression_stays_blocked(self) -> None:
        path = self.root / "src/test/pow_tests.cpp"
        path.write_text(
            path.read_text(encoding="utf8")
            .replace(
                "ChainParams_MAIN_auxpow_chain_id_is_distinct",
                "ChainParams_MAIN_auxpow_chain_id_is_placeholder",
            )
            .replace("BOOST_CHECK_NE", "BOOST_CHECK_EQUAL"),
            encoding="utf8",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Missing ChainParams_MAIN_auxpow_chain_id_is_distinct test",
            result.stderr,
        )

    def test_auxpow_chain_id_must_fit_its_consensus_field(self) -> None:
        path = self.root / "src/kernel/chainparams.cpp"
        path.write_text(
            path.read_text(encoding="utf8").replace(
                "QBIT_MAINNET_AUXPOW_CHAIN_ID{4919}",
                "QBIT_MAINNET_AUXPOW_CHAIN_ID{65536}",
            ),
            encoding="utf8",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("outside the 16-bit", result.stderr)

    def test_draft_difficulty_marker_fails(self) -> None:
        artifact = dict(VALID_DIFFICULTY)
        artifact["auxpow"] = dict(artifact["auxpow"], source="Draft value to replace")
        self.write(
            "src/test/data/mainnet_launch_difficulty.json",
            json.dumps(artifact) + "\n",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("draft marker", result.stderr)

    def test_temporary_difficulty_key_fails(self) -> None:
        artifact = dict(VALID_DIFFICULTY)
        artifact["genesis"] = dict(artifact["genesis"])
        artifact["genesis"]["temporary_bits"] = artifact["genesis"].pop("bits")
        self.write(
            "src/test/data/mainnet_launch_difficulty.json",
            json.dumps(artifact) + "\n",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("temporary", result.stderr)

    def test_declared_temporary_runtime_bits_are_coherent_but_not_publishable(self) -> None:
        artifact = json.loads(json.dumps(VALID_DIFFICULTY))
        artifact["genesis"]["temporary_runtime_bits"] = "0x1f00ffff"
        self.write(
            "src/test/data/mainnet_launch_difficulty.json",
            json.dumps(artifact) + "\n",
        )
        path = self.root / "src/kernel/chainparams.cpp"
        path.write_text(
            path.read_text(encoding="utf8").replace(
                "genesis = CreateGenesisBlock(1, 2, 0x1a7f1ab5, 4, 5);",
                "genesis = CreateGenesisBlock(1, 2, 0x1f00ffff, 4, 5);",
            ),
            encoding="utf8",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("temporary", result.stderr)
        self.assertNotIn("launch code target mismatch", result.stderr)

    def test_asserted_genesis_hash_must_satisfy_runtime_target(self) -> None:
        path = self.root / "src/kernel/chainparams.cpp"
        path.write_text(
            path.read_text(encoding="utf8").replace(
                "0" * 63 + "1",
                "f" * 64,
            ),
            encoding="utf8",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "asserted genesis hash does not satisfy its runtime target",
            result.stderr,
        )

    def test_calculated_lane_bits_must_match_fixture_expectation(self) -> None:
        artifact = json.loads(json.dumps(VALID_DIFFICULTY))
        artifact["permissionless"]["expected_bits"] = "0x18109c28"
        self.write(
            "src/test/data/mainnet_launch_difficulty.json",
            json.dumps(artifact) + "\n",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("launch fixture target mismatch", result.stderr)
        self.assertIn("permissionless calculated 0x18109c29", result.stderr)

    def test_chainparams_lane_bits_must_match_fixture(self) -> None:
        path = self.root / "src/kernel/chainparams.cpp"
        path.write_text(
            path.read_text(encoding="utf8").replace("0x1801ca70", "0x1801ca71"),
            encoding="utf8",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("launch code target mismatch", result.stderr)
        self.assertIn("ASERT AuxPoW is 0x1801ca71", result.stderr)

    def test_fixed_seed_bytes_must_match_approved_input(self) -> None:
        path = self.root / "src/chainparamsseeds.h"
        path.write_text(
            path.read_text(encoding="utf8").replace("0x39,0x81", "0x39,0x82"),
            encoding="utf8",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("does not exactly match", result.stderr)

    def test_bootstrap_assertions_are_required(self) -> None:
        path = self.root / "src/test/pow_tests.cpp"
        path.write_text(
            path.read_text(encoding="utf8").replace(
                '    BOOST_CHECK_EQUAL(dns_seeds[1], "phase-mainnet.qbit.org");\n',
                "",
            ),
            encoding="utf8",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("bootstrap test is missing", result.stderr)

    def test_testnet_only_build_default_must_be_off(self) -> None:
        path = self.root / "CMakeLists.txt"
        path.write_text(
            path.read_text(encoding="utf8").replace('guard" OFF', 'guard" ON'),
            encoding="utf8",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("must default to OFF in CMake", result.stderr)

    def test_default_chain_runtime_assertions_are_required(self) -> None:
        path = self.root / "src/test/argsman_chain_tests.cpp"
        path.write_text(
            path.read_text(encoding="utf8").replace(
                "BOOST_CHECK_NO_THROW(CheckTestnetOnlyReleaseChain", "CHECK_REMOVED("
            ),
            encoding="utf8",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("chain-selection test is missing", result.stderr)

    def test_release_tag_reads_peeled_target_not_worktree(self) -> None:
        self.git("init", "-q")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "final mainnet source")
        self.git("tag", "-a", "v1.0.0", "-m", "v1.0.0")
        self.write("CMakeLists.txt", 'option(QBIT_TESTNET_ONLY_RELEASE "guard" ON)\n')

        result = self.run_validator(release_tag="v1.0.0")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_checked_in_draft_is_blocked_until_final_values_land(self) -> None:
        result_path = self.root / "result.json"
        result = self.run_validator(source_root=REPO_ROOT, result_json=result_path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("must differ from testnet4", result.stderr)
        self.assertIn("draft marker", result.stderr)
        failures = json.loads(result_path.read_text(encoding="utf8"))["failures"]
        self.assertEqual(
            {failure["id"] for failure in failures},
            {"auxpow_chain_id", "genesis_asert"},
        )

    def test_core_checks_runs_real_gate_on_release_candidate_tag(self) -> None:
        workflow = CORE_CHECKS.read_text(encoding="utf8")

        self.assertIn("mainnet-publish-gate:", workflow)
        self.assertIn("mainnet_publish_gate_required", workflow)
        self.assertIn("ci/release/verify_mainnet_release_posture.py", workflow)
        self.assertIn('--release-tag "${RELEASE_CANDIDATE_TAG}"', workflow)
        self.assertIn("- mainnet-publish-gate", workflow)


if __name__ == "__main__":
    unittest.main()
