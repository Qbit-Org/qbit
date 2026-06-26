#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Tests for the configure-docker BuildKit config helper."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github/actions/configure-docker/buildkit-config.sh"


class ConfigureDockerBuildKitConfigTest(unittest.TestCase):
    def run_script(self, extra_env: dict[str, str]) -> tuple[str, str]:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner_temp = Path(tmpdir) / "runner-temp"
            runner_temp.mkdir()
            github_env = Path(tmpdir) / "github-env"

            env = os.environ.copy()
            for name in (
                "BUILDKIT_DNS_NAMESERVERS",
                "BUILDKIT_DNS_SEARCH_DOMAINS",
                "CI_BUILDKIT_DNS_NAMESERVERS",
                "CI_BUILDKIT_DNS_SEARCH_DOMAINS",
                "CI_ENFORCE_INTERNAL_REGISTRY",
                "CI_IMAGE_REGISTRY_PREFIX",
            ):
                env.pop(name, None)
            env.update(extra_env)
            env["RUNNER_TEMP"] = str(runner_temp)
            env["GITHUB_ENV"] = str(github_env)

            subprocess.run(
                ["bash", str(SCRIPT)],
                check=True,
                env=env,
                text=True,
                capture_output=True,
            )

            return (
                (runner_temp / "buildkitd.toml").read_text(encoding="utf8"),
                github_env.read_text(encoding="utf8"),
            )

    def test_writes_internal_registry_and_dns_config(self) -> None:
        config, github_env = self.run_script(
            {
                "CI_ENFORCE_INTERNAL_REGISTRY": "1",
                "CI_IMAGE_REGISTRY_PREFIX": "qbit-ci-autoscaler:5000/qbit-cache",
                "CI_BUILDKIT_DNS_NAMESERVERS": "100.100.100.100,1.1.1.1,8.8.8.8",
                "CI_BUILDKIT_DNS_SEARCH_DOMAINS": "tailfa7aa.ts.net,localdomain",
            }
        )

        self.assertEqual(
            config,
            '\n'.join(
                [
                    "[registry]",
                    '  [registry."qbit-ci-autoscaler:5000"]',
                    "    http = true",
                    "    insecure = true",
                    "",
                    "[dns]",
                    '  nameservers = ["100.100.100.100", "1.1.1.1", "8.8.8.8"]',
                    '  searchDomains = ["tailfa7aa.ts.net", "localdomain"]',
                    "",
                ]
            ),
        )
        self.assertIn("BUILDKIT_CONFIG=", github_env)

    def test_preserves_registry_config_without_dns(self) -> None:
        config, _github_env = self.run_script(
            {
                "CI_ENFORCE_INTERNAL_REGISTRY": "1",
                "CI_IMAGE_REGISTRY_PREFIX": "qbit-ci-autoscaler:5000/qbit-cache",
            }
        )

        self.assertEqual(
            config,
            '\n'.join(
                [
                    "[registry]",
                    '  [registry."qbit-ci-autoscaler:5000"]',
                    "    http = true",
                    "    insecure = true",
                    "",
                ]
            ),
        )

    def test_action_input_dns_values_override_ci_env_values(self) -> None:
        config, _github_env = self.run_script(
            {
                "BUILDKIT_DNS_NAMESERVERS": "100.100.100.100",
                "BUILDKIT_DNS_SEARCH_DOMAINS": "tailfa7aa.ts.net, localdomain",
                "CI_BUILDKIT_DNS_NAMESERVERS": "192.0.2.1",
                "CI_BUILDKIT_DNS_SEARCH_DOMAINS": "example.invalid",
            }
        )

        self.assertEqual(
            config,
            '\n'.join(
                [
                    "[dns]",
                    '  nameservers = ["100.100.100.100"]',
                    '  searchDomains = ["tailfa7aa.ts.net", "localdomain"]',
                    "",
                ]
            ),
        )


if __name__ == "__main__":
    unittest.main()
