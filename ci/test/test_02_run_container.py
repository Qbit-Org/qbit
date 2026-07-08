# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

import importlib.util
import unittest
from pathlib import Path


def load_run_container():
    script_path = Path(__file__).with_name("02_run_container.py")
    spec = importlib.util.spec_from_file_location("run_container", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUN_CONTAINER = load_run_container()


class RunContainerTest(unittest.TestCase):
    def test_container_name_keeps_derived_network_name_within_docker_limit(self):
        name = RUN_CONTAINER.ci_container_name(
            base="ci_native_nowallet_libbitcoinkernel",
            run_id="28956539484",
            run_attempt="12",
            job="nightly-heavy-linux-aarch64-cross-build",
            runner_name=(
                "qbit-self-hosted-linux-runner-with-a-name-long-enough-to-"
                "exceed-docker-name-limits"
            ),
        )

        self.assertLessEqual(len(name), RUN_CONTAINER.MAX_CI_CONTAINER_NAME_LEN)
        self.assertLessEqual(
            len(RUN_CONTAINER.CI_NETWORK_PREFIX + name),
            RUN_CONTAINER.MAX_DOCKER_NAME_LEN,
        )

    def test_container_name_distinguishes_runner_instances(self):
        kwargs = {
            "base": "ci_arm_linux",
            "run_id": "28956539484",
            "run_attempt": "1",
            "job": "nightly-heavy",
        }

        name_a = RUN_CONTAINER.ci_container_name(
            runner_name="qbit-self-hosted-runner-a",
            **kwargs,
        )
        name_b = RUN_CONTAINER.ci_container_name(
            runner_name="qbit-self-hosted-runner-b",
            **kwargs,
        )

        self.assertNotEqual(name_a, name_b)


if __name__ == "__main__":
    unittest.main()
