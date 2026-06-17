#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

import os
import re
import shlex
import subprocess
import sys


def run(cmd, **kwargs):
    print("+ " + shlex.join(cmd), flush=True)
    try:
        return subprocess.run(cmd, check=True, **kwargs)
    except Exception as e:
        sys.exit(e)


def main():
    print("Export only allowed settings:")
    settings = run(
        ["bash", "-c", "grep export ./ci/test/00_setup_env*.sh"],
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf8",
    ).stdout.splitlines()
    settings = set(l.split("=")[0].split("export ")[1] for l in settings)
    # Add "hidden" settings, which are never exported, manually. Otherwise,
    # they will not be passed on.
    settings.update([
        "BASE_BUILD_DIR",
        "CI_FAILFAST_TEST_LEAVE_DANGLING",
    ])

    # Make container/env-file names unique per workflow run to avoid collisions
    # between concurrent jobs sharing one Docker daemon.
    unique_id = "{run_id}-{attempt}-{job}".format(
        run_id=os.getenv("GITHUB_RUN_ID", "local"),
        attempt=os.getenv("GITHUB_RUN_ATTEMPT", "0"),
        job=os.getenv("GITHUB_JOB", "job"),
    )
    unique_id = re.sub(r"[^A-Za-z0-9_.-]", "-", unique_id)
    container_name = "{base}-{suffix}".format(
        base=os.getenv("CONTAINER_NAME", "ci"),
        suffix=unique_id,
    )
    env_file = "/tmp/env-{u}-{c}".format(
        u=os.getenv("USER", "ci"),
        c=container_name,
    )
    os.environ["CI_CONTAINER_NAME"] = container_name
    os.environ["CI_ENV_FILE"] = env_file
    with open(env_file, "w", encoding="utf8") as file:
        for k, v in os.environ.items():
            if k in settings:
                file.write(f"{k}={v}\n")
    run(["cat", env_file])

    run(["./ci/test/02_run_container.sh"])  # run the remainder


if __name__ == "__main__":
    main()
