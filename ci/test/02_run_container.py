#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

import hashlib
import os
import re
import shlex
import subprocess
import sys

MAX_DOCKER_NAME_LEN = 63
CI_NETWORK_PREFIX = "ci-ip6net-"
MAX_CI_CONTAINER_NAME_LEN = MAX_DOCKER_NAME_LEN - len(CI_NETWORK_PREFIX)


def sanitize_name_part(value):
    return re.sub(r"[^A-Za-z0-9_.-]", "-", value)


def short_hash(value, length=10):
    return hashlib.sha256(value.encode("utf8")).hexdigest()[:length]


def ci_container_name(base, run_id, run_attempt, job, runner_name):
    base = sanitize_name_part(base or "ci")
    unique_id = "-".join(
        sanitize_name_part(part)
        for part in (
            run_id or "local",
            run_attempt or "0",
            job or "job",
            f"r{short_hash(runner_name or 'runner')}",
        )
        if part
    )
    candidate = f"{base}-{unique_id}"
    if len(candidate) <= MAX_CI_CONTAINER_NAME_LEN:
        return candidate

    digest = short_hash(candidate)
    prefix_len = MAX_CI_CONTAINER_NAME_LEN - len(digest) - 1
    return f"{candidate[:prefix_len].rstrip('-')}-{digest}"


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

    # Make container/env-file names unique per runner instance. GitHub sets the
    # same GITHUB_JOB for every matrix entry, while qbit self-hosted runner
    # instances can share one Docker daemon.
    container_name = ci_container_name(
        base=os.getenv("CONTAINER_NAME", "ci"),
        run_id=os.getenv("GITHUB_RUN_ID", "local"),
        run_attempt=os.getenv("GITHUB_RUN_ATTEMPT", "0"),
        job=os.getenv("GITHUB_JOB", "job"),
        runner_name=os.getenv("RUNNER_NAME", "runner"),
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
