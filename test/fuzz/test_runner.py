#!/usr/bin/env python3
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run fuzz test targets.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import argparse
import configparser
import logging
import os
import random
import re
import subprocess
import sys
import tempfile

# Targets whose corpora must be replayed when --require_qbit_corpus is passed.
# The seeds for them live in test/fuzz/qbit_corpora.
QBIT_REQUIRED_CORPUS_TARGETS = (
    "asert_chain_transition",
    "asert_edge_cases",
    "asert_math",
    "auxpow",
    "p2mr_script",
    "pqc",
)
MUTATE_MIN_TIME_MAX_SECONDS = 3600
# How long a mutation job may run past its budget (process start-up, a slow
# final input) before it is stopped and reported as failed.
MUTATION_TIMEOUT_GRACE_SECONDS = 600


def get_fuzz_env(*, target, source_dir):
    symbolizer = os.environ.get('LLVM_SYMBOLIZER_PATH', "/usr/bin/llvm-symbolizer")
    fuzz_env = os.environ | {
        'FUZZ': target,
        'UBSAN_OPTIONS':
        f'suppressions={source_dir}/test/sanitizer_suppressions/ubsan:print_stacktrace=1:halt_on_error=1:report_error_type=1',
        'UBSAN_SYMBOLIZER_PATH': symbolizer,
        "ASAN_OPTIONS": "detect_leaks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1",
        'ASAN_SYMBOLIZER_PATH': symbolizer,
        'MSAN_SYMBOLIZER_PATH': symbolizer,
    }
    return fuzz_env


def mutate_min_time(value):
    """Parse a whole number of seconds, as accepted by libFuzzer's -max_total_time."""
    if not re.fullmatch(r"[1-9][0-9]*", value) or int(value) > MUTATE_MIN_TIME_MAX_SECONDS:
        raise argparse.ArgumentTypeError(
            f"expected a whole number of seconds from 1 to {MUTATE_MIN_TIME_MAX_SECONDS}, got {value!r}"
        )
    return int(value)


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='''Run the fuzz targets with all inputs from the corpus_dir once.''',
    )
    parser.add_argument(
        "-l",
        "--loglevel",
        dest="loglevel",
        default="INFO",
        help="log events at this level and higher to the console. Can be set to DEBUG, INFO, WARNING, ERROR or CRITICAL. Passing --loglevel DEBUG will output all logs to console.",
    )
    parser.add_argument(
        '--valgrind',
        action='store_true',
        help='If true, run fuzzing binaries under the valgrind memory error detector',
    )
    parser.add_argument(
        "--empty_min_time",
        type=int,
        help="If set, run at least this long, if the existing fuzz inputs directory is empty.",
    )
    parser.add_argument(
        '-x',
        '--exclude',
        help="A comma-separated list of targets to exclude",
    )
    parser.add_argument(
        '--par',
        '-j',
        type=int,
        default=4,
        help='How many targets to merge or execute in parallel.',
    )
    parser.add_argument(
        'corpus_dir',
        help='The corpus to run on (must contain subfolders for each fuzz target).',
    )
    parser.add_argument(
        'target',
        nargs='*',
        help='The target(s) to run. Default is to run all targets.',
    )
    parser.add_argument(
        '--m_dir',
        action="append",
        help="Merge inputs from these directories into the corpus_dir.",
    )
    parser.add_argument(
        '-g',
        '--generate',
        action='store_true',
        help='Create new corpus (or extend the existing ones) by running'
             ' the given targets for a finite number of times. Outputs them to'
             ' the passed corpus_dir.'
    )
    parser.add_argument(
        '--require_qbit_corpus',
        action='store_true',
        help="Fail unless all of {} are compiled and selected, each has at least one regular"
             " input file in corpus_dir, and the fuzz binary reports replaying them.".format(
                 ", ".join(QBIT_REQUIRED_CORPUS_TARGETS)),
    )
    parser.add_argument(
        '--mutate_min_time',
        type=mutate_min_time,
        help="Instead of replaying once, run a libFuzzer mutation phase of this many seconds per"
             " target, seeded from corpus_dir. New inputs go to a temporary directory; corpus_dir"
             " is not modified.",
    )

    args = parser.parse_args()
    args.corpus_dir = Path(args.corpus_dir)
    if args.mutate_min_time is not None:
        conflicting = [
            name for name, used in (
                ("--generate", args.generate),
                ("--m_dir", args.m_dir),
                ("--empty_min_time", args.empty_min_time is not None),
                ("--valgrind", args.valgrind),
            ) if used
        ]
        if conflicting:
            parser.error("--mutate_min_time cannot be combined with {}".format(", ".join(conflicting)))
    if args.require_qbit_corpus and (args.generate or args.m_dir):
        parser.error("--require_qbit_corpus cannot be combined with --generate or --m_dir")

    # Set up logging
    logging.basicConfig(
        format='%(message)s',
        level=int(args.loglevel) if args.loglevel.isdigit() else args.loglevel.upper(),
    )

    # Read config generated by configure.
    config = configparser.ConfigParser()
    configfile = os.path.abspath(os.path.dirname(__file__)) + "/../config.ini"
    config.read_file(open(configfile, encoding="utf8"))

    if not config["components"].getboolean("ENABLE_FUZZ_BINARY"):
        logging.error("Must have fuzz executable built")
        sys.exit(1)

    fuzz_bin=os.getenv("BITCOINFUZZ", default=os.path.join(config["environment"]["BUILDDIR"], 'bin', 'fuzz'))

    # Build list of tests
    test_list_all = parse_test_list(
        fuzz_bin=fuzz_bin,
        source_dir=config['environment']['SRCDIR'],
    )

    if not test_list_all:
        logging.error("No fuzz targets found")
        sys.exit(1)

    logging.debug("{} fuzz target(s) found: {}".format(len(test_list_all), " ".join(sorted(test_list_all))))

    args.target = args.target or test_list_all  # By default run all
    test_list_error = list(set(args.target).difference(set(test_list_all)))
    if test_list_error:
        logging.error("Unknown fuzz targets selected: {}".format(test_list_error))
    test_list_selection = list(set(test_list_all).intersection(set(args.target)))
    if not test_list_selection:
        logging.error("No fuzz targets selected")
    if args.exclude:
        for excluded_target in args.exclude.split(","):
            if excluded_target not in test_list_selection:
                logging.error("Target \"{}\" not found in current target list.".format(excluded_target))
                continue
            test_list_selection.remove(excluded_target)
    test_list_selection.sort()

    logging.info("{} of {} detected fuzz target(s) selected: {}".format(len(test_list_selection), len(test_list_all), " ".join(test_list_selection)))

    required_corpus_files = {}
    if args.require_qbit_corpus:
        required_corpus_files = check_required_corpus(
            corpus_dir=args.corpus_dir,
            test_list_all=test_list_all,
            test_list_selection=test_list_selection,
        )

    if not args.generate:
        test_list_missing_corpus = []
        for t in test_list_selection:
            corpus_path = os.path.join(args.corpus_dir, t)
            if not os.path.exists(corpus_path) or len(os.listdir(corpus_path)) == 0:
                test_list_missing_corpus.append(t)
        test_list_missing_corpus.sort()
        if test_list_missing_corpus:
            logging.info(
                "Fuzzing harnesses lacking a corpus: {}".format(
                    " ".join(test_list_missing_corpus)
                )
            )
            logging.info("Please consider adding a fuzz corpus at https://github.com/bitcoin-core/qa-assets")

    print("Check if using libFuzzer ... ", end='')
    help_output = subprocess.run(
        args=[
            fuzz_bin,
            '-help=1',
        ],
        env=get_fuzz_env(target=test_list_selection[0], source_dir=config['environment']['SRCDIR']),
        check=False,
        stderr=subprocess.PIPE,
        text=True,
    ).stderr
    using_libfuzzer = "libFuzzer" in help_output
    print(using_libfuzzer)
    if (args.generate or args.m_dir) and not using_libfuzzer:
        logging.error("Must be built with libFuzzer")
        sys.exit(1)
    if args.mutate_min_time is not None and not using_libfuzzer:
        logging.error("--mutate_min_time requires a fuzz executable built with libFuzzer")
        sys.exit(1)

    with ThreadPoolExecutor(max_workers=args.par) as fuzz_pool:
        if args.generate:
            return generate_corpus(
                fuzz_pool=fuzz_pool,
                src_dir=config['environment']['SRCDIR'],
                fuzz_bin=fuzz_bin,
                corpus_dir=args.corpus_dir,
                targets=test_list_selection,
            )

        if args.m_dir:
            merge_inputs(
                fuzz_pool=fuzz_pool,
                corpus=args.corpus_dir,
                test_list=test_list_selection,
                src_dir=config['environment']['SRCDIR'],
                fuzz_bin=fuzz_bin,
                merge_dirs=[Path(m_dir) for m_dir in args.m_dir],
            )
            return

        if args.mutate_min_time is not None:
            run_mutation(
                fuzz_pool=fuzz_pool,
                corpus=args.corpus_dir,
                test_list=test_list_selection,
                src_dir=config['environment']['SRCDIR'],
                fuzz_bin=fuzz_bin,
                min_time=args.mutate_min_time,
                required_corpus_files=required_corpus_files,
            )
            return

        run_once(
            fuzz_pool=fuzz_pool,
            corpus=args.corpus_dir,
            test_list=test_list_selection,
            src_dir=config['environment']['SRCDIR'],
            fuzz_bin=fuzz_bin,
            using_libfuzzer=using_libfuzzer,
            use_valgrind=args.valgrind,
            empty_min_time=args.empty_min_time,
            required_corpus_files=required_corpus_files,
        )


def check_required_corpus(*, corpus_dir, test_list_all, test_list_selection):
    """Return {target: number of regular input files} for the required targets, or exit if any is unusable."""
    errors = []
    file_counts = {}
    for t in QBIT_REQUIRED_CORPUS_TARGETS:
        corpus_path = corpus_dir / t
        if t not in test_list_all:
            errors.append(f"{t}: not compiled into the fuzz executable")
        elif t not in test_list_selection:
            errors.append(f"{t}: not selected (check the target list and --exclude)")
        elif not corpus_path.is_dir():
            errors.append(f"{t}: corpus directory {corpus_path} does not exist")
        else:
            # Only regular files directly in the directory are replayed by every fuzz engine.
            file_count = sum(1 for p in corpus_path.iterdir() if p.is_file())
            if file_count == 0:
                errors.append(f"{t}: corpus directory {corpus_path} has no regular input files")
            file_counts[t] = file_count
    if errors:
        for error in errors:
            logging.error(f"Required qbit corpus check failed: {error}")
        sys.exit(1)
    return file_counts


def last_int_match(pattern, output):
    """Return the integers captured by the only line matching pattern, or None if there is not exactly one."""
    matches = re.findall(pattern, output, flags=re.MULTILINE)
    if len(matches) != 1:
        return None
    return tuple(int(m) for m in matches[0]) if isinstance(matches[0], tuple) else int(matches[0])


def reported_input_count(*, output, target, using_libfuzzer):
    """Return how many inputs the fuzz executable reports having run from the corpus, or None."""
    if using_libfuzzer:
        return last_int_match(r"^INFO: seed corpus: files: (\d+) ", output)
    return last_int_match(rf"^{re.escape(target)}: succeeded against (\d+) files in ", output)


def as_text(stream):
    if stream is None:
        return ""
    return stream.decode(errors="replace") if isinstance(stream, bytes) else stream


def transform_process_message_target(targets, src_dir):
    """Add a target per process message, and also keep ("process_message", {}) to allow for
    cross-pollination, or unlimited search"""

    p2p_msg_target = "process_message"
    if (p2p_msg_target, {}) in targets:
        lines = subprocess.run(
            ["git", "grep", "--function-context", "ALL_NET_MESSAGE_TYPES{", src_dir / "src" / "protocol.h"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.splitlines()
        lines = [l.split("::", 1)[1].split(",")[0].lower() for l in lines if l.startswith("src/protocol.h-    NetMsgType::")]
        assert len(lines)
        targets += [(p2p_msg_target, {"LIMIT_TO_MESSAGE_TYPE": m}) for m in lines]
    return targets


def transform_rpc_target(targets, src_dir):
    """Add a target per RPC command, and also keep ("rpc", {}) to allow for cross-pollination,
    or unlimited search"""

    rpc_target = "rpc"
    if (rpc_target, {}) in targets:
        lines = subprocess.run(
            ["git", "grep", "--function-context", "RPC_COMMANDS_SAFE_FOR_FUZZING{", src_dir / "src" / "test" / "fuzz" / "rpc.cpp"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.splitlines()
        lines = [l.split("\"", 1)[1].split("\"")[0] for l in lines if l.startswith("src/test/fuzz/rpc.cpp-    \"")]
        assert len(lines)
        targets += [(rpc_target, {"LIMIT_TO_RPC_COMMAND": r}) for r in lines]
    return targets


def generate_corpus(*, fuzz_pool, src_dir, fuzz_bin, corpus_dir, targets):
    """Generates new corpus.

    Run {targets} without input, and outputs the generated corpus to
    {corpus_dir}.
    """
    logging.info("Generating corpus to {}".format(corpus_dir))
    targets = [(t, {}) for t in targets]  # expand to add dictionary for target-specific env variables
    targets = transform_process_message_target(targets, Path(src_dir))
    targets = transform_rpc_target(targets, Path(src_dir))

    def job(command, t, t_env):
        logging.debug(f"Running '{command}'")
        logging.debug("Command '{}' output:\n'{}'\n".format(
            command,
            subprocess.run(
                command,
                env={
                    **t_env,
                    **get_fuzz_env(target=t, source_dir=src_dir),
                },
                check=True,
                stderr=subprocess.PIPE,
                text=True,
            ).stderr,
        ))

    futures = []
    for target, t_env in targets:
        target_corpus_dir = corpus_dir / target
        os.makedirs(target_corpus_dir, exist_ok=True)
        use_value_profile = int(random.random() < .3)
        command = [
            fuzz_bin,
            "-rss_limit_mb=8000",
            "-max_total_time=6000",
            "-reload=0",
            f"-use_value_profile={use_value_profile}",
            target_corpus_dir,
        ]
        futures.append(fuzz_pool.submit(job, command, target, t_env))

    for future in as_completed(futures):
        future.result()


def merge_inputs(*, fuzz_pool, corpus, test_list, src_dir, fuzz_bin, merge_dirs):
    logging.info(f"Merge the inputs from the passed dir into the corpus_dir. Passed dirs {merge_dirs}")
    jobs = []
    for t in test_list:
        args = [
            fuzz_bin,
            '-rss_limit_mb=8000',
            '-set_cover_merge=1',
            # set_cover_merge is used instead of -merge=1 to reduce the overall
            # size of the qa-assets git repository a bit, but more importantly,
            # to cut the runtime to iterate over all fuzz inputs [0].
            # [0] https://github.com/bitcoin-core/qa-assets/issues/130#issuecomment-1761760866
            '-shuffle=0',
            '-prefer_small=1',
            '-use_value_profile=0',
            # use_value_profile is enabled by oss-fuzz [0], but disabled for
            # now to avoid bloating the qa-assets git repository [1].
            # [0] https://github.com/google/oss-fuzz/issues/1406#issuecomment-387790487
            # [1] https://github.com/bitcoin-core/qa-assets/issues/130#issuecomment-1749075891
            os.path.join(corpus, t),
        ] + [str(m_dir / t) for m_dir in merge_dirs]
        os.makedirs(os.path.join(corpus, t), exist_ok=True)
        for m_dir in merge_dirs:
            (m_dir / t).mkdir(exist_ok=True)

        def job(t, args):
            output = 'Run {} with args {}\n'.format(t, " ".join(args))
            output += subprocess.run(
                args,
                env=get_fuzz_env(target=t, source_dir=src_dir),
                check=True,
                stderr=subprocess.PIPE,
                text=True,
            ).stderr
            logging.debug(output)

        jobs.append(fuzz_pool.submit(job, t, args))

    for future in as_completed(jobs):
        future.result()


def run_once(*, fuzz_pool, corpus, test_list, src_dir, fuzz_bin, using_libfuzzer, use_valgrind, empty_min_time, required_corpus_files):
    jobs = []
    for t in test_list:
        corpus_path = corpus / t
        os.makedirs(corpus_path, exist_ok=True)
        args = [
            fuzz_bin,
        ]
        empty_dir = not any(corpus_path.iterdir())
        if using_libfuzzer:
            if empty_min_time and empty_dir:
                args += [f"-max_total_time={empty_min_time}"]
            else:
                args += [
                    "-runs=1",
                    corpus_path,
                ]
        else:
            args += [corpus_path]
        if use_valgrind:
            args = ['valgrind', '--quiet', '--error-exitcode=1'] + args

        def job(t, args):
            output = 'Run {} with args {}\n'.format(t, args)
            result = subprocess.run(
                args,
                env=get_fuzz_env(target=t, source_dir=src_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            output += result.stderr
            if not output.endswith("\n"):
                output += "\n"
            # Non-libFuzzer executables report the replayed input count on stdout.
            output += result.stdout
            return output, result, t

        jobs.append(fuzz_pool.submit(job, t, args))

    stats = []
    replay_evidence = []
    for future in as_completed(jobs):
        output, result, target = future.result()
        logging.debug(output)
        try:
            result.check_returncode()
        except subprocess.CalledProcessError as e:
            if e.stdout:
                logging.info(e.stdout)
            if e.stderr:
                logging.info(e.stderr)
            logging.info(f"⚠️ Failure generated from target with exit code {e.returncode}: {result.args}")
            sys.exit(1)
        if using_libfuzzer:
            done_stat = [l for l in output.splitlines() if "DONE" in l]
            assert len(done_stat) == 1
            stats.append((target, done_stat[0]))
        if target in required_corpus_files:
            replayed = reported_input_count(output=output, target=target, using_libfuzzer=using_libfuzzer)
            replay_evidence.append((target, required_corpus_files[target], replayed))

    if using_libfuzzer:
        print("Summary:")
        max_len = max(len(t[0]) for t in stats)
        for t, s in sorted(stats):
            t = t.ljust(max_len + 1)
            print(f"{t}{s}")

    if required_corpus_files and not report_replay_evidence(replay_evidence, required_corpus_files):
        sys.exit(1)


def report_replay_evidence(replay_evidence, required_corpus_files):
    """Print per-target replay counts; return False unless every required target replayed all its files."""
    ok = True
    print("Required qbit corpus replay:")
    reported = {target: (present, replayed) for target, present, replayed in replay_evidence}
    for target in sorted(required_corpus_files):
        present, replayed = reported.get(target, (required_corpus_files[target], None))
        if replayed is None:
            status = "FAILED: the fuzz executable did not report a replay count"
            ok = False
        elif replayed == 0 or replayed < present:
            status = f"FAILED: {replayed} inputs replayed"
            ok = False
        else:
            status = f"{replayed} inputs replayed"
        print(f"{target}: {present} regular input files present, {status}")
    return ok


def run_mutation(*, fuzz_pool, corpus, test_list, src_dir, fuzz_bin, min_time, required_corpus_files):
    """Run a libFuzzer mutation phase of min_time seconds per target, seeded from the corpus.

    libFuzzer writes new inputs to the first directory argument, so that is a
    fresh temporary directory removed when the job ends; the corpus directory
    is passed second and only read. Crash artifacts go to the working
    directory, as for any libFuzzer run. A target fails unless libFuzzer
    reports more runs in total than it needed to initialize from the corpus.
    """
    timeout = min_time + MUTATION_TIMEOUT_GRACE_SECONDS

    def job(t):
        corpus_path = corpus / t
        if not corpus_path.is_dir():
            return t, [], "missing", f"corpus directory {corpus_path} does not exist"
        with tempfile.TemporaryDirectory(prefix=f"fuzz_mutate_{t}_") as output_dir:
            args = [
                fuzz_bin,
                f"-max_total_time={min_time}",
                "-reload=0",
                output_dir,
                str(corpus_path),
            ]
            try:
                result = subprocess.run(
                    args,
                    env=get_fuzz_env(target=t, source_dir=src_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as e:
                return t, args, "timeout", as_text(e.stderr) + as_text(e.stdout)
        return t, args, result.returncode, result.stderr + result.stdout

    jobs = [fuzz_pool.submit(job, t) for t in test_list]

    failed = False
    lines = []
    for future in as_completed(jobs):
        target, args, returncode, output = future.result()
        logging.debug(f"Run {target} with args {args}\n{output}")
        if returncode == "missing":
            logging.error(f"⚠️ {target}: {output}")
            failed = True
            continue
        if returncode == "timeout":
            logging.info(output)
            logging.error(f"⚠️ {target}: mutation phase did not exit within {timeout}s and was stopped: {args}")
            failed = True
            continue
        if returncode != 0:
            logging.info(output)
            logging.info(f"⚠️ Failure generated from target with exit code {returncode}: {args}")
            failed = True
            continue

        problems = []
        done = last_int_match(r"^Done (\d+) runs in (\d+) second", output)
        inited = last_int_match(r"^#(\d+)\s+INITED\b", output)
        rng_seed = last_int_match(r"^INFO: Seed: (\d+)$", output)
        loaded = reported_input_count(output=output, target=target, using_libfuzzer=True)
        if done is None:
            problems.append("libFuzzer did not report its run count")
        elif done[1] < min_time:
            problems.append(f"stopped after {done[1]}s, before the {min_time}s budget")
        # The time budget includes loading the seed corpus, so a slow target can
        # use all of it before a single mutated input runs.
        if inited is None:
            problems.append("libFuzzer did not report its initialization run count")
        elif done is not None and done[0] <= inited:
            problems.append(f"{inited} initialization runs, {done[0]} runs in total: no inputs were run after corpus initialization")
        if target in required_corpus_files:
            present = required_corpus_files[target]
            if loaded is None or loaded == 0 or loaded < present:
                problems.append(f"seed corpus inputs run: {loaded}, regular input files present: {present}")
        if problems:
            logging.info(output)
            logging.error(f"⚠️ {target}: " + "; ".join(problems))
            failed = True
            continue
        runs, seconds = done
        lines.append(
            f"{target}: rng seed {rng_seed}, {loaded} seed corpus inputs, {inited} initialization runs, "
            f"{runs - inited} runs after initialization, {runs} runs in {seconds}s"
        )

    print("Mutation summary:")
    for line in sorted(lines):
        print(line)
    if failed:
        sys.exit(1)


def parse_test_list(*, fuzz_bin, source_dir):
    test_list_all = subprocess.run(
        fuzz_bin,
        env={
            'PRINT_ALL_FUZZ_TARGETS_AND_ABORT': '',
            **get_fuzz_env(target="", source_dir=source_dir)
        },
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.splitlines()
    return test_list_all


if __name__ == '__main__':
    main()
