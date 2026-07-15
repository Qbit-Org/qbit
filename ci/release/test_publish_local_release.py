#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Behavioral tests for the local GitHub Release publisher."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PUBLISHER = REPO_ROOT / "contrib" / "release-process" / "publish-local-release.sh"
TAG = "v0.0.0-testnet1"
GENERATED_NOTES = "Generated release notes\n\n* Deterministic change list\n"


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=qbit release test",
            "-c",
            "user.email=release-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            "-C",
            str(repo),
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


class PublishLocalReleaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.gh_state = self.root / "gh-state"
        self.gh_state.mkdir()
        self.gh_log = self.root / "gh.log"
        self.validator_log = self.root / "validator.log"
        self._write_fake_gh()
        self._write_executable(self.bin_dir / "gpg", "#!/usr/bin/env bash\nexit 0\n")
        self._write_executable(self.bin_dir / "sleep", "#!/usr/bin/env bash\nexit 0\n")
        self.trusted = self._build_trusted_checkout()
        self.guix_sigs = self._build_guix_sigs_checkout()
        self.artifacts = self._build_artifacts()
        self.posture = self.root / "testnet-posture.env"
        self.posture.write_text("testnet_release_posture=validated\n", encoding="utf8")
        self.p2mr_evidence = self.root / "p2mr-evidence.json"
        self.p2mr_oracle = self.root / "p2mr-oracle.json"
        self.p2mr_matrix = self.root / "p2mr-matrix.json"
        for path in (self.p2mr_evidence, self.p2mr_oracle, self.p2mr_matrix):
            path.write_text("{}\n", encoding="utf8")
        self.tag_object = git(self.trusted, "rev-parse", f"refs/tags/{TAG}^{{tag}}")
        self.tag_target = git(self.trusted, "rev-parse", f"refs/tags/{TAG}^{{commit}}")
        self.trusted_ref = git(self.trusted, "rev-parse", "HEAD")
        self.guix_sigs_ref = git(self.guix_sigs, "rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def _write_executable(path: Path, body: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(body), encoding="utf8")
        path.chmod(0o755)

    def _write_fake_gh(self) -> None:
        self._write_executable(
            self.bin_dir / "gh",
            r"""#!/usr/bin/env python3
import hashlib
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
state = Path(os.environ["FAKE_GH_STATE"])
log = Path(os.environ["FAKE_GH_LOG"])
with log.open("a", encoding="utf8") as output:
    output.write(" ".join(args) + "\n")


def sequence_value(name, fallback, index):
    values = os.environ.get(name, fallback).split(",")
    return values[min(index, len(values) - 1)]


def next_counter(name):
    path = state / name
    value = int(path.read_text(encoding="utf8")) if path.exists() else 0
    path.write_text(str(value + 1), encoding="utf8")
    return value


def api_fields():
    fields = {}
    for index, value in enumerate(args[:-1]):
        if value in {"-f", "-F", "--raw-field", "--field"}:
            key, field_value = args[index + 1].split("=", 1)
            fields[key] = field_value
    return fields


if args[:2] == ["auth", "status"]:
    raise SystemExit(0)

if args and args[0] == "api":
    endpoint = next(value for value in args[1:] if value.startswith("repos/"))
    if "/git/ref/tags/" in endpoint:
        index = next_counter("tag-ref-read-count")
        moved_tag_path = state / "moved-tag-object"
        if moved_tag_path.exists():
            tag_object = moved_tag_path.read_text(encoding="utf8")
        else:
            tag_object = sequence_value(
                "FAKE_GH_TAG_OBJECT_SEQUENCE",
                os.environ["FAKE_GH_TAG_OBJECT"],
                index,
            )
        print("tag " + tag_object)
    elif "/git/tags/" in endpoint:
        index = next_counter("tag-object-read-count")
        print(
            "\t".join(
                [
                    sequence_value(
                        "FAKE_GH_TAG_TARGET_SEQUENCE",
                        os.environ["FAKE_GH_TAG_TARGET"],
                        index,
                    ),
                    "commit",
                    sequence_value(
                        "FAKE_GH_VERIFIED_SEQUENCE",
                        os.environ.get("FAKE_GH_VERIFIED", "true"),
                        index,
                    ),
                    sequence_value(
                        "FAKE_GH_VERIFICATION_REASON_SEQUENCE", "valid", index
                    ),
                    "2026-01-01T00:00:00Z",
                ]
            )
        )
    elif "/compare/" in endpoint:
        print("behind")
    elif "/commits/" in endpoint:
        print(endpoint.rsplit("/", 1)[1])
    elif endpoint.count("/") == 2:
        print(os.environ.get("FAKE_GH_CAN_PUSH", "true"))
    elif endpoint.endswith("/releases/generate-notes"):
        print(
            json.dumps(
                {
                    "name": os.environ["FAKE_GH_TAG"],
                    "body": os.environ["FAKE_GH_GENERATED_NOTES"],
                }
            )
        )
    elif endpoint.endswith("/releases?per_page=100"):
        if os.environ.get("FAKE_GH_RELEASE_LOOKUP_ERROR") == "true":
            print("simulated release lookup failure", file=sys.stderr)
            raise SystemExit(1)
        release_state = state / "release-state"
        if release_state.exists():
            draft = release_state.read_text(encoding="utf8").strip() == "draft"
            if draft:
                immutable = os.environ.get("FAKE_GH_DRAFT_IMMUTABLE", "false")
            else:
                moved_tag_object = os.environ.get(
                    "FAKE_GH_TAG_OBJECT_DURING_IMMUTABLE_POLL", ""
                )
                if moved_tag_object:
                    (state / "moved-tag-object").write_text(
                        moved_tag_object, encoding="utf8"
                    )
                sequence = os.environ.get("FAKE_GH_IMMUTABLE_SEQUENCE", "true").split(",")
                counter_path = state / "immutable-view-count"
                counter = int(counter_path.read_text(encoding="utf8")) if counter_path.exists() else 0
                immutable = sequence[min(counter, len(sequence) - 1)]
                counter_path.write_text(str(counter + 1), encoding="utf8")
            print(
                "\t".join(
                    [
                        "1",
                        str(draft).lower(),
                        immutable,
                        os.environ["FAKE_GH_TAG"],
                        "https://example.invalid/release/" + os.environ["FAKE_GH_TAG"],
                    ]
                )
            )
    elif "/releases/1/assets" in endpoint:
        assets = state / "assets.tsv"
        if assets.exists():
            asset_text = assets.read_text(encoding="utf8")
            release_state = state / "release-state"
            published = (
                release_state.exists()
                and release_state.read_text(encoding="utf8").strip() == "published"
            )
            if published:
                lag = int(os.environ.get("FAKE_GH_PUBLISHED_ASSET_LAG", "0"))
                counter_path = state / "published-asset-view-count"
                counter = (
                    int(counter_path.read_text(encoding="utf8"))
                    if counter_path.exists()
                    else 0
                )
                counter_path.write_text(str(counter + 1), encoding="utf8")
                if counter < lag:
                    for line in asset_text.splitlines():
                        if line:
                            print(line.split("\t", 1)[0] + "\t")
                    raise SystemExit(0)
            asset_reads = state / "asset-reads"
            read_count = (
                int(asset_reads.read_text(encoding="utf8"))
                if asset_reads.exists()
                else 0
            )
            asset_reads.write_text(str(read_count + 1), encoding="utf8")
            if read_count < int(os.environ["FAKE_GH_EMPTY_DIGEST_READS"]):
                for line in asset_text.splitlines():
                    print(line.split("\t", 1)[0] + "\t")
            else:
                print(asset_text, end="")
    elif endpoint.endswith("/releases/1") and "PATCH" in args:
        fields = api_fields()
        if fields.get("draft") == "false":
            (state / "release-state").write_text("published\n", encoding="utf8")
        if "make_latest" in fields:
            (state / "latest-mode").write_text(
                fields["make_latest"], encoding="utf8"
            )
            (state / "latest-state").write_text(
                fields["make_latest"], encoding="utf8"
            )
        print(json.dumps({"id": 1, "draft": fields.get("draft") != "false"}))
    elif endpoint.endswith("/releases/1"):
        body_path = state / "release-body"
        body = body_path.read_text(encoding="utf8") if body_path.exists() else ""
        title_path = state / "release-title"
        title = title_path.read_text(encoding="utf8") if title_path.exists() else ""
        print(json.dumps({"body": body, "name": title}))
    else:
        print("unsupported fake gh api endpoint: " + endpoint, file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(0)

if args[:2] == ["release", "create"]:
    (state / "release-state").write_text("draft\n", encoding="utf8")
    (state / "assets.tsv").write_text("", encoding="utf8")
    notes_file = Path(args[args.index("--notes-file") + 1])
    (state / "release-body").write_text(
        notes_file.read_text(encoding="utf8"), encoding="utf8"
    )
    title = args[args.index("--title") + 1]
    (state / "release-title").write_text(title, encoding="utf8")
    prerelease = "true" if "--prerelease" in args else "false"
    latest = "true" if "--latest" in args else "false"
    (state / "prerelease-state").write_text(prerelease, encoding="utf8")
    (state / "latest-state").write_text(latest, encoding="utf8")
    raise SystemExit(0)

if args[:2] == ["release", "upload"]:
    path = Path(args[3])
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with (state / "assets.tsv").open("a", encoding="utf8") as output:
        output.write(f"{path.name}\tsha256:{digest}\n")
    raise SystemExit(0)

if args[:2] == ["release", "edit"]:
    if (
        "--notes-file" in args
        and os.environ.get("FAKE_GH_IGNORE_NOTES_EDIT") != "true"
    ):
        notes_file = Path(args[args.index("--notes-file") + 1])
        (state / "release-body").write_text(
            notes_file.read_text(encoding="utf8"), encoding="utf8"
        )
    if "--title" in args:
        title = args[args.index("--title") + 1]
        (state / "release-title").write_text(title, encoding="utf8")
    if "--draft=false" in args:
        (state / "release-state").write_text("published\n", encoding="utf8")
    if "--prerelease" in args:
        (state / "prerelease-state").write_text("true", encoding="utf8")
    elif "--prerelease=false" in args:
        (state / "prerelease-state").write_text("false", encoding="utf8")
    if "--latest" in args:
        (state / "latest-state").write_text("true", encoding="utf8")
    elif "--latest=false" in args:
        (state / "latest-state").write_text("false", encoding="utf8")
    raise SystemExit(0)

print("unsupported fake gh command: " + " ".join(args), file=sys.stderr)
raise SystemExit(2)
""",
        )

    def _build_trusted_checkout(self) -> Path:
        root = self.root / "trusted"
        root.mkdir()
        git(root, "init", "-q")
        (root / "README.md").write_text("release source\n", encoding="utf8")
        git(root, "add", "README.md")
        git(root, "commit", "-q", "-m", "release source")
        git(root, "tag", "-a", TAG, "-m", TAG)

        publisher = root / "contrib" / "release-process" / PUBLISHER.name
        publisher.parent.mkdir(parents=True)
        shutil.copy2(PUBLISHER, publisher)
        keys_dir = root / "contrib" / "keys" / "operator-keys"
        keys_dir.mkdir(parents=True)
        (keys_dir / "keys.json").write_text('{"schema_version": 2}\n', encoding="utf8")

        validator_dir = root / "ci" / "release"
        validator_dir.mkdir(parents=True)
        self._write_executable(
            validator_dir / "validate_release_artifacts.py",
            r"""#!/usr/bin/env python3
import os
import sys
from pathlib import Path

args = sys.argv[1:]
def option(name):
    return args[args.index(name) + 1]

artifacts = Path(option("--artifacts-dir"))
output_path = Path(option("--github-output"))
notes_to_mutate = os.environ.get("FAKE_MUTATE_NOTES_FILE")
if notes_to_mutate:
    Path(notes_to_mutate).write_text("mutated after snapshot\n", encoding="utf8")
files = sorted(path.resolve() for path in artifacts.iterdir() if path.is_file())
with output_path.open("a", encoding="utf8") as output:
    output.write(f"file_count={len(files)}\n")
    output.write("artifact_count=1\n")
    output.write("core_artifact_count=1\n")
    output.write("photon_artifact_count=0\n")
    output.write("release_signer_count=3\n")
    output.write("release_signature_count=2\n")
    output.write("release_signature_quorum=2\n")
    output.write("release_signature_aliases=operator-01,operator-02\n")
    output.write("keys_json_sha256=" + "a" * 64 + "\n")
    output.write("files<<__FILES__\n")
    for path in files:
        output.write(str(path) + "\n")
    output.write("__FILES__\n")
with open(os.environ["FAKE_VALIDATOR_LOG"], "a", encoding="utf8") as log:
    log.write("release " + " ".join(args) + "\n")
""",
        )
        self._write_executable(
            validator_dir / "validate_builder_attestations.py",
            r"""#!/usr/bin/env python3
import os
import sys
from pathlib import Path

args = sys.argv[1:]
def option(name):
    return args[args.index(name) + 1]

with Path(option("--github-output")).open("a", encoding="utf8") as output:
    output.write("builder_attestation_quorum=2\n")
    output.write("builder_attestation_core_count=2\n")
    output.write("builder_attestation_core_aliases=operator-01,operator-02\n")
    output.write("builder_attestation_source_archive=qbit-0.0.0-testnet1.tar.gz\n")
    output.write("builder_attestation_source_sha256=" + "b" * 64 + "\n")
    output.write("builder_attestation_tag_target=" + option("--expected-tag-target") + "\n")
with open(os.environ["FAKE_VALIDATOR_LOG"], "a", encoding="utf8") as log:
    log.write("builder " + " ".join(args) + "\n")
""",
        )
        self._write_executable(
            validator_dir / "verify_p2mr_v1_conformance.py",
            r"""#!/usr/bin/env python3
import os
import sys

with open(os.environ["FAKE_VALIDATOR_LOG"], "a", encoding="utf8") as log:
    log.write("p2mr " + " ".join(sys.argv[1:]) + "\n")
""",
        )
        self._write_executable(
            validator_dir / "verify_mainnet_release_posture.py",
            r"""#!/usr/bin/env python3
import os
import sys

with open(os.environ["FAKE_VALIDATOR_LOG"], "a", encoding="utf8") as log:
    log.write("mainnet-posture " + " ".join(sys.argv[1:]) + "\n")
""",
        )
        for name in ("validate_key_metadata.py", "verify_testnet_release_posture.py"):
            self._write_executable(
                validator_dir / name,
                "#!/usr/bin/env python3\nraise SystemExit(0)\n",
            )

        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "trusted release policy")
        return root

    def _build_guix_sigs_checkout(self) -> Path:
        root = self.root / "qbit-guix.sigs"
        keys_dir = root / "operator-keys"
        keys_dir.mkdir(parents=True)
        (keys_dir / "keys.json").write_text('{"schema_version": 2}\n', encoding="utf8")
        git(root, "init", "-q")
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "builder attestations")
        return root

    def _build_artifacts(self) -> Path:
        root = self.root / "artifacts"
        root.mkdir()
        artifact = root / "qbit-0.0.0-testnet1-x86_64-linux-gnu.tar.gz"
        artifact.write_bytes(b"release artifact\n")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        (root / "SHA256SUMS").write_text(
            f"{digest}  {artifact.name}\n", encoding="utf8"
        )
        (root / "SHA256SUMS.asc").write_text("release signatures\n", encoding="utf8")
        return root

    def run_publisher(
        self,
        *extra_args: str,
        verified: bool = True,
        trusted_ref: str | None = None,
        ignore_notes_edit: bool = False,
        empty_digest_reads: int = 0,
        release_line: str = "testnet",
        immutable_sequence: tuple[str, ...] = ("true",),
        draft_immutable: str = "false",
        release_lookup_error: bool = False,
        published_asset_lag: int = 0,
        can_push: bool = True,
        tag_object_sequence: tuple[str, ...] | None = None,
        tag_target_sequence: tuple[str, ...] | None = None,
        verified_sequence: tuple[bool, ...] | None = None,
        verification_reason_sequence: tuple[str, ...] | None = None,
        tag_object_during_immutable_poll: str | None = None,
        mutate_notes_file: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PATH"] = f"{self.bin_dir}{os.pathsep}{env['PATH']}"
        env.update(
            {
                "FAKE_GH_STATE": str(self.gh_state),
                "FAKE_GH_LOG": str(self.gh_log),
                "FAKE_GH_TAG": TAG,
                "FAKE_GH_TAG_OBJECT": self.tag_object,
                "FAKE_GH_TAG_TARGET": self.tag_target,
                "FAKE_GH_VERIFIED": str(verified).lower(),
                "FAKE_GH_TAG_OBJECT_SEQUENCE": ",".join(
                    tag_object_sequence or (self.tag_object,)
                ),
                "FAKE_GH_TAG_TARGET_SEQUENCE": ",".join(
                    tag_target_sequence or (self.tag_target,)
                ),
                "FAKE_GH_VERIFIED_SEQUENCE": ",".join(
                    str(value).lower()
                    for value in (verified_sequence or (verified,))
                ),
                "FAKE_GH_VERIFICATION_REASON_SEQUENCE": ",".join(
                    verification_reason_sequence or ("valid",)
                ),
                "FAKE_GH_TAG_OBJECT_DURING_IMMUTABLE_POLL": (
                    tag_object_during_immutable_poll or ""
                ),
                "FAKE_GH_GENERATED_NOTES": GENERATED_NOTES,
                "FAKE_GH_IGNORE_NOTES_EDIT": str(ignore_notes_edit).lower(),
                "FAKE_GH_EMPTY_DIGEST_READS": str(empty_digest_reads),
                "FAKE_GH_IMMUTABLE_SEQUENCE": ",".join(immutable_sequence),
                "FAKE_GH_DRAFT_IMMUTABLE": draft_immutable,
                "FAKE_GH_RELEASE_LOOKUP_ERROR": str(release_lookup_error).lower(),
                "FAKE_GH_PUBLISHED_ASSET_LAG": str(published_asset_lag),
                "FAKE_GH_CAN_PUSH": str(can_push).lower(),
                "FAKE_VALIDATOR_LOG": str(self.validator_log),
                "FAKE_MUTATE_NOTES_FILE": str(mutate_notes_file or ""),
            }
        )
        args = [
            str(self.trusted / "contrib" / "release-process" / PUBLISHER.name),
            "--tag",
            TAG,
            "--artifacts-dir",
            str(self.artifacts),
            "--trusted-release-ref",
            trusted_ref or self.trusted_ref,
            "--guix-sigs-repo",
            str(self.guix_sigs),
            "--guix-sigs-ref",
            self.guix_sigs_ref,
            "--release-line",
            release_line,
        ]
        if release_line == "testnet":
            args.extend(["--testnet-posture-evidence", str(self.posture)])
        args.extend(extra_args)
        return subprocess.run(args, check=False, capture_output=True, text=True, env=env)

    def test_validation_only_uses_pr84_source_binding_inputs(self) -> None:
        result = self.run_publisher()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Validation-only mode", result.stdout)
        self.assertIn("would be created with the expected notes", result.stdout)
        self.assertNotIn("gh release create", result.stdout)
        validator_log = self.validator_log.read_text(encoding="utf8")
        self.assertIn(f"--source-root {self.trusted.resolve()}", validator_log)
        self.assertIn(f"--expected-tag-target {self.tag_target}", validator_log)
        gh_log = self.gh_log.read_text(encoding="utf8")
        self.assertNotIn("release create", gh_log)
        self.assertNotIn("release upload", gh_log)

    def test_unverified_remote_tag_fails_before_validation(self) -> None:
        result = self.run_publisher(verified=False)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a GitHub-verified signed tag", result.stderr)
        self.assertFalse(self.validator_log.exists())

    def test_mainnet_requires_complete_p2mr_conformance_evidence(self) -> None:
        result = self.run_publisher(release_line="mainnet")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("P2MR_V1_CONFORMANCE_EVIDENCE is required", result.stderr)
        self.assertFalse(self.validator_log.exists())

    def test_mainnet_posture_runs_before_conformance_and_artifact_validation(self) -> None:
        result = self.run_publisher(
            "--p2mr-v1-conformance-evidence",
            str(self.p2mr_evidence),
            "--p2mr-v1-oracle-report",
            str(self.p2mr_oracle),
            "--p2mr-v1-integration-matrix",
            str(self.p2mr_matrix),
            release_line="mainnet",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        validator_log = self.validator_log.read_text(encoding="utf8")
        self.assertLess(
            validator_log.index("mainnet-posture "), validator_log.index("p2mr ")
        )
        self.assertLess(validator_log.index("p2mr "), validator_log.index("release "))
        self.assertIn(f"--source-root {self.trusted.resolve()}", validator_log)
        self.assertIn(f"--release-tag {TAG}", validator_log)

    def test_p2mr_conformance_runs_before_artifact_validation(self) -> None:
        result = self.run_publisher(
            "--p2mr-v1-conformance-evidence",
            str(self.p2mr_evidence),
            "--p2mr-v1-oracle-report",
            str(self.p2mr_oracle),
            "--p2mr-v1-integration-matrix",
            str(self.p2mr_matrix),
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        validator_log = self.validator_log.read_text(encoding="utf8")
        self.assertLess(validator_log.index("p2mr "), validator_log.index("release "))
        self.assertIn(f"--source-root {self.trusted.resolve()}", validator_log)
        self.assertIn(f"--release-tag {TAG}", validator_log)

    def test_partial_p2mr_conformance_evidence_fails_closed(self) -> None:
        result = self.run_publisher(
            "--p2mr-v1-conformance-evidence",
            str(self.p2mr_evidence),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("P2MR_V1_ORACLE_REPORT is required", result.stderr)
        self.assertFalse(self.validator_log.exists())

    def test_validation_only_fails_when_release_lookup_is_inconclusive(self) -> None:
        result = self.run_publisher(release_lookup_error=True)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("simulated release lookup failure", result.stderr)
        self.assertIn("Could not inspect GitHub Release", result.stderr)
        gh_log = self.gh_log.read_text(encoding="utf8")
        self.assertNotIn("release create", gh_log)
        self.assertNotIn("release upload", gh_log)
        self.assertNotIn("release edit", gh_log)

    def test_release_discovery_requires_push_access(self) -> None:
        result = self.run_publisher(can_push=False)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires push access", result.stderr)
        self.assertFalse(self.validator_log.exists())

    def test_wrong_trusted_ref_fails_closed(self) -> None:
        result = self.run_publisher(trusted_ref="1" * 40)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Publisher checkout resolved", result.stderr)
        self.assertFalse(self.validator_log.exists())

    def test_published_release_is_never_modified(self) -> None:
        (self.gh_state / "release-state").write_text("published\n", encoding="utf8")
        (self.gh_state / "assets.tsv").write_text("", encoding="utf8")

        result = self.run_publisher("--publish")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists and is published", result.stderr)
        gh_log = self.gh_log.read_text(encoding="utf8")
        self.assertNotIn("release upload", gh_log)
        self.assertNotIn("release edit", gh_log)

    def test_validation_only_accepts_matching_immutable_published_release(self) -> None:
        (self.gh_state / "release-state").write_text("published\n", encoding="utf8")
        remote_assets = []
        for path in sorted(self.artifacts.iterdir()):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            remote_assets.append(f"{path.name}\tsha256:{digest}")
        (self.gh_state / "assets.tsv").write_text(
            "\n".join(remote_assets) + "\n", encoding="utf8"
        )

        result = self.run_publisher()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Published release assets exactly match", result.stdout)
        self.assertIn("Validation-only mode complete", result.stdout)
        gh_log = self.gh_log.read_text(encoding="utf8")
        self.assertNotIn("release create", gh_log)
        self.assertNotIn("release upload", gh_log)
        self.assertNotIn("release edit", gh_log)

    def test_validation_only_rejects_matching_mutable_published_release(self) -> None:
        (self.gh_state / "release-state").write_text("published\n", encoding="utf8")

        result = self.run_publisher(
            "--repo", "Example-Org/release-target", immutable_sequence=("false",)
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not confirm it as immutable", result.stderr)
        self.assertIn("Example-Org/release-target", result.stderr)
        self.assertIn("Settings > Releases", result.stderr)
        gh_log = self.gh_log.read_text(encoding="utf8")
        self.assertNotIn("release upload", gh_log)
        self.assertNotIn("release edit", gh_log)

    def test_validation_only_rejects_missing_published_immutable_state(self) -> None:
        (self.gh_state / "release-state").write_text("published\n", encoding="utf8")

        result = self.run_publisher(immutable_sequence=("null",))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("isImmutable=null", result.stderr)

    def test_create_draft_does_not_require_immutable_state(self) -> None:
        result = self.run_publisher("--create-draft", draft_immutable="null")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Verified draft release", result.stdout)
        self.assertFalse((self.gh_state / "immutable-view-count").exists())

    def test_resumed_draft_preserves_omitted_release_metadata(self) -> None:
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        (self.gh_state / "assets.tsv").write_text("", encoding="utf8")
        (self.gh_state / "prerelease-state").write_text("true", encoding="utf8")
        (self.gh_state / "latest-state").write_text("true", encoding="utf8")
        (self.gh_state / "release-title").write_text(
            "Custom coordinator title", encoding="utf8"
        )

        result = self.run_publisher("--publish")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.gh_state / "prerelease-state").read_text(encoding="utf8"), "true"
        )
        self.assertEqual(
            (self.gh_state / "latest-state").read_text(encoding="utf8"), "true"
        )
        self.assertEqual(
            (self.gh_state / "release-title").read_text(encoding="utf8"),
            "Custom coordinator title",
        )
        edit_args = next(
            line.split()
            for line in self.gh_log.read_text(encoding="utf8").splitlines()
            if line.startswith("release edit")
        )
        self.assertNotIn("--prerelease", edit_args)
        self.assertNotIn("--prerelease=false", edit_args)
        self.assertNotIn("--latest", edit_args)
        self.assertNotIn("--latest=false", edit_args)
        self.assertNotIn("--title", edit_args)
        gh_log = self.gh_log.read_text(encoding="utf8")
        self.assertIn("/releases?per_page=100", gh_log)
        self.assertNotIn("/releases/tags/", gh_log)
        self.assertNotIn("release create", gh_log)
        publish_call = next(
            line
            for line in gh_log.splitlines()
            if "/releases/1 --method PATCH" in line and "draft=false" in line
        )
        self.assertNotIn("make_latest=", publish_call)

    def test_resumed_draft_replaces_title_only_when_explicit(self) -> None:
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        (self.gh_state / "assets.tsv").write_text("", encoding="utf8")
        (self.gh_state / "release-title").write_text(
            "Custom coordinator title", encoding="utf8"
        )

        result = self.run_publisher(
            "--publish", "--release-name", "Approved release title"
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.gh_state / "release-title").read_text(encoding="utf8"),
            "Approved release title",
        )
        edit_call = next(
            line
            for line in self.gh_log.read_text(encoding="utf8").splitlines()
            if line.startswith("release edit ")
        )
        self.assertIn("--title Approved release title", edit_call)

    def test_resumed_draft_metadata_can_be_explicitly_cleared(self) -> None:
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        (self.gh_state / "assets.tsv").write_text("", encoding="utf8")
        (self.gh_state / "prerelease-state").write_text("true", encoding="utf8")
        (self.gh_state / "latest-state").write_text("true", encoding="utf8")

        result = self.run_publisher(
            "--create-draft", "--no-prerelease", "--make-latest", "false"
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.gh_state / "prerelease-state").read_text(encoding="utf8"), "false"
        )
        self.assertEqual(
            (self.gh_state / "latest-state").read_text(encoding="utf8"), "false"
        )

    def test_draft_asset_digest_mismatch_fails_without_replacement(self) -> None:
        artifact = next(
            path for path in self.artifacts.iterdir() if path.name.startswith("qbit-")
        )
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        (self.gh_state / "assets.tsv").write_text(
            f"{artifact.name}\tsha256:{'0' * 64}\n", encoding="utf8"
        )

        result = self.run_publisher("--publish")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest_mismatch", result.stderr)
        gh_log = self.gh_log.read_text(encoding="utf8")
        self.assertNotIn("release upload", gh_log)
        self.assertNotIn("--clobber", gh_log)

    def test_resume_retries_transient_remote_asset_digest(self) -> None:
        artifact = next(
            path for path in self.artifacts.iterdir() if path.name.startswith("qbit-")
        )
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        (self.gh_state / "assets.tsv").write_text(
            f"{artifact.name}\tsha256:{digest}\n", encoding="utf8"
        )
        (self.gh_state / "release-body").write_text("stale\n", encoding="utf8")

        result = self.run_publisher(
            "--create-draft",
            empty_digest_reads=1,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Found matching draft release", result.stdout)
        self.assertGreaterEqual(
            self.gh_log.read_text(encoding="utf8").count("/releases/1/assets"),
            4,
        )

    def test_publish_replaces_stale_draft_body_with_generated_notes(self) -> None:
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        (self.gh_state / "assets.tsv").write_text("", encoding="utf8")
        (self.gh_state / "release-body").write_text(
            "stale arbitrary notes\n", encoding="utf8"
        )

        result = self.run_publisher("--publish")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.gh_state / "release-body").read_text(encoding="utf8"),
            GENERATED_NOTES,
        )
        edit_commands = [
            line
            for line in self.gh_log.read_text(encoding="utf8").splitlines()
            if line.startswith("release edit ")
        ]
        self.assertEqual(len(edit_commands), 1)
        self.assertIn("--draft", edit_commands[0].split())
        self.assertNotIn("--draft=false", edit_commands[0].split())
        self.assertIn(
            "draft=false",
            next(
                line
                for line in self.gh_log.read_text(encoding="utf8").splitlines()
                if "/releases/1 --method PATCH" in line
            ),
        )

    def test_publish_replaces_stale_draft_body_with_explicit_notes(self) -> None:
        notes = self.root / "release-notes.md"
        notes.write_text("Curated notes\n\nNo trailing newline", encoding="utf8")
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        (self.gh_state / "assets.tsv").write_text("", encoding="utf8")
        (self.gh_state / "release-body").write_text("stale\n", encoding="utf8")

        result = self.run_publisher("--publish", "--notes-file", str(notes))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.gh_state / "release-body").read_text(encoding="utf8"),
            notes.read_text(encoding="utf8"),
        )
        self.assertNotIn(
            "releases/generate-notes",
            self.gh_log.read_text(encoding="utf8"),
        )

    def test_publish_uses_snapshot_when_explicit_notes_change_during_validation(self) -> None:
        notes = self.root / "release-notes.md"
        approved_notes = "Approved notes\n\nExact coordinator contents"
        notes.write_text(approved_notes, encoding="utf8")

        result = self.run_publisher(
            "--publish",
            "--notes-file",
            str(notes),
            mutate_notes_file=notes,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(notes.read_text(encoding="utf8"), "mutated after snapshot\n")
        self.assertEqual(
            (self.gh_state / "release-body").read_text(encoding="utf8"),
            approved_notes,
        )

    def test_publish_fails_closed_when_draft_body_cannot_be_corrected(self) -> None:
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        (self.gh_state / "assets.tsv").write_text("", encoding="utf8")
        (self.gh_state / "release-body").write_text("stale\n", encoding="utf8")

        result = self.run_publisher("--publish", ignore_notes_edit=True)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("body does not match expected notes", result.stderr)
        self.assertEqual(
            (self.gh_state / "release-state").read_text(encoding="utf8").strip(),
            "draft",
        )
        gh_log = self.gh_log.read_text(encoding="utf8")
        self.assertNotIn("--draft=false", gh_log)

    def test_publish_uploads_exact_validated_set_then_publishes(self) -> None:
        result = self.run_publisher("--publish", "--prerelease")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Draft release assets exactly match", result.stdout)
        self.assertIn("Published immutable release", result.stdout)
        self.assertEqual(
            (self.gh_state / "release-state").read_text(encoding="utf8").strip(),
            "published",
        )
        uploaded = {
            line.split("\t", 1)[0]
            for line in (self.gh_state / "assets.tsv")
            .read_text(encoding="utf8")
            .splitlines()
        }
        self.assertEqual(uploaded, {path.name for path in self.artifacts.iterdir()})
        gh_log = self.gh_log.read_text(encoding="utf8")
        self.assertEqual(gh_log.count("release create"), 1)
        self.assertEqual(gh_log.count("release upload"), len(uploaded))
        self.assertIn("release edit", gh_log)
        self.assertIn("--method PATCH -F draft=false -f make_latest=false", gh_log)
        log_lines = gh_log.splitlines()
        final_view = max(
            i
            for i, line in enumerate(log_lines)
            if "/releases?per_page=100" in line
        )
        final_assets = max(i for i, line in enumerate(log_lines) if "/releases/1/assets" in line)
        self.assertGreater(final_assets, final_view)

    def test_publish_polls_final_asset_digests(self) -> None:
        result = self.run_publisher("--publish", published_asset_lag=2)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Published immutable release", result.stdout)
        self.assertEqual(
            (self.gh_state / "published-asset-view-count").read_text(encoding="utf8"),
            "3",
        )

    def test_publish_fails_after_bounded_final_asset_poll(self) -> None:
        result = self.run_publisher("--publish", published_asset_lag=5)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest_mismatch", result.stderr)
        self.assertIn("Published immutable release assets do not exactly match", result.stderr)
        self.assertEqual(
            (self.gh_state / "published-asset-view-count").read_text(encoding="utf8"),
            "5",
        )

    def test_publish_polls_until_release_becomes_immutable(self) -> None:
        result = self.run_publisher(
            "--publish", immutable_sequence=("false", "null", "true")
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Published immutable release", result.stdout)
        self.assertEqual(
            (self.gh_state / "immutable-view-count").read_text(encoding="utf8"), "3"
        )

    def test_publish_maps_make_latest_auto_to_github_legacy_mode(self) -> None:
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        (self.gh_state / "assets.tsv").write_text("", encoding="utf8")
        (self.gh_state / "latest-state").write_text("true", encoding="utf8")

        result = self.run_publisher("--publish", "--make-latest", "auto")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.gh_state / "latest-mode").read_text(encoding="utf8"), "legacy"
        )
        publish_call = next(
            line
            for line in self.gh_log.read_text(encoding="utf8").splitlines()
            if "/releases/1 --method PATCH" in line and "draft=false" in line
        )
        self.assertIn("make_latest=legacy", publish_call)

    def test_tag_move_before_publication_leaves_release_as_draft(self) -> None:
        moved_tag_object = "f" * 40

        result = self.run_publisher(
            "--publish",
            tag_object_sequence=(self.tag_object, moved_tag_object),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("during pre-publication verification", result.stderr)
        self.assertEqual(
            (self.gh_state / "release-state").read_text(encoding="utf8").strip(),
            "draft",
        )
        self.assertNotIn("draft=false", self.gh_log.read_text(encoding="utf8"))

    def test_tag_target_change_before_publication_leaves_release_as_draft(self) -> None:
        moved_tag_target = "e" * 40

        result = self.run_publisher(
            "--publish",
            tag_target_sequence=(self.tag_target, moved_tag_target),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match pinned tag target", result.stderr)
        self.assertIn("during pre-publication verification", result.stderr)
        self.assertEqual(
            (self.gh_state / "release-state").read_text(encoding="utf8").strip(),
            "draft",
        )

    def test_tag_signature_change_before_publication_leaves_release_as_draft(self) -> None:
        result = self.run_publisher(
            "--publish",
            verified_sequence=(True, False),
            verification_reason_sequence=("valid", "invalid"),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact valid status", result.stderr)
        self.assertIn("during pre-publication verification", result.stderr)
        self.assertEqual(
            (self.gh_state / "release-state").read_text(encoding="utf8").strip(),
            "draft",
        )

    def test_tag_move_during_immutable_polling_fails_after_publication(self) -> None:
        moved_tag_object = "d" * 40

        result = self.run_publisher(
            "--publish",
            immutable_sequence=("false", "true"),
            tag_object_during_immutable_poll=moved_tag_object,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("during post-publication verification", result.stderr)
        self.assertIn("may already be immutable", result.stderr)
        self.assertIn("Stop distribution", result.stderr)
        self.assertEqual(
            (self.gh_state / "release-state").read_text(encoding="utf8").strip(),
            "published",
        )
        log_lines = self.gh_log.read_text(encoding="utf8").splitlines()
        publish_index = next(
            index
            for index, line in enumerate(log_lines)
            if "/releases/1 --method PATCH" in line and "draft=false" in line
        )
        final_tag_index = max(
            index
            for index, line in enumerate(log_lines)
            if "/git/ref/tags/" in line
        )
        self.assertGreater(final_tag_index, publish_index)

    def test_publish_fails_when_release_remains_mutable(self) -> None:
        result = self.run_publisher("--publish", immutable_sequence=("false",))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not confirm it as immutable", result.stderr)
        self.assertEqual(
            (self.gh_state / "immutable-view-count").read_text(encoding="utf8"), "5"
        )


if __name__ == "__main__":
    unittest.main()
