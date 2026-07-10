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
        self.trusted = self._build_trusted_checkout()
        self.guix_sigs = self._build_guix_sigs_checkout()
        self.artifacts = self._build_artifacts()
        self.posture = self.root / "testnet-posture.env"
        self.posture.write_text("testnet_release_posture=validated\n", encoding="utf8")
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
import os
import sys
from pathlib import Path

args = sys.argv[1:]
state = Path(os.environ["FAKE_GH_STATE"])
log = Path(os.environ["FAKE_GH_LOG"])
with log.open("a", encoding="utf8") as output:
    output.write(" ".join(args) + "\n")

if args[:2] == ["auth", "status"]:
    raise SystemExit(0)

if args and args[0] == "api":
    endpoint = args[1]
    if "/git/ref/tags/" in endpoint:
        print("tag " + os.environ["FAKE_GH_TAG_OBJECT"])
    elif "/git/tags/" in endpoint:
        print(
            "\t".join(
                [
                    os.environ["FAKE_GH_TAG_TARGET"],
                    "commit",
                    os.environ.get("FAKE_GH_VERIFIED", "true"),
                    "valid",
                    "2026-01-01T00:00:00Z",
                ]
            )
        )
    elif "/compare/" in endpoint:
        print("behind")
    elif "/commits/" in endpoint:
        print(endpoint.rsplit("/", 1)[1])
    elif "/releases/1/assets" in endpoint:
        assets = state / "assets.tsv"
        if assets.exists():
            print(assets.read_text(encoding="utf8"), end="")
    else:
        print("unsupported fake gh api endpoint: " + endpoint, file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(0)

if args[:2] == ["release", "view"]:
    release_state = state / "release-state"
    if not release_state.exists():
        raise SystemExit(1)
    draft = release_state.read_text(encoding="utf8").strip() == "draft"
    immutable = not draft
    print(
        "\t".join(
            [
                "1",
                str(draft).lower(),
                str(immutable).lower(),
                os.environ["FAKE_GH_TAG"],
                "https://example.invalid/release/" + os.environ["FAKE_GH_TAG"],
            ]
        )
    )
    raise SystemExit(0)

if args[:2] == ["release", "create"]:
    (state / "release-state").write_text("draft\n", encoding="utf8")
    (state / "assets.tsv").write_text("", encoding="utf8")
    raise SystemExit(0)

if args[:2] == ["release", "upload"]:
    path = Path(args[3])
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with (state / "assets.tsv").open("a", encoding="utf8") as output:
        output.write(f"{path.name}\tsha256:{digest}\n")
    raise SystemExit(0)

if args[:2] == ["release", "edit"]:
    if "--draft=false" in args:
        (state / "release-state").write_text("published\n", encoding="utf8")
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
        self, *extra_args: str, verified: bool = True, trusted_ref: str | None = None
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
                "FAKE_VALIDATOR_LOG": str(self.validator_log),
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
            "testnet",
            "--testnet-posture-evidence",
            str(self.posture),
            *extra_args,
        ]
        return subprocess.run(args, check=False, capture_output=True, text=True, env=env)

    def test_validation_only_uses_pr84_source_binding_inputs(self) -> None:
        result = self.run_publisher()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Validation-only mode", result.stdout)
        self.assertIn("gh release create", result.stdout)
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

    def test_publish_uploads_exact_validated_set_then_publishes(self) -> None:
        result = self.run_publisher("--publish", "--prerelease")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Draft release assets exactly match", result.stdout)
        self.assertIn("Published release", result.stdout)
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
        self.assertIn("--draft=false", gh_log)


if __name__ == "__main__":
    unittest.main()
