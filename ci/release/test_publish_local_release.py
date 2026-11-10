#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Behavioral tests for the local GitHub Release publisher."""

from __future__ import annotations

import hashlib
import json
import os
import re
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


def git(repo: Path, *args: str, input: str | None = None) -> str:
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
        input=input,
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
        # Local bare repositories stand in for GitHub's copies. The publisher
        # never fetches, so it reads only the checkouts; tests clone or commit
        # in the bare repositories to make history a checkout lacks.
        self.github = self.root / "github"
        for repository, checkout in (
            ("Qbit-Org/qbit", self.trusted),
            ("Qbit-Org/qbit-guix.sigs", self.guix_sigs),
        ):
            bare = self.github / f"{repository}.git"
            bare.parent.mkdir(parents=True, exist_ok=True)
            git(self.root, "init", "-q", "--bare", "--initial-branch=main", str(bare))
            git(checkout, "push", "-q", str(bare), "HEAD:refs/heads/main")

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
import urllib.parse
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
    elif "/rules/branches/" in endpoint:
        tips = json.loads(os.environ["FAKE_GH_BRANCH_TIPS"])
        path = urllib.parse.unquote(endpoint.split("#", 1)[0])
        key = path[len("repos/"):].replace("/rules/branches/", "/", 1)
        if key not in tips:
            raise SystemExit(f"fake gh: no branch {key}")
        rules = json.loads(os.environ.get("FAKE_GH_BRANCH_RULES", "{}"))
        for rule_type in rules.get(key, ["deletion", "non_fast_forward", "required_signatures"]):
            print(rule_type)
    elif "/branches/" in endpoint:
        tips = json.loads(os.environ["FAKE_GH_BRANCH_TIPS"])
        # Like gh, drop a URL fragment and decode the path.
        path = urllib.parse.unquote(endpoint.split("#", 1)[0])
        key = path[len("repos/"):].replace("/branches/", "/", 1)
        if key not in tips:
            raise SystemExit(f"fake gh: no branch {key}")
        unprotected = json.loads(os.environ.get("FAKE_GH_UNPROTECTED_BRANCHES", "[]"))
        print(tips[key] + "\t" + ("false" if key in unprotected else "true"))
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
        list_result = sequence_value(
            "FAKE_GH_ASSET_LIST_SEQUENCE", "ok", next_counter("asset-list-count")
        )
        with log.open("a", encoding="utf8") as output:
            output.write("# asset-list-result " + list_result + "\n")
        if list_result == "partial":
            # gh --paginate emits the pages it fetched before a later page fails.
            asset_lines = (
                assets.read_text(encoding="utf8").splitlines()
                if assets.exists()
                else []
            )
            for line in asset_lines[:1]:
                print(line)
            print("simulated asset list failure: HTTP 502 on page 2", file=sys.stderr)
            raise SystemExit(1)
        if list_result == "fail":
            print("simulated asset list failure: HTTP 502", file=sys.stderr)
            raise SystemExit(1)
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
        git(root, "init", "-q", "-b", "main")
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
import subprocess
import sys
from pathlib import Path


class ReleaseValidationError(Exception):
    pass


def load_release_policy(policy_path, keys_dir, release_line):
    return {"release_line": release_line}


def import_release_keys(gpg, gnupg_home, keys_dir, policy):
    pass


def verify_tag_signature(gpg, gnupg_home, tag, policy):
    # Like the real one: git verify-tag <tag> in the current directory. A tag
    # object listed in FAKE_UNSIGNED_TAG_OBJECTS counts as unsigned.
    resolved = subprocess.run(
        ["git", "rev-parse", "--verify", "-q", tag + "^{tag}"], capture_output=True, text=True
    ).stdout.strip()
    with open(os.environ["FAKE_VALIDATOR_LOG"], "a", encoding="utf8") as log:
        log.write(f"verify-tag {tag} object={resolved}\n")
    if not resolved or resolved in os.environ.get("FAKE_UNSIGNED_TAG_OBJECTS", "").split(","):
        raise ReleaseValidationError(f"Release tag {tag} was not signed by an active qbit release key")


def main():
    args = sys.argv[1:]

    def option(name):
        return args[args.index(name) + 1]

    artifacts = Path(option("--artifacts-dir"))
    output_path = Path(option("--github-output"))
    notes_to_mutate = os.environ.get("FAKE_MUTATE_NOTES_FILE")
    if notes_to_mutate:
        Path(notes_to_mutate).write_text("mutated after snapshot\n", encoding="utf8")
    if "--verify-tag-signature" in args:
        try:
            verify_tag_signature(None, None, option("--tag"), None)
        except ReleaseValidationError as exc:
            raise SystemExit(f"ERR: {exc}")
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
        log.write(
            f"release-python ignore_environment={sys.flags.ignore_environment} "
            f"no_user_site={sys.flags.no_user_site} no_site={sys.flags.no_site} "
            f"dont_write_bytecode={sys.flags.dont_write_bytecode} script={__file__}\n"
        )


if __name__ == "__main__":
    main()
""",
        )
        self._write_executable(
            validator_dir / "validate_builder_attestations.py",
            r"""#!/usr/bin/env python3
import hashlib
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
    guix_keys = Path(option("--guix-operator-key-policy")).read_bytes()
    log.write("builder-guix-keys " + hashlib.sha256(guix_keys).hexdigest() + "\n")
    guix_sigs = Path(option("--guix-sigs-repo"))
    files = sorted(str(path.relative_to(guix_sigs)) for path in guix_sigs.rglob("*") if path.is_file())
    log.write("builder-guix-files " + " ".join(files) + "\n")
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
        git(root, "init", "-q", "-b", "main")
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
        asset_list_sequence: tuple[str, ...] = ("ok",),
        branch_tips: dict[str, str] | None = None,
        unprotected_branches: tuple[str, ...] = (),
        branch_rules: dict[str, list[str]] | None = None,
        cwd: Path | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PATH"] = f"{self.bin_dir}{os.pathsep}{env['PATH']}"
        tips = {
            "Qbit-Org/qbit/main": self.trusted_ref,
            "Qbit-Org/qbit-guix.sigs/main": self.guix_sigs_ref,
        }
        tips.update(branch_tips or {})
        env.update(
            {
                "FAKE_GH_BRANCH_TIPS": json.dumps(tips),
                "FAKE_GH_UNPROTECTED_BRANCHES": json.dumps(list(unprotected_branches)),
                "FAKE_GH_BRANCH_RULES": json.dumps(branch_rules or {}),
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
                "FAKE_GH_ASSET_LIST_SEQUENCE": ",".join(asset_list_sequence),
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
        env.update(extra_env or {})
        return subprocess.run(args, check=False, capture_output=True, text=True, env=env, cwd=cwd)

    def assert_no_write_after_failed_asset_list(self) -> None:
        """Fail if gh changed the release before a failed listing was superseded."""
        listing_failed = False
        for line in self.gh_log.read_text(encoding="utf8").splitlines():
            if line.startswith("# asset-list-result "):
                listing_failed = line.split()[-1] != "ok"
                continue
            is_write = line.startswith(
                ("release create", "release upload", "release edit")
            ) or "--method PATCH" in line
            self.assertFalse(
                listing_failed and is_write,
                f"release write after a failed asset listing: {line}",
            )

    def asset_list_calls(self) -> int:
        return self.gh_log.read_text(encoding="utf8").count("# asset-list-result ")

    def write_remote_assets(self, *entries: tuple[Path, str | None]) -> None:
        lines = []
        for path, digest in entries:
            if digest is None:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{path.name}\tsha256:{digest}\n")
        (self.gh_state / "assets.tsv").write_text("".join(lines), encoding="utf8")

    def release_artifact(self) -> Path:
        return next(
            path for path in self.artifacts.iterdir() if path.name.startswith("qbit-")
        )

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

    def test_validators_and_policy_come_from_the_trusted_commit(self) -> None:
        result = self.run_publisher()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        validator_log = self.validator_log.read_text(encoding="utf8")
        self.assertIn(
            "release-python ignore_environment=1 no_user_site=1 no_site=1 dont_write_bytecode=1", validator_log
        )
        self.assertIn("/trusted-ref/ci/release/validate_release_artifacts.py", validator_log)
        self.assertIn("/trusted-ref/contrib/keys/operator-keys/keys.json", validator_log)
        self.assertNotIn(f"{self.trusted.resolve()}/contrib/keys", validator_log)

    def test_modules_in_the_callers_directory_never_load(self) -> None:
        marker = self.root / "shadowed.log"
        caller = self.root / "caller"
        caller.mkdir()
        for module in ("hashlib", "json"):
            (caller / f"{module}.py").write_text(
                f"open({str(marker)!r}, 'a', encoding='utf8').write('{module}\\n')\n", encoding="utf8"
            )

        result = self.run_publisher(cwd=caller)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists(), marker.read_text(encoding="utf8") if marker.exists() else "")

    def test_replace_ref_does_not_change_what_is_read(self) -> None:
        trusted_head = self.trusted_ref
        validator = "ci/release/validate_release_artifacts.py"
        git(self.trusted, "checkout", "-q", "-b", "replacement")
        with (self.trusted / validator).open("a", encoding="utf8") as source:
            source.write('open(os.environ["FAKE_VALIDATOR_LOG"], "a", encoding="utf8").write("REPLACED\\n")\n')
        git(self.trusted, "commit", "-q", "-am", "replacement")
        replacement = git(self.trusted, "rev-parse", "HEAD")
        git(self.trusted, "checkout", "-q", "-")
        git(self.trusted, "replace", trusted_head, replacement)
        # With replace refs honoured, the checkout now holds the replacement
        # while HEAD still names the trusted commit.
        git(self.trusted, "reset", "-q", "--hard", trusted_head)
        self.assertEqual(git(self.trusted, "rev-parse", "HEAD"), trusted_head)

        result = self.run_publisher()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Trusted release checkout must be clean", result.stderr)
        self.assertFalse(self.validator_log.exists())

        # The replace ref stays, but the checkout holds the real commit again:
        # the publisher reads the trusted commit, not the replacement.
        git(self.trusted, "--no-replace-objects", "reset", "-q", "--hard", trusted_head)
        result = self.run_publisher()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("REPLACED", self.validator_log.read_text(encoding="utf8"))

    def test_repository_config_and_hooks_never_run_programs(self) -> None:
        markers = self.root / "programs-run.log"

        def program(name: str, body: str) -> Path:
            path = self.root / "planted" / name
            path.parent.mkdir(exist_ok=True)
            self._write_executable(path, f"#!/bin/sh\necho {name} >> '{markers}'\n{body}\n")
            return path

        for label, checkout in (("trusted", self.trusted), ("guix-sigs", self.guix_sigs)):
            git(checkout, "config", "core.fsmonitor", str(program(f"{label}-fsmonitor", "exit 1")))
            git(checkout, "config", "filter.planted.clean", str(program(f"{label}-clean-filter", "exec cat")))
            git(checkout, "config", "filter.planted.smudge", str(program(f"{label}-smudge-filter", "exec cat")))
            git(checkout, "config", "filter.planted.required", "true")
            (checkout / ".git" / "info").mkdir(exist_ok=True)
            # A driver with an empty name, which "filter=" selects, and one
            # whose name is not UTF-8.
            with (checkout / ".git" / "config").open("ab") as config:
                config.write(b'[filter ""]\n\tclean = ' + str(program(f"{label}-empty-name-filter", "exec cat")).encode())
                config.write(b'\n[filter "pl\xe4nted"]\n\tclean = ' + str(program(f"{label}-latin-filter", "exec cat")).encode())
                config.write(b"\n")
            (checkout / ".git" / "info" / "attributes").write_bytes(
                b"* filter=planted\nREADME.md filter=\noperator-keys/keys.json filter=pl\xe4nted\n"
            )
            (checkout / ".git" / "hooks").mkdir(exist_ok=True)
            program(f"{label}-post-index-change", "exit 0").rename(checkout / ".git" / "hooks" / "post-index-change")
            self.assertEqual(git(checkout, "-c", "core.fsmonitor=false", "status", "--porcelain"), "")
            # After that status refreshed the index: stat-dirty files make git
            # status run the clean filter and want to write the index (the hook).
            for path in checkout.rglob("*"):
                if ".git" not in path.relative_to(checkout).parts and path.is_file():
                    os.utime(path, (1, 1))
        markers.unlink(missing_ok=True)

        result = self.run_publisher()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(markers.exists(), markers.read_text(encoding="utf8") if markers.exists() else "")
        # The empty graft file disables grafts without git's deprecation hint.
        self.assertNotIn("grafts", result.stderr)

    def test_tag_signature_is_checked_on_the_refs_tags_object(self) -> None:
        # The repro: refs/tags/<tag> holds an unsigned tag, while the signed tag
        # object stays reachable under the bare name through refs/<tag> or
        # .git/<tag>, which git resolves first and git status does not show.
        # The publisher refuses the ambiguous name, and checks the signature of
        # the refs/tags object only.
        unsigned = self.tag_object
        git(self.trusted, "tag", "-f", "-a", "v0.0.0-signed", "-m", "signed", self.tag_target)
        signed = git(self.trusted, "rev-parse", "refs/tags/v0.0.0-signed")
        git(self.trusted, "update-ref", "-d", "refs/tags/v0.0.0-signed")
        strays = {
            f"refs/{TAG}": lambda: git(self.trusted, "update-ref", f"refs/{TAG}", signed),
            f".git/{TAG}": lambda: (self.trusted / ".git" / TAG).write_text(signed + "\n", encoding="utf8"),
        }
        for stray, plant in strays.items():
            with self.subTest(stray=stray):
                plant()
                try:
                    self.assertEqual(git(self.trusted, "rev-parse", "--verify", "-q", f"{TAG}^{{tag}}"), signed)
                    self.assertEqual(git(self.trusted, "status", "--porcelain"), "")
                    self.validator_log.unlink(missing_ok=True)
                    result = self.run_publisher(extra_env={"FAKE_UNSIGNED_TAG_OBJECTS": unsigned})
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(f"The name {TAG} resolves to {signed}, not to refs/tags/{TAG} ({unsigned})",
                                  result.stderr)
                    self.assertFalse(self.validator_log.exists())
                finally:
                    if stray.startswith("refs/"):
                        git(self.trusted, "update-ref", "-d", stray)
                    else:
                        (self.trusted / stray).unlink()

        # The signature check gets the refs/tags object by id.
        result = self.run_publisher(extra_env={"FAKE_UNSIGNED_TAG_OBJECTS": unsigned})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"Release tag {TAG} ({unsigned}) was not signed by an active qbit release key", result.stderr)
        self.assertIn(f"verify-tag {unsigned} object={unsigned}\n", self.validator_log.read_text(encoding="utf8"))
        self.validator_log.unlink()
        result = self.run_publisher()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"verify-tag {unsigned} object={unsigned}\n", self.validator_log.read_text(encoding="utf8"))

    def test_release_tag_is_read_from_refs_tags_only(self) -> None:
        # A signed tag object of another release moved to refs/tags/<tag>.
        git(self.trusted, "tag", "-a", "v0.0.0-other", "-m", "other", self.tag_target)
        other = git(self.trusted, "rev-parse", "refs/tags/v0.0.0-other")
        git(self.trusted, "update-ref", f"refs/tags/{TAG}", other)
        result = self.run_publisher(tag_object_sequence=(other,))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"Release tag {TAG} is a tag object named v0.0.0-other ({other} at refs/tags/{TAG})",
                      result.stderr)
        self.assertFalse(self.validator_log.exists())

        # Control characters in the tag object's name are shown escaped.
        odd = git(self.trusted, "hash-object", "-t", "tag", "--literally", "-w", "--stdin", input=(
            f"object {self.tag_target}\ntype commit\ntag {TAG}\x1b[2K\n"
            "tagger qbit release test <release-test@example.invalid> 1700000000 +0000\n\nodd\n"
        ))
        git(self.trusted, "update-ref", f"refs/tags/{TAG}", odd)
        result = self.run_publisher(tag_object_sequence=(odd,))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"Release tag {TAG} is a tag object named $'{TAG}\\E[2K' ({odd}", result.stderr)
        self.assertNotIn("\x1b", result.stderr)

        # A lightweight tag is not an annotated release tag.
        git(self.trusted, "update-ref", f"refs/tags/{TAG}", self.tag_target)
        result = self.run_publisher()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"Trusted release checkout is missing annotated tag {TAG}", result.stderr)
        self.assertFalse(self.validator_log.exists())

        # With refs/tags/<tag> gone, git would resolve refs/tags/<tag> as
        # refs/refs/tags/<tag>; the publisher reads only the exact ref.
        git(self.trusted, "update-ref", "-d", f"refs/tags/{TAG}")
        git(self.trusted, "update-ref", f"refs/refs/tags/{TAG}", self.tag_object)
        self.assertEqual(git(self.trusted, "rev-parse", "--verify", "-q", f"refs/tags/{TAG}^{{tag}}"), self.tag_object)
        result = self.run_publisher()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"Trusted release checkout is missing annotated tag {TAG}", result.stderr)
        self.assertFalse(self.validator_log.exists())

    def test_partial_clones_fail_closed(self) -> None:
        for label, checkout in (("Trusted release checkout", self.trusted), ("qbit-guix.sigs checkout", self.guix_sigs)):
            with self.subTest(checkout=label):
                git(checkout, "config", "core.repositoryformatversion", "1")
                git(checkout, "config", "extensions.partialClone", "origin")
                result = self.run_publisher()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"{label} must not be a partial clone (extensions.partialclone)", result.stderr)
                self.assertFalse(self.validator_log.exists())
                # The value is a remote name, so even "false" counts.
                git(checkout, "config", "extensions.partialClone", "false")
                result = self.run_publisher()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"{label} must not be a partial clone (extensions.partialclone)", result.stderr)
                git(checkout, "config", "--unset", "extensions.partialClone")
                # A promisor remote alone is enough for git to fetch.
                git(checkout, "config", "remote.origin.promisor", "true")
                result = self.run_publisher()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"{label} must not be a partial clone (remote.origin.promisor)", result.stderr)
                self.assertFalse(self.validator_log.exists())
                git(checkout, "config", "--unset", "remote.origin.promisor")

    def test_guix_sigs_files_come_from_the_pinned_commit(self) -> None:
        keys = self.guix_sigs / "operator-keys" / "keys.json"
        committed = keys.read_bytes()
        # Same size and mtime, other bytes: with core.checkStat=minimal git
        # status trusts the index's stat data and reports a clean checkout.
        # (An old mtime keeps the entry from being racily clean.)
        os.utime(keys, (1, 1))
        git(self.guix_sigs, "update-index", "--refresh")
        git(self.guix_sigs, "config", "core.checkStat", "minimal")
        keys.write_bytes(committed.replace(b"2", b"3"))
        os.utime(keys, (1, 1))
        self.assertNotEqual(keys.read_bytes(), committed)
        self.assertEqual(git(self.guix_sigs, "status", "--porcelain"), "")

        result = self.run_publisher()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        log = self.validator_log.read_text(encoding="utf8")
        self.assertIn("builder-guix-keys " + hashlib.sha256(committed).hexdigest(), log)
        self.assertNotIn(f"--guix-sigs-repo {self.guix_sigs.resolve()} ", log)

    def test_guix_sigs_checkout_hides_nothing_that_is_validated(self) -> None:
        manifest = self.guix_sigs / "operator-keys" / "keys.json"
        git(self.guix_sigs, "update-index", "--skip-worktree", "operator-keys/keys.json")
        manifest.write_text('{"schema_version": 3}\n', encoding="utf8")
        self.assertEqual(git(self.guix_sigs, "status", "--porcelain"), "")
        result = self.run_publisher()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qbit-guix.sigs checkout has index flags (assume-unchanged or skip-worktree) on: "
                      "operator-keys/keys.json", result.stderr)
        git(self.guix_sigs, "update-index", "--no-skip-worktree", "operator-keys/keys.json")
        git(self.guix_sigs, "checkout", "--", "operator-keys/keys.json")

        # An ignored file next to the attestations is not validated: the
        # validators get the pinned commit's files only.
        planted = self.guix_sigs / TAG.removeprefix("v") / "operator-01" / "all.SHA256SUMS"
        planted.parent.mkdir(parents=True)
        planted.write_text("planted\n", encoding="utf8")
        (self.guix_sigs / ".git" / "info").mkdir(exist_ok=True)
        (self.guix_sigs / ".git" / "info" / "exclude").write_text("all.SHA256SUMS\n", encoding="utf8")
        self.assertEqual(git(self.guix_sigs, "status", "--porcelain"), "")
        result = self.run_publisher()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("builder-guix-files operator-keys/keys.json\n", self.validator_log.read_text(encoding="utf8"))

    def test_submodule_checkouts_are_never_entered(self) -> None:
        markers = self.root / "programs-run.log"
        clean = self.root / "planted" / "sub-clean"
        clean.parent.mkdir()
        self._write_executable(clean, f"#!/bin/sh\necho sub-clean >> '{markers}'\nexec cat\n")
        sub = self.trusted / "sub"
        sub.mkdir()
        git(sub, "init", "-q")
        (sub / "file.txt").write_text("submodule\n", encoding="utf8")
        git(sub, "add", "file.txt")
        git(sub, "commit", "-q", "-m", "submodule")
        git(sub, "config", "filter.planted.clean", str(clean))
        (sub / ".git" / "info").mkdir(exist_ok=True)
        (sub / ".git" / "info" / "attributes").write_text("* filter=planted\n", encoding="utf8")
        os.utime(sub / "file.txt", (1, 1))
        git(self.trusted, "update-index", "--add", "--cacheinfo", f"160000,{git(sub, 'rev-parse', 'HEAD')},sub")
        markers.unlink(missing_ok=True)
        result = self.run_publisher()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Trusted release checkout must be clean", result.stderr)
        self.assertFalse(markers.exists(), "git status ran inside the submodule checkout")

    def test_git_older_than_2_31_is_refused(self) -> None:
        real_git = shutil.which("git")
        self._write_executable(
            self.bin_dir / "git",
            f'#!/usr/bin/env bash\n[ "$1" != version ] || {{ echo "git version 2.30.2"; exit 0; }}\nexec {real_git} "$@"\n',
        )
        result = self.run_publisher()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("git version 2.30.2 is too old: the publisher needs git 2.31 or newer", result.stderr)
        self.assertFalse(self.validator_log.exists())

    def test_shallow_trusted_checkout_fails_closed(self) -> None:
        first = git(self.trusted, "rev-list", "--max-parents=0", "HEAD")
        (self.trusted / ".git" / "shallow").write_text(first + "\n", encoding="utf8")

        result = self.run_publisher()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Trusted release checkout must not be shallow", result.stderr)
        self.assertFalse(self.validator_log.exists())

    def test_index_flags_on_trusted_paths_fail_closed(self) -> None:
        keys_json = "contrib/keys/operator-keys/keys.json"
        git(self.trusted, "update-index", "--skip-worktree", keys_json)
        (self.trusted / keys_json).write_text('{"schema_version": 3}\n', encoding="utf8")
        self.assertEqual(git(self.trusted, "status", "--porcelain"), "")

        result = self.run_publisher()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("index flags (assume-unchanged or skip-worktree) on: " + keys_json, result.stderr)
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

        bare = self.github / "Example-Org" / "release-target.git"
        bare.parent.mkdir(parents=True)
        git(self.root, "init", "-q", "--bare", "--initial-branch=main", str(bare))
        git(self.trusted, "push", "-q", str(bare), "HEAD:refs/heads/main")
        result = self.run_publisher(
            "--repo",
            "Example-Org/release-target",
            immutable_sequence=("false",),
            branch_tips={"Example-Org/release-target/main": self.trusted_ref},
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

    def test_resume_aborts_when_asset_list_persistently_fails(self) -> None:
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        self.write_remote_assets((self.release_artifact(), None))

        result = self.run_publisher("--publish", asset_list_sequence=("fail",))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("simulated asset list failure", result.stderr)
        self.assertIn("asset-list request for release", result.stderr)
        self.assertIn("during draft resume verification", result.stderr)
        self.assertNotIn("not a digest-matching subset", result.stderr)
        self.assertNotIn("Found matching draft release", result.stdout)
        self.assertEqual(self.asset_list_calls(), 5)
        gh_log = self.gh_log.read_text(encoding="utf8")
        self.assertNotIn("release upload", gh_log)
        self.assertNotIn("release edit", gh_log)
        self.assertNotIn("--method PATCH", gh_log)
        self.assert_no_write_after_failed_asset_list()

    def test_resume_retries_transient_asset_list_failure(self) -> None:
        artifact = self.release_artifact()
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        self.write_remote_assets((artifact, None))

        result = self.run_publisher(
            "--create-draft", asset_list_sequence=("fail", "fail", "ok")
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Found matching draft release", result.stdout)
        self.assertIn(f"Keeping verified draft asset {artifact.name}", result.stdout)
        uploads = [
            line.split()[3]
            for line in self.gh_log.read_text(encoding="utf8").splitlines()
            if line.startswith("release upload ")
        ]
        self.assertEqual(
            sorted(Path(upload).name for upload in uploads),
            sorted(
                path.name for path in self.artifacts.iterdir() if path != artifact
            ),
        )
        self.assert_no_write_after_failed_asset_list()

    def test_resume_does_not_compare_partial_paginated_asset_list(self) -> None:
        artifact = self.release_artifact()
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        # The first page matches; the unread second page holds a wrong digest.
        self.write_remote_assets(
            (artifact, None), (self.artifacts / "SHA256SUMS", "0" * 64)
        )

        result = self.run_publisher("--publish", asset_list_sequence=("partial",))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 502 on page 2", result.stderr)
        self.assertIn("asset-list request for release", result.stderr)
        self.assertNotIn("Found matching draft release", result.stdout)
        gh_log = self.gh_log.read_text(encoding="utf8")
        self.assertNotIn("release upload", gh_log)
        self.assertNotIn("release edit", gh_log)
        self.assert_no_write_after_failed_asset_list()

    def test_publish_final_verification_reports_persistent_asset_list_failure(self) -> None:
        result = self.run_publisher(
            "--publish", asset_list_sequence=("ok", "ok", "fail")
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("simulated asset list failure", result.stderr)
        self.assertIn("during post-publication verification", result.stderr)
        self.assertIn("already published", result.stderr)
        self.assertNotIn("do not exactly match", result.stderr)
        self.assertNotIn("Published immutable release assets exactly match", result.stdout)
        self.assertEqual(
            (self.gh_state / "release-state").read_text(encoding="utf8").strip(),
            "published",
        )
        self.assertEqual(self.asset_list_calls(), 7)
        self.assert_no_write_after_failed_asset_list()

    def test_validation_only_aborts_when_published_asset_list_fails(self) -> None:
        (self.gh_state / "release-state").write_text("published\n", encoding="utf8")
        self.write_remote_assets(
            *((path, None) for path in sorted(self.artifacts.iterdir()))
        )

        result = self.run_publisher(asset_list_sequence=("fail",))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("simulated asset list failure", result.stderr)
        self.assertIn("during published release validation", result.stderr)
        self.assertNotIn("do not exactly match", result.stderr)
        self.assertNotIn("Validation-only mode complete", result.stdout)
        self.assertEqual(self.asset_list_calls(), 1)

    def test_validation_only_aborts_when_draft_asset_list_fails(self) -> None:
        (self.gh_state / "release-state").write_text("draft\n", encoding="utf8")
        self.write_remote_assets((self.release_artifact(), None))

        result = self.run_publisher(asset_list_sequence=("fail",))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("during draft resume verification", result.stderr)
        self.assertNotIn("Found matching draft release", result.stdout)
        self.assertNotIn("gh release upload", result.stdout)
        self.assertNotIn("Validation-only mode", result.stdout)


    def _set_github_branch(self, repository: str, checkout: Path, branch: str, commit: str) -> None:
        bare = self.github / f"{repository}.git"
        git(checkout, "push", "-q", "--force", str(bare), f"{commit}:refs/heads/{branch}")

    def _merge_object(self, checkout: Path, first_parent: str | None, second_parent: str) -> str:
        """Create, without moving HEAD, a branch state that merges second_parent.

        The branch's own line starts from first_parent, or from a new root."""
        tree = f"{first_parent or second_parent}^{{tree}}"
        parents = ["-p", first_parent] if first_parent else []
        side = git(checkout, "commit-tree", tree, *parents, "-m", "side")
        return git(
            checkout, "commit-tree", f"{second_parent}^{{tree}}",
            "-p", side, "-p", second_parent, "-m", "Merge pull request #1",
        )

    def test_trusted_release_ref_on_branch_first_parent_history_passes(self) -> None:
        later = git(
            self.trusted, "commit-tree", f"{self.trusted_ref}^{{tree}}",
            "-p", self.trusted_ref, "-m", "main moved on",
        )
        self._set_github_branch("Qbit-Org/qbit", self.trusted, "main", later)
        result = self.run_publisher(branch_tips={"Qbit-Org/qbit/main": later})

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("repos/Qbit-Org/qbit/branches/main", self.gh_log.read_text(encoding="utf8"))

    def test_trusted_release_ref_merged_as_pull_request_head_fails(self) -> None:
        merge = self._merge_object(self.trusted, self.tag_target, self.trusted_ref)
        self._set_github_branch("Qbit-Org/qbit", self.trusted, "main", merge)
        result = self.run_publisher(branch_tips={"Qbit-Org/qbit/main": merge})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"Trusted release ref {self.trusted_ref} must be on the first-parent history of "
            "Qbit-Org/qbit:main",
            result.stderr,
        )

    def test_branch_tip_missing_from_the_checkout_fails_without_a_fetch(self) -> None:
        # A merge landed on GitHub after the operator's last fetch: the API
        # reports a tip that only GitHub has. The publisher stops and fetches
        # nothing.
        for repository, checkout, label in (
            ("Qbit-Org/qbit", self.trusted, "Trusted release"),
            ("Qbit-Org/qbit-guix.sigs", self.guix_sigs, "qbit-guix.sigs"),
        ):
            with self.subTest(repository=repository):
                bare = self.github / f"{repository}.git"
                later = git(
                    bare, "commit-tree", "refs/heads/main^{tree}",
                    "-p", "refs/heads/main", "-m", "merge that landed meanwhile",
                )
                git(bare, "update-ref", "refs/heads/main", later)
                result = self.run_publisher(branch_tips={f"{repository}/main": later})

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"{label} branch {repository}:main is at {later}, which {checkout} does not have",
                    result.stderr,
                )
                self.assertNotIn("first-parent history", result.stderr)
                missing = subprocess.run(
                    ["git", "-C", str(checkout), "cat-file", "-e", f"{later}^{{commit}}"],
                    check=False, capture_output=True,
                )
                self.assertNotEqual(missing.returncode, 0)

    def test_unprotected_trusted_release_branch_fails(self) -> None:
        self._set_github_branch("Qbit-Org/qbit", self.trusted, "topic", self.trusted_ref)
        result = self.run_publisher(
            "--trusted-release-branch", "topic",
            branch_tips={"Qbit-Org/qbit/topic": self.trusted_ref},
            unprotected_branches=("Qbit-Org/qbit/topic",),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Qbit-Org/qbit:topic is not a protected branch; protect it with a ruleset before releasing from it",
            result.stderr,
        )

    def test_unprotected_guix_sigs_branch_fails(self) -> None:
        result = self.run_publisher(unprotected_branches=("Qbit-Org/qbit-guix.sigs/main",))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Qbit-Org/qbit-guix.sigs:main is not a protected branch; protect it with a ruleset before releasing from it",
            result.stderr,
        )

    def test_guix_sigs_branch_without_rules_fails(self) -> None:
        # Live today: qbit-guix.sigs main is protected but has no rules.
        result = self.run_publisher(branch_rules={"Qbit-Org/qbit-guix.sigs/main": []})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Qbit-Org/qbit-guix.sigs:main can be force-pushed or deleted; its ruleset needs "
            "non_fast_forward and deletion rules before releasing from it",
            result.stderr,
        )

    def test_trusted_branch_needs_both_history_rules(self) -> None:
        for rules in (["deletion", "required_signatures"], ["non_fast_forward", "pull_request"]):
            with self.subTest(rules=rules):
                result = self.run_publisher(branch_rules={"Qbit-Org/qbit/main": rules})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Qbit-Org/qbit:main can be force-pushed or deleted", result.stderr)

    def test_branch_rules_are_read_with_the_encoded_branch_name(self) -> None:
        self._set_github_branch("Qbit-Org/qbit", self.trusted, "rel#1", self.trusted_ref)
        result = self.run_publisher(
            "--trusted-release-branch", "rel#1",
            branch_tips={"Qbit-Org/qbit/rel#1": self.trusted_ref},
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("repos/Qbit-Org/qbit/rules/branches/rel%231", self.gh_log.read_text(encoding="utf8"))

    def test_default_trusted_release_branch_is_printed_with_hint(self) -> None:
        hint = "==> Hint: a release-line release must pass --trusted-release-branch <line>"
        for tag in (TAG, "v1.2.3"):
            with self.subTest(tag=tag):
                result = self.run_publisher("--tag", tag)
                self.assertIn("==> Trusted release branch: Qbit-Org/qbit:main", result.stdout)
                self.assertIn(hint, result.stdout)

    def test_explicit_trusted_release_branch_prints_no_hint(self) -> None:
        result = self.run_publisher("--trusted-release-branch", "main")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("==> Trusted release branch: Qbit-Org/qbit:main", result.stdout)
        self.assertNotIn("Hint: a release-line release", result.stdout)

    def test_release_line_uses_its_own_trusted_branch(self) -> None:
        self._set_github_branch("Qbit-Org/qbit", self.trusted, "1.x.x", self.trusted_ref)
        result = self.run_publisher(
            "--trusted-release-branch", "1.x.x",
            branch_tips={"Qbit-Org/qbit/1.x.x": self.trusted_ref},
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("repos/Qbit-Org/qbit/branches/1.x.x", self.gh_log.read_text(encoding="utf8"))

    def test_invalid_trusted_release_branch_fails(self) -> None:
        result = self.run_publisher("--trusted-release-branch", "bad..branch")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--trusted-release-branch is not a valid branch name", result.stderr)

    def test_branch_names_are_checked_as_full_refs(self) -> None:
        # Run where @{-1} names a real branch: check-ref-format --branch would
        # expand it and accept it.
        git(self.trusted, "checkout", "-q", "-b", "previous")
        git(self.trusted, "checkout", "-q", "main")
        for option in ("--trusted-release-branch", "--guix-sigs-branch"):
            for name in ("@{-1}", "a..b", "-x", "HEAD"):
                with self.subTest(option=option, name=name):
                    result = self.run_publisher(option, name, cwd=self.trusted)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"{option} is not a valid branch name: {name}", result.stderr)

    def test_branch_name_is_percent_encoded_in_the_api_path(self) -> None:
        # A valid branch name can contain '#'. Unencoded, it would start a URL
        # fragment and the publisher would read main instead.
        result = self.run_publisher("--trusted-release-branch", "main#x")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("repos/Qbit-Org/qbit/branches/main%23x", self.gh_log.read_text(encoding="utf8"))
        self.assertIn("Could not read Trusted release branch Qbit-Org/qbit:main#x", result.stderr)

    def test_shallow_trusted_checkout_fails(self) -> None:
        # The publisher's own checkout, cloned shallow at the branch tip: the
        # walk from the tip would miss the trusted release ref.
        later = git(
            self.trusted, "commit-tree", f"{self.trusted_ref}^{{tree}}",
            "-p", self.trusted_ref, "-m", "main moved on",
        )
        self._set_github_branch("Qbit-Org/qbit", self.trusted, "main", later)
        bare = self.github / "Qbit-Org/qbit.git"
        git(self.trusted, "push", "-q", str(bare), f"refs/tags/{TAG}")
        shallow = self.root / "qbit-shallow"
        git(
            self.root, "clone", "-q", "--depth", "1", "--branch", "main",
            f"file://{bare}", str(shallow),
        )
        git(shallow, "fetch", "-q", "origin", self.trusted_ref, f"refs/tags/{TAG}:refs/tags/{TAG}")
        git(shallow, "checkout", "-q", "--detach", self.trusted_ref)
        self.assertEqual(git(shallow, "rev-parse", "--is-shallow-repository"), "true")
        self.trusted = shallow
        result = self.run_publisher(branch_tips={"Qbit-Org/qbit/main": later})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Trusted release checkout must not be shallow", result.stderr)
        self.assertNotIn("must be on the first-parent history", result.stderr)

    def test_guix_sigs_ref_on_branch_first_parent_history_passes(self) -> None:
        later = git(
            self.guix_sigs, "commit-tree", f"{self.guix_sigs_ref}^{{tree}}",
            "-p", self.guix_sigs_ref, "-m", "more attestations",
        )
        self._set_github_branch("Qbit-Org/qbit-guix.sigs", self.guix_sigs, "main", later)
        result = self.run_publisher(branch_tips={"Qbit-Org/qbit-guix.sigs/main": later})

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "repos/Qbit-Org/qbit-guix.sigs/branches/main", self.gh_log.read_text(encoding="utf8")
        )

    def test_shallow_guix_sigs_checkout_fails(self) -> None:
        # In a shallow clone of the branch tip, the walk from the tip stops at
        # the shallow boundary and misses a merged commit fetched afterwards.
        later = git(
            self.guix_sigs, "commit-tree", f"{self.guix_sigs_ref}^{{tree}}",
            "-p", self.guix_sigs_ref, "-m", "more attestations",
        )
        self._set_github_branch("Qbit-Org/qbit-guix.sigs", self.guix_sigs, "main", later)
        shallow = self.root / "qbit-guix.sigs-shallow"
        git(
            self.root, "clone", "-q", "--depth", "1", "--branch", "main",
            f"file://{self.github}/Qbit-Org/qbit-guix.sigs.git", str(shallow),
        )
        git(shallow, "fetch", "-q", "origin", self.guix_sigs_ref)
        git(shallow, "checkout", "-q", "--detach", self.guix_sigs_ref)
        self.assertEqual(git(shallow, "rev-parse", "--is-shallow-repository"), "true")
        self.guix_sigs = shallow
        result = self.run_publisher(branch_tips={"Qbit-Org/qbit-guix.sigs/main": later})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "The qbit-guix.sigs checkout is shallow; run git fetch --unshallow", result.stderr
        )
        self.assertNotIn("must be on the first-parent history", result.stderr)

    def test_guix_sigs_ref_merged_as_pull_request_head_fails(self) -> None:
        merge = self._merge_object(self.guix_sigs, None, self.guix_sigs_ref)
        self._set_github_branch("Qbit-Org/qbit-guix.sigs", self.guix_sigs, "main", merge)
        result = self.run_publisher(branch_tips={"Qbit-Org/qbit-guix.sigs/main": merge})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"qbit-guix.sigs commit {self.guix_sigs_ref} must be on the first-parent history of "
            "Qbit-Org/qbit-guix.sigs:main",
            result.stderr,
        )
        self.assertIn(
            "pin the merge commit that landed the attestations, not the pull request head", result.stderr
        )


def extract_shell_function(source: str, name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", source, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f"{name} is not defined in {PUBLISHER}")
    return match.group(0)


class FirstParentHistoryTest(unittest.TestCase):
    """Run the publisher's first-parent history check on a merge-commit history."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp_dir.name) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        self.commits: dict[str, str] = {}
        self._commit("m1", "base.txt")
        self._commit("m2", "base.txt")
        # A multi-commit pull request merged with the merge button.
        self._branch_and_merge("multi", ["multi-1", "multi-2"], "merge-multi")
        # A release pull request opened on a stale base: main gets S while it
        # is open, so the merge has X+S+R but the pull request head has X+R.
        git(self.repo, "checkout", "-q", "-b", "release")
        self._commit("release", "release.txt")
        git(self.repo, "checkout", "-q", "main")
        self._commit("main-while-release-open", "base.txt")
        self._merge("release", "merge-release")
        # A long-lived side line merged in.
        self._branch_and_merge("line", ["line-1", "line-2", "line-3"], "merge-line")
        self._commit("m3", "base.txt")
        self.trusted_ref = self.commits["m3"]
        source = PUBLISHER.read_text(encoding="utf8")
        self.script = "\n".join(
            [
                "set -euo pipefail",
                extract_shell_function(source, "lowercase"),
                extract_shell_function(source, "on_first_parent_history"),
                'on_first_parent_history "$1" "$2" "$3"',
            ]
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _commit(self, label: str, path: str = "file") -> None:
        (self.repo / path).write_text(f"{label}\n", encoding="utf8")
        git(self.repo, "add", path)
        git(self.repo, "commit", "-q", "-m", label)
        self.commits[label] = git(self.repo, "rev-parse", "HEAD")

    def _merge(self, branch: str, merge_label: str) -> None:
        git(self.repo, "merge", "-q", "--no-ff", "-m", merge_label, branch)
        self.commits[merge_label] = git(self.repo, "rev-parse", "HEAD")

    def _branch_and_merge(self, branch: str, labels: list[str], merge_label: str) -> None:
        git(self.repo, "checkout", "-q", "-b", branch)
        for label in labels:
            self._commit(label, f"{branch}.txt")
        git(self.repo, "checkout", "-q", "main")
        self._merge(branch, merge_label)

    def check(self, commit: str, history_ref: str | None = None) -> int:
        result = subprocess.run(
            [
                "bash",
                "-c",
                self.script,
                "first-parent-check",
                str(self.repo),
                history_ref or self.trusted_ref,
                commit,
            ],
            capture_output=True,
            text=True,
        )
        return result.returncode

    def test_first_parent_commits_pass(self) -> None:
        for label in ("m1", "m2", "main-while-release-open", "m3"):
            with self.subTest(label=label):
                self.assertEqual(self.check(self.commits[label]), 0)

    def test_merge_commits_pass(self) -> None:
        for label in ("merge-multi", "merge-release", "merge-line"):
            with self.subTest(label=label):
                self.assertEqual(self.check(self.commits[label]), 0)

    def test_uppercase_commit_passes(self) -> None:
        self.assertEqual(self.check(self.commits["merge-release"].upper()), 0)

    def test_merged_pull_request_heads_fail(self) -> None:
        for label in ("release", "multi-2"):
            with self.subTest(label=label):
                self.assertNotEqual(self.check(self.commits[label]), 0)

    def test_stale_base_pull_request_head_never_was_a_branch_state(self) -> None:
        head_tree = git(self.repo, "rev-parse", f"{self.commits['release']}^{{tree}}")
        merge_tree = git(self.repo, "rev-parse", f"{self.commits['merge-release']}^{{tree}}")
        self.assertNotEqual(head_tree, merge_tree)
        self.assertNotEqual(self.check(self.commits["release"]), 0)
        self.assertEqual(self.check(self.commits["merge-release"]), 0)

    def test_intermediate_commit_of_merged_pull_request_fails(self) -> None:
        self.assertNotEqual(self.check(self.commits["multi-1"]), 0)

    def test_merged_long_lived_branch_commits_fail(self) -> None:
        for label in ("line-3", "line-2", "line-1"):
            with self.subTest(label=label):
                self.assertNotEqual(self.check(self.commits[label]), 0)

    def test_unknown_history_ref_fails(self) -> None:
        self.assertNotEqual(self.check(self.commits["m2"], history_ref="1" * 40), 0)


if __name__ == "__main__":
    unittest.main()
