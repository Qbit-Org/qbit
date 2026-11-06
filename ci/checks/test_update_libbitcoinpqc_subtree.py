#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for contrib/devtools/update-libbitcoinpqc-subtree.sh and its lint."""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER = Path("contrib/devtools/update-libbitcoinpqc-subtree.sh")
LINT = Path("test/lint/libbitcoinpqc-subtree-check.sh")
LIBRARY = Path("test/lint/libbitcoinpqc-release-tag.sh")
PREFIX = "src/libbitcoinpqc"
REAL_UPSTREAM = "https://github.com/Qbit-Org/qbit-libbitcoinpqc.git"
PRIVATE_REFS = ("refs/libbitcoinpqc-import", "refs/libbitcoinpqc-subtree-check")


def git_version() -> tuple[int, int]:
    output = subprocess.run(["git", "version"], capture_output=True, text=True, check=True).stdout
    match = re.match(r"git version (\d+)\.(\d+)", output)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


HAVE_GPG = all(shutil.which(tool) for tool in ("gpg", "gpgconf"))
HAVE_GIT_2_45 = git_version() >= (2, 45)


@unittest.skipUnless(HAVE_GPG, "gpg and gpgconf are required")
class UpdateLibbitcoinpqcSubtreeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp_dir.name)
        cls.git_config = cls.root / "gitconfig"
        cls.git_config.write_text(
            "[user]\n\tname = qbit import test\n\temail = import-test@example.invalid\n"
            "[init]\n\tdefaultBranch = main\n"
            "[commit]\n\tgpgsign = false\n[tag]\n\tgpgsign = false\n",
            encoding="utf8",
        )
        cls.empty_home = cls._gnupg_home("empty")
        cls.signer_home = cls._gnupg_home("signer")
        cls.wrong_home = cls._gnupg_home("wrong")
        cls.maintainer_home = cls._gnupg_home("maintainer")
        cls.signer = cls._generate_key(cls.signer_home, "Test Signer <signer@example.invalid>")
        cls.wrong = cls._generate_key(cls.wrong_home, "Wrong Signer <wrong@example.invalid>")
        cls.maintainer = cls._generate_key(cls.maintainer_home, "Maintainer <maintainer@example.invalid>")
        cls.signer_cert = cls.root / "signer.asc"
        cls.signer_cert.write_text(
            cls._run(["gpg", "--armor", "--export", cls.signer], gnupghome=cls.signer_home),
            encoding="utf8",
        )
        cls.upstream = cls._build_upstream()

    @classmethod
    def tearDownClass(cls) -> None:
        for home in (cls.empty_home, cls.signer_home, cls.wrong_home, cls.maintainer_home):
            for command in (["gpgconf", "--kill", "all"], ["gpgconf", "--remove-socketdir"]):
                subprocess.run(command, env=cls._env(gnupghome=home), capture_output=True)
        cls.temp_dir.cleanup()

    @classmethod
    def _env(cls, gnupghome: Path | None = None, **extra: str) -> dict[str, str]:
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(
            {
                "GIT_CONFIG_GLOBAL": str(cls.git_config),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GNUPGHOME": str(gnupghome or cls.empty_home),
                "LC_ALL": "C",
            }
        )
        env.update(extra)
        return env

    @classmethod
    def _run(cls, args: list[str], cwd: Path | None = None, gnupghome: Path | None = None) -> str:
        result = subprocess.run(
            args, cwd=cwd, env=cls._env(gnupghome=gnupghome), capture_output=True, text=True
        )
        if result.returncode != 0:
            raise AssertionError(f"{args} failed: {result.stderr}")
        return result.stdout

    @classmethod
    def _git(cls, repo: Path, *args: str, gnupghome: Path | None = None) -> str:
        return cls._run(["git", "-C", str(repo), *args], gnupghome=gnupghome).strip()

    @classmethod
    def _gnupg_home(cls, name: str) -> Path:
        home = cls.root / f"gnupg-{name}"
        home.mkdir(mode=0o700)
        return home

    @classmethod
    def _generate_key(cls, home: Path, uid: str) -> str:
        cls._run(
            [
                "gpg", "--batch", "--quiet", "--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-gen-key", uid, "ed25519", "sign", "never",
            ],
            gnupghome=home,
        )
        listing = cls._run(["gpg", "--with-colons", "--list-secret-keys"], gnupghome=home)
        return next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))

    @classmethod
    def _build_upstream(cls) -> Path:
        work = cls.root / "upstream-work"
        cls._git(cls.root, "init", "-q", str(work))
        releases = [
            ("v0.2.0", {"README.md": "v0.2\n", "Cargo.lock": "a = 1\nb = 1\n", "src.c": "int x;\n"}),
            ("v0.3.0", {"README.md": "v0.3.0\n"}),
            ("v0.3.2", {"README.md": "v0.3.2\n", "Cargo.lock": "a = 2\nb = 1\n"}),
        ]
        (work / ".gitignore").write_text("build/\n", encoding="utf8")
        for tag, files in releases:
            for name, content in files.items():
                (work / name).write_text(content, encoding="utf8")
            cls._git(work, "add", "-A")
            cls._git(work, "commit", "-q", "-m", f"release {tag}")
            cls._sign_tag(work, tag, cls.signer, cls.signer_home)
        cls._git(work, "tag", "-a", "-m", "unsigned", "v9.9.9-unsigned", "HEAD")
        cls._git(work, "tag", "v9.9.7-lightweight", "HEAD")
        side_releases = [
            ("v0.3.3", {"newdir/inner.c": "int inner;\n"}),
            ("v0.3.4", {"fixture.gen": "generated\n"}),
            ("v0.3.5", {}),
        ]
        for tag, files in side_releases:
            cls._git(work, "checkout", "-q", "--detach", "v0.3.2")
            for name, content in files.items():
                (work / name).parent.mkdir(parents=True, exist_ok=True)
                (work / name).write_text(content, encoding="utf8")
            cls._git(work, "add", "-A")
            cls._git(work, "commit", "-q", "--allow-empty", "-m", f"release {tag}")
            cls._sign_tag(work, tag, cls.signer, cls.signer_home)
        cls._git(work, "checkout", "-q", "--detach", "v0.3.0")
        (work / "Cargo.lock").write_text("a = 1\nb = 2\n", encoding="utf8")
        cls._git(work, "add", "-A")
        cls._git(work, "commit", "-q", "-m", "release v0.3.6: upstream qbit's lockfile change")
        cls._sign_tag(work, "v0.3.6", cls.signer, cls.signer_home)
        # An annotated decoy whose ref name ends in v0.3.2 and sorts first.
        cls._git(work, "tag", "-a", "-m", "decoy", "0/v0.3.2", "v0.3.0^{commit}")
        cls._git(work, "checkout", "-q", "v0.3.2")
        cls._sign_tag(work, "v9.9.9-wrong", cls.wrong, cls.wrong_home)
        # An older signed tag object published under a new name.
        cls._git(work, "update-ref", "refs/tags/v9.9.8", cls._git(work, "rev-parse", "v0.3.0"))
        upstream = cls.root / "upstream.git"
        cls._git(cls.root, "clone", "-q", "--bare", "--no-local", str(work), str(upstream))
        return upstream

    @classmethod
    def _sign_tag(cls, repo: Path, tag: str, key: str, home: Path) -> None:
        cls._git(
            repo, "-c", "gpg.openpgp.program=gpg", "-c", f"user.signingkey={key}",
            "tag", "-s", "-m", f"{tag} release", tag, "HEAD", gnupghome=home,
        )

    def setUp(self) -> None:
        self.case_dir = Path(tempfile.mkdtemp(dir=self.root))
        self.tmp = self.case_dir / "tmp"
        self.tmp.mkdir()

    def make_downstream(self, sign: bool = False) -> Path:
        repo = self.case_dir / "qbit"
        self._git(self.case_dir, "init", "-q", str(repo))
        self._git(repo, "config", "gpg.openpgp.program", "gpg")
        self._git(repo, "config", "commit.gpgsign", "true" if sign else "false")
        if sign:
            self._git(repo, "config", "user.signingkey", self.maintainer)
        for path in (HELPER, LINT, LIBRARY):
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / path, repo / path)
        (repo / "README").write_text("qbit\n", encoding="utf8")
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-q", "-m", "root", gnupghome=self.maintainer_home)
        self._git(repo, "fetch", "-q", str(self.upstream), "refs/tags/v0.3.0")
        split = self._git(repo, "rev-parse", "FETCH_HEAD^{commit}")
        self._git(repo, "read-tree", f"--prefix={PREFIX}/", "-u", f"{split}^{{tree}}")
        self.commit(
            repo, f"Squashed '{PREFIX}/' content from commit {split[:10]}",
            f"git-subtree-dir: {PREFIX}\ngit-subtree-split: {split}",
        )
        return repo

    def commit(self, repo: Path, subject: str, body: str = "") -> None:
        args = ["commit", "-q", "-m", subject] + (["-m", body] if body else [])
        self._git(repo, *args, gnupghome=self.maintainer_home)

    def state(self, repo: Path) -> tuple[str, str, str]:
        return (
            self._git(repo, "rev-parse", "HEAD"),
            self._git(repo, "write-tree"),
            self._git(repo, "status", "--porcelain", "--ignored"),
        )

    def signer_args(self) -> list[str]:
        return ["--test-signer-cert", str(self.signer_cert), "--test-signer-fingerprint", self.signer]

    def helper_env(
        self, gnupghome: Path | None = None, extra_env: dict[str, str] | None = None
    ) -> dict[str, str]:
        env = self._env(gnupghome=gnupghome, LIBBITCOINPQC_REMOTE_URL=str(self.upstream), TMPDIR=str(self.tmp))
        env.update(extra_env or {})
        return env

    def assert_nothing_left_behind(self, repo: Path) -> None:
        self.assertEqual(list(self.tmp.iterdir()), [], "the throwaway keyring was left behind")
        self.assertEqual(self._git(repo, "for-each-ref", *PRIVATE_REFS), "", "a private tag ref was left behind")
        # A --depth fetch would mark the repository shallow.
        self.assertEqual(self._git(repo, "rev-parse", "--is-shallow-repository"), "false")

    def run_helper(
        self,
        repo: Path,
        *args: str,
        gnupghome: Path | None = None,
        path_prefix: Path | None = None,
        test_signer: bool = True,
        extra_env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = self.helper_env(gnupghome, extra_env)
        if path_prefix is not None:
            env["PATH"] = f"{path_prefix}{os.pathsep}{env['PATH']}"
        signer_args = self.signer_args() if test_signer else []
        result = subprocess.run(
            [str(repo / HELPER), *signer_args, *args], cwd=cwd or repo, env=env, capture_output=True, text=True
        )
        self.assert_nothing_left_behind(repo)
        return result

    def run_lint(
        self,
        repo: Path,
        tag: str,
        test_signer: bool = True,
        url: str | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = self._env(
            LIBBITCOINPQC_REMOTE_URL=url or str(self.upstream),
            LIBBITCOINPQC_REMOTE_REF=tag,
            TMPDIR=str(self.tmp),
        )
        env.update(extra_env or {})
        signer_args = self.signer_args() if test_signer else []
        result = subprocess.run(
            [str(repo / LINT), *signer_args], cwd=repo, env=env, capture_output=True, text=True
        )
        self.assert_nothing_left_behind(repo)
        return result

    def assert_refused(self, repo: Path, message: str, *args: str, **kwargs: object) -> str:
        before = self.state(repo)
        result = self.run_helper(repo, *args, **kwargs)  # type: ignore[arg-type]
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertEqual(self.state(repo), before)
        return result.stderr

    def assert_imported(self, repo: Path, tag: str, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GOOD", result.stdout)
        split = self._git(self.upstream, "rev-parse", f"{tag}^{{commit}}")
        message = self._git(repo, "log", "-1", "--format=%B")
        self.assertRegex(message, rf"^Squashed '{PREFIX}/' changes from [0-9a-f]{{10}}\.\.{split[:10]}\n")
        self.assertIn(f"\ngit-subtree-dir: {PREFIX}\ngit-subtree-split: {split}", message)
        self.assertEqual(
            self._git(repo, "rev-parse", f"HEAD:{PREFIX}"),
            self._git(self.upstream, "rev-parse", f"{tag}^{{tree}}"),
        )
        self.assertEqual(self._git(repo, "status", "--porcelain"), "")

    def write_shim(self, name: str, body: str) -> Path:
        shim_dir = self.case_dir / f"shim-{name}"
        shim_dir.mkdir()
        shim = shim_dir / name
        shim.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf8")
        shim.chmod(0o755)
        return shim_dir

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_imports_signed_release(self) -> None:
        repo = self.make_downstream()
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "v0.3.2"))
        self.assertEqual(self._git(repo, "log", "-1", "--format=%G?"), "N")

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_signing_maintainer_gets_signed_import_commit(self) -> None:
        repo = self.make_downstream(sign=True)
        result = self.run_helper(repo, "v0.3.2", gnupghome=self.maintainer_home)
        self.assert_imported(repo, "v0.3.2", result)
        status = subprocess.run(
            ["git", "-c", "gpg.openpgp.program=gpg", "verify-commit", "--raw", "HEAD"],
            cwd=repo, env=self._env(gnupghome=self.maintainer_home), capture_output=True, text=True,
        )
        self.assertIn(f"[GNUPG:] VALIDSIG {self.maintainer} ", status.stderr)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_already_imported_tag_is_a_no_op(self) -> None:
        repo = self.make_downstream()
        before = self.state(repo)
        result = self.run_helper(repo, "v0.3.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already imports v0.3.0", result.stdout)
        self.assertIn("GOOD", result.stdout)
        self.assertEqual(self.state(repo), before)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_refuses_staged_only_change(self) -> None:
        repo = self.make_downstream()
        (repo / "README").write_text("staged\n", encoding="utf8")
        self._git(repo, "add", "README")
        (repo / "README").write_text("qbit\n", encoding="utf8")
        self.assert_refused(repo, "the index has staged changes", "v0.3.2")

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_refuses_unstaged_change(self) -> None:
        repo = self.make_downstream()
        (repo / "README").write_text("unstaged\n", encoding="utf8")
        self.assert_refused(repo, "the worktree has changes", "v0.3.2")

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_refuses_untracked_file_under_prefix(self) -> None:
        repo = self.make_downstream()
        (repo / PREFIX / "stray.c").write_text("stray\n", encoding="utf8")
        self.assert_refused(repo, f"untracked files under {PREFIX}", "v0.3.2")

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_refuses_ignored_file_under_prefix(self) -> None:
        repo = self.make_downstream()
        (repo / PREFIX / "build").mkdir()
        (repo / PREFIX / "build" / "artefact.o").write_text("object\n", encoding="utf8")
        self.assert_refused(repo, f"git clean -ndX {PREFIX}", "v0.3.2")

    def test_refuses_old_git(self) -> None:
        repo = self.make_downstream()
        real_git = shutil.which("git")
        shim_dir = self.write_shim(
            "git", f'[ "$1" = version ] && {{ echo "git version 2.44.2"; exit 0; }}\nexec {real_git} "$@"'
        )
        self.assert_refused(repo, "Git 2.45 or later is required", "v0.3.2", path_prefix=shim_dir)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_refuses_unsigned_tag(self) -> None:
        repo = self.make_downstream()
        self.assert_refused(repo, "has no good signature", "v9.9.9-unsigned")

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_refuses_wrong_signer(self) -> None:
        repo = self.make_downstream()
        self.assert_refused(repo, "has no good signature", "v9.9.9-wrong")

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_refuses_republished_tag_name(self) -> None:
        repo = self.make_downstream()
        self.assert_refused(repo, "is not v9.9.8 pointing at a commit", "v9.9.8")

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_refuses_downgrade_unless_allowed(self) -> None:
        repo = self.make_downstream()
        self.assert_refused(repo, "--allow-downgrade", "v0.2.0")
        self.assert_imported(repo, "v0.2.0", self.run_helper(repo, "--allow-downgrade", "v0.2.0"))

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_refuses_dropped_delta_unless_accepted(self) -> None:
        repo = self.make_downstream()
        (repo / PREFIX / "src.c").write_text("int x;\nint qbit_only;\n", encoding="utf8")
        self._git(repo, "add", "-A")
        self.commit(repo, "qbit-only change the release lacks")
        self.assert_refused(repo, "  src.c", "v0.3.2")
        self.assert_refused(
            repo, "--accept-upstream other.c does not name a path", "--accept-upstream", "other.c", "v0.3.2"
        )
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "--accept-upstream", "src.c", "v0.3.2"))

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_conflicting_delta_needs_accept_upstream(self) -> None:
        repo = self.make_downstream()
        (repo / PREFIX / "Cargo.lock").write_text("a = 3\nb = 1\n", encoding="utf8")
        self._git(repo, "add", "-A")
        self.commit(repo, "qbit lockfile change that conflicts with the release")
        stderr = self.assert_refused(repo, "conflicts with how v0.3.2 changed them:\n  Cargo.lock\n", "v0.3.2")
        self.assertNotIn("~", stderr)
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "--accept-upstream", "Cargo.lock", "v0.3.2"))

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_delta_contained_in_release_imports(self) -> None:
        repo = self.make_downstream()
        (repo / PREFIX / "Cargo.lock").write_text("a = 2\nb = 1\n", encoding="utf8")
        self._git(repo, "add", "-A")
        self.commit(repo, "qbit lockfile change that the release also makes")
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "v0.3.2"))

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_failing_gpgconf_still_removes_keyring(self) -> None:
        repo = self.make_downstream()
        real_gpgconf = shutil.which("gpgconf")
        shim_dir = self.write_shim("gpgconf", f'{real_gpgconf} "$@" || true\nexit 1')
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "v0.3.2", path_prefix=shim_dir))

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_lint_failure_undoes_import_commit(self) -> None:
        repo = self.make_downstream()
        (repo / LINT).write_text("#!/usr/bin/env bash\necho 'FAIL: forced' >&2\nexit 1\n", encoding="utf8")
        self._git(repo, "add", "-A")
        self.commit(repo, "force a lint failure")
        self.assert_refused(repo, "the import commit was undone", "v0.3.2")

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_file_directory_conflict_lists_the_real_path(self) -> None:
        repo = self.make_downstream()
        (repo / PREFIX / "newdir").write_text("qbit file\n", encoding="utf8")
        self._git(repo, "add", "-A")
        self.commit(repo, "qbit adds a file where the release adds a directory")
        stderr = self.assert_refused(repo, "changed them:\n  newdir\n", "v0.3.3")
        self.assertNotIn("newdir~", stderr)
        self.assert_imported(repo, "v0.3.3", self.run_helper(repo, "--accept-upstream", "newdir", "v0.3.3"))

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_renamed_path_lists_both_names(self) -> None:
        repo = self.make_downstream()
        self._git(repo, "mv", f"{PREFIX}/src.c", f"{PREFIX}/renamed.c")
        self.commit(repo, "qbit renames a file")
        stderr = self.assert_refused(repo, "  renamed.c\n", "v0.3.2")
        self.assertIn("  src.c\n", stderr)
        self.assert_refused(repo, "  src.c\n", "--accept-upstream", "renamed.c", "v0.3.2")
        result = self.run_helper(repo, "--accept-upstream", "renamed.c", "--accept-upstream", "src.c", "v0.3.2")
        self.assert_imported(repo, "v0.3.2", result)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_non_ascii_path_can_be_accepted(self) -> None:
        repo = self.make_downstream()
        name = "\u00fcn\u00efcode.c"
        (repo / PREFIX / name).write_text("int u;\n", encoding="utf8")
        self._git(repo, "add", "-A")
        self.commit(repo, "qbit adds a non-ASCII path")
        self.assert_refused(repo, f"  {name}\n", "v0.3.2")
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "--accept-upstream", name, "v0.3.2"))

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_release_with_the_vendored_tree_moves_only_the_split(self) -> None:
        repo = self.make_downstream()
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "v0.3.2"))
        result = self.run_helper(repo, "v0.3.5")
        self.assert_imported(repo, "v0.3.5", result)
        self.assertIn("the import commit only moves the split", result.stdout)
        self.assertEqual(self._git(repo, "diff", "--name-only", "HEAD~1", "HEAD"), "")

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_release_that_upstreams_the_downstream_delta_imports(self) -> None:
        repo = self.make_downstream()
        (repo / PREFIX / "Cargo.lock").write_text("a = 1\nb = 2\n", encoding="utf8")
        self._git(repo, "add", "-A")
        self.commit(repo, "qbit's approved lockfile delta")
        self.assert_imported(repo, "v0.3.6", self.run_helper(repo, "v0.3.6"))
        self.assertEqual(self._git(repo, "diff", "--name-only", "HEAD~1", "HEAD"), "")
        lint = self.run_lint(repo, "v0.3.6")
        self.assertEqual(lint.returncode, 0, lint.stderr)
        self.assertIn("GOOD", lint.stdout)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_decoy_tag_ref_does_not_mislead_the_lint(self) -> None:
        repo = self.make_downstream()
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "v0.3.2"))
        lint = self.run_lint(repo, "v0.3.2")
        self.assertEqual(lint.returncode, 0, lint.stderr)
        self.assertIn(
            f"resolves to commit {self._git(self.upstream, 'rev-parse', 'v0.3.2^{commit}')}", lint.stdout
        )

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_helper_rejects_a_lint_that_verified_another_commit(self) -> None:
        repo = self.make_downstream()
        other = self._git(self.upstream, "rev-parse", "v0.3.0^{commit}")
        (repo / LINT).write_text(
            f"#!/usr/bin/env bash\necho 'x v0.3.2 resolves to commit {other} tree t'\necho GOOD\n",
            encoding="utf8",
        )
        self._git(repo, "add", "-A")
        self.commit(repo, "a lint that verifies another commit")
        self.assert_refused(repo, f"the subtree check verified {other}, not v0.3.2", "v0.3.2")

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_lint_failure_that_cannot_be_undone_says_how_to_recover(self) -> None:
        repo = self.make_downstream()
        (repo / LINT).write_text(
            f"#!/usr/bin/env bash\necho dirty >> {PREFIX}/README.md\nexit 1\n", encoding="utf8"
        )
        self._git(repo, "add", "-A")
        self.commit(repo, "a lint that dirties the subtree and fails")
        before = self._git(repo, "rev-parse", "HEAD")
        result = self.run_helper(repo, "v0.3.2")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"the subtree check failed; the import commit could not be undone; run git reset --hard {before}",
            result.stderr,
        )

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_already_imported_tag_still_runs_the_subtree_check(self) -> None:
        repo = self.make_downstream()
        (repo / PREFIX / "src.c").write_text("int drift;\n", encoding="utf8")
        self._git(repo, "add", "-A")
        self.commit(repo, "vendored tree drifts")
        result = self.run_helper(repo, "v0.3.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already imports v0.3.0", result.stdout)
        self.assertIn("already imports v0.3.0, but the subtree check failed", result.stderr)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_failed_commit_restores_the_prefix_including_ignored_files(self) -> None:
        repo = self.make_downstream()
        (repo / ".gitignore").write_text("*.gen\n", encoding="utf8")
        self._git(repo, "add", ".gitignore")
        self.commit(repo, "qbit ignores generated files")
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf8")
        hook.chmod(0o755)
        self.assert_refused(repo, "", "v0.3.4")
        self.assertFalse((repo / PREFIX / "fixture.gen").exists())

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_test_signer_flags_warn(self) -> None:
        repo = self.make_downstream()
        result = self.run_helper(repo, "v0.3.2")
        self.assert_imported(repo, "v0.3.2", result)
        self.assertIn("TEST SIGNER IN USE: not for real imports", result.stderr)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_signer_environment_variables_are_ignored(self) -> None:
        repo = self.make_downstream()
        cert = repo / "contrib/keys/operator-keys/public-keys/operator-01-release.asc"
        cert.parent.mkdir(parents=True)
        shutil.copy2(REPO_ROOT / "contrib/keys/operator-keys/public-keys/operator-01-release.asc", cert)
        self._git(repo, "add", "-A")
        self.commit(repo, "add the pinned signer certificate")
        stderr = self.assert_refused(
            repo,
            "has no good signature from 289EA3EC2F1939A24984840ED26CFC05586D371E",
            "v0.3.2",
            test_signer=False,
            extra_env={
                "LIBBITCOINPQC_TEST_SIGNER_CERT": str(self.signer_cert),
                "LIBBITCOINPQC_TEST_SIGNER_FINGERPRINT": self.signer,
            },
        )
        self.assertNotIn("TEST SIGNER IN USE", stderr)

    def test_test_signer_flags_must_be_given_together(self) -> None:
        repo = self.make_downstream()
        self.assert_refused(
            repo, "must be given together", "--test-signer-cert", str(self.signer_cert), "v0.3.2",
            test_signer=False,
        )

    def test_usage_errors(self) -> None:
        repo = self.make_downstream()
        self.assert_refused(repo, "unknown option: --bogus", "--bogus")
        self.assert_refused(repo, "--accept-upstream requires a path", "--accept-upstream")
        self.assert_refused(repo, "expected at most one tag", "v0.3.2", "v0.3.3")
        self.assert_refused(repo, "not a valid tag name", "bad..tag")
        result = self.run_helper(repo, "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--accept-upstream <path>", result.stdout)
        self.assertIn("A first import is a maintainer task outside this helper.", result.stdout)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_lint_fails_closed_on_a_commit_that_quotes_the_trailer(self) -> None:
        repo = self.make_downstream()
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "v0.3.2"))
        quoted = f"git-subtree-dir: {PREFIX}\ngit-subtree-split: {'0' * 40}"
        (repo / "README").write_text("docs\n", encoding="utf8")
        self._git(repo, "add", "README")
        self.commit(repo, "doc: describe the import", quoted)
        result = self.run_lint(repo, "v0.3.2")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("FAIL", result.stderr)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_lint_finds_import_landed_by_a_merge_commit(self) -> None:
        repo = self.make_downstream()
        self._git(repo, "checkout", "-q", "-b", "import")
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "v0.3.2"))
        self._git(repo, "checkout", "-q", "main")
        (repo / "README").write_text("main moved on\n", encoding="utf8")
        self._git(repo, "add", "README")
        self.commit(repo, "main: unrelated change")
        quoted_title = f"git-subtree-dir: {PREFIX}\ngit-subtree-split: {'0' * 40}"
        self._git(
            repo, "merge", "-q", "--no-ff", "-m", "Merge pull request #1", "-m", quoted_title, "import",
            gnupghome=self.maintainer_home,
        )
        result = self.run_lint(repo, "v0.3.2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GOOD", result.stdout)

    def assert_interrupt_undoes_the_import(self, signum: int) -> None:
        repo = self.make_downstream()
        started = self.case_dir / "lint-started"
        (repo / LINT).write_text(
            '#!/usr/bin/env bash\ntouch "${LINT_STARTED:?}"\nsleep 60\necho GOOD\n', encoding="utf8"
        )
        self._git(repo, "add", "-A")
        self.commit(repo, "a slow subtree check")
        before = self.state(repo)
        process = subprocess.Popen(
            [str(repo / HELPER), *self.signer_args(), "v0.3.2"],
            cwd=repo, env=self.helper_env(extra_env={"LINT_STARTED": str(started)}),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 60
            while not started.exists():
                self.assertIsNone(process.poll(), "the helper exited before the subtree check started")
                self.assertLess(time.monotonic(), deadline, "the subtree check never started")
                time.sleep(0.05)
            # The import commit exists now. Signal the whole job, as Ctrl-C does.
            self.assertNotEqual(self._git(repo, "rev-parse", "HEAD"), before[0])
            os.killpg(process.pid, signum)
            _stdout, stderr = process.communicate(timeout=60)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
        self.assertEqual(process.returncode, 128 + signum, stderr)
        self.assertIn("the import stopped before the subtree check passed; the import commit was undone", stderr)
        self.assertEqual(self.state(repo), before)
        self.assert_nothing_left_behind(repo)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_sigterm_during_the_subtree_check_undoes_the_import(self) -> None:
        self.assert_interrupt_undoes_the_import(signal.SIGTERM)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_sigint_during_the_subtree_check_undoes_the_import(self) -> None:
        self.assert_interrupt_undoes_the_import(signal.SIGINT)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_lint_requires_a_release_tag_from_the_signer(self) -> None:
        repo = self.make_downstream()
        cases = [
            ("v9.9.9-unsigned", "v9.9.9-unsigned has no good signature from"),
            ("v9.9.7-lightweight", "v9.9.7-lightweight is not a signed annotated tag"),
            ("v9.9.9-wrong", "v9.9.9-wrong has no good signature from"),
            ("v9.9.8", "the fetched tag object is not v9.9.8 pointing at a commit"),
        ]
        for tag, message in cases:
            with self.subTest(tag=tag):
                result = self.run_lint(repo, tag)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(message, result.stderr)
                self.assertIn(f"FAIL: {self.upstream} {tag} is not a release tag signed by", result.stderr)
                self.assertNotIn("resolves to commit", result.stdout)
        result = self.run_lint(repo, "v0.3.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"has a good signature from {self.signer}", result.stdout)
        self.assertIn("GOOD", result.stdout)

    def test_lint_checks_the_pinned_signer_without_test_options(self) -> None:
        repo = self.make_downstream()
        result = self.run_lint(repo, "v0.3.0", test_signer=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"FAIL: signer certificate not found: {repo}/contrib/keys/operator-keys/public-keys/", result.stderr
        )

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_test_signer_options_are_refused_for_the_real_upstream(self) -> None:
        repo = self.make_downstream()
        rewritten = str(self.case_dir / "looks-local")
        forms = {
            "https": ({"LIBBITCOINPQC_REMOTE_URL": REAL_UPSTREAM}, REAL_UPSTREAM),
            "scp": ({"LIBBITCOINPQC_REMOTE_URL": "git@github.com:Qbit-Org/qbit-libbitcoinpqc.git"}, None),
            "insteadOf": (
                {
                    "LIBBITCOINPQC_REMOTE_URL": rewritten,
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": f"url.{REAL_UPSTREAM}.insteadOf",
                    "GIT_CONFIG_VALUE_0": rewritten,
                },
                rewritten,
            ),
        }
        for form, (extra_env, url) in forms.items():
            with self.subTest(form=form):
                self.assert_refused(
                    repo, "are accepted only for a local repository", "v0.3.2", extra_env=extra_env
                )
                lint = self.run_lint(
                    repo, "v0.3.0", url=extra_env["LIBBITCOINPQC_REMOTE_URL"], extra_env=extra_env
                )
                self.assertEqual(lint.returncode, 1, lint.stdout)
                self.assertIn("test signer options are accepted only for a local repository", lint.stderr)
                if url is not None:
                    self.assertIn(f"not {url}", lint.stderr)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_a_stale_fetch_head_is_not_read(self) -> None:
        # The fixture's own fetch left FETCH_HEAD at the v0.3.0 tag object. A
        # fetch that does not write it, as with --no-write-fetch-head, or one
        # that another fetch overwrites, leaves it stale.
        repo = self.make_downstream()
        stale = (repo / ".git" / "FETCH_HEAD").read_text(encoding="utf8")
        real_git = shutil.which("git")
        shim_dir = self.write_shim(
            "git",
            f'[ "$1" = fetch ] && {{ shift; exec {real_git} fetch --no-write-fetch-head "$@"; }}\n'
            f'exec {real_git} "$@"',
        )
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "v0.3.2", path_prefix=shim_dir))
        lint = self.run_lint(repo, "v0.3.2", extra_env={"PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}"})
        self.assertEqual(lint.returncode, 0, lint.stderr)
        self.assertEqual((repo / ".git" / "FETCH_HEAD").read_text(encoding="utf8"), stale)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_a_skewed_committer_date_does_not_pick_an_older_import(self) -> None:
        # The v0.3.2 import is dated in the future. Walked by date from the
        # merge, it would come before the v0.3.5 import that descends from it.
        repo = self.make_downstream()
        future = {"GIT_COMMITTER_DATE": "2035-01-01T00:00:00Z"}
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "v0.3.2", extra_env=future))
        self._git(repo, "checkout", "-q", "-b", "import")
        self.assert_imported(repo, "v0.3.5", self.run_helper(repo, "v0.3.5"))
        self._git(repo, "checkout", "-q", "main")
        later = self._env(gnupghome=self.maintainer_home, GIT_COMMITTER_DATE="2030-01-01T00:00:00Z")
        for args in (
            ["commit", "-q", "--allow-empty", "-m", "main moved on"],
            ["merge", "-q", "--no-ff", "-m", "Merge pull request #2", "import"],
        ):
            subprocess.run(["git", "-C", str(repo), *args], env=later, check=True, capture_output=True)
        lint = self.run_lint(repo, "v0.3.5")
        self.assertEqual(lint.returncode, 0, lint.stderr)
        self.assertIn("GOOD", lint.stdout)
        result = self.run_helper(repo, "v0.3.5")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already imports v0.3.5", result.stdout)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_an_inherited_libbitcoinpqc_path_is_ignored(self) -> None:
        repo = self.make_downstream()
        elsewhere = {"LIBBITCOINPQC_PATH": "does/not/exist"}
        lint = self.run_lint(repo, "v0.3.0", extra_env=elsewhere)
        self.assertEqual(lint.returncode, 0, lint.stderr)
        self.assertIn(f"{PREFIX} in HEAD currently refers to tree", lint.stdout)
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "v0.3.2", extra_env=elsewhere))

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_relative_remote_is_resolved_from_the_starting_directory(self) -> None:
        repo = self.make_downstream()
        start = repo / PREFIX
        relative = os.path.relpath(self.upstream, start)
        result = self.run_helper(repo, "v0.3.2", cwd=start, extra_env={"LIBBITCOINPQC_REMOTE_URL": relative})
        self.assert_imported(repo, "v0.3.2", result)
        self.assertIn(f"Fetching v0.3.2 from {start}/{relative}", result.stdout)


if __name__ == "__main__":
    unittest.main()
