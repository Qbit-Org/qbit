#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for contrib/devtools/update-libbitcoinpqc-subtree.sh and its lint."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER = Path("contrib/devtools/update-libbitcoinpqc-subtree.sh")
LINT = Path("test/lint/libbitcoinpqc-subtree-check.sh")
PREFIX = "src/libbitcoinpqc"


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
        for path in (HELPER, LINT):
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

    def run_helper(
        self,
        repo: Path,
        *args: str,
        gnupghome: Path | None = None,
        path_prefix: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = self._env(
            gnupghome=gnupghome,
            LIBBITCOINPQC_REMOTE_URL=str(self.upstream),
            LIBBITCOINPQC_TEST_SIGNER_CERT=str(self.signer_cert),
            LIBBITCOINPQC_TEST_SIGNER_FINGERPRINT=self.signer,
            TMPDIR=str(self.tmp),
        )
        if path_prefix is not None:
            env["PATH"] = f"{path_prefix}{os.pathsep}{env['PATH']}"
        result = subprocess.run(
            [str(repo / HELPER), *args], cwd=repo, env=env, capture_output=True, text=True
        )
        self.assertEqual(list(self.tmp.iterdir()), [], "the throwaway keyring was left behind")
        return result

    def run_lint(self, repo: Path, tag: str) -> subprocess.CompletedProcess[str]:
        env = self._env(LIBBITCOINPQC_REMOTE_URL=str(self.upstream), LIBBITCOINPQC_REMOTE_REF=tag)
        return subprocess.run([str(repo / LINT)], cwd=repo, env=env, capture_output=True, text=True)

    def assert_refused(self, repo: Path, message: str, *args: str, **kwargs: Path) -> None:
        before = self.state(repo)
        result = self.run_helper(repo, *args, **kwargs)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertEqual(self.state(repo), before)

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
        self.assertEqual(self.state(repo), before)

    def test_refuses_staged_only_change(self) -> None:
        repo = self.make_downstream()
        (repo / "README").write_text("staged\n", encoding="utf8")
        self._git(repo, "add", "README")
        (repo / "README").write_text("qbit\n", encoding="utf8")
        self.assert_refused(repo, "the index has staged changes", "v0.3.2")

    def test_refuses_unstaged_change(self) -> None:
        repo = self.make_downstream()
        (repo / "README").write_text("unstaged\n", encoding="utf8")
        self.assert_refused(repo, "the worktree has changes", "v0.3.2")

    def test_refuses_untracked_file_under_prefix(self) -> None:
        repo = self.make_downstream()
        (repo / PREFIX / "stray.c").write_text("stray\n", encoding="utf8")
        self.assert_refused(repo, f"untracked files under {PREFIX}", "v0.3.2")

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
        self.assert_refused(repo, "also conflicts", "v0.3.2")
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

    def test_usage_errors(self) -> None:
        repo = self.make_downstream()
        self.assert_refused(repo, "unknown option: --bogus", "--bogus")
        self.assert_refused(repo, "--accept-upstream requires a path", "--accept-upstream")
        self.assert_refused(repo, "expected at most one tag", "v0.3.2", "v0.3.3")
        self.assert_refused(repo, "not a valid tag name", "bad..tag")
        result = self.run_helper(repo, "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--accept-upstream <path>", result.stdout)

    @unittest.skipUnless(HAVE_GIT_2_45, "Git 2.45 or later is required")
    def test_lint_ignores_commits_that_only_quote_the_trailer(self) -> None:
        repo = self.make_downstream()
        self.assert_imported(repo, "v0.3.2", self.run_helper(repo, "v0.3.2"))
        quoted = f"git-subtree-dir: {PREFIX}\ngit-subtree-split: {'0' * 40}"
        (repo / "README").write_text("docs\n", encoding="utf8")
        self._git(repo, "add", "README")
        self.commit(repo, "doc: describe the import", quoted)
        result = self.run_lint(repo, "v0.3.2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GOOD", result.stdout)

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


if __name__ == "__main__":
    unittest.main()
