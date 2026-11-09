#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for the release SHA256SUMS staging, signing and combining tools.

The tests are hermetic: throwaway OpenPGP keys live in a temporary GNUPGHOME,
and every trusted checkout, qbit-guix.sigs tree and builder output is created
inside the test. The v1.0.0 cases use only public v1.0.0 inputs embedded below:
one operator's builder manifests (all three attested identical bytes), the
published SHA256SUMS and per-operator signatures, and the three signers'
public certificates.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import py_compile
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

try:
    import resource
except ImportError:  # pragma: no cover - not available on Windows
    resource = None  # type: ignore[assignment]


# Importing the tools in-process must not leave bytecode beside them: the tools
# refuse to run from a checkout with ignored files in contrib/release-process.
sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "contrib" / "release-process"
VALIDATORS_DIR = REPO_ROOT / "ci" / "release"
STAGE_TOOL = "stage-release-artifacts.py"
SIGN_TOOL = "sign-sha256sums.py"
COMBINE_TOOL = "combine-sha256sums-signatures.py"
TOOL_FILES = ("release_staging_common.py", STAGE_TOOL, SIGN_TOOL, COMBINE_TOOL)
VALIDATOR_FILES = (
    "validate_key_metadata.py",
    "validate_release_artifacts.py",
    "validate_builder_attestations.py",
)
GPG = shutil.which("gpg")
GIT = shutil.which("git")
TAG = "v1.0.0-testnet1"
VERSION = TAG[1:]
OPERATORS = ("operator-01", "operator-02", "operator-03")
V1_0_0_SHA256SUMS_SHA256 = "14d885f6bb86ebcf41e764f5d5c31412ae75774ce5634f68bc7caf97c52102fe"
V1_0_0_COMBINED_SHA256 = "4bcaaa01a34693e56e611212cafe097720a8494bbede2b2d492a4744d8ee6b1e"
V1_0_0_SIGNERS = {
    "operator-01": "289EA3EC2F1939A24984840ED26CFC05586D371E",
    "operator-02": "1B95A7AA02F5530BDB1CD92387012E62F6CC1393",
    "operator-03": "05A14A415C26F4216DC254FE52D5CC557D764586",
}

V1_0_0_CORE_MANIFEST = """\
e2d9a00805a16049d8501ac30a3edd49d985bd8db3f970b76470604c280ae882  qbit-1.0.0-aarch64-linux-gnu-debug.tar.gz
a0242e5941eec64070f386e80c848220e2ec2292984a9b2ab1fd93f57436b31d  qbit-1.0.0-aarch64-linux-gnu.tar.gz
3c214c627c922d4ac4b9100a6fdc4ae334605fd93ec5260eb2a1773d5c3728c4  qbit-1.0.0-arm-linux-gnueabihf-debug.tar.gz
5607d03b68d804934ae5918f7b8bdf4c6e0da3507e809bc05b97146de13156d7  qbit-1.0.0-arm-linux-gnueabihf.tar.gz
3dd11096aa75652135312fca4a52f9d2154cbabff82c61531f44e325927e4b90  qbit-1.0.0-arm64-apple-darwin-codesigning.tar.gz
a98310136b57f49471bb19b7bbba1ccf3801da9a1d64202cf7dcf6756db0b3a1  qbit-1.0.0-arm64-apple-darwin-unsigned.tar.gz
3580f170ada2bc4230ff9b6c0000c8d23d1195c0ff9a178f99add1285f8f819b  qbit-1.0.0-arm64-apple-darwin-unsigned.zip
a8cd8831b006e6a5cb8a2b9b77be8715995cfcd5a602498eabe70e5b5aa61a36  qbit-1.0.0-powerpc64-linux-gnu-debug.tar.gz
acfc5098de60029e359fffda6438f29822e12a0ed5504b1a5940409c627f0384  qbit-1.0.0-powerpc64-linux-gnu.tar.gz
224a164efd8f2355556ddbcc06dc787140a895b0b2f89f862958b8c02998c702  qbit-1.0.0-riscv64-linux-gnu-debug.tar.gz
02455e62c33c0fac5ad65c3d8c8aa0c05be191cf7ad915a9d6dd4892c6b74cc4  qbit-1.0.0-riscv64-linux-gnu.tar.gz
22702cdd75bf2010dfbda062e1bdea8eade187f434f9b522d31c25b02a7c4a46  qbit-1.0.0-win64-codesigning.tar.gz
21fb3b74c8319315d02b36777aa2bdad446c88e5ed64a056308ad0b0dea50da3  qbit-1.0.0-win64-debug.zip
1e2255e532c1e8cb2f49501bd9ceac49eb38b49001b13b52ef0d3bd42b387173  qbit-1.0.0-win64-setup-unsigned.exe
93ca27facf73f736c1e1b152ad19f11eba0f075b800053bd07de9068fbe885b4  qbit-1.0.0-win64-unsigned.zip
5c986f0a8c365a5b5881bccae437b57b0df1bee84c0b4daf2eae09cb32cd8837  qbit-1.0.0-x86_64-apple-darwin-codesigning.tar.gz
e49b48469432e6f8bef26416b1660fc2a64809e0415f3b80cd6cb7b3f2109a2a  qbit-1.0.0-x86_64-apple-darwin-unsigned.tar.gz
6f9de70a569df992218db792366cfb0b4d368a162ad53dccca03250d40517727  qbit-1.0.0-x86_64-apple-darwin-unsigned.zip
047b0f5a547ffface32e5fc786652b7950850fcf7e8f79e0c6c3f6607def58c4  qbit-1.0.0-x86_64-linux-gnu-debug.tar.gz
ae121af03263b55d530e3f3e8719a71362d0950cba82f54a2bc2d6c437a029b5  qbit-1.0.0-x86_64-linux-gnu.tar.gz
4bd82433703137a537a01d9c728b9e87ea6bf6a32d69efc1828519684a876319  qbit-1.0.0.tar.gz
"""

V1_0_0_PHOTON_MANIFEST = """\
4bd82433703137a537a01d9c728b9e87ea6bf6a32d69efc1828519684a876319  qbit-1.0.0.tar.gz
5514bde5faa536a98c5b2327d8ad317d2bd31ebd4d7e3ea687daf84607eaab7d  qbit-photon-1.0.0-x86_64-linux-gnu-debug.tar.gz
93f0f4375f11a70690bf5598b3cafa49318f03a74cdf72cfc117639d73f909fb  qbit-photon-1.0.0-x86_64-linux-gnu.tar.gz
"""

V1_0_0_SHA256SUMS = """\
e2d9a00805a16049d8501ac30a3edd49d985bd8db3f970b76470604c280ae882  qbit-1.0.0-aarch64-linux-gnu-debug.tar.gz
a0242e5941eec64070f386e80c848220e2ec2292984a9b2ab1fd93f57436b31d  qbit-1.0.0-aarch64-linux-gnu.tar.gz
3c214c627c922d4ac4b9100a6fdc4ae334605fd93ec5260eb2a1773d5c3728c4  qbit-1.0.0-arm-linux-gnueabihf-debug.tar.gz
5607d03b68d804934ae5918f7b8bdf4c6e0da3507e809bc05b97146de13156d7  qbit-1.0.0-arm-linux-gnueabihf.tar.gz
a98310136b57f49471bb19b7bbba1ccf3801da9a1d64202cf7dcf6756db0b3a1  qbit-1.0.0-arm64-apple-darwin-unsigned.tar.gz
3580f170ada2bc4230ff9b6c0000c8d23d1195c0ff9a178f99add1285f8f819b  qbit-1.0.0-arm64-apple-darwin-unsigned.zip
a8cd8831b006e6a5cb8a2b9b77be8715995cfcd5a602498eabe70e5b5aa61a36  qbit-1.0.0-powerpc64-linux-gnu-debug.tar.gz
acfc5098de60029e359fffda6438f29822e12a0ed5504b1a5940409c627f0384  qbit-1.0.0-powerpc64-linux-gnu.tar.gz
224a164efd8f2355556ddbcc06dc787140a895b0b2f89f862958b8c02998c702  qbit-1.0.0-riscv64-linux-gnu-debug.tar.gz
02455e62c33c0fac5ad65c3d8c8aa0c05be191cf7ad915a9d6dd4892c6b74cc4  qbit-1.0.0-riscv64-linux-gnu.tar.gz
21fb3b74c8319315d02b36777aa2bdad446c88e5ed64a056308ad0b0dea50da3  qbit-1.0.0-win64-debug.zip
1e2255e532c1e8cb2f49501bd9ceac49eb38b49001b13b52ef0d3bd42b387173  qbit-1.0.0-win64-setup-unsigned.exe
93ca27facf73f736c1e1b152ad19f11eba0f075b800053bd07de9068fbe885b4  qbit-1.0.0-win64-unsigned.zip
e49b48469432e6f8bef26416b1660fc2a64809e0415f3b80cd6cb7b3f2109a2a  qbit-1.0.0-x86_64-apple-darwin-unsigned.tar.gz
6f9de70a569df992218db792366cfb0b4d368a162ad53dccca03250d40517727  qbit-1.0.0-x86_64-apple-darwin-unsigned.zip
047b0f5a547ffface32e5fc786652b7950850fcf7e8f79e0c6c3f6607def58c4  qbit-1.0.0-x86_64-linux-gnu-debug.tar.gz
ae121af03263b55d530e3f3e8719a71362d0950cba82f54a2bc2d6c437a029b5  qbit-1.0.0-x86_64-linux-gnu.tar.gz
5514bde5faa536a98c5b2327d8ad317d2bd31ebd4d7e3ea687daf84607eaab7d  qbit-photon-1.0.0-x86_64-linux-gnu-debug.tar.gz
93f0f4375f11a70690bf5598b3cafa49318f03a74cdf72cfc117639d73f909fb  qbit-photon-1.0.0-x86_64-linux-gnu.tar.gz
"""

V1_0_0_SIGNATURE_OPERATOR_01 = """\
-----BEGIN PGP SIGNATURE-----

iJEEABYIADkWIQQonqPsLxk5okmEhA7SbPwFWG03HgUCalgSzhsUgAAAAAAEAA5t
YW51MiwyLjUrMS4xMiwwLDMACgkQ0mz8BVhtNx4wAgEAtIG4Nk0t+GfJPTcf3vmM
3c14N5cjm+IMlm8tEpzq14YBAMiu6g89pIANl8qLzPELS1971Aq0vqmYAMy7Uc7B
U5kG
=/KjE
-----END PGP SIGNATURE-----
"""

V1_0_0_SIGNATURE_OPERATOR_02 = """\
-----BEGIN PGP SIGNATURE-----

iHUEABYIAB0WIQQblaeqAvVTC9sc2SOHAS5i9swTkwUCalgTaAAKCRCHAS5i9swT
k25xAQDGttqgDqIgxOUisq1M6CibM8hukbpRzEWDpu8Gd84QmgD+J/B9TBhRZujU
bmAuwwIyP2SFifoIzq9taZMCa9iegwM=
=+IGc
-----END PGP SIGNATURE-----
"""

V1_0_0_SIGNATURE_OPERATOR_03 = """\
-----BEGIN PGP SIGNATURE-----

iJEEABYIADkWIQQFoUpBXCb0IW3CVP5S1cxVfXZFhgUCalgSixsUgAAAAAAEAA5t
YW51MiwyLjUrMS4xMiwwLDMACgkQUtXMVX12RYZSgwEApjaQ1o8Z64/lJ2IMy1QS
9vDOv7WAb9OsXcJmdX/tWi8A/3ye0ROFYA3KYZC24AxmN5SciS6jMxgzom8B701c
cjkO
=tExe
-----END PGP SIGNATURE-----
"""

V1_0_0_CERTIFICATE_OPERATOR_01 = """\
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaicdlRYJKwYBBAHaRw8BAQdASq6wUzEfuNKNvntwFp/03obL3Y4vmNMNX/Vf
w+2OolS0GEFsZXggPGFsZXhAc3dhcGxhYnMueHl6Poi1BBMWCgBdFiEEUfVpZF8F
RbDmyEDCNXBSRDzglNgFAmonHZUbFIAAAAAABAAObWFudTIsMi41KzEuMTIsMCwz
AhsDBQkDwmcABQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEDVwUkQ84JTY
OiQBALiDyo9NNa88wYRh8q4XMz0I6YRiprztUWlqTO3qjUG/AP0a1Dzwx5qdnA6q
xjpqaV+8SCBqPrgvwTJrKscRPsY5ALgzBGowHVoWCSsGAQQB2kcPAQEHQAnYUDcI
icdtC6HDNpBOeXoTDuUcPdbR9YpVl1JsCRbxiQELBBgWCgA8FiEEUfVpZF8FRbDm
yEDCNXBSRDzglNgFAmowHVobFIAAAAAABAAObWFudTIsMi41KzEuMTIsMCwzAhsC
AIEJEDVwUkQ84JTYdiAEGRYKAB0WIQQonqPsLxk5okmEhA7SbPwFWG03HgUCajAd
WgAKCRDSbPwFWG03HiaqAPsH1bmU7FG9AMjyeAugx2WFqqL57KhyZXgfP2RP/1+G
8gD/egP0VquaqLWFlkK0e3gLFPTN98XmiT/8sz2osE85mwrHrgD8CQaxJSdQlAcW
bLrb6LJyf3dBQ0/YmAQEoD9aJSnPI7UBAIs12v+xvgiYQ6auqkIT5iSpNlAxCuP3
HrNy/8Oug34H
=Z2fd
-----END PGP PUBLIC KEY BLOCK-----
"""

V1_0_0_CERTIFICATE_OPERATOR_02 = """\
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEajAuPRYJKwYBBAHaRw8BAQdAw58dDd6I2917Pw5S0kXMD5nshTEMSg+wrADr
BXoyu3y0FmRhbiA8ZGFuQHN3YXBsYWJzLnh5ej6IkwQTFgoAOxYhBKdicSk1o/+8
ZSPq66Y3sxUYT4EZBQJqMC49AhsBBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA
AAoJEKY3sxUYT4EZK2kA/3ifb4ST3PDFCFtAiQnNeHMSxwMMJsm6jCbHvIuOVm9D
AQColYYxH2BNXM8nyopSq5Kej11xwzcBSsKe6m3LmtvfDLgzBGowLmoWCSsGAQQB
2kcPAQEHQJGhDsJ0I1PonDunmkJyW77Me6IvrByPzkXKiT5WrTr0iO8EGBYKACAW
IQSnYnEpNaP/vGUj6uumN7MVGE+BGQUCajAuagIbAgCBCRCmN7MVGE+BGXYgBBkW
CgAdFiEEG5WnqgL1UwvbHNkjhwEuYvbME5MFAmowLmoACgkQhwEuYvbME5NSUgEA
kGp4rtltKD2WM96TNkasr4Zz3AB+blkNHBtUw8o/D3IBALnNbJONNFTchs3EDwSF
PwMZ4vZAMOdb6e+uCavnGZMEqBoA/1+5uHkwzesuJuSxZFx94nLCpMwT0UQI5TUW
ZWfJKwaMAQCVLSGFgxCHoawAtsxc9bdO3g7AKHZQPlTnc46H/rfcAg==
=sI4x
-----END PGP PUBLIC KEY BLOCK-----
"""

V1_0_0_CERTIFICATE_OPERATOR_03 = """\
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEajAt9xYJKwYBBAHaRw8BAQdAGE4ypAyD5QfPRFmuH3EINi7GnT5m3NUZmfhC
g/KOBF20IEFuYXRvbGllIDxhbmF0b2xpZUBzd2FwbGFicy54eXo+iK8EExYKAFcW
IQTodf4iPXjiun94W1h7/5wqH7Ui/AUCajAt9xsUgAAAAAAEAA5tYW51MiwyLjUr
MS4xMiwwLDMCGwEFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQe/+cKh+1
IvzeTQEAuJBzn5mQ3f/iT8Cz9BWTGtXks9JukKMXpiT6vCogFl0BAKUyI731NKz1
FtjFDJtUxA+ww85pQTgqdUvrDwlyrPMGuDMEajAuZxYJKwYBBAHaRw8BAQdAMC27
vA4206GT64Aj+DH5mUzRW6Uby7V01a9uPWXeTRaJAQsEGBYKADwWIQTodf4iPXji
un94W1h7/5wqH7Ui/AUCajAuZxsUgAAAAAAEAA5tYW51MiwyLjUrMS4xMiwwLDMC
GwIAgQkQe/+cKh+1Ivx2IAQZFgoAHRYhBAWhSkFcJvQhbcJU/lLVzFV9dkWGBQJq
MC5nAAoJEFLVzFV9dkWGhSUBANUKj3/p69OrPueITk+gJS+JjkpGimp5rlfuGo8k
MiOuAP9UDwct6dHoWQHmirPcm4Q5OYPldnhdZzIivJOdeo5LA+DKAQDGhkkDPWuT
Z3ckIpXQLLTYzK5Kj4jCqc/5VlBfRaB5ugD+MXo4lumaQ+8xmMDMwuB4/7ZvDVzS
IRgu0NVU0YFASg0=
=aKdJ
-----END PGP PUBLIC KEY BLOCK-----
"""

KEYRING: Keyring | None = None
KEYRING_TMP: tempfile.TemporaryDirectory[str] | None = None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        [
            GIT,
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
        encoding="utf8",
    )
    return result.stdout.strip()


def load_tool_module(file_name: str) -> ModuleType:
    """Import a tool of this checkout in-process to exercise its pure helpers."""

    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    module_name = "release_tool_" + file_name.removesuffix(".py").replace("-", "_")
    spec = importlib.util.spec_from_file_location(module_name, TOOLS_DIR / file_name)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def repo_validators() -> object:
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    return tools_common().load_validators(VALIDATORS_DIR)


def tools_common() -> ModuleType:
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    return importlib.import_module("release_staging_common")


def parse_outputs(stdout: str) -> dict[str, list[str]]:
    outputs: dict[str, list[str]] = {}
    for line in stdout.splitlines():
        key, _, value = line.partition("=")
        outputs.setdefault(key, []).append(value)
    return outputs


def write_executable(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf8")
    path.chmod(0o755)
    return path


def make_policy(
    signers: dict[str, str],
    *,
    release_line: str = "testnet",
    release_quorum: int = 2,
    builder_quorum: int = 2,
    revoked: dict[str, str] | None = None,
    effective_from_tag: str = TAG,
) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    for alias, fingerprint in signers.items():
        entries.append(
            {
                "alias": alias,
                "status": "active",
                "key_origin": "qbit-generated",
                "public_key_file": f"public-keys/{alias}-release.asc",
                "signing_fingerprint": fingerprint,
                "release_lines": [release_line],
                "capabilities": ["release-signing", "builder-attestation"],
                "artifact_sets": ["core", "photon"],
                "created": "2026-06-08",
                "first_release": effective_from_tag,
            }
        )
    for alias, fingerprint in (revoked or {}).items():
        entries.append(
            {
                "alias": alias,
                "status": "revoked",
                "key_origin": "external-gpg",
                "public_key_file": f"public-keys/{alias}-release.asc",
                "signing_fingerprint": fingerprint,
                "release_lines": [],
                "capabilities": [],
                "artifact_sets": [],
                "created": "2026-06-08",
                "revocation_date": "2026-06-09",
            }
        )
    return {
        "schema_version": 2,
        "policy_id": f"qbit-release-keys-{release_line}-000001",
        "policy_sequence": 1,
        "previous_policy_sha256": None,
        "effective_from_tag": effective_from_tag,
        "release_lines": {
            release_line: {
                "active_signer_set_size": len(signers),
                "release_signature_quorum": release_quorum,
                "builder_attestation_quorum": builder_quorum,
                "policy_change_quorum": min(2, len(signers)),
            }
        },
        "signers": entries,
    }


def build_trusted_checkout(
    root: Path,
    *,
    policy: dict[str, object],
    certificates: dict[str, str],
    tag: str | None = TAG,
) -> tuple[Path, str]:
    """Create a clean qbit checkout holding the tools, validators and key policy."""

    repo = root / "trusted"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "README.md").write_text("release source\n", encoding="utf8")
    # Like qbit's .gitignore, so bytecode is an ignored file, not an untracked one.
    (repo / ".gitignore").write_text("*.pyc\n__pycache__/\n", encoding="utf8")
    git(repo, "add", "README.md", ".gitignore")
    git(repo, "commit", "-q", "-m", "release source")
    if tag is not None:
        git(repo, "tag", "-a", tag, "-m", tag)
    tools_dir = repo / "contrib" / "release-process"
    tools_dir.mkdir(parents=True)
    for name in TOOL_FILES:
        shutil.copy2(TOOLS_DIR / name, tools_dir / name)
    validators_dir = repo / "ci" / "release"
    validators_dir.mkdir(parents=True)
    for name in VALIDATOR_FILES:
        shutil.copy2(VALIDATORS_DIR / name, validators_dir / name)
    keys_dir = repo / "contrib" / "keys" / "operator-keys"
    (keys_dir / "public-keys").mkdir(parents=True)
    for alias, certificate in certificates.items():
        (keys_dir / "public-keys" / f"{alias}-release.asc").write_text(certificate, encoding="utf8")
    (keys_dir / "keys.json").write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "trusted release ref")
    return repo, git(repo, "rev-parse", "HEAD")


class Keyring:
    """Throwaway signing keys in a private GNUPGHOME.

    SUBKEY_SIGNER mirrors the real operator certificates: a certification-only
    primary key with a signing subkey, which keys.json names. It also carries a
    second, newer signing subkey that GnuPG would pick if the tools did not ask
    for the exact subkey.
    """

    ALIASES = (*OPERATORS, "revoked-01", "outsider-01")
    SUBKEY_SIGNER = "operator-03"

    def __init__(self, root: Path) -> None:
        self.home = root / "secret-gnupg"
        self.home.mkdir(mode=0o700)
        self.fingerprints: dict[str, str] = {}
        self.newer_subkeys: dict[str, str] = {}
        for index, alias in enumerate(self.ALIASES, start=1):
            if alias == self.SUBKEY_SIGNER:
                self.fingerprints[alias] = self.generate_with_subkeys(index, alias)
            else:
                self.fingerprints[alias] = self.generate(index, alias)

    def gpg(self, *args: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [GPG, "--homedir", str(self.home), "--batch", *args],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf8",
        )
        if result.returncode != 0:
            raise AssertionError(f"gpg {' '.join(args)} failed:\n{result.stdout}{result.stderr}")
        return result

    def generate(self, index: int, alias: str) -> str:
        email = f"{alias}@example.invalid"
        batch = self.home.parent / f"{alias}.batch"
        batch.write_text(
            "\n".join(
                [
                    "Key-Type: eddsa",
                    "Key-Curve: ed25519",
                    "Key-Usage: sign",
                    f"Name-Real: qbit release test signer {index}",
                    f"Name-Email: {email}",
                    "Expire-Date: 0",
                    "%no-protection",
                    "%commit",
                    "",
                ]
            ),
            encoding="utf8",
        )
        self.gpg("--generate-key", str(batch))
        listing = self.gpg("--with-colons", "--fingerprint", "--list-keys", email)
        return next(line.split(":")[9] for line in listing.stdout.splitlines() if line.startswith("fpr:"))

    def generate_with_subkeys(self, index: int, alias: str) -> str:
        email = f"{alias}@example.invalid"
        batch = self.home.parent / f"{alias}.batch"
        batch.write_text(
            "\n".join(
                [
                    "Key-Type: eddsa",
                    "Key-Curve: ed25519",
                    "Key-Usage: cert",
                    "Subkey-Type: eddsa",
                    "Subkey-Curve: ed25519",
                    "Subkey-Usage: sign",
                    f"Name-Real: qbit release test signer {index}",
                    f"Name-Email: {email}",
                    "Expire-Date: 0",
                    "%no-protection",
                    "%commit",
                    "",
                ]
            ),
            encoding="utf8",
        )
        self.gpg("--faked-system-time", "20260101T000000!", "--generate-key", str(batch))
        primary = self.colon_fingerprints(email)[0]
        self.gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-add-key", primary, "ed25519", "sign", "0")
        fingerprints = self.colon_fingerprints(email)
        if len(fingerprints) != 3:
            raise AssertionError(f"expected a primary key and two signing subkeys, got {fingerprints}")
        self.newer_subkeys[alias] = fingerprints[2]
        return fingerprints[1]

    def colon_fingerprints(self, email: str) -> list[str]:
        listing = self.gpg("--with-colons", "--with-subkey-fingerprint", "--list-keys", email)
        return [line.split(":")[9] for line in listing.stdout.splitlines() if line.startswith("fpr:")]

    def certificate(self, alias: str) -> str:
        return self.gpg("--armor", "--export", self.fingerprints[alias]).stdout

    def sign(self, alias: str, path: Path, output: Path) -> None:
        self.sign_with(self.fingerprints[alias], path, output)

    def sign_with(self, fingerprint: str, path: Path, output: Path) -> None:
        self.gpg(
            "--yes",
            "--armor",
            "--detach-sign",
            "--local-user",
            fingerprint + "!",
            "--output",
            str(output),
            str(path),
        )

    def close(self) -> None:
        subprocess.run(
            ["gpgconf", "--homedir", str(self.home), "--kill", "all"],
            check=False,
            capture_output=True,
        )


class ReleaseFixture:
    """A trusted checkout, qbit-guix.sigs attestations and builder outputs for TAG."""

    def __init__(self, root: Path, keyring: Keyring, *, builder_quorum: int = 2) -> None:
        self.root = root
        self.keyring = keyring
        operators = {alias: keyring.fingerprints[alias] for alias in OPERATORS}
        self.policy = make_policy(
            operators,
            builder_quorum=builder_quorum,
            revoked={"revoked-01": keyring.fingerprints["revoked-01"]},
        )
        certificates = {alias: keyring.certificate(alias) for alias in (*OPERATORS, "revoked-01")}
        self.trusted, self.ref = build_trusted_checkout(root, policy=self.policy, certificates=certificates)
        self.keys_dir = self.trusted / "contrib" / "keys" / "operator-keys"
        self.tag_target = git(self.trusted, "rev-parse", f"refs/tags/{TAG}^{{commit}}")
        validators = repo_validators()
        self.source_archive = validators.builder_attestations.reconstruct_canonical_source_archive(
            git=GIT,
            source_root=self.trusted,
            tag=TAG,
            expected_tag_target=self.tag_target,
        )
        self.core_output = root / "output"
        self.photon_output = root / "output-photon"
        self.outputs = {
            self.core_output / "x86_64-linux-gnu" / f"qbit-{VERSION}-x86_64-linux-gnu.tar.gz": b"core linux\n",
            self.core_output / "x86_64-linux-gnu" / f"qbit-{VERSION}-x86_64-linux-gnu-debug.tar.gz": b"debug\n",
            self.core_output / "x86_64-w64-mingw32" / f"qbit-{VERSION}-win64-unsigned.zip": b"windows\n",
            self.core_output / "x86_64-w64-mingw32" / f"qbit-{VERSION}-win64-codesigning.tar.gz": b"payload\n",
            self.photon_output / "x86_64-linux-gnu" / f"qbit-photon-{VERSION}-x86_64-linux-gnu.tar.gz": b"photon\n",
        }
        for path, content in self.outputs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        (self.core_output / "src").mkdir()
        (self.core_output / "src" / f"qbit-{VERSION}.tar.gz").write_bytes(b"guix source tarball\n")
        (self.core_output / "x86_64-linux-gnu" / "SHA256SUMS.part").write_text("fragment\n", encoding="utf8")
        self.guix_sigs = root / "guix-sigs"
        for alias in OPERATORS:
            self.attest(alias, "core")
            self.attest(alias, "photon")
        self.stage_dir = root / "staged-release"

    def replace_output(self, path: Path, content: bytes) -> None:
        """Change a builder output and re-attest it for every operator."""

        self.outputs[path] = content
        path.write_bytes(content)
        for alias in OPERATORS:
            self.attest(alias, "core")
            self.attest(alias, "photon")

    def manifest_entries(self, artifact: str) -> dict[str, str]:
        output_dir = self.core_output if artifact == "core" else self.photon_output
        entries = {
            path.name: sha256_hex(content)
            for path, content in self.outputs.items()
            if path.is_relative_to(output_dir)
        }
        entries[self.source_archive.name] = self.source_archive.sha256
        return entries

    def attest(
        self,
        alias: str,
        artifact: str,
        *,
        entries: dict[str, str] | None = None,
        sign_as: str | None = None,
    ) -> Path:
        builder_dir = self.guix_sigs / VERSION / alias
        builder_dir.mkdir(parents=True, exist_ok=True)
        prefix = "" if artifact == "core" else f"{artifact}-"
        manifest = builder_dir / f"{prefix}noncodesigned.SHA256SUMS"
        lines = entries if entries is not None else self.manifest_entries(artifact)
        manifest.write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(lines.items())), encoding="utf8")
        self.keyring.sign(sign_as or alias, manifest, Path(f"{manifest}.asc"))
        return manifest

    def run(
        self,
        tool: str,
        *args: str,
        release_line: str = "testnet",
        gpg: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(self.trusted / "contrib" / "release-process" / tool),
            "--trusted-release-ref",
            self.ref,
            "--release-line",
            release_line,
            *args,
        ]
        if gpg is not None:
            command += ["--gpg", str(gpg)]
        process_env = os.environ.copy()
        process_env.update(env or {})
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf8",
            env=process_env,
        )

    def stage(self, *extra: str, stage_dir: Path | None = None) -> subprocess.CompletedProcess[str]:
        return self.run(
            STAGE_TOOL,
            "--tag",
            TAG,
            "--guix-sigs-dir",
            str(self.guix_sigs),
            "--allow-unsigned-platform-artifacts",
            "--builder-output-dir",
            str(self.core_output),
            "--builder-output-dir",
            str(self.photon_output),
            "--stage-dir",
            str(stage_dir or self.stage_dir),
            *extra,
        )

    def sign(self, alias: str, *extra: str, gpg: Path | None = None) -> subprocess.CompletedProcess[str]:
        return self.run(
            SIGN_TOOL,
            "--stage-dir",
            str(self.stage_dir),
            "--alias",
            alias,
            "--yes",
            *extra,
            gpg=gpg,
            env={"GNUPGHOME": str(self.keyring.home)},
        )

    def combine(self, *extra: str, gpg: Path | None = None) -> subprocess.CompletedProcess[str]:
        return self.run(COMBINE_TOOL, "--stage-dir", str(self.stage_dir), *extra, gpg=gpg)

    def scratch_leftovers(self) -> list[Path]:
        return sorted(self.root.glob(".*.tmp-*"))

    def expected_sha256sums(self) -> bytes:
        names = {
            f"qbit-{VERSION}-x86_64-linux-gnu.tar.gz",
            f"qbit-{VERSION}-x86_64-linux-gnu-debug.tar.gz",
            f"qbit-{VERSION}-win64-unsigned.zip",
            f"qbit-photon-{VERSION}-x86_64-linux-gnu.tar.gz",
        }
        digests = {path.name: sha256_hex(content) for path, content in self.outputs.items()}
        return "".join(f"{digests[name]}  {name}\n" for name in sorted(names)).encode("utf8")


def setUpModule() -> None:
    global KEYRING, KEYRING_TMP
    if not (GPG and GIT):
        return
    KEYRING_TMP = tempfile.TemporaryDirectory(prefix="qbit-release-tools-keys-")
    KEYRING = Keyring(Path(KEYRING_TMP.name))


def tearDownModule() -> None:
    if KEYRING is not None:
        KEYRING.close()
        KEYRING_TMP.cleanup()


@unittest.skipUnless(GPG and GIT, "gpg and git are required for release tool tests")
class ReleaseToolTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="qbit-release-tools-")
        self.root = Path(self.tmp.name)
        assert KEYRING is not None
        self.keyring = KEYRING

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def fixture(self, **kwargs: object) -> ReleaseFixture:
        return ReleaseFixture(self.root, self.keyring, **kwargs)

    def assert_ok(self, result: subprocess.CompletedProcess[str]) -> dict[str, list[str]]:
        self.assertEqual(result.returncode, 0, msg=f"stdout={result.stdout}\nstderr={result.stderr}")
        return parse_outputs(result.stdout)

    def assert_fails(self, result: subprocess.CompletedProcess[str], message: str) -> None:
        self.assertNotEqual(result.returncode, 0, msg=f"unexpected success:\n{result.stdout}")
        self.assertIn(message, result.stderr)

    def gpg_wrapper(self, name: str, body: str) -> Path:
        """Write a gpg stand-in that runs ``body`` and otherwise defers to the real gpg."""

        script = f"#!{sys.executable}\nimport os\nimport sys\nREAL_GPG = {GPG!r}\nargs = sys.argv[1:]\n"
        script += textwrap.dedent(body)
        script += "os.execv(REAL_GPG, [REAL_GPG, *args])\n"
        return write_executable(self.root / "bin" / name, script)


class StageReleaseArtifactsTest(ReleaseToolTestCase):
    def test_stages_counted_attestations_with_publisher_rules(self) -> None:
        fixture = self.fixture()
        result = fixture.stage()
        outputs = self.assert_ok(result)

        sha256sums = (fixture.stage_dir / "SHA256SUMS").read_bytes()
        self.assertEqual(sha256sums, fixture.expected_sha256sums())
        staged = sorted(path.name for path in fixture.stage_dir.iterdir())
        self.assertEqual(
            staged,
            sorted(["SHA256SUMS", *(line.split("  ", 1)[1] for line in sha256sums.decode().splitlines())]),
        )
        self.assertEqual(outputs["status"], ["created"])
        self.assertEqual(outputs["counted_core"], [",".join(OPERATORS)])
        self.assertEqual(outputs["counted_photon"], [",".join(OPERATORS)])
        self.assertEqual(outputs["artifact_count"], ["4"])
        self.assertEqual(outputs["sha256sums_sha256"], [sha256_hex(sha256sums)])
        self.assertEqual(outputs["source_sha256"], [fixture.source_archive.sha256])
        self.assertEqual(outputs["trusted_release_ref"], [fixture.ref])
        self.assertIn(f"not staged: qbit-{VERSION}-win64-codesigning.tar.gz: Codesigning payloads", result.stderr)
        self.assertIn(f"not staged: qbit-{VERSION}.tar.gz: Artifact name does not match", result.stderr)
        self.assertEqual(fixture.scratch_leftovers(), [])
        self.assertEqual(git(fixture.trusted, "status", "--porcelain", "--untracked-files=all"), "")

    def test_unsigned_platform_artifacts_need_the_publisher_waiver(self) -> None:
        fixture = self.fixture()
        sha256sums = self.root / "derived" / "SHA256SUMS"
        outputs = self.assert_ok(
            fixture.run(
                STAGE_TOOL,
                "--tag",
                TAG,
                "--guix-sigs-dir",
                str(fixture.guix_sigs),
                "--sha256sums-output",
                str(sha256sums),
            )
        )
        self.assertNotIn(f"qbit-{VERSION}-win64-unsigned.zip", outputs["artifact"])
        self.assertEqual(outputs["artifact_count"], ["3"])

    def test_sha256sums_only_matches_the_staged_manifest(self) -> None:
        fixture = self.fixture()
        derived = self.root / "derived" / "SHA256SUMS"
        args = ("--tag", TAG, "--guix-sigs-dir", str(fixture.guix_sigs), "--allow-unsigned-platform-artifacts")
        self.assert_ok(fixture.run(STAGE_TOOL, *args, "--sha256sums-output", str(derived)))
        self.assertEqual(derived.read_bytes(), fixture.expected_sha256sums())
        self.assertEqual(
            parse_outputs(fixture.run(STAGE_TOOL, *args, "--sha256sums-output", str(derived)).stdout)["status"],
            ["unchanged"],
        )
        derived.write_bytes(b"different\n")
        self.assert_fails(
            fixture.run(STAGE_TOOL, *args, "--sha256sums-output", str(derived)),
            "already exists with different content",
        )
        self.assertEqual(derived.read_bytes(), b"different\n")

    def test_rerun_is_idempotent_and_never_overwrites_a_different_stage(self) -> None:
        fixture = self.fixture()
        self.assert_ok(fixture.stage())
        before = {path.name: path.read_bytes() for path in fixture.stage_dir.iterdir()}
        self.assertEqual(self.assert_ok(fixture.stage())["status"], ["unchanged"])

        tampered = fixture.stage_dir / f"qbit-{VERSION}-win64-unsigned.zip"
        tampered.write_bytes(b"tampered\n")
        self.assert_fails(fixture.stage(), "already exists and differs")
        self.assertEqual(tampered.read_bytes(), b"tampered\n")

        tampered.write_bytes(before[tampered.name])
        (fixture.stage_dir / "SHA256SUMS").write_bytes(before["SHA256SUMS"] + b"\n")
        self.assert_fails(fixture.stage(), "already exists with a different SHA256SUMS")

    def test_failure_after_partial_copy_leaves_no_stage_behind(self) -> None:
        fixture = self.fixture()
        # The PHOTON artifact sorts last, so every other artifact is already
        # copied into the scratch stage when its digest check fails.
        photon = fixture.photon_output / "x86_64-linux-gnu" / f"qbit-photon-{VERSION}-x86_64-linux-gnu.tar.gz"
        photon.write_bytes(b"not the attested build\n")
        self.assert_fails(fixture.stage(), "does not match the attested digest")
        self.assertFalse(fixture.stage_dir.exists())
        self.assertEqual(fixture.scratch_leftovers(), [])

        photon.write_bytes(fixture.outputs[photon])
        self.assertEqual(self.assert_ok(fixture.stage())["status"], ["created"])

    def test_builder_quorum_is_required(self) -> None:
        fixture = self.fixture()
        for alias in ("operator-02", "operator-03"):
            shutil.rmtree(fixture.guix_sigs / VERSION / alias)
        self.assert_fails(fixture.stage(), "No core upload set reaches the builder-attestation quorum of 2")
        self.assertFalse(fixture.stage_dir.exists())

    def test_attestation_signed_by_the_wrong_key_is_not_counted(self) -> None:
        fixture = self.fixture()
        fixture.attest("operator-02", "core", sign_as="outsider-01")
        result = fixture.stage()
        outputs = self.assert_ok(result)
        self.assertEqual(outputs["counted_core"], ["operator-01,operator-03"])
        self.assertIn("core attestation not counted: operator-02", result.stderr)

        fixture.attest("operator-03", "core", sign_as="outsider-01")
        shutil.rmtree(fixture.stage_dir)
        self.assert_fails(fixture.stage(), "No core upload set reaches the builder-attestation quorum")

    def test_nested_attested_sets_resolve_to_the_quorum_superset(self) -> None:
        fixture = self.fixture()
        partial = fixture.manifest_entries("core")
        del partial[f"qbit-{VERSION}-x86_64-linux-gnu-debug.tar.gz"]
        fixture.attest("operator-03", "core", entries=partial)
        result = fixture.stage()
        outputs = self.assert_ok(result)
        self.assertEqual(outputs["counted_core"], ["operator-01,operator-02"])
        self.assertIn(f"qbit-{VERSION}-x86_64-linux-gnu-debug.tar.gz", outputs["artifact"])
        self.assertIn("operator-03 verifies but does not cover the staged set", result.stderr)

    def test_conflicting_attested_sets_are_refused(self) -> None:
        fixture = self.fixture(builder_quorum=1)
        conflicting = fixture.manifest_entries("core")
        conflicting[f"qbit-{VERSION}-win64-unsigned.zip"] = "0" * 64
        fixture.attest("operator-03", "core", entries=conflicting)
        self.assert_fails(fixture.stage(), "Ambiguous core upload set")
        self.assertFalse(fixture.stage_dir.exists())

    def test_builder_outputs_must_match_the_attested_set(self) -> None:
        fixture = self.fixture()
        extra = fixture.core_output / "riscv64-linux-gnu" / f"qbit-{VERSION}-riscv64-linux-gnu.tar.gz"
        extra.parent.mkdir()
        extra.write_bytes(b"unattested\n")
        self.assert_fails(fixture.stage(), "do not cover: " + str(extra))
        extra.unlink()

        missing = fixture.core_output / "x86_64-linux-gnu" / f"qbit-{VERSION}-x86_64-linux-gnu-debug.tar.gz"
        missing.unlink()
        self.assert_fails(fixture.stage(), f"missing attested artifacts: qbit-{VERSION}-x86_64-linux-gnu-debug.tar.gz")

        missing.symlink_to(fixture.root / "README")
        self.assert_fails(fixture.stage(), "must be a regular file")
        self.assertFalse(fixture.stage_dir.exists())

    def test_inputs_are_validated_at_the_boundary(self) -> None:
        fixture = self.fixture()
        self.assert_fails(fixture.stage("--tag", "1.0.0"), "--tag must be a safe v-prefixed release tag")
        (fixture.guix_sigs / "9.9.9-testnet1").mkdir()
        self.assert_fails(fixture.stage("--tag", "v9.9.9-testnet1"), "Failed to resolve release tag v9.9.9-testnet1")
        self.assert_fails(
            fixture.run(STAGE_TOOL, "--tag", TAG, "--guix-sigs-dir", str(fixture.guix_sigs), "--stage-dir", "x"),
            "--stage-dir requires at least one --builder-output-dir",
        )
        self.assert_fails(
            fixture.stage(stage_dir=fixture.core_output / "staged"),
            "--stage-dir must not overlap the builder output directory",
        )
        self.assert_fails(
            fixture.stage(stage_dir=fixture.root),
            "--stage-dir must not overlap",
        )
        shutil.rmtree(fixture.guix_sigs / VERSION)
        self.assert_fails(fixture.stage(), "qbit-guix.sigs has no attestations for")


class TrustedCheckoutTest(ReleaseToolTestCase):
    def test_tools_require_a_clean_checkout_at_the_trusted_ref(self) -> None:
        fixture = self.fixture()
        self.assert_ok(fixture.stage())
        for tool, args in (
            (STAGE_TOOL, ("--tag", TAG, "--guix-sigs-dir", str(fixture.guix_sigs), "--sha256sums-output", "x")),
            (SIGN_TOOL, ("--stage-dir", str(fixture.stage_dir), "--alias", "operator-01", "--yes")),
            (COMBINE_TOOL, ("--stage-dir", str(fixture.stage_dir))),
        ):
            with self.subTest(tool=tool):
                fixture.ref = "0" * 40
                self.assert_fails(fixture.run(tool, *args), "not --trusted-release-ref")
                fixture.ref = "abc"
                self.assert_fails(fixture.run(tool, *args), "must be a full 40-character commit SHA")
                fixture.ref = git(fixture.trusted, "rev-parse", "HEAD")
                untracked = fixture.trusted / "contrib" / "keys" / "operator-keys" / "vendored-keys.json"
                untracked.write_text("{}\n", encoding="utf8")
                self.assert_fails(fixture.run(tool, *args), "Trusted qbit checkout must be clean")
                untracked.unlink()

    def test_tools_refuse_to_run_outside_the_trusted_checkout(self) -> None:
        fixture = self.fixture()
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        for name in TOOL_FILES:
            shutil.copy2(TOOLS_DIR / name, elsewhere / name)
        result = subprocess.run(
            [sys.executable, str(elsewhere / COMBINE_TOOL), "--trusted-release-ref", fixture.ref,
             "--release-line", "testnet", "--stage-dir", str(self.root)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ERR:", result.stderr)


class SignSha256sumsTest(ReleaseToolTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.release = self.fixture()
        self.digest = self.assert_ok(self.release.stage())["sha256sums_sha256"][0]

    def test_signs_once_with_the_policy_fingerprint_and_verifies(self) -> None:
        result = self.release.sign("operator-02", "--expected-sha256sums-sha256", self.digest)
        outputs = self.assert_ok(result)
        signature = self.release.stage_dir / "SHA256SUMS.operator-02.asc"
        self.assertEqual(outputs["status"], ["created"])
        self.assertEqual(outputs["signer_fpr"], [self.keyring.fingerprints["operator-02"]])
        self.assertEqual(outputs["signature_path"], [str(signature)])
        self.assertEqual(outputs["signature_sha256"], [sha256_hex(signature.read_bytes())])
        data = signature.read_bytes()
        self.assertTrue(data.startswith(b"-----BEGIN PGP SIGNATURE-----\n"))
        self.assertTrue(data.endswith(b"-----END PGP SIGNATURE-----\n"))
        verify = subprocess.run(
            [GPG, "--homedir", str(self.keyring.home), "--batch", "--status-fd", "1", "--verify",
             str(signature), str(self.release.stage_dir / "SHA256SUMS")],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf8",
        )
        self.assertEqual(verify.returncode, 0, msg=verify.stderr)
        self.assertIn(f"VALIDSIG {self.keyring.fingerprints['operator-02']}", verify.stdout)
        self.assertEqual(self.release.scratch_leftovers(), [])

        rerun = self.assert_ok(self.release.sign("operator-02"))
        self.assertEqual(rerun["status"], ["unchanged"])
        self.assertEqual(signature.read_bytes(), data)

    def test_signs_with_the_policy_subkey_not_the_newest_signing_subkey(self) -> None:
        alias = Keyring.SUBKEY_SIGNER
        self.assertNotEqual(self.keyring.newer_subkeys[alias], self.keyring.fingerprints[alias])
        default_choice = self.root / "default-choice.asc"
        self.keyring.gpg(
            "--armor", "--detach-sign", "--local-user", self.keyring.fingerprints[alias],
            "--output", str(default_choice), str(self.release.stage_dir / "SHA256SUMS"),
        )
        verify = self.keyring.gpg(
            "--status-fd", "1", "--verify", str(default_choice), str(self.release.stage_dir / "SHA256SUMS")
        )
        # Without "!", GnuPG signs with the newest signing subkey, which keys.json does not name.
        self.assertIn(f"VALIDSIG {self.keyring.newer_subkeys[alias]}", verify.stdout)

        outputs = self.assert_ok(self.release.sign(alias))
        self.assertEqual(outputs["signer_fpr"], [self.keyring.fingerprints[alias]])
        verify = self.keyring.gpg(
            "--status-fd", "1", "--verify",
            str(self.release.stage_dir / f"SHA256SUMS.{alias}.asc"), str(self.release.stage_dir / "SHA256SUMS"),
        )
        self.assertIn(f"VALIDSIG {self.keyring.fingerprints[alias]}", verify.stdout)

    def test_existing_signature_that_does_not_verify_is_never_replaced(self) -> None:
        signature = self.release.stage_dir / "SHA256SUMS.operator-01.asc"
        self.keyring.sign("outsider-01", self.release.stage_dir / "SHA256SUMS", signature)
        before = signature.read_bytes()
        self.assert_fails(self.release.sign("operator-01"), "already exists and does not verify")
        self.assertEqual(signature.read_bytes(), before)

    def test_refuses_to_sign_a_stage_that_does_not_match_sha256sums(self) -> None:
        (self.release.stage_dir / f"qbit-{VERSION}-win64-unsigned.zip").write_bytes(b"tampered\n")
        self.assert_fails(self.release.sign("operator-01"), "SHA256 mismatch")
        (self.release.stage_dir / f"qbit-{VERSION}-win64-unsigned.zip").write_bytes(b"windows\n")
        (self.release.stage_dir / "notes.txt").write_text("extra\n", encoding="utf8")
        self.assert_fails(self.release.sign("operator-01"), "not covered by SHA256SUMS: notes.txt")
        self.assertEqual(sorted(self.release.stage_dir.glob("SHA256SUMS.*.asc")), [])

    def test_signer_and_digest_inputs_are_checked(self) -> None:
        self.assert_fails(
            self.release.sign("operator-01", "--expected-sha256sums-sha256", "0" * 64),
            "SHA256SUMS SHA-256 mismatch",
        )
        self.assert_fails(
            self.release.sign("operator-01", "--expected-sha256sums-sha256", "xyz"),
            "must be a 64-character hex",
        )
        self.assert_fails(
            self.release.sign("operator-01", "--expected-fingerprint", self.keyring.fingerprints["operator-02"]),
            "not --expected-fingerprint",
        )
        self.assert_fails(self.release.sign("revoked-01"), "is not an active release-signing signer for testnet")
        self.assert_fails(self.release.sign("outsider-01"), "is not an active release-signing signer")
        self.assert_fails(
            self.release.run(SIGN_TOOL, "--stage-dir", str(self.release.stage_dir), "--alias", "operator-01",
                             env={"GNUPGHOME": str(self.keyring.home)}),
            "Signing requires --yes when stdin is not interactive",
        )
        self.assertEqual(sorted(self.release.stage_dir.glob("SHA256SUMS.*.asc")), [])

    def test_failure_after_a_partial_signature_write_leaves_nothing_behind(self) -> None:
        # Another operator's card answers the signing request.
        wrong_key = self.gpg_wrapper(
            "gpg-wrong-key",
            f"""\
            if "--detach-sign" in args:
                args[args.index("--local-user") + 1] = {self.keyring.fingerprints["operator-01"]!r} + "!"
            """,
        )
        partial = self.gpg_wrapper(
            "gpg-partial",
            """\
            if "--detach-sign" in args:
                with open(args[args.index("--output") + 1], "w", encoding="utf8") as output:
                    output.write("-----BEGIN PGP SIGNATURE-----\\n\\npartial")
                sys.exit(2)
            """,
        )
        for wrapper, message in ((wrong_key, "was signed by unexpected fingerprint"), (partial, "gpg failed to sign")):
            with self.subTest(wrapper=wrapper.name):
                self.assert_fails(self.release.sign("operator-03", gpg=wrapper), message)
                self.assertFalse((self.release.stage_dir / "SHA256SUMS.operator-03.asc").exists())
                self.assertEqual(self.release.scratch_leftovers(), [])
        self.assertEqual(self.assert_ok(self.release.sign("operator-03"))["status"], ["created"])


class CombineSha256sumsSignaturesTest(ReleaseToolTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.release = self.fixture()
        self.assert_ok(self.release.stage())
        self.stage_dir = self.release.stage_dir

    def sign_all(self, aliases: tuple[str, ...] = OPERATORS) -> None:
        for alias in aliases:
            self.assert_ok(self.release.sign(alias))

    def test_combined_stage_passes_the_publisher_validators(self) -> None:
        self.sign_all()
        outputs = self.assert_ok(self.release.combine())
        combined = (self.stage_dir / "SHA256SUMS.asc").read_bytes()
        self.assertEqual(
            combined,
            b"".join((self.stage_dir / f"SHA256SUMS.{alias}.asc").read_bytes() for alias in OPERATORS),
        )
        self.assertEqual(outputs["release_signature_aliases"], [",".join(OPERATORS)])
        self.assertEqual(outputs["combined_sha256"], [sha256_hex(combined)])
        self.assertEqual(self.release.scratch_leftovers(), [])
        self.assertEqual(git(self.release.trusted, "status", "--porcelain", "--untracked-files=all"), "")

        keys = self.release.keys_dir
        validate_release = subprocess.run(
            [sys.executable, str(VALIDATORS_DIR / "validate_release_artifacts.py"),
             "--artifacts-dir", str(self.stage_dir), "--tag", TAG, "--release-line", "testnet",
             "--operator-key-policy", str(keys / "keys.json"), "--operator-keys-dir", str(keys),
             "--allow-unsigned-platform-artifacts"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf8",
        )
        self.assertEqual(validate_release.returncode, 0, msg=validate_release.stderr)
        self.assertIn("3/2 release signatures", validate_release.stdout)
        validate_builders = subprocess.run(
            [sys.executable, str(VALIDATORS_DIR / "validate_builder_attestations.py"),
             "--artifacts-dir", str(self.stage_dir), "--tag", TAG, "--source-root", str(self.release.trusted),
             "--expected-tag-target", self.release.tag_target, "--release-line", "testnet",
             "--guix-sigs-repo", str(self.release.guix_sigs), "--operator-key-policy", str(keys / "keys.json"),
             "--operator-keys-dir", str(keys), "--artifact", "core", "--artifact", "photon"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf8",
        )
        self.assertEqual(validate_builders.returncode, 0, msg=validate_builders.stderr)

        self.assertEqual(self.assert_ok(self.release.combine())["status"], ["unchanged"])

    def test_release_signature_quorum_is_required(self) -> None:
        self.sign_all(("operator-01",))
        self.assert_fails(self.release.combine(), "Release signature quorum not met for testnet")
        self.assertFalse((self.stage_dir / "SHA256SUMS.asc").exists())

    def test_every_signature_must_come_from_its_policy_signer(self) -> None:
        self.sign_all(("operator-01", "operator-02"))
        forged = self.stage_dir / "SHA256SUMS.operator-03.asc"
        self.keyring.sign("operator-01", self.stage_dir / "SHA256SUMS", forged)
        self.assert_fails(self.release.combine(), "SHA256SUMS.operator-03.asc was signed by unexpected fingerprint")
        self.keyring.sign("outsider-01", self.stage_dir / "SHA256SUMS", forged)
        self.assert_fails(self.release.combine(), "SHA256SUMS.operator-03.asc does not verify against SHA256SUMS")
        forged.unlink()

        self.keyring.sign("revoked-01", self.stage_dir / "SHA256SUMS", self.stage_dir / "SHA256SUMS.revoked-01.asc")
        self.assert_fails(self.release.combine(), "release signature for non-active release signer")
        (self.stage_dir / "SHA256SUMS.revoked-01.asc").unlink()

        (self.stage_dir / "SHA256SUMS.operator-01.asc.bak").write_bytes(b"backup\n")
        self.assert_fails(self.release.combine(), "Unexpected SHA256SUMS files")
        (self.stage_dir / "SHA256SUMS.operator-01.asc.bak").unlink()

        doubled = self.stage_dir / "SHA256SUMS.operator-02.asc"
        original = doubled.read_bytes()
        doubled.write_bytes(original + original)
        self.assert_fails(self.release.combine(), "exactly one ASCII-armored PGP signature block")
        doubled.write_bytes(original)
        self.assertFalse((self.stage_dir / "SHA256SUMS.asc").exists())

        self.assertEqual(self.assert_ok(self.release.combine())["release_signature_count"], ["2"])

    def test_existing_combined_file_is_kept_only_if_identical(self) -> None:
        self.sign_all(("operator-01", "operator-02"))
        partial = (self.stage_dir / "SHA256SUMS.operator-01.asc").read_bytes()
        (self.stage_dir / "SHA256SUMS.asc").write_bytes(partial)
        self.assert_fails(self.release.combine(), "already exists and differs")
        self.assertEqual((self.stage_dir / "SHA256SUMS.asc").read_bytes(), partial)

    def test_failure_after_writing_the_combined_candidate_leaves_nothing_behind(self) -> None:
        self.sign_all()
        failing = self.gpg_wrapper(
            "gpg-fail-combined",
            """\
            if "--verify" in args and os.path.basename(args[args.index("--verify") + 1]) == "SHA256SUMS.asc":
                sys.exit(2)
            """,
        )
        self.assert_fails(self.release.combine(gpg=failing), "SHA256SUMS.asc does not verify")
        self.assertFalse((self.stage_dir / "SHA256SUMS.asc").exists())
        self.assertEqual(self.release.scratch_leftovers(), [])
        self.assertEqual(self.assert_ok(self.release.combine())["status"], ["created"])


class TrustedCheckoutHardeningTest(ReleaseToolTestCase):
    """What git status does not show must not change what the tools trust."""

    def setUp(self) -> None:
        super().setUp()
        self.release = self.fixture()
        self.assert_ok(self.release.stage())

    def sign_all(self) -> None:
        for alias in OPERATORS:
            self.assert_ok(self.release.sign(alias))

    def test_index_flags_on_release_paths_are_refused(self) -> None:
        keys_json = "contrib/keys/operator-keys/keys.json"
        policy = json.loads((self.release.trusted / keys_json).read_text(encoding="utf8"))
        policy["release_lines"]["testnet"]["release_signature_quorum"] = 1
        git(self.release.trusted, "update-index", "--skip-worktree", keys_json)
        (self.release.trusted / keys_json).write_text(json.dumps(policy), encoding="utf8")
        self.assertEqual(git(self.release.trusted, "status", "--porcelain"), "")
        self.assert_fails(self.release.combine(), "index flags (assume-unchanged or skip-worktree) on: " + keys_json)
        git(self.release.trusted, "update-index", "--no-skip-worktree", keys_json)
        git(self.release.trusted, "checkout", "--", keys_json)

        validator = "ci/release/validate_release_artifacts.py"
        git(self.release.trusted, "update-index", "--assume-unchanged", validator)
        self.assert_fails(self.release.sign("operator-01"), "index flags (assume-unchanged or skip-worktree) on: " + validator)
        git(self.release.trusted, "update-index", "--no-assume-unchanged", validator)
        self.assert_ok(self.release.sign("operator-01"))

    def test_planted_bytecode_beside_the_tools_never_runs(self) -> None:
        source = self.root / "planted.py"
        source.write_text('import sys\nsys.stderr.write("PLANTED-CODE-RAN\\n")\n', encoding="utf8")
        planted = self.release.trusted / "contrib" / "release-process" / "argparse.pyc"
        py_compile.compile(str(source), cfile=str(planted), doraise=True)
        self.assertEqual(git(self.release.trusted, "status", "--porcelain"), "")
        result = self.release.combine()
        self.assertNotIn("PLANTED-CODE-RAN", result.stdout + result.stderr)
        self.assert_fails(result, "must not contain untracked or ignored files: contrib/release-process/argparse.pyc")

    def test_bytecode_left_by_the_publisher_does_not_block_the_tools(self) -> None:
        # Running the publisher's validators from the checkout writes ignored
        # bytecode under ci/release; the tools read the validators from the
        # trusted ref instead, so that bytecode is never loaded or in the way.
        pycache = self.release.trusted / "ci" / "release" / "__pycache__"
        pycache.mkdir()
        (pycache / "validate_release_artifacts.cpython-399.pyc").write_bytes(b"not bytecode")
        self.sign_all()
        self.assert_ok(self.release.combine())


class InterruptedRunTest(ReleaseToolTestCase):
    def signalling_gpg(self, name: str, condition: str, signum: int) -> Path:
        return self.gpg_wrapper(
            name,
            f"""\
            import signal
            import time
            from pathlib import Path
            if {condition}:
                os.kill(os.getppid(), {signum})
                time.sleep(30)
            """,
        )

    def test_sigterm_during_stage_verification_removes_the_scratch_copies(self) -> None:
        fixture = self.fixture()
        wrapper = self.signalling_gpg(
            "gpg-sigterm",
            f'"--verify" in args and any(Path({str(self.root)!r}).glob(".staged-release.tmp-*/SHA256SUMS"))',
            signal.SIGTERM,
        )
        result = fixture.run(
            STAGE_TOOL,
            "--tag", TAG, "--guix-sigs-dir", str(fixture.guix_sigs), "--allow-unsigned-platform-artifacts",
            "--builder-output-dir", str(fixture.core_output), "--builder-output-dir", str(fixture.photon_output),
            "--stage-dir", str(fixture.stage_dir),
            gpg=wrapper,
        )
        self.assertEqual(result.returncode, 128 + signal.SIGTERM, msg=result.stderr)
        self.assertIn("ERR: interrupted by SIGTERM; scratch copies were removed", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(fixture.stage_dir.exists())
        self.assertEqual(fixture.scratch_leftovers(), [])
        self.assertEqual(self.assert_ok(fixture.stage())["status"], ["created"])

    def test_sigint_during_signing_writes_no_signature(self) -> None:
        fixture = self.fixture()
        self.assert_ok(fixture.stage())
        wrapper = self.signalling_gpg("gpg-sigint", '"--detach-sign" in args', signal.SIGINT)
        result = fixture.sign("operator-01", gpg=wrapper)
        self.assertEqual(result.returncode, 128 + signal.SIGINT, msg=result.stderr)
        self.assertIn("ERR: interrupted by SIGINT", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse((fixture.stage_dir / "SHA256SUMS.operator-01.asc").exists())
        self.assertEqual(fixture.scratch_leftovers(), [])

    @unittest.skipUnless(resource is not None, "needs RLIMIT_FSIZE")
    def test_os_error_while_copying_is_reported_without_a_traceback(self) -> None:
        fixture = self.fixture()
        large = fixture.core_output / "x86_64-linux-gnu" / f"qbit-{VERSION}-x86_64-linux-gnu.tar.gz"
        fixture.replace_output(large, b"\0" * (1 << 20))
        limit = 256 * 1024

        def limit_file_size() -> None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

        command = [
            sys.executable, str(fixture.trusted / "contrib" / "release-process" / STAGE_TOOL),
            "--trusted-release-ref", fixture.ref, "--release-line", "testnet",
            "--tag", TAG, "--guix-sigs-dir", str(fixture.guix_sigs), "--allow-unsigned-platform-artifacts",
            "--builder-output-dir", str(fixture.core_output), "--builder-output-dir", str(fixture.photon_output),
            "--stage-dir", str(fixture.stage_dir),
        ]
        result = subprocess.run(
            command, check=False, capture_output=True, text=True, encoding="utf8",
            stdin=subprocess.DEVNULL, preexec_fn=limit_file_size,
        )
        self.assertEqual(result.returncode, 1, msg=result.stderr)
        self.assertIn("File too large", result.stderr)
        self.assertTrue(result.stderr.splitlines()[-1].startswith("ERR: [Errno 27] File too large"), msg=result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(fixture.stage_dir.exists())
        self.assertEqual(fixture.scratch_leftovers(), [])

    def test_scratch_left_by_a_killed_run_is_reported_not_deleted(self) -> None:
        fixture = self.fixture()
        leftover = self.root / ".staged-release.tmp-killed"
        leftover.mkdir()
        result = fixture.stage()
        self.assert_ok(result)
        self.assertIn(f"scratch left by an interrupted run, safe to delete: {leftover}", result.stderr)
        self.assertTrue(leftover.is_dir())


class OutputPublishingTest(ReleaseToolTestCase):
    def test_stage_directory_gets_the_mode_of_a_plain_mkdir(self) -> None:
        fixture = self.fixture()
        self.assert_ok(fixture.stage())
        umask = os.umask(0o022)
        os.umask(umask)
        self.assertEqual(stat.S_IMODE(fixture.stage_dir.stat().st_mode), 0o777 & ~umask)

    def test_fallback_without_hard_links_never_writes_the_destination_in_place(self) -> None:
        common = tools_common()
        source = self.root / "candidate"
        source.write_bytes(b"verified bytes\n")
        destination = self.root / "out" / "SHA256SUMS.asc"
        destination.parent.mkdir()
        no_links = mock.patch.object(common.os, "link", side_effect=PermissionError("no hard links"))

        with no_links, mock.patch.object(common.os, "fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                common.publish_file_no_clobber(source, destination)
        self.assertEqual(sorted(destination.parent.iterdir()), [])

        with no_links:
            common.publish_file_no_clobber(source, destination)
        self.assertEqual(destination.read_bytes(), b"verified bytes\n")
        umask = os.umask(0o022)
        os.umask(umask)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o666 & ~umask)
        self.assertEqual(sorted(path.name for path in destination.parent.iterdir()), ["SHA256SUMS.asc"])

        with no_links, self.assertRaises(common.ReleaseToolError):
            common.publish_file_no_clobber(source, destination)
        self.assertEqual(sorted(path.name for path in destination.parent.iterdir()), ["SHA256SUMS.asc"])

    def test_sign_passes_the_verified_bytes_to_gpg_on_stdin(self) -> None:
        fixture = self.fixture()
        self.assert_ok(fixture.stage())
        manifest = fixture.stage_dir / "SHA256SUMS"
        # A file argument would let gpg read SHA256SUMS a second time.
        stdin_only = self.gpg_wrapper(
            "gpg-stdin-only",
            """\
            if "--detach-sign" in args and args[-2] != "--output":
                sys.exit(5)
            """,
        )
        self.assertEqual(self.assert_ok(fixture.sign("operator-01", gpg=stdin_only))["status"], ["created"])

        swapping = self.gpg_wrapper(
            "gpg-swap-manifest",
            f"""\
            if "--detach-sign" in args:
                os.replace({str(manifest)!r}, {str(manifest)!r} + ".orig")
                with open({str(manifest)!r}, "w", encoding="utf8") as output:
                    output.write("swapped\\n")
            """,
        )
        self.assert_fails(fixture.sign("operator-02", gpg=swapping), "SHA256SUMS changed while it was being signed")
        self.assertFalse((fixture.stage_dir / "SHA256SUMS.operator-02.asc").exists())
        os.replace(f"{manifest}.orig", manifest)


class CombinePublisherParityTest(ReleaseToolTestCase):
    """combine accepts exactly the signature sets that the publisher's check accepts."""

    def publisher_accepts(self, trusted: Path, stage_dir: Path) -> bool:
        vra = repo_validators().release_artifacts
        keys_dir = trusted / "contrib" / "keys" / "operator-keys"
        try:
            policy = vra.load_release_policy(keys_dir / "keys.json", keys_dir, "testnet")
            with tempfile.TemporaryDirectory(prefix="qbit-parity-gnupg-") as home:
                Path(home).chmod(0o700)
                vra.import_release_keys(GPG, Path(home), keys_dir, policy)
                vra.verify_manifest_signatures(GPG, Path(home), stage_dir, policy)
        except vra.ReleaseValidationError:
            return False
        return True

    def run_scenario(self, name: str, signers: dict[str, str], certificates: dict[str, str],
                     signatures: dict[str, str]) -> tuple[bool, bool]:
        root = self.root / name
        root.mkdir()
        policy = make_policy(signers, revoked={"revoked-01": self.keyring.fingerprints["revoked-01"]})
        certificates = {**certificates, "revoked-01": self.keyring.certificate("revoked-01")}
        trusted, ref = build_trusted_checkout(root, policy=policy, certificates=certificates, tag=None)
        stage_dir = root / "stage"
        stage_dir.mkdir()
        (stage_dir / "SHA256SUMS").write_text(f"{'ab' * 32}  qbit-{VERSION}-x86_64-linux-gnu.tar.gz\n", encoding="utf8")
        for alias, fingerprint in signatures.items():
            self.keyring.sign_with(fingerprint, stage_dir / "SHA256SUMS", stage_dir / f"SHA256SUMS.{alias}.asc")
        publisher_dir = root / "publisher"
        shutil.copytree(stage_dir, publisher_dir)
        (publisher_dir / "SHA256SUMS.asc").write_bytes(
            b"".join((stage_dir / f"SHA256SUMS.{alias}.asc").read_bytes() for alias in sorted(signatures))
        )
        combine = subprocess.run(
            [sys.executable, str(trusted / "contrib" / "release-process" / COMBINE_TOOL),
             "--trusted-release-ref", ref, "--release-line", "testnet", "--stage-dir", str(stage_dir)],
            check=False, capture_output=True, text=True, encoding="utf8",
        )
        return combine.returncode == 0, self.publisher_accepts(trusted, publisher_dir)

    def test_combine_and_publisher_agree(self) -> None:
        fingerprints = self.keyring.fingerprints
        operators = {alias: fingerprints[alias] for alias in OPERATORS}
        certificates = {alias: self.keyring.certificate(alias) for alias in OPERATORS}
        scenarios = {
            "all-three": (operators, certificates, operators, True),
            "below-quorum": (operators, certificates, {"operator-01": fingerprints["operator-01"]}, False),
            "another-operators-key": (
                operators, certificates,
                {"operator-01": fingerprints["operator-01"], "operator-03": fingerprints["operator-01"]}, False,
            ),
            "outsider-key": (
                operators, certificates,
                {"operator-01": fingerprints["operator-01"], "operator-03": fingerprints["outsider-01"]}, False,
            ),
            "revoked-signer": (
                operators, certificates,
                {**{alias: operators[alias] for alias in ("operator-01", "operator-02")},
                 "revoked-01": fingerprints["revoked-01"]},
                False,
            ),
        }
        for name, (signers, certs, signatures, expected) in scenarios.items():
            with self.subTest(scenario=name):
                combine_accepts, publisher_accepts = self.run_scenario(name, signers, certs, signatures)
                self.assertEqual(combine_accepts, publisher_accepts)
                self.assertEqual(combine_accepts, expected)

        # Two aliases on signing subkeys of one certificate: whatever the
        # publisher's check decides (counting by primary key rejects it), combine
        # must decide the same, because it runs that same check.
        shared = Keyring.SUBKEY_SIGNER
        signers = {**operators, "operator-02": self.keyring.newer_subkeys[shared]}
        certs = {**certificates, "operator-02": self.keyring.certificate(shared)}
        for name, aliases in (
            ("shared-primary-only", ("operator-02", "operator-03")),
            ("shared-primary-plus-one", ("operator-01", "operator-02", "operator-03")),
        ):
            with self.subTest(scenario=name):
                signatures = {alias: signers[alias] for alias in aliases}
                combine_accepts, publisher_accepts = self.run_scenario(name, signers, certs, signatures)
                self.assertEqual(combine_accepts, publisher_accepts)


@unittest.skipUnless(GPG and GIT, "gpg and git are required for release tool tests")
class V100ReproductionTest(unittest.TestCase):
    """Byte-for-byte reproduction of the published v1.0.0 SHA256SUMS and SHA256SUMS.asc."""

    def test_v1_0_0_sha256sums_follows_from_the_attested_manifests(self) -> None:
        stage = load_tool_module(STAGE_TOOL)
        validators = repo_validators()
        rules = stage.NamingRules(
            tag="v1.0.0",
            release_line="mainnet",
            allow_unsigned_platform_artifacts=True,
            allow_codesigning_artifacts=False,
        )
        parser = validators.builder_attestations.parse_sha256sums
        entries: dict[str, str] = {}
        excluded: set[str] = set()
        with tempfile.TemporaryDirectory(prefix="qbit-v1.0.0-manifests-") as tmp:
            for artifact, manifest_text in (("core", V1_0_0_CORE_MANIFEST), ("photon", V1_0_0_PHOTON_MANIFEST)):
                manifest = Path(tmp) / f"{artifact}.SHA256SUMS"
                manifest.write_text(manifest_text, encoding="utf8")
                selected, skipped = stage.derive_upload_entries(
                    validators, parser(manifest), artifact=artifact, rules=rules
                )
                entries.update(selected)
                excluded.update(skipped)
        rendered = stage.render_sha256sums(entries)
        self.assertEqual(rendered, V1_0_0_SHA256SUMS.encode("utf8"))
        self.assertEqual(sha256_hex(rendered), V1_0_0_SHA256SUMS_SHA256)
        self.assertEqual(len(entries), 19)
        self.assertEqual(
            excluded,
            {
                "qbit-1.0.0.tar.gz",
                "qbit-1.0.0-arm64-apple-darwin-codesigning.tar.gz",
                "qbit-1.0.0-win64-codesigning.tar.gz",
                "qbit-1.0.0-x86_64-apple-darwin-codesigning.tar.gz",
            },
        )

    def test_v1_0_0_combined_signature_is_reproduced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qbit-v1.0.0-combine-") as tmp:
            root = Path(tmp)
            policy = make_policy(
                V1_0_0_SIGNERS,
                release_line="mainnet",
                release_quorum=3,
                builder_quorum=3,
                effective_from_tag="v1.0.0",
            )
            certificates = {
                "operator-01": V1_0_0_CERTIFICATE_OPERATOR_01,
                "operator-02": V1_0_0_CERTIFICATE_OPERATOR_02,
                "operator-03": V1_0_0_CERTIFICATE_OPERATOR_03,
            }
            trusted, ref = build_trusted_checkout(root, policy=policy, certificates=certificates, tag=None)
            stage_dir = root / "v1.0.0"
            stage_dir.mkdir()
            (stage_dir / "SHA256SUMS").write_text(V1_0_0_SHA256SUMS, encoding="utf8")
            signatures = {
                "operator-01": V1_0_0_SIGNATURE_OPERATOR_01,
                "operator-02": V1_0_0_SIGNATURE_OPERATOR_02,
                "operator-03": V1_0_0_SIGNATURE_OPERATOR_03,
            }
            for alias, signature in signatures.items():
                (stage_dir / f"SHA256SUMS.{alias}.asc").write_text(signature, encoding="utf8")
            result = subprocess.run(
                [sys.executable, str(trusted / "contrib" / "release-process" / COMBINE_TOOL),
                 "--trusted-release-ref", ref, "--release-line", "mainnet", "--stage-dir", str(stage_dir),
                 "--expected-sha256sums-sha256", V1_0_0_SHA256SUMS_SHA256],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf8",
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            combined = (stage_dir / "SHA256SUMS.asc").read_bytes()
            self.assertEqual(sha256_hex(combined), V1_0_0_COMBINED_SHA256)
            self.assertEqual(parse_outputs(result.stdout)["combined_sha256"], [V1_0_0_COMBINED_SHA256])


if __name__ == "__main__":
    unittest.main()
