#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that plaintext PQC key records in an encrypted wallet are reported,
refused and re-encrypted on unlock (#283).

The wallet file is built the way v1.0.0 could leave it: a top-up that raced
encryptwallet committed plaintext walletdescriptorpqckey rows, with their
walletdescriptor and cache rows, into the encrypted wallet.
"""

from io import BytesIO
import struct

try:
    import sqlite3
except ImportError:
    pass

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import (
    deser_compact_size,
    hash256,
    ser_compact_size,
    ser_string,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

PASSPHRASE = "passphrase"
PQC_KEY = ser_string(b"walletdescriptorpqckey")
PQC_CKEY = ser_string(b"walletdescriptorpqc_ckey")
REWRITE_RECORD = ser_string(b"postencryptionrewrite")
REWRITE_LOG = "Rewrote the wallet file after encryption"
# The rows a v1.0.0 top-up commits.
TOP_UP_RECORD_TYPES = [ser_string(t) for t in (
    b"walletdescriptor",
    b"walletdescriptorcache",
    b"walletdescriptorlhcache",
    b"walletdescriptorp2mrcache",
    b"walletdescriptorpqckey",
)]
FIRST_COUNTER = 20


def read_rows(path):
    conn = sqlite3.connect(path)
    with conn:
        rows = dict(conn.execute("SELECT key, value FROM main").fetchall())
    conn.close()
    return rows


def record_type(key):
    stream = BytesIO(key)
    length = deser_compact_size(stream)
    return ser_compact_size(length) + stream.read(length)


def parse_plaintext_value(value):
    """Return (secret, sig_counter) of a walletdescriptorpqckey value."""
    stream = BytesIO(value)
    secret = stream.read(deser_compact_size(stream))
    stream.read(32)
    sig_counter = struct.unpack("<I", stream.read(4))[0]
    assert_equal(stream.read(), b"")
    return secret, sig_counter


def plaintext_value(pubkey, secret, sig_counter):
    counter = struct.pack("<I", sig_counter)
    return ser_compact_size(len(secret)) + secret + hash256(pubkey + secret + counter) + counter


def parse_crypted_counter(value):
    stream = BytesIO(value)
    stream.read(deser_compact_size(stream))
    sig_counter = struct.unpack("<I", stream.read(4))[0]
    assert_equal(len(stream.read()), 32)
    return sig_counter


def record_pubkey(key):
    """The serialized pubkey at the end of a PQC key record's key."""
    stream = BytesIO(key)
    stream.read(deser_compact_size(stream))
    stream.read(32)
    return stream.read(deser_compact_size(stream))


class WalletP2MRPlaintextReencryptionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_py_sqlite3()

    def wallet_file(self, name):
        return self.nodes[0].wallets_path / name / self.wallet_data_filename

    def external_p2mr_range(self, wallet):
        for entry in wallet.listdescriptors()["descriptors"]:
            if entry["active"] and not entry["internal"] and entry["desc"].startswith("mr("):
                return entry["range"]
        raise AssertionError("no active external P2MR descriptor")

    def assert_no_file_contains(self, directory, secrets):
        for path in directory.iterdir():
            data = path.read_bytes()
            for secret in secrets:
                assert secret not in data, f"{path.name} still holds a plaintext PQC key"

    def run_test(self):
        node = self.nodes[0]
        funder = node.get_wallet_rpc(self.default_wallet_name)
        self.generate(node, COINBASE_MATURITY + 1)
        backup_dir = node.datadir_path / "backups"
        backup_dir.mkdir()

        self.log.info("Build a v1.0.0-shaped encrypted wallet that holds plaintext PQC key records")
        node.createwallet("original")
        original = node.get_wallet_rpc("original")
        before_backup = backup_dir / "before_top_up.dat"
        original.backupwallet(before_backup)
        old_range = self.external_p2mr_range(original)
        original.keypoolrefill(old_range[1] + 21)
        new_range = self.external_p2mr_range(original)
        assert_greater_than(new_range[1], old_range[1])
        after_backup = backup_dir / "after_top_up.dat"
        original.backupwallet(after_backup)
        node.unloadwallet("original")

        before_rows = read_rows(before_backup)
        changed = {k: v for k, v in read_rows(self.wallet_file("original")).items() if before_rows.get(k) != v}
        stale_rows = {k: v for k, v in changed.items() if record_type(k) in TOP_UP_RECORD_TYPES}
        self.log.debug(f"Ignoring changed rows of types {sorted({record_type(k) for k in changed} - set(TOP_UP_RECORD_TYPES))}")

        # Give each plaintext record its own counter, so the test can tell
        # whether re-encryption keeps it.
        secrets = []
        counters = {}
        for counter, key in enumerate(sorted(k for k in stale_rows if record_type(k) == PQC_KEY), start=FIRST_COUNTER):
            secret, _ = parse_plaintext_value(stale_rows[key])
            stale_rows[key] = plaintext_value(record_pubkey(key), secret, counter)
            secrets.append(secret)
            counters[key] = counter
        assert_greater_than(len(counters), 20)

        # An address at the first index the stale top-up added.
        node.restorewallet("scratch", after_backup)
        scratch = node.get_wallet_rpc("scratch")
        self.wait_pqc_key_validation_ready(scratch)
        for _ in range(old_range[1] + 1):
            scratch.getnewaddress(address_type="p2mr")
        affected_address = scratch.getnewaddress(address_type="p2mr")
        node.unloadwallet("scratch")

        node.restorewallet("affected", before_backup)
        affected = node.get_wallet_rpc("affected")
        self.wait_pqc_key_validation_ready(affected)
        affected.encryptwallet(PASSPHRASE)
        node.unloadwallet("affected")
        conn = sqlite3.connect(self.wallet_file("affected"))
        with conn:
            conn.executemany("INSERT OR REPLACE INTO main VALUES(?, ?)", stale_rows.items())
            # v1.0.0 does not record the rewrite after encryption.
            conn.execute("DELETE FROM main WHERE key = ?", (REWRITE_RECORD,))
        conn.close()
        # Loading rewrites the file, but the plaintext records are still live.
        with node.assert_debug_log([REWRITE_LOG]):
            node.loadwallet("affected")
        affected = node.get_wallet_rpc("affected")

        self.log.info("The wallet reports the plaintext records before it is unlocked")
        self.wait_until(lambda: affected.getwalletinfo()["pqc_key_validation"]["status"] == "complete")
        validation = affected.getwalletinfo()["pqc_key_validation"]
        assert_equal(validation["plaintext_records"], len(counters))
        assert_equal(validation["reencryption_required"], True)
        assert_equal(validation["signing_blocked"], True)
        assert_equal(validation["encryption_recommended"], False)
        assert_equal(affected.getwalletinfo()["unlocked_until"], 0)

        address_info = affected.getaddressinfo(affected_address)
        assert_equal(address_info["ismine"], True)
        counter = address_info["pqc_signature_count"]
        assert counter in counters.values()

        self.log.info("Signing fails closed with an error that names the cause and the remedy")
        funder.sendtoaddress(affected_address, 5)
        self.generate(node, 1)
        assert_equal(affected.getbalances()["mine"]["trusted"], 5)
        assert_raises_rpc_error(-4, "this encrypted wallet still stores PQC private keys unencrypted", affected.send, {funder.getnewaddress(): 1})
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase with walletpassphrase first", affected.sendtoaddress, funder.getnewaddress(), 1)

        # A backup made now keeps the plaintext keys whatever happens later.
        old_backup = backup_dir / "affected_before_unlock.dat"
        affected.backupwallet(old_backup)
        assert all(secret in old_backup.read_bytes() for secret in secrets)

        self.log.info("Unlocking re-encrypts every plaintext record and rewrites the file")
        with node.assert_debug_log([f"Re-encrypted {len(counters)} plaintext PQC key records", REWRITE_LOG]):
            affected.walletpassphrase(PASSPHRASE, 600)
        validation = affected.getwalletinfo()["pqc_key_validation"]
        assert_equal(validation["status"], "not_required")
        assert_equal(validation["plaintext_records"], 0)
        assert_equal(validation["reencryption_required"], False)
        assert_equal(validation["signing_blocked"], False)
        assert_equal(affected.getaddressinfo(affected_address)["pqc_signature_count"], counter)
        self.assert_no_file_contains(self.wallet_file("affected").parent, secrets)
        affected.walletlock()

        node.unloadwallet("affected")
        rows = read_rows(self.wallet_file("affected"))
        assert not any(record_type(k) == PQC_KEY for k in rows)
        assert REWRITE_RECORD in rows
        for key, expected in counters.items():
            assert_equal(parse_crypted_counter(rows[PQC_CKEY + key[len(PQC_KEY):]]), expected)

        self.log.info("After a reload the key signs from its preserved counter")
        with node.assert_debug_log([], unexpected_msgs=[REWRITE_LOG]):
            node.loadwallet("affected")
        affected = node.get_wallet_rpc("affected")
        assert_equal(affected.getwalletinfo()["pqc_key_validation"]["reencryption_required"], False)
        affected.walletpassphrase(PASSPHRASE, 600)
        result = affected.sendall([funder.getnewaddress()])
        assert_equal(result["complete"], True)
        self.generate(node, 1)
        assert_equal(affected.getbalances()["mine"]["trusted"], 0)
        assert_equal(affected.getaddressinfo(affected_address)["pqc_signature_count"], counter + 1)
        node.unloadwallet("affected")
        rows = read_rows(self.wallet_file("affected"))
        assert not any(record_type(k) == PQC_KEY for k in rows)

        # The backup taken before the unlock still holds the plaintext keys.
        assert_equal(sum(record_type(k) == PQC_KEY for k in read_rows(old_backup)), len(counters))


if __name__ == '__main__':
    WalletP2MRPlaintextReencryptionTest(__file__).main()
