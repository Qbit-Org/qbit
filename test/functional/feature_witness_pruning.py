#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise explicit witness pruning against archive-by-default nodes."""

import hashlib
import http.client
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY, create_block, create_coinbase
from test_framework.messages import (
    CBlock,
    CBlockHeader,
    CInv,
    MSG_BLOCK,
    MSG_WITNESS_BLOCK,
    NODE_ARCHIVE,
    NODE_WITNESS_PRUNED,
    from_hex,
    msg_getdata,
    msg_headers,
    msg_no_witness_block,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    assert_not_equal,
    assert_raises_rpc_error,
    ensure_for,
)
from test_framework.wallet import MiniWallet


WITNESS_PRUNE_DEPTH = COINBASE_MATURITY
VERBOSE_WITNESS_PRUNED_ERROR = (
    "Verbose block view unavailable: witness data for this historical block was pruned; "
    "use verbosity=0 to fetch stored block bytes."
)
RAWTX_WITNESS_PRUNED_ERROR = (
    "Raw transaction unavailable: witness data for this historical block was pruned; "
    "use an archive node with full witness history."
)


class WitnessPrunePeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.lastgetdata = []

    def on_inv(self, message):
        pass

    def on_getdata(self, message):
        self.lastgetdata = message.inv

    def request_block(self, block_hash, inv_type):
        with p2p_lock:
            self.last_message.pop("block", None)
            self.last_message.pop("notfound", None)
        self.send_and_ping(msg_getdata(inv=[CInv(inv_type, int(block_hash, 16))]))

    def announce_block_and_wait_for_getdata(self, block, *, timeout=60):
        with p2p_lock:
            self.last_message.pop("getdata", None)
        headers = msg_headers()
        headers.headers = [CBlockHeader(block)]
        self.send_and_ping(headers, timeout=timeout)
        self.wait_for_getdata([block.hash_int], timeout=timeout)

    def wait_for_notfound(self, block_hash, *, timeout=10):
        target = int(block_hash, 16)

        def received_notfound():
            msg = self.last_message.get("notfound")
            if msg is None:
                return False
            return any(inv.hash == target for inv in msg.vec)

        self.wait_until(received_notfound, timeout=timeout)


def snapshot_blk_sizes(blocks_path: Path):
    return {p.name: p.stat().st_size for p in blocks_path.glob("blk[0-9][0-9][0-9][0-9][0-9].dat")}


def snapshot_dir_state(path: Path):
    if not path.exists():
        return None
    return sorted(
        (
            str(p.relative_to(path)),
            p.stat().st_size,
            hashlib.sha256(p.read_bytes()).hexdigest(),
        )
        for p in path.rglob("*")
        if p.is_file()
    )


class WitnessPruningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.rpc_timeout = 600
        # Use fastprune so compaction has many small files to process in this test.
        self.extra_args = [
            ["-fastprune", "-prunewitnesses=1"],
            ["-fastprune"],
            ["-fastprune", "-test=disable_witness_pruning"],
            ["-fastprune"],
        ]

    def mine_blocks_with_witness_txs(self, node, wallet, count):
        mined = []
        for _ in range(count):
            tx = wallet.send_self_transfer(from_node=node)
            block_hash = self.generate(node, 1, sync_fun=self.no_op)[0]
            mined.append((block_hash, tx["txid"], tx["hex"]))
        return mined

    @staticmethod
    def assert_stripped_matches_no_witness(stripped_hex, full_hex):
        full_block = from_hex(CBlock(), full_hex)
        full_witness = full_block.serialize()
        full_no_witness = full_block.serialize(False)
        assert_not_equal(full_witness, full_no_witness)
        assert_equal(bytes.fromhex(stripped_hex), full_no_witness)

    def assert_pruned_or_full(self, maybe_stripped_hex, full_hex):
        if maybe_stripped_hex == full_hex:
            return
        self.assert_stripped_matches_no_witness(maybe_stripped_hex, full_hex)

    @staticmethod
    def find_block_file(blocks_path: Path, block_hex: str) -> Path:
        block_bytes = bytes.fromhex(block_hex)
        obfuscation_key = (blocks_path / "xor.dat").read_bytes()
        for path in sorted(blocks_path.glob("blk[0-9][0-9][0-9][0-9][0-9].dat")):
            file_bytes = path.read_bytes()
            if obfuscation_key:
                file_bytes = bytes(
                    byte ^ obfuscation_key[offset % len(obfuscation_key)]
                    for offset, byte in enumerate(file_bytes)
                )
            if block_bytes in file_bytes:
                return path
        raise AssertionError("unable to locate block bytes in blk files")

    @staticmethod
    def assert_verbose_block_equal(left_node, right_node, block_hash, verbosity):
        assert_equal(left_node.getblock(block_hash, verbosity), right_node.getblock(block_hash, verbosity))

    @staticmethod
    def get_bestblockhash_resilient(node):
        try:
            return node.getbestblockhash()
        except (BrokenPipeError, ConnectionResetError, http.client.RemoteDisconnected):
            node.rpc_connected = False
            node.wait_for_rpc_connection(wait_for_import=False)
            return node.getbestblockhash()

    @staticmethod
    def is_witness_pruned_block(node, block_hash):
        try:
            node.getblock(block_hash, 1)
        except JSONRPCException as e:
            return VERBOSE_WITNESS_PRUNED_ERROR in e.error["message"]
        return False

    def assert_reindex_chainstate_assumevalid_fails_without_wipe(
        self,
        node,
        assumevalid_hash,
        expected_msg,
        snapshot_path=None,
    ):
        chainstate_path = node.chain_path / "chainstate"
        chainstate_before = snapshot_dir_state(chainstate_path)
        snapshot_before = snapshot_dir_state(snapshot_path) if snapshot_path else None
        log_pos = node.debug_log_path.stat().st_size if node.debug_log_path.exists() else 0

        extra_args = ["-fastprune", "-reindex-chainstate"]
        if assumevalid_hash is not None:
            extra_args.append(f"-assumevalid={assumevalid_hash}")
        node.assert_start_raises_init_error(
            extra_args=extra_args,
            expected_msg=expected_msg,
            match=ErrorMatch.PARTIAL_REGEX,
        )

        assert_equal(snapshot_dir_state(chainstate_path), chainstate_before)
        if snapshot_path is not None:
            assert_equal(snapshot_dir_state(snapshot_path), snapshot_before)

        with node.debug_log_path.open("rb") as debug_log:
            debug_log.seek(log_pos)
            new_log = debug_log.read().decode("utf-8", errors="replace")
        assert "Wiping LevelDB" not in new_log
        assert "[snapshot] deleting snapshot chainstate due to reindexing" not in new_log

    def run_test(self):
        pruned_node = self.nodes[0]
        archive_node = self.nodes[1]
        disabled_node = self.nodes[2]
        ibd_node = self.nodes[3]

        self.log.info("Guard: -txindex is incompatible with explicit witness pruning")
        self.stop_node(0)
        pruned_node.assert_start_raises_init_error(
            extra_args=["-fastprune", "-prunewitnesses=1", "-txindex=1"],
            expected_msg=(
                "Error: Witness pruning is incompatible with -txindex. "
                "Disable -prunewitnesses to keep txindex-backed full transaction history."
            ),
        )
        self.start_node(0, extra_args=self.extra_args[0])
        pruned_node = self.nodes[0]
        self.connect_nodes(1, 0)

        wallet = MiniWallet(pruned_node)
        self.disconnect_nodes(2, 3)

        self.log.info("Check service flag signaling before any witness compaction")
        pruned_services = pruned_node.getnetworkinfo()
        archive_services = archive_node.getnetworkinfo()
        disabled_services = disabled_node.getnetworkinfo()
        assert (int(pruned_services["localservices"], 16) & NODE_WITNESS_PRUNED) == 0
        assert int(pruned_services["localservices"], 16) & NODE_ARCHIVE
        assert "WITNESS_PRUNED" not in pruned_services["localservicesnames"]
        assert "ARCHIVE" in pruned_services["localservicesnames"]
        assert (int(archive_services["localservices"], 16) & NODE_WITNESS_PRUNED) == 0
        assert int(archive_services["localservices"], 16) & NODE_ARCHIVE
        assert "WITNESS_PRUNED" not in archive_services["localservicesnames"]
        assert "ARCHIVE" in archive_services["localservicesnames"]
        assert (int(disabled_services["localservices"], 16) & NODE_WITNESS_PRUNED) == 0
        assert int(disabled_services["localservices"], 16) & NODE_ARCHIVE
        assert "WITNESS_PRUNED" not in disabled_services["localservicesnames"]
        assert "ARCHIVE" in disabled_services["localservicesnames"]

        self.log.info("Mine maturity blocks so MiniWallet has spendable UTXOs")
        self.generate(wallet, WITNESS_PRUNE_DEPTH + 5, sync_fun=self.no_op)
        self.sync_blocks(self.nodes[:3])

        start_height = pruned_node.getblockcount()
        self.log.info("Mine witness-bearing blocks, then mine forward enough to make them prunable")
        witness_blocks = self.mine_blocks_with_witness_txs(pruned_node, wallet, 300)
        before_sizes = snapshot_blk_sizes(pruned_node.blocks_path)
        self.generate(pruned_node, 900, sync_fun=self.no_op)
        self.sync_blocks(self.nodes[:3])

        self.log.info("Verify at least one historical blk file was compacted")
        after_sizes = snapshot_blk_sizes(pruned_node.blocks_path)
        assert any(
            name in after_sizes and after_sizes[name] < size
            for name, size in before_sizes.items()
        )

        pruned_height = start_height + 20
        pruned_hash, pruned_txid, pruned_tx_hex = witness_blocks[pruned_height - start_height - 1]
        assert_equal(pruned_hash, pruned_node.getblockhash(pruned_height))
        tip_height = pruned_node.getblockcount()
        assert tip_height - pruned_height > WITNESS_PRUNE_DEPTH

        self.log.info("Wait for a prunable block to be stripped on witness-pruning node")
        def witness_stripped():
            node0_raw = pruned_node.getblock(pruned_hash, False)
            node1_raw = archive_node.getblock(pruned_hash, False)
            try:
                self.assert_stripped_matches_no_witness(node0_raw, node1_raw)
            except AssertionError:
                return False
            return True

        self.wait_until(witness_stripped, timeout=120)
        pruned_raw = pruned_node.getblock(pruned_hash, False)
        compacted_blk_path = self.find_block_file(pruned_node.blocks_path, pruned_raw)
        assert_equal(disabled_node.getblock(pruned_hash, False), archive_node.getblock(pruned_hash, False))

        self.log.info("Service flag flips on once historical witness data has been compacted")
        pruned_services = pruned_node.getnetworkinfo()
        assert int(pruned_services["localservices"], 16) & NODE_WITNESS_PRUNED
        assert_equal(int(pruned_services["localservices"], 16) & NODE_ARCHIVE, 0)
        assert "WITNESS_PRUNED" in pruned_services["localservicesnames"]
        assert "ARCHIVE" not in pruned_services["localservicesnames"]

        self.log.info("Verbose getblock rejects witness-pruned history but stays canonical on full-history peers")
        for verbosity in range(1, 4):
            assert_raises_rpc_error(-1, VERBOSE_WITNESS_PRUNED_ERROR, pruned_node.getblock, pruned_hash, verbosity)
            self.assert_verbose_block_equal(disabled_node, archive_node, pruned_hash, verbosity)

        self.log.info("getrawtransaction rejects witness-pruned historical transactions")
        for verbosity in [False, True, 2]:
            assert_raises_rpc_error(
                -1,
                RAWTX_WITNESS_PRUNED_ERROR,
                pruned_node.getrawtransaction,
                pruned_txid,
                verbosity,
                pruned_hash,
            )
        archive_tx = archive_node.getrawtransaction(pruned_txid, True, pruned_hash)
        assert_equal(archive_tx["hex"], pruned_tx_hex)
        assert "txinwitness" in archive_tx["vin"][0]
        assert_equal(archive_node.getrawtransaction(pruned_txid, False, pruned_hash), pruned_tx_hex)

        self.log.info("Recent blocks should still keep witness data")
        recent_hash = pruned_node.getblockhash(tip_height - 10)
        recent_pruned_raw = pruned_node.getblock(recent_hash, False)
        recent_archive_raw = archive_node.getblock(recent_hash, False)
        assert_equal(recent_pruned_raw, recent_archive_raw)
        for verbosity in range(1, 4):
            self.assert_verbose_block_equal(pruned_node, archive_node, recent_hash, verbosity)

        self.log.info("Startup recovers a recoverable .wpruned temp file before blk-file checks")
        self.stop_node(0)
        compacted_blk_bytes = compacted_blk_path.read_bytes()
        recoverable_temp_path = compacted_blk_path.with_suffix(compacted_blk_path.suffix + ".wpruned")
        compacted_blk_path.rename(recoverable_temp_path)
        assert not compacted_blk_path.exists()
        assert recoverable_temp_path.exists()

        self.start_node(0, extra_args=self.extra_args[0])
        pruned_node = self.nodes[0]
        assert compacted_blk_path.exists()
        assert not recoverable_temp_path.exists()
        assert_equal(compacted_blk_path.read_bytes(), compacted_blk_bytes)
        self.assert_stripped_matches_no_witness(pruned_node.getblock(pruned_hash, False), archive_node.getblock(pruned_hash, False))

        self.log.info("Startup finalizes a post-commit witness compaction backup cleanup")
        self.stop_node(0)
        rollback_backup_path = compacted_blk_path.with_suffix(compacted_blk_path.suffix + ".wfull")
        rollback_backup_path.write_bytes(b"full-backup")
        assert rollback_backup_path.exists()

        self.start_node(0, extra_args=self.extra_args[0])
        pruned_node = self.nodes[0]
        assert compacted_blk_path.exists()
        assert not rollback_backup_path.exists()
        self.assert_stripped_matches_no_witness(pruned_node.getblock(pruned_hash, False), archive_node.getblock(pruned_hash, False))

        self.log.info("Boundary checks at prune depth n-1/n/n+1")
        cutoff_height = tip_height - WITNESS_PRUNE_DEPTH
        assert cutoff_height > 1
        height_n_plus_1 = cutoff_height + 1
        height_n = cutoff_height
        height_n_minus_1 = cutoff_height - 1

        hash_n_plus_1 = pruned_node.getblockhash(height_n_plus_1)
        hash_n = pruned_node.getblockhash(height_n)
        hash_n_minus_1 = pruned_node.getblockhash(height_n_minus_1)

        # n+1 is still inside the retention window and must match archive bytes.
        assert_equal(pruned_node.getblock(hash_n_plus_1, False), archive_node.getblock(hash_n_plus_1, False))

        # n and n-1 are outside the retention window. Compaction is file-granular,
        # so these blocks can be either full (not yet compacted) or stripped.
        self.assert_pruned_or_full(pruned_node.getblock(hash_n, False), archive_node.getblock(hash_n, False))
        self.assert_pruned_or_full(pruned_node.getblock(hash_n_minus_1, False), archive_node.getblock(hash_n_minus_1, False))

        # Disabled mode keeps witness bytes in historical blocks.
        assert_equal(disabled_node.getblock(hash_n, False), archive_node.getblock(hash_n, False))
        assert_equal(disabled_node.getblock(hash_n_minus_1, False), archive_node.getblock(hash_n_minus_1, False))

        self.log.info("P2P semantics: MSG_WITNESS_BLOCK -> NOTFOUND, MSG_BLOCK -> stripped block")
        peer = pruned_node.add_p2p_connection(WitnessPrunePeer())

        peer.request_block(pruned_hash, MSG_WITNESS_BLOCK)
        peer.wait_for_notfound(pruned_hash, timeout=10)

        peer.request_block(pruned_hash, MSG_BLOCK)
        peer.wait_for_block(int(pruned_hash, 16), timeout=10)
        served_block = peer.last_message["block"].block.serialize(False)
        assert_equal(served_block, bytes.fromhex(pruned_node.getblock(pruned_hash, False)))

        self.log.info("Negative gate: stripped blocks requested with witness data are rejected")
        self.disconnect_nodes(0, 1)
        detached_tip_hash = archive_node.getbestblockhash()
        detached_block_hash = self.generate(archive_node, 1, sync_fun=self.no_op)[0]
        detached_block = from_hex(CBlock(), archive_node.getblock(detached_block_hash, False))
        assert_not_equal(detached_block.serialize(), detached_block.serialize(False))

        peer.announce_block_and_wait_for_getdata(detached_block)
        with p2p_lock:
            assert_equal(len(peer.lastgetdata), 1)
            assert_equal(peer.lastgetdata[0].type, MSG_WITNESS_BLOCK)
        with pruned_node.assert_debug_log(expected_msgs=["bad-witness-nonce-size"]):
            peer.send_without_ping(msg_no_witness_block(detached_block))
            peer.wait_for_disconnect(timeout=10)
        assert_not_equal(pruned_node.getbestblockhash(), detached_block_hash)

        archive_node.invalidateblock(detached_block_hash)
        assert_equal(archive_node.getbestblockhash(), detached_tip_hash)
        self.connect_nodes(0, 1)
        self.sync_blocks([pruned_node, archive_node])

        self.log.info("Find the highest witness-pruned block for reindex-chainstate guard boundaries")
        highest_witness_pruned_height = next(
            height
            for height in range(tip_height, 0, -1)
            if self.is_witness_pruned_block(pruned_node, pruned_node.getblockhash(height))
        )
        highest_witness_pruned_hash = pruned_node.getblockhash(highest_witness_pruned_height)
        first_unpruned_after_witness_pruned_hash = pruned_node.getblockhash(highest_witness_pruned_height + 1)
        assert self.is_witness_pruned_block(pruned_node, highest_witness_pruned_hash)
        assert not self.is_witness_pruned_block(pruned_node, first_unpruned_after_witness_pruned_hash)
        assert pruned_height < highest_witness_pruned_height

        self.log.info("Create a known off-best-header-chain hash for the reindex-chainstate assumevalid guard")
        side_parent_height = tip_height - 2
        side_parent_hash = pruned_node.getblockhash(side_parent_height)
        side_parent_header = pruned_node.getblockheader(side_parent_hash)
        offchain_block = create_block(
            int(side_parent_hash, 16),
            create_coinbase(side_parent_height + 1),
            side_parent_header["time"] + 1,
        )
        offchain_block.solve()
        offchain_assumevalid_hash = offchain_block.hash_hex
        pruned_node.submitheader(CBlockHeader(offchain_block).serialize().hex())
        assert_equal(pruned_node.getblockheader(offchain_assumevalid_hash)["hash"], offchain_assumevalid_hash)

        self.log.info("Guard: -txindex on a witness-pruned datadir should fail")
        self.stop_node(0)
        pruned_node.assert_start_raises_init_error(
            extra_args=["-fastprune", "-txindex=1"],
            expected_msg=(
                "Error: Cannot use -txindex on a node that has pruned witness data. "
                "Delete the data directory and perform a fresh archive sync, or restart without -txindex."
            ),
        )

        self.log.info("Guard: -reindex on a witness-pruned node should fail")
        pruned_node.assert_start_raises_init_error(
            extra_args=["-fastprune", "-reindex"],
            expected_msg=(
                "Error: Cannot use -reindex on a node that has pruned witness data. "
                "Witness-pruned block index flags would be lost, causing data corruption. "
                "Use -reindex-chainstate instead, or delete the data directory and perform a fresh sync."
            ),
        )

        self.log.info("Guard: -reindex-chainstate without assumevalid should fail before chainstate wipe")
        self.assert_reindex_chainstate_assumevalid_fails_without_wipe(
            pruned_node,
            assumevalid_hash=None,
            expected_msg=(
                "Error: Cannot use -reindex-chainstate on a witness-pruned node without "
                "-assumevalid=<hash>"
            ),
        )

        self.log.info("Guard: unusable assumevalid values should fail before chainstate or snapshot wipe")
        snapshot_path = pruned_node.chain_path / "chainstate_snapshot"
        assert not snapshot_path.exists()
        snapshot_path.mkdir()
        (snapshot_path / "base_blockhash").write_bytes(b"z" * 32)
        unknown_hash = "1".zfill(64)
        below_pruned_range_hash = archive_node.getblockhash(start_height)
        self.assert_reindex_chainstate_assumevalid_fails_without_wipe(
            pruned_node,
            assumevalid_hash=unknown_hash,
            expected_msg="Error: Cannot use -reindex-chainstate on a witness-pruned node with unknown -assumevalid block",
            snapshot_path=snapshot_path,
        )
        self.assert_reindex_chainstate_assumevalid_fails_without_wipe(
            pruned_node,
            assumevalid_hash=offchain_assumevalid_hash,
            expected_msg=(
                "Error: Cannot use -reindex-chainstate on a witness-pruned node with "
                f"-assumevalid={offchain_assumevalid_hash} because that block is not on the best-header chain"
            ),
            snapshot_path=snapshot_path,
        )
        self.assert_reindex_chainstate_assumevalid_fails_without_wipe(
            pruned_node,
            assumevalid_hash=below_pruned_range_hash,
            expected_msg="Error: Cannot use -reindex-chainstate on a witness-pruned node with -assumevalid=.*does not cover witness-pruned block",
            snapshot_path=snapshot_path,
        )
        self.assert_reindex_chainstate_assumevalid_fails_without_wipe(
            pruned_node,
            assumevalid_hash=pruned_hash,
            expected_msg="Error: Cannot use -reindex-chainstate on a witness-pruned node with -assumevalid=.*does not cover witness-pruned block",
            snapshot_path=snapshot_path,
        )
        (snapshot_path / "base_blockhash").unlink()
        snapshot_path.rmdir()

        self.log.info("Guard: -reindex-chainstate with assumevalid at the highest witness-pruned block succeeds")
        self.start_node(0, extra_args=["-fastprune", "-reindex-chainstate", f"-assumevalid={highest_witness_pruned_hash}"])
        pruned_node = self.nodes[0]
        assert_equal(pruned_node.getblockcount(), tip_height)

        self.log.info("Guard: -reindex-chainstate with assumevalid immediately above the pruned range succeeds")
        self.stop_node(0)
        assumevalid_hash = first_unpruned_after_witness_pruned_hash
        self.start_node(0, extra_args=["-fastprune", "-reindex-chainstate", f"-assumevalid={assumevalid_hash}"])
        pruned_node = self.nodes[0]
        assert_equal(pruned_node.getblockcount(), tip_height)

        self.log.info("IBD from only a witness-pruned peer stalls until an archive peer is added")
        self.restart_node(3, extra_args=["-fastprune", f"-assumevalid={assumevalid_hash}"])
        ibd_node = self.nodes[3]
        self.connect_nodes(0, 3)
        self.wait_until(
            lambda: ibd_node.getpeerinfo() and max(peer["synced_headers"] for peer in ibd_node.getpeerinfo()) >= tip_height,
            timeout=60,
        )
        self.wait_until(
            lambda: (
                ibd_node.getpeerinfo()
                and ibd_node.getblockcount() < tip_height
                and not ibd_node.getpeerinfo()[0]["inflight"]
            ),
            timeout=120,
        )
        stalled_height = ibd_node.getblockcount()
        ensure_for(
            duration=5,
            check_interval=0.1,
            f=lambda: ibd_node.getblockcount() == stalled_height,
        )
        self.connect_nodes(1, 3)
        self.wait_until(lambda: ibd_node.getblockcount() == tip_height, timeout=180)
        assert_equal(ibd_node.getblock(pruned_hash, False), archive_node.getblock(pruned_hash, False))

        self.log.info("Restart a witness-pruned node in default archive mode; service flag must remain set")
        self.restart_node(0, extra_args=["-fastprune"])
        pruned_node = self.nodes[0]
        restarted_services = pruned_node.getnetworkinfo()
        assert int(restarted_services["localservices"], 16) & NODE_WITNESS_PRUNED
        assert_equal(int(restarted_services["localservices"], 16) & NODE_ARCHIVE, 0)
        assert "WITNESS_PRUNED" in restarted_services["localservicesnames"]
        assert "ARCHIVE" not in restarted_services["localservicesnames"]
        self.assert_stripped_matches_no_witness(pruned_node.getblock(pruned_hash, False), disabled_node.getblock(pruned_hash, False))

        self.log.info("Deep reorg recovery: recover missing witness data and switch back to the better chain")
        fork_height = pruned_height - 10
        fork_next_hash = disabled_node.getblockhash(fork_height + 1)
        old_tip_hash = disabled_node.getbestblockhash()
        old_tip_height = disabled_node.getblockcount()

        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(1, 2)

        archive_node.invalidateblock(fork_next_hash)
        self.generate(archive_node, old_tip_height - fork_height + 2, sync_fun=self.no_op)
        archive_tip_hash = archive_node.getbestblockhash()
        archive_tip_height = archive_node.getblockcount()

        self.connect_nodes(0, 1)
        self.sync_blocks([pruned_node, archive_node])
        assert_equal(self.get_bestblockhash_resilient(pruned_node), archive_tip_hash)

        assert_equal(disabled_node.getbestblockhash(), old_tip_hash)
        self.generate(disabled_node, archive_tip_height - old_tip_height + 2, sync_fun=self.no_op)
        assert disabled_node.getblockcount() > archive_tip_height

        with pruned_node.assert_debug_log(
            expected_msgs=[
                "Scheduling temporary witness recovery for block",
            ],
            timeout=20,
        ):
            self.connect_nodes(0, 2)
            self.wait_until(
                lambda: self.get_bestblockhash_resilient(pruned_node) == disabled_node.getbestblockhash(),
                timeout=120,
            )

        assert_equal(self.get_bestblockhash_resilient(pruned_node), disabled_node.getbestblockhash())
        assert_equal(pruned_node.getblockcount(), disabled_node.getblockcount())
        self.assert_stripped_matches_no_witness(
            pruned_node.getblock(pruned_hash, False),
            disabled_node.getblock(pruned_hash, False),
        )

        self.log.info("Startup compaction under explicit prune mode should advertise NODE_WITNESS_PRUNED")
        shared_witness_height = start_height + 5
        shared_witness_hash = archive_node.getblockhash(shared_witness_height)
        startup_assumevalid_hash = disabled_node.getblockhash(disabled_node.getblockcount() - 5)
        self.stop_node(2)
        self.start_node(2, extra_args=["-fastprune", "-prunewitnesses=1", "-reindex-chainstate", f"-assumevalid={startup_assumevalid_hash}"])
        disabled_node = self.nodes[2]
        self.wait_until(
            lambda: int(disabled_node.getnetworkinfo()["localservices"], 16) & NODE_WITNESS_PRUNED,
            timeout=60,
        )
        restarted_services = disabled_node.getnetworkinfo()
        assert_equal(int(restarted_services["localservices"], 16) & NODE_ARCHIVE, 0)
        assert "WITNESS_PRUNED" in restarted_services["localservicesnames"]
        assert "ARCHIVE" not in restarted_services["localservicesnames"]
        self.assert_stripped_matches_no_witness(
            disabled_node.getblock(shared_witness_hash, False),
            archive_node.getblock(shared_witness_hash, False),
        )

        self.log.info("Corrupt block index during the -reindex guard should fail closed")
        self.stop_node(2)
        manifest_files = sorted((disabled_node.blocks_path / "index").glob("MANIFEST*"))
        assert manifest_files
        for manifest_file in manifest_files:
            manifest_file.rename(manifest_file.with_suffix(manifest_file.suffix + ".bak"))
        disabled_node.assert_start_raises_init_error(
            extra_args=["-fastprune", "-reindex"],
            expected_msg=r"Error reading block database while checking whether -reindex would corrupt witness-pruned data: .*",
            match=ErrorMatch.PARTIAL_REGEX,
        )


if __name__ == "__main__":
    WitnessPruningTest(__file__).main()
