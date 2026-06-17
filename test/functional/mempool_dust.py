#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test dust limit mempool policy (`-dustrelayfee` parameter)"""
from copy import deepcopy
from decimal import Decimal

from test_framework.messages import (
    COIN,
    CTxOut,
    ser_compact_size,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
    OP_TRUE,
)
from test_framework.script_util import (
    key_to_p2pk_script,
    key_to_p2pkh_script,
    key_to_p2wpkh_script,
    keys_to_multisig_script,
    output_key_to_p2tr_script,
    program_to_witness_script,
    script_to_p2sh_script,
    script_to_p2wsh_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_equal,
    bisect_last_true,
    find_first_false,
    get_fee,
)
from test_framework.wallet import MiniWallet, p2mr_op_true_script
from test_framework.wallet_util import generate_keypair


DUST_RELAY_TX_FEE = 750  # default setting [sat/kvB]
P2MR_PQC_SIG_SIZE = 3680
P2MR_PUBKEY_SIZE = 32


def p2mr_dust_spend_size() -> int:
    signature_size = P2MR_PQC_SIG_SIZE + 1
    leaf_script_size = 1 + P2MR_PUBKEY_SIZE + 1
    control_block_size = 1
    return (
        32 + 4 + 1 + 4
        + len(ser_compact_size(3))
        + len(ser_compact_size(signature_size)) + signature_size
        + len(ser_compact_size(leaf_script_size)) + leaf_script_size
        + len(ser_compact_size(control_block_size)) + control_block_size
    )


class DustRelayFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-permitbaremultisig']]

    def assert_output_rejected(self, node: TestNode, output_script: CScript,
                               type_desc: str, reject_reason: str) -> None:
        self.log.info(f"-> Test {type_desc} output is rejected with {reject_reason}")

        tx = self.wallet.create_self_transfer()["tx"]
        amount = 1_000
        tx.vout.append(CTxOut(nValue=amount, scriptPubKey=output_script))
        tx.vout[0].nValue -= amount
        assert tx.vout[0].nValue >= 0

        res = node.testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(res['allowed'], False)
        assert_equal(res['reject-reason'], reject_reason)

    def test_dust_output(self, node: TestNode, dust_relay_fee: Decimal,
                         output_script: CScript, type_desc: str, spend_size: int,
                         exact_boundary: bool = False) -> None:
        # determine dust threshold (see `GetDustThreshold`)
        if output_script[0] == OP_RETURN:
            dust_threshold = 0
        else:
            tx_size = len(CTxOut(nValue=0, scriptPubKey=output_script).serialize())
            tx_size += spend_size
            dust_threshold = int(get_fee(tx_size, dust_relay_fee) * COIN)
        self.log.info(f"-> Test {type_desc} output (size {len(output_script)}, limit {dust_threshold})")

        base_tx = self.wallet.create_self_transfer()["tx"]
        base_output_value = base_tx.vout[0].nValue
        probe_cache = {}

        def probe(amount: int):
            if amount not in probe_cache:
                tx = deepcopy(base_tx)
                tx.vout.append(CTxOut(nValue=amount, scriptPubKey=output_script))
                tx.vout[0].nValue -= amount
                assert tx.vout[0].nValue >= 0
                res = node.testmempoolaccept([tx.serialize().hex()])[0]
                probe_cache[amount] = (tx, res)
            return probe_cache[amount]

        def is_dust_rejected(amount: int) -> bool:
            _tx, res = probe(amount)
            if res['allowed']:
                return False
            assert_equal(res['reject-reason'], 'dust')
            return True

        lo_dust = -1
        tx_start, res_start = probe(dust_threshold)
        if exact_boundary:
            assert_equal(res_start['allowed'], True)
            tx_good = tx_start
            if dust_threshold > 0:
                _tx_dust, res_dust = probe(dust_threshold - 1)
                assert_equal(res_dust['allowed'], False)
                assert_equal(res_dust['reject-reason'], 'dust')
        elif res_start['allowed']:
            hi_pass = dust_threshold
            tx_good = tx_start
        else:
            # Chain policy may differ from this test's static dust approximation.
            # Find the minimum passing amount, then verify one sat below fails.
            assert_equal(res_start['reject-reason'], 'dust')
            lo_dust = dust_threshold
            hi_pass = find_first_false(
                start=max(1, dust_threshold),
                predicate=is_dust_rejected,
                max_value=base_output_value - 1,
            )
            lo_dust = bisect_last_true(
                low_true=lo_dust,
                high_false=hi_pass,
                predicate=is_dust_rejected,
            )
            tx_good, _res_good = probe(hi_pass)

        tx_good_hex = tx_good.serialize().hex()
        assert_equal(node.testmempoolaccept([tx_good_hex])[0]['allowed'], True)
        if lo_dust >= 0:
            _tx_dust, res_dust = probe(lo_dust)
            assert_equal(res_dust['allowed'], False)
            assert_equal(res_dust['reject-reason'], 'dust')

        # finally send the transaction to avoid running out of MiniWallet UTXOs
        self.wallet.sendrawtransaction(from_node=node, tx_hex=tx_good_hex)

    def test_dustrelay(self):
        self.log.info("Test that small outputs are acceptable when dust relay rate is set to 0 that would otherwise trigger ephemeral dust rules")

        self.restart_node(0, extra_args=["-dustrelayfee=0"])

        assert_equal(self.nodes[0].getrawmempool(), [])

        # Create two dust outputs. Transaction has zero fees. both dust outputs are unspent, and would have failed individual checks.
        # The amount is 1 satoshi because create_self_transfer_multi disallows 0.
        dusty_tx = self.wallet.create_self_transfer_multi(fee_per_output=1000, amount_per_output=1, num_outputs=2)
        dust_txid = self.wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=dusty_tx["hex"], maxfeerate=0)

        assert_equal(self.nodes[0].getrawmempool(), [dust_txid])

        # Spends one dust along with fee input, leave other dust unspent to check ephemeral dust checks aren't being enforced
        sweep_tx = self.wallet.create_self_transfer_multi(utxos_to_spend=[self.wallet.get_utxo(), dusty_tx["new_utxos"][0]])
        sweep_txid = self.nodes[0].sendrawtransaction(sweep_tx["hex"])

        mempool_entries = self.nodes[0].getrawmempool()
        assert dust_txid in mempool_entries
        assert sweep_txid in mempool_entries
        assert_equal(len(mempool_entries), 2)

        # Wipe extra arg to reset dust relay
        self.restart_node(0, extra_args=[])

        assert_equal(self.nodes[0].getrawmempool(), [])

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.ensure_cached_coinbase_mature(self.nodes[0])
        self.wallet.ensure_spendable_utxos(min_spendable=2, mature_coinbase_count=1)

        self.test_dustrelay()

        # prepare output scripts of each standard type
        _, uncompressed_pubkey = generate_keypair(compressed=False)
        _, pubkey = generate_keypair(compressed=True)

        for version in range(3, 17):
            self.assert_output_rejected(
                self.nodes[0],
                program_to_witness_script(version, bytes([version]) * 2),
                f"reserved witness version {version}",
                "scriptpubkey",
            )

        standard_spend_size = 148
        output_scripts = (
            (key_to_p2pk_script(uncompressed_pubkey),          "P2PK (uncompressed)", standard_spend_size, False),
            (key_to_p2pk_script(pubkey),                       "P2PK (compressed)", standard_spend_size, False),
            (key_to_p2pkh_script(pubkey),                      "P2PKH", standard_spend_size, False),
            (script_to_p2sh_script(CScript([OP_TRUE])),        "P2SH", standard_spend_size, False),
            (key_to_p2wpkh_script(pubkey),                     "P2WPKH", standard_spend_size, False),
            (script_to_p2wsh_script(CScript([OP_TRUE])),       "P2WSH", standard_spend_size, False),
            (output_key_to_p2tr_script(pubkey[1:]),            "P2TR", standard_spend_size, False),
            (p2mr_op_true_script(),                            "P2MR", p2mr_dust_spend_size(), True),
            # Unknown witness version 2 outputs remain standard as long as they are not P2MR.
            (program_to_witness_script(2,  b'\x66' * 2),       "witness version 2 (non-P2MR)", standard_spend_size, False),
            # largest possible output script considered standard
            (keys_to_multisig_script([uncompressed_pubkey]*3), "bare multisig (m-of-3)", standard_spend_size, False),
            (CScript([OP_RETURN, b'superimportanthash']),      "null data (OP_RETURN)", standard_spend_size, False),
        )

        # test default (no parameter), disabled (=0) and a bunch of arbitrary dust fee rates [sat/kvB]
        for dustfee_sat_kvb in (DUST_RELAY_TX_FEE, 0, 1, 66, 500, 1337, 12345, 21212, 333333):
            dustfee_btc_kvb = dustfee_sat_kvb / Decimal(COIN)
            if dustfee_sat_kvb == DUST_RELAY_TX_FEE:
                self.log.info(f"Test default dust limit setting ({dustfee_sat_kvb} sat/kvB)...")
            else:
                dust_parameter = f"-dustrelayfee={dustfee_btc_kvb:.8f}"
                self.log.info(f"Test dust limit setting {dust_parameter} ({dustfee_sat_kvb} sat/kvB)...")
                self.restart_node(0, extra_args=[dust_parameter, "-permitbaremultisig"])

            for output_script, description, spend_size, exact_boundary in output_scripts:
                self.test_dust_output(
                    self.nodes[0],
                    dustfee_btc_kvb,
                    output_script,
                    description,
                    spend_size,
                    exact_boundary,
                )
            self.generate(self.nodes[0], 1)


if __name__ == '__main__':
    DustRelayFeeTest(__file__).main()
