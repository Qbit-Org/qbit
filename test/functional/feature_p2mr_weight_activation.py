#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Exercise delayed P2MR and validation-weight-v2 with a real 5-of-5 spend."""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


ACTIVATION_HEIGHT = COINBASE_MATURITY + 30
P2MR_ACTIVATION_HEIGHT = ACTIVATION_HEIGHT - 2


class P2MRValidationWeightActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-keypool=2",
            f"-testactivationheight=p2mr@{P2MR_ACTIVATION_HEIGHT}",
            f"-testactivationheight=p2mrweightv2@{ACTIVATION_HEIGHT}",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine(self, wallet, count=1):
        self.generatetoaddress(self.nodes[0], count, wallet.getnewaddress())

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("activation_miner")
        miner = node.get_wallet_rpc("activation_miner")
        try:
            miner.createwalletdescriptor("p2mr")
        except JSONRPCException as error:
            assert "Descriptor already exists" in error.error["message"]
        self.mine(miner, COINBASE_MATURITY + 1)

        signer_wallets = []
        signer_pubkeys = []
        for index in range(5):
            name = f"weight_signer_{index}"
            node.createwallet(name)
            signer = node.get_wallet_rpc(name)
            try:
                signer.createwalletdescriptor("p2mr")
            except JSONRPCException as error:
                assert "Descriptor already exists" in error.error["message"]
            exported = signer.exportpubkeydb()
            signer_pubkeys.append(exported["pubkeys"][0]["pubkey"])
            signer_wallets.append(signer)

        descriptor = descsum_create(f"mr(multi_a(5,{','.join(signer_pubkeys)}))")
        node.createwallet("weight_watch", blank=True, disable_private_keys=True)
        watch = node.get_wallet_rpc("weight_watch")
        imported = watch.importdescriptors([{"desc": descriptor, "timestamp": "now"}])
        assert_equal(imported[0]["success"], True)
        address = node.deriveaddresses(descriptor)[0]

        amount = Decimal("1.00000000")
        funding_txid = miner.sendtoaddress(address, amount)
        self.mine(miner)
        assert watch.gettransaction(funding_txid)["confirmations"] > 0

        funded = watch.walletcreatefundedpsbt(
            [],
            [{miner.getnewaddress(): amount}],
            0,
            {
                "includeWatching": True,
                "subtractFeeFromOutputs": [0],
                "fee_rate": 200,
            },
        )
        signed = []
        for signer in signer_wallets:
            processed = signer.walletprocesspsbt(
                psbt=funded["psbt"],
                sign=True,
                sighashtype="DEFAULT",
                bip32derivs=True,
                finalize=False,
            )
            assert_equal(processed["complete"], False)
            signed.append(processed["psbt"])

        finalized = node.finalizepsbt(node.combinepsbt(signed))
        assert_equal(finalized["complete"], True)
        spend_txid = node.decoderawtransaction(finalized["hex"])["txid"]

        target = P2MR_ACTIVATION_HEIGHT - 2
        if node.getblockcount() < target:
            self.mine(miner, target - node.getblockcount())
        assert_equal(node.getblockcount(), target)

        self.log.info("Legacy weight policy is pre-enforced before delayed P2MR activation")
        before_p2mr = node.testmempoolaccept([finalized["hex"]])[0]
        assert_equal(before_p2mr["allowed"], False)
        assert "validation" in before_p2mr["reject-reason"].lower()

        self.mine(miner)
        assert_equal(node.getblockcount(), P2MR_ACTIVATION_HEIGHT - 1)
        p2mr_template = node.getblocktemplate({"rules": ["segwit"]})
        template_weight = p2mr_template["p2mr_validation_weight"]
        assert_equal(template_weight["per_sigop"], 3730)
        assert_equal(template_weight["v2_active"], False)
        assert spend_txid not in {tx["txid"] for tx in p2mr_template["transactions"]}

        self.mine(miner)
        assert_equal(node.getblockcount(), P2MR_ACTIVATION_HEIGHT)

        pre_activation = node.testmempoolaccept([finalized["hex"]])[0]
        assert_equal(pre_activation["allowed"], False)
        assert "validation" in pre_activation["reject-reason"].lower()

        self.mine(miner)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        pre_activation_tip = node.getbestblockhash()
        template_weight = node.getblocktemplate({"rules": ["segwit"]})["p2mr_validation_weight"]
        assert_equal(template_weight["per_sigop"], 3683)
        assert_equal(template_weight["v2_active"], True)
        assert_equal(template_weight["v2_activation_height"], ACTIVATION_HEIGHT)
        activation_candidate = node.testmempoolaccept([finalized["hex"]])[0]
        assert_equal(activation_candidate["allowed"], True)

        txid = node.sendrawtransaction(finalized["hex"])
        activation_block = self.generatetoaddress(node, 1, miner.getnewaddress())[0]
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)
        assert txid in node.getblock(activation_block)["tx"]

        info = node.getblockchaininfo()["p2mr_validation_weight"]
        assert_equal(info["activation_height"], ACTIVATION_HEIGHT)
        assert_equal(info["legacy_per_sigop"], 3730)
        assert_equal(info["v2_per_sigop"], 3683)
        assert_equal(info["active_for_tip"], True)
        assert_equal(info["active_for_next_block"], True)

        node.invalidateblock(activation_block)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert txid in node.getrawmempool()

        node.invalidateblock(pre_activation_tip)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 2)
        assert txid not in node.getrawmempool()
        reorg_candidate = node.testmempoolaccept([finalized["hex"]])[0]
        assert_equal(reorg_candidate["allowed"], False)

        node.reconsiderblock(pre_activation_tip)
        node.reconsiderblock(activation_block)
        assert_equal(node.getbestblockhash(), activation_block)


if __name__ == "__main__":
    P2MRValidationWeightActivationTest(__file__).main()
