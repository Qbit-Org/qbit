#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""P2MR integration and -p2mronly restricted-output checks."""

from decimal import Decimal

from test_framework.address import (
    key_to_p2pkh,
    program_to_witness,
)
from test_framework.blocktools import (
    COINBASE_MATURITY,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.descriptors import descsum_create
from test_framework.messages import (
    COIN,
    CTxOut,
)
from test_framework.script_util import (
    ANCHOR_ADDRESS,
    DUMMY_MIN_OP_RETURN_SCRIPT,
    PAY_TO_ANCHOR,
    key_to_p2pkh_script,
    program_to_witness_script,
)
from test_framework.segwit_addr import (
    Encoding,
    bech32_encode,
    convertbits,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch, QBIT_BECH32_HRPS, QBIT_RESTRICTED_OUTPUT_CHAINS, TestNode
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
    p2mr_op_true_script,
)
from test_framework.wallet_util import generate_keypair


P2MR_DELAYED_ACTIVATION_HEIGHT = 2
NON_P2MR_OUTPUT_TYPES = ("legacy", "p2sh-segwit", "bech32", "bech32m")


def reserved_witness_script(version, fill=0x42):
    return program_to_witness_script(version, bytes([fill] * 32))


class WalletP2MRTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 6
        self.extra_args = [
            ["-p2mronly=0"],
            ["-p2mronly=0"],
            ["-p2mronly=0"],
            ["-p2mronly=1"],
            ["-p2mronly=1", f"-testactivationheight=p2mr@{P2MR_DELAYED_ACTIVATION_HEIGHT}"],
            [],
        ]
        self.extra_init = [
            {},
            {},
            {},
            {},
            {},
            {"extra_conf": ["bind=127.0.0.1", "p2mronly=1", "[test]", "p2mronly=0"]},
        ]
        self.wallet_names = [
            False,
            False,
            False,
            False,
            False,
            False,
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def submit_manual_block(self, node, *, coinbase_script=None, txlist=None):
        tip = node.getbestblockhash()
        block_time = node.getblockheader(tip)["mediantime"] + 1
        height = node.getblockcount() + 1
        block = create_block(int(tip, 16), create_coinbase(height, script_pubkey=coinbase_script or p2mr_op_true_script()), block_time, txlist=txlist)
        add_witness_commitment(block)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        return block

    def run_test(self):
        node_default = self.nodes[0]
        node_mixed_managers = self.nodes[2]
        node_restricted_outputs = self.nodes[3]
        node_delayed_restricted_outputs = self.nodes[4]
        node_config_restricted_outputs = self.nodes[5]

        # Keep restricted-output-mode tests isolated from the unrestricted helper nodes.
        self.disconnect_nodes(2, 1)
        self.disconnect_nodes(3, 0)
        self.disconnect_nodes(3, 1)
        self.disconnect_nodes(3, 2)
        self.disconnect_nodes(4, 3)
        self.disconnect_nodes(5, 4)

        self.log.info("Check TestNode -p2mronly parsing mirrors ArgsManager boolean semantics")
        for option, expected in (
            ("p2mronly", True),
            ("p2mronly=1", True),
            ("p2mronly=0", False),
            ("p2mronly=", False),
            ("p2mronly=true", False),
            ("p2mronly=false", False),
            ("p2mronly=1abc", True),
            ("nop2mronly", False),
            ("nop2mronly=1", False),
            ("nop2mronly=0", True),
            ("nop2mronly=", True),
            ("nop2mronly=true", True),
            ("-p2mronly=", False),
            ("-p2mronly=1", True),
            ("regtest.p2mronly=1", True),
            ("regtest.nop2mronly=0", True),
        ):
            assert_equal(TestNode._p2mronly_setting_value(option), expected)
        assert_equal(TestNode._p2mronly_setting_value("debug=1"), None)
        assert_equal(TestNode._p2mronly_setting_value("regtest.p2mronly=1", chain="regtest"), True)
        assert_equal(TestNode._p2mronly_setting_value("test.p2mronly=1", chain="regtest"), None)
        assert_equal(QBIT_BECH32_HRPS[""], QBIT_BECH32_HRPS["main"])
        assert "" in QBIT_RESTRICTED_OUTPUT_CHAINS

        self.log.info("Check mixed-manager wallets reject explicit non-P2MR output types under -p2mronly")
        mixed_wallet_name = "mixed_output_wallet"
        node_mixed_managers.createwallet(wallet_name=mixed_wallet_name, load_on_startup=False)
        mixed_wallet = node_mixed_managers.get_wallet_rpc(mixed_wallet_name)
        for output_type in (*NON_P2MR_OUTPUT_TYPES, "p2mr"):
            mixed_wallet.getnewaddress("", output_type)
            mixed_wallet.getrawchangeaddress(output_type)
        mixed_wallet.unloadwallet(load_on_startup=False)

        self.stop_node(2)
        node_mixed_managers.assert_start_raises_init_error(
            ["-p2mronly=1", f"-wallet={mixed_wallet_name}", "-addresstype=legacy"],
            expected_msg="Address type 'legacy' is not available on this chain",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        node_mixed_managers.assert_start_raises_init_error(
            ["-p2mronly=1", f"-wallet={mixed_wallet_name}", "-changetype=bech32"],
            expected_msg="Change type 'bech32' is not available on this chain",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        self.start_node(2, ["-p2mronly=1", f"-wallet={mixed_wallet_name}"])
        mixed_wallet = node_mixed_managers.get_wallet_rpc(mixed_wallet_name)

        mixed_default_receive = mixed_wallet.getnewaddress()
        assert mixed_default_receive.startswith("qbrt1z")
        mixed_default_change = mixed_wallet.getrawchangeaddress()
        assert mixed_default_change.startswith("qbrt1z")
        for output_type in NON_P2MR_OUTPUT_TYPES:
            assert_raises_rpc_error(
                -5,
                f"address type '{output_type}' is not available on this chain",
                mixed_wallet.getnewaddress,
                "",
                output_type,
            )
            assert_raises_rpc_error(
                -5,
                f"address type '{output_type}' is not available on this chain",
                mixed_wallet.getrawchangeaddress,
                output_type,
            )

        self.generatetoaddress(node_mixed_managers, COINBASE_MATURITY + 1, mixed_default_receive, sync_fun=self.no_op)
        mixed_raw_tx = mixed_wallet.createrawtransaction([], {mixed_wallet.getnewaddress(): Decimal("1")})
        for output_type in NON_P2MR_OUTPUT_TYPES:
            assert_raises_rpc_error(
                -5,
                f"change type '{output_type}' is not available on this chain",
                mixed_wallet.fundrawtransaction,
                mixed_raw_tx,
                {"change_type": output_type},
            )
            assert_raises_rpc_error(
                -5,
                f"change type '{output_type}' is not available on this chain",
                mixed_wallet.walletcreatefundedpsbt,
                [],
                [{mixed_wallet.getnewaddress(): Decimal("1")}],
                0,
                {"change_type": output_type},
            )

        self.log.info("Check -p2mronly wallets still default to P2MR addresses and reject explicit legacy types")
        node_restricted_outputs.createwallet("restricted_outputs_wallet")
        p2mr_wallet = node_restricted_outputs.get_wallet_rpc("restricted_outputs_wallet")
        default_receive = p2mr_wallet.getnewaddress()
        assert default_receive.startswith("qbrt1z")
        default_change = p2mr_wallet.getrawchangeaddress()
        assert default_change.startswith("qbrt1z")
        assert_raises_rpc_error(-4, "gethdkeys is unavailable for P2MR-only wallets", p2mr_wallet.gethdkeys)
        assert_raises_rpc_error(
            -5,
            "Unable to parse HD key. Please provide a valid xpub",
            p2mr_wallet.createwalletdescriptor,
            "p2mr",
            {"hdkey": "not-a-key"},
        )
        public_descs = p2mr_wallet.listdescriptors()
        assert_equal(public_descs["descriptors"], [])
        assert "warnings" in public_descs
        assert "Omitted P2MR descriptors" in public_descs["warnings"][0]
        private_descs = p2mr_wallet.listdescriptors(True)["descriptors"]
        assert_equal(len(private_descs), 2)
        assert all(desc["desc"].startswith("mr(pk(pqc(") for desc in private_descs)
        assert all("qrpv" in desc["desc"] for desc in private_descs)
        receive_info = p2mr_wallet.getaddressinfo(default_receive)
        change_info = p2mr_wallet.getaddressinfo(default_change)
        assert "parent_desc" not in receive_info
        assert "parent_desc" not in change_info
        assert_raises_rpc_error(-5, "address type 'bech32' is not available on this chain", p2mr_wallet.getnewaddress, "", "bech32")
        assert_raises_rpc_error(-5, "address type 'bech32' is not available on this chain", p2mr_wallet.getrawchangeaddress, "bech32")
        assert_raises_rpc_error(-5, "address type 'bech32' is not available on this chain", p2mr_wallet.createwalletdescriptor, "bech32")

        self.log.info("Check delayed -p2mronly wallets do not emit P2MR outputs before activation")
        node_delayed_restricted_outputs.createwallet("delayed_restricted_outputs_wallet")
        delayed_p2mr_wallet = node_delayed_restricted_outputs.get_wallet_rpc("delayed_restricted_outputs_wallet")
        activation_error = f"P2MR wallet outputs are unavailable before activation height {P2MR_DELAYED_ACTIVATION_HEIGHT}"
        assert_raises_rpc_error(-12, activation_error, delayed_p2mr_wallet.getnewaddress)
        assert_raises_rpc_error(-12, activation_error, delayed_p2mr_wallet.getnewaddress, "", "p2mr")
        assert_raises_rpc_error(-12, activation_error, delayed_p2mr_wallet.getrawchangeaddress)
        assert_raises_rpc_error(-12, activation_error, delayed_p2mr_wallet.getrawchangeaddress, "p2mr")

        self.log.info("Check delayed -p2mronly wallets switch to P2MR outputs at activation")
        for _ in range(P2MR_DELAYED_ACTIVATION_HEIGHT):
            self.submit_manual_block(node_delayed_restricted_outputs)
        node_delayed_restricted_outputs.syncwithvalidationinterfacequeue()
        assert delayed_p2mr_wallet.getnewaddress().startswith("qbrt1z")
        assert delayed_p2mr_wallet.getrawchangeaddress().startswith("qbrt1z")

        self.log.info("Check -p2mronly rejects legacy address, multisig, descriptor, and message-signing surfaces")
        legacy_privkey_for_rpc, legacy_pubkey_for_rpc = generate_keypair(wif=True)
        legacy_addr = key_to_p2pkh(legacy_pubkey_for_rpc)
        legacy_info = node_restricted_outputs.validateaddress(legacy_addr)
        assert_equal(legacy_info["isvalid"], False)
        assert_equal(legacy_info["error"], "Address type is not supported on this chain; use a p2mr address.")

        assert_raises_rpc_error(-5, "Legacy multisig address creation is disabled on this chain", node_restricted_outputs.createmultisig, 1, [legacy_pubkey_for_rpc.hex()])

        legacy_desc = node_default.getdescriptorinfo(f"wpkh({legacy_pubkey_for_rpc.hex()})")["descriptor"]
        assert_raises_rpc_error(-5, "only p2mr descriptors are supported", node_restricted_outputs.getdescriptorinfo, legacy_desc)
        assert_raises_rpc_error(-5, "only p2mr descriptors are supported", node_restricted_outputs.deriveaddresses, legacy_desc)
        import_result = p2mr_wallet.importdescriptors([{"desc": legacy_desc, "timestamp": "now"}])
        assert_equal(import_result[0]["success"], False)
        assert_equal(import_result[0]["error"]["code"], -5)
        assert "only p2mr descriptors are supported" in import_result[0]["error"]["message"]

        assert_raises_rpc_error(-32, "Legacy message signing is disabled on this chain", p2mr_wallet.signmessage, default_receive, "message")
        assert_raises_rpc_error(-32, "Legacy message signing is disabled on this chain", node_restricted_outputs.signmessagewithprivkey, legacy_privkey_for_rpc, "message")
        assert_raises_rpc_error(-32, "Legacy message verification is disabled on this chain", node_restricted_outputs.verifymessage, default_receive, "signature", "message")

        self.log.info("Check -p2mronly allows PayToAnchor descriptors")
        anchor_addr_desc = descsum_create(f"addr({ANCHOR_ADDRESS})")
        anchor_raw_desc = descsum_create(f"raw({PAY_TO_ANCHOR.hex()})")
        assert_equal(node_restricted_outputs.getdescriptorinfo(anchor_addr_desc)["isrange"], False)
        assert_equal(node_restricted_outputs.getdescriptorinfo(anchor_raw_desc)["isrange"], False)
        assert_equal(node_restricted_outputs.deriveaddresses(anchor_addr_desc), [ANCHOR_ADDRESS])
        assert_equal(node_restricted_outputs.deriveaddresses(anchor_raw_desc), [ANCHOR_ADDRESS])
        node_restricted_outputs.createwallet("restricted_anchor_watch", disable_private_keys=True)
        anchor_watch_wallet = node_restricted_outputs.get_wallet_rpc("restricted_anchor_watch")
        anchor_import_result = anchor_watch_wallet.importdescriptors([
            {"desc": anchor_addr_desc, "timestamp": "now"},
            {"desc": anchor_raw_desc, "timestamp": "now"},
        ])
        assert_equal(anchor_import_result[0]["success"], True)
        assert_equal(anchor_import_result[1]["success"], True)

        self.log.info("Check -p2mronly createwalletdescriptor can still use hdkey to select among private HD roots")
        node_restricted_outputs.createwallet("p2mr_root_source")
        root_source = node_restricted_outputs.get_wallet_rpc("p2mr_root_source")
        source_private_desc = next(
            desc
            for desc in root_source.listdescriptors(True)["descriptors"]
            if desc["active"] and not desc["internal"] and desc["desc"].startswith("mr(")
        )
        source_public_desc = node_restricted_outputs.getdescriptorinfo(source_private_desc["desc"])["descriptor"]
        source_key_expr = source_public_desc.split("pqc(", 1)[1].split(")", 1)[0]
        if source_key_expr.startswith("["):
            source_key_expr = source_key_expr.split("]", 1)[1]
        source_xpub = source_key_expr.split("/", 1)[0]

        node_restricted_outputs.createwallet("p2mr_multi_root")
        multi_root_wallet = node_restricted_outputs.get_wallet_rpc("p2mr_multi_root")
        import_result = multi_root_wallet.importdescriptors([{
            "desc": source_private_desc["desc"],
            "timestamp": "now",
            "active": True,
            "internal": False,
            "range": source_private_desc["range"],
            "next_index": source_private_desc["next_index"],
        }])[0]
        assert_equal(import_result["success"], True)
        assert_raises_rpc_error(
            -5,
            "Unable to determine which HD key to use from active descriptors. Please specify with 'hdkey'",
            multi_root_wallet.createwalletdescriptor,
            "p2mr",
            {"internal": True},
        )
        old_private_descs = set(desc["desc"] for desc in multi_root_wallet.listdescriptors(True)["descriptors"])
        created = multi_root_wallet.createwalletdescriptor("p2mr", {"internal": True, "hdkey": source_xpub})
        assert_equal(created["descs"], [])
        assert "warnings" in created
        assert "Omitted P2MR descriptors" in created["warnings"][0]
        new_private_descs = set(desc["desc"] for desc in multi_root_wallet.listdescriptors(True)["descriptors"]) - old_private_descs
        assert_equal(len(new_private_descs), 1)
        new_public_desc = node_restricted_outputs.getdescriptorinfo(next(iter(new_private_descs)))["descriptor"]
        assert source_xpub in new_public_desc

        p2mr_program = bytes(range(32))
        p2mr_script_hex = "5220" + p2mr_program.hex()
        p2mr_address = program_to_witness(2, p2mr_program, main=False)
        assert_equal(p2mr_address, "qbrt1zqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s8kqqny")

        self.log.info("Check P2MR address encoding/roundtrip and validateaddress fields")
        dec = node_default.decodescript(p2mr_script_hex)
        assert_equal(dec["type"], "witness_v2_p2mr")
        assert_equal(dec["address"], p2mr_address)

        info = node_default.validateaddress(p2mr_address)
        assert_equal(info["isvalid"], True)
        assert_equal(info["isscript"], True)
        assert_equal(info["iswitness"], True)
        assert_equal(info["witness_version"], 2)
        assert_equal(info["witness_program"], p2mr_program.hex())
        assert_equal(info["scriptPubKey"], p2mr_script_hex)
        assert_equal(node_default.decodescript(info["scriptPubKey"])["address"], p2mr_address)

        self.log.info("Check hardcoded P2MR address decoding")
        hardcoded_info = node_default.validateaddress("qbrt1zqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s8kqqny")
        assert_equal(hardcoded_info["isvalid"], True)
        assert_equal(hardcoded_info["scriptPubKey"], p2mr_script_hex)

        self.log.info("Check invalid P2MR address formats are rejected")
        invalid_checksum = p2mr_address[:-1] + ("q" if p2mr_address[-1] != "q" else "p")
        invalid_version = bech32_encode(Encoding.BECH32M, "qbrt", [17] + convertbits(p2mr_program, 8, 5))
        invalid_size = bech32_encode(Encoding.BECH32M, "qbrt", [2] + convertbits(b"\x01", 8, 5))
        for invalid in [invalid_checksum, invalid_version, invalid_size]:
            invalid_info = node_default.validateaddress(invalid)
            assert_equal(invalid_info["isvalid"], False)
            assert "error" in invalid_info

        self.log.info("Fund a wallet and send to a P2MR address; verify gettxout/solver view")
        node_default.createwallet("p2mr_sender")
        sender = node_default.get_wallet_rpc("p2mr_sender")
        mining_addr = sender.getnewaddress()
        self.generatetoaddress(node_default, COINBASE_MATURITY + 1, mining_addr, sync_fun=self.no_op)

        send_txid = sender.sendtoaddress(p2mr_address, 1)
        mined_block = self.generate(node_default, 1, sync_fun=self.no_op)[0]
        tx = node_default.getrawtransaction(send_txid, True, mined_block)
        p2mr_vout = None
        for vout in tx["vout"]:
            if vout["scriptPubKey"].get("address") == p2mr_address:
                p2mr_vout = vout["n"]
                break
        assert p2mr_vout is not None
        txout = node_default.gettxout(send_txid, p2mr_vout)
        assert txout is not None
        assert_equal(txout["scriptPubKey"]["type"], "witness_v2_p2mr")
        assert_equal(txout["scriptPubKey"]["hex"], p2mr_script_hex)

        self.log.info("Prepare restricted-output node with spendable coins")
        mini = MiniWallet(node_restricted_outputs, mode=MiniWalletMode.ADDRESS_P2MR_OP_TRUE)

        self.log.info("Check restricted-output TestNode.generate uses the spendable P2MR OP_TRUE script")
        generated_block = self.generate(node_restricted_outputs, 1, sync_fun=self.no_op)[0]
        generated_coinbase_txid = node_restricted_outputs.getblock(generated_block)["tx"][0]
        mini.rescan_utxos()
        assert any(
            utxo["txid"] == generated_coinbase_txid
            for utxo in mini.get_utxos(include_immature_coinbase=True, mark_as_spent=False)
        )

        self.log.info("Check config-backed -p2mronly TestNode.generate uses the spendable P2MR OP_TRUE script")
        config_mini = MiniWallet(node_config_restricted_outputs, mode=MiniWalletMode.ADDRESS_P2MR_OP_TRUE)
        generated_block = self.generate(node_config_restricted_outputs, 1, sync_fun=self.no_op)[0]
        generated_coinbase_txid = node_config_restricted_outputs.getblock(generated_block)["tx"][0]
        config_mini.rescan_utxos()
        assert any(
            utxo["txid"] == generated_coinbase_txid
            for utxo in config_mini.get_utxos(include_immature_coinbase=True, mark_as_spent=False)
        )

        self.generate(mini, COINBASE_MATURITY + 1, sync_fun=self.no_op)
        mini.send_to(from_node=node_restricted_outputs, scriptPubKey=bytes.fromhex(receive_info["scriptPubKey"]), amount=2 * COIN)
        self.generate(mini, 1, sync_fun=self.no_op)
        node_restricted_outputs.syncwithvalidationinterfacequeue()
        spendable_utxos = mini.get_utxos(confirmed_only=True, mark_as_spent=False)
        spend_utxo = spendable_utxos[0]
        reserved_block_utxo = spendable_utxos[1]

        self.log.info("Check -p2mronly allows empty legacy solving_data arrays with P2MR descriptors")
        empty_legacy_solving_data = {
            "pubkeys": [],
            "scripts": [],
            "descriptors": [private_descs[0]["desc"]],
        }
        raw_tx = p2mr_wallet.createrawtransaction([], {default_receive: Decimal("1")})
        funded = p2mr_wallet.fundrawtransaction(raw_tx, solving_data=empty_legacy_solving_data)
        assert "hex" in funded
        funded_psbt = p2mr_wallet.walletcreatefundedpsbt(
            [],
            [{default_receive: Decimal("1")}],
            0,
            {"solving_data": empty_legacy_solving_data},
        )
        assert "psbt" in funded_psbt
        assert_raises_rpc_error(
            -8,
            "Legacy pubkey/script solving data is disabled",
            p2mr_wallet.fundrawtransaction,
            raw_tx,
            solving_data={"pubkeys": [legacy_pubkey_for_rpc.hex()]},
        )
        assert_raises_rpc_error(
            -8,
            "Legacy pubkey/script solving data is disabled",
            p2mr_wallet.walletcreatefundedpsbt,
            [],
            [{default_receive: Decimal("1")}],
            0,
            {"solving_data": {"scripts": [key_to_p2pkh_script(legacy_pubkey_for_rpc).hex()]}},
        )

        self.log.info("Check restricted-output mempool rejection for legacy outputs")
        _, non_p2mr_pubkey = generate_keypair(wif=True)
        non_p2mr_tx = mini.create_self_transfer(utxo_to_spend=spend_utxo)["tx"]
        non_p2mr_tx.vout[0].scriptPubKey = key_to_p2pkh_script(non_p2mr_pubkey)
        non_p2mr_hex = non_p2mr_tx.serialize().hex()
        reject = node_restricted_outputs.testmempoolaccept([non_p2mr_hex], maxfeerate=0)[0]
        assert_equal(reject["allowed"], False)
        assert_equal(reject["reject-reason"], "tx-output-not-p2mr")

        self.log.info("Check reserved witness-namespace outputs fail the restricted-output consensus gate before activation")
        reserved_output_tx = mini.create_self_transfer(utxo_to_spend=reserved_block_utxo)["tx"]
        reserved_output_tx.vout[0].scriptPubKey = reserved_witness_script(3)
        reserved_output_hex = reserved_output_tx.serialize().hex()
        reserved_reject = node_restricted_outputs.testmempoolaccept([reserved_output_hex], maxfeerate=0)[0]
        assert_equal(reserved_reject["allowed"], False)
        assert_equal(reserved_reject["reject-reason"], "tx-output-not-p2mr")

        self.log.info("Check restricted-output blocks reject reserved witness-namespace outputs before activation")
        tip = node_restricted_outputs.getbestblockhash()
        block_time = node_restricted_outputs.getblockheader(tip)["mediantime"] + 1
        height = node_restricted_outputs.getblockcount() + 1
        reserved_block = create_block(int(tip, 16), create_coinbase(height, script_pubkey=p2mr_op_true_script()), block_time, txlist=[reserved_output_tx])
        add_witness_commitment(reserved_block)
        reserved_block.solve()
        prev_tip = node_restricted_outputs.getbestblockhash()
        assert_equal(node_restricted_outputs.submitblock(reserved_block.serialize().hex()), "bad-txns-output-not-p2mr")
        assert_equal(node_restricted_outputs.getbestblockhash(), prev_tip)

        self.log.info("Check restricted-output block rejection reason for legacy outputs")
        _, legacy_pubkey = generate_keypair(wif=True)
        legacy_tx = mini.create_self_transfer(utxo_to_spend=spend_utxo)["tx"]
        legacy_tx.vout[0].scriptPubKey = key_to_p2pkh_script(legacy_pubkey)

        tip = node_restricted_outputs.getbestblockhash()
        block_time = node_restricted_outputs.getblockheader(tip)["mediantime"] + 1
        height = node_restricted_outputs.getblockcount() + 1
        invalid_block = create_block(int(tip, 16), create_coinbase(height, script_pubkey=p2mr_op_true_script()), block_time, txlist=[legacy_tx])
        add_witness_commitment(invalid_block)
        invalid_block.solve()
        assert_equal(node_restricted_outputs.submitblock(invalid_block.serialize().hex()), "bad-txns-output-not-p2mr")

        self.log.info("Check restricted-output mode allows PayToAnchor outputs")
        anchor_tx = mini.create_self_transfer(utxo_to_spend=spend_utxo)["tx"]
        anchor_value = 10_000
        anchor_tx.vout[0].nValue -= anchor_value
        anchor_tx.vout[0].scriptPubKey = program_to_witness_script(2, p2mr_program)
        anchor_tx.vout.append(CTxOut(anchor_value, PAY_TO_ANCHOR))
        anchor_hex = anchor_tx.serialize().hex()
        anchor_allow = node_restricted_outputs.testmempoolaccept([anchor_hex], maxfeerate=0)[0]
        assert_equal(anchor_allow["allowed"], True)

        self.log.info("Check restricted-output mode allows OP_RETURN outputs")
        op_return_tx = mini.create_self_transfer(utxo_to_spend=spend_utxo)["tx"]
        op_return_tx.vout[0].scriptPubKey = program_to_witness_script(2, p2mr_program)
        op_return_tx.vout.append(CTxOut(0, DUMMY_MIN_OP_RETURN_SCRIPT))
        op_return_hex = op_return_tx.serialize().hex()
        allow = node_restricted_outputs.testmempoolaccept([op_return_hex], maxfeerate=0)[0]
        assert_equal(allow["allowed"], True)
        op_return_txid = node_restricted_outputs.sendrawtransaction(op_return_hex, maxfeerate=0)
        mined_block = self.generate(mini, 1, sync_fun=self.no_op)[0]
        assert op_return_txid in node_restricted_outputs.getblock(mined_block)["tx"]

        self.log.info("Check restricted-output mode rejects legacy coinbase payouts")
        _, legacy_coinbase_pubkey = generate_keypair(wif=True)
        tip = node_restricted_outputs.getbestblockhash()
        block_time = node_restricted_outputs.getblockheader(tip)["mediantime"] + 1
        height = node_restricted_outputs.getblockcount() + 1
        legacy_coinbase_block = create_block(
            int(tip, 16),
            create_coinbase(height, script_pubkey=key_to_p2pkh_script(legacy_coinbase_pubkey)),
            block_time,
        )
        add_witness_commitment(legacy_coinbase_block)
        legacy_coinbase_block.solve()
        assert_equal(node_restricted_outputs.submitblock(legacy_coinbase_block.serialize().hex()), "bad-txns-output-not-p2mr")

        self.log.info("Check restricted-output mode accepts P2MR coinbase payouts")
        height_before = node_restricted_outputs.getblockcount()
        self.generate(mini, 1, sync_fun=self.no_op)
        assert_equal(node_restricted_outputs.getblockcount(), height_before + 1)

        self.log.info("Check restricted-output mode allows OP_RETURN coinbase exemptions through mining RPC")
        height_before = node_restricted_outputs.getblockcount()
        self.generateblock(node_restricted_outputs, output="raw(6a)", transactions=[], sync_fun=self.no_op)
        assert_equal(node_restricted_outputs.getblockcount(), height_before + 1)


if __name__ == "__main__":
    WalletP2MRTest(__file__).main()
