#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the scantxoutset rpc call."""
from test_framework.address import address_to_scriptpubkey
from test_framework.descriptors import descsum_create
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import (
    MiniWallet,
    getnewdestination,
)

from decimal import Decimal


def descriptors(out):
    return sorted(u['desc'] for u in out['unspents'])


class ScantxoutsetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def sendtodestination(self, destination, amount):
        # interpret strings as addresses, assume scriptPubKey otherwise
        if isinstance(destination, str):
            destination = address_to_scriptpubkey(destination)
        self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=destination, amount=int(COIN * amount))

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        # Mature the default-cache coinbase UTXOs
        self.ensure_cached_coinbase_mature(self.nodes[0])

        self.log.info("Test if we find coinbase outputs.")
        assert_equal(sum(u["coinbase"] for u in self.nodes[0].scantxoutset("start", [self.wallet.get_descriptor()])["unspents"]), 49)

        self.log.info("Create UTXOs...")
        path_amounts = [
            ("/0'/0'/0'", 0.008),
            ("/0'/0'/1'", 0.016),
            ("/0'/0'/1500'", 0.032),
            ("/0'/0'/0", 0.064),
            ("/0'/0'/1", 0.128),
            ("/0'/0'/1500", 0.256),
            ("/1/1/0'", 0.512),
            ("/1/1/1'", 1.024),
            ("/1/1/1500'", 2.048),
            ("/1/1/0", 4.096),
            ("/1/1/1", 8.192),
            ("/1/1/1500", 16.384),
        ]
        required_amount = Decimal("0.007") + sum(Decimal(str(amount)) for _, amount in path_amounts)
        required_sats = int(COIN * required_amount) + 1000 * (3 + len(path_amounts) + 1)  # 15 send_to calls + 1 consolidation tx fee
        consolidated_utxos = []
        consolidated_value = 0
        while consolidated_value < required_sats:
            utxo = self.wallet.get_utxo()
            consolidated_utxos.append(utxo)
            consolidated_value += int(COIN * utxo["value"])
        self.wallet.send_self_transfer_multi(from_node=self.nodes[0], utxos_to_spend=consolidated_utxos)

        pubk1, spk_P2SH_SEGWIT, addr_P2SH_SEGWIT = getnewdestination("p2sh-segwit")
        pubk2, spk_LEGACY, addr_LEGACY = getnewdestination("legacy")
        pubk3, spk_BECH32, addr_BECH32 = getnewdestination("bech32")
        self.sendtodestination(spk_P2SH_SEGWIT, 0.001)
        self.sendtodestination(spk_LEGACY, 0.002)
        self.sendtodestination(spk_BECH32, 0.004)

        # Send to child keys of this tprv by deriving addresses at runtime, so
        # legacy prefixes come from current chain params instead of hardcoded literals.
        xprv = "qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm"
        derived_legacy_addrs = {}
        for path, amount in path_amounts:
            desc = descsum_create(f"pkh({xprv}{path})")
            addr = self.nodes[0].deriveaddresses(desc)[0]
            self.sendtodestination(addr, amount)
            derived_legacy_addrs[path] = addr

        self.generate(self.nodes[0], 1)

        scan = self.nodes[0].scantxoutset("start", [])
        info = self.nodes[0].gettxoutsetinfo()
        assert_equal(scan['success'], True)
        assert_equal(scan['height'], info['height'])
        assert_equal(scan['txouts'], info['txouts'])
        assert_equal(scan['bestblock'], info['bestblock'])

        self.log.info("Test if we have found the non HD unspent outputs.")
        assert_equal(self.nodes[0].scantxoutset("start", ["pkh(" + pubk1.hex() + ")", "pkh(" + pubk2.hex() + ")", "pkh(" + pubk3.hex() + ")"])['total_amount'], Decimal("0.002"))
        assert_equal(self.nodes[0].scantxoutset("start", ["wpkh(" + pubk1.hex() + ")", "wpkh(" + pubk2.hex() + ")", "wpkh(" + pubk3.hex() + ")"])['total_amount'], Decimal("0.004"))
        assert_equal(self.nodes[0].scantxoutset("start", ["sh(wpkh(" + pubk1.hex() + "))", "sh(wpkh(" + pubk2.hex() + "))", "sh(wpkh(" + pubk3.hex() + "))"])['total_amount'], Decimal("0.001"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(" + pubk1.hex() + ")", "combo(" + pubk2.hex() + ")", "combo(" + pubk3.hex() + ")"])['total_amount'], Decimal("0.007"))
        assert_equal(self.nodes[0].scantxoutset("start", ["addr(" + addr_P2SH_SEGWIT + ")", "addr(" + addr_LEGACY + ")", "addr(" + addr_BECH32 + ")"])['total_amount'], Decimal("0.007"))
        assert_equal(self.nodes[0].scantxoutset("start", ["addr(" + addr_P2SH_SEGWIT + ")", "addr(" + addr_LEGACY + ")", "combo(" + pubk3.hex() + ")"])['total_amount'], Decimal("0.007"))

        self.log.info("Test range validation.")
        assert_raises_rpc_error(-8, "End of range is too high", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": -1}])
        assert_raises_rpc_error(-8, "Range should be greater or equal than 0", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": [-1, 10]}])
        assert_raises_rpc_error(-8, "End of range is too high", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": [(2 << 31 + 1) - 1000000, (2 << 31 + 1)]}])
        assert_raises_rpc_error(-8, "Range specified as [begin,end] must not have begin after end", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": [2, 1]}])
        assert_raises_rpc_error(-8, "Range is too large", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": [0, 1000001]}])

        self.log.info("Test extended key derivation.")
        # Run various scans, and verify that the sum of the amounts of the matches corresponds to the expected subset.
        # Note that all amounts in the UTXO set are powers of 2 multiplied by 0.001 BTC, so each amounts uniquely identifies a subset.
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0'/0h/0h)"])['total_amount'], Decimal("0.008"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0'/0'/1h)"])['total_amount'], Decimal("0.016"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0h/0'/1500')"])['total_amount'], Decimal("0.032"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0h/0h/0)"])['total_amount'], Decimal("0.064"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0'/0h/1)"])['total_amount'], Decimal("0.128"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0h/0'/1500)"])['total_amount'], Decimal("0.256"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0'/0h/*h)", "range": 1499}])['total_amount'], Decimal("0.024"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0'/0'/*h)", "range": 1500}])['total_amount'], Decimal("0.056"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0h/0'/*)", "range": 1499}])['total_amount'], Decimal("0.192"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0'/0h/*)", "range": 1500}])['total_amount'], Decimal("0.448"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1/0')"])['total_amount'], Decimal("0.512"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1/1')"])['total_amount'], Decimal("1.024"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1/1500h)"])['total_amount'], Decimal("2.048"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1/0)"])['total_amount'], Decimal("4.096"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1/1)"])['total_amount'], Decimal("8.192"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1/1500)"])['total_amount'], Decimal("16.384"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1/1/0)"])['total_amount'], Decimal("4.096"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo([abcdef88/1/2'/3/4h]qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1/1/1)"])['total_amount'], Decimal("8.192"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1/1/1500)"])['total_amount'], Decimal("16.384"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1/*')", "range": 1499}])['total_amount'], Decimal("1.536"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1/*')", "range": 1500}])['total_amount'], Decimal("3.584"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1/*)", "range": 1499}])['total_amount'], Decimal("12.288"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1/*)", "range": 1500}])['total_amount'], Decimal("28.672"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1/1/*)", "range": 1499}])['total_amount'], Decimal("12.288"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1/1/*)", "range": 1500}])['total_amount'], Decimal("28.672"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1/1/*)", "range": [1500, 1500]}])['total_amount'], Decimal("16.384"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "pkh(qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1/1/<0;1>)"}])["total_amount"], Decimal("12.288"))

        # Test the reported descriptors for a few matches
        assert_equal(descriptors(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0h/0h/*)", "range": 1499}])), ["pkh([0c5f9a1e/0h/0h/0]026dbd8b2315f296d36e6b6920b1579ca75569464875c7ebe869b536a7d9503c8c)#rthll0rg", "pkh([0c5f9a1e/0h/0h/1]033e6f25d76c00bedb3a8993c7d5739ee806397f0529b1b31dda31ef890f19a60c)#mcjajulr"])
        assert_equal(descriptors(self.nodes[0].scantxoutset("start", ["combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1/0)"])), ["pkh([0c5f9a1e/1/1/0]03e1c5b6e650966971d7e71ef2674f80222752740fc1dfd63bbbd220d2da9bd0fb)#cxmct4w8"])
        assert_equal(descriptors(self.nodes[0].scantxoutset("start", [{"desc": "combo(qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1/1/*)", "range": 1500}])), ['pkh([0c5f9a1e/1/1/0]03e1c5b6e650966971d7e71ef2674f80222752740fc1dfd63bbbd220d2da9bd0fb)#cxmct4w8', 'pkh([0c5f9a1e/1/1/1500]03832901c250025da2aebae2bfb38d5c703a57ab66ad477f9c578bfbcd78abca6f)#vchwd07g', 'pkh([0c5f9a1e/1/1/1]030d820fc9e8211c4169be8530efbc632775d8286167afd178caaf1089b77daba7)#z2t3ypsa'])

        # Check that status and abort don't need second arg
        assert_equal(self.nodes[0].scantxoutset("status"), None)
        assert_equal(self.nodes[0].scantxoutset("abort"), False)

        # Check that the blockhash and confirmations fields are correct
        self.generate(self.nodes[0], 2)
        unspent = self.nodes[0].scantxoutset("start", [f"addr({derived_legacy_addrs['/1/1/1500']})"])["unspents"][0]
        blockhash = self.nodes[0].getblockhash(info["height"])
        assert_equal(unspent["height"], info["height"])
        assert_equal(unspent["blockhash"], blockhash)
        assert_equal(unspent["confirmations"], 3)

        # Check that first arg is needed
        assert_raises_rpc_error(-1, "scantxoutset \"action\" ( [scanobjects,...] )", self.nodes[0].scantxoutset)

        # Check that second arg is needed for start
        assert_raises_rpc_error(-1, "scanobjects argument is required for the start action", self.nodes[0].scantxoutset, "start")

        # Check that invalid command give error
        assert_raises_rpc_error(-8, "Invalid action 'invalid_command'", self.nodes[0].scantxoutset, "invalid_command")


if __name__ == "__main__":
    ScantxoutsetTest(__file__).main()
