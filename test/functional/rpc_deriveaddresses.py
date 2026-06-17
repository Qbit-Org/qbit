#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the deriveaddresses rpc call."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.descriptors import descsum_create
from test_framework.util import assert_equal, assert_raises_rpc_error

P2MR_ROOT_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
P2MR_REGTEST_ADDRESS = "qbrt1zqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s8kqqny"
P2MR_PQC_REGTEST_ADDRESSES = [
    "qbrt1zkmrc2kyue9uf34x29gzy6c73m4y8z35neeaqqw95l5a647ej4l5suqqg6f",
    "qbrt1zq8dy85fl2gl9mcp735w4svgdgldhx02s3uak05jnajcqq5rsh5rsxqsptm",
]

class DeriveaddressesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        assert_raises_rpc_error(-5, "Missing checksum", self.nodes[0].deriveaddresses, "a")

        keypath = "qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1"
        rawmr_descriptor = descsum_create(f"rawmr({P2MR_ROOT_HEX})")
        assert_equal(self.nodes[0].deriveaddresses(rawmr_descriptor), [P2MR_REGTEST_ADDRESS])

        p2mr_pqc_descriptor = descsum_create(f"mr(pk(pqc({keypath}/0)))")
        assert_equal(self.nodes[0].deriveaddresses(p2mr_pqc_descriptor), [P2MR_PQC_REGTEST_ADDRESSES[0]])

        p2mr_pqc_ranged_descriptor = descsum_create(f"mr(pk(pqc({keypath}/*)))")
        assert_equal(self.nodes[0].deriveaddresses(p2mr_pqc_ranged_descriptor, [0, 1]), P2MR_PQC_REGTEST_ADDRESSES)

        descriptor = descsum_create(f"wpkh({keypath}/0)")
        address = self.nodes[0].deriveaddresses(descriptor)[0]
        assert_equal(self.nodes[0].deriveaddresses(descriptor), [address])

        descriptor = descriptor[:-9]
        assert_raises_rpc_error(-5, "Missing checksum", self.nodes[0].deriveaddresses, descriptor)

        descriptor_pubkey = descsum_create("wpkh(qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1/1/0)")
        assert_equal(self.nodes[0].deriveaddresses(descriptor_pubkey), [address])

        ranged_descriptor = descsum_create(f"wpkh({keypath}/*)")
        range_addresses = self.nodes[0].deriveaddresses(ranged_descriptor, 2)
        assert_equal(self.nodes[0].deriveaddresses(ranged_descriptor, [1, 2]), range_addresses[1:])
        assert_equal(range_addresses[0], address)

        multipath_descriptor = descsum_create("wpkh(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/<0;1>/*)")
        multipath_addresses = self.nodes[0].deriveaddresses(multipath_descriptor, [1, 2])
        assert_equal(multipath_addresses[1], range_addresses[1:])
        assert_equal(len(multipath_addresses[0]), 2)
        assert_equal(len(multipath_addresses[1]), 2)
        assert multipath_addresses[0] != multipath_addresses[1]

        assert_raises_rpc_error(-8, "Range should not be specified for an un-ranged descriptor", self.nodes[0].deriveaddresses, descsum_create(f"wpkh({keypath}/0)"), [0, 2])

        assert_raises_rpc_error(-8, "Range must be specified for a ranged descriptor", self.nodes[0].deriveaddresses, ranged_descriptor)

        assert_raises_rpc_error(-8, "End of range is too high", self.nodes[0].deriveaddresses, ranged_descriptor, 10000000000)

        assert_raises_rpc_error(-8, "Range is too large", self.nodes[0].deriveaddresses, ranged_descriptor, [1000000000, 2000000000])

        assert_raises_rpc_error(-8, "Range specified as [begin,end] must not have begin after end", self.nodes[0].deriveaddresses, ranged_descriptor, [2, 0])

        assert_raises_rpc_error(-8, "Range should be greater or equal than 0", self.nodes[0].deriveaddresses, ranged_descriptor, [-1, 0])

        combo_descriptor = descsum_create("combo(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/1/0)")
        legacy_address = self.nodes[0].deriveaddresses(descsum_create(f"pkh({keypath}/0)"))[0]
        p2sh_segwit_address = self.nodes[0].deriveaddresses(descsum_create(f"sh(wpkh({keypath}/0))"))[0]
        assert_equal(self.nodes[0].deriveaddresses(combo_descriptor), [legacy_address, address, p2sh_segwit_address])

        # P2PK does not have a valid address
        assert_raises_rpc_error(-5, "Descriptor does not have a corresponding address", self.nodes[0].deriveaddresses, descsum_create("pk(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm)"))

        # Before #26275, bitcoind would crash when deriveaddresses was
        # called with derivation index 2147483647, which is the maximum
        # positive value of a signed int32, and - currently - the
        # maximum value that the deriveaddresses bitcoin RPC call
        # accepts as derivation index.
        max_index_address = self.nodes[0].deriveaddresses(descsum_create("wpkh(qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1/1/2147483647)"))[0]
        assert_equal(self.nodes[0].deriveaddresses(ranged_descriptor, [2147483647, 2147483647]), [max_index_address])

        hardened_without_privkey_descriptor = descsum_create("wpkh(qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1'/1/0)")
        assert_raises_rpc_error(-5, "Cannot derive script without private keys", self.nodes[0].deriveaddresses, hardened_without_privkey_descriptor)

        bare_multisig_descriptor = descsum_create("multi(1,qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1/1/0,qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh/1/1/1)")
        assert_raises_rpc_error(-5, "Descriptor does not have a corresponding address", self.nodes[0].deriveaddresses, bare_multisig_descriptor)

if __name__ == '__main__':
    DeriveaddressesTest(__file__).main()
