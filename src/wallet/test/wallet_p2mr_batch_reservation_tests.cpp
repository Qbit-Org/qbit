// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_batch_reservation_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(P2MRBatchPQCReservationAdvancesCounterRange)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    const CachedP2MRPubKeys pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};
    const auto provider{p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(provider);
    BOOST_REQUIRE(provider->pqc_counter_batch_reserver);

    std::map<CPQCPubKey, uint32_t> counts{{pubkeys.pqc_pubkey, 3}};
    std::map<CPQCPubKey, PQCSignatureCounterRange> ranges;
    BOOST_REQUIRE(provider->pqc_counter_batch_reserver(counts, ranges));

    BOOST_REQUIRE_EQUAL(ranges.size(), 1U);
    const auto& range{ranges.at(pubkeys.pqc_pubkey)};
    BOOST_CHECK(range.pubkey == pubkeys.pqc_pubkey);
    BOOST_CHECK_EQUAL(range.previous_counter, 0U);
    BOOST_CHECK_EQUAL(range.reserved_counter, 3U);
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), 3U);
}

BOOST_AUTO_TEST_CASE(P2MRBatchPQCReservationRejectsNearLimitWithoutAdvancing)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    const CachedP2MRPubKeys pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};
    auto provider{p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(provider);

    uint32_t previous_counter{0};
    uint32_t reserved_counter{0};
    BOOST_REQUIRE(provider->pqc_counter_reserver(pubkeys.pqc_pubkey, PQC_MAX_SIGNATURES - 1, previous_counter, reserved_counter));
    BOOST_CHECK_EQUAL(previous_counter, 0U);
    BOOST_CHECK_EQUAL(reserved_counter, PQC_MAX_SIGNATURES - 1);

    provider = p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey);
    BOOST_REQUIRE(provider);
    BOOST_REQUIRE(provider->pqc_counter_batch_reserver);

    std::map<CPQCPubKey, uint32_t> counts{{pubkeys.pqc_pubkey, 2}};
    std::map<CPQCPubKey, PQCSignatureCounterRange> ranges;
    BOOST_CHECK(!provider->pqc_counter_batch_reserver(counts, ranges));
    BOOST_CHECK(ranges.empty());
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), PQC_MAX_SIGNATURES - 1);
}

BOOST_AUTO_TEST_CASE(P2MRBatchPQCReservationRejectsMultipleKeysAtomically)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, FOUR_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    const CachedP2MRPubKeys first_pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};
    const CachedP2MRPubKeys second_pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/1)};
    BOOST_REQUIRE(!(first_pubkeys.pqc_pubkey == second_pubkeys.pqc_pubkey));

    auto provider{p2mr_spk_man->GetSigningProvider(first_pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(provider);

    uint32_t previous_counter{0};
    uint32_t reserved_counter{0};
    BOOST_REQUIRE(provider->pqc_counter_reserver(first_pubkeys.pqc_pubkey, PQC_MAX_SIGNATURES - 1, previous_counter, reserved_counter));
    BOOST_CHECK_EQUAL(previous_counter, 0U);
    BOOST_CHECK_EQUAL(reserved_counter, PQC_MAX_SIGNATURES - 1);

    provider = p2mr_spk_man->GetSigningProvider(first_pubkeys.pqc_pubkey);
    BOOST_REQUIRE(provider);
    BOOST_REQUIRE(provider->pqc_counter_batch_reserver);

    std::map<CPQCPubKey, uint32_t> counts{{first_pubkeys.pqc_pubkey, 2}, {second_pubkeys.pqc_pubkey, 1}};
    std::map<CPQCPubKey, PQCSignatureCounterRange> ranges;
    BOOST_CHECK(!provider->pqc_counter_batch_reserver(counts, ranges));
    BOOST_CHECK(ranges.empty());
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, first_pubkeys.descriptor_pubkey, first_pubkeys.pqc_pubkey), PQC_MAX_SIGNATURES - 1);
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, second_pubkeys.descriptor_pubkey, second_pubkeys.pqc_pubkey), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
