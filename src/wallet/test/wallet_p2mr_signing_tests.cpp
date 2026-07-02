// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_signing_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(P2MRWalletCanSignSingleInputSpend)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    CPubKey descriptor_pubkey;
    CScript p2mr_script;
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        std::vector<CScript> scripts;
        FlatSigningProvider out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, scripts, out_keys));
        BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
        BOOST_REQUIRE_EQUAL(out_keys.pubkeys.size(), 1U);
        p2mr_script = scripts.at(0);
        descriptor_pubkey = out_keys.pubkeys.begin()->second;
    }

    auto provider = p2mr_spk_man->GetSigningProvider(descriptor_pubkey);
    BOOST_REQUIRE(provider);
    BOOST_CHECK_EQUAL(provider->mr_trees.size(), 1U);
    BOOST_CHECK_EQUAL(provider->pqc_keys.size(), 1U);

    std::vector<std::vector<unsigned char>> solutions;
    BOOST_REQUIRE_EQUAL(Solver(p2mr_script, solutions), TxoutType::WITNESS_V2_P2MR);
    const WitnessV2P2MR output{std::span<const unsigned char>{solutions.at(0)}};
    P2MRSpendData spenddata;
    BOOST_REQUIRE(provider->GetP2MRSpendData(output, spenddata));
    BOOST_CHECK_EQUAL(spenddata.scripts.size(), 1U);

    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(1 * COIN, p2mr_script);

    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint{funding_tx.GetHash(), 0});
    spend_tx.vout.emplace_back(1 * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::map<COutPoint, Coin> coins;
    coins.emplace(spend_tx.vin.at(0).prevout, Coin{funding_tx.vout.at(0), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});

    std::map<int, bilingual_str> input_errors;
    const auto format_errors = [&input_errors]() {
        std::string message;
        for (const auto& [input_index, error] : input_errors) {
            if (!message.empty()) message += "; ";
            message += strprintf("input %d: %s", input_index, error.original);
        }
        return message;
    };

    bool signed_ok{false};
    {
        LOCK(wallet->cs_wallet);
        signed_ok = wallet->SignTransaction(spend_tx, coins, SIGHASH_DEFAULT, input_errors);
    }
    BOOST_REQUIRE_MESSAGE(signed_ok, format_errors());
    BOOST_CHECK_MESSAGE(input_errors.empty(), format_errors());
    BOOST_CHECK(!spend_tx.vin.at(0).scriptWitness.IsNull());
}

BOOST_AUTO_TEST_CASE(P2MRWalletCanSignManyInputSpend)
{
    static constexpr size_t INPUT_COUNT{3};

    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, FOUR_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    std::vector<CScript> p2mr_scripts;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        for (int32_t pos{0}; pos < static_cast<int32_t>(INPUT_COUNT); ++pos) {
            std::vector<CScript> scripts;
            FlatSigningProvider out_keys;
            BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(pos, wallet_descriptor.cache, scripts, out_keys));
            BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
            p2mr_scripts.push_back(scripts.at(0));
        }
    }

    CMutableTransaction funding_tx;
    for (const CScript& script : p2mr_scripts) {
        funding_tx.vout.emplace_back(1 * COIN, script);
    }

    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;
    const auto funding_txid{funding_tx.GetHash()};
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        const COutPoint prevout{funding_txid, static_cast<uint32_t>(input_index)};
        spend_tx.vin.emplace_back(prevout);
        coins.emplace(prevout, Coin{funding_tx.vout.at(input_index), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    spend_tx.vout.emplace_back(static_cast<CAmount>(INPUT_COUNT) * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::map<int, bilingual_str> input_errors;
    const auto format_errors = [&input_errors]() {
        std::string message;
        for (const auto& [input_index, error] : input_errors) {
            if (!message.empty()) message += "; ";
            message += strprintf("input %d: %s", input_index, error.original);
        }
        return message;
    };

    size_t pqc_signature_count{0};
    bool signed_ok{false};
    {
        LOCK(wallet->cs_wallet);
        signed_ok = wallet->SignTransaction(spend_tx, coins, SIGHASH_DEFAULT, input_errors, [&](const CPQCPubKey&, uint32_t, uint32_t) {
            ++pqc_signature_count;
        });
    }
    BOOST_REQUIRE_MESSAGE(signed_ok, format_errors());
    BOOST_CHECK_MESSAGE(input_errors.empty(), format_errors());
    BOOST_CHECK_EQUAL(pqc_signature_count, INPUT_COUNT);
    for (const CTxIn& input : spend_tx.vin) {
        BOOST_CHECK(!input.scriptWitness.IsNull());
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
