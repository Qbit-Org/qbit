// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_basic_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(DefaultAddressTypeRequiresP2MRSPKM)
{
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto seeded_wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    CKey key = GenerateRandomKey();
    BOOST_REQUIRE(CreateDescriptor(*seeded_wallet, "wpkh(" + EncodeSecret(key) + ")", true));

    auto wallet = TestLoadWallet(DuplicateMockDatabase(seeded_wallet->GetDatabase()), context, WALLET_FLAG_DESCRIPTORS);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_CHECK_EQUAL(wallet->m_default_address_type, OutputType::BECH32);
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_AUTO_TEST_CASE(DefaultAddressTypeUsesP2MROnMainnet)
{
    m_args.ForceSetArg("-keypool", util::ToString(SINGLE_ADDRESS_KEYPOOL_SIZE));
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_CHECK_EQUAL(wallet->m_default_address_type, OutputType::P2MR);
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(DefaultAddressTypeUsesP2MROnRegtestP2MROnly, RegtestP2MROnlyWalletTestingSetup)
{
    m_args.ForceSetArg("-keypool", util::ToString(SINGLE_ADDRESS_KEYPOOL_SIZE));
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_CHECK_EQUAL(wallet->m_default_address_type, OutputType::P2MR);
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(WalletOutputAvailabilityRequiresAllowedTypeAndManager, RegtestP2MROnlyWalletTestingSetup)
{
    CWallet bare_wallet{m_node.chain.get(), "", CreateMockableWalletDatabase()};
    BOOST_CHECK(bare_wallet.GetActiveScriptPubKeyMans().empty());
    BOOST_CHECK(!HasWalletOutputTypeManager(bare_wallet, OutputType::P2MR, /*internal=*/false));
    BOOST_CHECK(!IsAvailableWalletOutputType(bare_wallet, OutputType::P2MR, /*internal=*/false));

    m_args.ForceSetArg("-keypool", util::ToString(SINGLE_ADDRESS_KEYPOOL_SIZE));
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_CHECK(HasWalletOutputTypeManager(*wallet, OutputType::P2MR, /*internal=*/false));
        BOOST_CHECK(IsAvailableWalletOutputType(*wallet, OutputType::P2MR, /*internal=*/false));
        BOOST_CHECK(!HasWalletOutputTypeManager(*wallet, OutputType::LEGACY, /*internal=*/false));
        BOOST_CHECK(!IsAvailableWalletOutputType(*wallet, OutputType::LEGACY, /*internal=*/false));
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_AUTO_TEST_CASE(FreshWalletOnlyCreatesP2MRManagers)
{
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/false));
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(FreshRegtestWalletDefaultsToP2MROnlyManagers, RegtestDefaultWalletTestingSetup)
{
    m_args.ForceSetArg("-keypool", util::ToString(SINGLE_ADDRESS_KEYPOOL_SIZE));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/true));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/true));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true));
        BOOST_CHECK_EQUAL(wallet->m_default_address_type, OutputType::P2MR);
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(FreshRegtestWalletCanOptOutOfP2MROnlyManagers, RegtestUnrestrictedWalletTestingSetup)
{
    m_args.ForceSetArg("-keypool", util::ToString(SINGLE_ADDRESS_KEYPOOL_SIZE));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    {
        LOCK(wallet->cs_wallet);
        for (const auto& output_type : SUPPORTED_OUTPUT_TYPES) {
            BOOST_CHECK(wallet->GetScriptPubKeyMan(output_type, /*internal=*/false));
            BOOST_CHECK(wallet->GetScriptPubKeyMan(output_type, /*internal=*/true));
        }
        BOOST_CHECK_EQUAL(wallet->m_default_address_type, DEFAULT_ADDRESS_TYPE);
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
