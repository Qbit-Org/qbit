// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <common/args.h>
#include <util/chaintype.h>

#include <stdexcept>
#include <string>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(argsman_chain_tests)

BOOST_AUTO_TEST_CASE(testnet_only_release_mainnet_guard)
{
    ArgsManager args;
    args.AddArg("-chain=<chain>", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-testnet4", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

#if QBIT_TESTNET_ONLY_RELEASE
    const auto check_mainnet_guard = [](const std::runtime_error& e) {
        const std::string message{e.what()};
        return message.find("public testnet4 only") != std::string::npos &&
               message.find("-testnet4") != std::string::npos &&
               message.find("-chain=testnet4") != std::string::npos &&
               message.find("Mainnet is not launched") != std::string::npos &&
               message.find("in-tree mainnet genesis is a development placeholder") != std::string::npos;
    };
#endif

    const char* argv_default[] = {"cmd"};
    const char* argv_main[] = {"cmd", "-chain=main"};
    const char* argv_testnet4[] = {"cmd", "-testnet4"};
    std::string error;

    BOOST_CHECK(args.ParseParameters(1, argv_default, error));
    BOOST_CHECK(args.GetChainType() == ChainType::MAIN);
    BOOST_CHECK_EQUAL(args.GetChainTypeString(), "main");
#if QBIT_TESTNET_ONLY_RELEASE
    BOOST_CHECK_EXCEPTION(CheckTestnetOnlyReleaseChain(args.GetChainType()), std::runtime_error, check_mainnet_guard);
#else
    BOOST_CHECK_NO_THROW(CheckTestnetOnlyReleaseChain(args.GetChainType()));
#endif

    BOOST_CHECK(args.ParseParameters(2, argv_main, error));
    BOOST_CHECK(args.GetChainType() == ChainType::MAIN);
    BOOST_CHECK_EQUAL(args.GetChainTypeString(), "main");
#if QBIT_TESTNET_ONLY_RELEASE
    BOOST_CHECK_EXCEPTION(CheckTestnetOnlyReleaseChain(args.GetChainType()), std::runtime_error, check_mainnet_guard);
#else
    BOOST_CHECK_NO_THROW(CheckTestnetOnlyReleaseChain(args.GetChainType()));
#endif

    BOOST_CHECK(args.ParseParameters(2, argv_testnet4, error));
    BOOST_CHECK(args.GetChainType() == ChainType::TESTNET4);
    BOOST_CHECK_EQUAL(args.GetChainTypeString(), "testnet4");
    BOOST_CHECK_NO_THROW(CheckTestnetOnlyReleaseChain(args.GetChainType()));
}

BOOST_AUTO_TEST_SUITE_END()
