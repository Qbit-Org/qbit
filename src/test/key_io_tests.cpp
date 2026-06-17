// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/key_io_invalid.json.h>
#include <test/data/key_io_valid.json.h>

#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <script/script.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>

BOOST_FIXTURE_TEST_SUITE(key_io_tests, BasicTestingSetup)

// Goal: check that parsed keys match test payload
BOOST_AUTO_TEST_CASE(key_io_valid_parse)
{
    UniValue tests = read_json(json_tests::key_io_valid);
    CKey privkey;
    CTxDestination destination;
    SelectParams(ChainType::MAIN);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) { // Allow for extra stuff (useful for comments)
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        const std::vector<std::byte> exp_payload{ParseHex<std::byte>(test[1].get_str())};
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        bool try_case_flip = metadata.find_value("tryCaseFlip").isNull() ? false : metadata.find_value("tryCaseFlip").get_bool();
        if (isPrivkey) {
            bool isCompressed = metadata.find_value("isCompressed").get_bool();
            // Must be valid private key
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(privkey.IsValid(), "!IsValid:" + strTest);
            BOOST_CHECK_MESSAGE(privkey.IsCompressed() == isCompressed, "compressed mismatch:" + strTest);
            BOOST_CHECK_MESSAGE(std::ranges::equal(privkey, exp_payload), "key mismatch:" + strTest);

            // Private key must be invalid public key
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid privkey as pubkey:" + strTest);
        } else {
            // Must be valid public key
            const std::vector<unsigned char> exp_script_payload{ParseHex(test[1].get_str())};
            CScript exp_script(exp_script_payload.begin(), exp_script_payload.end());
            CTxDestination exp_dest;
            const bool is_p2mr = ExtractDestination(exp_script, exp_dest) && std::holds_alternative<WitnessV2P2MR>(exp_dest);
            std::string error;
            destination = DecodeDestination(exp_base58string, error);
            if (IsP2MROnlyOutputChain() && !is_p2mr && !IsDestinationOutputTypeAllowed(destination)) {
                BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid unsupported address:" + strTest);
                BOOST_CHECK_EQUAL(error, "Address type is not supported on this chain; use a p2mr address.");

                // Public key must be invalid private key
                privkey = DecodeSecret(exp_base58string);
                BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid pubkey as privkey:" + strTest);
                continue;
            }

            CScript script = GetScriptForDestination(destination);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination), "!IsValid:" + strTest);
            BOOST_CHECK_EQUAL(error, "");
            BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));

            // Try flipped case version
            for (char& c : exp_base58string) {
                if (c >= 'a' && c <= 'z') {
                    c = (c - 'a') + 'A';
                } else if (c >= 'A' && c <= 'Z') {
                    c = (c - 'A') + 'a';
                }
            }
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination) == try_case_flip, "!IsValid case flipped:" + strTest);
            if (IsValidDestination(destination)) {
                script = GetScriptForDestination(destination);
                BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));
            }

            // Public key must be invalid private key
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid pubkey as privkey:" + strTest);
        }
    }
}

// Goal: check that generated keys match test vectors
BOOST_AUTO_TEST_CASE(key_io_valid_gen)
{
    UniValue tests = read_json(json_tests::key_io_valid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        std::vector<unsigned char> exp_payload = ParseHex(test[1].get_str());
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        if (isPrivkey) {
            bool isCompressed = metadata.find_value("isCompressed").get_bool();
            CKey key;
            key.Set(exp_payload.begin(), exp_payload.end(), isCompressed);
            assert(key.IsValid());
            BOOST_CHECK_MESSAGE(EncodeSecret(key) == exp_base58string, "result mismatch: " + strTest);
        } else {
            CTxDestination dest;
            CScript exp_script(exp_payload.begin(), exp_payload.end());
            BOOST_CHECK(ExtractDestination(exp_script, dest));
            std::string address = EncodeDestination(dest);

            BOOST_CHECK_EQUAL(address, exp_base58string);
        }
    }

    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(key_io_legacy_key_prefixes_parse)
{
    struct LegacySecretTest {
        ChainType chain;
        std::string legacy;
        std::string current;
        std::string payload;
        bool compressed;
    };

    const std::vector<LegacySecretTest> secret_tests{
        {ChainType::MAIN, "5JuW2AMDYu4xVwRG9DZW18VbzQrGcd5RCgb99sS6ehJsNQXu5b9", "6MAaVMGCy62ygNS8FBoUa55cNwwXmTCZbVnUiWktU1WtfjPwajq", "8f8943bf956de595665c38ffff23827e17c10cdc1c27a028caae6c9810626198", false},
        {ChainType::MAIN, "L5nJeqKmpHp4P7F8ZYyjwc5a7P4d8EabuGAzfGJk7yC1BJyzNaEd", "QfkrNqVfF4DKb9ewhuDRd11fprHr1Cz8wxV31M3gLoZ4ua8P32dK", "ff778740f88ddcf102aeb81daee289c044c4a4571c4b6f287400f4b8e0b843f8", true},
        {ChainType::TESTNET4, "92ZdE5HoLafywnTBbzPxbvRmp75pSfzvdU3XaZGh1cToipgdHVh", "6yzDTvurMdRAik1AJdY1RMrXx9X1nibWdUixhRK1Ne49cwFQfgs", "80c32d81e91bdea04cd7a3819b32275fc3298af4c7ec87eb0099527d041ced5c", false},
        {ChainType::SIGNET, "cND53Dhp8eCZqG2ghe8YhSCGesXZ8fE5PGD1khrqNvEi4RBoXhEK", "TLqcANiwTGKBPhDpy2458pRZUNGmD8gjTKD4czj4RjGHtE6shDyH", "12b5a10f3a11e708dc5412833c47ab7c368a21b9efe19293793ec879ce683018", true},
        {ChainType::REGTEST, "cPisAUdLvqqAr6MYtXnrWvgvyUAwuNyuTvZkDGw6miPhZdaiSDNH", "RbPqRhKg9cx8iKPUWzyfQDnNokWKxqBqag6EN7eBvnNk1U8iGZDT", "3fdfec1371cedcdb8c190ca6ff8ad603f817edc0d93c2a687c7b36dd66e70f2a", true},
    };

    for (const auto& test : secret_tests) {
        SelectParams(test.chain);
        CKey key = DecodeSecret(test.legacy);
        BOOST_REQUIRE_MESSAGE(key.IsValid(), test.legacy);
        BOOST_CHECK_EQUAL(key.IsCompressed(), test.compressed);
        BOOST_CHECK(std::ranges::equal(key, ParseHex<std::byte>(test.payload)));
        BOOST_CHECK_EQUAL(EncodeSecret(key), test.current);
    }

    SelectParams(ChainType::MAIN);
    CExtKey main_xprv = DecodeExtKey("xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc");
    BOOST_REQUIRE(main_xprv.key.IsValid());
    BOOST_CHECK_EQUAL(EncodeExtKey(main_xprv), "qprvYei2WCrgXEtABbBuJwdqv29zNbnhhpPSvHiQWzQieq7P2tapJAkWbcHJYK14hNAUCeTFa2LHZ9FMbqAc2PuuvkeMFwhSZUcvUKJHSti2fgp");
    CExtPubKey main_xpub = DecodeExtPubKey("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL");
    BOOST_REQUIRE(main_xpub.pubkey.IsValid());
    BOOST_CHECK_EQUAL(EncodeExtPubKey(main_xpub), "qpubUshNuiPaMcSTQ5GNQyArHA6ivddC7H7JHWe1KNpLDAeMuguxqi4m9QbnPZo9Fc4PAj9LfR6hRMnwfJqBokTxuvWTjriSJkkT2qQMnVc6LKM");

    SelectParams(ChainType::REGTEST);
    CExtKey regtest_tprv = DecodeExtKey("tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK");
    BOOST_REQUIRE(regtest_tprv.key.IsValid());
    BOOST_CHECK_EQUAL(EncodeExtKey(regtest_tprv), "qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm");
    CExtPubKey regtest_tpub = DecodeExtPubKey("tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B");
    BOOST_REQUIRE(regtest_tpub.pubkey.IsValid());
    BOOST_CHECK_EQUAL(EncodeExtPubKey(regtest_tpub), "qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh");

    SelectParams(ChainType::MAIN);
}


// Goal: check that base58 parsing code is robust against a variety of corrupted data
BOOST_AUTO_TEST_CASE(key_io_invalid)
{
    UniValue tests = read_json(json_tests::key_io_invalid); // Negative testcases
    CKey privkey;
    CTxDestination destination;

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();

        // must be invalid as public and as private key
        for (const auto& chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::SIGNET, ChainType::REGTEST}) {
            SelectParams(chain);
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid pubkey in mainnet:" + strTest);
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid privkey in mainnet:" + strTest);
        }
    }
}

BOOST_AUTO_TEST_CASE(key_io_base58_bech32_hrp_collision)
{
    SelectParams(ChainType::MAIN);
    const std::string& hrp = Params().Bech32HRP();

    std::string collision_address;
    std::vector<unsigned char> hash_bytes(20);
    bool found_collision = false;

    for (uint32_t i = 0; i < 200000; ++i) {
        hash_bytes[0] = static_cast<unsigned char>(i);
        hash_bytes[1] = static_cast<unsigned char>(i >> 8);
        hash_bytes[2] = static_cast<unsigned char>(i >> 16);
        hash_bytes[3] = static_cast<unsigned char>(i >> 24);
        hash_bytes[4] = static_cast<unsigned char>(i * 17);
        hash_bytes[5] = static_cast<unsigned char>(i * 31);

        PKHash candidate{uint160(hash_bytes)};
        std::string encoded = EncodeDestination(candidate);
        if (encoded.size() > hrp.size() && encoded[hrp.size()] == '1' &&
            ToLower(encoded.substr(0, hrp.size())) == hrp) {
            collision_address = encoded;
            found_collision = true;
            break;
        }
    }

    BOOST_REQUIRE_MESSAGE(found_collision, "Unable to find a base58 address matching bech32 prefix heuristic");
    std::string error_msg;
    CTxDestination decoded = DecodeDestination(collision_address, error_msg);
    BOOST_CHECK_EQUAL(error_msg, "Address type is not supported on this chain; use a p2mr address.");
    BOOST_CHECK(!IsValidDestination(decoded));
}

BOOST_AUTO_TEST_CASE(key_io_p2mr_uses_dedicated_destination_type)
{
    SelectParams(ChainType::REGTEST);

    const std::vector<unsigned char> witness_program(sizeof(uint256), 0x42);
    const CScript p2mr_script = CScript{} << OP_2 << witness_program;

    CTxDestination extracted_dest;
    BOOST_REQUIRE(ExtractDestination(p2mr_script, extracted_dest));
    BOOST_REQUIRE(std::get_if<WitnessV2P2MR>(&extracted_dest) != nullptr);
    BOOST_CHECK(std::get_if<WitnessUnknown>(&extracted_dest) == nullptr);

    const std::string p2mr_address = EncodeDestination(extracted_dest);
    BOOST_REQUIRE(!p2mr_address.empty());
    const CTxDestination decoded_dest = DecodeDestination(p2mr_address);
    BOOST_REQUIRE(std::get_if<WitnessV2P2MR>(&decoded_dest) != nullptr);
    BOOST_CHECK_EQUAL(HexStr(GetScriptForDestination(decoded_dest)), HexStr(p2mr_script));

    // Canonicalize v2/32 programs to the known P2MR destination type.
    const CTxDestination unknown_v2 = WitnessUnknown{2, witness_program};
    const CTxDestination canonical = DecodeDestination(EncodeDestination(unknown_v2));
    BOOST_CHECK(std::get_if<WitnessV2P2MR>(&canonical) != nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
