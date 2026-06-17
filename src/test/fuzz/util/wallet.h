// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_TEST_FUZZ_UTIL_WALLET_H
#define QBIT_TEST_FUZZ_UTIL_WALLET_H

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <key_io.h>
#include <outputtype.h>
#include <policy/policy.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

namespace wallet {

/**
 * Wraps a descriptor wallet for fuzzing.
 */
struct FuzzedWallet {
    std::shared_ptr<CWallet> wallet;
    FuzzedWallet(interfaces::Chain& chain, const std::string& name, const std::string& seed_insecure)
    {
        wallet = std::make_shared<CWallet>(&chain, name, CreateMockableWalletDatabase());
        {
            LOCK(wallet->cs_wallet);
            wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            auto height{*Assert(chain.getHeight())};
            wallet->SetLastBlockProcessed(height, chain.getBlockHash(height));
        }
        wallet->m_keypool_size = 1; // Avoid timeout in TopUp()
        assert(wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
        ImportDescriptors(seed_insecure);
    }
    void ImportDescriptors(const std::string& seed_insecure)
    {
        const CExtKey master_key = DecodeExtKey(seed_insecure);
        assert(master_key.key.IsValid());

        LOCK(wallet->cs_wallet);
        assert(RunWithinTxn(wallet->GetDatabase(), /*process_desc=*/"setup descriptors", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            wallet->SetupDescriptorScriptPubKeyMans(batch, master_key, GetSupportedOutputTypes());
            return true;
        }));
    }
    CTxDestination GetDestination(FuzzedDataProvider& fuzzed_data_provider)
    {
        auto type{fuzzed_data_provider.PickValueInArray(SUPPORTED_OUTPUT_TYPES)};
        if (fuzzed_data_provider.ConsumeBool()) {
            return *Assert(wallet->GetNewDestination(type, ""));
        } else {
            return *Assert(wallet->GetNewChangeDestination(type));
        }
    }
    CScript GetScriptPubKey(FuzzedDataProvider& fuzzed_data_provider) { return GetScriptForDestination(GetDestination(fuzzed_data_provider)); }
};
}

#endif // QBIT_TEST_FUZZ_UTIL_WALLET_H
