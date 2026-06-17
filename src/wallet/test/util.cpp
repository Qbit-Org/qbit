// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/util.h>

#include <chain.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <validationinterface.h>
#include <wallet/context.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <memory>

namespace wallet {
namespace {
void SetupDescriptorScriptPubKeyMans(CWallet& wallet, std::span<const OutputType> output_types)
{
    Assert(!output_types.empty());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    CExtKey master_key;
    master_key.SetSeed(GenerateRandomKey());
    Assert(RunWithinTxn(wallet.GetDatabase(), /*process_desc=*/"setup descriptors", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) {
        for (bool internal : {false, true}) {
            for (OutputType output_type : output_types) {
                wallet.SetupDescriptorScriptPubKeyMan(batch, master_key, output_type, internal);
            }
        }
        return true;
    }));
}
} // namespace

std::unique_ptr<CWallet> CreateSyncedWallet(interfaces::Chain& chain, CChain& cchain, const CKey& key)
{
    return CreateSyncedWallet(chain, cchain, key, GetSupportedOutputTypes(), /*keypool_size=*/1);
}

std::unique_ptr<CWallet> CreateDescriptorWallet(interfaces::Chain& chain, std::span<const OutputType> output_types, int64_t keypool_size, const std::string& wallet_name)
{
    auto wallet = std::make_unique<CWallet>(&chain, wallet_name, CreateMockableWalletDatabase());
    Assert(wallet->LoadWallet() == DBErrors::LOAD_OK);
    wallet->m_keypool_size = keypool_size;
    SetupDescriptorScriptPubKeyMans(*wallet, output_types);
    return wallet;
}

std::unique_ptr<CWallet> CreateSyncedWallet(interfaces::Chain& chain, CChain& cchain, const CKey& key, std::span<const OutputType> output_types, int64_t keypool_size)
{
    auto wallet = CreateDescriptorWallet(chain, output_types, keypool_size);
    {
        LOCK2(wallet->cs_wallet, ::cs_main);
        wallet->SetLastBlockProcessed(cchain.Height(), cchain.Tip()->GetBlockHash());
    }
    {
        LOCK(wallet->cs_wallet);
        FlatSigningProvider provider;
        std::string error;
        auto descs = Parse("combo(" + EncodeSecret(key) + ")", provider, error, /* require_checksum=*/ false);
        assert(descs.size() == 1);
        auto& desc = descs.at(0);
        WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
        Assert(wallet->AddWalletDescriptor(w_desc, provider, "", false));
    }
    WalletRescanReserver reserver(*wallet);
    reserver.reserve();
    CWallet::ScanResult result = wallet->ScanForWalletTransactions(cchain.Genesis()->GetBlockHash(), /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
    assert(result.status == CWallet::ScanResult::SUCCESS);
    assert(result.last_scanned_block == cchain.Tip()->GetBlockHash());
    assert(*result.last_scanned_height == cchain.Height());
    assert(result.last_failed_block.IsNull());
    return wallet;
}

std::shared_ptr<CWallet> TestLoadWallet(std::unique_ptr<WalletDatabase> database, WalletContext& context, uint64_t create_flags)
{
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CWallet::Create(context, "", std::move(database), create_flags, error, warnings);
    NotifyWalletLoaded(context, wallet);
    if (context.chain) {
        wallet->postInitProcess();
    }
    return wallet;
}

std::shared_ptr<CWallet> TestLoadWallet(WalletContext& context)
{
    DatabaseOptions options;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto database = MakeWalletDatabase("", options, status, error);
    return TestLoadWallet(std::move(database), context, options.create_flags);
}

void TestUnloadWallet(std::shared_ptr<CWallet>&& wallet)
{
    // Calls SyncWithValidationInterfaceQueue
    wallet->chain().waitForNotificationsIfTipChanged({});
    wallet->m_chain_notifications_handler.reset();
    WaitForDeleteWallet(std::move(wallet));
}

std::unique_ptr<WalletDatabase> DuplicateMockDatabase(WalletDatabase& database)
{
    return std::make_unique<MockableDatabase>(dynamic_cast<MockableDatabase&>(database).m_records);
}

std::string getnewaddress(CWallet& w)
{
    constexpr auto output_type = OutputType::BECH32;
    return EncodeDestination(getNewDestination(w, output_type));
}

CTxDestination getNewDestination(CWallet& w, OutputType output_type)
{
    return *Assert(w.GetNewDestination(output_type, ""));
}

MockableCursor::MockableCursor(const MockableData& records, bool pass, std::span<const std::byte> prefix)
{
    m_pass = pass;
    std::tie(m_cursor, m_cursor_end) = records.equal_range(BytePrefix{prefix});
}

DatabaseCursor::Status MockableCursor::Next(DataStream& key, DataStream& value)
{
    if (!m_pass) {
        return Status::FAIL;
    }
    if (m_cursor == m_cursor_end) {
        return Status::DONE;
    }
    key.clear();
    value.clear();
    const auto& [key_data, value_data] = *m_cursor;
    key.write(key_data);
    value.write(value_data);
    m_cursor++;
    return Status::MORE;
}

bool MockableBatch::ReadKey(DataStream&& key, DataStream& value)
{
    if (!m_database.m_pass || !m_database.m_read_pass) {
        return false;
    }
    SerializeData key_data{key.begin(), key.end()};
    const auto& it = m_database.m_records.find(key_data);
    if (it == m_database.m_records.end()) {
        return false;
    }
    value.clear();
    value.write(it->second);
    return true;
}

bool MockableBatch::WriteKey(DataStream&& key, DataStream&& value, bool overwrite)
{
    ++m_database.m_write_count;
    if (!m_database.m_pass || !m_database.m_write_pass ||
        (m_database.m_write_fail_after >= 0 && m_database.m_write_count > m_database.m_write_fail_after)) {
        return false;
    }
    SerializeData key_data{key.begin(), key.end()};
    SerializeData value_data{value.begin(), value.end()};
    auto [it, inserted] = m_database.m_records.emplace(key_data, value_data);
    if (!inserted && overwrite) { // Overwrite if requested
        it->second = value_data;
        inserted = true;
    }
    return inserted;
}

bool MockableBatch::EraseKey(DataStream&& key)
{
    if (!m_database.m_pass || !m_database.m_erase_pass) {
        return false;
    }
    SerializeData key_data{key.begin(), key.end()};
    m_database.m_records.erase(key_data);
    return true;
}

bool MockableBatch::HasKey(DataStream&& key)
{
    if (!m_database.m_pass || !m_database.m_read_pass) {
        return false;
    }
    SerializeData key_data{key.begin(), key.end()};
    return m_database.m_records.count(key_data) > 0;
}

bool MockableBatch::ErasePrefix(std::span<const std::byte> prefix)
{
    if (!m_database.m_pass || !m_database.m_erase_pass) {
        return false;
    }
    auto it = m_database.m_records.begin();
    while (it != m_database.m_records.end()) {
        auto& key = it->first;
        if (key.size() < prefix.size() || std::search(key.begin(), key.end(), prefix.begin(), prefix.end()) != key.begin()) {
            it++;
            continue;
        }
        it = m_database.m_records.erase(it);
    }
    return true;
}

std::unique_ptr<DatabaseCursor> MockableBatch::GetNewCursor()
{
    return std::make_unique<MockableCursor>(m_database.m_records, m_database.m_pass && m_database.m_read_pass);
}

std::unique_ptr<DatabaseCursor> MockableBatch::GetNewPrefixCursor(std::span<const std::byte> prefix)
{
    return std::make_unique<MockableCursor>(m_database.m_records, m_database.m_pass && m_database.m_read_pass, prefix);
}

bool MockableBatch::TxnBegin()
{
    ++m_database.m_txn_begin_count;
    return m_database.m_pass && m_database.m_txn_begin_pass;
}

bool MockableBatch::TxnCommit()
{
    ++m_database.m_txn_commit_count;
    return m_database.m_pass && m_database.m_txn_commit_pass;
}

bool MockableBatch::TxnAbort()
{
    ++m_database.m_txn_abort_count;
    return m_database.m_pass && m_database.m_txn_abort_pass;
}

std::unique_ptr<WalletDatabase> CreateMockableWalletDatabase(MockableData records)
{
    return std::make_unique<MockableDatabase>(records);
}

MockableDatabase& GetMockableDatabase(CWallet& wallet)
{
    return dynamic_cast<MockableDatabase&>(wallet.GetDatabase());
}

wallet::DescriptorScriptPubKeyMan* CreateDescriptor(CWallet& keystore, const std::string& desc_str, const bool success)
{
    keystore.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    FlatSigningProvider keys;
    std::string error;
    auto parsed_descs = Parse(desc_str, keys, error, false);
    Assert(success == (!parsed_descs.empty()));
    if (!success) return nullptr;
    auto& desc = parsed_descs.at(0);

    const int64_t range_start = 0, range_end = 1, next_index = 0, timestamp = 1;

    WalletDescriptor w_desc(std::move(desc), timestamp, range_start, range_end, next_index);

    LOCK(keystore.cs_wallet);
    auto spkm = Assert(keystore.AddWalletDescriptor(w_desc, keys,/*label=*/"", /*internal=*/false));
    return &spkm.value().get();
};
} // namespace wallet
