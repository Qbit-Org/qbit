// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <clientversion.h>
#include <core_io.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <outputtype.h>
#include <merkleblock.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/p2mr_sizing.h>
#include <script/script.h>
#include <script/solver.h>
#include <sync.h>
#include <uint256.h>
#include <util/bip32.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <cstdint>
#include <fstream>
#include <tuple>
#include <string>
#include <string_view>
#include <set>

#include <univalue.h>



using interfaces::FoundBlock;

namespace wallet {
RPCHelpMan importprunedfunds()
{
    return RPCHelpMan{
        "importprunedfunds",
        "Imports funds without rescan. Corresponding address or script must previously be included in wallet. Aimed towards pruned wallets. The end-user is responsible to import additional transactions that subsequently spend the imported outputs or rescan after the point in the blockchain the transaction is included.\n",
                {
                    {"rawtransaction", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A raw transaction in hex funding an already-existing address in wallet"},
                    {"txoutproof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex output from gettxoutproof that contains the transaction"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }

    DataStream ssMB{ParseHexV(request.params[1], "proof")};
    CMerkleBlock merkleBlock;
    ssMB >> merkleBlock;

    //Search partial merkle tree in proof for our transaction and index in valid block
    std::vector<Txid> vMatch;
    std::vector<unsigned int> vIndex;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Something wrong with merkleblock");
    }

    LOCK(pwallet->cs_wallet);
    int height;
    if (!pwallet->chain().findAncestorByHash(pwallet->GetLastBlockHash(), merkleBlock.header.GetHash(), FoundBlock().height(height))) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");
    }

    std::vector<Txid>::const_iterator it;
    if ((it = std::find(vMatch.begin(), vMatch.end(), tx.GetHash())) == vMatch.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction given doesn't exist in proof");
    }

    unsigned int txnIndex = vIndex[it - vMatch.begin()];

    CTransactionRef tx_ref = MakeTransactionRef(tx);
    if (pwallet->IsMine(*tx_ref)) {
        pwallet->AddToWallet(std::move(tx_ref), TxStateConfirmed{merkleBlock.header.GetHash(), height, static_cast<int>(txnIndex)});
        return UniValue::VNULL;
    }

    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No addresses in wallet correspond to included transaction");
},
    };
}

RPCHelpMan removeprunedfunds()
{
    return RPCHelpMan{
        "removeprunedfunds",
        "Deletes the specified transaction from the wallet. Meant for use with pruned wallets and as a companion to importprunedfunds. This will affect wallet balances.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded id of the transaction you are deleting"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("removeprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("removeprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    Txid hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};
    std::vector<Txid> vHash;
    vHash.push_back(hash);
    if (auto res = pwallet->RemoveTxs(vHash); !res) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);
    }

    return UniValue::VNULL;
},
    };
}

static std::optional<bool> InferPubkeyDBChangeFromAddressBook(const CWallet& wallet, const DescriptorScriptPubKeyMan& desc_spk_man)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    bool saw_address{false};
    bool all_change{true};
    bool all_receive{true};
    for (const CScript& script : desc_spk_man.GetScriptPubKeys()) {
        CTxDestination dest;
        if (!ExtractDestination(script, dest)) continue;
        saw_address = true;
        const bool has_address_book_entry = wallet.FindAddressBookEntry(dest) != nullptr;
        all_change &= !has_address_book_entry;
        all_receive &= has_address_book_entry;
    }
    if (!saw_address || all_change == all_receive) return std::nullopt;
    return all_change;
}

RPCHelpMan exportpubkeydb()
{
    struct ExportedPubkeyRecord {
        std::string pubkey_hex;
        std::optional<int64_t> account;
        std::optional<bool> change;
        std::optional<int64_t> index;

        auto AsTuple() const
        {
            return std::tie(pubkey_hex, account, change, index);
        }

        bool operator<(const ExportedPubkeyRecord& other) const
        {
            return AsTuple() < other.AsTuple();
        }
    };

    return RPCHelpMan{
        "exportpubkeydb",
        "Exports wallet P2MR pubkeys as an explicit-pubkey JSON database that can be imported into a watch-only wallet.",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "count", "The number of exported pubkeys"},
                {RPCResult::Type::ARR, "pubkeys", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "pubkey", "P2MR pubkey (hex, 32 bytes)"},
                                {RPCResult::Type::NUM, "account", /*optional=*/true, "P2MR account number when known"},
                                {RPCResult::Type::BOOL, "change", /*optional=*/true, "True if the pubkey came from a change/internal descriptor"},
                                {RPCResult::Type::NUM, "index", /*optional=*/true, "Descriptor index when known"},
                            },
                        },
                    },
                },
            },
        },
        RPCExamples{
            HelpExampleCli("exportpubkeydb", "") +
            HelpExampleRpc("exportpubkeydb", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    const auto strip_prefix_suffix = [](const std::string& str, std::string_view prefix, std::string_view suffix, std::string& out) {
        if (str.size() < prefix.size() + suffix.size()) return false;
        if (!str.starts_with(prefix)) return false;
        if (!str.ends_with(suffix)) return false;
        out = str.substr(prefix.size(), str.size() - prefix.size() - suffix.size());
        return true;
    };

    const auto parse_p2mr_metadata = [&](const std::string& descriptor,
                                         std::optional<int64_t>& account,
                                         std::optional<bool>& change,
                                         std::optional<int64_t>& fixed_index) {
        std::string descriptor_no_checksum = descriptor;
        const size_t checksum_pos = descriptor.rfind('#');
        if (checksum_pos != std::string::npos) {
            descriptor_no_checksum = descriptor.substr(0, checksum_pos);
        }

        std::string inner;
        if (!strip_prefix_suffix(descriptor_no_checksum, "mr(pk(pqc(", ")))", inner)) return false;

        std::vector<std::string> parts;
        size_t start{0};
        while (true) {
            const size_t slash = inner.find('/', start);
            parts.push_back(inner.substr(start, slash == std::string::npos ? std::string::npos : slash - start));
            if (slash == std::string::npos) break;
            start = slash + 1;
        }
        const auto parse_hardened = [](const std::string& value) -> std::optional<int64_t> {
            if (value.size() < 2 || (value.back() != 'h' && value.back() != '\'')) return std::nullopt;
            return ToIntegral<int64_t>(value.substr(0, value.size() - 1));
        };

        if (parts.size() != 6) return false;
        const auto parsed_purpose = parse_hardened(parts[1]);
        if (!parsed_purpose || *parsed_purpose != 87) return false;
        if (!parse_hardened(parts[2])) return false;
        const auto parsed_account = parse_hardened(parts[3]);
        if (!parsed_account) return false;
        if (parts[4] != "0" && parts[4] != "1") return false;

        account = *parsed_account;
        change = parts[4] == "1";
        if (parts[5] != "*") {
            const auto parsed_index = ToIntegral<int64_t>(parts[5]);
            if (!parsed_index || *parsed_index < 0) return false;
            fixed_index = *parsed_index;
        }
        return true;
    };

    const auto parse_explicit_pubkey = [&](const std::string& descriptor) -> std::optional<CPQCPubKey> {
        std::string descriptor_no_checksum = descriptor;
        const size_t checksum_pos = descriptor.rfind('#');
        if (checksum_pos != std::string::npos) {
            descriptor_no_checksum = descriptor.substr(0, checksum_pos);
        }

        std::string inner;
        if (!strip_prefix_suffix(descriptor_no_checksum, "mr(pk(", "))", inner)) return std::nullopt;
        if (inner.size() != CPQCPubKey::SIZE * 2 || !IsHex(inner)) return std::nullopt;
        return CPQCPubKey{ParseHex(inner)};
    };

    std::set<ExportedPubkeyRecord> pubkeys;
    for (auto spk_man : pwallet->GetAllScriptPubKeyMans()) {
        const auto* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (!desc_spk_man) continue;

        const auto pqc_keys = desc_spk_man->GetPQCKeys();
        WalletDescriptor wallet_descriptor;
        {
            LOCK(desc_spk_man->cs_desc_man);
            wallet_descriptor = desc_spk_man->GetWalletDescriptor();
            const auto out_type = wallet_descriptor.descriptor->GetOutputType();
            if (!out_type || *out_type != OutputType::P2MR) {
                continue;
            }
        }

        const std::string descriptor = wallet_descriptor.descriptor->ToString();
        std::optional<int64_t> account;
        std::optional<bool> descriptor_change;
        std::optional<int64_t> fixed_index;
        parse_p2mr_metadata(descriptor, account, descriptor_change, fixed_index);

        std::optional<bool> change = pwallet->IsInternalScriptPubKeyMan(desc_spk_man);
        if (!change.has_value()) {
            change = descriptor_change;
        }
        if (!change.has_value() && !wallet_descriptor.descriptor->IsRange()) {
            change = InferPubkeyDBChangeFromAddressBook(*pwallet, *desc_spk_man);
        }

        const auto add_pubkey = [&](const CPQCPubKey& pubkey, std::optional<int64_t> index) {
            if (!pubkey.IsValid()) return;
            std::optional<int64_t> exported_account = account;
            std::optional<bool> exported_change = change;
            std::optional<int64_t> exported_index = index;
            if (const auto pool_key = WITH_LOCK(pwallet->cs_wallet, return pwallet->GetPubKeyDBPoolKey(pubkey))) {
                exported_account = pool_key->account;
                exported_change = pool_key->internal;
                exported_index = pool_key->index;
            }
            pubkeys.insert({
                HexStr(std::span{pubkey.data(), pubkey.size()}),
                exported_account,
                exported_change,
                exported_index,
            });
        };

        bool exported_from_cache{false};
        const auto derived_pubkeys = wallet_descriptor.cache.GetCachedDerivedP2MRPubKeys();
        for (const auto& [_, pubkey_map] : derived_pubkeys) {
            for (const auto& [derivation_index, pubkey] : pubkey_map) {
                add_pubkey(pubkey, wallet_descriptor.descriptor->IsRange() ? std::optional<int64_t>{derivation_index} : fixed_index);
                exported_from_cache = true;
            }
        }

        if (exported_from_cache) continue;

        if (const auto explicit_pubkey = parse_explicit_pubkey(descriptor)) {
            add_pubkey(*explicit_pubkey, fixed_index);
            continue;
        }

        for (const auto& pubkey : pqc_keys) {
            add_pubkey(pubkey, fixed_index);
        }
    }

    UniValue pubkey_arr(UniValue::VARR);
    for (const auto& pubkey : pubkeys) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("pubkey", pubkey.pubkey_hex);
        if (pubkey.account.has_value()) {
            entry.pushKV("account", *pubkey.account);
        }
        if (pubkey.change.has_value()) {
            entry.pushKV("change", *pubkey.change);
        }
        if (pubkey.index.has_value()) {
            entry.pushKV("index", *pubkey.index);
        }
        pubkey_arr.push_back(std::move(entry));
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("count", static_cast<int64_t>(pubkeys.size()));
    ret.pushKV("pubkeys", std::move(pubkey_arr));
    return ret;
},
    };
}

static int64_t ParseTimestampOrNow(const UniValue& timestamp, int64_t now, std::string_view context)
{
    if (timestamp.isNum()) {
        const auto parsed_timestamp = ToIntegral<int64_t>(timestamp.getValStr());
        if (!parsed_timestamp) {
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Expected integer or \"now\" timestamp value%s, got %s", context, timestamp.getValStr()));
        }
        return *parsed_timestamp;
    } else if (timestamp.isStr()) {
        const std::string& timestamp_str{timestamp.get_str()};
        if (timestamp_str == "now") {
            return now;
        }
        const auto parsed_timestamp = ToIntegral<int64_t>(timestamp_str);
        if (!parsed_timestamp) {
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Expected integer or \"now\" timestamp value%s, got %s", context, timestamp_str));
        }
        return *parsed_timestamp;
    }
    throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Expected integer or \"now\" timestamp value%s, got type %s", context, uvTypeName(timestamp.type())));
}

RPCHelpMan importpubkeydb()
{
    return RPCHelpMan{
        "importpubkeydb",
        "Imports a JSON pubkey database into a watch-only wallet as P2MR descriptors.",
        {
            {"pubkeys", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of pubkey records",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "P2MR pubkey (hex, 32 bytes)"},
                            {"account", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "P2MR account number when known (informational)"},
                            {"change", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Whether this pubkey should be imported as a change/internal descriptor"},
                            {"index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Descriptor index when known (informational)"},
                        },
                    },
                },
            },
            {"internal", RPCArg::Type::BOOL, RPCArg::Default{false}, "Fallback internal/change flag for entries that do not specify 'change' or 'internal'"},
            {"timestamp", RPCArg::Type::NUM, RPCArg::DefaultHint{"now"}, "Timestamp for imported descriptors in " + UNIX_EPOCH_TIME,
                RPCArgOptions{.skip_type_check = true, .type_str={"timestamp | \"now\"", "integer / string"}}},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "imported", "Number of imported pubkeys"},
            },
        },
        RPCExamples{
            HelpExampleCli("importpubkeydb", "'[{\"pubkey\":\"001122...\"}]'") +
            HelpExampleRpc("importpubkeydb", "'[{\"pubkey\":\"001122...\"}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;
    CWallet& wallet{*pwallet};

    if (!pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "importpubkeydb requires a wallet with private keys disabled");
    }

    wallet.BlockUntilSyncedToCurrentChain();

    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    const auto get_entry_internal = [](const UniValue& entry, bool fallback_internal) {
        std::optional<bool> entry_internal;
        if (entry.exists("change")) {
            if (!entry["change"].isBool()) {
                throw JSONRPCError(RPC_TYPE_ERROR, "Pubkey entry field 'change' must be a boolean");
            }
            entry_internal = entry["change"].get_bool();
        }
        if (entry.exists("internal")) {
            if (!entry["internal"].isBool()) {
                throw JSONRPCError(RPC_TYPE_ERROR, "Pubkey entry field 'internal' must be a boolean");
            }
            const bool internal = entry["internal"].get_bool();
            if (entry_internal.has_value() && *entry_internal != internal) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Pubkey entry fields 'change' and 'internal' must match when both are provided");
            }
            entry_internal = internal;
        }
        return entry_internal.value_or(fallback_internal);
    };

    const auto validate_optional_int = [](const UniValue& entry, const std::string& field) {
        if (!entry.exists(field)) return;
        if (!entry[field].isNum()) {
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Pubkey entry field '%s' must be a number", field));
        }
        if (entry[field].getInt<int64_t>() < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Pubkey entry field '%s' must be non-negative", field));
        }
    };

    const bool internal = request.params[1].isNull() ? false : request.params[1].get_bool();
    const UniValue& pubkey_entries = request.params[0];
    const int64_t minimum_timestamp = 1;
    int64_t now = 0;
    int64_t timestamp = 0;
    int64_t imported{0};
    bool imported_descriptors{false};
    {
        LOCK(pwallet->cs_wallet);
        CHECK_NONFATAL(pwallet->chain().findBlock(pwallet->GetLastBlockHash(), FoundBlock().time(timestamp).mtpTime(now)));

        timestamp = now;
        if (!request.params[2].isNull()) {
            timestamp = ParseTimestampOrNow(request.params[2], now, "");
        }
        timestamp = std::max(timestamp, minimum_timestamp);

        WalletBatch batch(wallet.GetDatabase());
        for (const UniValue& entry : pubkey_entries.getValues()) {
            if (!entry.isObject() || !entry.exists("pubkey")) {
                throw JSONRPCError(RPC_TYPE_ERROR, "Each pubkey entry must be an object with a 'pubkey' field");
            }
            validate_optional_int(entry, "account");
            validate_optional_int(entry, "index");
            const std::string pubkey_hex = entry["pubkey"].get_str();
            if (!IsHex(pubkey_hex)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hex in 'pubkey' field");
            }
            std::vector<unsigned char> pubkey_bytes = ParseHex(pubkey_hex);
            if (pubkey_bytes.size() != CPQCPubKey::SIZE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("P2MR pubkey must be %u bytes", CPQCPubKey::SIZE));
            }
            CPQCPubKey pubkey{pubkey_bytes};
            if (!pubkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid P2MR pubkey");
            }

            const std::string desc_str = strprintf("mr(pk(%s))", pubkey_hex);
            FlatSigningProvider keys;
            std::string error;
            auto parsed_descs = Parse(desc_str, keys, error, /*require_checksum=*/false);
            if (parsed_descs.size() != 1) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Could not parse descriptor '%s': %s", desc_str, error));
            }

            WalletDescriptor w_desc(std::move(parsed_descs.at(0)), timestamp, 0, 0, 0);
            const bool entry_internal = get_entry_internal(entry, internal);
            const std::optional<PubKeyDBPoolKey> pool_key = entry.exists("index")
                ? std::optional<PubKeyDBPoolKey>{PubKeyDBPoolKey{
                    entry.exists("account") ? entry["account"].getInt<int64_t>() : 0,
                    entry_internal,
                    entry["index"].getInt<int64_t>(),
                }}
                : std::nullopt;

            if (pool_key) {
                if (const auto existing_pool_key = pwallet->GetPubKeyDBPoolKey(pubkey); existing_pool_key && *existing_pool_key != *pool_key) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Pubkey %s already mapped to account=%d internal=%d index=%d",
                            pubkey_hex, existing_pool_key->account, existing_pool_key->internal, existing_pool_key->index));
                }
                const auto existing_chain_entries = pwallet->GetPubKeyDBPoolEntries(pool_key->Chain(), pool_key->index);
                if (!existing_chain_entries.empty() &&
                    existing_chain_entries.front().first.index == pool_key->index &&
                    existing_chain_entries.front().second != pubkey) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Pubkeydb pool account=%d internal=%d index=%d already assigned to another pubkey",
                            pool_key->account, pool_key->internal, pool_key->index));
                }
            }

            bool changed{false};
            if (pwallet->GetScriptPubKeyMan(w_desc.id) == nullptr) {
                if (auto spk_manager_res = pwallet->AddWalletDescriptor(w_desc, keys, /*label=*/"", entry_internal); !spk_manager_res) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(spk_manager_res).original);
                }
                imported_descriptors = true;
                changed = true;
            }
            if (pool_key) {
                const auto pool_res = pwallet->AddPubKeyDBPoolEntry(batch, *pool_key, pubkey);
                if (!pool_res) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(pool_res).original);
                }
                changed = changed || *pool_res;
            }

            if (changed) {
                ++imported;
            }
        }

        if (imported_descriptors) {
            pwallet->ConnectScriptPubKeyManNotifiers();
            pwallet->RefreshAllTXOs();
        }
    }

    if (imported_descriptors) {
        const int64_t scanned_time = pwallet->RescanFromTime(timestamp, reserver, /*update=*/true);
        pwallet->ResubmitWalletTransactions(/*relay=*/false, /*force=*/true);

        if (pwallet->IsAbortingRescan()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted by user.");
        }

        if (scanned_time > timestamp) {
            std::string error_msg{strprintf("Rescan failed for imported pubkeys with timestamp %d. There "
                    "was an error reading a block from time %d, which is after or within %d seconds "
                    "of key creation, and could contain transactions pertaining to the imported pubkeys. As a "
                    "result, related transactions and coins may not appear in the wallet.",
                    timestamp, scanned_time - TIMESTAMP_WINDOW - 1, TIMESTAMP_WINDOW)};
            if (pwallet->chain().havePruned()) {
                error_msg += strprintf(" This error could be caused by pruning or data corruption "
                        "(see qbitd log for details) and could be dealt with by downloading and "
                        "rescanning the relevant blocks (see -reindex option and rescanblockchain RPC).");
            } else if (pwallet->chain().hasAssumedValidChain()) {
                error_msg += strprintf(" This error is likely caused by an in-progress assumeutxo "
                        "background sync. Check logs or getchainstates RPC for assumeutxo background "
                        "sync progress and try again later.");
            } else {
                error_msg += strprintf(" This error could potentially caused by data corruption. If "
                        "the issue persists you may want to reindex (see -reindex option).");
            }
            throw JSONRPCError(RPC_MISC_ERROR, error_msg);
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("imported", imported);
    return result;
},
    };
}

static constexpr int64_t PUBKEYDB_LOW_WATERMARK = 100;

struct PubKeyDBChainSnapshot {
    std::optional<PubKeyDBPoolKey> next_key;
    std::optional<CPQCPubKey> next_pubkey;
    int64_t highest_imported_index{-1};
    int64_t remaining{0};
};

static util::Result<CTxDestination> DerivePubKeyDBDestination(const CPQCPubKey& pubkey)
{
    FlatSigningProvider keys;
    FlatSigningProvider out_keys;
    std::vector<CScript> scripts;
    std::string error;
    const std::string desc_str = strprintf("mr(pk(%s))", HexStr(std::span{pubkey.data(), pubkey.size()}));
    auto parsed_descs = Parse(desc_str, keys, error, /*require_checksum=*/false);
    if (parsed_descs.size() != 1) {
        return util::Error{Untranslated(strprintf("Could not parse descriptor '%s': %s", desc_str, error))};
    }
    if (!parsed_descs.at(0)->Expand(0, keys, scripts, out_keys, /*write_cache=*/nullptr) || scripts.size() != 1) {
        return util::Error{Untranslated(strprintf("Could not derive address from descriptor '%s'", desc_str))};
    }

    CTxDestination dest;
    if (!ExtractDestination(scripts[0], dest)) {
        return util::Error{Untranslated("Could not derive pubkeydb destination")};
    }
    return dest;
}

static util::Result<PubKeyDBChainSnapshot> GetPubKeyDBChainSnapshot(const CWallet& wallet, const PubKeyDBChainKey& chain)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    PubKeyDBChainSnapshot snapshot;
    const int64_t cursor = wallet.GetPubKeyDBCursor(chain);
    const auto entries = wallet.GetPubKeyDBPoolEntries(chain, /*minimum_index=*/0);
    if (entries.empty()) {
        return snapshot;
    }

    snapshot.highest_imported_index = entries.back().first.index;
    const std::set<CTxDestination> used_destinations = wallet.GetWalletTxOutDestinations();
    bool count_remaining{false};
    for (const auto& [key, pubkey] : entries) {
        if (key.index < cursor) continue;

        const auto dest = DerivePubKeyDBDestination(pubkey);
        if (!dest) {
            return util::Error{util::ErrorString(dest)};
        }
        const bool used = used_destinations.contains(*dest);
        if (!snapshot.next_key.has_value() && !used) {
            snapshot.next_key = key;
            snapshot.next_pubkey = pubkey;
            count_remaining = true;
        }
        if (count_remaining && !used) {
            ++snapshot.remaining;
        }
    }

    return snapshot;
}

RPCHelpMan getnextpubkeydbaddress()
{
    return RPCHelpMan{
        "getnextpubkeydbaddress",
        "Returns the next allocatable imported P2MR pubkey-pool address for a watch-only wallet.",
        {
            {"internal", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether to allocate from the internal/change pool"},
            {"account", RPCArg::Type::NUM, RPCArg::Default{0}, "Account number to allocate from"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "The next imported P2MR address"},
                {RPCResult::Type::STR_HEX, "pubkey", "P2MR pubkey backing the allocated address"},
                {RPCResult::Type::BOOL, "internal", "Whether the address came from the internal/change pool"},
                {RPCResult::Type::NUM, "account", "Account number for the allocated address"},
                {RPCResult::Type::NUM, "index", "Imported pool index for the allocated address"},
                {RPCResult::Type::NUM, "remaining", "Remaining allocatable entries in the same pool after this allocation"},
            },
        },
        RPCExamples{
            HelpExampleCli("getnextpubkeydbaddress", "") +
            HelpExampleRpc("getnextpubkeydbaddress", "") +
            HelpExampleCli("getnextpubkeydbaddress", "true") +
            HelpExampleRpc("getnextpubkeydbaddress", "true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const bool internal = request.params[0].isNull() ? false : request.params[0].get_bool();
    const int64_t account = request.params[1].isNull() ? 0 : request.params[1].getInt<int64_t>();
    if (account < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Account must be non-negative");
    }

    LOCK(pwallet->cs_wallet);
    const PubKeyDBChainKey chain{account, internal};
    const auto snapshot = GetPubKeyDBChainSnapshot(*pwallet, chain);
    if (!snapshot) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(snapshot).original);
    }
    if (snapshot->highest_imported_index < 0) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            strprintf("No imported pubkey pool is available for account=%d internal=%d", account, internal));
    }

    WalletBatch batch(pwallet->GetDatabase());
    if (!snapshot->next_key.has_value() || !snapshot->next_pubkey.has_value()) {
        const int64_t exhausted_cursor = snapshot->highest_imported_index + 1;
        if (pwallet->GetPubKeyDBCursor(chain) < exhausted_cursor &&
            !pwallet->SetPubKeyDBCursor(batch, chain, exhausted_cursor)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Could not update pubkey pool cursor");
        }
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT,
            strprintf("Error: Imported pubkey pool exhausted for account=%d internal=%d", account, internal));
    }

    const auto dest = DerivePubKeyDBDestination(*snapshot->next_pubkey);
    if (!dest) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(dest).original);
    }
    if (!pwallet->SetPubKeyDBCursor(batch, chain, snapshot->next_key->index + 1)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Could not update pubkey pool cursor");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(*dest));
    result.pushKV("pubkey", HexStr(std::span{snapshot->next_pubkey->data(), snapshot->next_pubkey->size()}));
    result.pushKV("internal", internal);
    result.pushKV("account", account);
    result.pushKV("index", snapshot->next_key->index);
    result.pushKV("remaining", snapshot->remaining - 1);
    return result;
},
    };
}

RPCHelpMan listpubkeydbstatus()
{
    return RPCHelpMan{
        "listpubkeydbstatus",
        "Reports imported P2MR pubkey-pool allocation status by account and chain.",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ARR, "chains", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::NUM, "account", "Account number for this pool"},
                                {RPCResult::Type::BOOL, "internal", "Whether this pool is for internal/change addresses"},
                                {RPCResult::Type::NUM, "next_index", "Next allocatable imported index, or one past the highest imported index if exhausted"},
                                {RPCResult::Type::NUM, "highest_imported_index", "Highest imported index seen in this pool"},
                                {RPCResult::Type::NUM, "remaining", "Remaining allocatable entries in this pool"},
                                {RPCResult::Type::NUM, "low_watermark", "Remaining-entry threshold where top-up is recommended"},
                                {RPCResult::Type::BOOL, "needs_topup", "Whether the remaining allocatable entries are at or below the low-watermark threshold"},
                            },
                        },
                    },
                },
            },
        },
        RPCExamples{
            HelpExampleCli("listpubkeydbstatus", "") +
            HelpExampleRpc("listpubkeydbstatus", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);
    UniValue chains(UniValue::VARR);
    for (const PubKeyDBChainKey& chain : pwallet->GetPubKeyDBChains()) {
        const auto snapshot = GetPubKeyDBChainSnapshot(*pwallet, chain);
        if (!snapshot) {
            throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(snapshot).original);
        }
        if (snapshot->highest_imported_index < 0) {
            continue;
        }

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("account", chain.account);
        entry.pushKV("internal", chain.internal);
        entry.pushKV("next_index", snapshot->next_key ? snapshot->next_key->index : snapshot->highest_imported_index + 1);
        entry.pushKV("highest_imported_index", snapshot->highest_imported_index);
        entry.pushKV("remaining", snapshot->remaining);
        entry.pushKV("low_watermark", PUBKEYDB_LOW_WATERMARK);
        entry.pushKV("needs_topup", snapshot->remaining <= PUBKEYDB_LOW_WATERMARK);
        chains.push_back(std::move(entry));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("chains", std::move(chains));
    return result;
},
    };
}

static int64_t GetImportTimestamp(const UniValue& data, int64_t now)
{
    if (data.exists("timestamp")) {
        const UniValue& timestamp = data["timestamp"];
        if (timestamp.isNum()) {
            return timestamp.getInt<int64_t>();
        } else if (timestamp.isStr() && timestamp.get_str() == "now") {
            return now;
        }
        throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Expected number or \"now\" timestamp value for key. got type %s", uvTypeName(timestamp.type())));
    }
    throw JSONRPCError(RPC_TYPE_ERROR, "Missing required timestamp field for key");
}

static std::string FormatExpandedActiveDescriptorRangeWarning(bool internal, int64_t requested_range_start, int64_t requested_range_end, int64_t effective_range_end)
{
    return strprintf(
        "Requested active %s descriptor range [%d,%d] was expanded to effective range [%d,%d] to satisfy wallet keypool lookahead",
        internal ? "internal" : "external",
        requested_range_start,
        requested_range_end - 1,
        requested_range_start,
        effective_range_end - 1);
}

static UniValue ProcessDescriptorImport(CWallet& wallet, const UniValue& data, const int64_t timestamp) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    UniValue warnings(UniValue::VARR);
    UniValue result(UniValue::VOBJ);

    try {
        if (!data.exists("desc")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor not found.");
        }

        const std::string& descriptor = data["desc"].get_str();
        const bool active = data.exists("active") ? data["active"].get_bool() : false;
        const std::string label{LabelFromValue(data["label"])};

        // Parse descriptor string
        FlatSigningProvider keys;
        std::string error;
        auto parsed_descs = Parse(descriptor, keys, error, /* require_checksum = */ true);
        if (parsed_descs.empty()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
        }
        for (const auto& parsed_desc : parsed_descs) {
            EnsureDescriptorOutputTypeAllowed(*parsed_desc, "Imported");
            if (parsed_desc->GetOutputType() == OutputType::P2MR && parsed_desc->IsSolvable() && !parsed_desc->HasP2MRStandardSatisfaction()) {
                if (active) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        strprintf("Cannot activate P2MR descriptor without a wallet-constructible satisfaction; multi_a thresholds must not exceed %u", P2MR_V1_MAX_STANDARD_SIGNATURES));
                }
                warnings.push_back(strprintf("Imported inactive P2MR descriptor has no wallet-constructible satisfaction; multi_a thresholds above %u cannot be finalized", P2MR_V1_MAX_STANDARD_SIGNATURES));
            }
        }
        std::optional<bool> internal;
        if (data.exists("internal")) {
            if (parsed_descs.size() > 1) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot have multipath descriptor while also specifying \'internal\'");
            }
            internal = data["internal"].get_bool();
        }

        // Range check
        int64_t range_start = 0, range_end = 1, next_index = 0;
        if (!parsed_descs.at(0)->IsRange() && data.exists("range")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should not be specified for an un-ranged descriptor");
        } else if (parsed_descs.at(0)->IsRange()) {
            if (data.exists("range")) {
                auto range = ParseDescriptorRange(data["range"]);
                range_start = range.first;
                range_end = range.second + 1; // Specified range end is inclusive, but we need range end as exclusive
            } else {
                warnings.push_back("Range not given, using default keypool range");
                range_start = 0;
                range_end = wallet.m_keypool_size;
            }
            next_index = range_start;

            if (data.exists("next_index")) {
                next_index = data["next_index"].getInt<int64_t>();
                // bound checks
                if (next_index < range_start || next_index >= range_end) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "next_index is out of range");
                }
            }
        }

        // Active descriptors must be ranged
        if (active && !parsed_descs.at(0)->IsRange()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Active descriptors must be ranged");
        }

        // Multipath descriptors should not have a label
        if (parsed_descs.size() > 1 && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Multipath descriptors should not have a label");
        }

        // Ranged descriptors should not have a label
        if (data.exists("range") && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Ranged descriptors should not have a label");
        }

        // Internal addresses should not have a label either
        if (internal && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Internal addresses should not have a label");
        }

        // Combo descriptor check
        if (active && !parsed_descs.at(0)->IsSingleType()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Combo descriptors cannot be set to active");
        }

        // If the wallet disabled private keys, abort if private keys exist
        if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && !keys.keys.empty()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import private keys to a wallet with private keys disabled");
        }

        for (size_t j = 0; j < parsed_descs.size(); ++j) {
            auto parsed_desc = std::move(parsed_descs[j]);
            bool desc_internal = internal.has_value() && internal.value();
            if (parsed_descs.size() == 2) {
                desc_internal = j == 1;
            } else if (parsed_descs.size() > 2) {
                CHECK_NONFATAL(!desc_internal);
            }
            if (IsP2MRBIP32PublicDerivationDescriptor(*parsed_desc) && keys.keys.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import public P2MR descriptor: " + P2MR_BIP32_PUBLIC_DERIVATION_ERROR);
            }

            // Need to ExpandPrivate to check if private keys are available for all pubkeys
            FlatSigningProvider expand_keys;
            std::vector<CScript> scripts;
            if (!parsed_desc->Expand(0, keys, scripts, expand_keys)) {
                const bool is_public_p2mr = parsed_desc->GetOutputType() &&
                                            *parsed_desc->GetOutputType() == OutputType::P2MR &&
                                            keys.keys.empty();
                if (is_public_p2mr) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                                       "Cannot import public P2MR descriptor without private keys; pqc() descriptors need private key material to derive PQC pubkeys");
                }
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot expand descriptor. Probably because of hardened derivations without private keys provided");
            }
            parsed_desc->ExpandPrivate(0, keys, expand_keys);

            // Check if all private keys are provided
            bool have_all_privkeys = !expand_keys.keys.empty();
            for (const auto& entry : expand_keys.origins) {
                const CKeyID& key_id = entry.first;
                CKey key;
                if (!expand_keys.GetKey(key_id, key)) {
                    have_all_privkeys = false;
                    break;
                }
            }

            // If private keys are enabled, check some things.
            if (!wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
               if (keys.keys.empty()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import descriptor without private keys to a wallet with private keys enabled");
               }
               if (!have_all_privkeys) {
                   warnings.push_back("Not all private keys provided. Some wallet functionality may return unexpected errors");
               }
            }

            WalletDescriptor w_desc(std::move(parsed_desc), timestamp, range_start, range_end, next_index);

            // Add descriptor to the wallet
            auto spk_manager_res = wallet.AddWalletDescriptor(w_desc, keys, label, desc_internal);

            if (!spk_manager_res) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Could not add descriptor '%s': %s", descriptor, util::ErrorString(spk_manager_res).original));
            }

            auto& spk_manager = spk_manager_res.value().get();

            if (active && data.exists("range") && w_desc.descriptor->GetOutputType()) {
                LOCK(spk_manager.cs_desc_man);
                const WalletDescriptor effective_desc = spk_manager.GetWalletDescriptor();
                if (effective_desc.range_end > range_end) {
                    warnings.push_back(FormatExpandedActiveDescriptorRangeWarning(
                        desc_internal,
                        range_start,
                        range_end,
                        effective_desc.range_end));
                }
            }

            // Set descriptor as active if necessary
            if (active) {
                if (!w_desc.descriptor->GetOutputType()) {
                    warnings.push_back("Unknown output type, cannot set descriptor to active.");
                } else {
                    wallet.AddActiveScriptPubKeyMan(spk_manager.GetID(), *w_desc.descriptor->GetOutputType(), desc_internal);
                }
            } else {
                if (w_desc.descriptor->GetOutputType()) {
                    wallet.DeactivateScriptPubKeyMan(spk_manager.GetID(), *w_desc.descriptor->GetOutputType(), desc_internal);
                }
            }
        }

        result.pushKV("success", UniValue(true));
    } catch (const UniValue& e) {
        result.pushKV("success", UniValue(false));
        result.pushKV("error", e);
    }
    PushWarnings(warnings, result);
    return result;
}

RPCHelpMan importdescriptors()
{
    return RPCHelpMan{
        "importdescriptors",
        "Import descriptors. This will trigger a rescan of the blockchain based on the earliest timestamp of all descriptors being imported. Requires a new wallet backup.\n"
        "When importing descriptors with multipath key expressions, if the multipath specifier contains exactly two elements, the descriptor produced from the second element will be imported as an internal descriptor.\n"
        "P2MR descriptors that depend only on BIP32 extended public keys are not accepted; use importpubkeydb for watch-only P2MR tracking.\n"
            "\nNote: This call can take over an hour to complete if using an early timestamp; during that time, other rpc calls\n"
            "may report that the imported keys, addresses or scripts exist but related transactions are still missing.\n"
            "The rescan is significantly faster if block filters are available (using startup option \"-blockfilterindex=1\").\n",
                {
                    {"requests", RPCArg::Type::ARR, RPCArg::Optional::NO, "Data to be imported",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "Descriptor to import."},
                                    {"active", RPCArg::Type::BOOL, RPCArg::Default{false}, "Set this descriptor to be the active descriptor for the corresponding output type/externality"},
                                    {"range", RPCArg::Type::RANGE, RPCArg::Optional::OMITTED, "If a ranged descriptor is used, this specifies the end or the range (in the form [begin,end]) to import"},
                                    {"next_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "If a ranged descriptor is set to active, this specifies the next index to generate addresses from"},
                                    {"timestamp", RPCArg::Type::NUM, RPCArg::Optional::NO, "Time from which to start rescanning the blockchain for this descriptor, in " + UNIX_EPOCH_TIME + "\n"
                                        "Use the string \"now\" to substitute the current synced blockchain time.\n"
                                        "\"now\" can be specified to bypass scanning, for outputs which are known to never have been used, and\n"
                                        "0 can be specified to scan the entire blockchain. Blocks up to 2 hours before the earliest timestamp\n"
                                        "of all descriptors being imported will be scanned as well as the mempool.",
                                        RPCArgOptions{.type_str={"timestamp | \"now\"", "integer / string"}}
                                    },
                                    {"internal", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether matching outputs should be treated as not incoming payments (e.g. change)"},
                                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "Label to assign to the address, only allowed with internal=false. Disabled for ranged descriptors"},
                                },
                            },
                        },
                        RPCArgOptions{.oneline_description="requests"}},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "Response is an array with the same size as the input that has the execution result",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "success", ""},
                            {RPCResult::Type::ARR, "warnings", /*optional=*/true, "",
                            {
                                {RPCResult::Type::STR, "", ""},
                            }},
                            {RPCResult::Type::OBJ, "error", /*optional=*/true, "",
                            {
                                {RPCResult::Type::ELISION, "", "JSONRPC error"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("importdescriptors", "'[{ \"desc\": \"<my descriptor>\", \"timestamp\":1455191478, \"internal\": true }, "
                                          "{ \"desc\": \"<my descriptor 2>\", \"label\": \"example 2\", \"timestamp\": 1455191480 }]'") +
                    HelpExampleCli("importdescriptors", "'[{ \"desc\": \"<my descriptor>\", \"timestamp\":1455191478, \"active\": true, \"range\": [0,100], \"label\": \"<my bech32 wallet>\" }]'")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& main_request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(main_request);
    if (!pwallet) return UniValue::VNULL;
    CWallet& wallet{*pwallet};

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve(/*with_passphrase=*/true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    // Ensure that the wallet is not locked for the remainder of this RPC, as
    // the passphrase is used to top up the keypool.
    LOCK(pwallet->m_relock_mutex);

    const UniValue& requests = main_request.params[0];
    const int64_t minimum_timestamp = 1;
    int64_t now = 0;
    int64_t lowest_timestamp = 0;
    bool rescan = false;
    UniValue response(UniValue::VARR);
    {
        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(*pwallet);

        CHECK_NONFATAL(pwallet->chain().findBlock(pwallet->GetLastBlockHash(), FoundBlock().time(lowest_timestamp).mtpTime(now)));

        // Get all timestamps and extract the lowest timestamp
        for (const UniValue& request : requests.getValues()) {
            // This throws an error if "timestamp" doesn't exist
            const int64_t timestamp = std::max(GetImportTimestamp(request, now), minimum_timestamp);
            const UniValue result = ProcessDescriptorImport(*pwallet, request, timestamp);
            response.push_back(result);

            if (lowest_timestamp > timestamp ) {
                lowest_timestamp = timestamp;
            }

            // If we know the chain tip, and at least one request was successful then allow rescan
            if (!rescan && result["success"].get_bool()) {
                rescan = true;
            }
        }
        pwallet->ConnectScriptPubKeyManNotifiers();
        pwallet->RefreshAllTXOs();
    }

    // Rescan the blockchain using the lowest timestamp
    if (rescan) {
        int64_t scanned_time = pwallet->RescanFromTime(lowest_timestamp, reserver, /*update=*/true);
        pwallet->ResubmitWalletTransactions(/*relay=*/false, /*force=*/true);

        if (pwallet->IsAbortingRescan()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted by user.");
        }

        if (scanned_time > lowest_timestamp) {
            std::vector<UniValue> results = response.getValues();
            response.clear();
            response.setArray();

            // Compose the response
            for (unsigned int i = 0; i < requests.size(); ++i) {
                const UniValue& request = requests.getValues().at(i);

                // If the descriptor timestamp is within the successfully scanned
                // range, or if the import result already has an error set, let
                // the result stand unmodified. Otherwise replace the result
                // with an error message.
                if (scanned_time <= GetImportTimestamp(request, now) || results.at(i).exists("error")) {
                    response.push_back(results.at(i));
                } else {
                    std::string error_msg{strprintf("Rescan failed for descriptor with timestamp %d. There "
                            "was an error reading a block from time %d, which is after or within %d seconds "
                            "of key creation, and could contain transactions pertaining to the desc. As a "
                            "result, transactions and coins using this desc may not appear in the wallet.",
                            GetImportTimestamp(request, now), scanned_time - TIMESTAMP_WINDOW - 1, TIMESTAMP_WINDOW)};
                    if (pwallet->chain().havePruned()) {
                        error_msg += strprintf(" This error could be caused by pruning or data corruption "
                                "(see qbitd log for details) and could be dealt with by downloading and "
                                "rescanning the relevant blocks (see -reindex option and rescanblockchain RPC).");
                    } else if (pwallet->chain().hasAssumedValidChain()) {
                        error_msg += strprintf(" This error is likely caused by an in-progress assumeutxo "
                                "background sync. Check logs or getchainstates RPC for assumeutxo background "
                                "sync progress and try again later.");
                    } else {
                        error_msg += strprintf(" This error could potentially caused by data corruption. If "
                                "the issue persists you may want to reindex (see -reindex option).");
                    }

                    UniValue result = UniValue(UniValue::VOBJ);
                    result.pushKV("success", UniValue(false));
                    result.pushKV("error", JSONRPCError(RPC_MISC_ERROR, error_msg));
                    response.push_back(std::move(result));
                }
            }
        }
    }

    return response;
},
    };
}

RPCHelpMan listdescriptors()
{
    return RPCHelpMan{
        "listdescriptors",
        "List all descriptors present in a wallet.\n"
        "On P2MR-only chains, public output omits P2MR descriptors that rely on BIP32 extended public keys; use exportpubkeydb for watch-only P2MR exports.\n",
        {
            {"private", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show private descriptors."}
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "wallet_name", "Name of wallet this operation was performed on"},
            {RPCResult::Type::ARR, "descriptors", "Array of descriptor objects (sorted by descriptor string representation)",
            {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR, "desc", "Descriptor string representation"},
                    {RPCResult::Type::NUM, "timestamp", "The creation time of the descriptor"},
                    {RPCResult::Type::BOOL, "active", "Whether this descriptor is currently used to generate new addresses"},
                    {RPCResult::Type::BOOL, "internal", /*optional=*/true, "True if this descriptor is used to generate change addresses. False if this descriptor is used to generate receiving addresses; defined only for active descriptors"},
                    {RPCResult::Type::ARR_FIXED, "range", /*optional=*/true, "Defined only for ranged descriptors", {
                        {RPCResult::Type::NUM, "", "Range start inclusive"},
                        {RPCResult::Type::NUM, "", "Range end inclusive"},
                    }},
                    {RPCResult::Type::NUM, "next", /*optional=*/true, "Same as next_index field. Kept for compatibility reason."},
                    {RPCResult::Type::NUM, "next_index", /*optional=*/true, "The next index to generate addresses from; defined only for ranged descriptors"},
                }},
            }},
            {RPCResult::Type::ARR, "warnings", /*optional=*/true, "", {
                {RPCResult::Type::STR, "", ""},
            }},
        }},
        RPCExamples{
            HelpExampleCli("listdescriptors", "") + HelpExampleRpc("listdescriptors", "")
            + HelpExampleCli("listdescriptors", "true") + HelpExampleRpc("listdescriptors", "true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return UniValue::VNULL;

    const bool priv = !request.params[0].isNull() && request.params[0].get_bool();
    if (priv) {
        EnsureWalletIsUnlocked(*wallet);
    }

    LOCK(wallet->cs_wallet);

    const auto active_spk_mans = wallet->GetActiveScriptPubKeyMans();

    struct WalletDescInfo {
        std::string descriptor;
        uint64_t creation_time;
        bool active;
        std::optional<bool> internal;
        std::optional<std::pair<int64_t,int64_t>> range;
        int64_t next_index;
    };

    std::vector<WalletDescInfo> wallet_descriptors;
    bool suppressed_p2mr_bip32_descriptors{false};
    for (const auto& spk_man : wallet->GetAllScriptPubKeyMans()) {
        const auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (!desc_spk_man) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Unexpected ScriptPubKey manager type.");
        }
        LOCK(desc_spk_man->cs_desc_man);
        const auto& wallet_descriptor = desc_spk_man->GetWalletDescriptor();
        if (ShouldSuppressP2MRBIP32Descriptor(*wallet_descriptor.descriptor, priv)) {
            suppressed_p2mr_bip32_descriptors = true;
            continue;
        }

        std::string descriptor;
        if (!desc_spk_man->GetDescriptorString(descriptor, priv)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Can't get descriptor string.");
        }
        const bool is_range = wallet_descriptor.descriptor->IsRange();
        wallet_descriptors.push_back({
            descriptor,
            wallet_descriptor.creation_time,
            active_spk_mans.count(desc_spk_man) != 0,
            wallet->IsInternalScriptPubKeyMan(desc_spk_man),
            is_range ? std::optional(std::make_pair(wallet_descriptor.range_start, wallet_descriptor.range_end)) : std::nullopt,
            wallet_descriptor.next_index
        });
    }

    std::sort(wallet_descriptors.begin(), wallet_descriptors.end(), [](const auto& a, const auto& b) {
        return a.descriptor < b.descriptor;
    });

    UniValue descriptors(UniValue::VARR);
    for (const WalletDescInfo& info : wallet_descriptors) {
        UniValue spk(UniValue::VOBJ);
        spk.pushKV("desc", info.descriptor);
        spk.pushKV("timestamp", info.creation_time);
        spk.pushKV("active", info.active);
        if (info.internal.has_value()) {
            spk.pushKV("internal", info.internal.value());
        }
        if (info.range.has_value()) {
            UniValue range(UniValue::VARR);
            range.push_back(info.range->first);
            range.push_back(info.range->second - 1);
            spk.pushKV("range", std::move(range));
            spk.pushKV("next", info.next_index);
            spk.pushKV("next_index", info.next_index);
        }
        descriptors.push_back(std::move(spk));
    }

    UniValue response(UniValue::VOBJ);
    response.pushKV("wallet_name", wallet->GetName());
    response.pushKV("descriptors", std::move(descriptors));
    if (suppressed_p2mr_bip32_descriptors) {
        UniValue warnings(UniValue::VARR);
        warnings.push_back(P2MR_DESCRIPTOR_EXPORT_WARNING);
        PushWarnings(warnings, response);
    }

    return response;
},
    };
}

RPCHelpMan backupwallet()
{
    return RPCHelpMan{
        "backupwallet",
        "Safely copies the current wallet file to the specified destination, which can either be a directory or a path with a filename.\n",
                {
                    {"destination", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination directory or file"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    std::string strDest = request.params[0].get_str();
    if (!pwallet->BackupWallet(strDest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
    }

    return UniValue::VNULL;
},
    };
}


RPCHelpMan restorewallet()
{
    return RPCHelpMan{
        "restorewallet",
        "Restores and loads a wallet from backup.\n"
        "\nThe rescan is significantly faster if block filters are available"
        "\n(using startup option \"-blockfilterindex=1\").\n",
        {
            {"wallet_name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name that will be applied to the restored wallet"},
            {"backup_file", RPCArg::Type::STR, RPCArg::Optional::NO, "The backup file that will be used to restore the wallet."},
            {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "name", "The wallet name if restored successfully."},
                {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to restoring and loading the wallet.",
                {
                    {RPCResult::Type::STR, "", ""},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("restorewallet", "\"testwallet\" \"home\\backups\\backup-file.bak\"")
            + HelpExampleRpc("restorewallet", "\"testwallet\" \"home\\backups\\backup-file.bak\"")
            + HelpExampleCliNamed("restorewallet", {{"wallet_name", "testwallet"}, {"backup_file", "home\\backups\\backup-file.bak\""}, {"load_on_startup", true}})
            + HelpExampleRpcNamed("restorewallet", {{"wallet_name", "testwallet"}, {"backup_file", "home\\backups\\backup-file.bak\""}, {"load_on_startup", true}})
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{

    WalletContext& context = EnsureWalletContext(request.context);

    auto backup_file = fs::u8path(request.params[1].get_str());

    std::string wallet_name = request.params[0].get_str();

    std::optional<bool> load_on_start = request.params[2].isNull() ? std::nullopt : std::optional<bool>(request.params[2].get_bool());

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    const std::shared_ptr<CWallet> wallet = RestoreWallet(context, backup_file, wallet_name, load_on_start, status, error, warnings);

    HandleWalletError(wallet, status, error);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    PushWarnings(warnings, obj);

    return obj;

},
    };
}
} // namespace wallet
