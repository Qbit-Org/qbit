// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/rawtransaction_util.h>

#include <coins.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/rbf.h>
#include <util/string.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <string_view>

namespace {

constexpr std::string_view PQC_KEY_PREFIX{"pqc("};
constexpr std::string_view DUMMY_P2MR_DESCRIPTOR_PREFIX{"mr(pk("};
constexpr std::string_view DUMMY_P2MR_DESCRIPTOR_SUFFIX{"))"};

bool IsExplicitPQCKey(const std::string& key, std::string_view& payload)
{
    if (key.size() <= PQC_KEY_PREFIX.size() || !key.starts_with(PQC_KEY_PREFIX) || key.back() != ')') {
        return false;
    }
    payload = std::string_view{key}.substr(PQC_KEY_PREFIX.size(), key.size() - PQC_KEY_PREFIX.size() - 1);
    return true;
}

bool ParseExplicitPQCSecret(std::string_view payload, FlatSigningProvider& keystore)
{
    const std::string payload_str{payload};
    if (!IsHex(payload_str)) return false;

    const std::vector<unsigned char> key_bytes{ParseHex(payload_str)};
    if (key_bytes.size() != CPQCKey::SIZE) return false;

    CPQCKey key;
    key.Set(key_bytes.data(), key_bytes.data() + key_bytes.size());
    if (!key.IsValid()) return false;

    const CPQCPubKey pubkey = key.GetPubKey();
    if (!pubkey.IsValid()) return false;

    keystore.pqc_keys.emplace(pubkey, key);
    keystore.pqc_sig_counters.try_emplace(pubkey, 0);
    return true;
}

bool ParseDescriptorPQCPrivateKey(const std::string& key, FlatSigningProvider& keystore)
{
    FlatSigningProvider parse_keys;
    std::string error;
    const std::string descriptor = std::string{DUMMY_P2MR_DESCRIPTOR_PREFIX} + key + std::string{DUMMY_P2MR_DESCRIPTOR_SUFFIX};
    auto parsed = Parse(descriptor, parse_keys, error, /*require_checksum=*/false);
    if (parsed.size() != 1 || parsed.front()->IsRange()) return false;

    FlatSigningProvider expanded_keys;
    parsed.front()->ExpandPrivate(/*pos=*/0, parse_keys, expanded_keys);
    if (expanded_keys.pqc_keys.empty()) return false;

    keystore.pqc_keys.insert(expanded_keys.pqc_keys.begin(), expanded_keys.pqc_keys.end());
    for (const auto& [pubkey, counter] : expanded_keys.pqc_sig_counters) {
        auto [it, inserted] = keystore.pqc_sig_counters.emplace(pubkey, counter);
        if (!inserted && counter > it->second) {
            it->second = counter;
        }
    }
    return true;
}

std::optional<WitnessV2P2MR> ExtractP2MROutput(const CScript& script_pub_key)
{
    std::vector<std::vector<unsigned char>> solutions;
    if (Solver(script_pub_key, solutions) != TxoutType::WITNESS_V2_P2MR || solutions.size() != 1) return std::nullopt;
    return WitnessV2P2MR{std::span<const unsigned char>{solutions[0].data(), solutions[0].size()}};
}

void ParseP2MRPrevout(const UniValue& prev_out, const WitnessV2P2MR& output, FlatSigningProvider& keystore)
{
    RPCTypeCheckObj(prev_out,
        {
            {"p2mrScript", UniValueType(UniValue::VSTR)},
            {"p2mrControlBlock", UniValueType(UniValue::VSTR)},
            {"p2mrLeafVersion", UniValueType(UniValue::VNUM)},
        }, true);

    const UniValue& script_uv{prev_out.find_value("p2mrScript")};
    const UniValue& control_uv{prev_out.find_value("p2mrControlBlock")};
    if (script_uv.isNull() && control_uv.isNull()) return;
    if (script_uv.isNull() || control_uv.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing p2mrScript/p2mrControlBlock");
    }

    const std::vector<unsigned char> script_bytes{ParseHexV(script_uv, "p2mrScript")};
    const std::vector<unsigned char> control_block{ParseHexV(control_uv, "p2mrControlBlock")};
    if (control_block.size() < P2MR_CONTROL_BASE_SIZE || control_block.size() > P2MR_CONTROL_MAX_SIZE ||
        ((control_block.size() - P2MR_CONTROL_BASE_SIZE) % P2MR_CONTROL_NODE_SIZE) != 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid P2MR control block size");
    }
    if ((control_block.front() & 1) == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "P2MR control byte bit 0 must be set");
    }

    const int leaf_version = prev_out.exists("p2mrLeafVersion") ? prev_out.find_value("p2mrLeafVersion").getInt<int>() : (control_block.front() & TAPROOT_LEAF_MASK);
    if (leaf_version < 0 || leaf_version > 0xff) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "p2mrLeafVersion out of range");
    }
    if ((control_block.front() & TAPROOT_LEAF_MASK) != leaf_version) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "p2mrLeafVersion does not match p2mrControlBlock");
    }

    const uint256 leaf_hash = ComputeP2MRLeafHash(static_cast<uint8_t>(leaf_version), script_bytes);
    if (ComputeP2MRMerkleRoot(control_block, leaf_hash) != output.GetMerkleRoot()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "p2mrScript/p2mrControlBlock does not match scriptPubKey");
    }

    P2MRSpendData& spenddata = keystore.p2mr_spenddata[output];
    spenddata.merkle_root = output.GetMerkleRoot();
    spenddata.scripts[{script_bytes, leaf_version}].insert(control_block);
}

} // namespace

bool ParseRawTransactionKey(const std::string& key, FlatSigningProvider& keystore, std::string& error)
{
    std::string_view pqc_payload;
    if (IsExplicitPQCKey(key, pqc_payload)) {
        if (ParseExplicitPQCSecret(pqc_payload, keystore) || ParseDescriptorPQCPrivateKey(key, keystore)) {
            return true;
        }
        error = "Invalid PQC private key";
        return false;
    }

    if (IsP2MROnlyOutputChain()) {
        error = "Legacy WIF private keys are disabled on this chain; use pqc(KEY) expressions";
        return false;
    }

    CKey decoded = DecodeSecret(key);
    if (!decoded.IsValid()) {
        error = "Invalid private key";
        return false;
    }

    const CPubKey pubkey = decoded.GetPubKey();
    const CKeyID key_id = pubkey.GetID();
    keystore.pubkeys.emplace(key_id, pubkey);
    keystore.keys.emplace(key_id, decoded);
    return true;
}

std::optional<int> NormalizeActiveHeight(int active_height)
{
    return active_height >= 0 ? std::optional<int>{active_height} : std::nullopt;
}

void AddInputs(CMutableTransaction& rawTx, const UniValue& inputs_in, std::optional<bool> rbf)
{
    UniValue inputs;
    if (inputs_in.isNull()) {
        inputs = UniValue::VARR;
    } else {
        inputs = inputs_in.get_array();
    }

    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        Txid txid = Txid::FromUint256(ParseHashO(o, "txid"));

        const UniValue& vout_v = o.find_value("vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.getInt<int>();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout cannot be negative");

        uint32_t nSequence;

        if (rbf.value_or(true)) {
            nSequence = MAX_BIP125_RBF_SEQUENCE; /* CTxIn::SEQUENCE_FINAL - 2 */
        } else if (rawTx.nLockTime) {
            nSequence = CTxIn::MAX_SEQUENCE_NONFINAL; /* CTxIn::SEQUENCE_FINAL - 1 */
        } else {
            nSequence = CTxIn::SEQUENCE_FINAL;
        }

        // set the sequence number if passed in the parameters object
        const UniValue& sequenceObj = o.find_value("sequence");
        if (sequenceObj.isNum()) {
            int64_t seqNr64 = sequenceObj.getInt<int64_t>();
            if (seqNr64 < 0 || seqNr64 > CTxIn::SEQUENCE_FINAL) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, sequence number is out of range");
            } else {
                nSequence = (uint32_t)seqNr64;
            }
        }

        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        rawTx.vin.push_back(in);
    }
}

UniValue NormalizeOutputs(const UniValue& outputs_in)
{
    if (outputs_in.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output argument must be non-null");
    }

    const bool outputs_is_obj = outputs_in.isObject();
    UniValue outputs = outputs_is_obj ? outputs_in.get_obj() : outputs_in.get_array();

    if (!outputs_is_obj) {
        // Translate array of key-value pairs into dict
        UniValue outputs_dict = UniValue(UniValue::VOBJ);
        for (size_t i = 0; i < outputs.size(); ++i) {
            const UniValue& output = outputs[i];
            if (!output.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, key-value pair not an object as expected");
            }
            if (output.size() != 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, key-value pair must contain exactly one key");
            }
            outputs_dict.pushKVs(output);
        }
        outputs = std::move(outputs_dict);
    }
    return outputs;
}

std::vector<std::pair<CTxDestination, CAmount>> ParseOutputs(const UniValue& outputs)
{
    // Duplicate checking
    std::set<CTxDestination> destinations;
    std::vector<std::pair<CTxDestination, CAmount>> parsed_outputs;
    bool has_data{false};
    for (const std::string& name_ : outputs.getKeys()) {
        if (name_ == "data") {
            if (has_data) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, duplicate key: data");
            }
            has_data = true;
            std::vector<unsigned char> data = ParseHexV(outputs[name_].getValStr(), "Data");
            CTxDestination destination{CNoDestination{CScript() << OP_RETURN << data}};
            CAmount amount{0};
            parsed_outputs.emplace_back(destination, amount);
        } else {
            CTxDestination destination{DecodeDestination(name_)};
            CAmount amount{AmountFromValue(outputs[name_])};
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid qbit address: ") + name_);
            }

            if (!destinations.insert(destination).second) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + name_);
            }
            parsed_outputs.emplace_back(destination, amount);
        }
    }
    return parsed_outputs;
}

void AddOutputs(CMutableTransaction& rawTx, const UniValue& outputs_in)
{
    UniValue outputs(UniValue::VOBJ);
    outputs = NormalizeOutputs(outputs_in);

    std::vector<std::pair<CTxDestination, CAmount>> parsed_outputs = ParseOutputs(outputs);
    for (const auto& [destination, nAmount] : parsed_outputs) {
        CScript scriptPubKey = GetScriptForDestination(destination);

        CTxOut out(nAmount, scriptPubKey);
        rawTx.vout.push_back(out);
    }
}

CMutableTransaction ConstructTransaction(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, std::optional<bool> rbf, const uint32_t version)
{
    CMutableTransaction rawTx;

    if (!locktime.isNull()) {
        int64_t nLockTime = locktime.getInt<int64_t>();
        if (nLockTime < 0 || nLockTime > LOCKTIME_MAX)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        rawTx.nLockTime = nLockTime;
    }

    if (version < TX_MIN_STANDARD_VERSION || version > TX_MAX_STANDARD_VERSION) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, version out of range(%d~%d)", TX_MIN_STANDARD_VERSION, TX_MAX_STANDARD_VERSION));
    }
    rawTx.version = version;

    AddInputs(rawTx, inputs_in, rbf);
    AddOutputs(rawTx, outputs_in);

    if (rbf.has_value() && rbf.value() && rawTx.vin.size() > 0 && !SignalsOptInRBF(CTransaction(rawTx))) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter combination: Sequence number(s) contradict replaceable option");
    }

    return rawTx;
}

/** Pushes a JSON object for script verification or signing errors to vErrorsRet. */
static void TxInErrorToJSON(const CTxIn& txin, UniValue& vErrorsRet, const std::string& strMessage)
{
    UniValue entry(UniValue::VOBJ);
    entry.pushKV("txid", txin.prevout.hash.ToString());
    entry.pushKV("vout", (uint64_t)txin.prevout.n);
    UniValue witness(UniValue::VARR);
    for (unsigned int i = 0; i < txin.scriptWitness.stack.size(); i++) {
        witness.push_back(HexStr(txin.scriptWitness.stack[i]));
    }
    entry.pushKV("witness", std::move(witness));
    entry.pushKV("scriptSig", HexStr(txin.scriptSig));
    entry.pushKV("sequence", (uint64_t)txin.nSequence);
    entry.pushKV("error", strMessage);
    vErrorsRet.push_back(std::move(entry));
}

void ParsePrevouts(const UniValue& prevTxsUnival, FlatSigningProvider* keystore, std::map<COutPoint, Coin>& coins, std::optional<int> active_height)
{
    if (!prevTxsUnival.isNull()) {
        const UniValue& prevTxs = prevTxsUnival.get_array();
        for (unsigned int idx = 0; idx < prevTxs.size(); ++idx) {
            const UniValue& p = prevTxs[idx];
            if (!p.isObject()) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");
            }

            const UniValue& prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut,
                {
                    {"txid", UniValueType(UniValue::VSTR)},
                    {"vout", UniValueType(UniValue::VNUM)},
                    {"scriptPubKey", UniValueType(UniValue::VSTR)},
                });

            Txid txid = Txid::FromUint256(ParseHashO(prevOut, "txid"));

            int nOut = prevOut.find_value("vout").getInt<int>();
            if (nOut < 0) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout cannot be negative");
            }

            COutPoint out(txid, nOut);
            std::vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());
            if (IsP2MROnlyOutputChain()) {
                CTxDestination dest;
                if (!ExtractDestination(scriptPubKey, dest)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Only restricted-output-mode prevout scriptPubKeys are supported on this chain");
                }
                const bool output_type_allowed = active_height.has_value() ?
                    IsDestinationOutputTypeAllowedAtHeight(dest, *active_height) :
                    IsDestinationOutputTypeAllowed(dest);
                if (!output_type_allowed) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Only restricted-output-mode prevout scriptPubKeys are supported on this chain");
                }
            }

            {
                auto coin = coins.find(out);
                if (coin != coins.end() && !coin->second.IsSpent() && coin->second.out.scriptPubKey != scriptPubKey) {
                    std::string err("Previous output scriptPubKey mismatch:\n");
                    err = err + ScriptToAsmStr(coin->second.out.scriptPubKey) + "\nvs:\n"+
                        ScriptToAsmStr(scriptPubKey);
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                Coin newcoin;
                newcoin.out.scriptPubKey = scriptPubKey;
                newcoin.out.nValue = MAX_MONEY;
                if (prevOut.exists("amount")) {
                    newcoin.out.nValue = AmountFromValue(prevOut.find_value("amount"));
                }
                newcoin.nHeight = 1;
                coins[out] = std::move(newcoin);
            }

            // if redeemScript and private keys were given, add redeemScript to the keystore so it can be signed
            const bool is_p2sh = scriptPubKey.IsPayToScriptHash();
            const bool is_p2wsh = scriptPubKey.IsPayToWitnessScriptHash();
            const auto p2mr_output = ExtractP2MROutput(scriptPubKey);
            if (keystore && (is_p2sh || is_p2wsh)) {
                RPCTypeCheckObj(prevOut,
                    {
                        {"redeemScript", UniValueType(UniValue::VSTR)},
                        {"witnessScript", UniValueType(UniValue::VSTR)},
                    }, true);
                const UniValue& rs{prevOut.find_value("redeemScript")};
                const UniValue& ws{prevOut.find_value("witnessScript")};
                if (rs.isNull() && ws.isNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing redeemScript/witnessScript");
                }

                // work from witnessScript when possible
                std::vector<unsigned char> scriptData(!ws.isNull() ? ParseHexV(ws, "witnessScript") : ParseHexV(rs, "redeemScript"));
                CScript script(scriptData.begin(), scriptData.end());
                keystore->scripts.emplace(CScriptID(script), script);
                // Automatically also add the P2WSH wrapped version of the script (to deal with P2SH-P2WSH).
                // This is done for redeemScript only for compatibility, it is encouraged to use the explicit witnessScript field instead.
                CScript witness_output_script{GetScriptForDestination(WitnessV0ScriptHash(script))};
                keystore->scripts.emplace(CScriptID(witness_output_script), witness_output_script);

                if (!ws.isNull() && !rs.isNull()) {
                    // if both witnessScript and redeemScript are provided,
                    // they should either be the same (for backwards compat),
                    // or the redeemScript should be the encoded form of
                    // the witnessScript (ie, for p2sh-p2wsh)
                    if (ws.get_str() != rs.get_str()) {
                        std::vector<unsigned char> redeemScriptData(ParseHexV(rs, "redeemScript"));
                        CScript redeemScript(redeemScriptData.begin(), redeemScriptData.end());
                        if (redeemScript != witness_output_script) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "redeemScript does not correspond to witnessScript");
                        }
                    }
                }

                if (is_p2sh) {
                    const CTxDestination p2sh{ScriptHash(script)};
                    const CTxDestination p2sh_p2wsh{ScriptHash(witness_output_script)};
                    if (scriptPubKey == GetScriptForDestination(p2sh)) {
                        // traditional p2sh; arguably an error if
                        // we got here with rs.IsNull(), because
                        // that means the p2sh script was specified
                        // via witnessScript param, but for now
                        // we'll just quietly accept it
                    } else if (scriptPubKey == GetScriptForDestination(p2sh_p2wsh)) {
                        // p2wsh encoded as p2sh; ideally the witness
                        // script was specified in the witnessScript
                        // param, but also support specifying it via
                        // redeemScript param for backwards compat
                        // (in which case ws.IsNull() == true)
                    } else {
                        // otherwise, can't generate scriptPubKey from
                        // either script, so we got unusable parameters
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "redeemScript/witnessScript does not match scriptPubKey");
                    }
                } else if (is_p2wsh) {
                    // plain p2wsh; could throw an error if script
                    // was specified by redeemScript rather than
                    // witnessScript (ie, ws.IsNull() == true), but
                    // accept it for backwards compat
                    const CTxDestination p2wsh{WitnessV0ScriptHash(script)};
                    if (scriptPubKey != GetScriptForDestination(p2wsh)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "redeemScript/witnessScript does not match scriptPubKey");
                    }
                }
            }

            if (keystore && !p2mr_output.has_value() &&
                (prevOut.exists("p2mrScript") || prevOut.exists("p2mrControlBlock") || prevOut.exists("p2mrLeafVersion"))) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "p2mrScript/p2mrControlBlock require a P2MR scriptPubKey");
            }

            if (keystore && p2mr_output.has_value()) {
                ParseP2MRPrevout(prevOut, *p2mr_output, *keystore);
            }
        }
    }
}

void SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, const UniValue& hashType, UniValue& result)
{
    std::optional<int> nHashType = ParseSighashString(hashType);
    if (!nHashType) {
        nHashType = SIGHASH_DEFAULT;
    }

    // Script verification errors
    std::map<int, bilingual_str> input_errors;

    bool complete = SignTransaction(mtx, keystore, coins, *nHashType, input_errors);
    SignTransactionResultToJSON(mtx, complete, coins, input_errors, result);
}

void SignTransactionResultToJSON(CMutableTransaction& mtx, bool complete, const std::map<COutPoint, Coin>& coins, const std::map<int, bilingual_str>& input_errors, UniValue& result)
{
    // Make errors UniValue
    UniValue vErrors(UniValue::VARR);
    for (const auto& err_pair : input_errors) {
        if (err_pair.second.original == "Missing amount") {
            // This particular error needs to be an exception for some reason
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing amount for %s", coins.at(mtx.vin.at(err_pair.first).prevout).out.ToString()));
        }
        TxInErrorToJSON(mtx.vin.at(err_pair.first), vErrors, err_pair.second.original);
    }

    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    result.pushKV("complete", complete);
    if (!vErrors.empty()) {
        if (result.exists("errors")) {
            vErrors.push_backV(result["errors"].getValues());
        }
        result.pushKV("errors", std::move(vErrors));
    }
}
