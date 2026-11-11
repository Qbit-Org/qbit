// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/util.h>
#include <scheduler.h>
#include <wallet/context.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <exception>


namespace wallet {
RPCHelpMan walletpassphrase()
{
    return RPCHelpMan{
        "walletpassphrase",
        "Stores the wallet decryption key in memory for 'timeout' seconds.\n"
                "This is needed prior to performing transactions related to private keys such as sending QBT\n"
            "\nNote:\n"
            "Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock\n"
            "time that overrides the old one.\n"
            "Before it returns, the call refills the wallet's keypools to -keypool, so that a full keypool\n"
            "of addresses can be handed out after the wallet is locked again. A P2MR key takes roughly\n"
            "15 ms to derive, so the first unlock of a new wallet at the default -keypool takes about\n"
            "30 seconds. The refill holds the wallet lock only briefly at a time, so most other calls on\n"
            "the wallet keep working, but walletlock, walletpassphrasechange, rescans and imports wait for\n"
            "it. The timeout counts from the end of the refill. If addresses are drawn from the wallet\n"
            "about as fast as the refill derives them, it stops after a bounded number of steps and\n"
            "continues in the background while the wallet is unlocked. If the refill fails, the call\n"
            "returns an error and the wallet stays unlocked until the timeout.\n",
                {
                    {"passphrase", RPCArg::Type::STR, RPCArg::Optional::NO, "The wallet passphrase"},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The time to keep the decryption key in seconds; capped at 100000000 (~3 years)."},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
            "\nUnlock the wallet for 60 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 60") +
            "\nLock the wallet again (before 60 seconds)\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("walletpassphrase", "\"my pass phrase\", 60")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return UniValue::VNULL;
    CWallet* const pwallet = wallet.get();
    WalletContext& context = EnsureWalletContext(request.context);

    int64_t nSleepTime;
    int64_t relock_time;
    // Prevent concurrent walletpassphrase calls and serialize nRelockTime updates with relocks.
    LOCK(pwallet->m_unlock_mutex);
    LOCK(pwallet->m_relock_mutex);
    {
        LOCK(pwallet->cs_wallet);

        if (!pwallet->IsCrypted()) {
            throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");
        }

        // Note that the walletpassphrase is stored in request.params[0] which is not mlock()ed
        SecureString strWalletPass;
        strWalletPass.reserve(100);
        strWalletPass = std::string_view{request.params[0].get_str()};

        // Get the timeout
        nSleepTime = request.params[1].getInt<int64_t>();
        // Timeout cannot be negative, otherwise it will relock immediately
        if (nSleepTime < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Timeout cannot be negative.");
        }
        // Clamp timeout
        constexpr int64_t MAX_SLEEP_TIME = 100000000; // larger values trigger a macos/libevent bug?
        if (nSleepTime > MAX_SLEEP_TIME) {
            nSleepTime = MAX_SLEEP_TIME;
        }

        if (strWalletPass.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "passphrase cannot be empty");
        }

        // Deriving P2MR keys here would hold cs_wallet for seconds per hundred
        // keys; they are derived below in steps that hold it only briefly.
        if (!pwallet->Unlock(strWalletPass, /*run_pending_initial_keypool_top_up=*/false)) {
            // Check if the passphrase has a null character (see #27067 for details)
            if (strWalletPass.find('\0') == std::string::npos) {
                throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
            } else {
                throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered is incorrect. "
                                                                    "It contains a null character (ie - a zero byte). "
                                                                    "If the passphrase was set with a version of this software prior to 25.0, "
                                                                    "please try again with only the characters up to — but not including — "
                                                                    "the first null character. If this is successful, please set a new "
                                                                    "passphrase to avoid this issue in the future.");
            }
        }

        pwallet->nRelockTime = GetTime() + nSleepTime;
        relock_time = pwallet->nRelockTime;
    }

    // The wallet is unlocked now, so whatever happens below, schedule the
    // relock before returning or rethrowing.
    P2MRKeyPoolRefillResult refill_result{P2MRKeyPoolRefillResult::FAILED};
    std::exception_ptr error;
    try {
        // Replace plaintext PQC key records left by older versions. This
        // needs cs_wallet released.
        pwallet->ReencryptPlaintextPQCKeys();

        // A locked wallet cannot derive P2MR keys, so refill those keypools
        // to -keypool now: callers commonly lock the wallet again right away
        // and then hand out addresses. The steps hold cs_wallet only briefly.
        // Holding m_relock_mutex keeps walletlock and relock callbacks from
        // locking the wallet before the refill and the top-up below finish.
        refill_result = RefillP2MRKeyPoolsAfterUnlock(*pwallet);
        // Top up the non-P2MR keypools, and let a P2MR refill that stopped
        // short continue in the background. A background P2MR step that
        // starts after the relock stops without deriving.
        TopUpKeyPoolAfterUnlock(context, wallet);
    } catch (...) {
        error = std::current_exception();
    }

    // Move the deadline set above to after that work, which can include a
    // long database rewrite and the keypool refill, so the timeout counts from
    // here and the wallet relocks when unlocked_until says.
    {
        LOCK(pwallet->cs_wallet);
        pwallet->nRelockTime = GetTime() + nSleepTime;
        relock_time = pwallet->nRelockTime;
    }

    // Get wallet scheduler to queue up the relock callback in the future.
    // Scheduled events don't get destructed until they are executed,
    // and they are executed in series in a single scheduler thread so
    // no cs_wallet lock is needed.
    // Keep a weak pointer to the wallet so that it is possible to unload the
    // wallet before the following callback is called. If a valid shared pointer
    // is acquired in the callback then the wallet is still loaded.
    std::weak_ptr<CWallet> weak_wallet = wallet;
    context.scheduler->scheduleFromNow([weak_wallet, relock_time] {
        if (auto shared_wallet = weak_wallet.lock()) {
            // A later walletpassphrase can hold m_relock_mutex for its whole
            // keypool refill. Return without waiting for it if a later unlock
            // or a walletlock has already replaced this deadline, so that the
            // scheduler thread is not held up.
            if (WITH_LOCK(shared_wallet->cs_wallet, return shared_wallet->nRelockTime != relock_time)) return;
            LOCK(shared_wallet->m_relock_mutex);
            {
                LOCK(shared_wallet->cs_wallet);
                // Skip if this is not the most recent relock callback.
                if (shared_wallet->nRelockTime != relock_time) return;
            }
            shared_wallet->Lock();
            WITH_LOCK(shared_wallet->cs_wallet, shared_wallet->nRelockTime = 0);
        }
    }, std::chrono::seconds(nSleepTime));

    if (error) std::rethrow_exception(error);
    if (refill_result == P2MRKeyPoolRefillResult::FAILED) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The wallet is unlocked until the timeout, but its keypool could not be refilled; "
                                             "see the debug log. Call walletlock to lock it now.");
    }
    return UniValue::VNULL;
},
    };
}


RPCHelpMan walletpassphrasechange()
{
    return RPCHelpMan{
        "walletpassphrasechange",
        "Changes the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n",
                {
                    {"oldpassphrase", RPCArg::Type::STR, RPCArg::Optional::NO, "The current passphrase"},
                    {"newpassphrase", RPCArg::Type::STR, RPCArg::Optional::NO, "The new passphrase"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("walletpassphrasechange", "\"old one\" \"new one\"")
            + HelpExampleRpc("walletpassphrasechange", "\"old one\", \"new one\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");
    }

    if (pwallet->IsScanningWithPassphrase()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: the wallet is currently being used to rescan the blockchain for related transactions. Please call `abortrescan` before changing the passphrase.");
    }

    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = std::string_view{request.params[0].get_str()};

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = std::string_view{request.params[1].get_str()};

    if (strOldWalletPass.empty() || strNewWalletPass.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "passphrase cannot be empty");
    }

    if (!pwallet->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass)) {
        // Check if the old passphrase had a null character (see #27067 for details)
        if (strOldWalletPass.find('\0') == std::string::npos) {
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
        } else {
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The old wallet passphrase entered is incorrect. "
                                                                "It contains a null character (ie - a zero byte). "
                                                                "If the old passphrase was set with a version of this software prior to 25.0, "
                                                                "please try again with only the characters up to — but not including — "
                                                                "the first null character.");
        }
    }

    return UniValue::VNULL;
},
    };
}


RPCHelpMan walletlock()
{
    return RPCHelpMan{
        "walletlock",
        "Removes the wallet encryption key from memory, locking the wallet.\n"
                "After calling this method, you will need to call walletpassphrase again\n"
                "before being able to call any methods which require the wallet to be unlocked.\n",
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
            "\nSet the passphrase for 2 minutes to perform a transaction\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 120") +
            "\nPerform a send (requires passphrase set)\n"
            + HelpExampleCli("sendtoaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 1.0") +
            "\nClear the passphrase since we are done before 2 minutes is up\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("walletlock", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");
    }

    if (pwallet->IsScanningWithPassphrase()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: the wallet is currently being used to rescan the blockchain for related transactions. Please call `abortrescan` before locking the wallet.");
    }

    LOCK(pwallet->m_relock_mutex);
    pwallet->Lock();
    WITH_LOCK(pwallet->cs_wallet, pwallet->nRelockTime = 0);

    return UniValue::VNULL;
},
    };
}


RPCHelpMan encryptwallet()
{
    return RPCHelpMan{
        "encryptwallet",
        "Encrypts the wallet with 'passphrase'. This is for first time encryption.\n"
        "After this, any calls that interact with private keys such as sending or signing \n"
        "will require the passphrase to be set prior to making these calls.\n"
                "Use the walletpassphrase call for this, and then walletlock call.\n"
                "If the wallet is already encrypted, use the walletpassphrasechange call.\n"
                "** IMPORTANT **\n"
                "For security reasons, the encryption process will generate a new HD seed, resulting\n"
                "in the creation of a fresh set of active descriptors. Therefore, it is crucial to\n"
                "securely back up the newly generated wallet file using the backupwallet RPC.\n",
                {
                    {"passphrase", RPCArg::Type::STR, RPCArg::Optional::NO, "The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long."},
                },
                RPCResult{RPCResult::Type::STR, "", "A string with further instructions. It starts with \"wallet encrypted\" whenever the wallet was encrypted, and contains a warning if setting up the new HD seed, or rewriting the wallet file, did not finish."},
                RPCExamples{
            "\nEncrypt your wallet\n"
            + HelpExampleCli("encryptwallet", "\"my pass phrase\"") +
            "\nNow set the passphrase to use the wallet, such as for signing or sending QBT\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\"") +
            "\nNow we can do something like sign\n"
            + HelpExampleCli("signmessage", "\"address\" \"test message\"") +
            "\nNow lock the wallet again by removing the passphrase\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("encryptwallet", "\"my pass phrase\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: wallet does not contain private keys, nothing to encrypt.");
    }

    // A rescan or descriptor import holds m_relock_mutex for its whole run,
    // and an import also holds cs_wallet while it derives keys. Fail at once,
    // with the errors and in the order that encryptwallet used before it took
    // the locks first, and like it read the encryption state without them.
    // The checks are repeated under the locks.
    if (pwallet->IsScanningWithPassphrase()) {
        if (pwallet->IsCrypted()) {
            throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");
        }
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: the wallet is currently being used to rescan the blockchain for related transactions. Please call `abortrescan` before encrypting the wallet.");
    }

    // Announce the encryption before taking the locks below, which this call
    // holds until the encryption has finished: the checks under them can
    // wait for a background keypool top-up, and listeners such as the GUI
    // must stop reading the wallet before they could wait for the locks. The
    // fail-fast checks above run before the announcement, so a call that
    // fails them announces nothing. A call that fails under the locks, or
    // finds the wallet encrypted there, ends the announcement once it has
    // released them.
    const CWallet::EncryptionInProgressScope encryption_in_progress{*pwallet};

    // Hold the locks from the encryption-state check through the encryption
    // itself, so a call that overlaps another encryption reports the wallet
    // as already encrypted once that encryption has finished.
    LOCK2(pwallet->m_relock_mutex, pwallet->cs_wallet);

    if (pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");
    }

    if (pwallet->IsScanningWithPassphrase()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: the wallet is currently being used to rescan the blockchain for related transactions. Please call `abortrescan` before encrypting the wallet.");
    }

    const PQCKeyValidationInfo pqc_validation{pwallet->GetPQCKeyValidationInfo()};
    if (pqc_validation.pending_records > 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: plaintext PQC wallet key validation is still in progress. Try encryptwallet again after validation completes.");
    }
    if (pqc_validation.failed_records > 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: plaintext PQC wallet key validation failed. Wallet encryption is disabled until the wallet is restored or repaired.");
    }

    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = std::string_view{request.params[0].get_str()};

    if (strWalletPass.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "passphrase cannot be empty");
    }

    bilingual_str new_seed_error;
    if (!pwallet->EncryptWallet(strWalletPass, /*use_create_keypool_warmup=*/false, &new_seed_error)) {
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");
    }

    // The wallet is encrypted either way, so a failure to set up the new seed
    // is reported in the result rather than as an error.
    std::string result{new_seed_error.empty() ?
        "wallet encrypted; The keypool has been flushed and a new HD seed was generated. You need to make a new backup with the backupwallet RPC." :
        "wallet encrypted; Warning: " + NewSeedFailedWarning(new_seed_error).original};
    if (pwallet->NeedsRewriteAfterEncryption()) {
        result += " Warning: " + PendingRewriteWarning().original;
    }
    return result;
},
    };
}
} // namespace wallet
