// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/fees.h>

#include <wallet/coincontrol.h>
#include <wallet/wallet.h>


namespace wallet {
CAmount GetRequiredFee(const CWallet& wallet, unsigned int nTxBytes)
{
    return GetRequiredFeeRate(wallet).GetFee(static_cast<int32_t>(nTxBytes));
}


CAmount GetMinimumFee(const CWallet& wallet, unsigned int nTxBytes, const CCoinControl& coin_control, FeeCalculation* feeCalc)
{
    return GetMinimumFeeRate(wallet, coin_control, feeCalc).GetFee(static_cast<int32_t>(nTxBytes));
}

CFeeRate GetRequiredFeeRate(const CWallet& wallet)
{
    return std::max(wallet.m_min_fee, wallet.chain().relayMinFee());
}

CFeeRate GetMinimumFeeRate(const CWallet& wallet, const CCoinControl& coin_control, FeeCalculation* feeCalc)
{
    /* User control of how to calculate fee uses the following parameter precedence:
       1. coin_control.m_feerate
       2. coin_control.m_confirm_target
       3. m_pay_tx_fee (user-set member variable of wallet)
       4. m_confirm_target (user-set member variable of wallet)
       The first parameter that is set is used.
    */
    CFeeRate feerate_needed;
    if (feeCalc) feeCalc->estimate_unavailable = false;
    if (coin_control.m_feerate) { // 1.
        feerate_needed = *(coin_control.m_feerate);
        if (feeCalc) feeCalc->reason = FeeReason::PAYTXFEE;
        // Allow to override automatic min/max check over coin control instance
        if (coin_control.fOverrideFeeRate) return feerate_needed;
    }
    else if (!coin_control.m_confirm_target && wallet.m_pay_tx_fee != CFeeRate(0)) { // 3. TODO: remove magic value of 0 for wallet member m_pay_tx_fee
        feerate_needed = wallet.m_pay_tx_fee;
        if (feeCalc) feeCalc->reason = FeeReason::PAYTXFEE;
    }
    else { // 2. or 4.
        // We will use smart fee estimation
        unsigned int target = coin_control.m_confirm_target ? *coin_control.m_confirm_target : wallet.m_confirm_target;
        // By default estimates are economical iff we are signaling opt-in-RBF
        bool conservative_estimate = !coin_control.m_signal_bip125_rbf.value_or(wallet.m_signal_rbf);
        // Allow to override the default fee estimate mode over the CoinControl instance
        if (coin_control.m_fee_mode == FeeEstimateMode::CONSERVATIVE) conservative_estimate = true;
        else if (coin_control.m_fee_mode == FeeEstimateMode::ECONOMICAL) conservative_estimate = false;

        feerate_needed = wallet.chain().estimateSmartFee(target, conservative_estimate, feeCalc);
        if (feerate_needed == CFeeRate(0)) {
            // if we don't have enough data for estimateSmartFee, then use fallback fee
            feerate_needed = wallet.m_fallback_fee;
            if (feeCalc) {
                feeCalc->reason = FeeReason::FALLBACK;
                // The minimums below may replace the reason, but not the fact that there was no estimate
                feeCalc->estimate_unavailable = true;
            }

            // directly return if fallback fee is disabled (feerate 0 == disabled)
            if (wallet.m_fallback_fee == CFeeRate(0)) return feerate_needed;
        }
        // Obey mempool min fee when using smart fee estimation
        CFeeRate min_mempool_feerate = wallet.chain().mempoolMinFee();
        if (feerate_needed < min_mempool_feerate) {
            feerate_needed = min_mempool_feerate;
            if (feeCalc) feeCalc->reason = FeeReason::MEMPOOL_MIN;
        }
    }

    // prevent user from paying a fee below the required fee rate
    CFeeRate required_feerate = GetRequiredFeeRate(wallet);
    if (required_feerate > feerate_needed) {
        feerate_needed = required_feerate;
        if (feeCalc) feeCalc->reason = FeeReason::REQUIRED;
    }
    return feerate_needed;
}

CFeeRate GetDiscardRate(const CWallet& wallet)
{
    unsigned int highest_target = wallet.chain().estimateMaxBlocks();
    CFeeRate discard_rate = wallet.chain().estimateSmartFee(highest_target, /*conservative=*/false);
    // Without an estimate for the longest target, and unless -discardfee was set, let the fallback
    // fee, raised to the required fee rate that spending the change must pay too, stand in for it.
    // Otherwise change worth up to the cost of spending it at the -discardfee default, many times
    // the default fallback fee, would be added to the fee.
    if (discard_rate == CFeeRate(0) && wallet.m_allow_fallback_fee && !wallet.m_discard_rate_set) {
        discard_rate = std::max(wallet.m_fallback_fee, GetRequiredFeeRate(wallet));
    }
    // Don't let discard_rate be greater than longest possible fee estimate if we get a valid fee estimate
    discard_rate = (discard_rate == CFeeRate(0)) ? wallet.m_discard_rate : std::min(discard_rate, wallet.m_discard_rate);
    // Discard rate must be at least dust relay feerate
    discard_rate = std::max(discard_rate, wallet.chain().relayDustFee());
    return discard_rate;
}
} // namespace wallet
