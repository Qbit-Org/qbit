// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/transactionrecordtests.h>

#include <interfaces/wallet.h>
#include <primitives/transaction.h>
#include <qt/transactionrecord.h>
#include <script/script.h>
#include <uint256.h>

#include <utility>
#include <vector>

#include <QTest>

namespace {
interfaces::WalletTx MakeWalletTx(const std::vector<CAmount>& output_amounts,
                                  const std::vector<bool>& output_is_mine,
                                  const std::vector<bool>& output_is_change,
                                  CAmount debit)
{
    Q_ASSERT(output_amounts.size() == output_is_mine.size());
    Q_ASSERT(output_amounts.size() == output_is_change.size());

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    for (const CAmount amount : output_amounts) {
        tx.vout.emplace_back(amount, CScript{} << OP_TRUE);
    }

    interfaces::WalletTx wtx;
    wtx.tx = MakeTransactionRef(std::move(tx));
    wtx.txin_is_mine = {true};
    wtx.txout_is_mine = output_is_mine;
    wtx.txout_is_change = output_is_change;
    wtx.txout_address.assign(output_amounts.size(), CNoDestination{});
    wtx.txout_address_is_mine = output_is_mine;
    wtx.credit = 0;
    wtx.change = 0;
    for (size_t i = 0; i < output_amounts.size(); ++i) {
        if (output_is_mine[i]) wtx.credit += output_amounts[i];
        if (output_is_change[i]) wtx.change += output_amounts[i];
    }
    wtx.debit = debit;
    wtx.time = 1;
    wtx.is_coinbase = false;
    return wtx;
}
} // namespace

void TransactionRecordTests::feeBearingChangeOnlyPayment()
{
    const interfaces::WalletTx wtx{MakeWalletTx(
        /*output_amounts=*/{50, 49},
        /*output_is_mine=*/{true, true},
        /*output_is_change=*/{true, true},
        /*debit=*/100)};

    const QList<TransactionRecord> parts{TransactionRecord::decomposeTransaction(wtx)};

    QCOMPARE(parts.size(), 1);
    QCOMPARE(parts.front().type, TransactionRecord::PaymentToSelf);
    QCOMPARE(parts.front().debit, -1);
    QCOMPARE(parts.front().credit, 0);
    QCOMPARE(parts.front().getOutputIndex(), -1);
    QCOMPARE(parts.front().debit + parts.front().credit, wtx.credit - wtx.debit);
}

void TransactionRecordTests::ordinaryPaymentWithChange()
{
    const interfaces::WalletTx wtx{MakeWalletTx(
        /*output_amounts=*/{30, 69},
        /*output_is_mine=*/{false, true},
        /*output_is_change=*/{false, true},
        /*debit=*/100)};

    const QList<TransactionRecord> parts{TransactionRecord::decomposeTransaction(wtx)};

    QCOMPARE(parts.size(), 1);
    QCOMPARE(parts.front().type, TransactionRecord::SendToOther);
    QCOMPARE(parts.front().debit, -31);
    QCOMPARE(parts.front().credit, 0);
    QCOMPARE(parts.front().getOutputIndex(), 0);
}

void TransactionRecordTests::zeroFeeChangeOnlyPayment()
{
    const interfaces::WalletTx wtx{MakeWalletTx(
        /*output_amounts=*/{100},
        /*output_is_mine=*/{true},
        /*output_is_change=*/{true},
        /*debit=*/100)};

    QVERIFY(TransactionRecord::decomposeTransaction(wtx).empty());
}
