// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/transactionfilterproxytests.h>

#include <consensus/amount.h>
#include <qt/transactionfilterproxy.h>
#include <qt/transactionrecord.h>
#include <qt/transactiontablemodel.h>

#include <cstdlib>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include <QAbstractListModel>
#include <QDateTime>
#include <QString>
#include <QTest>
#include <QTimeZone>
#include <QVariant>

namespace {
struct Row {
    int status;
    int type;
    QDateTime date;
    QString address;
    QString label;
    QString txid;
    qint64 amount;
};

//! A transaction list that counts the roles read from it.
class CountingSourceModel : public QAbstractListModel
{
public:
    explicit CountingSourceModel(std::vector<Row> rows) : m_rows(std::move(rows)) {}

    int rowCount(const QModelIndex& parent = QModelIndex()) const override
    {
        return parent.isValid() ? 0 : static_cast<int>(m_rows.size());
    }

    QVariant data(const QModelIndex& index, int role) const override
    {
        ++m_reads[role];
        const Row& row{m_rows.at(index.row())};
        switch (role) {
        case TransactionTableModel::StatusRole: return row.status;
        case TransactionTableModel::TypeRole: return row.type;
        case TransactionTableModel::DateRole: return row.date;
        case TransactionTableModel::AddressRole: return row.address;
        case TransactionTableModel::LabelRole: return row.label;
        case TransactionTableModel::TxHashRole: return row.txid;
        case TransactionTableModel::AmountRole: return row.amount;
        }
        return {};
    }

    int reads(int role) const
    {
        const auto it{m_reads.find(role)};
        return it == m_reads.end() ? 0 : it->second;
    }
    void resetReads() { m_reads.clear(); }
    //! Notify a change of every row, as TransactionTableModel::updateConfirmations does.
    void touchAllRows() { Q_EMIT dataChanged(index(0), index(rowCount() - 1)); }

private:
    std::vector<Row> m_rows;
    mutable std::map<int, int> m_reads;
};

const QDateTime BASE_DATE{QDate{2026, 1, 1}, QTime{12, 0}, QTimeZone::utc()};

//! Rows that mix every status and type, with search texts that each match
//! only one of address, label and txid.
std::vector<Row> MakeRows()
{
    const std::vector<int> statuses{
        TransactionStatus::Confirmed, TransactionStatus::Unconfirmed, TransactionStatus::Confirming,
        TransactionStatus::Conflicted, TransactionStatus::Abandoned, TransactionStatus::Immature,
        TransactionStatus::NotAccepted};
    const std::vector<int> types{
        TransactionRecord::Other, TransactionRecord::Generated, TransactionRecord::SendToAddress,
        TransactionRecord::SendToOther, TransactionRecord::RecvWithAddress, TransactionRecord::RecvFromOther,
        TransactionRecord::PaymentToSelf};
    const std::vector<QString> addresses{"qbrt1qAbCdEf0", "qbrt1qxyz1", "", "qbrt1qABCDzz2", "qbrt1qmno3"};
    const std::vector<QString> labels{"Savings", "", "Mining pool", "", "savings jar", "Ärger"};
    const std::vector<qint64> amounts{0, 1 * COIN, -1 * COIN, 5 * COIN, -7 * COIN, 1000 * COIN, -4999 * COIN, 3};

    std::vector<Row> rows;
    for (int i = 0; i < 49; ++i) {
        rows.push_back({
            .status = statuses.at(i % statuses.size()),
            .type = types.at((i / 7 + i) % types.size()),
            .date = BASE_DATE.addDays(i),
            .address = addresses.at(i % addresses.size()),
            .label = labels.at(i % labels.size()),
            // Hex digits only, so no txid contains the address or label search texts.
            .txid = QString("%1").arg(0xf00 + i * 0x31, 64, 16, QLatin1Char('0')),
            .amount = amounts.at(i % amounts.size()),
        });
    }
    return rows;
}

struct FilterState {
    std::optional<QDateTime> date_from;
    std::optional<QDateTime> date_to;
    QString search;
    quint32 types{TransactionFilterProxy::ALL_TYPES};
    CAmount min_amount{0};
    bool show_inactive{true};
};

//! TransactionFilterProxy::filterAcceptsRow before it skipped the address,
//! label and txid for an empty search.
bool ReferenceAccepts(const QAbstractItemModel& model, int row, const FilterState& filter)
{
    const QModelIndex index{model.index(row, 0)};

    const int status{index.data(TransactionTableModel::StatusRole).toInt()};
    if (!filter.show_inactive && status == TransactionStatus::Conflicted) return false;

    const int type{index.data(TransactionTableModel::TypeRole).toInt()};
    if (!(TransactionFilterProxy::TYPE(type) & filter.types)) return false;

    const QDateTime datetime{index.data(TransactionTableModel::DateRole).toDateTime()};
    if (filter.date_from && datetime < *filter.date_from) return false;
    if (filter.date_to && datetime > *filter.date_to) return false;

    const QString address{index.data(TransactionTableModel::AddressRole).toString()};
    const QString label{index.data(TransactionTableModel::LabelRole).toString()};
    const QString txid{index.data(TransactionTableModel::TxHashRole).toString()};
    if (!address.contains(filter.search, Qt::CaseInsensitive) &&
        !label.contains(filter.search, Qt::CaseInsensitive) &&
        !txid.contains(filter.search, Qt::CaseInsensitive)) {
        return false;
    }

    const qint64 amount{llabs(index.data(TransactionTableModel::AmountRole).toLongLong())};
    if (amount < filter.min_amount) return false;

    return true;
}

void Apply(TransactionFilterProxy& proxy, const FilterState& filter)
{
    proxy.setDateRange(filter.date_from, filter.date_to);
    proxy.setSearchString(filter.search);
    proxy.setTypeFilter(filter.types);
    proxy.setMinAmount(filter.min_amount);
    proxy.setShowInactive(filter.show_inactive);
}

std::set<int> AcceptedRows(const TransactionFilterProxy& proxy)
{
    std::set<int> rows;
    for (int i = 0; i < proxy.rowCount(); ++i) {
        rows.insert(proxy.mapToSource(proxy.index(i, 0)).row());
    }
    return rows;
}

std::vector<FilterState> MakeFilterStates()
{
    const std::vector<std::pair<std::optional<QDateTime>, std::optional<QDateTime>>> date_ranges{
        {std::nullopt, std::nullopt},
        {BASE_DATE.addDays(10), std::nullopt},
        {std::nullopt, BASE_DATE.addDays(30)},
        {BASE_DATE.addDays(10), BASE_DATE.addDays(30)},
        {BASE_DATE.addDays(30), BASE_DATE.addDays(10)},
    };
    const std::vector<quint32> type_filters{
        TransactionFilterProxy::ALL_TYPES,
        TransactionFilterProxy::TYPE(TransactionRecord::Generated) | TransactionFilterProxy::TYPE(TransactionRecord::RecvWithAddress),
        TransactionFilterProxy::TYPE(TransactionRecord::SendToAddress),
        0,
    };
    // An address prefix in another case, a label word in another case, a
    // txid fragment, and a text nothing contains.
    const std::vector<QString> searches{"", "abcd", "SAVINGS", "f31", "no such text", "ä"};
    const std::vector<CAmount> min_amounts{0, 5 * COIN, 1000 * COIN};

    std::vector<FilterState> states;
    for (const bool show_inactive : {true, false}) {
        for (const quint32 types : type_filters) {
            for (const auto& [from, to] : date_ranges) {
                for (const CAmount min_amount : min_amounts) {
                    for (const QString& search : searches) {
                        states.push_back({
                            .date_from = from,
                            .date_to = to,
                            .search = search,
                            .types = types,
                            .min_amount = min_amount,
                            .show_inactive = show_inactive,
                        });
                    }
                }
            }
        }
    }
    return states;
}
} // namespace

void TransactionFilterProxyTests::emptySearchSkipsAddressLabelAndTxid()
{
    CountingSourceModel source{MakeRows()};
    TransactionFilterProxy proxy;
    const int rows{source.rowCount()};
    const auto search_reads{[&source] {
        return source.reads(TransactionTableModel::AddressRole) +
               source.reads(TransactionTableModel::LabelRole) +
               source.reads(TransactionTableModel::TxHashRole);
    }};

    // The first pass, and a pass after the source reports every row changed,
    // as it does for each new block. Without a date range the date is not
    // read either.
    proxy.setSourceModel(&source);
    QVERIFY(proxy.rowCount() > 0);
    QVERIFY(source.reads(TransactionTableModel::StatusRole) >= rows);
    QCOMPARE(search_reads(), 0);
    QCOMPARE(source.reads(TransactionTableModel::DateRole), 0);

    source.resetReads();
    source.touchAllRows();
    QVERIFY(proxy.rowCount() > 0);
    QVERIFY(source.reads(TransactionTableModel::StatusRole) >= rows);
    QCOMPARE(search_reads(), 0);
    QCOMPARE(source.reads(TransactionTableModel::DateRole), 0);

    // The other filters run their passes without the search texts.
    source.resetReads();
    Apply(proxy, {
        .date_from = BASE_DATE.addDays(5),
        .date_to = BASE_DATE.addDays(40),
        .search = QString(),
        .types = TransactionFilterProxy::TYPE(TransactionRecord::Generated) | TransactionFilterProxy::TYPE(TransactionRecord::RecvWithAddress),
        .min_amount = 1 * COIN,
        .show_inactive = false,
    });
    QVERIFY(proxy.rowCount() > 0);
    QVERIFY(source.reads(TransactionTableModel::StatusRole) >= rows);
    QVERIFY(source.reads(TransactionTableModel::DateRole) > 0);
    QCOMPARE(search_reads(), 0);
    source.resetReads();
    source.touchAllRows();
    QVERIFY(proxy.rowCount() > 0);
    QVERIFY(source.reads(TransactionTableModel::StatusRole) >= rows);
    QCOMPARE(search_reads(), 0);

    // A search reads them, for the rows the other filters accept.
    source.resetReads();
    proxy.setSearchString("abcd");
    QVERIFY(source.reads(TransactionTableModel::AddressRole) > 0);
    QVERIFY(source.reads(TransactionTableModel::AddressRole) < rows);

    // Clearing the search stops the reads again.
    proxy.setSearchString(QString());
    source.resetReads();
    source.touchAllRows();
    QVERIFY(proxy.rowCount() > 0);
    QVERIFY(source.reads(TransactionTableModel::StatusRole) >= rows);
    QCOMPARE(search_reads(), 0);
}

void TransactionFilterProxyTests::acceptedRowsMatchReference()
{
    CountingSourceModel source{MakeRows()};
    TransactionFilterProxy proxy;
    proxy.setSourceModel(&source);

    int empty_results{0};
    int partial_results{0};
    int full_results{0};
    std::map<QString, int> rows_found_by_search;
    for (const FilterState& filter : MakeFilterStates()) {
        Apply(proxy, filter);
        std::set<int> expected;
        for (int row = 0; row < source.rowCount(); ++row) {
            if (ReferenceAccepts(source, row, filter)) expected.insert(row);
        }
        const std::set<int> accepted{AcceptedRows(proxy)};
        if (accepted != expected) {
            QFAIL(qPrintable(QString("Accepted rows differ for search '%1', types %2, min amount %3, show inactive %4, from %5, to %6")
                                 .arg(filter.search)
                                 .arg(filter.types)
                                 .arg(filter.min_amount)
                                 .arg(QString(filter.show_inactive ? "yes" : "no"))
                                 .arg(filter.date_from ? filter.date_from->toString(Qt::ISODate) : QString("-"))
                                 .arg(filter.date_to ? filter.date_to->toString(Qt::ISODate) : QString("-"))));
        }
        if (expected.empty()) {
            ++empty_results;
        } else if (static_cast<int>(expected.size()) == source.rowCount()) {
            ++full_results;
        } else {
            ++partial_results;
        }
        rows_found_by_search[filter.search] += expected.size();
    }

    // The states cover the outcomes, and every search except the one nothing
    // contains finds rows.
    QVERIFY(empty_results > 0);
    QVERIFY(partial_results > 0);
    QVERIFY(full_results > 0);
    for (const auto& [search, found] : rows_found_by_search) {
        QCOMPARE(found > 0, search != "no such text");
    }
}
