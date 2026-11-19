// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/overviewpagetests.h>

#include <addresstype.h>
#include <consensus/amount.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <primitives/transaction.h>
#include <qt/clientmodel.h>
#include <qt/headproxymodel.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/qbitunits.h>
#include <qt/test/syntheticwallet.h>
#include <qt/transactiontablemodel.h>
#include <qt/walletmodel.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/translation.h>

#include <QAbstractItemModelTester>
#include <QAbstractProxyModel>
#include <QCoreApplication>
#include <QEvent>
#include <QIcon>
#include <QIdentityProxyModel>
#include <QListView>
#include <QPersistentModelIndex>
#include <QSignalSpy>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QStringList>
#include <QStringListModel>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {
//! The number of recent transactions the overview page shows (NUM_ITEMS).
constexpr int NUM_ITEMS{5};

//! Rebuilds the column 0 contents a view of the model holds from the model's
//! signals alone, so a change the model does not announce shows up as a
//! difference from the model's current contents.
class ModelMirror : public QObject
{
public:
    explicit ModelMirror(QAbstractItemModel& model) : m_model{model}
    {
        connect(&model, &QAbstractItemModel::rowsInserted, this, [this](const QModelIndex&, int first, int last) {
            for (int row = first; row <= last; ++row) m_rows.insert(row, read(row));
        });
        connect(&model, &QAbstractItemModel::rowsRemoved, this, [this](const QModelIndex&, int first, int last) {
            if (first < 0 || last >= m_rows.size()) {
                m_out_of_range = true;
                return;
            }
            m_rows.remove(first, last - first + 1);
        });
        connect(&model, &QAbstractItemModel::dataChanged, this, [this](const QModelIndex& top_left, const QModelIndex& bottom_right) {
            for (int row = top_left.row(); row <= bottom_right.row(); ++row) {
                if (row < 0 || row >= m_rows.size()) {
                    m_out_of_range = true;
                    return;
                }
                m_rows[row] = read(row);
            }
        });
        connect(&model, &QAbstractItemModel::layoutChanged, this, [this] { reload(); });
        connect(&model, &QAbstractItemModel::modelReset, this, [this] { reload(); });
        reload();
    }

    const QStringList& rows() const { return m_rows; }
    //! Whether the model announced a change to rows it did not have.
    bool outOfRange() const { return m_out_of_range; }

private:
    QString read(int row) const { return m_model.index(row, 0).data().toString(); }
    void reload()
    {
        m_rows.clear();
        for (int row = 0; row < m_model.rowCount(); ++row) m_rows.append(read(row));
    }

    QAbstractItemModel& m_model;
    QStringList m_rows;
    bool m_out_of_range{false};
};

//! Column 0 of the first rows of the model.
QStringList FirstRows(const QAbstractItemModel& model, int limit)
{
    QStringList rows;
    for (int row = 0; row < std::min(limit, model.rowCount()); ++row) rows.append(model.index(row, 0).data().toString());
    return rows;
}

//! Check that head shows the first NUM_ITEMS rows of source, in every column
//! and role, maps them to their source rows, and announced what it shows.
void CheckHead(const HeadProxyModel& head, const QAbstractItemModel& source, const ModelMirror& mirror)
{
    const int rows{std::min(NUM_ITEMS, source.rowCount())};
    QCOMPARE(head.rowCount(), rows);
    QCOMPARE(head.columnCount(), source.columnCount());
    for (int row = 0; row < rows; ++row) {
        for (int column = 0; column < source.columnCount(); ++column) {
            const QModelIndex proxy_index{head.index(row, column)};
            const QModelIndex source_index{source.index(row, column)};
            QVERIFY(proxy_index.isValid());
            QCOMPARE(proxy_index.data(), source_index.data());
            QCOMPARE(head.mapToSource(proxy_index), source_index);
            QCOMPARE(head.mapFromSource(source_index), proxy_index);
        }
    }
    QVERIFY(!head.index(rows, 0).isValid());
    if (source.rowCount() > rows) QVERIFY(!head.mapFromSource(source.index(rows, 0)).isValid());
    QVERIFY(!mirror.outOfRange());
    QCOMPARE(mirror.rows(), FirstRows(source, NUM_ITEMS));
}

#define CHECK_HEAD(head, source, mirror)       \
    do {                                       \
        CheckHead((head), (source), (mirror)); \
        if (QTest::currentTestFailed()) return; \
    } while (0)

void AppendRow(QStandardItemModel& model, const QString& name)
{
    model.appendRow({new QStandardItem{name}, new QStandardItem{name + QStringLiteral("-amount")}});
}

//! Insert names at row in one rowsInserted.
void InsertRows(QStandardItemModel& model, int row, const QStringList& names)
{
    model.insertRows(row, names.size());
    for (int i = 0; i < names.size(); ++i) {
        model.setData(model.index(row + i, 0), names.at(i));
        model.setData(model.index(row + i, 1), QString{names.at(i) + QStringLiteral("-amount")});
    }
}

//! Accepts the rows whose column 0 text, after its first character, is a
//! number of at least minimum. Changing minimum changes the filter without
//! telling the proxy, as before an invalidate().
class MinimumFilter : public QSortFilterProxyModel
{
public:
    int minimum{0};

protected:
    bool filterAcceptsRow(int source_row, const QModelIndex& source_parent) const override
    {
        return sourceModel()->index(source_row, 0, source_parent).data().toString().mid(1).toInt() >= minimum;
    }
};

//! Counts the calls a proxy makes into its source.
class CountingProxy : public QIdentityProxyModel
{
public:
    int rowCount(const QModelIndex& parent = QModelIndex()) const override
    {
        ++calls;
        return QIdentityProxyModel::rowCount(parent);
    }
    int columnCount(const QModelIndex& parent = QModelIndex()) const override
    {
        ++calls;
        return QIdentityProxyModel::columnCount(parent);
    }
    bool hasChildren(const QModelIndex& parent = QModelIndex()) const override
    {
        ++calls;
        return QIdentityProxyModel::hasChildren(parent);
    }
    Qt::ItemFlags flags(const QModelIndex& index) const override
    {
        ++calls;
        return QIdentityProxyModel::flags(index);
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        ++calls;
        return QIdentityProxyModel::headerData(section, orientation, role);
    }
    QVariant data(const QModelIndex& index, int role) const override
    {
        ++calls;
        return QIdentityProxyModel::data(index, role);
    }
    QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override
    {
        ++calls;
        return QIdentityProxyModel::index(row, column, parent);
    }

    mutable int calls{0};
};

//! Reads the persistent indexes a model keeps, and updates on every change
//! of its rows, through a pointer to the protected member.
class PersistentIndexes : public QAbstractItemModel
{
public:
    static qsizetype Count(const QAbstractItemModel& model)
    {
        return (model.*(&PersistentIndexes::persistentIndexList))().size();
    }
};

//! Persistent indexes held on the model and on every model below it.
qsizetype ChainPersistentIndexes(const QAbstractItemModel* model)
{
    qsizetype count{0};
    while (model) {
        count += PersistentIndexes::Count(*model);
        const auto* proxy{qobject_cast<const QAbstractProxyModel*>(model)};
        model = proxy ? proxy->sourceModel() : nullptr;
    }
    return count;
}

//! The sorted, filtered history under the view.
QSortFilterProxyModel* SortedHistory(const QListView& view)
{
    QAbstractItemModel* model{view.model()};
    while (auto* proxy{qobject_cast<QAbstractProxyModel*>(model)}) {
        if (auto* sorted{qobject_cast<QSortFilterProxyModel*>(proxy)}) return sorted;
        model = proxy->sourceModel();
    }
    return nullptr;
}

struct OverviewEnvironment {
    explicit OverviewEnvironment(interfaces::Node& node)
        : test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}}
    {
        node.setContext(&test.m_node);
        platform_style.reset(PlatformStyle::instantiate("other"));
        options_model = std::make_unique<OptionsModel>(node);
        bilingual_str error;
        if (!options_model->Init(error)) throw std::runtime_error{error.original};
        client_model = std::make_unique<ClientModel>(node, options_model.get());
    }

    std::unique_ptr<WalletModel> makeModel(const std::shared_ptr<qt_test::SyntheticWalletState>& state)
    {
        return std::make_unique<WalletModel>(qt_test::MakeSyntheticWallet({}, state), *client_model, platform_style.get());
    }

    TestChain100Setup test;
    std::unique_ptr<const PlatformStyle> platform_style;
    std::unique_ptr<OptionsModel> options_model;
    std::unique_ptr<ClientModel> client_model;
};

constexpr int UNCONFIRMED{std::numeric_limits<int>::max()};
constexpr int CONFLICTED{-1};

//! The status the wallet reports for a transaction received at time and
//! confirmed at height, or UNCONFIRMED, or CONFLICTED.
interfaces::WalletTxStatus MakeStatus(int64_t time, int height)
{
    interfaces::WalletTxStatus status{};
    status.time_received = static_cast<unsigned int>(time);
    status.is_trusted = true;
    if (height == CONFLICTED) {
        status.block_height = UNCONFIRMED;
        status.depth_in_main_chain = -1;
    } else if (height == UNCONFIRMED) {
        status.block_height = UNCONFIRMED;
        status.depth_in_main_chain = 0;
    } else {
        status.block_height = height;
        status.depth_in_main_chain = 1;
        status.is_in_main_chain = true;
    }
    return status;
}

//! Add a payment of one coin to the synthetic wallet's history. Each n gives
//! a different transaction, shown as one row.
Txid AddTx(qt_test::SyntheticWalletState& state, uint32_t n, int64_t time, int height)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid{}, n});
    const CTxDestination destination{PKHash{uint160{}}};
    mtx.vout.emplace_back(COIN, GetScriptForDestination(destination));
    const CTransactionRef tx{MakeTransactionRef(mtx)};
    qt_test::SyntheticWalletState::HistoryTx entry{
        .tx = interfaces::WalletTx{
            .tx = tx,
            .txin_is_mine = {false},
            .txout_is_mine = {true},
            .txout_is_change = {false},
            .txout_address = {destination},
            .txout_address_is_mine = {true},
            .credit = COIN,
            .debit = 0,
            .change = 0,
            .time = time,
            .value_map = {},
            .is_coinbase = false,
        },
        .status = MakeStatus(time, height),
    };
    std::lock_guard lock{state.mutex};
    state.history.emplace(tx->GetHash(), std::move(entry));
    return tx->GetHash();
}

void SetTxHeight(qt_test::SyntheticWalletState& state, const Txid& txid, int height)
{
    std::lock_guard lock{state.mutex};
    auto& entry{state.history.at(txid)};
    entry.status = MakeStatus(entry.tx.time, height);
}

void RemoveTx(qt_test::SyntheticWalletState& state, const Txid& txid)
{
    std::lock_guard lock{state.mutex};
    state.history.erase(txid);
}

//! Send the wallet's transaction notification and deliver the update it
//! queues for the transaction table.
void NotifyTx(qt_test::SyntheticWalletState& state, const Txid& txid, ChangeType change)
{
    std::vector<interfaces::Wallet::TransactionChangedFn> listeners;
    {
        std::lock_guard lock{state.mutex};
        for (const auto& [id, notify] : state.transaction_changed) listeners.push_back(notify);
    }
    for (const auto& notify : listeners) notify(txid, change);
    QCoreApplication::sendPostedEvents();
}

QString Hash(const Txid& txid)
{
    return QString::fromStdString(txid.ToString());
}

QStringList Hashes(const std::vector<Txid>& txids)
{
    QStringList hashes;
    for (const Txid& txid : txids) hashes.append(Hash(txid));
    return hashes;
}

//! The transactions the list shows, in order.
QStringList VisibleTransactions(const QListView& view)
{
    QStringList hashes;
    const QAbstractItemModel* model{view.model()};
    for (int row = 0; row < model->rowCount(); ++row) {
        if (view.isRowHidden(row)) continue;
        hashes.append(model->index(row, TransactionTableModel::ToAddress).data(TransactionTableModel::TxHashRole).toString());
    }
    return hashes;
}

int TableRow(const TransactionTableModel& table, const Txid& txid)
{
    for (int row = 0; row < table.rowCount({}); ++row) {
        if (table.index(row, 0).data(TransactionTableModel::TxHashRole).toString() == Hash(txid)) return row;
    }
    return -1;
}

//! Check that every role TxViewDelegate paints from reaches it unchanged for
//! the rows the list shows.
void CheckDelegateRoles(const QListView& view, const TransactionTableModel& table)
{
    const QAbstractItemModel* model{view.model()};
    for (int row = 0; row < model->rowCount(); ++row) {
        if (view.isRowHidden(row)) continue;
        const QModelIndex shown{model->index(row, TransactionTableModel::ToAddress)};
        const QString hash{shown.data(TransactionTableModel::TxHashRole).toString()};
        int table_row{-1};
        for (int i = 0; i < table.rowCount({}); ++i) {
            if (table.index(i, 0).data(TransactionTableModel::TxHashRole).toString() == hash) table_row = i;
        }
        QVERIFY(table_row >= 0);
        const QModelIndex source{table.index(table_row, TransactionTableModel::ToAddress)};
        for (const int role : {int{Qt::DisplayRole}, int{Qt::ForegroundRole}, int{TransactionTableModel::DateRole},
                               int{TransactionTableModel::AmountRole}, int{TransactionTableModel::ConfirmedRole}}) {
            QCOMPARE(shown.data(role), source.data(role));
        }
        QCOMPARE(qvariant_cast<QIcon>(shown.data(TransactionTableModel::RawDecorationRole)).isNull(),
                 qvariant_cast<QIcon>(source.data(TransactionTableModel::RawDecorationRole)).isNull());
    }
}

#define CHECK_RECENT(view, table, expected)                   \
    do {                                                      \
        QCOMPARE(VisibleTransactions(view), Hashes(expected)); \
        CheckDelegateRoles((view), (table));                  \
        if (QTest::currentTestFailed()) return;               \
    } while (0)

//! Re-read a transaction's status and tell the filter that the row changed
//! in every column, including the one it sorts by.
void RefreshRow(TransactionTableModel& table, qt_test::SyntheticWalletState& state, const Txid& txid)
{
    NotifyTx(state, txid, CT_UPDATED);
    const int row{TableRow(table, txid)};
    QVERIFY(row >= 0);
    Q_EMIT table.dataChanged(table.index(row, 0), table.index(row, TransactionTableModel::Amount));
}
} // namespace

void OverviewPageTests::headProxyModelTests()
{
    // A plain list: inserts, removals and data changes inside, across and
    // beyond the head, and resets.
    {
        QStandardItemModel source{0, 2};
        HeadProxyModel head{NUM_ITEMS};
        head.setSourceModel(&source);
        QAbstractItemModelTester tester{&head, QAbstractItemModelTester::FailureReportingMode::QtTest};
        ModelMirror mirror{head};
        CHECK_HEAD(head, source, mirror);

        for (const char* name : {"a", "b", "c"}) AppendRow(source, QString::fromLatin1(name));
        CHECK_HEAD(head, source, mirror);
        for (const char* name : {"d", "e"}) AppendRow(source, QString::fromLatin1(name));
        CHECK_HEAD(head, source, mirror);

        QSignalSpy inserted{&head, &QAbstractItemModel::rowsInserted};
        QSignalSpy removed{&head, &QAbstractItemModel::rowsRemoved};
        QSignalSpy changed{&head, &QAbstractItemModel::dataChanged};
        for (const char* name : {"f", "g"}) AppendRow(source, QString::fromLatin1(name));
        InsertRows(source, NUM_ITEMS, {QStringLiteral("x0"), QStringLiteral("x1")});
        QCOMPARE(inserted.count(), 0);
        QCOMPARE(removed.count(), 0);
        QCOMPARE(changed.count(), 0);
        CHECK_HEAD(head, source, mirror);

        InsertRows(source, 0, {QStringLiteral("n0")});
        CHECK_HEAD(head, source, mirror);
        InsertRows(source, 3, {QStringLiteral("n1"), QStringLiteral("n2")});
        CHECK_HEAD(head, source, mirror);
        InsertRows(source, 1, {"m0", "m1", "m2", "m3", "m4", "m5", "m6", "m7"});
        CHECK_HEAD(head, source, mirror);
        InsertRows(source, NUM_ITEMS - 1, {"k0", "k1", "k2"});
        CHECK_HEAD(head, source, mirror);

        source.removeRows(0, 1);
        CHECK_HEAD(head, source, mirror);
        source.removeRows(2, 7);
        CHECK_HEAD(head, source, mirror);
        removed.clear();
        source.removeRows(NUM_ITEMS, 2);
        QCOMPARE(removed.count(), 0);
        CHECK_HEAD(head, source, mirror);

        changed.clear();
        source.setData(source.index(1, 1), QStringLiteral("changed"));
        QCOMPARE(changed.count(), 1);
        source.setData(source.index(NUM_ITEMS, 0), QStringLiteral("unseen"));
        QCOMPARE(changed.count(), 1);
        CHECK_HEAD(head, source, mirror);

        QPersistentModelIndex kept{head.index(3, 1)};
        const QVariant kept_data{kept.data()};
        source.removeRows(0, 2);
        QCOMPARE(kept.row(), 1);
        QCOMPARE(kept.data(), kept_data);
        CHECK_HEAD(head, source, mirror);
        InsertRows(source, 0, {"p0", "p1", "p2", "p3"});
        QVERIFY(!kept.isValid());
        CHECK_HEAD(head, source, mirror);

        source.removeRows(0, source.rowCount() - 2);
        CHECK_HEAD(head, source, mirror);
        source.insertColumn(1);
        CHECK_HEAD(head, source, mirror);
        source.clear();
        CHECK_HEAD(head, source, mirror);
        source.setColumnCount(2);
        for (int i = 0; i < 8; ++i) AppendRow(source, QStringLiteral("r%1").arg(i));
        CHECK_HEAD(head, source, mirror);
    }

    // A sorted, filtered proxy like the overview's: re-sorts, filter changes
    // and resets of the proxy under the head.
    {
        QStandardItemModel items{0, 2};
        for (int i = 10; i < 90; i += 10) AppendRow(items, QStringLiteral("k%1").arg(i));
        QSortFilterProxyModel sorted;
        sorted.setSourceModel(&items);
        sorted.setDynamicSortFilter(true);
        sorted.sort(0, Qt::AscendingOrder);
        HeadProxyModel head{NUM_ITEMS};
        head.setSourceModel(&sorted);
        QAbstractItemModelTester tester{&head, QAbstractItemModelTester::FailureReportingMode::QtTest};
        ModelMirror mirror{head};
        CHECK_HEAD(head, sorted, mirror);

        // A row from beyond the head sorts first.
        const QPersistentModelIndex second{head.index(1, 0)};
        items.setData(sorted.mapToSource(sorted.index(7, 0)), QStringLiteral("a00"));
        QCOMPARE(head.index(0, 0).data().toString(), QStringLiteral("a00"));
        QCOMPARE(second.row(), 2);
        CHECK_HEAD(head, sorted, mirror);

        // The first row sorts last and leaves the head.
        const QPersistentModelIndex first{head.index(0, 1)};
        items.setData(sorted.mapToSource(sorted.index(0, 0)), QStringLiteral("zzz"));
        QVERIFY(!first.isValid());
        QCOMPARE(second.row(), 1);
        CHECK_HEAD(head, sorted, mirror);

        sorted.setFilterFixedString(QStringLiteral("k"));
        CHECK_HEAD(head, sorted, mirror);
        sorted.setFilterFixedString(QString{});
        CHECK_HEAD(head, sorted, mirror);
        sorted.invalidate();
        CHECK_HEAD(head, sorted, mirror);
        sorted.sort(0, Qt::DescendingOrder);
        CHECK_HEAD(head, sorted, mirror);

        AppendRow(items, QStringLiteral("zzzz"));
        CHECK_HEAD(head, sorted, mirror);
        items.removeRows(sorted.mapToSource(sorted.index(1, 0)).row(), 1);
        CHECK_HEAD(head, sorted, mirror);

        sorted.setSourceModel(nullptr);
        CHECK_HEAD(head, sorted, mirror);
        sorted.setSourceModel(&items);
        CHECK_HEAD(head, sorted, mirror);
    }

    // A layout change that changes the number of rows: a filter changed
    // before an invalidate().
    {
        QStandardItemModel items{0, 2};
        for (int i = 1; i <= 8; ++i) AppendRow(items, QStringLiteral("k%1").arg(i));
        MinimumFilter filtered;
        filtered.setSourceModel(&items);
        HeadProxyModel head{NUM_ITEMS};
        head.setSourceModel(&filtered);
        QAbstractItemModelTester tester{&head, QAbstractItemModelTester::FailureReportingMode::QtTest};
        ModelMirror mirror{head};
        CHECK_HEAD(head, filtered, mirror);

        QSignalSpy source_layout{&filtered, &QAbstractItemModel::layoutChanged};
        const QPersistentModelIndex first{head.index(0, 0)};
        const QPersistentModelIndex last{head.index(NUM_ITEMS - 1, 1)};
        filtered.minimum = 5;
        filtered.invalidate();
        QCOMPARE(source_layout.count(), 1);
        QCOMPARE(head.rowCount(), 4);
        QVERIFY(!first.isValid());
        QCOMPARE(last.row(), 0);
        CHECK_HEAD(head, filtered, mirror);
        filtered.minimum = 8;
        filtered.invalidate();
        CHECK_HEAD(head, filtered, mirror);
        filtered.minimum = 0;
        filtered.invalidate();
        QCOMPARE(head.rowCount(), NUM_ITEMS);
        QVERIFY(!last.isValid());
        CHECK_HEAD(head, filtered, mirror);
    }

    // Moves inside, into, out of and beyond the head.
    {
        QStringListModel source{{"a", "b", "c", "d", "e", "f", "g", "h", "i"}};
        HeadProxyModel head{NUM_ITEMS};
        head.setSourceModel(&source);
        QAbstractItemModelTester tester{&head, QAbstractItemModelTester::FailureReportingMode::QtTest};
        ModelMirror mirror{head};
        CHECK_HEAD(head, source, mirror);

        const QPersistentModelIndex b{head.index(1, 0)};
        QVERIFY(source.moveRows({}, 6, 1, {}, 0));
        QCOMPARE(b.row(), 2);
        CHECK_HEAD(head, source, mirror);
        QVERIFY(source.moveRows({}, 0, 2, {}, source.rowCount()));
        QCOMPARE(b.row(), 0);
        CHECK_HEAD(head, source, mirror);
        QVERIFY(source.moveRows({}, 1, 1, {}, 4));
        CHECK_HEAD(head, source, mirror);
        QSignalSpy layout{&head, &QAbstractItemModel::layoutChanged};
        QVERIFY(source.moveRows({}, 6, 1, {}, 8));
        QCOMPARE(layout.count(), 0);
        CHECK_HEAD(head, source, mirror);
        QVERIFY(source.moveRows({}, 0, 1, {}, 7));
        QVERIFY(!b.isValid());
        CHECK_HEAD(head, source, mirror);

        source.setStringList({"x", "y"});
        CHECK_HEAD(head, source, mirror);
    }

    // A source that goes away leaves the head empty.
    {
        HeadProxyModel head{NUM_ITEMS};
        auto source{std::make_unique<QStringListModel>(QStringList{"a", "b"})};
        head.setSourceModel(source.get());
        QAbstractItemModelTester tester{&head, QAbstractItemModelTester::FailureReportingMode::QtTest};
        QCOMPARE(head.rowCount(), 2);
        source.reset();
        QCOMPARE(head.rowCount(), 0);
        QVERIFY(!head.index(0, 0).isValid());
        QVERIFY(!head.sourceModel());
    }
}

void OverviewPageTests::headProxyModelBoundedWork()
{
    QStringList names;
    for (int i = 0; i < 20000; ++i) names.append(QStringLiteral("row%1").arg(i, 6, 10, QLatin1Char('0')));
    QStringListModel source{names};
    CountingProxy counting;
    counting.setSourceModel(&source);
    HeadProxyModel head{NUM_ITEMS};
    head.setSourceModel(&counting);
    QListView view;
    view.setModel(&head);
    view.setCurrentIndex(head.index(2, 0));
    QCOMPARE(head.rowCount(), NUM_ITEMS);

    // Each change of the long source costs the head a few calls into it, not
    // one per source row.
    constexpr int MAX_CALLS{4 * NUM_ITEMS};
    counting.calls = 0;
    QVERIFY(source.insertRows(0, 1));
    source.setData(source.index(0, 0), QStringLiteral("first"));
    QVERIFY2(counting.calls <= MAX_CALLS, qPrintable(QString::number(counting.calls)));
    counting.calls = 0;
    QVERIFY(source.removeRows(1, 1));
    QVERIFY2(counting.calls <= MAX_CALLS, qPrintable(QString::number(counting.calls)));
    counting.calls = 0;
    QVERIFY(source.moveRows({}, 19000, 1, {}, 0));
    QVERIFY2(counting.calls <= MAX_CALLS, qPrintable(QString::number(counting.calls)));
    counting.calls = 0;
    source.sort(0, Qt::DescendingOrder);
    QVERIFY2(counting.calls <= MAX_CALLS, qPrintable(QString::number(counting.calls)));
    QCOMPARE(FirstRows(head, NUM_ITEMS), FirstRows(source, NUM_ITEMS));
    QCOMPARE(head.rowCount(), NUM_ITEMS);
    // The head keeps no persistent index per source row either.
    QVERIFY(ChainPersistentIndexes(&head) <= 2 * NUM_ITEMS);
}

void OverviewPageTests::recentTransactionsTests()
{
    OverviewEnvironment env{m_node};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    std::vector<Txid> tx(16);
    for (uint32_t n = 1; n <= 3; ++n) tx[n] = AddTx(*state, n, 100 * n, n);
    auto model{env.makeModel(state)};
    TransactionTableModel& table{*model->getTransactionTableModel()};

    OverviewPage overview{env.platform_style.get()};
    overview.setClientModel(env.client_model.get());
    overview.setWalletModel(model.get());
    overview.resize(640, 480);
    QListView* const recent{overview.findChild<QListView*>("listTransactions")};
    QVERIFY(recent);
    QAbstractItemModelTester tester{recent->model(), QAbstractItemModelTester::FailureReportingMode::QtTest};
    QSortFilterProxyModel* const sorted{SortedHistory(*recent)};
    QVERIFY(sorted);
    overview.grab();

    // Fewer rows than the list holds, then exactly as many.
    CHECK_RECENT(*recent, table, (std::vector{tx[3], tx[2], tx[1]}));
    for (uint32_t n = 4; n <= 5; ++n) {
        tx[n] = AddTx(*state, n, 100 * n, n);
        NotifyTx(*state, tx[n], CT_NEW);
    }
    CHECK_RECENT(*recent, table, (std::vector{tx[5], tx[4], tx[3], tx[2], tx[1]}));
    // Lay out and paint the page as a shown window does.
    overview.show();
    const auto settle{[&overview] {
        for (int i = 0; i < 3; ++i) {
            QCoreApplication::sendPostedEvents(nullptr, QEvent::LayoutRequest);
            overview.grab();
        }
    }};
    settle();
    const int row_height{recent->sizeHintForIndex(recent->model()->index(0, TransactionTableModel::ToAddress)).height()};
    QCOMPARE(recent->sizeHint().height(), NUM_ITEMS * row_height);
    const int full_height{recent->height()};
    std::vector<QRect> full_rects;
    for (int row = 0; row < NUM_ITEMS; ++row) full_rects.push_back(recent->visualRect(recent->model()->index(row, TransactionTableModel::ToAddress)));

    // Older transactions than the ones shown do not change the list or where
    // its rows are. The list asks for one row's height more for each, as it
    // did when it held them as hidden rows, and grows into the free space.
    for (uint32_t n = 6; n <= 8; ++n) {
        tx[n] = AddTx(*state, n, 10 * (n - 5), n);
        NotifyTx(*state, tx[n], CT_NEW);
    }
    QCOMPARE(table.rowCount({}), 8);
    CHECK_RECENT(*recent, table, (std::vector{tx[5], tx[4], tx[3], tx[2], tx[1]}));
    settle();
    QCOMPARE(recent->sizeHint().height(), 8 * row_height);
    QVERIFY2(recent->height() > full_height, qPrintable(QStringLiteral("%1 %2").arg(recent->height()).arg(full_height)));
    for (int row = 0; row < NUM_ITEMS; ++row) {
        // The width follows what the delegate last painted; the rows stay
        // where they were.
        const QRect rect{recent->visualRect(recent->model()->index(row, TransactionTableModel::ToAddress))};
        QCOMPARE(rect.top(), full_rects.at(row).top());
        QCOMPARE(rect.height(), full_rects.at(row).height());
    }

    // A new transaction sorts first and pushes the oldest shown one out.
    tx[9] = AddTx(*state, 9, 1000, UNCONFIRMED);
    NotifyTx(*state, tx[9], CT_NEW);
    CHECK_RECENT(*recent, table, (std::vector{tx[9], tx[5], tx[4], tx[3], tx[2]}));

    // A shown transaction becomes conflicted and leaves the filter at the
    // next status refresh; the next one slides in.
    SetTxHeight(*state, tx[4], CONFLICTED);
    NotifyTx(*state, tx[4], CT_UPDATED);
    table.updateConfirmations();
    CHECK_RECENT(*recent, table, (std::vector{tx[9], tx[5], tx[3], tx[2], tx[1]}));

    // A shown transaction is removed from the wallet.
    RemoveTx(*state, tx[5]);
    NotifyTx(*state, tx[5], CT_DELETED);
    CHECK_RECENT(*recent, table, (std::vector{tx[9], tx[3], tx[2], tx[1], tx[8]}));

    // Re-sorts: transactions received in the same second sort by the height
    // of their block, unconfirmed ones first. A block is disconnected and the
    // oldest of them, beyond the list, becomes unconfirmed and sorts first;
    // then it confirms again in a later block and sorts among the others.
    tx[10] = AddTx(*state, 10, 2000, 40);
    NotifyTx(*state, tx[10], CT_NEW);
    for (uint32_t n = 11; n <= 15; ++n) {
        tx[n] = AddTx(*state, n, 2000, 50 + 2 * (n - 11));
        NotifyTx(*state, tx[n], CT_NEW);
    }
    CHECK_RECENT(*recent, table, (std::vector{tx[15], tx[14], tx[13], tx[12], tx[11]}));
    SetTxHeight(*state, tx[10], UNCONFIRMED);
    RefreshRow(table, *state, tx[10]);
    if (QTest::currentTestFailed()) return;
    CHECK_RECENT(*recent, table, (std::vector{tx[10], tx[15], tx[14], tx[13], tx[12]}));
    SetTxHeight(*state, tx[10], 55);
    RefreshRow(table, *state, tx[10]);
    if (QTest::currentTestFailed()) return;
    CHECK_RECENT(*recent, table, (std::vector{tx[15], tx[14], tx[10], tx[13], tx[12]}));
    sorted->invalidate();
    CHECK_RECENT(*recent, table, (std::vector{tx[15], tx[14], tx[10], tx[13], tx[12]}));
    const std::vector shown{tx[15], tx[14], tx[10], tx[13], tx[12]};

    // A display unit change repaints the same rows.
    QSignalSpy changed{recent->model(), &QAbstractItemModel::dataChanged};
    env.options_model->setDisplayUnit(QVariant::fromValue(QbitUnit::mQBT));
    QVERIFY(changed.count() >= 1);
    CHECK_RECENT(*recent, table, shown);
    env.options_model->setDisplayUnit(QVariant::fromValue(QbitUnit::QBT));
    CHECK_RECENT(*recent, table, shown);

    // Privacy mode hides the list and shows it again with the same rows.
    overview.setPrivacy(true);
    QVERIFY(recent->isHidden());
    CHECK_RECENT(*recent, table, shown);
    overview.setPrivacy(false);
    QVERIFY(!recent->isHidden());
    CHECK_RECENT(*recent, table, shown);

    // Resets of the history under the list, to an empty history with the
    // same columns and back. (A reset to a model without columns would move
    // the list to column 0, with or without the head proxy.)
    QStandardItemModel empty{0, table.columnCount({})};
    sorted->setSourceModel(&empty);
    QCOMPARE(recent->model()->rowCount(), 0);
    sorted->setSourceModel(&table);
    QCOMPARE(recent->modelColumn(), int{TransactionTableModel::ToAddress});
    CHECK_RECENT(*recent, table, shown);

    // Clicking the k-th row opens the k-th transaction shown.
    settle();
    QSignalSpy clicked{&overview, &OverviewPage::transactionClicked};
    for (int k = 0; k < NUM_ITEMS; ++k) {
        // The k-th row the list shows.
        int row{-1};
        for (int seen = -1; seen < k && row + 1 < recent->model()->rowCount();) {
            if (!recent->isRowHidden(++row)) ++seen;
        }
        const QRect rect{recent->visualRect(recent->model()->index(row, TransactionTableModel::ToAddress))};
        QVERIFY(recent->viewport()->rect().contains(rect.center()));
        QTest::mouseClick(recent->viewport(), Qt::LeftButton, {}, rect.center());
        QCOMPARE(clicked.count(), k + 1);
        const QModelIndex source{qvariant_cast<QModelIndex>(clicked.at(k).at(0))};
        QCOMPARE(source.model(), &table);
        QCOMPARE(source.column(), int{TransactionTableModel::ToAddress});
        QCOMPARE(source.data(TransactionTableModel::TxHashRole).toString(), Hash(shown.at(k)));
    }
    overview.hide();
}

void OverviewPageTests::recentTransactionsLongHistory()
{
    // A long history, such as a watch-only wallet that receives a coinbase
    // in most blocks.
    constexpr uint32_t HISTORY{20000};
    OverviewEnvironment env{m_node};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    std::vector<Txid> tx(HISTORY + 1);
    for (uint32_t n = 1; n <= HISTORY; ++n) tx[n] = AddTx(*state, n, 10 * n, n);
    auto model{env.makeModel(state)};
    TransactionTableModel& table{*model->getTransactionTableModel()};
    QCOMPARE(table.rowCount({}), int{HISTORY});

    OverviewPage overview{env.platform_style.get()};
    overview.setClientModel(env.client_model.get());
    overview.setWalletModel(model.get());
    overview.resize(640, 480);
    QListView* const recent{overview.findChild<QListView*>("listTransactions")};
    QVERIFY(recent);
    overview.grab();

    // The list's model has only the rows shown, and neither the list nor
    // the models under it keep state for each row of the history, which
    // they would have to update on every change of the history.
    const auto check_bounded{[&] {
        const qsizetype persistent{ChainPersistentIndexes(recent->model())};
        qInfo() << "recent transactions: model rows" << recent->model()->rowCount() << "persistent indexes" << persistent;
        QVERIFY2(recent->model()->rowCount() <= NUM_ITEMS, qPrintable(QString::number(recent->model()->rowCount())));
        QVERIFY2(persistent <= 2 * NUM_ITEMS, qPrintable(QString::number(persistent)));
        for (int row = 0; row < recent->model()->rowCount(); ++row) QVERIFY(!recent->isRowHidden(row));
    }};
    QCOMPARE(VisibleTransactions(*recent), Hashes({tx[HISTORY], tx[HISTORY - 1], tx[HISTORY - 2], tx[HISTORY - 3], tx[HISTORY - 4]}));
    // The list asks for the height of the whole history, as it did when it
    // held it with all but the first rows hidden.
    const int row_height{recent->sizeHintForIndex(recent->model()->index(0, TransactionTableModel::ToAddress)).height()};
    QCOMPARE(recent->sizeHint().height(), int{HISTORY} * row_height);
    check_bounded();
    if (QTest::currentTestFailed()) return;

    // What the list is told about a change concerns its own rows only.
    QSignalSpy inserted{recent->model(), &QAbstractItemModel::rowsInserted};
    QSignalSpy removed{recent->model(), &QAbstractItemModel::rowsRemoved};
    QSignalSpy changed{recent->model(), &QAbstractItemModel::dataChanged};
    QSignalSpy layout{recent->model(), &QAbstractItemModel::layoutChanged};
    const auto check_rows{[&](const QSignalSpy& spy) {
        for (const QList<QVariant>& args : spy) {
            QVERIFY(args.at(1).toInt() < NUM_ITEMS);
            QVERIFY(args.at(2).toInt() < NUM_ITEMS);
        }
    }};

    // A new transaction.
    const Txid newest{AddTx(*state, HISTORY + 1, 10 * (HISTORY + 1), UNCONFIRMED)};
    NotifyTx(*state, newest, CT_NEW);
    QCOMPARE(table.rowCount({}), int{HISTORY} + 1);
    QCOMPARE(VisibleTransactions(*recent), Hashes({newest, tx[HISTORY], tx[HISTORY - 1], tx[HISTORY - 2], tx[HISTORY - 3]}));
    QCOMPARE(inserted.count(), 1);
    QCOMPARE(removed.count(), 1);
    check_rows(inserted);
    check_rows(removed);
    QCOMPARE(layout.count(), 0);
    check_bounded();
    if (QTest::currentTestFailed()) return;

    // An old one, far below the list, does not reach it.
    inserted.clear();
    removed.clear();
    const Txid old{AddTx(*state, HISTORY + 2, 5, 1)};
    NotifyTx(*state, old, CT_NEW);
    QCOMPARE(table.rowCount({}), int{HISTORY} + 2);
    QCOMPARE(inserted.count(), 0);
    QCOMPARE(removed.count(), 0);

    // A status refresh for every row of the history repaints the list's.
    changed.clear();
    table.updateConfirmations();
    QVERIFY(changed.count() >= 1);
    for (const QList<QVariant>& args : changed) {
        QVERIFY(qvariant_cast<QModelIndex>(args.at(1)).row() < NUM_ITEMS);
    }
    QCOMPARE(VisibleTransactions(*recent), Hashes({newest, tx[HISTORY], tx[HISTORY - 1], tx[HISTORY - 2], tx[HISTORY - 3]}));
    check_bounded();
}
