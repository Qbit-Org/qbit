// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pokerlobby.h>

#include <qt/pokertableview.h>

#include <algorithm>
#include <utility>

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPoint>
#include <QPushButton>
#include <QStringList>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

namespace {
constexpr int SEATS_ROLE{Qt::UserRole};
constexpr int SPEC_ROLE{Qt::UserRole + 1};
//! Pixels between cascaded table windows, and how many fit down a diagonal before the next one starts.
constexpr int CASCADE_STEP{30};
constexpr int CASCADE_LENGTH{8};
} // namespace

PokerLobby::PokerLobby(QWidget* parent)
    : QWidget{parent, Qt::Window}, m_specs{DefaultTables()}
{
    setWindowTitle(tr("Poker Lobby"));

    m_games = new QTreeWidget(this);
    m_games->setHeaderHidden(true);
    m_games->setMinimumWidth(130);
    m_games->setMaximumWidth(190);
    auto* holdem{new QTreeWidgetItem(m_games, QStringList{tr("No Limit Hold'em")})};
    holdem->setData(0, SEATS_ROLE, 0);
    for (const auto& [label, seats] : {std::pair{tr("Heads up"), 2}, std::pair{tr("6 max"), 6}, std::pair{tr("Full ring"), 9}}) {
        auto* item{new QTreeWidgetItem(holdem, QStringList{label})};
        item->setData(0, SEATS_ROLE, seats);
    }
    m_games->expandAll();
    m_games->setCurrentItem(holdem);

    m_tables = new QTreeWidget(this);
    m_tables->setObjectName(QStringLiteral("pokerTables"));
    m_tables->setRootIsDecorated(false);
    m_tables->setAlternatingRowColors(true);
    m_tables->setHeaderLabels({tr("Table"), tr("Seats"), tr("Blinds"), tr("Buy-in")});
    m_tables->header()->setSectionResizeMode(0, QHeaderView::Stretch);

    auto* join{new QPushButton(tr("&Join Table"), this)};
    auto* open_new{new QPushButton(tr("&Open New Table"), this)};
    auto* buttons{new QHBoxLayout};
    buttons->addWidget(open_new);
    buttons->addStretch();
    buttons->addWidget(join);

    auto* note{new QLabel(tr("Play money only: chips have no value and cannot be bought, sold or withdrawn, and "
                             "nothing here touches your wallet. Your opponents are computer players. The lobby "
                             "and table follow the poker windows Satoshi Nakamoto drew for the first Bitcoin "
                             "client in 2009 but never finished."),
                          this)};
    note->setWordWrap(true);
    note->setStyleSheet(QStringLiteral("color: palette(mid);"));

    auto* right{new QVBoxLayout};
    right->addWidget(m_tables, /*stretch=*/1);
    right->addLayout(buttons);
    right->addWidget(note);
    auto* layout{new QHBoxLayout(this)};
    layout->addWidget(m_games);
    layout->addLayout(right, /*stretch=*/1);

    connect(m_games, &QTreeWidget::currentItemChanged, this, &PokerLobby::showTables);
    connect(m_tables, &QTreeWidget::itemActivated, this, &PokerLobby::joinSelectedTable);
    connect(join, &QPushButton::clicked, this, &PokerLobby::joinSelectedTable);
    connect(open_new, &QPushButton::clicked, this, &PokerLobby::openNewTable);

    showTables();
    resize(640, 460);
}

std::vector<PokerTableSpec> PokerLobby::DefaultTables()
{
    return {
        {.name = QStringLiteral("Genesis"), .seats = 6, .small_blind = 1, .big_blind = 2, .buy_in = 200},
        {.name = QStringLiteral("Block 170"), .seats = 2, .small_blind = 1, .big_blind = 2, .buy_in = 200},
        {.name = QStringLiteral("Chancellor"), .seats = 9, .small_blind = 1, .big_blind = 2, .buy_in = 200},
        {.name = QStringLiteral("Cypherpunk"), .seats = 6, .small_blind = 5, .big_blind = 10, .buy_in = 1000},
        {.name = QStringLiteral("Pizza Day"), .seats = 9, .small_blind = 5, .big_blind = 10, .buy_in = 1000},
        {.name = QStringLiteral("Timechain"), .seats = 2, .small_blind = 25, .big_blind = 50, .buy_in = 5000},
        {.name = QStringLiteral("Lattice"), .seats = 6, .small_blind = 25, .big_blind = 50, .buy_in = 5000},
        {.name = QStringLiteral("Merkle"), .seats = 9, .small_blind = 25, .big_blind = 50, .buy_in = 5000},
    };
}

int PokerLobby::selectedSeats() const
{
    const QTreeWidgetItem* item{m_games->currentItem()};
    return item ? item->data(0, SEATS_ROLE).toInt() : 0;
}

void PokerLobby::showTables()
{
    const int seats{selectedSeats()};
    m_tables->clear();
    for (size_t i{0}; i < m_specs.size(); ++i) {
        const PokerTableSpec& spec{m_specs[i]};
        if (seats != 0 && spec.seats != seats) continue;
        auto* item{new QTreeWidgetItem(m_tables, QStringList{
                                                     spec.name,
                                                     QString::number(spec.seats),
                                                     tr("%1/%2").arg(PokerTableView::chipsText(spec.small_blind), PokerTableView::chipsText(spec.big_blind)),
                                                     PokerTableView::chipsText(spec.buy_in),
                                                 })};
        item->setData(0, SPEC_ROLE, static_cast<qulonglong>(i));
    }
    if (m_tables->topLevelItemCount() > 0) m_tables->setCurrentItem(m_tables->topLevelItem(0));
}

void PokerLobby::joinSelectedTable()
{
    const QTreeWidgetItem* item{m_tables->currentItem()};
    if (!item) return;
    const auto index{item->data(0, SPEC_ROLE).toULongLong()};
    if (index < m_specs.size()) openTable(m_specs[index]);
}

void PokerLobby::openNewTable()
{
    const int seats{selectedSeats() == 0 ? 6 : selectedSeats()};
    m_specs.push_back({.name = tr("Table %1").arg(++m_new_table_count), .seats = seats, .small_blind = 1, .big_blind = 2, .buy_in = 200});
    showTables();
    openTable(m_specs.back());
}

PokerTableWindow* PokerLobby::openTable(const PokerTableSpec& spec)
{
    // Cascade into the first position no open table holds, so a new window never covers an open one.
    std::erase_if(m_open_tables, [](const OpenTable& open) { return open.window.isNull(); });
    int slot{0};
    while (std::ranges::any_of(m_open_tables, [slot](const OpenTable& open) { return open.slot == slot; })) ++slot;
    auto* window{new PokerTableWindow(spec, this)};
    // Each diagonal of windows starts a little to the right of the last, so windows stay on screen without
    // landing exactly on each other.
    const int along{slot % CASCADE_LENGTH};
    const int diagonal{slot / CASCADE_LENGTH};
    window->move(pos() + QPoint{60 + CASCADE_STEP * along + (CASCADE_STEP / 2) * diagonal, 40 + CASCADE_STEP * along});
    window->show();
    m_open_tables.push_back({window, slot});
    return window;
}

void PokerLobby::closeTables()
{
    for (const OpenTable& open : m_open_tables) {
        if (open.window) open.window->close();
    }
    m_open_tables.clear();
}
