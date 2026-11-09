// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_POKERLOBBY_H
#define QBIT_QT_POKERLOBBY_H

#include <qt/pokertable.h>

#include <vector>

#include <QList>
#include <QPointer>
#include <QWidget>

class QTreeWidget;

/**
 * The poker lobby, after CPokerLobbyDialogBase in the original 2009 Bitcoin
 * client: game types on the left, tables on the right, "Open New Table" below.
 */
class PokerLobby : public QWidget
{
    Q_OBJECT

public:
    explicit PokerLobby(QWidget* parent = nullptr);

    /** Open a window for a table. */
    PokerTableWindow* openTable(const PokerTableSpec& spec);
    /** Close every table window opened from this lobby. */
    void closeTables();

    static std::vector<PokerTableSpec> DefaultTables();

private:
    void showTables();
    void joinSelectedTable();
    void openNewTable();
    int selectedSeats() const;

    QTreeWidget* m_games{nullptr};
    QTreeWidget* m_tables{nullptr};
    std::vector<PokerTableSpec> m_specs;
    QList<QPointer<PokerTableWindow>> m_open_tables;
    int m_new_table_count{0};
};

#endif // QBIT_QT_POKERLOBBY_H
