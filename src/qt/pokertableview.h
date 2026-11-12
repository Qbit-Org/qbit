// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_POKERTABLEVIEW_H
#define QBIT_QT_POKERTABLEVIEW_H

#include <qt/poker/game.h>

#include <QSize>
#include <QString>
#include <QWidget>

class QPaintEvent;

/**
 * Draws a poker table: felt, seats, cards, bets, the board, the pot and the
 * result of the last hand. A read-only view of a poker::Table; call update()
 * after the table changes.
 */
class PokerTableView : public QWidget
{
    Q_OBJECT

public:
    PokerTableView(const poker::Table& table, int hero_seat, QWidget* parent = nullptr);

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

    /** Chip count with the locale's digit grouping. */
    static QString chipsText(poker::Chips chips);
    /** Card label such as "A♠" or "10♥". */
    static QString cardText(poker::Card card);
    /** Hand name such as "Full house, kings full of fives". */
    static QString handText(poker::HandValue value);

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    const poker::Table& m_table;
    const int m_hero_seat;
};

#endif // QBIT_QT_POKERTABLEVIEW_H
