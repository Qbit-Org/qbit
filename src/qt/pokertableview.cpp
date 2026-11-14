// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pokertableview.h>

#include <qt/poker/handeval.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <numbers>
#include <vector>

#include <QBrush>
#include <QChar>
#include <QColor>
#include <QFont>
#include <QFontMetricsF>
#include <QLinearGradient>
#include <QLocale>
#include <QPainter>
#include <QPen>
#include <QPointF>
#include <QRadialGradient>
#include <QRectF>
#include <QStringList>

namespace {
constexpr QRgb GOLD{0xffffca28};
constexpr QRgb WIN_GREEN{0xff66bb6a};
constexpr QRgb RED_SUIT{0xffd32f2f};
constexpr QRgb BLACK_SUIT{0xff212121};

QString RankLabel(int rank)
{
    static constexpr std::array<const char*, poker::NUM_RANKS> LABELS{"2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"};
    return QString::fromLatin1(LABELS.at(rank));
}

QString SuitSymbol(int suit)
{
    // Clubs, diamonds, hearts, spades.
    static constexpr std::array<char16_t, poker::NUM_SUITS> SYMBOLS{u'♣', u'♦', u'♥', u'♠'};
    return QString{QChar{SYMBOLS.at(suit)}};
}

bool IsRed(poker::Card card)
{
    return poker::SuitOf(card) == poker::HEARTS || poker::SuitOf(card) == poker::DIAMONDS;
}

QPointF Normalized(const QPointF& v)
{
    const double length{std::hypot(v.x(), v.y())};
    return length > 0 ? v / length : QPointF{0, -1};
}

QFont SizedFont(const QFont& base, double pixels, bool bold = false)
{
    QFont font{base};
    font.setPixelSize(std::max(7, static_cast<int>(pixels)));
    font.setBold(bold);
    return font;
}

void DrawCard(QPainter& painter, const QRectF& rect, poker::Card card, bool face_up, bool highlight, const QFont& base)
{
    const double radius{rect.width() * 0.12};
    painter.save();
    if (face_up) {
        painter.setPen(highlight ? QPen{QColor{GOLD}, rect.width() * 0.08} : QPen{QColor{0x9e, 0x9e, 0x9e}, 1.0});
        painter.setBrush(QColor{0xfa, 0xfa, 0xfa});
        painter.drawRoundedRect(rect, radius, radius);
        painter.setPen(QColor{IsRed(card) ? RED_SUIT : BLACK_SUIT});
        // Corner index (rank over suit) stays readable when another card covers the right side.
        const double index_width{rect.width() * 0.56};
        painter.setFont(SizedFont(base, rect.height() * 0.27, /*bold=*/true));
        painter.drawText(QRectF{rect.left() + rect.width() * 0.03, rect.top() + rect.height() * 0.02, index_width, rect.height() * 0.3},
                         Qt::AlignHCenter | Qt::AlignTop, RankLabel(poker::RankOf(card)));
        painter.setFont(SizedFont(base, rect.height() * 0.22));
        painter.drawText(QRectF{rect.left() + rect.width() * 0.03, rect.top() + rect.height() * 0.3, index_width, rect.height() * 0.25},
                         Qt::AlignHCenter | Qt::AlignTop, SuitSymbol(poker::SuitOf(card)));
        painter.setFont(SizedFont(base, rect.height() * 0.42));
        painter.drawText(QRectF{rect.left() + rect.width() * 0.3, rect.top() + rect.height() * 0.44, rect.width() * 0.66, rect.height() * 0.54},
                         Qt::AlignCenter, SuitSymbol(poker::SuitOf(card)));
    } else {
        QLinearGradient back{rect.topLeft(), rect.bottomRight()};
        back.setColorAt(0, QColor{0x1e, 0x88, 0xe5});
        back.setColorAt(1, QColor{0x0d, 0x47, 0xa1});
        painter.setPen(QPen{QColor{0xe3, 0xf2, 0xfd}, 1.0});
        painter.setBrush(back);
        painter.drawRoundedRect(rect, radius, radius);
        const double inset{rect.width() * 0.12};
        painter.setPen(QPen{QColor{255, 255, 255, 120}, 1.0});
        painter.setBrush(Qt::NoBrush);
        painter.drawRoundedRect(rect.adjusted(inset, inset, -inset, -inset), radius * 0.6, radius * 0.6);
        painter.setBrush(QBrush{QColor{255, 255, 255, 45}, Qt::DiagCrossPattern});
        painter.setPen(Qt::NoPen);
        painter.drawRoundedRect(rect.adjusted(inset, inset, -inset, -inset), radius * 0.6, radius * 0.6);
    }
    painter.restore();
}

void DrawPill(QPainter& painter, const QPointF& center, const QString& text, const QColor& fill, const QColor& ink, const QFont& font)
{
    const QFontMetricsF metrics{font};
    const double height{metrics.height() * 1.3};
    const double width{metrics.horizontalAdvance(text) + metrics.height()};
    const QRectF rect{center.x() - width / 2, center.y() - height / 2, width, height};
    painter.setPen(Qt::NoPen);
    painter.setBrush(fill);
    painter.drawRoundedRect(rect, height / 2, height / 2);
    painter.setFont(font);
    painter.setPen(ink);
    painter.drawText(rect, Qt::AlignCenter, text);
}

void DrawChipStack(QPainter& painter, const QPointF& center, double radius)
{
    for (int i{1}; i >= 0; --i) {
        const QRectF chip{center.x() - radius, center.y() - radius - i * radius * 0.4, 2 * radius, 2 * radius};
        painter.setPen(QPen{QColor{255, 255, 255, 220}, radius * 0.22, Qt::DotLine});
        painter.setBrush(QColor{0xc6, 0x28, 0x28});
        painter.drawEllipse(chip);
    }
}
} // namespace

PokerTableView::PokerTableView(const poker::Table& table, int hero_seat, QWidget* parent)
    : QWidget{parent}, m_table{table}, m_hero_seat{hero_seat}
{
    setAttribute(Qt::WA_OpaquePaintEvent);
}

QSize PokerTableView::sizeHint() const { return {900, 520}; }

QSize PokerTableView::minimumSizeHint() const { return {620, 380}; }

QString PokerTableView::chipsText(poker::Chips chips)
{
    return QLocale{}.toString(static_cast<qlonglong>(chips));
}

QString PokerTableView::cardText(poker::Card card)
{
    return RankLabel(poker::RankOf(card)) + SuitSymbol(poker::SuitOf(card));
}

QString PokerTableView::handText(poker::HandValue value)
{
    const auto name{[](int rank) {
        const std::array<QString, poker::NUM_RANKS> names{
            tr("two"), tr("three"), tr("four"), tr("five"), tr("six"), tr("seven"), tr("eight"),
            tr("nine"), tr("ten"), tr("jack"), tr("queen"), tr("king"), tr("ace")};
        return names.at(rank);
    }};
    const auto plural{[](int rank) {
        const std::array<QString, poker::NUM_RANKS> names{
            tr("twos"), tr("threes"), tr("fours"), tr("fives"), tr("sixes"), tr("sevens"), tr("eights"),
            tr("nines"), tr("tens"), tr("jacks"), tr("queens"), tr("kings"), tr("aces")};
        return names.at(rank);
    }};
    const std::vector<int> ranks{poker::DecidingRanks(value)};
    if (ranks.empty()) return {};
    switch (poker::CategoryOf(value)) {
    case poker::HandCategory::STRAIGHT_FLUSH:
        return ranks[0] == poker::RANK_ACE ? tr("Royal flush") : tr("Straight flush, %1 high").arg(name(ranks[0]));
    case poker::HandCategory::FOUR_OF_A_KIND:
        return tr("Four of a kind, %1").arg(plural(ranks[0]));
    case poker::HandCategory::FULL_HOUSE:
        return tr("Full house, %1 full of %2").arg(plural(ranks[0]), plural(ranks[1]));
    case poker::HandCategory::FLUSH:
        return tr("Flush, %1 high").arg(name(ranks[0]));
    case poker::HandCategory::STRAIGHT:
        return tr("Straight, %1 high").arg(name(ranks[0]));
    case poker::HandCategory::THREE_OF_A_KIND:
        return tr("Three of a kind, %1").arg(plural(ranks[0]));
    case poker::HandCategory::TWO_PAIR:
        return tr("Two pair, %1 and %2").arg(plural(ranks[0]), plural(ranks[1]));
    case poker::HandCategory::PAIR:
        return tr("Pair of %1").arg(plural(ranks[0]));
    case poker::HandCategory::HIGH_CARD:
        return tr("High card %1").arg(name(ranks[0]));
    }
    return {};
}

void PokerTableView::paintEvent(QPaintEvent*)
{
    QPainter painter{this};
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setRenderHint(QPainter::TextAntialiasing);
    const QFont base{font()};
    const QRectF area{rect()};
    const double s{std::clamp(std::min(area.width() / 900.0, area.height() / 520.0), 0.6, 1.6)};

    QLinearGradient room{area.topLeft(), area.bottomLeft()};
    room.setColorAt(0, QColor{0x1d, 0x24, 0x2b});
    room.setColorAt(1, QColor{0x10, 0x14, 0x18});
    painter.fillRect(area, room);

    // Felt and rim.
    const QPointF center{area.center().x(), area.center().y() - 4 * s};
    const double rx{std::max(120.0, area.width() / 2 - 118 * s)};
    const double ry{std::max(90.0, area.height() / 2 - 74 * s)};
    const double rim_width{14 * s};
    QRadialGradient rim{center, rx + rim_width};
    rim.setColorAt(0.8, QColor{0x5d, 0x40, 0x37});
    rim.setColorAt(1.0, QColor{0x2d, 0x1e, 0x19});
    painter.setPen(Qt::NoPen);
    painter.setBrush(rim);
    painter.drawEllipse(center, rx + rim_width, ry + rim_width);
    QRadialGradient felt{center, rx};
    felt.setColorAt(0, QColor{0x2e, 0x8b, 0x57});
    felt.setColorAt(1, QColor{0x1b, 0x5e, 0x3b});
    painter.setBrush(felt);
    painter.drawEllipse(center, rx, ry);
    painter.setPen(QPen{QColor{255, 255, 255, 35}, 2 * s});
    painter.setBrush(Qt::NoBrush);
    painter.drawEllipse(center, rx - 20 * s, ry - 20 * s);
    painter.setFont(SizedFont(base, 30 * s, /*bold=*/true));
    painter.setPen(QColor{255, 255, 255, 28});
    painter.drawText(QRectF{center.x() - rx, center.y() - ry * 0.78, 2 * rx, ry * 0.4}, Qt::AlignCenter, QStringLiteral("qbit"));

    // What the event log says about each seat: last action on this street, shown hands, winnings.
    struct SeatNote {
        QString action;
        poker::HandValue shown{0};
        poker::Chips won{0};
    };
    std::array<SeatNote, poker::Table::MAX_SEATS> notes{};
    const std::vector<poker::Event>& events{m_table.Events()};
    size_t street_start{0};
    for (size_t i{0}; i < events.size(); ++i) {
        if (events[i].type == poker::EventType::BOARD) street_start = i;
    }
    std::array<bool, poker::DECK_SIZE> highlight{};
    QStringList results;
    for (size_t i{0}; i < events.size(); ++i) {
        const poker::Event& e{events[i]};
        if (e.seat < 0 || e.seat >= poker::Table::MAX_SEATS) continue;
        SeatNote& note{notes[e.seat]};
        const QString amount{chipsText(e.amount)};
        const QString total{chipsText(e.total)};
        const bool this_street{i >= street_start};
        switch (e.type) {
        case poker::EventType::SMALL_BLIND:
            if (this_street) note.action = tr("Small blind");
            break;
        case poker::EventType::BIG_BLIND:
            if (this_street) note.action = tr("Big blind");
            break;
        case poker::EventType::FOLD:
            note.action = tr("Fold");
            break;
        case poker::EventType::CHECK:
            if (this_street) note.action = tr("Check");
            break;
        case poker::EventType::CALL:
            if (this_street) note.action = e.all_in ? tr("All-in") : tr("Call %1").arg(amount);
            break;
        case poker::EventType::BET:
            if (this_street) note.action = e.all_in ? tr("All-in %1").arg(total) : tr("Bet %1").arg(total);
            break;
        case poker::EventType::RAISE:
            if (this_street) note.action = e.all_in ? tr("All-in %1").arg(total) : tr("Raise to %1").arg(total);
            break;
        case poker::EventType::SHOW:
            note.shown = e.value;
            note.action = handText(e.value);
            break;
        case poker::EventType::WIN: {
            note.won += e.amount;
            const poker::Seat& winner{m_table.GetSeat(e.seat)};
            const QString who{e.seat == m_hero_seat ? tr("You") : QString::fromStdString(winner.name)};
            if (e.value != 0) {
                results.append(tr("%1: %2 (%3)").arg(who, chipsText(e.amount), handText(e.value)));
                if (e.pot_index == 0 && m_table.Board().size() == 5) {
                    std::vector<poker::Card> cards{winner.hole[0], winner.hole[1]};
                    cards.insert(cards.end(), m_table.Board().begin(), m_table.Board().end());
                    for (const poker::Card card : poker::BestFiveCards(cards)) highlight[card] = true;
                }
            } else {
                results.append(tr("%1: %2").arg(who, chipsText(e.amount)));
            }
            break;
        }
        case poker::EventType::HAND_START:
        case poker::EventType::UNCALLED:
        case poker::EventType::BOARD:
            break;
        }
    }
    const bool hand_over{m_table.GetPhase() == poker::Phase::IDLE};

    // Board.
    const QSizeF board_card{50 * s, 72 * s};
    const double gap{7 * s};
    const double board_width{5 * board_card.width() + 4 * gap};
    const QPointF board_origin{center.x() - board_width / 2, center.y() - board_card.height() / 2};
    for (int i{0}; i < 5; ++i) {
        const QRectF slot{board_origin.x() + i * (board_card.width() + gap), board_origin.y(), board_card.width(), board_card.height()};
        if (i < static_cast<int>(m_table.Board().size())) {
            const poker::Card card{m_table.Board()[i]};
            DrawCard(painter, slot, card, /*face_up=*/true, hand_over && highlight[card], base);
        } else {
            painter.setPen(QPen{QColor{255, 255, 255, 40}, 1.5 * s, Qt::DashLine});
            painter.setBrush(Qt::NoBrush);
            painter.drawRoundedRect(slot, 6 * s, 6 * s);
        }
    }
    const QFont label_font{SizedFont(base, 14 * s, /*bold=*/true)};
    if (m_table.PotTotal() > 0) {
        DrawPill(painter, QPointF{center.x(), board_origin.y() - 18 * s}, tr("Pot %1").arg(chipsText(m_table.PotTotal())),
                 QColor{0, 0, 0, 110}, Qt::white, label_font);
    }
    if (hand_over && !results.isEmpty()) {
        painter.setFont(label_font);
        painter.setPen(QColor{0xff, 0xf8, 0xe1});
        const QRectF below{center.x() - rx * 0.8, board_origin.y() + board_card.height() + 8 * s, rx * 1.6, ry * 0.5};
        painter.drawText(below, Qt::AlignHCenter | Qt::AlignTop, results.mid(0, 3).join(QLatin1Char('\n')));
    }

    // Seats around the rim, the hero at the bottom and the deal going clockwise.
    const int num_seats{m_table.NumSeats()};
    const QSizeF box{136 * s, 50 * s};
    const QFont name_font{SizedFont(base, 14 * s, /*bold=*/true)};
    const QFont stack_font{SizedFont(base, 13 * s)};
    const QFont pill_font{SizedFont(base, 12 * s, /*bold=*/true)};
    for (int seat_index{0}; seat_index < num_seats; ++seat_index) {
        const double angle{std::numbers::pi / 2 + (seat_index - m_hero_seat) * 2 * std::numbers::pi / num_seats};
        const QPointF pos{center.x() + (rx + 8 * s) * std::cos(angle), center.y() + (ry + 16 * s) * std::sin(angle)};
        const QRectF box_rect{pos.x() - box.width() / 2, pos.y() - box.height() / 2, box.width(), box.height()};
        const poker::Seat& seat{m_table.GetSeat(seat_index)};
        if (!seat.occupied) {
            painter.setOpacity(0.5);
            painter.setPen(QPen{QColor{255, 255, 255, 90}, 1.2 * s, Qt::DashLine});
            painter.setBrush(Qt::NoBrush);
            painter.drawRoundedRect(box_rect, 10 * s, 10 * s);
            painter.setFont(stack_font);
            painter.setPen(QColor{0xb0, 0xbe, 0xc5});
            painter.drawText(box_rect, Qt::AlignCenter, tr("Empty seat"));
            painter.setOpacity(1.0);
            continue;
        }
        const bool hero{seat_index == m_hero_seat};
        const bool to_act{m_table.ToAct() == seat_index};
        const SeatNote& note{notes[seat_index]};
        const bool winner{hand_over && note.won > 0};
        const QPointF toward{Normalized(center - pos)};

        // Hole cards, between the seat and the board.
        const QSizeF card{(hero ? 48 : 36) * s, (hero ? 68 : 50) * s};
        const double pair_width{hero ? 2 * card.width() + 4 * s : card.width() * 1.6};
        const double reach{0.5 * (std::abs(toward.x()) * box.width() + std::abs(toward.y()) * box.height()) +
                           0.5 * (std::abs(toward.x()) * pair_width + std::abs(toward.y()) * card.height()) + 5 * s};
        const QPointF cards_center{pos + toward * reach};
        if (seat.in_hand && (!seat.folded || hero)) {
            const bool face_up{hero || note.shown != 0};
            painter.setOpacity(seat.folded ? 0.35 : 1.0);
            for (int k{0}; k < 2; ++k) {
                const double x{k == 0 ? cards_center.x() - pair_width / 2 : cards_center.x() + pair_width / 2 - card.width()};
                const QRectF card_rect{x, cards_center.y() - card.height() / 2, card.width(), card.height()};
                DrawCard(painter, card_rect, seat.hole[k], face_up, hand_over && face_up && highlight[seat.hole[k]], base);
            }
            painter.setOpacity(1.0);
        }

        // Chips in front of the seat.
        if (seat.street_bet > 0) {
            const double beyond{0.5 * (std::abs(toward.x()) * pair_width + std::abs(toward.y()) * card.height()) + 22 * s};
            const QPointF bet_pos{cards_center + toward * beyond};
            DrawChipStack(painter, bet_pos - QPointF{14 * s, 0}, 8 * s);
            painter.setFont(pill_font);
            painter.setPen(Qt::white);
            painter.drawText(QRectF{bet_pos.x() - 2 * s, bet_pos.y() - 10 * s, 90 * s, 20 * s}, Qt::AlignLeft | Qt::AlignVCenter,
                             chipsText(seat.street_bet));
        }

        // Dealer button beside the cards.
        if (m_table.HandNumber() > 0 && m_table.Button() == seat_index) {
            const QPointF side{-toward.y(), toward.x()};
            const QPointF button_pos{cards_center + side * (pair_width / 2 + 16 * s)};
            painter.setPen(QPen{QColor{0x90, 0x90, 0x90}, 1.0});
            painter.setBrush(QColor{0xfa, 0xfa, 0xfa});
            painter.drawEllipse(button_pos, 11 * s, 11 * s);
            painter.setFont(SizedFont(base, 12 * s, /*bold=*/true));
            painter.setPen(QColor{BLACK_SUIT});
            painter.drawText(QRectF{button_pos.x() - 11 * s, button_pos.y() - 11 * s, 22 * s, 22 * s}, Qt::AlignCenter, tr("D"));
        }

        // The seat itself.
        const bool dimmed{(seat.in_hand && seat.folded) || !seat.in_hand};
        painter.setOpacity(dimmed && !winner ? 0.6 : 1.0);
        QPen border{QColor{255, 255, 255, 60}, 1.2 * s};
        if (to_act) border = QPen{QColor{GOLD}, 3 * s};
        if (winner) border = QPen{QColor{WIN_GREEN}, 3 * s};
        painter.setPen(border);
        painter.setBrush(QColor{0x26, 0x32, 0x38, 235});
        painter.drawRoundedRect(box_rect, 10 * s, 10 * s);
        const QString name{hero ? tr("You") : QString::fromStdString(seat.name)};
        painter.setFont(name_font);
        painter.setPen(Qt::white);
        const QRectF name_rect{box_rect.left() + 6 * s, box_rect.top() + 3 * s, box_rect.width() - 12 * s, box.height() / 2};
        painter.drawText(name_rect, Qt::AlignCenter, QFontMetricsF{name_font}.elidedText(name, Qt::ElideRight, name_rect.width()));
        QString status{chipsText(seat.stack)};
        if (seat.AllIn() && !hand_over) status = tr("All-in");
        if (!seat.in_hand && seat.sitting_out) status = tr("Sitting out");
        if (seat.stack == 0 && (hand_over || !seat.in_hand)) status = tr("Out of chips");
        painter.setFont(stack_font);
        painter.setPen(QColor{0xcf, 0xd8, 0xdc});
        painter.drawText(QRectF{box_rect.left(), box_rect.center().y(), box_rect.width(), box.height() / 2 - 3 * s}, Qt::AlignCenter, status);
        painter.setOpacity(1.0);

        // Last action, or winnings, on the top edge of the seat.
        if (winner) {
            DrawPill(painter, QPointF{pos.x(), box_rect.top()}, tr("+%1").arg(chipsText(note.won)), QColor{WIN_GREEN}, QColor{0x10, 0x20, 0x10}, pill_font);
        } else if (!note.action.isEmpty() && seat.in_hand) {
            const QColor fill{to_act ? QColor{GOLD} : QColor{0x37, 0x47, 0x4f}};
            DrawPill(painter, QPointF{pos.x(), box_rect.top()}, note.action, fill, to_act ? QColor{0x21, 0x21, 0x21} : Qt::white, pill_font);
        }
    }
}
