// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/pokertests.h>

#include <qt/poker/bot.h>
#include <qt/poker/cards.h>
#include <qt/poker/game.h>
#include <qt/poker/handeval.h>
#include <qt/pokerlobby.h>
#include <qt/pokertable.h>
#include <random.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <QCheckBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QTreeWidget>

using poker::Action;
using poker::Card;
using poker::Chips;
using poker::EventType;
using poker::HandCategory;
using poker::Phase;
using poker::Table;

namespace {
std::vector<Card> Cards(std::string_view text)
{
    return Assert(poker::ParseCards(text)).value();
}

poker::HandValue Eval(std::string_view text)
{
    return poker::EvaluateHand(Cards(text));
}

/** A full deck that deals `first` (in order) before the remaining cards. */
std::vector<Card> Deck(std::string_view first)
{
    std::vector<Card> deck{Cards(first)};
    std::array<bool, poker::DECK_SIZE> used{};
    for (const Card card : deck) used[card] = true;
    for (int card{0}; card < poker::DECK_SIZE; ++card) {
        if (!used[card]) deck.push_back(static_cast<Card>(card));
    }
    return deck;
}

/** A table whose first hand puts the button on seat 0. A zero stack leaves the seat empty. */
Table MakeTable(Chips small_blind, Chips big_blind, const std::vector<Chips>& stacks)
{
    Table table{{.num_seats = static_cast<int>(stacks.size()), .small_blind = small_blind, .big_blind = big_blind}};
    for (size_t i{0}; i < stacks.size(); ++i) {
        if (stacks[i] > 0) Assert(table.SitDown(static_cast<int>(i), std::string{"P"} + static_cast<char>('0' + i), stacks[i]));
    }
    Assert(table.SetButton(table.NumSeats() - 1));
    return table;
}

void Act(Table& table, int seat, const Action& action)
{
    std::string error;
    QVERIFY2(table.Act(seat, action, &error), error.c_str());
}

void RunOut(Table& table)
{
    while (table.GetPhase() == Phase::DEALING || table.GetPhase() == Phase::SHOWDOWN) {
        QVERIFY(table.Advance());
    }
}

int CountEvents(const Table& table, EventType type)
{
    return static_cast<int>(std::ranges::count_if(table.Events(), [type](const poker::Event& e) { return e.type == type; }));
}

void CheckInvariants(const Table& table, Chips expected_total)
{
    QCOMPARE(table.TotalChips(), expected_total);
    for (int i{0}; i < table.NumSeats(); ++i) {
        const poker::Seat& seat{table.GetSeat(i)};
        QVERIFY(seat.stack >= 0);
        QVERIFY(seat.street_bet >= 0);
        QVERIFY(seat.street_bet <= seat.total_bet);
        if (!seat.occupied) QCOMPARE(seat.stack, Chips{0});
    }
    if (table.GetPhase() == Phase::IDLE) return;
    static constexpr std::array<size_t, 4> BOARD_SIZE{0, 3, 4, 5};
    QCOMPARE(table.Board().size(), BOARD_SIZE[static_cast<int>(table.GetStreet())]);
    Chips in_pots{0};
    for (const poker::Pot& pot : table.BuildPots()) {
        QVERIFY(!pot.eligible.empty());
        in_pots += pot.amount;
    }
    QCOMPARE(in_pots, table.PotTotal());
    if (table.GetPhase() == Phase::BETTING) {
        QVERIFY(table.ToAct().has_value());
        QVERIFY(table.GetSeat(*table.ToAct()).CanAct());
    }
}
} // namespace

void PokerTests::cardText()
{
    for (int card{0}; card < poker::DECK_SIZE; ++card) {
        const auto text{poker::CardToString(static_cast<Card>(card))};
        QCOMPARE(poker::ParseCard(text), std::optional<Card>{static_cast<Card>(card)});
    }
    QCOMPARE(poker::CardToString(poker::MakeCard(poker::RANK_ACE, poker::SPADES)), std::string{"As"});
    QCOMPARE(poker::ParseCard("td"), std::optional<Card>{poker::MakeCard(poker::RANK_TEN, poker::DIAMONDS)});
    QVERIFY(!poker::ParseCard("1s"));
    QVERIFY(!poker::ParseCard("Ax"));
    QVERIFY(!poker::ParseCard("A"));
    QVERIFY(!poker::ParseCards("As As"));
    QVERIFY(!poker::ParseCards("As Kd7h"));
    QCOMPARE(Cards("  As  Kd ").size(), size_t{2});
}

void PokerTests::handRanking()
{
    // Strictly increasing strength.
    const std::vector<std::string_view> ladder{
        "7c 5d 4h 3s 2c", // lowest possible hand
        "Ac Kd Qh Js 9c",
        "2c 2d 3h 4s 5c",
        "Ac Ad Kh Qs Tc",
        "Ac Ad Kh Qs Jc",
        "2c 2d 3h 3s 4c",
        "Ac Ad Kh Ks Qc",
        "2c 2d 2h 3s 4c",
        "Ac 2d 3h 4s 5c", // wheel: the lowest straight
        "2c 3d 4h 5s 6c",
        "Tc Jd Qh Ks Ac",
        "2c 3c 4c 5c 7c",
        "Ac Kc Qc Jc 9c",
        "2c 2d 2h 3s 3c",
        "Ac Ad Ah Ks Kc",
        "2c 2d 2h 2s 3c",
        "Ac Ad Ah As Kc",
        "Ac 2c 3c 4c 5c", // steel wheel
        "9c Tc Jc Qc Kc",
        "Tc Jc Qc Kc Ac", // royal flush
    };
    for (size_t i{1}; i < ladder.size(); ++i) {
        QVERIFY2(Eval(ladder[i - 1]) < Eval(ladder[i]), std::string{ladder[i]}.c_str());
    }
    QCOMPARE(Eval("Ac Kd Qh Js 9c"), Eval("Ad Kc Qs Jh 9d"));
    QCOMPARE(Eval("Ac Ad Kh Ks 2c 2d 7h"), Eval("Ah As Kc Kd 7s"));

    // Seven-card hands.
    QCOMPARE(poker::CategoryOf(Eval("2c 3d Ah Kh Qh Jh Th")), HandCategory::STRAIGHT_FLUSH);
    QCOMPARE(Eval("Ac Ad Ah Kc Kd Ks 2c"), Eval("Ac Ad Ah Kc Kd"));
    QCOMPARE(Eval("Ac Ad Kc Kd Qc Qd 2s"), Eval("Ac Ad Kc Kd Qs"));
    QCOMPARE(Eval("As 2s 3s 4s 5h 6h 7h"), Eval("3c 4d 5h 6s 7c"));
    QCOMPARE(poker::CategoryOf(Eval("4h 5h 6h 7h 9h 8c Tc")), HandCategory::FLUSH);
    QCOMPARE(poker::CategoryOf(Eval("Ac Ad Ah As Kc Kd Kh")), HandCategory::FOUR_OF_A_KIND);
    QCOMPARE(poker::DecidingRanks(Eval("Ac Ad Ah As Kc Kd Kh")), (std::vector<int>{12, 11}));
    QCOMPARE(poker::DecidingRanks(Eval("Ac 2d 3h 4s 5c 9d Jh")), (std::vector<int>{3}));
    QCOMPARE(poker::DecidingRanks(Eval("9c 9d 4h 4s Kc 2d 3h")), (std::vector<int>{7, 2, 11}));
}

void PokerTests::handCensus()
{
    // Every five-card hand: the textbook count per category, and exactly 7462 distinct strengths.
    std::array<int, 9> counts{};
    std::vector<bool> seen(size_t{9} << 20);
    int distinct{0};
    std::array<Card, 5> hand{};
    for (int a{0}; a < 52; ++a) {
        for (int b{a + 1}; b < 52; ++b) {
            for (int c{b + 1}; c < 52; ++c) {
                for (int d{c + 1}; d < 52; ++d) {
                    for (int e{d + 1}; e < 52; ++e) {
                        hand = {Card(a), Card(b), Card(c), Card(d), Card(e)};
                        const poker::HandValue value{poker::EvaluateHand(hand)};
                        ++counts[static_cast<int>(poker::CategoryOf(value))];
                        if (!seen[value]) {
                            seen[value] = true;
                            ++distinct;
                        }
                    }
                }
            }
        }
    }
    const std::array<int, 9> expected{1302540, 1098240, 123552, 54912, 10200, 5108, 3744, 624, 40};
    QCOMPARE(counts, expected);
    QCOMPARE(distinct, 7462);
}

void PokerTests::sevenCardHands()
{
    // The seven-card evaluator must equal the best of the 21 five-card subsets.
    FastRandomContext rng{/*fDeterministic=*/true};
    for (int i{0}; i < 20000; ++i) {
        const std::vector<Card> deck{poker::ShuffledDeck(rng)};
        const std::span<const Card> seven{deck.data(), 7};
        poker::HandValue best{0};
        for (unsigned mask{0}; mask < (1U << 7); ++mask) {
            if (std::popcount(mask) != 5) continue;
            std::array<Card, 5> five{};
            int k{0};
            for (unsigned j{0}; j < 7; ++j) {
                if (mask & (1U << j)) five[k++] = seven[j];
            }
            best = std::max(best, poker::EvaluateHand(five));
        }
        QCOMPARE(poker::EvaluateHand(seven), best);
        QCOMPARE(poker::EvaluateHand(poker::BestFiveCards(seven)), best);
    }
}

void PokerTests::headsUpHand()
{
    Table table{MakeTable(1, 2, {100, 100})};
    // Heads-up the button posts the small blind and acts first before the flop.
    // Deal order starts left of the button: seat 1, seat 0, seat 1, seat 0.
    QVERIFY(table.StartHand(Deck("Kc As Kd Ah 2c 7h 8d 9s 2d Jc 2h 3s")));
    QCOMPARE(table.Button(), 0);
    QCOMPARE(table.SmallBlindSeat(), 0);
    QCOMPARE(table.BigBlindSeat(), 1);
    QCOMPARE(table.ToAct(), std::optional<int>{0});
    QCOMPARE(table.PotTotal(), Chips{3});
    QCOMPARE(table.Legal().call_amount, Chips{1});
    QCOMPARE(table.Legal().min_raise_to, Chips{4});
    Act(table, 0, Action::Call());
    // The big blind keeps its option.
    QCOMPARE(table.ToAct(), std::optional<int>{1});
    QVERIFY(table.Legal().can_check);
    QVERIFY(table.Legal().can_raise);
    Act(table, 1, Action::Check());
    QCOMPARE(table.GetPhase(), Phase::DEALING);
    QVERIFY(table.Advance());
    QCOMPARE(table.Board(), Cards("7h 8d 9s"));
    // After the flop the big blind acts first.
    QCOMPARE(table.ToAct(), std::optional<int>{1});
    QCOMPARE(table.Legal().min_raise_to, Chips{2});
    Act(table, 1, Action::RaiseTo(4));
    Act(table, 0, Action::Call());
    QVERIFY(table.Advance());
    Act(table, 1, Action::Check());
    Act(table, 0, Action::Check());
    QVERIFY(table.Advance());
    QCOMPARE(table.Board(), Cards("7h 8d 9s Jc 3s"));
    Act(table, 1, Action::Check());
    Act(table, 0, Action::Check());
    QCOMPARE(table.GetPhase(), Phase::SHOWDOWN);
    QVERIFY(table.Advance());
    QCOMPARE(table.GetPhase(), Phase::IDLE);
    // Aces beat kings.
    QCOMPARE(table.GetSeat(0).stack, Chips{106});
    QCOMPARE(table.GetSeat(1).stack, Chips{94});
    QCOMPARE(CountEvents(table, EventType::SHOW), 2);
    QCOMPARE(table.Events().back().type, EventType::WIN);
    QCOMPARE(table.Events().back().seat, 0);

    // The button moves to seat 1 for the next hand.
    QVERIFY(table.StartHand(Deck("")));
    QCOMPARE(table.Button(), 1);
    QCOMPARE(table.ToAct(), std::optional<int>{1});
}

void PokerTests::minimumRaise()
{
    Table table{MakeTable(1, 2, {1000, 1000, 1000})};
    QVERIFY(table.StartHand(Deck("")));
    // Three-handed: button 0, small blind 1, big blind 2; the button acts first.
    QCOMPARE(table.ToAct(), std::optional<int>{0});
    QCOMPARE(table.Legal().min_raise_to, Chips{4});
    QCOMPARE(table.Legal().max_raise_to, Chips{1000});
    Act(table, 0, Action::RaiseTo(10));
    // The next raise must be at least the last raise (8) on top.
    QCOMPARE(table.Legal().min_raise_to, Chips{18});
    const uint64_t version{table.Version()};
    std::string error;
    QVERIFY(!table.Act(1, Action::RaiseTo(17), &error));
    QVERIFY(!table.Act(1, Action::RaiseTo(1001), &error));
    QCOMPARE(table.Version(), version);
    Act(table, 1, Action::RaiseTo(18));
    QCOMPARE(table.Legal().min_raise_to, Chips{26});
    Act(table, 2, Action::Fold());
    Act(table, 0, Action::Call());
    QCOMPARE(table.GetPhase(), Phase::DEALING);
    QCOMPARE(table.PotTotal(), Chips{38});
}

void PokerTests::shortAllInRaise()
{
    // Four-handed: button 0, small blind 1, big blind 2, first to act 3.
    {
        Table table{MakeTable(1, 2, {1000, 14, 1000, 1000})};
        QVERIFY(table.StartHand(Deck("")));
        Act(table, 3, Action::RaiseTo(10));
        Act(table, 0, Action::Call());
        // An all-in for 14 is a raise of only 4, less than the full raise of 8.
        QCOMPARE(table.Legal().max_raise_to, Chips{14});
        Act(table, 1, Action::RaiseTo(14));
        Act(table, 2, Action::Fold());
        // Seats that already acted may only call or fold.
        QCOMPARE(table.ToAct(), std::optional<int>{3});
        QVERIFY(!table.Legal().can_raise);
        QCOMPARE(table.Legal().call_amount, Chips{4});
        std::string error;
        QVERIFY(!table.Act(3, Action::RaiseTo(30), &error));
        Act(table, 3, Action::Call());
        QVERIFY(!table.Legal().can_raise);
        Act(table, 0, Action::Call());
        QCOMPARE(table.GetPhase(), Phase::DEALING);
    }
    {
        // Two short all-ins that together make a full raise reopen the betting.
        Table table{MakeTable(1, 2, {1000, 14, 18, 1000})};
        QVERIFY(table.StartHand(Deck("")));
        Act(table, 3, Action::RaiseTo(10));
        Act(table, 0, Action::Call());
        Act(table, 1, Action::RaiseTo(14));
        Act(table, 2, Action::RaiseTo(18));
        QCOMPARE(table.ToAct(), std::optional<int>{3});
        QVERIFY(table.Legal().can_raise);
        QCOMPARE(table.Legal().min_raise_to, Chips{26});
        Act(table, 3, Action::RaiseTo(26));
        Act(table, 0, Action::Fold());
        QCOMPARE(table.GetPhase(), Phase::DEALING);
        // Seat 3's raise to 26 was not called by anyone who could: 8 chips come back.
        QCOMPARE(CountEvents(table, EventType::UNCALLED), 1);
        QCOMPARE(table.GetSeat(3).stack, Chips{1000 - 18});
    }
}

void PokerTests::sidePots()
{
    // Button 0, small blind 1, big blind 2, first to act 3. Deal order: 1, 2, 3, 0, 1, 2, 3, 0.
    Table table{MakeTable(1, 2, {50, 100, 200, 300})};
    QVERIFY(table.StartHand(Deck("Ks Qs 7c As Kh Qh 2d Ah 5d 3c 8d 9s 6h Jh 6d 4c")));
    Act(table, 3, Action::RaiseTo(300));
    Act(table, 0, Action::Call());
    Act(table, 1, Action::Call());
    Act(table, 2, Action::Call());
    // Nobody matched the last 100 of seat 3's bet.
    QCOMPARE(CountEvents(table, EventType::UNCALLED), 1);
    QCOMPARE(table.GetSeat(3).stack, Chips{100});
    const std::vector<poker::Pot> pots{table.BuildPots()};
    QCOMPARE(pots.size(), size_t{3});
    QCOMPARE(pots[0].amount, Chips{200});
    QCOMPARE(pots[0].eligible, (std::vector<int>{0, 1, 2, 3}));
    QCOMPARE(pots[1].amount, Chips{150});
    QCOMPARE(pots[1].eligible, (std::vector<int>{1, 2, 3}));
    QCOMPARE(pots[2].amount, Chips{200});
    QCOMPARE(pots[2].eligible, (std::vector<int>{2, 3}));
    RunOut(table);
    QCOMPARE(table.Board(), Cards("3c 8d 9s Jh 4c"));
    // Aces win the main pot, kings the first side pot and queens the second.
    QCOMPARE(table.GetSeat(0).stack, Chips{200});
    QCOMPARE(table.GetSeat(1).stack, Chips{150});
    QCOMPARE(table.GetSeat(2).stack, Chips{200});
    QCOMPARE(table.GetSeat(3).stack, Chips{100});
    QCOMPARE(table.TotalChips(), Chips{650});
}

void PokerTests::splitPotOddChip()
{
    // Button 0, small blind 1, big blind 2. Deal order: 1, 2, 0, 1, 2, 0. The board is a straight.
    Table table{MakeTable(1, 2, {100, 100, 100})};
    QVERIFY(table.StartHand(Deck("6s 4h 2c 7s 5c 3d 8c As Kd Qh 9c Jc 9d Ts")));
    Act(table, 0, Action::Call());
    Act(table, 1, Action::Fold());
    Act(table, 2, Action::Check());
    while (table.GetPhase() != Phase::IDLE) {
        if (table.GetPhase() == Phase::BETTING) {
            Act(table, *table.ToAct(), Action::Check());
        } else {
            QVERIFY(table.Advance());
        }
    }
    // A pot of 5 splits 3/2; the odd chip goes to the first winner left of the button (seat 2).
    QCOMPARE(table.GetSeat(0).stack, Chips{100});
    QCOMPARE(table.GetSeat(1).stack, Chips{99});
    QCOMPARE(table.GetSeat(2).stack, Chips{101});
}

void PokerTests::walkAndShortBlinds()
{
    {
        // Everyone folds to the big blind, whose uncalled blind comes back.
        Table table{MakeTable(1, 2, {100, 100, 100})};
        QVERIFY(table.StartHand(Deck("")));
        Act(table, 0, Action::Fold());
        Act(table, 1, Action::Fold());
        QCOMPARE(table.GetPhase(), Phase::IDLE);
        QCOMPARE(table.GetSeat(2).stack, Chips{101});
        QCOMPARE(CountEvents(table, EventType::UNCALLED), 1);
        QCOMPARE(CountEvents(table, EventType::SHOW), 0);
    }
    {
        // Heads-up with a big blind of one chip: nobody can bet, so the board runs out at once.
        Table table{MakeTable(1, 2, {100, 1})};
        QVERIFY(table.StartHand(Deck("")));
        QCOMPARE(table.GetSeat(1).stack, Chips{0});
        QCOMPARE(table.GetPhase(), Phase::DEALING);
        RunOut(table);
        QCOMPARE(table.GetPhase(), Phase::IDLE);
        QCOMPARE(table.TotalChips(), Chips{101});
        QCOMPARE(table.Board().size(), size_t{5});
    }
    {
        // A short big blind still leaves the full big blind as the price to call.
        Table table{MakeTable(5, 10, {1000, 1000, 4})};
        QVERIFY(table.StartHand(Deck("")));
        QCOMPARE(table.ToAct(), std::optional<int>{0});
        QCOMPARE(table.Legal().call_amount, Chips{10});
        QCOMPARE(table.Legal().min_raise_to, Chips{20});
        Act(table, 0, Action::Call());
        Act(table, 1, Action::Call());
        QCOMPARE(table.GetPhase(), Phase::DEALING);
        const std::vector<poker::Pot> pots{table.BuildPots()};
        QCOMPARE(pots.size(), size_t{2});
        QCOMPARE(pots[0].amount, Chips{12});
        QCOMPARE(pots[1].amount, Chips{12});
    }
}

void PokerTests::illegalActions()
{
    // Out-of-range settings are clamped.
    const Table tiny{{.num_seats = 0, .small_blind = 5, .big_blind = 0}};
    QCOMPARE(tiny.NumSeats(), 2);
    QCOMPARE(tiny.Config().big_blind, Chips{1});
    QCOMPARE(tiny.Config().small_blind, Chips{1});
    const Table huge{{.num_seats = 99, .small_blind = 0, .big_blind = 4}};
    QCOMPARE(huge.NumSeats(), Table::MAX_SEATS);
    QCOMPARE(huge.Config().small_blind, Chips{1});

    Table table{MakeTable(1, 2, {100, 100, 100})};
    std::string error;
    QVERIFY(!table.Act(0, Action::Fold(), &error));
    QVERIFY(!table.Advance());
    QVERIFY(!table.SitDown(0, "again", 100));
    QVERIFY(!table.SitDown(5, "nowhere", 100));
    QVERIFY(!table.AddChips(1, 0));
    QVERIFY(!table.AddChips(1, poker::MAX_STACK));
    QVERIFY(!table.StartHand(std::vector<Card>(52, Card{0})));
    QVERIFY(!table.StartHand(Cards("As Kd")));
    QVERIFY(table.StartHand(Deck("")));
    const uint64_t version{table.Version()};
    QVERIFY(!table.Act(1, Action::Fold(), &error));
    QVERIFY(!table.Act(0, Action::Check(), &error));
    QVERIFY(!table.Act(0, Action::RaiseTo(3), &error));
    QVERIFY(!table.Act(0, Action::RaiseTo(-5), &error));
    QVERIFY(!table.Act(0, Action{static_cast<poker::ActionType>(42), 0}, &error));
    QVERIFY(!table.Advance());
    QVERIFY(!table.SitDown(0, "mid-hand", 10));
    QVERIFY(!table.StandUp(0));
    QVERIFY(!table.AddChips(0, 10));
    QVERIFY(!table.SetButton(1));
    QCOMPARE(table.Version(), version);
    Act(table, 0, Action::Call());
    Act(table, 1, Action::Call());
    QVERIFY(!table.Act(2, Action::Call(), &error));
}

void PokerTests::equityEstimates()
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const auto equity{[&](std::string_view hole, std::string_view board, int opponents, double range = 1.0) {
        const std::vector<Card> cards{Cards(hole)};
        return poker::EstimateEquity({cards[0], cards[1]}, Cards(board), opponents, 4000, rng, range);
    }};
    // Known heads-up preflop equities: aces about 85%, seven-deuce offsuit about 35%.
    QVERIFY(std::abs(equity("As Ah", "", 1) - 0.85) < 0.03);
    QVERIFY(std::abs(equity("7c 2d", "", 1) - 0.35) < 0.03);
    // The nuts on the river always wins; a counterfeited hand against a board straight always splits.
    QCOMPARE(equity("Ah Kh", "Qh Jh Th 2c 3d", 3), 1.0);
    QCOMPARE(equity("2c 3d", "As Kd Qh Jc Ts", 1), 0.5);
    // Against only the best starting hands, kings run into aces and seven-deuce wins far less.
    QVERIFY(equity("Ks Kh", "", 1, 0.05) < equity("Ks Kh", "", 1) - 0.1);
    QVERIFY(equity("7c 2d", "", 1, 0.10) < 0.30);
}

void PokerTests::chenScores()
{
    const auto chen{[](std::string_view hand) {
        const std::vector<Card> cards{Cards(hand)};
        return poker::ChenScore(cards[0], cards[1]);
    }};
    QCOMPARE(chen("As Ah"), 20);
    QCOMPARE(chen("Ks Kh"), 16);
    QCOMPARE(chen("As Ks"), 12);
    QCOMPARE(chen("As Kd"), 10);
    QCOMPARE(chen("Js Ts"), 9);
    QCOMPARE(chen("5s 4s"), 6);
    QCOMPARE(chen("Ah 5d"), 5);
    QCOMPARE(chen("2s 2h"), 5);
    QCOMPARE(chen("7c 2d"), -1);
    // The share table matches a count over all 1326 starting hands.
    std::array<int, 22> at_score{};
    for (int a{0}; a < poker::DECK_SIZE; ++a) {
        for (int b{a + 1}; b < poker::DECK_SIZE; ++b) ++at_score[poker::ChenScore(Card(a), Card(b)) + 1];
    }
    int at_least{0};
    for (int score{20}; score >= -1; --score) {
        at_least += at_score[score + 1];
        QVERIFY(std::abs(poker::ShareScoringAtLeast(score) - at_least / 1326.0) < 0.0001);
    }
}

void PokerTests::botStyles()
{
    // Computer players should play a believable share of hands, raise as well as call, follow their
    // style, and open up heads-up.
    FastRandomContext rng{/*fDeterministic=*/true};
    const std::array<poker::BotStyle, 3> styles{{{0.15, 0.25, 0.02}, {0.5, 0.5, 0.08}, {0.85, 0.9, 0.25}}};
    for (const int seats : {6, 2}) {
        Table table{{.num_seats = seats, .small_blind = 1, .big_blind = 2}};
        for (int seat{0}; seat < seats; ++seat) QVERIFY(table.SitDown(seat, "P", 200));
        std::array<int, 3> dealt{};
        std::array<int, 3> voluntary{};
        std::array<int, 3> raised{};
        for (int hand{0}; hand < 600; ++hand) {
            for (int seat{0}; seat < seats; ++seat) {
                if (table.GetSeat(seat).stack == 0) QVERIFY(table.AddChips(seat, 200));
            }
            QVERIFY(table.StartHand(rng));
            std::array<bool, Table::MAX_SEATS> played{};
            std::array<bool, Table::MAX_SEATS> raised_this_hand{};
            while (table.GetPhase() != Phase::IDLE) {
                if (table.GetPhase() != Phase::BETTING) {
                    QVERIFY(table.Advance());
                    continue;
                }
                const int seat{*table.ToAct()};
                const Action action{poker::ChooseAction(table, seat, styles[seat % 3], rng)};
                if (table.GetStreet() == poker::Street::PREFLOP) {
                    played[seat] = played[seat] || action.type == poker::ActionType::CALL || action.type == poker::ActionType::RAISE;
                    raised_this_hand[seat] = raised_this_hand[seat] || action.type == poker::ActionType::RAISE;
                }
                QVERIFY(table.Act(seat, action));
            }
            for (int seat{0}; seat < seats; ++seat) {
                ++dealt[seat % 3];
                voluntary[seat % 3] += played[seat];
                raised[seat % 3] += raised_this_hand[seat];
            }
        }
        for (int style{0}; style < std::min(seats, 3); ++style) {
            const double vpip{double(voluntary[style]) / dealt[style]};
            const double pfr{double(raised[style]) / dealt[style]};
            QVERIFY2(vpip > (seats == 2 ? 0.3 : 0.08) && vpip < 0.75, qPrintable(QStringLiteral("seats %1 style %2 VPIP %3").arg(seats).arg(style).arg(vpip)));
            QVERIFY2(pfr > 0.04, qPrintable(QStringLiteral("seats %1 style %2 PFR %3").arg(seats).arg(style).arg(pfr)));
        }
        if (seats == 6) QVERIFY(voluntary[0] < voluntary[2]);
    }
}

void PokerTests::preActions()
{
    // Button 0, small blind 1, big blind 2. The big blind picks an action while seat 0 is to act.
    Table table{MakeTable(1, 2, {100, 100, 100})};
    QVERIFY(table.StartHand(Deck("")));
    const PreActionContext chosen{table.HandNumber(), table.GetStreet(), table.CurrentBet()};
    QVERIFY(!ResolvePreAction(PreAction::CALL_ANY, chosen, table, 2)); // Not its turn yet.
    Act(table, 0, Action::Call());
    Act(table, 1, Action::Call());
    // The bet did not change: CALL checks the option, RAISE makes the minimum raise, FOLD checks for free.
    QCOMPARE(ResolvePreAction(PreAction::CALL, chosen, table, 2)->type, poker::ActionType::CHECK);
    QCOMPARE(ResolvePreAction(PreAction::RAISE, chosen, table, 2)->raise_to, Chips{4});
    QCOMPARE(ResolvePreAction(PreAction::FOLD, chosen, table, 2)->type, poker::ActionType::CHECK);
    QVERIFY(!ResolvePreAction(PreAction::NONE, chosen, table, 2));
    Act(table, 2, Action::Check());
    QVERIFY(table.Advance());
    // Picked on an earlier street: stale even though the bet level matches.
    const PreActionContext earlier_street{table.HandNumber(), poker::Street::PREFLOP, 0};
    QCOMPARE(table.ToAct(), std::optional<int>{1});
    QVERIFY(!ResolvePreAction(PreAction::CALL, earlier_street, table, 1));

    // Someone raises before our turn: CALL and RAISE no longer apply, the ANY versions still act.
    Table raised{MakeTable(1, 2, {100, 100, 100})};
    QVERIFY(raised.StartHand(Deck("")));
    const PreActionContext before{raised.HandNumber(), raised.GetStreet(), raised.CurrentBet()};
    Act(raised, 0, Action::RaiseTo(10));
    Act(raised, 1, Action::Fold());
    QCOMPARE(raised.ToAct(), std::optional<int>{2});
    QVERIFY(!ResolvePreAction(PreAction::CALL, before, raised, 2));
    QVERIFY(!ResolvePreAction(PreAction::RAISE, before, raised, 2));
    QCOMPARE(ResolvePreAction(PreAction::CALL_ANY, before, raised, 2)->type, poker::ActionType::CALL);
    QCOMPARE(ResolvePreAction(PreAction::RAISE_ANY, before, raised, 2)->raise_to, Chips{18});
    QCOMPARE(ResolvePreAction(PreAction::FOLD, before, raised, 2)->type, poker::ActionType::FOLD);
}

void PokerTests::randomTables()
{
    // Random tables, stacks and actions (including illegal ones), with bots in half the seats.
    // A hand must always finish, conserve chips and never accept an illegal action.
    FastRandomContext rng{/*fDeterministic=*/true};
    const poker::BotStyle style{};
    for (int round{0}; round < 25; ++round) {
        const int num_seats{2 + static_cast<int>(rng.randrange(9))};
        const Chips big_blind{rng.randbool() ? 2 : 10};
        Table table{{.num_seats = num_seats, .small_blind = big_blind / 2, .big_blind = big_blind}};
        for (int seat{0}; seat < num_seats; ++seat) {
            if (seat >= 2 && rng.randrange(5) == 0) continue;
            QVERIFY(table.SitDown(seat, "P", 1 + static_cast<Chips>(rng.randrange(40 * big_blind))));
        }
        QVERIFY(table.SetButton(static_cast<int>(rng.randrange(num_seats))));
        Chips total{table.TotalChips()};
        for (int hand{0}; hand < 40; ++hand) {
            for (int seat{0}; seat < num_seats; ++seat) {
                if (table.GetSeat(seat).occupied && table.GetSeat(seat).stack == 0) {
                    const Chips rebuy{1 + static_cast<Chips>(rng.randrange(40 * big_blind))};
                    QVERIFY(table.AddChips(seat, rebuy));
                    total += rebuy;
                }
            }
            QVERIFY(table.StartHand(rng));
            int steps{0};
            while (table.GetPhase() != Phase::IDLE) {
                QVERIFY(++steps < 1000);
                CheckInvariants(table, total);
                if (table.GetPhase() != Phase::BETTING) {
                    QVERIFY(table.Advance());
                    continue;
                }
                const int seat{*table.ToAct()};
                const poker::LegalActions legal{table.Legal()};
                if (seat % 2 == 0) {
                    const Action action{poker::ChooseAction(table, seat, style, rng)};
                    std::string error;
                    QVERIFY2(table.Act(seat, action, &error), error.c_str());
                    continue;
                }
                const auto type{static_cast<poker::ActionType>(rng.randrange(4))};
                const Chips raise_to{legal.min_raise_to - 1 + static_cast<Chips>(rng.randrange(legal.max_raise_to - legal.min_raise_to + 3))};
                const uint64_t version{table.Version()};
                const bool allowed{(type == poker::ActionType::FOLD) ||
                                   (type == poker::ActionType::CHECK && legal.can_check) ||
                                   (type == poker::ActionType::CALL && legal.can_call) ||
                                   (type == poker::ActionType::RAISE && legal.can_raise && raise_to >= legal.min_raise_to && raise_to <= legal.max_raise_to)};
                QCOMPARE(table.Act(seat, Action{type, raise_to}), allowed);
                if (!allowed) {
                    QCOMPARE(table.Version(), version);
                    QVERIFY(table.Act(seat, legal.can_check ? Action::Check() : Action::Call()));
                }
            }
            CheckInvariants(table, total);
        }
    }
}

void PokerTests::tableWindow()
{
    // A whole table driven through its widgets at full speed: our clicks, an action picked in advance,
    // sitting out while the computer players continue, and closing mid-hand.
    QPointer<PokerTableWindow> window{new PokerTableWindow({.name = QStringLiteral("Test"), .seats = 6, .small_blind = 1, .big_blind = 2, .buy_in = 100000})};
    window->setPace(0, 0, 0);
    window->show();
    auto* fold{window->findChild<QPushButton*>(QStringLiteral("pokerFoldButton"))};
    auto* call{window->findChild<QPushButton*>(QStringLiteral("pokerCallButton"))};
    auto* rebuy{window->findChild<QPushButton*>(QStringLiteral("pokerRebuyButton"))};
    auto* call_any{window->findChild<QCheckBox*>(QStringLiteral("pokerPreCallAny"))};
    auto* sit_out{window->findChild<QCheckBox*>(QStringLiteral("pokerSitOut"))};
    auto* log{window->findChild<QPlainTextEdit*>(QStringLiteral("pokerLog"))};
    QVERIFY(fold && call && rebuy && call_any && sit_out && log);
    const Table& table{window->table()};
    const int hero{window->heroSeat()};
    const auto busted{[&] { return table.GetPhase() == Phase::IDLE && table.GetSeat(hero).stack == 0; }};

    int turns{0};
    while (table.HandNumber() < 8) {
        QTRY_VERIFY_WITH_TIMEOUT(table.ToAct() == hero || busted() || table.HandNumber() >= 8, 20000);
        if (busted()) {
            rebuy->click();
        } else if (table.ToAct() == hero) {
            const uint64_t version{table.Version()};
            (++turns % 3 == 0 ? fold : call)->click();
            QVERIFY(table.Version() != version);
        }
        QVERIFY(!window->grab().isNull());
    }
    QVERIFY(turns > 0);
    QVERIFY(log->toPlainText().contains(QStringLiteral("Hand #8")));

    // "Call any" acts for us when our turn comes, without a click.
    window->setPace(150, 0, 0);
    bool played_ahead{false};
    for (int attempt{0}; attempt < 100 && !played_ahead; ++attempt) {
        QTRY_VERIFY_WITH_TIMEOUT(call_any->isEnabled() || table.ToAct() == hero || busted(), 20000);
        if (busted()) {
            rebuy->click();
            continue;
        }
        if (table.ToAct() == hero) {
            fold->click();
            continue;
        }
        const uint64_t hand{table.HandNumber()};
        const size_t seen{table.Events().size()};
        call_any->click();
        QVERIFY(call_any->isChecked());
        QTRY_VERIFY_WITH_TIMEOUT(!call_any->isChecked(), 20000);
        if (table.HandNumber() != hand) continue;
        for (size_t i{seen}; i < table.Events().size(); ++i) {
            const poker::Event& e{table.Events()[i]};
            played_ahead = played_ahead || (e.seat == hero && (e.type == EventType::CHECK || e.type == EventType::CALL));
        }
    }
    QVERIFY(played_ahead);

    // Deal Me Out: the computer players keep playing without us.
    window->setPace(0, 0, 0);
    sit_out->click();
    QVERIFY(table.GetSeat(hero).sitting_out);
    const uint64_t hands{table.HandNumber()};
    while (table.HandNumber() < hands + 3) {
        QTRY_VERIFY_WITH_TIMEOUT(table.ToAct() == hero || table.HandNumber() >= hands + 3, 20000);
        if (table.ToAct() == hero) fold->click();
    }
    QVERIFY(!table.GetSeat(hero).in_hand);
    QVERIFY(!window->grab().isNull());

    window->close();
    QTRY_VERIFY(window.isNull());

    // The lobby lists the default tables, opens a table and closes it again.
    PokerLobby lobby;
    QCOMPARE(lobby.findChild<QTreeWidget*>(QStringLiteral("pokerTables"))->topLevelItemCount(), 8);
    QPointer<PokerTableWindow> opened{lobby.openTable(PokerLobby::DefaultTables().front())};
    QVERIFY(opened);
    lobby.closeTables();
    QTRY_VERIFY(opened.isNull());
}
