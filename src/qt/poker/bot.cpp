// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/poker/bot.h>

#include <qt/poker/handeval.h>
#include <random.h>

#include <algorithm>
#include <cmath>
#include <utility>
#include <vector>

namespace poker {
namespace {
//! Simulated deals per decision: about +/-2% equity error, about a millisecond on the GUI thread.
constexpr int EQUITY_ITERATIONS{500};
//! Picks allowed per simulated opponent before falling back to any two cards (a clash is rarely over 30% likely).
constexpr int RANGE_TRIES{24};

//! Share of starting hands whose Chen score is at least s, for s = -1..20 (exact over all 1326 hands).
constexpr std::array<double, 22> CHEN_AT_LEAST{1.0, 0.9638, 0.8824, 0.7888, 0.6712, 0.5173, 0.4329, 0.2549,
                                               0.178, 0.1071, 0.0664, 0.0437, 0.0241, 0.0211, 0.0136, 0.0136,
                                               0.009, 0.009, 0.0045, 0.0045, 0.0045, 0.0045};

double Uniform(FastRandomContext& rng)
{
    return static_cast<double>(rng.randbits(30)) / static_cast<double>(1 << 30);
}

/**
 * Whether a starting hand is among the best `share` of hands. Chen scores are
 * coarse, so a hand on the boundary score qualifies with the probability that
 * makes the overall share exact.
 */
bool InTopShare(int score, double share, FastRandomContext& rng)
{
    const double this_or_better{ShareScoringAtLeast(score)};
    const double better{ShareScoringAtLeast(score + 1)};
    if (this_or_better <= share) return true;
    if (better >= share) return false;
    return Uniform(rng) < (share - better) / (this_or_better - better);
}

/** Facts about the current hand that a player at the table could know. */
struct Situation {
    int opponents{0};     //!< Other seats still contesting the pot.
    int behind{0};        //!< Opponents who have not acted on this street yet.
    int dealt{0};         //!< Seats dealt into the hand.
    int raises{0};        //!< Bets and raises on this street.
    int callers{0};       //!< Calls on this street.
    bool preflop_raiser{false}; //!< This seat made the last raise before the flop.
    bool preflop_raised{false}; //!< Someone raised before the flop.
};

Situation Assess(const Table& table, int seat)
{
    Situation s;
    for (int i{0}; i < table.NumSeats(); ++i) {
        const Seat& other{table.GetSeat(i)};
        if (other.in_hand) ++s.dealt;
        if (i == seat || !other.Contesting()) continue;
        ++s.opponents;
        if (other.CanAct() && !other.acted) ++s.behind;
    }
    int last_preflop_raiser{-1};
    for (const Event& e : table.Events()) {
        const bool aggressive{e.type == EventType::BET || e.type == EventType::RAISE};
        if (e.street == Street::PREFLOP && aggressive) last_preflop_raiser = e.seat;
        if (e.street != table.GetStreet()) continue;
        if (aggressive) ++s.raises;
        if (e.type == EventType::CALL) ++s.callers;
    }
    s.preflop_raised = last_preflop_raiser >= 0;
    s.preflop_raiser = last_preflop_raiser == seat;
    return s;
}
} // namespace

int ChenScore(Card first, Card second)
{
    const int high{std::max(RankOf(first), RankOf(second))};
    const int low{std::min(RankOf(first), RankOf(second))};
    // Ace 10, king 8, queen 7, jack 6, other cards half their face value; computed in half points.
    const auto half_points{[](int rank) { return rank == RANK_ACE ? 20 : rank >= 9 ? 2 * (rank - 9) + 12 : rank + 2; }};
    int score{half_points(high)};
    if (high == low) {
        score = std::max(10, 2 * score);
    } else {
        if (SuitOf(first) == SuitOf(second)) score += 4;
        const int gap{high - low - 1};
        static constexpr std::array<int, 5> GAP_PENALTY{0, 2, 4, 8, 10};
        score -= GAP_PENALTY[std::min(gap, 4)];
        if (gap <= 1 && high < RANK_ACE - 2) score += 2; // Both cards below a queen.
    }
    // Round half points up.
    return score >= 0 ? (score + 1) / 2 : -((-score) / 2);
}

double ShareScoringAtLeast(int score)
{
    if (score <= -1) return 1.0;
    if (score > 20) return 0.0;
    return CHEN_AT_LEAST[score + 1];
}

double EstimateEquity(const std::array<Card, 2>& hole, std::span<const Card> board, int opponents, int iterations,
                      FastRandomContext& rng, double opponent_range)
{
    if (opponents <= 0) return 1.0;
    if (iterations <= 0 || board.size() > 5) return 0.0;

    std::array<bool, DECK_SIZE> known{};
    known[hole[0]] = true;
    known[hole[1]] = true;
    for (const Card card : board) known[card] = true;
    std::vector<Card> unseen;
    unseen.reserve(DECK_SIZE);
    for (int card{0}; card < DECK_SIZE; ++card) {
        if (!known[card]) unseen.push_back(static_cast<Card>(card));
    }
    const size_t missing{5 - board.size()};
    if (missing + 2 * static_cast<size_t>(opponents) > unseen.size()) return 0.0;

    // The starting hands opponents may hold, when they are assumed to play only the best ones.
    std::vector<std::array<Card, 2>> range_hands;
    if (opponent_range < 1.0) {
        for (size_t i{0}; i < unseen.size(); ++i) {
            for (size_t j{i + 1}; j < unseen.size(); ++j) {
                if (InTopShare(ChenScore(unseen[i], unseen[j]), opponent_range, rng)) range_hands.push_back({unseen[i], unseen[j]});
            }
        }
    }

    std::array<Card, 7> mine{};
    mine[0] = hole[0];
    mine[1] = hole[1];
    std::ranges::copy(board, mine.begin() + 2);
    std::array<Card, 7> theirs{};
    std::array<bool, DECK_SIZE> taken{};
    const auto draw_any{[&] {
        // Fewer than half the unseen cards are ever taken in one deal, so this ends quickly.
        while (true) {
            const Card card{unseen[rng.randrange(unseen.size())]};
            if (!taken[card]) {
                taken[card] = true;
                return card;
            }
        }
    }};

    double wins{0};
    for (int iteration{0}; iteration < iterations; ++iteration) {
        taken.fill(false);
        for (size_t i{0}; i < missing; ++i) mine[2 + board.size() + i] = draw_any();
        const HandValue my_value{EvaluateHand(mine)};
        std::copy(mine.begin() + 2, mine.end(), theirs.begin() + 2);
        int ties{0};
        bool lost{false};
        for (int opponent{0}; opponent < opponents && !lost; ++opponent) {
            // A uniform pick among the range hands that do not clash with cards already dealt; after a
            // few clashes in a row, any two cards.
            bool placed{false};
            for (int tries{0}; tries < RANGE_TRIES && !placed && !range_hands.empty(); ++tries) {
                const std::array<Card, 2>& hand{range_hands[rng.randrange(range_hands.size())]};
                if (taken[hand[0]] || taken[hand[1]]) continue;
                taken[hand[0]] = true;
                taken[hand[1]] = true;
                theirs[0] = hand[0];
                theirs[1] = hand[1];
                placed = true;
            }
            if (!placed) {
                theirs[0] = draw_any();
                theirs[1] = draw_any();
            }
            const HandValue value{EvaluateHand(theirs)};
            if (value > my_value) {
                lost = true;
            } else if (value == my_value) {
                ++ties;
            }
        }
        if (!lost) wins += 1.0 / (1 + ties);
    }
    return wins / iterations;
}

Action ChooseAction(const Table& table, int seat, const BotStyle& style, FastRandomContext& rng)
{
    const LegalActions legal{table.LegalFor(seat)};
    if (!legal.can_check && !legal.can_call && !legal.can_raise) return Action::Fold();
    const Action check_or_fold{legal.can_check ? Action::Check() : Action::Fold()};
    const Action check_or_call{legal.can_check ? Action::Check() : Action::Call()};

    const Seat& me{table.GetSeat(seat)};
    const Chips big_blind{table.Config().big_blind};
    const Chips small_blind{table.Config().small_blind};
    const Chips pot{table.PotTotal()};
    const Chips to_call{legal.call_amount};
    const Chips current_bet{table.CurrentBet()};
    const Situation situation{Assess(table, seat)};
    const int opponents{std::max(1, situation.opponents)};
    const double loose{0.6 + 0.8 * style.looseness};
    const double roll{Uniform(rng)};
    //! Share of the stack (including chips already bet this street) that calling would commit.
    const double commitment{static_cast<double>(to_call) / static_cast<double>(std::max<Chips>(1, me.stack + me.street_bet))};

    // Raise to about `target`, made legal. Goes all-in rather than leaving a small stack behind.
    const auto raise_to{[&](double target) {
        if (!legal.can_raise) return check_or_call;
        auto amount{static_cast<Chips>(std::clamp(target, 0.0, static_cast<double>(MAX_STACK)))};
        if (amount > small_blind) amount -= amount % small_blind;
        amount = std::clamp(amount, legal.min_raise_to, legal.max_raise_to);
        if (amount * 10 >= legal.max_raise_to * 6) amount = legal.max_raise_to;
        return Action::RaiseTo(amount);
    }};

    if (table.GetStreet() == Street::PREFLOP) {
        const int score{ChenScore(me.hole[0], me.hole[1])};
        const double bb{static_cast<double>(big_blind)};
        if (situation.raises == 0) {
            // Unopened or limped: open wider the fewer players are left to act.
            const double open_share{situation.dealt == 2 ? 0.8 : 0.62 / std::pow(std::max(1, situation.behind), 0.8)};
            if (InTopShare(score, std::min(0.95, open_share * loose), rng) && roll < 0.75 + 0.25 * style.aggression) {
                return raise_to((2.5 + situation.callers + 0.5 * Uniform(rng)) * bb);
            }
            if (legal.can_check) return Action::Check();
            // Passive players sometimes limp in with hands just outside their raising range.
            if (to_call <= big_blind && InTopShare(score, std::min(0.95, open_share * loose * (1.0 + style.looseness)), rng) &&
                Uniform(rng) < 0.35 + 0.5 * (1.0 - style.aggression)) {
                return Action::Call();
            }
            return Action::Fold();
        }
        // Facing a raise: re-raise the best hands, call with a few more, fold the rest.
        double reraise_share{(0.025 + 0.06 * style.aggression) * loose / situation.raises};
        double call_share{(0.07 + 0.15 * style.looseness) * (situation.dealt == 2 ? 1.8 : 1.0) / situation.raises};
        if (legal.can_check) call_share = 1.0;
        if (to_call <= big_blind) call_share *= 1.5; // A cheap call, for example in the big blind.
        if (commitment > 0.3) {
            reraise_share = std::min(reraise_share, 0.02 + 0.03 * style.aggression);
            call_share = std::min(call_share, 0.03 + 0.05 * style.looseness);
        }
        if (InTopShare(score, reraise_share, rng)) {
            return raise_to((3.0 + situation.callers) * static_cast<double>(current_bet));
        }
        if (InTopShare(score, reraise_share + call_share, rng)) return check_or_call;
        return check_or_fold;
    }

    // After the flop: equity against the hands opponents plausibly hold, normalized per opponent so the
    // same thresholds work heads-up and multiway.
    double range{situation.preflop_raised ? 0.35 : 0.6};
    if (situation.raises >= 1) range *= 0.75;
    if (situation.raises >= 2) range *= 0.6;
    const double equity{EstimateEquity(me.hole, table.Board(), opponents, EQUITY_ITERATIONS, rng, range)};
    const double per_opponent{std::pow(equity, 1.0 / opponents)};
    const double p{static_cast<double>(pot)};

    if (legal.can_check) {
        if (per_opponent >= 0.66 - 0.08 * style.aggression && roll < 0.6 + 0.35 * style.aggression) {
            return raise_to(p * (0.5 + 0.3 * Uniform(rng)));
        }
        // A continuation bet on the flop after raising before it.
        if (table.GetStreet() == Street::FLOP && situation.preflop_raiser && opponents <= 2 &&
            roll < (0.45 + 0.35 * style.aggression) / opponents) {
            return raise_to(p * (0.5 + 0.16 * Uniform(rng)));
        }
        if (per_opponent < 0.45 && roll < style.bluffing * 2.0 / (opponents + 1)) {
            return raise_to(p * 0.5);
        }
        return Action::Check();
    }

    const double pot_odds{static_cast<double>(to_call) / (p + static_cast<double>(to_call))};
    const double margin{0.06 * (1.0 - style.looseness) + 0.03 * std::max(0, situation.raises - 1) + (commitment > 0.5 ? 0.05 : 0.0)};
    if (per_opponent >= 0.82 - 0.06 * style.aggression && roll < 0.35 + 0.45 * style.aggression) {
        return raise_to(2.75 * static_cast<double>(current_bet) + 0.3 * p);
    }
    if (equity >= pot_odds + margin) {
        // With little left behind after calling, put it all in.
        if (legal.can_raise && (me.stack - to_call) * 4 < pot + to_call) return raise_to(static_cast<double>(legal.max_raise_to));
        return Action::Call();
    }
    if (opponents == 1 && legal.can_raise && roll < style.bluffing * 0.3) {
        return raise_to(3.0 * static_cast<double>(current_bet));
    }
    return Action::Fold();
}

} // namespace poker
