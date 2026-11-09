// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_POKER_BOT_H
#define QBIT_QT_POKER_BOT_H

#include <qt/poker/cards.h>
#include <qt/poker/game.h>

#include <array>
#include <span>

class FastRandomContext;

namespace poker {

/** Playing style of a computer player. Every field is in [0, 1]. */
struct BotStyle {
    double looseness{0.5};  //!< 0 plays few starting hands and folds marginal ones; 1 plays many.
    double aggression{0.5}; //!< 0 prefers checking and calling; 1 prefers betting and raising.
    double bluffing{0.08};  //!< How often it bets a weak hand when nobody has bet.
};

/**
 * Bill Chen's starting-hand score, from -1 (seven-deuce offsuit) to 20 (aces).
 * Pairs, high cards, suited and connected cards score higher.
 */
int ChenScore(Card first, Card second);

/** Share of the 1326 starting hands whose Chen score is at least `score`. */
double ShareScoringAtLeast(int score);

/**
 * Chance that `hole` beats `opponents` other hands, given the board so far,
 * over `iterations` random deals of the unseen cards. Ties count as a share of
 * a win. Opponents are assumed to hold starting hands from the best
 * `opponent_range` share by Chen score (1.0 means any two cards).
 */
double EstimateEquity(const std::array<Card, 2>& hole, std::span<const Card> board, int opponents, int iterations,
                      FastRandomContext& rng, double opponent_range = 1.0);

/** Choose an action for `seat`, which must be the seat to act. The result is always legal. */
Action ChooseAction(const Table& table, int seat, const BotStyle& style, FastRandomContext& rng);

} // namespace poker

#endif // QBIT_QT_POKER_BOT_H
