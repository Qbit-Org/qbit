// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_POKER_HANDEVAL_H
#define QBIT_QT_POKER_HANDEVAL_H

#include <qt/poker/cards.h>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace poker {

enum class HandCategory : uint8_t {
    HIGH_CARD,
    PAIR,
    TWO_PAIR,
    THREE_OF_A_KIND,
    STRAIGHT,
    FLUSH,
    FULL_HOUSE,
    FOUR_OF_A_KIND,
    STRAIGHT_FLUSH,
};

/**
 * Strength of the best five-card hand. A larger value beats a smaller one and
 * equal values tie. Layout: category in bits 20-23, then up to five deciding
 * ranks as 4-bit fields from bit 16 down to bit 0.
 */
using HandValue = uint32_t;

/** Evaluate the best five-card hand among 5 to 7 distinct cards. */
HandValue EvaluateHand(std::span<const Card> cards);

HandCategory CategoryOf(HandValue value);

/**
 * The ranks that decide ties within the category, most significant first:
 * one for a straight (its top card; 3 means a five-high wheel), two for four of
 * a kind or a full house, three for trips or two pair, four for a pair and five
 * for a flush or high card.
 */
std::vector<int> DecidingRanks(HandValue value);

/** Five of the given cards (5 to 7) that make the best hand, for display. */
std::array<Card, 5> BestFiveCards(std::span<const Card> cards);

} // namespace poker

#endif // QBIT_QT_POKER_HANDEVAL_H
