// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_POKER_CARDS_H
#define QBIT_QT_POKER_CARDS_H

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

class FastRandomContext;

namespace poker {

/** A playing card, encoded as rank * 4 + suit (0..51). Rank 0 is a deuce and rank 12 an ace. */
using Card = uint8_t;

inline constexpr int NUM_RANKS{13};
inline constexpr int NUM_SUITS{4};
inline constexpr int DECK_SIZE{52};
inline constexpr int RANK_TEN{8};
inline constexpr int RANK_ACE{12};

/** Suits in the order used by the card encoding. */
enum Suit : int { CLUBS = 0, DIAMONDS = 1, HEARTS = 2, SPADES = 3 };

constexpr Card MakeCard(int rank, int suit) { return static_cast<Card>(rank * NUM_SUITS + suit); }
constexpr int RankOf(Card card) { return card / NUM_SUITS; }
constexpr int SuitOf(Card card) { return card % NUM_SUITS; }

/** '2'..'9', 'T', 'J', 'Q', 'K' or 'A'. */
char RankChar(int rank);
/** 'c', 'd', 'h' or 's'. */
char SuitChar(int suit);
/** Two-character form such as "As" or "Td". */
std::string CardToString(Card card);
/** Parse the two-character form. Accepts upper or lower case. */
std::optional<Card> ParseCard(std::string_view text);
/** Parse space-separated cards such as "As Kd 7h". Fails on malformed or duplicate cards. */
std::optional<std::vector<Card>> ParseCards(std::string_view text);

/** All 52 cards in uniformly random order (Fisher-Yates over rng). */
std::vector<Card> ShuffledDeck(FastRandomContext& rng);

} // namespace poker

#endif // QBIT_QT_POKER_CARDS_H
