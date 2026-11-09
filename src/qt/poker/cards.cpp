// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/poker/cards.h>

#include <random.h>

#include <algorithm>
#include <array>
#include <utility>

namespace poker {
namespace {
constexpr std::string_view RANK_CHARS{"23456789TJQKA"};
constexpr std::string_view SUIT_CHARS{"cdhs"};

char ToLowerAscii(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }
char ToUpperAscii(char c) { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c; }
} // namespace

char RankChar(int rank) { return RANK_CHARS.at(rank); }

char SuitChar(int suit) { return SUIT_CHARS.at(suit); }

std::string CardToString(Card card)
{
    return {RankChar(RankOf(card)), SuitChar(SuitOf(card))};
}

std::optional<Card> ParseCard(std::string_view text)
{
    if (text.size() != 2) return std::nullopt;
    const auto rank{RANK_CHARS.find(ToUpperAscii(text[0]))};
    const auto suit{SUIT_CHARS.find(ToLowerAscii(text[1]))};
    if (rank == std::string_view::npos || suit == std::string_view::npos) return std::nullopt;
    return MakeCard(static_cast<int>(rank), static_cast<int>(suit));
}

std::optional<std::vector<Card>> ParseCards(std::string_view text)
{
    std::vector<Card> cards;
    std::array<bool, DECK_SIZE> seen{};
    size_t pos{0};
    while (pos < text.size()) {
        if (text[pos] == ' ') {
            ++pos;
            continue;
        }
        const size_t end{std::min(text.find(' ', pos), text.size())};
        const auto card{ParseCard(text.substr(pos, end - pos))};
        if (!card || seen[*card]) return std::nullopt;
        seen[*card] = true;
        cards.push_back(*card);
        pos = end;
    }
    return cards;
}

std::vector<Card> ShuffledDeck(FastRandomContext& rng)
{
    std::vector<Card> deck(DECK_SIZE);
    for (int i{0}; i < DECK_SIZE; ++i) deck[i] = static_cast<Card>(i);
    // Fisher-Yates with the node's ChaCha20-based generator. Implemented here rather than with
    // std::shuffle so that a seeded deck is identical on every standard library.
    for (int i{DECK_SIZE - 1}; i > 0; --i) {
        std::swap(deck[i], deck[rng.randrange(i + 1)]);
    }
    return deck;
}

} // namespace poker
