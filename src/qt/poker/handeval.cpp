// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/poker/handeval.h>

#include <util/check.h>

#include <algorithm>
#include <bit>
#include <initializer_list>

namespace poker {
namespace {
constexpr int CATEGORY_SHIFT{20};
constexpr int FIRST_RANK_SHIFT{16};

/** Deciding ranks of a hand, most significant first. Fixed size so evaluation never allocates. */
struct RankList {
    std::array<int, 5> ranks{};
    int size{0};

    void Add(int rank) { ranks[size++] = rank; }

    /** Add the count highest ranks present in mask. */
    void AddTop(uint16_t mask, int count)
    {
        for (int rank{RANK_ACE}; rank >= 0 && count > 0; --rank) {
            if (mask & (1 << rank)) {
                Add(rank);
                --count;
            }
        }
    }
};

HandValue Pack(HandCategory category, const RankList& list)
{
    HandValue value{static_cast<HandValue>(category) << CATEGORY_SHIFT};
    for (int i{0}; i < list.size; ++i) {
        value |= static_cast<HandValue>(list.ranks[i]) << (FIRST_RANK_SHIFT - 4 * i);
    }
    return value;
}

HandValue Pack(HandCategory category, std::initializer_list<int> ranks)
{
    RankList list;
    for (const int rank : ranks) list.Add(rank);
    return Pack(category, list);
}

constexpr uint16_t Bit(int rank) { return static_cast<uint16_t>(1 << rank); }

/** Top rank of the highest straight in a rank mask (3 for a five-high wheel), or -1 if none. */
int StraightTop(uint16_t mask)
{
    for (int top{RANK_ACE}; top >= 4; --top) {
        const auto window{static_cast<uint16_t>(0x1F << (top - 4))};
        if ((mask & window) == window) return top;
    }
    constexpr uint16_t WHEEL{Bit(RANK_ACE) | 0xF};
    return (mask & WHEEL) == WHEEL ? 3 : -1;
}
} // namespace

HandValue EvaluateHand(std::span<const Card> cards)
{
    // Correct for 5 to 7 cards; other sizes never index out of bounds but may misrank.
    Assume(cards.size() >= 5 && cards.size() <= 7);

    std::array<uint16_t, NUM_SUITS> suit_masks{};
    std::array<uint8_t, NUM_RANKS> counts{};
    uint16_t present{0};
    for (const Card card : cards) {
        suit_masks[SuitOf(card)] |= Bit(RankOf(card));
        present |= Bit(RankOf(card));
        ++counts[RankOf(card)];
    }

    // With at most seven cards only one suit can hold five or more.
    int flush_suit{-1};
    for (int suit{0}; suit < NUM_SUITS; ++suit) {
        if (std::popcount(suit_masks[suit]) >= 5) flush_suit = suit;
    }
    if (flush_suit >= 0) {
        const int top{StraightTop(suit_masks[flush_suit])};
        if (top >= 0) return Pack(HandCategory::STRAIGHT_FLUSH, {top});
    }

    int quads{-1};
    std::array<int, 2> trips{-1, -1};
    std::array<int, 3> pairs{-1, -1, -1};
    int num_trips{0};
    int num_pairs{0};
    for (int rank{RANK_ACE}; rank >= 0; --rank) {
        if (counts[rank] >= 4) {
            if (quads < 0) quads = rank;
        } else if (counts[rank] == 3) {
            if (num_trips < 2) trips[num_trips++] = rank;
        } else if (counts[rank] == 2) {
            if (num_pairs < 3) pairs[num_pairs++] = rank;
        }
    }

    RankList list;
    if (quads >= 0) {
        list.Add(quads);
        list.AddTop(present & ~Bit(quads), 1);
        return Pack(HandCategory::FOUR_OF_A_KIND, list);
    }
    if (num_trips >= 1 && (num_trips >= 2 || num_pairs >= 1)) {
        // The pair part is the higher of a second set of trips or the best pair.
        return Pack(HandCategory::FULL_HOUSE, {trips[0], std::max(trips[1], pairs[0])});
    }
    if (flush_suit >= 0) {
        list.AddTop(suit_masks[flush_suit], 5);
        return Pack(HandCategory::FLUSH, list);
    }
    if (const int top{StraightTop(present)}; top >= 0) {
        return Pack(HandCategory::STRAIGHT, {top});
    }
    if (num_trips == 1) {
        list.Add(trips[0]);
        list.AddTop(present & ~Bit(trips[0]), 2);
        return Pack(HandCategory::THREE_OF_A_KIND, list);
    }
    if (num_pairs >= 2) {
        list.Add(pairs[0]);
        list.Add(pairs[1]);
        list.AddTop(present & ~Bit(pairs[0]) & ~Bit(pairs[1]), 1);
        return Pack(HandCategory::TWO_PAIR, list);
    }
    if (num_pairs == 1) {
        list.Add(pairs[0]);
        list.AddTop(present & ~Bit(pairs[0]), 3);
        return Pack(HandCategory::PAIR, list);
    }
    list.AddTop(present, 5);
    return Pack(HandCategory::HIGH_CARD, list);
}

HandCategory CategoryOf(HandValue value)
{
    return static_cast<HandCategory>(value >> CATEGORY_SHIFT);
}

std::vector<int> DecidingRanks(HandValue value)
{
    // Indexed by HandCategory.
    static constexpr std::array<int, 9> COUNTS{5, 4, 3, 3, 1, 5, 2, 2, 1};
    const auto category{static_cast<size_t>(CategoryOf(value))};
    const int count{category < COUNTS.size() ? COUNTS[category] : 0};
    std::vector<int> ranks;
    ranks.reserve(count);
    for (int i{0}; i < count; ++i) {
        ranks.push_back(static_cast<int>((value >> (FIRST_RANK_SHIFT - 4 * i)) & 0xF));
    }
    return ranks;
}

std::array<Card, 5> BestFiveCards(std::span<const Card> cards)
{
    std::array<Card, 5> five{};
    if (!Assume(cards.size() >= 5 && cards.size() <= 7)) return five;
    const HandValue best{EvaluateHand(cards)};
    const unsigned n{static_cast<unsigned>(cards.size())};
    for (unsigned mask{0}; mask < (1U << n); ++mask) {
        if (std::popcount(mask) != 5) continue;
        int k{0};
        for (unsigned i{0}; i < n; ++i) {
            if (mask & (1U << i)) five[k++] = cards[i];
        }
        if (EvaluateHand(five) == best) return five;
    }
    Assume(false); // Some five-card subset always achieves the best value.
    return five;
}

} // namespace poker
