// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/poker/game.h>

#include <random.h>
#include <util/check.h>

#include <algorithm>
#include <span>
#include <utility>

namespace poker {
namespace {
bool Eligible(const Seat& seat) { return seat.occupied && !seat.sitting_out && seat.stack > 0; }
} // namespace

Table::Table(const TableConfig& config) : m_config{config}
{
    m_config.num_seats = std::clamp(m_config.num_seats, 2, MAX_SEATS);
    m_config.big_blind = std::clamp<Chips>(m_config.big_blind, 1, MAX_STACK);
    m_config.small_blind = std::clamp<Chips>(m_config.small_blind, 1, m_config.big_blind);
    m_seats.resize(m_config.num_seats);
    m_min_raise = m_config.big_blind;
}

template <typename Pred>
int Table::NextSeatWhere(int from, Pred pred) const
{
    const int n{NumSeats()};
    for (int k{1}; k <= n; ++k) {
        const int seat{((from + k) % n + n) % n};
        if (pred(m_seats[seat])) return seat;
    }
    return -1;
}

bool Table::SitDown(int seat, std::string name, Chips stack)
{
    if (m_phase != Phase::IDLE || !ValidSeat(seat) || m_seats[seat].occupied) return false;
    if (stack <= 0 || stack > MAX_STACK) return false;
    Seat& s{m_seats[seat]};
    s = Seat{};
    s.occupied = true;
    s.name = std::move(name);
    s.stack = stack;
    ++m_version;
    return true;
}

bool Table::StandUp(int seat)
{
    if (m_phase != Phase::IDLE || !ValidSeat(seat) || !m_seats[seat].occupied) return false;
    m_seats[seat] = Seat{};
    ++m_version;
    return true;
}

bool Table::AddChips(int seat, Chips amount)
{
    if (m_phase != Phase::IDLE || !ValidSeat(seat) || !m_seats[seat].occupied) return false;
    if (amount <= 0 || amount > MAX_STACK - m_seats[seat].stack) return false;
    m_seats[seat].stack += amount;
    ++m_version;
    return true;
}

bool Table::SetSittingOut(int seat, bool sitting_out)
{
    if (!ValidSeat(seat) || !m_seats[seat].occupied) return false;
    if (m_seats[seat].sitting_out != sitting_out) {
        m_seats[seat].sitting_out = sitting_out;
        ++m_version;
    }
    return true;
}

bool Table::SetButton(int seat)
{
    if (m_phase != Phase::IDLE || seat < -1 || seat >= NumSeats()) return false;
    m_button = seat;
    ++m_version;
    return true;
}

int Table::EligibleCount() const
{
    return static_cast<int>(std::ranges::count_if(m_seats, Eligible));
}

bool Table::CanStartHand() const
{
    return m_phase == Phase::IDLE && EligibleCount() >= 2;
}

bool Table::StartHand(FastRandomContext& rng)
{
    return StartHand(ShuffledDeck(rng));
}

bool Table::StartHand(const std::vector<Card>& deck)
{
    if (!CanStartHand() || deck.size() != DECK_SIZE) return false;
    std::array<bool, DECK_SIZE> seen{};
    for (const Card card : deck) {
        if (card >= DECK_SIZE || seen[card]) return false;
        seen[card] = true;
    }

    m_deck = deck;
    m_deck_pos = 0;
    m_board.clear();
    m_events.clear();
    int dealt{0};
    for (Seat& s : m_seats) {
        s.in_hand = Eligible(s);
        s.folded = false;
        s.hole = {};
        s.street_bet = 0;
        s.total_bet = 0;
        s.acted = false;
        s.bet_when_acted = 0;
        if (s.in_hand) ++dealt;
    }
    ++m_hand_number;
    ++m_version;

    const auto in_hand{[](const Seat& s) { return s.in_hand; }};
    m_button = NextSeatWhere(m_button, in_hand);
    if (dealt == 2) {
        m_small_blind_seat = m_button;
        m_big_blind_seat = NextSeatWhere(m_button, in_hand);
    } else {
        m_small_blind_seat = NextSeatWhere(m_button, in_hand);
        m_big_blind_seat = NextSeatWhere(m_small_blind_seat, in_hand);
    }
    m_street = Street::PREFLOP;
    m_events.push_back(Event{.type = EventType::HAND_START, .seat = m_button});

    PostBlind(m_small_blind_seat, m_config.small_blind, EventType::SMALL_BLIND);
    PostBlind(m_big_blind_seat, m_config.big_blind, EventType::BIG_BLIND);
    // The full big blind is the price to call even if the big blind was short.
    m_current_bet = m_config.big_blind;
    m_min_raise = m_config.big_blind;

    // Two rounds of one card each, starting left of the button.
    for (int round{0}; round < 2; ++round) {
        int seat{m_button};
        for (int i{0}; i < dealt; ++i) {
            seat = NextSeatWhere(seat, in_hand);
            m_seats[seat].hole[round] = Draw();
        }
    }

    m_phase = Phase::BETTING;
    // The seat after the big blind acts first; heads-up that is the button.
    if (const auto first{NextToAct(m_big_blind_seat)}) {
        m_to_act = *first;
    } else {
        EndBettingRound(); // Blinds put everyone (or all but one) all-in.
    }
    return true;
}

std::optional<int> Table::ToAct() const
{
    if (m_phase != Phase::BETTING) return std::nullopt;
    return m_to_act;
}

bool Table::AnyOtherCanAct(int seat) const
{
    for (int i{0}; i < NumSeats(); ++i) {
        if (i != seat && m_seats[i].CanAct()) return true;
    }
    return false;
}

Chips Table::MaxOtherStreetBet(int seat) const
{
    Chips best{0};
    for (int i{0}; i < NumSeats(); ++i) {
        if (i != seat && m_seats[i].Contesting()) best = std::max(best, m_seats[i].street_bet);
    }
    return best;
}

Chips Table::ToCall(int seat) const
{
    // When nobody else can act, matching more than the largest remaining bet would only be returned as
    // uncalled (this happens after a short all-in big blind), so the price is capped at that bet.
    const Chips target{AnyOtherCanAct(seat) ? m_current_bet : std::min(m_current_bet, MaxOtherStreetBet(seat))};
    return std::max<Chips>(0, target - m_seats[seat].street_bet);
}

bool Table::NeedsToAct(int seat) const
{
    if (!m_seats[seat].CanAct()) return false;
    if (ToCall(seat) > 0) return true;
    // With nothing to call, a seat that has not acted on this street still gets its turn, unless nobody
    // could respond to a bet.
    return !m_seats[seat].acted && AnyOtherCanAct(seat);
}

std::optional<int> Table::NextToAct(int after) const
{
    for (int k{1}; k <= NumSeats(); ++k) {
        const int seat{(after + k) % NumSeats()};
        if (NeedsToAct(seat)) return seat;
    }
    return std::nullopt;
}

LegalActions Table::Legal() const
{
    if (m_phase != Phase::BETTING) return {};
    return LegalFor(m_to_act);
}

LegalActions Table::LegalFor(int seat) const
{
    LegalActions legal;
    if (m_phase != Phase::BETTING || !ValidSeat(seat) || !m_seats[seat].CanAct()) return legal;
    const Seat& s{m_seats[seat]};

    const Chips to_call{ToCall(seat)};
    if (to_call == 0) {
        legal.can_check = true;
    } else {
        legal.can_call = true;
        legal.call_amount = std::min(to_call, s.stack);
    }

    // Raising needs someone who can respond, chips beyond the current bet, and open betting: either this
    // seat has not acted on this street, or the bet has grown by at least a full raise since it did.
    const Chips all_in_total{s.street_bet + s.stack};
    const bool reopened{!s.acted || m_current_bet - s.bet_when_acted >= m_min_raise};
    if (AnyOtherCanAct(seat) && reopened && all_in_total > m_current_bet) {
        legal.can_raise = true;
        legal.max_raise_to = all_in_total;
        legal.min_raise_to = std::min(m_current_bet + m_min_raise, all_in_total);
    }
    return legal;
}

void Table::Commit(int seat, Chips amount)
{
    Seat& s{m_seats[seat]};
    amount = std::clamp<Chips>(amount, 0, s.stack);
    s.stack -= amount;
    s.street_bet += amount;
    s.total_bet += amount;
}

void Table::PostBlind(int seat, Chips amount, EventType type)
{
    const Chips posted{std::min(amount, m_seats[seat].stack)};
    Commit(seat, posted);
    m_events.push_back(Event{
        .type = type,
        .seat = seat,
        .amount = posted,
        .total = posted,
        .all_in = m_seats[seat].stack == 0,
    });
}

Card Table::Draw()
{
    // A hand draws at most 2 * MAX_SEATS hole cards plus 3 burns and 5 board cards, well within 52.
    return m_deck.at(m_deck_pos++);
}

bool Table::Act(int seat, const Action& action, std::string* error)
{
    const auto fail{[error](const char* reason) {
        if (error) *error = reason;
        return false;
    }};
    if (m_phase != Phase::BETTING) return fail("no betting round in progress");
    if (seat != m_to_act) return fail("not this seat's turn");

    const LegalActions legal{LegalFor(seat)};
    Seat& s{m_seats[seat]};
    Event event{.seat = seat, .street = m_street};
    switch (action.type) {
    case ActionType::FOLD:
        s.folded = true;
        event.type = EventType::FOLD;
        break;
    case ActionType::CHECK:
        if (!legal.can_check) return fail("cannot check facing a bet");
        event.type = EventType::CHECK;
        break;
    case ActionType::CALL:
        if (!legal.can_call) return fail("there is nothing to call");
        Commit(seat, legal.call_amount);
        event.type = EventType::CALL;
        event.amount = legal.call_amount;
        event.total = s.street_bet;
        break;
    case ActionType::RAISE: {
        if (!legal.can_raise) return fail("raising is not allowed");
        if (action.raise_to < legal.min_raise_to || action.raise_to > legal.max_raise_to) {
            return fail("raise amount is out of range");
        }
        event.type = m_current_bet == 0 ? EventType::BET : EventType::RAISE;
        event.amount = action.raise_to - s.street_bet;
        event.total = action.raise_to;
        Commit(seat, event.amount);
        // Only a full raise sets a new minimum raise; a short all-in raise leaves it unchanged.
        m_min_raise = std::max(m_min_raise, action.raise_to - m_current_bet);
        m_current_bet = action.raise_to;
        break;
    }
    default:
        return fail("unknown action");
    }
    event.all_in = s.AllIn();
    s.acted = true;
    s.bet_when_acted = m_current_bet;
    m_events.push_back(std::move(event));
    ++m_version;
    AfterAction(seat);
    return true;
}

void Table::AfterAction(int seat)
{
    if (ContestingCount() == 1) {
        ReturnUncalledBet();
        AwardUncontested();
        FinishHand();
        return;
    }
    if (const auto next{NextToAct(seat)}) {
        m_to_act = *next;
        return;
    }
    EndBettingRound();
}

void Table::EndBettingRound()
{
    ReturnUncalledBet();
    for (Seat& s : m_seats) {
        s.street_bet = 0;
        s.acted = false;
        s.bet_when_acted = 0;
    }
    m_current_bet = 0;
    m_min_raise = m_config.big_blind;
    m_to_act = -1;
    m_phase = m_street == Street::RIVER ? Phase::SHOWDOWN : Phase::DEALING;
}

void Table::ReturnUncalledBet()
{
    int top{-1};
    Chips highest{0};
    Chips second{0};
    for (int i{0}; i < NumSeats(); ++i) {
        const Chips bet{m_seats[i].in_hand ? m_seats[i].street_bet : 0};
        if (bet > highest) {
            second = highest;
            highest = bet;
            top = i;
        } else if (bet > second) {
            second = bet;
        }
    }
    if (top < 0 || highest <= second) return;
    const Chips refund{highest - second};
    Seat& s{m_seats[top]};
    s.stack += refund;
    s.street_bet -= refund;
    s.total_bet -= refund;
    m_events.push_back(Event{.type = EventType::UNCALLED, .seat = top, .amount = refund, .street = m_street});
}

bool Table::Advance()
{
    if (m_phase == Phase::DEALING) {
        DealStreet();
        if (const auto first{NextToAct(m_button)}) {
            m_phase = Phase::BETTING;
            m_to_act = *first;
        } else {
            // Nobody can bet (all-in): keep dealing until the river.
            m_phase = m_street == Street::RIVER ? Phase::SHOWDOWN : Phase::DEALING;
        }
        ++m_version;
        return true;
    }
    if (m_phase == Phase::SHOWDOWN) {
        Showdown();
        FinishHand();
        return true;
    }
    return false;
}

void Table::DealStreet()
{
    Event event{.type = EventType::BOARD};
    Draw(); // Burn a card.
    const int count{m_street == Street::PREFLOP ? 3 : 1};
    for (int i{0}; i < count; ++i) {
        const Card card{Draw()};
        m_board.push_back(card);
        event.cards.push_back(card);
    }
    m_street = static_cast<Street>(static_cast<int>(m_street) + 1);
    event.street = m_street;
    m_events.push_back(std::move(event));
}

Chips Table::PotTotal() const
{
    Chips pot{0};
    for (const Seat& s : m_seats) {
        if (s.in_hand) pot += s.total_bet;
    }
    return pot;
}

std::vector<Pot> Table::BuildPots() const
{
    std::vector<Chips> levels;
    for (const Seat& s : m_seats) {
        if (s.Contesting() && s.total_bet > 0) levels.push_back(s.total_bet);
    }
    std::ranges::sort(levels);
    levels.erase(std::unique(levels.begin(), levels.end()), levels.end());

    std::vector<Pot> pots;
    Chips previous{0};
    for (const Chips level : levels) {
        Pot pot;
        for (int i{0}; i < NumSeats(); ++i) {
            const Seat& s{m_seats[i]};
            if (!s.in_hand) continue;
            pot.amount += std::clamp<Chips>(s.total_bet - previous, 0, level - previous);
            if (s.Contesting() && s.total_bet >= level) pot.eligible.push_back(i);
        }
        if (pot.amount > 0) pots.push_back(std::move(pot));
        previous = level;
    }
    // Folded chips above the largest contesting commitment belong to the last pot.
    Chips leftover{0};
    for (const Seat& s : m_seats) {
        if (s.in_hand) leftover += std::max<Chips>(0, s.total_bet - previous);
    }
    if (leftover > 0 && !pots.empty()) pots.back().amount += leftover;
    return pots;
}

void Table::AwardUncontested()
{
    const int winner{NextSeatWhere(-1, [](const Seat& s) { return s.Contesting(); })};
    if (!Assume(winner >= 0)) return;
    const Chips pot{PotTotal()};
    m_seats[winner].stack += pot;
    m_events.push_back(Event{.type = EventType::WIN, .seat = winner, .amount = pot, .total = pot, .street = m_street});
}

void Table::Showdown()
{
    std::array<HandValue, MAX_SEATS> values{};
    // Hands are shown, and odd chips paid, in order starting left of the button.
    std::vector<int> order;
    order.reserve(NumSeats());
    for (int k{1}; k <= NumSeats(); ++k) {
        const int seat{(m_button + k) % NumSeats()};
        if (m_seats[seat].Contesting()) order.push_back(seat);
    }
    for (const int seat : order) {
        const Seat& s{m_seats[seat]};
        std::array<Card, 7> cards{};
        cards[0] = s.hole[0];
        cards[1] = s.hole[1];
        std::ranges::copy(m_board, cards.begin() + 2);
        values[seat] = EvaluateHand(std::span{cards.data(), 2 + m_board.size()});
        m_events.push_back(Event{
            .type = EventType::SHOW,
            .seat = seat,
            .street = m_street,
            .cards = {s.hole[0], s.hole[1]},
            .value = values[seat],
        });
    }

    const std::vector<Pot> pots{BuildPots()};
    for (size_t p{0}; p < pots.size(); ++p) {
        const Pot& pot{pots[p]};
        HandValue best{0};
        for (const int seat : pot.eligible) best = std::max(best, values[seat]);
        std::vector<int> winners;
        for (const int seat : order) {
            if (values[seat] == best && std::ranges::find(pot.eligible, seat) != pot.eligible.end()) {
                winners.push_back(seat);
            }
        }
        if (!Assume(!winners.empty())) continue;
        const auto num_winners{static_cast<Chips>(winners.size())};
        Chips odd_chips{pot.amount % num_winners};
        for (const int seat : winners) {
            Chips won{pot.amount / num_winners};
            if (odd_chips > 0) {
                ++won;
                --odd_chips;
            }
            m_seats[seat].stack += won;
            m_events.push_back(Event{
                .type = EventType::WIN,
                .seat = seat,
                .amount = won,
                .total = pot.amount,
                .street = m_street,
                .value = best,
                .pot_index = static_cast<int>(p),
            });
        }
    }
}

void Table::FinishHand()
{
    for (Seat& s : m_seats) {
        s.street_bet = 0;
        s.total_bet = 0;
        s.acted = false;
        s.bet_when_acted = 0;
    }
    m_current_bet = 0;
    m_min_raise = m_config.big_blind;
    m_to_act = -1;
    m_phase = Phase::IDLE;
    ++m_version;
}

Chips Table::TotalChips() const
{
    Chips total{0};
    for (const Seat& s : m_seats) total += s.stack + s.total_bet;
    return total;
}

int Table::ContestingCount() const
{
    return static_cast<int>(std::ranges::count_if(m_seats, [](const Seat& s) { return s.Contesting(); }));
}

} // namespace poker
