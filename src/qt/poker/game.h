// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_POKER_GAME_H
#define QBIT_QT_POKER_GAME_H

#include <qt/poker/cards.h>
#include <qt/poker/handeval.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class FastRandomContext;

namespace poker {

/** Play-money chip amounts. Chips have no value and never touch the wallet. */
using Chips = int64_t;

/** Largest stack a seat may hold, so sums over a table stay far from overflow. */
inline constexpr Chips MAX_STACK{1'000'000'000'000};

enum class Street : uint8_t { PREFLOP, FLOP, TURN, RIVER };

enum class Phase : uint8_t {
    IDLE,     //!< No hand in progress. Seats may change; StartHand() deals the next hand.
    BETTING,  //!< ToAct() must act.
    DEALING,  //!< A betting round is over; Advance() deals the next street.
    SHOWDOWN, //!< All betting is over; Advance() shows the hands and pays the pots.
};

enum class ActionType : uint8_t { FOLD, CHECK, CALL, RAISE };

struct Action {
    ActionType type{ActionType::FOLD};
    //! RAISE (which also covers an opening bet): the seat's total bet on this street afterwards.
    Chips raise_to{0};

    static Action Fold() { return {ActionType::FOLD, 0}; }
    static Action Check() { return {ActionType::CHECK, 0}; }
    static Action Call() { return {ActionType::CALL, 0}; }
    static Action RaiseTo(Chips total) { return {ActionType::RAISE, total}; }
};

/** What a seat may do on its turn. Folding is always allowed on your turn. */
struct LegalActions {
    bool can_check{false};
    bool can_call{false};
    Chips call_amount{0};  //!< Chips a call adds; equals the stack for an all-in call.
    bool can_raise{false};
    Chips min_raise_to{0}; //!< Smallest RAISE total; equals max_raise_to when only an all-in raise is possible.
    Chips max_raise_to{0}; //!< RAISE total that puts the seat all-in.
};

struct Seat {
    bool occupied{false};
    std::string name;
    Chips stack{0};          //!< Chips not committed to the current hand.
    bool sitting_out{false}; //!< Not dealt in, from the next hand on.

    bool in_hand{false}; //!< Dealt into the current (or last) hand.
    bool folded{false};
    std::array<Card, 2> hole{};
    Chips street_bet{0};     //!< Committed on the current street.
    Chips total_bet{0};      //!< Committed to the current hand, including street_bet.
    bool acted{false};       //!< Has acted voluntarily on the current street.
    Chips bet_when_acted{0}; //!< The table bet right after this seat last acted on this street.

    bool Contesting() const { return in_hand && !folded; }
    bool AllIn() const { return Contesting() && stack == 0; }
    bool CanAct() const { return Contesting() && stack > 0; }
};

enum class EventType : uint8_t {
    HAND_START,  //!< seat: the button.
    SMALL_BLIND, //!< amount: chips posted (all_in when short).
    BIG_BLIND,   //!< amount: chips posted (all_in when short).
    FOLD,
    CHECK,
    CALL,     //!< amount: chips added. total: street bet afterwards.
    BET,      //!< amount: chips added. total: street bet afterwards.
    RAISE,    //!< amount: chips added. total: street bet afterwards.
    UNCALLED, //!< amount: chips returned to seat.
    BOARD,    //!< cards: the new board cards. street: the street they start.
    SHOW,     //!< cards: hole cards. value: hand strength.
    WIN,      //!< amount: chips won from pot pot_index (0 = main pot). total: pot size. value: 0 if uncontested.
};

struct Event {
    EventType type{EventType::HAND_START};
    int seat{-1};
    Chips amount{0};
    Chips total{0};
    bool all_in{false};
    Street street{Street::PREFLOP};
    std::vector<Card> cards{};
    HandValue value{0};
    int pot_index{0};
};

struct TableConfig {
    int num_seats{6};
    Chips small_blind{1};
    Chips big_blind{2};
};

/** A pot and the seats that can win it. */
struct Pot {
    Chips amount{0};
    std::vector<int> eligible;
};

/**
 * No-limit Texas hold'em rules for one table.
 *
 * The table does not know who controls a seat. Callers read ToAct() and
 * Legal(), then call Act(). Anything that breaks the rules is rejected without
 * changing state.
 *
 * Rules: moving button; heads-up the button posts the small blind and acts
 * first before the flop; a short all-in blind still leaves the full big blind
 * as the price to call; the minimum raise equals the last full raise; an all-in
 * raise smaller than a full raise does not reopen betting for seats that have
 * already acted, unless several such raises add up to a full raise; uncalled
 * bets are returned; side pots; odd chips of a split pot go to the winners
 * nearest the button's left.
 */
class Table
{
public:
    static constexpr int MAX_SEATS{10};

    /** Out-of-range settings are clamped: 2..MAX_SEATS seats, big blind >= 1, 1 <= small blind <= big blind. */
    explicit Table(const TableConfig& config);

    const TableConfig& Config() const { return m_config; }
    int NumSeats() const { return m_config.num_seats; }

    // Seat changes. Only while IDLE, except SetSittingOut, which takes effect from the next hand.
    bool SitDown(int seat, std::string name, Chips stack);
    bool StandUp(int seat);
    bool AddChips(int seat, Chips amount);
    bool SetSittingOut(int seat, bool sitting_out);
    /** Put the button marker on `seat` (-1 for none); the next hand moves it on as usual. IDLE only. */
    bool SetButton(int seat);

    /** Seats the next hand would deal in. */
    int EligibleCount() const;
    bool CanStartHand() const;
    bool StartHand(FastRandomContext& rng);
    /** Deal from a fixed order (deck[0] first). Requires all 52 cards exactly once. */
    bool StartHand(const std::vector<Card>& deck);

    Phase GetPhase() const { return m_phase; }
    Street GetStreet() const { return m_street; }
    /** The seat to act, while BETTING. */
    std::optional<int> ToAct() const;
    /** Legal actions of the seat to act; all false when nobody is to act. */
    LegalActions Legal() const;
    /** Legal actions `seat` would have if it acted in the current state (for actions picked in advance). */
    LegalActions LegalFor(int seat) const;
    /** Apply an action for the seat to act. When illegal, returns false with a reason and changes nothing. */
    bool Act(int seat, const Action& action, std::string* error = nullptr);
    /** DEALING: deal the next street. SHOWDOWN: show hands and pay the pots. Otherwise returns false. */
    bool Advance();

    const Seat& GetSeat(int seat) const { return m_seats.at(seat); }
    const std::vector<Card>& Board() const { return m_board; }
    int Button() const { return m_button; }
    int SmallBlindSeat() const { return m_small_blind_seat; }
    int BigBlindSeat() const { return m_big_blind_seat; }
    /** The bet to match on this street. */
    Chips CurrentBet() const { return m_current_bet; }
    /** Chips committed to the current hand, including bets on this street. */
    Chips PotTotal() const;
    /** How the committed chips would split into pots now, main pot first. */
    std::vector<Pot> BuildPots() const;
    /** Number of hands started at this table. */
    uint64_t HandNumber() const { return m_hand_number; }
    /** Increases on every state change, so callers can drop stale scheduled work. */
    uint64_t Version() const { return m_version; }
    /** Events of the current or last hand, oldest first. */
    const std::vector<Event>& Events() const { return m_events; }
    /** Sum of stacks and committed chips; a hand never changes it. */
    Chips TotalChips() const;
    /** Seats still contesting the pot. */
    int ContestingCount() const;

private:
    bool ValidSeat(int seat) const { return seat >= 0 && seat < NumSeats(); }
    template <typename Pred>
    int NextSeatWhere(int from, Pred pred) const;
    bool AnyOtherCanAct(int seat) const;
    Chips MaxOtherStreetBet(int seat) const;
    Chips ToCall(int seat) const;
    bool NeedsToAct(int seat) const;
    std::optional<int> NextToAct(int after) const;
    void Commit(int seat, Chips amount);
    void PostBlind(int seat, Chips amount, EventType type);
    Card Draw();
    void AfterAction(int seat);
    void EndBettingRound();
    void ReturnUncalledBet();
    void DealStreet();
    void AwardUncontested();
    void Showdown();
    void FinishHand();

    TableConfig m_config;
    std::vector<Seat> m_seats;
    std::vector<Card> m_deck;
    size_t m_deck_pos{0};
    std::vector<Card> m_board;
    std::vector<Event> m_events;
    Phase m_phase{Phase::IDLE};
    Street m_street{Street::PREFLOP};
    int m_button{-1};
    int m_small_blind_seat{-1};
    int m_big_blind_seat{-1};
    int m_to_act{-1};
    Chips m_current_bet{0};
    Chips m_min_raise{0};
    uint64_t m_hand_number{0};
    uint64_t m_version{0};
};

} // namespace poker

#endif // QBIT_QT_POKER_GAME_H
