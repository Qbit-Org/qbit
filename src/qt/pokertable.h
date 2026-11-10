// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_POKERTABLE_H
#define QBIT_QT_POKERTABLE_H

#include <qt/poker/bot.h>
#include <qt/poker/game.h>
#include <random.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <QMainWindow>
#include <QString>

class PokerTableView;
class QCheckBox;
class QCloseEvent;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QDoubleSpinBox;
class QSlider;
class QTimer;

/** An action picked before the hero's turn, as in the original FOLD / CALL / CALL ANY / RAISE / RAISE ANY boxes. */
enum class PreAction { NONE, FOLD, CALL, CALL_ANY, RAISE, RAISE_ANY };
inline constexpr size_t NUM_PRE_ACTIONS{static_cast<size_t>(PreAction::RAISE_ANY)};

/** The table state an advance action was picked in. */
struct PreActionContext {
    uint64_t hand{0};
    poker::Street street{poker::Street::PREFLOP};
    poker::Chips current_bet{0};
};

/**
 * What an advance action does now that it is `seat`'s turn. FOLD checks when
 * nobody has bet. CALL and RAISE were picked for one bet size: they do nothing if
 * the bet has changed since `chosen`. CALL ANY and RAISE ANY act whatever the bet.
 */
std::optional<poker::Action> ResolvePreAction(PreAction choice, const PreActionContext& chosen, const poker::Table& table, int seat);

/** Settings of a play-money table. */
struct PokerTableSpec {
    QString name;
    int seats{6};
    poker::Chips small_blind{1};
    poker::Chips big_blind{2};
    poker::Chips buy_in{200};
};

/**
 * A play-money no-limit hold'em table against computer players.
 *
 * Laid out after the table window of the original 2009 Bitcoin client
 * (CPokerDialogBase): Deal Hand, Fold, Call, Raise, Leave Table, "Deal Me Out",
 * and the FOLD / CALL / CALL ANY / RAISE / RAISE ANY actions you can pick
 * before your turn. Chips are not coins: nothing here touches the wallet or
 * the network.
 */
class PokerTableWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit PokerTableWindow(const PokerTableSpec& spec, QWidget* parent = nullptr);
    ~PokerTableWindow() override;

    /** Delays in milliseconds for a computer player's turn, dealing a street, and the pause between hands. */
    void setPace(int bot_ms, int street_ms, int hand_ms);
    const poker::Table& table() const { return m_table; }
    int heroSeat() const { return m_hero; }

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    enum class Task { NONE, BOT_TURN, ADVANCE, DEAL, PRE_ACTION };

    void buildUi();
    void refresh();
    void scheduleNext();
    void schedule(Task task, int delay_ms);
    void runTask();
    void startHand();
    void seatBot(int seat);
    void replaceBustedBots();
    void heroAct(const poker::Action& action);
    bool runPreAction();
    void preActionToggled(PreAction action, bool checked);
    QCheckBox* preActionBox(PreAction action) const;
    void clearPreActions();
    PreAction chosenPreAction() const;
    bool anyPreAction() const { return chosenPreAction() != PreAction::NONE; }
    void updateControls();
    void updateRaiseButton();
    poker::Chips raiseAmount() const;
    void setRaiseAmount(poker::Chips amount);
    poker::Chips sliderToChips(int position, const poker::LegalActions& legal) const;
    int chipsToSlider(poker::Chips amount, const poker::LegalActions& legal) const;
    void syncRaiseSlider();
    poker::Chips potSizedRaise(double fraction) const;
    void appendNewEvents();
    void log(const QString& line);
    QString seatName(int seat) const;
    bool autoDeal() const;
    int playersNextHand() const;
    int jitter(int delay_ms);

    const PokerTableSpec m_spec;
    poker::Table m_table;
    const int m_hero{0};
    FastRandomContext m_rng;
    std::array<std::optional<poker::BotStyle>, poker::Table::MAX_SEATS> m_bots{};

    QTimer* m_timer{nullptr};
    Task m_task{Task::NONE};
    uint64_t m_task_version{0};
    int m_bot_ms{900};
    int m_street_ms{700};
    int m_hand_ms{2600};

    uint64_t m_logged_hand{0};
    size_t m_logged_events{0};
    //! Table version the action controls were last drawn for; clicks for any other state are ignored.
    uint64_t m_controls_version{0};
    bool m_hero_turn_shown{false};
    //! Raise slider steps for the current turn: at most one per small blind, so every step changes the amount.
    int m_slider_steps{1};
    //! Set while the slider sets the amount, so the amount does not move the slider back.
    bool m_slider_driving{false};
    //! Table version at which dealing a hand failed; no automatic deal until the table changes.
    std::optional<uint64_t> m_deal_failed_at;
    //! The state the advance action was picked in.
    PreActionContext m_pre_context;

    PokerTableView* m_view{nullptr};
    QPlainTextEdit* m_log{nullptr};
    QLabel* m_status{nullptr};
    QPushButton* m_fold_button{nullptr};
    QPushButton* m_call_button{nullptr};
    QPushButton* m_raise_button{nullptr};
    QDoubleSpinBox* m_raise_amount{nullptr};
    QSlider* m_raise_slider{nullptr};
    QPushButton* m_half_pot_button{nullptr};
    QPushButton* m_pot_button{nullptr};
    QPushButton* m_all_in_button{nullptr};
    //! FOLD, CALL, CALL ANY, RAISE and RAISE ANY, in PreAction order.
    std::array<QCheckBox*, NUM_PRE_ACTIONS> m_pre_actions{};
    QCheckBox* m_sit_out{nullptr};
    QPushButton* m_deal_button{nullptr};
    QPushButton* m_rebuy_button{nullptr};
    QPushButton* m_leave_button{nullptr};
};

#endif // QBIT_QT_POKERTABLE_H
