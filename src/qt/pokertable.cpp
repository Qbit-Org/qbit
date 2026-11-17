// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pokertable.h>

#include <qt/pokertableview.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <initializer_list>
#include <utility>
#include <vector>

#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QDoubleSpinBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLatin1Char>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSlider>
#include <QStatusBar>
#include <QStringList>
#include <QTimer>
#include <QVBoxLayout>

namespace {
struct BotProfile {
    const char* name;
    poker::BotStyle style;
};

//! Computer players, named after the usual cast of cryptography papers.
constexpr std::array<BotProfile, 12> BOT_PROFILES{{
    {"Alice", {.looseness = 0.50, .aggression = 0.50, .bluffing = 0.08}},
    {"Bob", {.looseness = 0.80, .aggression = 0.20, .bluffing = 0.03}},
    {"Carol", {.looseness = 0.25, .aggression = 0.75, .bluffing = 0.10}},
    {"Dave", {.looseness = 0.75, .aggression = 0.75, .bluffing = 0.15}},
    {"Eve", {.looseness = 0.20, .aggression = 0.30, .bluffing = 0.04}},
    {"Mallory", {.looseness = 0.85, .aggression = 0.90, .bluffing = 0.25}},
    {"Trent", {.looseness = 0.15, .aggression = 0.25, .bluffing = 0.02}},
    {"Peggy", {.looseness = 0.50, .aggression = 0.65, .bluffing = 0.10}},
    {"Victor", {.looseness = 0.30, .aggression = 0.60, .bluffing = 0.06}},
    {"Sybil", {.looseness = 0.70, .aggression = 0.50, .bluffing = 0.12}},
    {"Oscar", {.looseness = 0.60, .aggression = 0.40, .bluffing = 0.07}},
    {"Wendy", {.looseness = 0.35, .aggression = 0.45, .bluffing = 0.05}},
}};

//! Most steps the raise slider takes from the minimum raise to all-in. The amount box is a QDoubleSpinBox
//! because it holds every chip count up to poker::MAX_STACK exactly, unlike an int.
constexpr int MAX_SLIDER_STEPS{1000};

//! m_pre_actions holds the boxes in PreAction order, FOLD first.
constexpr size_t PreActionIndex(PreAction action) { return static_cast<size_t>(action) - 1; }
constexpr PreAction PreActionAt(size_t index) { return static_cast<PreAction>(index + 1); }
static_assert(PreActionAt(0) == PreAction::FOLD && PreActionAt(NUM_PRE_ACTIONS - 1) == PreAction::RAISE_ANY);

// A free name for every computer seat, even while another seat is being refilled, so seatBot() always succeeds.
static_assert(BOT_PROFILES.size() >= poker::Table::MAX_SEATS);

QString ChipText(poker::Chips chips) { return PokerTableView::chipsText(chips); }
} // namespace

std::optional<poker::Action> ResolvePreAction(PreAction choice, const PreActionContext& chosen, const poker::Table& table, int seat)
{
    if (table.ToAct() != seat) return std::nullopt;
    const poker::LegalActions legal{table.Legal()};
    const bool same_bet{chosen.hand == table.HandNumber() && chosen.street == table.GetStreet() && chosen.current_bet == table.CurrentBet()};
    const poker::Action check_or_call{legal.can_check ? poker::Action::Check() : poker::Action::Call()};
    switch (choice) {
    case PreAction::FOLD:
        return legal.can_check ? poker::Action::Check() : poker::Action::Fold();
    case PreAction::CALL:
        if (same_bet) return check_or_call;
        return std::nullopt;
    case PreAction::CALL_ANY:
        return check_or_call;
    case PreAction::RAISE:
        if (same_bet && legal.can_raise) return poker::Action::RaiseTo(legal.min_raise_to);
        return std::nullopt;
    case PreAction::RAISE_ANY:
        return legal.can_raise ? poker::Action::RaiseTo(legal.min_raise_to) : check_or_call;
    case PreAction::NONE:
        return std::nullopt;
    }
    return std::nullopt;
}

PokerTableWindow::PokerTableWindow(const PokerTableSpec& spec, QWidget* parent)
    : QMainWindow{parent, Qt::Window},
      m_spec{spec},
      m_table{{.num_seats = spec.seats, .small_blind = spec.small_blind, .big_blind = spec.big_blind}}
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle(tr("Poker - %1").arg(m_spec.name));

    m_timer = new QTimer(this);
    m_timer->setObjectName(QStringLiteral("pokerTimer"));
    m_timer->setSingleShot(true);
    connect(m_timer, &QTimer::timeout, this, &PokerTableWindow::runTask);

    buildUi();
    log(tr("Welcome to %1: no-limit hold'em, blinds %2/%3. Play money only.")
            .arg(m_spec.name, ChipText(m_table.Config().small_blind), ChipText(m_table.Config().big_blind)));
    m_table.SitDown(m_hero, "You", std::clamp<poker::Chips>(m_spec.buy_in, 1, poker::MAX_STACK));
    for (int seat{0}; seat < m_table.NumSeats(); ++seat) {
        if (seat != m_hero) seatBot(seat);
    }
    m_table.SetButton(static_cast<int>(m_rng.randrange(m_table.NumSeats())));
    refresh();
}

PokerTableWindow::~PokerTableWindow()
{
    m_timer->stop();
    // Child widgets are normally deleted after this class's members. Everything in the central widget (the view
    // and the controls, whose handlers use this object) depends on those members, so delete it while they exist.
    delete takeCentralWidget();
}

void PokerTableWindow::buildUi()
{
    auto* central{new QWidget(this)};
    auto* layout{new QVBoxLayout(central)};
    layout->setContentsMargins(6, 6, 6, 6);
    m_view = new PokerTableView(m_table, m_hero, central);
    layout->addWidget(m_view, /*stretch=*/1);

    auto* bottom{new QHBoxLayout};
    m_log = new QPlainTextEdit(central);
    m_log->setObjectName(QStringLiteral("pokerLog"));
    m_log->setReadOnly(true);
    m_log->setMaximumBlockCount(2000);
    m_log->setMinimumWidth(260);
    m_log->setMaximumHeight(190);
    bottom->addWidget(m_log, /*stretch=*/2);

    auto* controls{new QVBoxLayout};
    auto* actions{new QHBoxLayout};
    m_fold_button = new QPushButton(tr("&Fold"), central);
    m_call_button = new QPushButton(tr("&Call"), central);
    m_raise_button = new QPushButton(tr("&Raise"), central);
    m_fold_button->setObjectName(QStringLiteral("pokerFoldButton"));
    m_call_button->setObjectName(QStringLiteral("pokerCallButton"));
    m_raise_button->setObjectName(QStringLiteral("pokerRaiseButton"));
    for (QPushButton* button : {m_fold_button, m_call_button, m_raise_button}) {
        button->setMinimumHeight(34);
        button->setMinimumWidth(120);
        actions->addWidget(button);
    }
    controls->addLayout(actions);

    auto* sizing{new QHBoxLayout};
    m_raise_slider = new QSlider(Qt::Horizontal, central);
    m_raise_amount = new QDoubleSpinBox(central);
    m_raise_amount->setObjectName(QStringLiteral("pokerRaiseAmount"));
    m_raise_amount->setDecimals(0);
    m_raise_amount->setGroupSeparatorShown(true);
    m_raise_amount->setMinimumWidth(110);
    m_half_pot_button = new QPushButton(tr("Half pot"), central);
    m_pot_button = new QPushButton(tr("Pot"), central);
    m_all_in_button = new QPushButton(tr("All-in"), central);
    sizing->addWidget(m_raise_slider, /*stretch=*/1);
    sizing->addWidget(m_raise_amount);
    sizing->addWidget(m_half_pot_button);
    sizing->addWidget(m_pot_button);
    sizing->addWidget(m_all_in_button);
    controls->addLayout(sizing);

    // Actions chosen ahead of your turn, as in the original FOLD / CALL / CALL ANY / RAISE / RAISE ANY boxes.
    auto* ahead{new QHBoxLayout};
    const std::array<QString, NUM_PRE_ACTIONS> labels{tr("Fold"), tr("Call"), tr("Call any"), tr("Raise"), tr("Raise any")};
    const std::array<QString, NUM_PRE_ACTIONS> tips{
        tr("When your turn comes: check if nobody has bet, otherwise fold."),
        tr("When your turn comes: call this amount. Cleared if someone raises first."),
        tr("When your turn comes: check or call whatever the bet is."),
        tr("When your turn comes: make this minimum raise. Cleared if someone raises first."),
        tr("When your turn comes: make the minimum raise, whatever the bet is."),
    };
    static constexpr std::array<const char*, NUM_PRE_ACTIONS> OBJECT_NAMES{"pokerPreFold", "pokerPreCall", "pokerPreCallAny", "pokerPreRaise", "pokerPreRaiseAny"};
    for (size_t i{0}; i < m_pre_actions.size(); ++i) {
        QCheckBox* box{new QCheckBox(labels[i], central)};
        box->setObjectName(QString::fromLatin1(OBJECT_NAMES[i]));
        box->setToolTip(tips[i]);
        ahead->addWidget(box);
        const PreAction action{PreActionAt(i)};
        connect(box, &QCheckBox::toggled, this, [this, action](bool checked) { preActionToggled(action, checked); });
        m_pre_actions[i] = box;
    }
    ahead->addStretch();
    controls->addLayout(ahead);

    auto* table_row{new QHBoxLayout};
    m_sit_out = new QCheckBox(tr("Deal Me Out"), central);
    m_sit_out->setObjectName(QStringLiteral("pokerSitOut"));
    m_sit_out->setToolTip(tr("Sit out from the next hand and watch the computer players."));
    m_deal_button = new QPushButton(tr("&Deal Hand"), central);
    m_deal_button->setObjectName(QStringLiteral("pokerDealButton"));
    m_rebuy_button = new QPushButton(tr("Re&buy"), central);
    m_rebuy_button->setObjectName(QStringLiteral("pokerRebuyButton"));
    m_leave_button = new QPushButton(tr("&Leave Table"), central);
    table_row->addWidget(m_sit_out);
    table_row->addStretch();
    table_row->addWidget(m_deal_button);
    table_row->addWidget(m_rebuy_button);
    table_row->addWidget(m_leave_button);
    controls->addLayout(table_row);
    bottom->addLayout(controls, /*stretch=*/3);
    layout->addLayout(bottom);
    setCentralWidget(central);

    m_status = new QLabel(this);
    statusBar()->addWidget(m_status, /*stretch=*/1);

    connect(m_fold_button, &QPushButton::clicked, this, [this] { heroAct(poker::Action::Fold()); });
    connect(m_call_button, &QPushButton::clicked, this, [this] {
        heroAct(m_table.Legal().can_check ? poker::Action::Check() : poker::Action::Call());
    });
    connect(m_raise_button, &QPushButton::clicked, this, [this] {
        const poker::LegalActions legal{m_table.Legal()};
        heroAct(poker::Action::RaiseTo(std::clamp(raiseAmount(), legal.min_raise_to, legal.max_raise_to)));
    });
    connect(m_raise_amount, &QDoubleSpinBox::valueChanged, this, [this] {
        if (!m_slider_driving) syncRaiseSlider();
        updateRaiseButton();
    });
    connect(m_raise_slider, &QSlider::valueChanged, this, [this](int position) {
        const poker::LegalActions legal{m_table.Legal()};
        if (!legal.can_raise) return;
        m_slider_driving = true;
        setRaiseAmount(sliderToChips(position, legal));
        m_slider_driving = false;
    });
    connect(m_half_pot_button, &QPushButton::clicked, this, [this] { setRaiseAmount(potSizedRaise(0.5)); });
    connect(m_pot_button, &QPushButton::clicked, this, [this] { setRaiseAmount(potSizedRaise(1.0)); });
    connect(m_all_in_button, &QPushButton::clicked, this, [this] { setRaiseAmount(m_table.Legal().max_raise_to); });
    connect(m_sit_out, &QCheckBox::toggled, this, [this](bool checked) {
        if (!m_table.SetSittingOut(m_hero, checked)) return;
        log(checked ? tr("You will sit out from the next hand.") : tr("You will be dealt in from the next hand."));
        refresh();
    });
    connect(m_deal_button, &QPushButton::clicked, this, [this] {
        startHand();
        refresh();
    });
    connect(m_rebuy_button, &QPushButton::clicked, this, [this] {
        const poker::Chips top_up{m_spec.buy_in - m_table.GetSeat(m_hero).stack};
        if (top_up > 0 && m_table.AddChips(m_hero, top_up)) log(tr("You add %1 chips.").arg(ChipText(top_up)));
        refresh();
    });
    connect(m_leave_button, &QPushButton::clicked, this, &QWidget::close);

    resize(1000, 760);
}

void PokerTableWindow::setPace(int bot_ms, int street_ms, int hand_ms)
{
    m_bot_ms = std::max(0, bot_ms);
    m_street_ms = std::max(0, street_ms);
    m_hand_ms = std::max(0, hand_ms);
    if (m_task != Task::NONE) scheduleNext();
}

void PokerTableWindow::closeEvent(QCloseEvent* event)
{
    m_timer->stop();
    m_task = Task::NONE;
    QMainWindow::closeEvent(event);
}

void PokerTableWindow::refresh()
{
    appendNewEvents();
    updateControls();
    m_view->update();
    scheduleNext();
}

void PokerTableWindow::scheduleNext()
{
    switch (m_table.GetPhase()) {
    case poker::Phase::IDLE:
        if (autoDeal()) {
            schedule(Task::DEAL, m_table.HandNumber() == 0 ? std::min(m_hand_ms, 800) : m_hand_ms);
        } else {
            schedule(Task::NONE, 0);
        }
        return;
    case poker::Phase::BETTING:
        if (m_table.ToAct() != m_hero) {
            schedule(Task::BOT_TURN, jitter(m_bot_ms));
        } else if (anyPreAction()) {
            schedule(Task::PRE_ACTION, std::min(m_bot_ms, 250));
        } else {
            schedule(Task::NONE, 0);
            QApplication::alert(this);
        }
        return;
    case poker::Phase::DEALING:
    case poker::Phase::SHOWDOWN:
        schedule(Task::ADVANCE, m_street_ms);
        return;
    }
}

void PokerTableWindow::schedule(Task task, int delay_ms)
{
    m_timer->stop();
    m_task = task;
    m_task_version = m_table.Version();
    if (task != Task::NONE) m_timer->start(std::max(0, delay_ms));
}

void PokerTableWindow::runTask()
{
    const Task task{std::exchange(m_task, Task::NONE)};
    // Work planned for an older state is dropped and planned again from the current one.
    if (m_table.Version() != m_task_version) {
        scheduleNext();
        return;
    }
    switch (task) {
    case Task::BOT_TURN: {
        const auto seat{m_table.ToAct()};
        if (!seat || *seat == m_hero) break;
        const poker::BotStyle style{m_bots[*seat].value_or(poker::BotStyle{})};
        if (!m_table.Act(*seat, poker::ChooseAction(m_table, *seat, style, m_rng))) {
            // ChooseAction only returns legal actions, but never let a table stall.
            m_table.Act(*seat, m_table.Legal().can_check ? poker::Action::Check() : poker::Action::Fold());
        }
        break;
    }
    case Task::ADVANCE:
        m_table.Advance();
        break;
    case Task::DEAL:
        startHand();
        break;
    case Task::PRE_ACTION:
        runPreAction();
        break;
    case Task::NONE:
        break;
    }
    refresh();
}

bool PokerTableWindow::autoDeal() const
{
    // Keep dealing while the hero plays or watches. Stop when the hero has run out of chips, when no hand can
    // start (sitting out of a heads-up table), or after a failed deal until something at the table changes.
    const poker::Seat& hero{m_table.GetSeat(m_hero)};
    if (m_deal_failed_at == m_table.Version()) return false;
    return (hero.sitting_out || hero.stack > 0) && playersNextHand() >= 2;
}

int PokerTableWindow::playersNextHand() const
{
    // The seats the table would deal in now, plus the computer seats that startHand() refills first.
    int refills{0};
    for (int seat{0}; seat < m_table.NumSeats(); ++seat) {
        const poker::Seat& s{m_table.GetSeat(seat)};
        if (seat != m_hero && (!s.occupied || s.stack == 0)) ++refills;
    }
    return m_table.EligibleCount() + refills;
}

int PokerTableWindow::jitter(int delay_ms)
{
    if (delay_ms <= 0) return 0;
    return delay_ms * (60 + static_cast<int>(m_rng.randrange(81))) / 100;
}

void PokerTableWindow::startHand()
{
    // Replace busted computer players only when a hand follows at once, so the last hand's results are never
    // shown under a newcomer's name.
    if (m_table.GetPhase() != poker::Phase::IDLE || playersNextHand() < 2) return;
    replaceBustedBots();
    if (!m_table.CanStartHand() || !m_table.StartHand(m_rng)) {
        // Not expected. Stop dealing on our own until something at the table changes; Deal Hand retries.
        m_deal_failed_at = m_table.Version();
        log(tr("The next hand could not be dealt."));
    }
}

void PokerTableWindow::seatBot(int seat)
{
    std::vector<const BotProfile*> free;
    for (const BotProfile& profile : BOT_PROFILES) {
        bool taken{false};
        for (int i{0}; i < m_table.NumSeats(); ++i) {
            taken = taken || (m_table.GetSeat(i).occupied && m_table.GetSeat(i).name == profile.name);
        }
        if (!taken) free.push_back(&profile);
    }
    if (free.empty()) return;
    const BotProfile& profile{*free[m_rng.randrange(free.size())]};
    if (m_table.SitDown(seat, profile.name, std::clamp<poker::Chips>(m_spec.buy_in, 1, poker::MAX_STACK))) {
        m_bots[seat] = profile.style;
        log(tr("%1 sits down with %2 chips.").arg(QString::fromLatin1(profile.name), ChipText(m_table.GetSeat(seat).stack)));
    }
}

void PokerTableWindow::replaceBustedBots()
{
    for (int seat{0}; seat < m_table.NumSeats(); ++seat) {
        if (seat == m_hero) continue;
        const poker::Seat& s{m_table.GetSeat(seat)};
        if (s.occupied && s.stack > 0) continue;
        if (s.occupied) {
            log(tr("%1 is out of chips and leaves the table.").arg(seatName(seat)));
            m_table.StandUp(seat);
            m_bots[seat].reset();
        }
        seatBot(seat);
    }
}

void PokerTableWindow::heroAct(const poker::Action& action)
{
    // Only act on the state the buttons were drawn for; this drops double clicks and late clicks.
    if (m_table.ToAct() != m_hero || m_table.Version() != m_controls_version) return;
    if (!m_table.Act(m_hero, action)) return;
    clearPreActions();
    refresh();
}

bool PokerTableWindow::runPreAction()
{
    const std::optional<poker::Action> action{ResolvePreAction(chosenPreAction(), m_pre_context, m_table, m_hero)};
    clearPreActions();
    return action && m_table.Act(m_hero, *action);
}

void PokerTableWindow::preActionToggled(PreAction action, bool checked)
{
    if (!checked) return;
    // Like radio buttons that can also be cleared.
    QCheckBox* const chosen{preActionBox(action)};
    for (QCheckBox* box : m_pre_actions) {
        if (box != chosen && box->isChecked()) {
            const QSignalBlocker blocker{box};
            box->setChecked(false);
        }
    }
    m_pre_context = {m_table.HandNumber(), m_table.GetStreet(), m_table.CurrentBet()};
}

QCheckBox* PokerTableWindow::preActionBox(PreAction action) const
{
    Assume(action != PreAction::NONE);
    return m_pre_actions.at(PreActionIndex(action));
}

void PokerTableWindow::clearPreActions()
{
    for (QCheckBox* box : m_pre_actions) {
        const QSignalBlocker blocker{box};
        box->setChecked(false);
    }
}

PreAction PokerTableWindow::chosenPreAction() const
{
    for (size_t i{0}; i < m_pre_actions.size(); ++i) {
        if (m_pre_actions[i]->isChecked()) return PreActionAt(i);
    }
    return PreAction::NONE;
}

void PokerTableWindow::updateControls()
{
    m_controls_version = m_table.Version();
    const poker::Phase phase{m_table.GetPhase()};
    const poker::Seat& hero{m_table.GetSeat(m_hero)};
    const bool my_turn{m_table.ToAct() == m_hero};
    const poker::LegalActions legal{m_table.LegalFor(m_hero)};

    // Your turn.
    m_fold_button->setEnabled(my_turn);
    m_call_button->setEnabled(my_turn);
    if (my_turn && legal.can_call) {
        m_call_button->setText(legal.call_amount >= hero.stack ? tr("&Call %1 (all-in)").arg(ChipText(legal.call_amount))
                                                               : tr("&Call %1").arg(ChipText(legal.call_amount)));
    } else {
        m_call_button->setText(my_turn ? tr("&Check") : tr("&Call"));
    }
    const bool can_raise{my_turn && legal.can_raise};
    for (QWidget* widget : std::initializer_list<QWidget*>{m_raise_button, m_raise_amount, m_raise_slider, m_half_pot_button, m_pot_button, m_all_in_button}) {
        widget->setEnabled(can_raise);
    }
    if (can_raise) {
        const QSignalBlocker block_amount{m_raise_amount};
        const QSignalBlocker block_slider{m_raise_slider};
        m_raise_amount->setRange(static_cast<double>(legal.min_raise_to), static_cast<double>(legal.max_raise_to));
        m_raise_amount->setSingleStep(static_cast<double>(m_table.Config().small_blind));
        if (!m_hero_turn_shown) m_raise_amount->setValue(static_cast<double>(legal.min_raise_to));
        // One slider step is at least one small blind, so arrow keys and the wheel always change the amount.
        const poker::Chips span{legal.max_raise_to - legal.min_raise_to};
        m_slider_steps = static_cast<int>(std::clamp<poker::Chips>(span / m_table.Config().small_blind, 1, MAX_SLIDER_STEPS));
        m_raise_slider->setRange(0, m_slider_steps);
        m_raise_slider->setSingleStep(1);
        m_raise_slider->setPageStep(std::max(1, m_slider_steps / 10));
        syncRaiseSlider();
    }
    m_hero_turn_shown = my_turn;
    updateRaiseButton();

    // Actions picked ahead of your turn belong to one street, and CALL / RAISE to one bet size.
    const bool same_street{m_pre_context.hand == m_table.HandNumber() && m_pre_context.street == m_table.GetStreet()};
    if (anyPreAction() && (!same_street || phase != poker::Phase::BETTING || !hero.CanAct())) clearPreActions();
    const PreAction chosen{chosenPreAction()};
    if ((chosen == PreAction::CALL || chosen == PreAction::RAISE) && m_pre_context.current_bet != m_table.CurrentBet()) {
        clearPreActions();
        statusBar()->showMessage(tr("The bet changed, so the action you picked in advance was cleared."), 4000);
    }
    const bool can_choose_ahead{phase == poker::Phase::BETTING && !my_turn && hero.CanAct()};
    preActionBox(PreAction::FOLD)->setText(legal.can_check ? tr("Check/Fold") : tr("Fold"));
    preActionBox(PreAction::CALL)->setText(legal.can_call ? tr("Call %1").arg(ChipText(legal.call_amount)) : tr("Check"));
    if (legal.can_raise) {
        preActionBox(PreAction::RAISE)->setText(m_table.CurrentBet() == 0 ? tr("Bet %1").arg(ChipText(legal.min_raise_to))
                                                                          : tr("Raise to %1").arg(ChipText(legal.min_raise_to)));
    } else {
        preActionBox(PreAction::RAISE)->setText(tr("Raise"));
    }
    for (QCheckBox* box : m_pre_actions) {
        box->setEnabled(can_choose_ahead && (box != preActionBox(PreAction::RAISE) || legal.can_raise));
    }

    // The table.
    const bool idle{phase == poker::Phase::IDLE};
    {
        const QSignalBlocker blocker{m_sit_out};
        m_sit_out->setChecked(hero.sitting_out);
    }
    m_deal_button->setEnabled(idle && playersNextHand() >= 2);
    m_rebuy_button->setEnabled(idle && hero.stack < m_spec.buy_in);
    m_rebuy_button->setText(hero.stack == 0 ? tr("Re&buy %1").arg(ChipText(m_spec.buy_in)) : tr("Top &up to %1").arg(ChipText(m_spec.buy_in)));

    QString status;
    switch (phase) {
    case poker::Phase::IDLE:
        if (m_deal_failed_at == m_table.Version()) {
            status = tr("The next hand could not be dealt. Click Deal Hand to try again.");
        } else if (hero.stack == 0 && !hero.sitting_out) {
            status = tr("You are out of chips. Rebuy to keep playing, or pick Deal Me Out to watch.");
        } else if (hero.sitting_out) {
            status = tr("You are sitting out.");
        } else {
            status = m_table.HandNumber() == 0 ? tr("Shuffling up and dealing...") : tr("Next hand coming up...");
        }
        break;
    case poker::Phase::BETTING:
        if (my_turn) {
            status = legal.can_call ? tr("Your turn: %1 to call.").arg(ChipText(legal.call_amount)) : tr("Your turn.");
        } else {
            status = tr("Waiting for %1...").arg(seatName(*m_table.ToAct()));
        }
        break;
    case poker::Phase::DEALING:
        status = tr("Dealing...");
        break;
    case poker::Phase::SHOWDOWN:
        status = tr("Showdown.");
        break;
    }
    m_status->setText(status);
}

void PokerTableWindow::updateRaiseButton()
{
    const poker::LegalActions legal{m_table.Legal()};
    if (m_table.ToAct() != m_hero || !legal.can_raise) {
        m_raise_button->setText(tr("&Raise"));
        return;
    }
    const poker::Chips raise_to{std::clamp(raiseAmount(), legal.min_raise_to, legal.max_raise_to)};
    const QString amount{ChipText(raise_to)};
    if (raise_to == legal.max_raise_to) {
        m_raise_button->setText(tr("All-&in %1").arg(amount));
    } else if (m_table.CurrentBet() == 0) {
        m_raise_button->setText(tr("&Bet %1").arg(amount));
    } else {
        m_raise_button->setText(tr("&Raise to %1").arg(amount));
    }
}

poker::Chips PokerTableWindow::raiseAmount() const
{
    return static_cast<poker::Chips>(std::llround(m_raise_amount->value()));
}

void PokerTableWindow::setRaiseAmount(poker::Chips amount)
{
    m_raise_amount->setValue(std::clamp(static_cast<double>(amount), m_raise_amount->minimum(), m_raise_amount->maximum()));
}

poker::Chips PokerTableWindow::sliderToChips(int position, const poker::LegalActions& legal) const
{
    // The far end is all-in; every other position is a whole number of small blinds above the minimum raise.
    if (position >= m_slider_steps) return legal.max_raise_to;
    const poker::Chips span{legal.max_raise_to - legal.min_raise_to};
    poker::Chips amount{legal.min_raise_to + static_cast<poker::Chips>(std::llround(static_cast<double>(span) * position / m_slider_steps))};
    amount -= (amount - legal.min_raise_to) % m_table.Config().small_blind;
    return std::clamp(amount, legal.min_raise_to, legal.max_raise_to);
}

int PokerTableWindow::chipsToSlider(poker::Chips amount, const poker::LegalActions& legal) const
{
    // Only the minimum raise sits at the start and only all-in at the end, so moving to either end always
    // changes the amount.
    const poker::Chips span{legal.max_raise_to - legal.min_raise_to};
    if (amount >= legal.max_raise_to || span <= 0) return m_slider_steps;
    if (amount <= legal.min_raise_to) return 0;
    const double share{static_cast<double>(amount - legal.min_raise_to) / static_cast<double>(span)};
    return std::clamp(static_cast<int>(std::lround(share * m_slider_steps)), 1, std::max(1, m_slider_steps - 1));
}

void PokerTableWindow::syncRaiseSlider()
{
    const poker::LegalActions legal{m_table.Legal()};
    if (!legal.can_raise) return;
    const QSignalBlocker blocker{m_raise_slider};
    m_raise_slider->setValue(chipsToSlider(raiseAmount(), legal));
}

poker::Chips PokerTableWindow::potSizedRaise(double fraction) const
{
    // A pot-sized raise first calls, then raises by the size of the pot after that call.
    const poker::LegalActions legal{m_table.Legal()};
    const poker::Chips pot_after_call{m_table.PotTotal() + legal.call_amount};
    return m_table.CurrentBet() + static_cast<poker::Chips>(fraction * static_cast<double>(pot_after_call));
}

QString PokerTableWindow::seatName(int seat) const
{
    if (seat == m_hero) return tr("You");
    if (seat < 0 || seat >= m_table.NumSeats()) return {};
    return QString::fromStdString(m_table.GetSeat(seat).name);
}

void PokerTableWindow::log(const QString& line)
{
    m_log->appendPlainText(line);
}

void PokerTableWindow::appendNewEvents()
{
    if (m_logged_hand != m_table.HandNumber()) {
        m_logged_hand = m_table.HandNumber();
        m_logged_events = 0;
    }
    const std::vector<poker::Event>& events{m_table.Events()};
    const bool side_pots{std::ranges::any_of(events, [](const poker::Event& e) { return e.type == poker::EventType::WIN && e.pot_index > 0; })};
    for (; m_logged_events < events.size(); ++m_logged_events) {
        const poker::Event& e{events[m_logged_events]};
        const bool you{e.seat == m_hero};
        const QString who{seatName(e.seat)};
        const QString amount{ChipText(e.amount)};
        const QString total{ChipText(e.total)};
        QString line;
        switch (e.type) {
        case poker::EventType::HAND_START: {
            log(QString{});
            log(you ? tr("Hand #%1. You have the button.").arg(m_table.HandNumber())
                    : tr("Hand #%1. %2 has the button.").arg(m_table.HandNumber()).arg(who));
            const poker::Seat& hero{m_table.GetSeat(m_hero)};
            if (hero.in_hand) {
                line = tr("Your cards: %1 %2").arg(PokerTableView::cardText(hero.hole[0]), PokerTableView::cardText(hero.hole[1]));
            }
            break;
        }
        case poker::EventType::SMALL_BLIND:
            line = you ? tr("You post the small blind of %1.").arg(amount) : tr("%1 posts the small blind of %2.").arg(who, amount);
            break;
        case poker::EventType::BIG_BLIND:
            line = you ? tr("You post the big blind of %1.").arg(amount) : tr("%1 posts the big blind of %2.").arg(who, amount);
            break;
        case poker::EventType::FOLD:
            line = you ? tr("You fold.") : tr("%1 folds.").arg(who);
            break;
        case poker::EventType::CHECK:
            line = you ? tr("You check.") : tr("%1 checks.").arg(who);
            break;
        case poker::EventType::CALL:
            line = you ? tr("You call %1.").arg(amount) : tr("%1 calls %2.").arg(who, amount);
            break;
        case poker::EventType::BET:
            line = you ? tr("You bet %1.").arg(total) : tr("%1 bets %2.").arg(who, total);
            break;
        case poker::EventType::RAISE:
            line = you ? tr("You raise to %1.").arg(total) : tr("%1 raises to %2.").arg(who, total);
            break;
        case poker::EventType::UNCALLED:
            line = you ? tr("Uncalled bet of %1 returned to you.").arg(amount) : tr("Uncalled bet of %1 returned to %2.").arg(amount, who);
            break;
        case poker::EventType::BOARD: {
            QStringList cards;
            for (const poker::Card card : e.cards) cards.append(PokerTableView::cardText(card));
            const QString text{cards.join(QLatin1Char(' '))};
            if (e.street == poker::Street::FLOP) line = tr("Flop: %1").arg(text);
            if (e.street == poker::Street::TURN) line = tr("Turn: %1").arg(text);
            if (e.street == poker::Street::RIVER) line = tr("River: %1").arg(text);
            break;
        }
        case poker::EventType::SHOW: {
            const QString cards{PokerTableView::cardText(e.cards.at(0)) + QLatin1Char(' ') + PokerTableView::cardText(e.cards.at(1))};
            line = you ? tr("You show %1 (%2).").arg(cards, PokerTableView::handText(e.value))
                       : tr("%1 shows %2 (%3).").arg(who, cards, PokerTableView::handText(e.value));
            break;
        }
        case poker::EventType::WIN: {
            if (e.value == 0) {
                line = you ? tr("You win %1.").arg(amount) : tr("%1 wins %2.").arg(who, amount);
                break;
            }
            const QString pot{e.pot_index == 0 ? (side_pots ? tr("the main pot") : tr("the pot")) : tr("side pot %1").arg(e.pot_index)};
            const QString hand{PokerTableView::handText(e.value)};
            line = you ? tr("You win %1 from %2 (%3).").arg(amount, pot, hand) : tr("%1 wins %2 from %3 (%4).").arg(who, amount, pot, hand);
            break;
        }
        }
        if (e.all_in && e.type != poker::EventType::FOLD) line += QLatin1Char(' ') + tr("All-in.");
        if (!line.isEmpty()) log(line);
    }
}
