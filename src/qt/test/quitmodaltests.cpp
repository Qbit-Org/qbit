// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/quitmodaltests.h>

#include <addresstype.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <crypto/pqc.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <qt/bitcoin.h>
#include <qt/bitcoinamountfield.h>
#include <qt/bitcoingui.h>
#include <qt/guiconstants.h>
#include <qt/networkstyle.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendcoinsentry.h>
#include <qt/test/syntheticwallet.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#include <qt/walletview.h>
#include <script/script.h>
#include <streams.h>
#include <util/strencodings.h>
#include <wallet/coincontrol.h>
#include <wallet/pqc_usage.h>

#include <mutex>
#include <string>
#include <utility>

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QCompleter>
#include <QDialog>
#include <QEvent>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QProcess>
#include <QProcessEnvironment>
#include <QProgressDialog>
#include <QPushButton>
#include <QScopedPointer>
#include <QTest>
#include <QTimer>
#include <QVBoxLayout>

namespace {
using namespace std::chrono_literals;

//! A step waiting longer than this means the flow is stuck.
constexpr auto STEP_TIMEOUT{60s};
//! Long enough for a deferred shutdown to be retried several times.
constexpr auto RETRY_SPAN{3 * SHUTDOWN_POLLING_DELAY};
//! A build without the fix joins a held worker during shutdown. Release it
//! after this long so such a run fails instead of hanging.
constexpr auto LATCH_RELEASE_DELAY{10s};
constexpr int CHILD_TIMEOUT_MS{300'000};
const QString RESCAN_TITLE{QStringLiteral("Rescanning…")};

#define QUIT_CHECK(condition)                                                 \
    do {                                                                      \
        if (!(condition)) QTest::qFail("Check failed: " #condition, __FILE__, __LINE__); \
    } while (false)

class AdoptionActivity : public WalletControllerActivity
{
public:
    using WalletControllerActivity::WalletControllerActivity;

    void adopt(std::unique_ptr<interfaces::Wallet> wallet, std::function<void(WalletModel*)> callback)
    {
        scheduleWalletModel(std::move(wallet), std::move(callback));
    }
};

template <typename Widget = QWidget, typename Predicate>
Widget* FindVisible(Predicate&& match)
{
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        Widget* const typed{qobject_cast<Widget*>(widget)};
        if (typed && widget->isVisible() && match(typed)) return typed;
    }
    return nullptr;
}

QMessageBox* FindConfirmation()
{
    return FindVisible<QMessageBox>([](QMessageBox* box) { return box->inherits("SendConfirmationDialog"); });
}

QMessageBox* FindMessageBox(const QString& title)
{
    return FindVisible<QMessageBox>([&](QMessageBox* box) {
        return !box->inherits("SendConfirmationDialog") && box->windowTitle().contains(title);
    });
}

QMessageBox* FindPSBTCopiedBox()
{
    return FindVisible<QMessageBox>([](QMessageBox* box) { return box->objectName() == "psbt_copied_message"; });
}

QDialog* FindDialog(const char* class_name)
{
    return FindVisible<QDialog>([&](QDialog* dialog) { return dialog->inherits(class_name); });
}

void ClickButton(QMessageBox* box, QMessageBox::StandardButton which)
{
    QAbstractButton* const button{box ? box->button(which) : nullptr};
    QUIT_CHECK(button);
    if (!button) return;
    // The send confirmation enables its buttons after a countdown.
    button->setEnabled(true);
    button->click();
}

PartiallySignedTransaction MakeUnsignedPSBT()
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid{}, 0});
    tx.vout.emplace_back(COIN - 1'000, CScript{} << OP_TRUE);

    PartiallySignedTransaction psbt{tx};
    const CKey key{GenerateRandomKey()};
    psbt.inputs.front().witness_utxo = CTxOut{COIN, GetScriptForDestination(WitnessV0KeyHash{key.GetPubKey()})};
    return psbt;
}

template <typename Predicate>
bool ReadState(const std::shared_ptr<qt_test::SyntheticWalletState>& state, Predicate&& predicate)
{
    std::lock_guard lock{state->mutex};
    return predicate(*state);
}

void Allow(const std::shared_ptr<qt_test::SyntheticWalletState>& state, bool qt_test::SyntheticWalletState::*flag)
{
    {
        std::lock_guard lock{state->mutex};
        state.get()->*flag = true;
    }
    state->condition.notify_all();
}

//! Release a held synthetic wallet worker from another thread if the
//! scenario has not done so in time.
std::thread ReleaseLater(std::shared_ptr<qt_test::SyntheticWalletState> state, bool qt_test::SyntheticWalletState::*flag)
{
    return std::thread{[state = std::move(state), flag] {
        std::unique_lock lock{state->mutex};
        if (!state->condition.wait_for(lock, LATCH_RELEASE_DELAY, [&] { return state.get()->*flag; })) {
            state.get()->*flag = true;
            lock.unlock();
            state->condition.notify_all();
        }
    }};
}
} // namespace

int QuitModalTests::RunScenario(BitcoinApplication& app, const QString& scenario)
{
    QuitModalScenario test{app, scenario};
    return QTest::qExec(&test);
}

void QuitModalTests::quitDuringDialog_data()
{
    QTest::addColumn<QString>("scenario");
    // Quit requests inside the nested event loop of a dialog the user must
    // answer: the send confirmation, the "PSBT copied" box, the PQC usage
    // warning shown after a broadcast, and the passphrase prompt.
    QTest::newRow("send-confirmation") << QStringLiteral("send-confirmation");
    QTest::newRow("psbt-copied") << QStringLiteral("psbt-copied");
    QTest::newRow("pqc-warning") << QStringLiteral("pqc-warning");
    QTest::newRow("passphrase") << QStringLiteral("passphrase");
    // A quit handled in the same event pass that closed the dialog, before
    // its exec() has returned.
    QTest::newRow("same-pass") << QStringLiteral("same-pass");
    // Quit requests while busy work runs behind a dialog.
    QTest::newRow("encryption") << QStringLiteral("encryption");
    QTest::newRow("psbt-signing") << QStringLiteral("psbt-signing");
    // A wallet unload while a progress dialog covers the send confirmation.
    QTest::newRow("unload-under-progress") << QStringLiteral("unload-under-progress");
    // Popups that run no nested event loop do not hold a quit up.
    QTest::newRow("popups") << QStringLiteral("popups");
}

void QuitModalTests::quitDuringDialog()
{
#ifdef Q_OS_MACOS
    if (QApplication::platformName() == "minimal") {
        // The scenarios start a BitcoinApplication; see AppTests::appTests.
        QSKIP("BitcoinApplication tests need 'QT_QPA_PLATFORM=cocoa' on mac");
    }
#endif
    QFETCH(QString, scenario);

    QProcess child;
    QProcessEnvironment environment{QProcessEnvironment::systemEnvironment()};
    environment.insert(SCENARIO_ENV, scenario);
    child.setProcessEnvironment(environment);
    // Show the child's test log and any sanitizer report.
    child.setProcessChannelMode(QProcess::ForwardedChannels);
    child.start(QCoreApplication::applicationFilePath(), QStringList{});
    QVERIFY(child.waitForStarted());
    if (!child.waitForFinished(CHILD_TIMEOUT_MS)) {
        child.kill();
        child.waitForFinished();
        QFAIL("The scenario timed out");
    }
    QCOMPARE(child.exitStatus(), QProcess::NormalExit);
    QCOMPARE(child.exitCode(), 0);
}

QuitModalScenario::QuitModalScenario(BitcoinApplication& app, QString scenario)
    : m_app{app}, m_scenario{std::move(scenario)}
{
}

void QuitModalScenario::quitDuringDialog()
{
    qRegisterMetaType<interfaces::BlockAndHeaderTipInfo>("interfaces::BlockAndHeaderTipInfo");
    m_app.parameterSetup();
    QVERIFY(m_app.createOptionsModel(/*resetSettings=*/true));
    QScopedPointer<const NetworkStyle> style(NetworkStyle::instantiate(Params().GetChainType()));
    m_app.setupPlatformStyle();
    m_app.createWindow(style.data());
    connect(&m_app, &BitcoinApplication::windowShown, this, &QuitModalScenario::start);
    connect(&m_app, &BitcoinApplication::requestedShutdown, this, [this] {
        if (++m_shutdown_requests > 1) return;
        // Another platform Quit, or File > Exit as the tray menu's Exit
        // triggers it, while the node stops must not start a second shutdown.
        QTimer::singleShot(0, this, [this] {
            sendQuitEvent();
            triggerQuitAction();
        });
    });
    QVERIFY(m_app.baseInitialize());
    m_app.requestInitialize();
    m_app.exec();
    if (m_latch_release.joinable()) m_latch_release.join();

    QVERIFY2(m_flow_finished, "The scenario did not reach its last step");
    QCOMPARE(m_shutdown_requests, 1);
    QVERIFY(!m_view);
    QVERIFY(!m_model);
    // Only the PQC warning scenario confirms a send; the others cancel.
    QCOMPARE(m_coins_sent, m_scenario == "pqc-warning" ? 1 : 0);
    if (m_scenario == "psbt-copied") {
        QVERIFY(ReadState(m_state, [](const auto& s) { return s.psbt_sign_calls == 0; }));
    } else if (m_scenario == "passphrase") {
        QVERIFY(ReadState(m_state, [](const auto& s) { return !s.create_entered && s.unlock_calls == 0 && s.locked; }));
    } else if (m_scenario == "encryption") {
        QVERIFY(ReadState(m_state, [](const auto& s) { return s.encrypt_calls == 1 && s.encrypt_finished && s.encrypted; }));
    } else if (m_scenario == "psbt-signing") {
        QVERIFY(ReadState(m_state, [](const auto& s) {
            return s.psbt_sign_calls == 1 && s.psbt_sign_finished && !s.psbt_cancel_observed;
        }));
    }
}

void QuitModalScenario::start(BitcoinGUI* window)
{
    m_window = window;
    for (QAction* action : window->findChildren<QAction*>()) {
        if (action->parent() == window && action->menuRole() == QAction::QuitRole) m_quit_action = action;
    }
    WalletController* const controller{window->getWalletController()};
    QUIT_CHECK(m_quit_action);
    QUIT_CHECK(controller);
    if (!m_quit_action || !controller) {
        sendQuitEvent();
        return;
    }

    m_state = std::make_shared<qt_test::SyntheticWalletState>();
    wallet::PQCUsageReport report;
    if (m_scenario == "psbt-copied") {
        m_state->private_keys_disabled = true;
    } else if (m_scenario == "pqc-warning") {
        report = qt_test::MakeSyntheticPQCUsageReport({{CPQCPubKey{}, wallet::PQC_WARNING_SIGNATURE_THRESHOLD}});
    } else if (m_scenario == "passphrase") {
        m_state->encrypted = true;
        m_state->locked = true;
    } else if (m_scenario == "encryption") {
        m_state->allow_encrypt = false;
        m_latch_release = ReleaseLater(m_state, &qt_test::SyntheticWalletState::allow_encrypt);
    } else if (m_scenario == "psbt-signing") {
        m_state->psbt_simulate_pqc_reservation = true;
        m_state->allow_psbt_completion = false;
        m_latch_release = ReleaseLater(m_state, &qt_test::SyntheticWalletState::allow_psbt_completion);
    }

    auto* const activity{new AdoptionActivity(controller, window)};
    activity->adopt(qt_test::MakeSyntheticWallet(report, m_state), [this, activity](WalletModel* model) {
        m_model = model;
        activity->deleteLater();
    });
    when("the synthetic wallet", [this] { return !m_model.isNull(); }, [this] {
        for (WalletView* view : m_window->findChildren<WalletView*>()) {
            if (view->getWalletModel() == m_model) m_view = view;
        }
        if (m_view) m_send_dialog = m_view->findChild<SendCoinsDialog*>();
        QUIT_CHECK(m_send_dialog);
        if (!m_send_dialog) {
            sendQuitEvent();
            return;
        }
        connect(m_send_dialog, &SendCoinsDialog::coinsSent, this, [this] { ++m_coins_sent; });

        if (m_scenario == "send-confirmation") return startSendConfirmation();
        if (m_scenario == "psbt-copied") return startPSBTCopied();
        if (m_scenario == "pqc-warning") return startPQCWarning();
        if (m_scenario == "passphrase") return startPassphrase();
        if (m_scenario == "same-pass") return startSamePass();
        if (m_scenario == "encryption") return startEncryption();
        if (m_scenario == "psbt-signing") return startPSBTSigning();
        if (m_scenario == "unload-under-progress") return startUnloadUnderProgress();
        if (m_scenario == "popups") return startPopups();
        QTest::qFail(qPrintable(QStringLiteral("Unknown scenario %1").arg(m_scenario)), __FILE__, __LINE__);
        sendQuitEvent();
    });
}

//! Quit while the send confirmation waits for an answer, then cancel the send.
void QuitModalScenario::startSendConfirmation()
{
    when("the send confirmation", [] { return FindConfirmation(); }, [this] {
        sendQuitEvent();
        expectDeferred("The platform Quit event");
        triggerQuitAction();
        expectDeferred("File > Exit");
        after(RETRY_SPAN, [this] {
            expectDeferred("A retried quit");
            ClickButton(FindConfirmation(), QMessageBox::Cancel);
            expectShutdown();
        });
    });
    pressSend();
}

//! Quit while the "PSBT copied" box of "Create Unsigned" is open, then
//! discard the PSBT.
void QuitModalScenario::startPSBTCopied()
{
    when("the send confirmation", [] { return FindConfirmation(); }, [this] {
        when("the PSBT copied box", [] { return FindPSBTCopiedBox(); }, [this] {
            triggerQuitAction();
            expectDeferred("File > Exit");
            sendQuitEvent();
            expectDeferred("The platform Quit event");
            after(RETRY_SPAN, [this] {
                expectDeferred("A retried quit");
                ClickButton(FindPSBTCopiedBox(), QMessageBox::Discard);
                expectShutdown();
            });
        });
        // The wallet has no private keys, so the confirmation offers
        // "Create Unsigned".
        ClickButton(FindConfirmation(), QMessageBox::Save);
    });
    pressSend();
}

//! Confirm a send whose signing advanced a PQC key into its warning range,
//! then quit while the warning shown after the broadcast is open.
void QuitModalScenario::startPQCWarning()
{
    when("the send confirmation", [] { return FindConfirmation(); }, [this] {
        when("the PQC usage warning", [] { return FindMessageBox(QStringLiteral("PQC usage warning")); }, [this] {
            QUIT_CHECK(m_coins_sent == 1);
            sendQuitEvent();
            expectDeferred("The platform Quit event");
            after(RETRY_SPAN, [this] {
                expectDeferred("A retried quit");
                ClickButton(FindMessageBox(QStringLiteral("PQC usage warning")), QMessageBox::Ok);
                expectShutdown();
            });
        });
        ClickButton(FindConfirmation(), QMessageBox::Yes);
    });
    pressSend();
}

//! Quit while the passphrase prompt of a send from a locked wallet is open,
//! then cancel the prompt.
void QuitModalScenario::startPassphrase()
{
    when("the passphrase prompt", [] { return FindDialog("AskPassphraseDialog"); }, [this] {
        sendQuitEvent();
        expectDeferred("The platform Quit event");
        triggerQuitAction();
        expectDeferred("File > Exit");
        after(RETRY_SPAN, [this] {
            expectDeferred("A retried quit");
            QDialog* const prompt{FindDialog("AskPassphraseDialog")};
            QUIT_CHECK(prompt);
            if (prompt) prompt->reject();
            expectShutdown();
        });
    });
    // Returns once the prompt is answered.
    pressSend();
}

//! Close the send confirmation and quit in the same event pass: done() hides
//! the dialog at once, but its exec() returns only after this pass.
void QuitModalScenario::startSamePass()
{
    when("the send confirmation", [] { return FindConfirmation(); }, [this] {
        QMessageBox* const confirmation{FindConfirmation()};
        confirmation->done(QMessageBox::Cancel);
        QUIT_CHECK(!confirmation->isVisible());
        QUIT_CHECK(QApplication::activeModalWidget() == nullptr);
        sendQuitEvent();
        expectDeferred("The platform Quit event in the pass that closed the dialog");
        expectShutdown();
    });
    pressSend();
}

//! Quit while the wallet is being encrypted (#174 C4 a). Encryption cannot be
//! cancelled, so the shutdown waits for it and for the user to read its
//! result.
void QuitModalScenario::startEncryption()
{
    m_view->encryptWallet();
    when("the encryption prompt", [] { return FindDialog("AskPassphraseDialog"); }, [this] {
        QDialog* const prompt{FindDialog("AskPassphraseDialog")};
        prompt->findChild<QLineEdit*>("passEdit2")->setText(QStringLiteral("quit-modal"));
        prompt->findChild<QLineEdit*>("passEdit3")->setText(QStringLiteral("quit-modal"));
        when("the encryption confirmation", [] { return FindMessageBox(QStringLiteral("Confirm wallet encryption")); }, [] {
            ClickButton(FindMessageBox(QStringLiteral("Confirm wallet encryption")), QMessageBox::Yes);
        });
        // Returns once the encryption has started.
        prompt->accept();
        when("the encryption to start", [this] { return ReadState(m_state, [](const auto& s) { return s.encrypt_entered; }); }, [this] {
            sendQuitEvent();
            expectDeferred("The platform Quit event");
            after(RETRY_SPAN, [this] {
                expectDeferred("A retried quit");
                QUIT_CHECK(ReadState(m_state, [](const auto& s) { return s.encrypt_in_progress; }));
                when("the encryption result", [] { return FindMessageBox(QStringLiteral("Wallet encrypted")); }, [this] {
                    expectDeferred("A retried quit");
                    ClickButton(FindMessageBox(QStringLiteral("Wallet encrypted")), QMessageBox::Ok);
                    expectShutdown();
                });
                Allow(m_state, &qt_test::SyntheticWalletState::allow_encrypt);
            });
        });
    });
}

//! Quit while a PSBT is being signed after its signing counters were
//! reserved (#174 C4 c). Signing cannot be cancelled then, so the shutdown
//! waits for it and for the user to close the PSBT dialog.
void QuitModalScenario::startPSBTSigning()
{
    m_window->setCurrentWallet(m_model);
    DataStream stream;
    stream << MakeUnsignedPSBT();
    QApplication::clipboard()->setText(QString::fromStdString(EncodeBase64(stream.str())));
    QUIT_CHECK(QMetaObject::invokeMethod(m_window, "gotoLoadPSBT", Q_ARG(bool, true)));
    const auto find_button{[](const char* name) -> QPushButton* {
        QDialog* const dialog{FindDialog("PSBTOperationsDialog")};
        return dialog ? dialog->findChild<QPushButton*>(name) : nullptr;
    }};
    when("the PSBT dialog", [find_button] {
        QPushButton* const sign{find_button("signTransactionButton")};
        return sign && sign->isEnabled();
    }, [this, find_button] {
        find_button("signTransactionButton")->click();
        when("the signing counters", [this] { return ReadState(m_state, [](const auto& s) { return s.psbt_counters_reserved; }); }, [this, find_button] {
            sendQuitEvent();
            expectDeferred("The platform Quit event");
            after(RETRY_SPAN, [this, find_button] {
                expectDeferred("A retried quit");
                when("the signing result", [find_button] {
                    QPushButton* const broadcast{find_button("broadcastTransactionButton")};
                    return broadcast && broadcast->isEnabled();
                }, [this, find_button] {
                    expectDeferred("A retried quit");
                    find_button("closeButton")->click();
                    expectShutdown();
                });
                Allow(m_state, &qt_test::SyntheticWalletState::allow_psbt_completion);
            });
        });
    });
}

//! A wallet rescan, for example one started over RPC, shows its progress
//! dialog on top of the send confirmation, and then the wallet is unloaded,
//! for example by unloadwallet. The unload waits for the confirmation.
void QuitModalScenario::startUnloadUnderProgress()
{
    when("the send confirmation", [] { return FindConfirmation(); }, [this] {
        Q_EMIT m_model->showProgress(RESCAN_TITLE, 0);
        QProgressDialog* progress{nullptr};
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            auto* const dialog{qobject_cast<QProgressDialog*>(widget)};
            if (dialog && dialog->labelText() == RESCAN_TITLE) progress = dialog;
        }
        QUIT_CHECK(progress);
        if (!progress) {
            sendQuitEvent();
            return;
        }
        // The dialog shows itself once the rescan has run for a while.
        progress->show();
        QUIT_CHECK(QApplication::activeModalWidget() == progress);
        Q_EMIT m_model->unload();
        after(RETRY_SPAN, [this] {
            QUIT_CHECK(m_view && m_model);
            if (m_model) Q_EMIT m_model->showProgress(RESCAN_TITLE, 100);
            ClickButton(FindConfirmation(), QMessageBox::Cancel);
            when("the deferred unload", [this] { return !m_view && !m_model; }, [this] {
                QUIT_CHECK(m_shutdown_requests == 0);
                // No dialog is open any more, so the quit runs at once.
                sendQuitEvent();
                QUIT_CHECK(m_shutdown_requests == 1);
                expectShutdown();
            });
        });
    });
    pressSend();
}

//! Quit while the node console's command completer and a context menu shown
//! with QMenu::popup() are open. Neither runs a nested event loop, so the
//! shutdown runs at once and deletes the menu with its wallet view.
void QuitModalScenario::startPopups()
{
    m_window->findChild<QAction*>("openRPCConsoleAction")->activate(QAction::Trigger);
    when("the node console", [] { return FindVisible([](QWidget* widget) { return widget->inherits("RPCConsole"); }); }, [this] {
        QWidget* const console{FindVisible([](QWidget* widget) { return widget->inherits("RPCConsole"); })};
        QLineEdit* const line_edit{console->findChild<QLineEdit*>("lineEdit")};
        QUIT_CHECK(line_edit && line_edit->completer());
        if (!line_edit || !line_edit->completer()) {
            sendQuitEvent();
            return;
        }
        QTest::keyClicks(line_edit, "getblockchain");
        QWidget* const completions{line_edit->completer()->popup()};
        QUIT_CHECK(completions->isVisible());

        auto* const menu{new QMenu(m_send_dialog)};
        menu->addAction(QStringLiteral("Copy"));
        menu->popup(m_send_dialog->mapToGlobal(QPoint{}));
        QUIT_CHECK(menu->isVisible());
        QUIT_CHECK(QApplication::activePopupWidget() != nullptr);
        QUIT_CHECK(completions->isVisible());

        sendQuitEvent();
        QUIT_CHECK(m_shutdown_requests == 1);
        expectShutdown();
    });
}

void QuitModalScenario::pressSend()
{
    m_model->pollBalanceChanged();
    QVBoxLayout* const entries{m_send_dialog->findChild<QVBoxLayout*>("entries")};
    SendCoinsEntry* const entry{qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget())};
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(QString::fromStdString(EncodeDestination(WitnessV2P2MR{})));
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(COIN);
    m_send_dialog->getCoinControl()->Select(COutPoint{Txid{}, 0});
    QUIT_CHECK(QMetaObject::invokeMethod(m_send_dialog, "sendButtonClicked", Q_ARG(bool, false)));
}

void QuitModalScenario::when(const char* what, std::function<bool()> ready, std::function<void()> action)
{
    auto* const poll{new QTimer(this)};
    const auto deadline{std::chrono::steady_clock::now() + STEP_TIMEOUT};
    connect(poll, &QTimer::timeout, this, [poll, what, deadline, ready = std::move(ready), action = std::move(action)] {
        if (!ready()) {
            if (std::chrono::steady_clock::now() > deadline) qFatal("Timed out waiting for %s", what);
            return;
        }
        poll->stop();
        poll->deleteLater();
        action();
    });
    poll->start(10ms);
}

void QuitModalScenario::after(std::chrono::milliseconds delay, std::function<void()> action)
{
    QTimer::singleShot(delay, this, std::move(action));
}

void QuitModalScenario::sendQuitEvent()
{
    QEvent quit{QEvent::Quit};
    QUIT_CHECK(QCoreApplication::sendEvent(&m_app, &quit));
}

void QuitModalScenario::triggerQuitAction()
{
    if (m_quit_action) m_quit_action->trigger();
}

void QuitModalScenario::expectDeferred(const char* trigger)
{
    if (m_shutdown_requests == 0 && m_view && m_model) return;
    QTest::qFail(qPrintable(QStringLiteral("%1 started the shutdown while the user was in a dialog").arg(trigger)), __FILE__, __LINE__);
}

void QuitModalScenario::expectShutdown()
{
    m_flow_finished = true;
    when("the deferred shutdown", [this] { return m_shutdown_requests > 0; }, [] {});
}
