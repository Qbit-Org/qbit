// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/apptests.h>

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <key.h>
#include <logging.h>
#include <qt/bitcoin.h>
#include <qt/bitcoingui.h>
#include <qt/networkstyle.h>
#include <qt/rpcconsole.h>
#include <test/util/setup_common.h>
#include <validation.h>

#ifdef ENABLE_WALLET
#include <common/args.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <qt/bitcoinamountfield.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendcoinsentry.h>
#include <qt/test/syntheticwallet.h>
#include <qt/walletcontroller.h>
#include <qt/walletview.h>
#include <univalue.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>
#endif // ENABLE_WALLET

#include <chrono>
#include <thread>

#include <QAction>
#include <QDialogButtonBox>
#include <QElapsedTimer>
#include <QEvent>
#include <QEventLoop>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QScopedPointer>
#include <QSignalSpy>
#include <QString>
#include <QTest>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <QtGlobal>
#include <QtTest/QtTestWidgets>
#include <QtTest/QtTestGui>

namespace {
using namespace std::chrono_literals;

#ifdef ENABLE_WALLET
class TestWalletAdoptionActivity : public WalletControllerActivity
{
public:
    using WalletControllerActivity::WalletControllerActivity;

    void adopt(std::unique_ptr<interfaces::Wallet> wallet, std::function<void(WalletModel*)> callback)
    {
        scheduleWalletModel(std::move(wallet), std::move(callback));
    }
};

void AcceptWalletUnlock()
{
    QTimer::singleShot(0, qApp, [] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (!widget->inherits("AskPassphraseDialog")) continue;
            QLineEdit* const passphrase{widget->findChild<QLineEdit*>("passEdit1")};
            QDialogButtonBox* const buttons{widget->findChild<QDialogButtonBox*>("buttonBox")};
            if (!passphrase || !buttons) return;
            passphrase->setText("test-passphrase");
            buttons->button(QDialogButtonBox::Ok)->click();
            return;
        }
    });
}

void AcceptFeeBumpConfirmation()
{
    auto* timer{new QTimer(qApp)};
    timer->setInterval(10);
    QObject::connect(timer, &QTimer::timeout, timer, [timer] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (!widget->inherits("SendConfirmationDialog") || !widget->isVisible()) continue;
            auto* dialog{qobject_cast<QMessageBox*>(widget)};
            if (!dialog) return;
            QAbstractButton* const yes_button{dialog->button(QMessageBox::Yes)};
            if (!yes_button) return;
            yes_button->setEnabled(true);
            yes_button->click();
            timer->stop();
            timer->deleteLater();
            return;
        }
    });
    timer->start();
}

bool WaitForIrreversibleFeeBumpSigning(const std::shared_ptr<qt_test::SyntheticWalletState>& state, int timeout_ms)
{
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeout_ms) {
        {
            std::lock_guard lock{state->mutex};
            if (state->bump_sign_entered && state->bump_counters_reserved) return true;
        }
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        QTest::qWait(10);
    }
    std::lock_guard lock{state->mutex};
    return state->bump_sign_entered && state->bump_counters_reserved;
}
#endif // ENABLE_WALLET

//! Regex find a string group inside of the console output
QString FindInConsole(const QString& output, const QString& pattern)
{
    const QRegularExpression re(pattern);
    return re.match(output).captured(1);
}

//! Call getblockchaininfo RPC and check first field of JSON output.
void TestRpcCommand(RPCConsole* console)
{
    QTextEdit* messagesWidget = console->findChild<QTextEdit*>("messagesWidget");
    QLineEdit* lineEdit = console->findChild<QLineEdit*>("lineEdit");
    QSignalSpy mw_spy(messagesWidget, &QTextEdit::textChanged);
    QVERIFY(mw_spy.isValid());
    QTest::keyClicks(lineEdit, "getblockchaininfo");
    QTest::keyClick(lineEdit, Qt::Key_Return);
    QVERIFY(mw_spy.wait(1000));
    QCOMPARE(mw_spy.count(), 4);
    const QString output = messagesWidget->toPlainText();
    const QString pattern = QStringLiteral("\"chain\": \"(\\w+)\"");
    QCOMPARE(FindInConsole(output, pattern), QString("regtest"));
}
} // namespace

//! Entry point for BitcoinApplication tests.
void AppTests::appTests()
{
#ifdef Q_OS_MACOS
    if (QApplication::platformName() == "minimal") {
        // Disable for mac on "minimal" platform to avoid crashes inside the Qt
        // framework when it tries to look up unimplemented cocoa functions,
        // and fails to handle returned nulls
        // (https://bugreports.qt.io/browse/QTBUG-49686).
        qWarning() << "Skipping AppTests on mac build with 'minimal' platform set due to Qt bugs. To run AppTests, invoke "
                      "with 'QT_QPA_PLATFORM=cocoa test_qbit-qt' on mac, or else use a linux or windows build.";
        return;
    }
#endif

    qRegisterMetaType<interfaces::BlockAndHeaderTipInfo>("interfaces::BlockAndHeaderTipInfo");
    m_app.parameterSetup();
    QVERIFY(m_app.createOptionsModel(/*resetSettings=*/true));
    QScopedPointer<const NetworkStyle> style(NetworkStyle::instantiate(Params().GetChainType()));
    m_app.setupPlatformStyle();
    m_app.createWindow(style.data());
    connect(&m_app, &BitcoinApplication::windowShown, this, &AppTests::guiTests);
    expectCallback("guiTests");
    m_app.baseInitialize();
    m_app.requestInitialize();
    m_app.exec();

#ifdef ENABLE_WALLET
    QVERIFY(m_shutdown_wallet_model);
    QVERIFY(m_shutdown_wallet_view);
    QVERIFY(m_shutdown_send_dialog);
    QVERIFY(m_shutdown_wallet_state);

    const auto state{m_shutdown_wallet_state};
    std::thread watchdog{[state] {
        std::unique_lock lock{state->mutex};
        if (!state->condition.wait_for(lock, 5s, [state] {
                return state->create_finished || state->shutdown_complete;
            })) {
            state->watchdog_released = true;
            state->allow_create = true;
            lock.unlock();
            state->condition.notify_all();
        }
    }};
    std::thread bump_signer_release{[state] {
        std::this_thread::sleep_for(100ms);
        {
            std::lock_guard lock{state->mutex};
            state->allow_bump_sign = true;
        }
        state->condition.notify_all();
    }};

    QElapsedTimer shutdown_timer;
    shutdown_timer.start();
    QEvent quit_event{QEvent::Quit};
    const bool quit_delivered{QCoreApplication::sendEvent(&m_app, &quit_event)};
    m_shutdown_elapsed_ms = shutdown_timer.elapsed();

    {
        std::lock_guard lock{state->mutex};
        state->shutdown_complete = true;
        state->allow_create = true;
    }
    state->condition.notify_all();
    watchdog.join();
    bump_signer_release.join();

    bool worker_destroyed{false};
    {
        std::unique_lock lock{state->mutex};
        worker_destroyed = state->condition.wait_for(lock, 5s, [state] {
            return state->background_clone_destroyed;
        });
    }
#else
    m_app.requestShutdown();
#endif // ENABLE_WALLET
    m_app.exec();

#ifdef ENABLE_WALLET
    bool cancel_observed{false};
    bool watchdog_released{false};
    bool locked{false};
    bool bump_committed{false};
    bool bump_cancel_observed{false};
    int lock_calls{0};
    int unlock_calls{0};
    {
        std::lock_guard lock{state->mutex};
        cancel_observed = state->cancel_observed;
        watchdog_released = state->watchdog_released;
        locked = state->locked;
        bump_committed = state->bump_committed;
        bump_cancel_observed = state->bump_cancel_observed;
        lock_calls = state->lock_calls;
        unlock_calls = state->unlock_calls;
    }
    QVERIFY(quit_delivered);
    QVERIFY2(m_shutdown_elapsed_ms < 5000, "Qt wallet shutdown exceeded the five-second bound");
    QVERIFY(!watchdog_released);
    QVERIFY(cancel_observed);
    QVERIFY(bump_committed);
    QVERIFY(!bump_cancel_observed);
    QVERIFY(worker_destroyed);
    QVERIFY(m_shutdown_wallet_model.isNull());
    QVERIFY(m_shutdown_wallet_view.isNull());
    QVERIFY(m_shutdown_send_dialog.isNull());
    QVERIFY(m_wallet_dependents_destroyed_before_model);
    QVERIFY(locked);
    QCOMPARE(unlock_calls, 1);
    QCOMPARE(lock_calls, 1);
    QCOMPARE(m_shutdown_coins_sent, 0);
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        QVERIFY(!widget->inherits("SendConfirmationDialog"));
    }
#endif // ENABLE_WALLET
}

void AppTests::cleanup()
{
#ifdef ENABLE_WALLET
    bool settings_written{true};
    if (m_remove_test_wallet_settings) {
        // WalletLoader::createWallet persists startup entries. Remove
        // test-only entries so later options tests see their original fixture.
        gArgs.LockSettings([](common::Settings& settings) {
            settings.rw_settings.erase("wallet");
        });
        settings_written = gArgs.WriteSettingsFile();
        m_remove_test_wallet_settings = false;
    }
#endif // ENABLE_WALLET

    // Reset global state even when a QVERIFY returns early from appTests().
    LogInstance().DisconnectTestLogger();

#ifdef ENABLE_WALLET
    QVERIFY(settings_written);
#endif // ENABLE_WALLET
}

//! Entry point for BitcoinGUI tests.
void AppTests::guiTests(BitcoinGUI* window)
{
    HandleCallback callback{"guiTests", *this};

#ifdef ENABLE_WALLET
    WalletController* const controller{window->getWalletController()};
    QVERIFY(controller);

    m_remove_test_wallet_settings = true;
    for (const std::string name : {"qt-shutdown-lifetime-1", "qt-shutdown-lifetime-2"}) {
        QSignalSpy wallet_added_spy(controller, &WalletController::walletAdded);
        QVERIFY(wallet_added_spy.isValid());
        WalletModel* wallet_model{nullptr};
        QObject wallet_added_context;
        connect(
            controller,
            &WalletController::walletAdded,
            &wallet_added_context,
            [&](WalletModel* model) { wallet_model = model; });
        std::vector<bilingual_str> warnings;
        auto wallet{m_app.node().walletLoader().createWallet(
            name,
            SecureString{},
            wallet::WALLET_FLAG_DESCRIPTORS | wallet::WALLET_FLAG_BLANK_WALLET,
            warnings)};
        QVERIFY(wallet);
        if (!wallet_model) QVERIFY(wallet_added_spy.wait(5000));
        QVERIFY(wallet_model);
    }

    m_shutdown_wallet_state = std::make_shared<qt_test::SyntheticWalletState>();
    {
        std::lock_guard lock{m_shutdown_wallet_state->mutex};
        m_shutdown_wallet_state->allow_create = false;
        m_shutdown_wallet_state->wait_for_cancel = true;
        m_shutdown_wallet_state->encrypted = true;
        m_shutdown_wallet_state->locked = true;
        m_shutdown_wallet_state->bump_enabled = true;
        m_shutdown_wallet_state->allow_bump_sign = false;
    }

    QSignalSpy wallet_added_spy(controller, &WalletController::walletAdded);
    QVERIFY(wallet_added_spy.isValid());
    auto* adoption_activity{new TestWalletAdoptionActivity(controller, window)};
    adoption_activity->adopt(
        qt_test::MakeSyntheticWallet(wallet::PQCUsageReport{}, m_shutdown_wallet_state),
        [this, adoption_activity](WalletModel* model) {
            m_shutdown_wallet_model = model;
            adoption_activity->deleteLater();
        });
    if (!m_shutdown_wallet_model) QVERIFY(wallet_added_spy.wait(5000));
    QVERIFY(m_shutdown_wallet_model);

    for (WalletView* wallet_view : window->findChildren<WalletView*>()) {
        if (wallet_view->getWalletModel() == m_shutdown_wallet_model) {
            m_shutdown_wallet_view = wallet_view;
            m_shutdown_send_dialog = wallet_view->findChild<SendCoinsDialog*>();
            break;
        }
    }
    QVERIFY(m_shutdown_wallet_view);
    QVERIFY(m_shutdown_send_dialog);
    connect(m_shutdown_wallet_model, &QObject::destroyed, this, [this] {
        m_wallet_dependents_destroyed_before_model =
            m_shutdown_wallet_view.isNull() && m_shutdown_send_dialog.isNull();
    });
    connect(m_shutdown_send_dialog, &SendCoinsDialog::coinsSent, this, [this] {
        ++m_shutdown_coins_sent;
    });

    m_shutdown_wallet_model->pollBalanceChanged();
    QVBoxLayout* const entries{m_shutdown_send_dialog->findChild<QVBoxLayout*>("entries")};
    QVERIFY(entries);
    SendCoinsEntry* const entry{qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget())};
    QVERIFY(entry);
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(QString::fromStdString(EncodeDestination(WitnessV2P2MR{})));
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(COIN);
    m_shutdown_send_dialog->getCoinControl()->Select(COutPoint{Txid{}, 0});
    QVERIFY(entry->validate(m_app.node()));
    QVERIFY(m_shutdown_send_dialog->getCoinControl()->HasSelected());
    QCOMPARE(
        m_shutdown_wallet_model->wallet().getAvailableBalance(*m_shutdown_send_dialog->getCoinControl()),
        50 * COIN);

    AcceptWalletUnlock();
    QVERIFY(QMetaObject::invokeMethod(m_shutdown_send_dialog, "sendButtonClicked", Q_ARG(bool, false)));
    {
        std::unique_lock lock{m_shutdown_wallet_state->mutex};
        QVERIFY(m_shutdown_wallet_state->condition.wait_for(lock, 5s, [this] {
            return m_shutdown_wallet_state->create_entered;
        }));
        QCOMPARE(m_shutdown_wallet_state->unlock_calls, 1);
        QVERIFY(!m_shutdown_wallet_state->locked);
    }

    AcceptFeeBumpConfirmation();
    QVERIFY(m_shutdown_wallet_model->bumpFee(Txid{}));
    QVERIFY(WaitForIrreversibleFeeBumpSigning(m_shutdown_wallet_state, 5000));

    QCOMPARE(window->findChildren<WalletView*>().size(), 3);
#endif // ENABLE_WALLET

    connect(window, &BitcoinGUI::consoleShown, this, &AppTests::consoleTests);
    expectCallback("consoleTests");
    QAction* action = window->findChild<QAction*>("openRPCConsoleAction");
    action->activate(QAction::Trigger);
}

//! Entry point for RPCConsole tests.
void AppTests::consoleTests(RPCConsole* console)
{
    HandleCallback callback{"consoleTests", *this};
#ifdef ENABLE_WALLET
    console->setCurrentWallet(nullptr);
#endif // ENABLE_WALLET
    TestRpcCommand(console);
}

//! Destructor to shut down after the last expected callback completes.
AppTests::HandleCallback::~HandleCallback()
{
    auto& callbacks = m_app_tests.m_callbacks;
    auto it = callbacks.find(m_callback);
    assert(it != callbacks.end());
    callbacks.erase(it);
    if (callbacks.empty()) {
        m_app_tests.m_app.exit(0);
    }
}
