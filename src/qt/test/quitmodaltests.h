// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_QUITMODALTESTS_H
#define QBIT_QT_TEST_QUITMODALTESTS_H

#include <QObject>
#include <QPointer>
#include <QString>

#include <chrono>
#include <functional>
#include <memory>
#include <thread>

class BitcoinApplication;
class BitcoinGUI;
class QAction;
class SendCoinsDialog;
class WalletModel;
class WalletView;

namespace qt_test {
struct SyntheticWalletState;
}

/**
 * Quit requests made while the user is in a dialog: the platform's Quit event
 * and File > Exit, which the tray menu's Exit also triggers. An application
 * shuts down only once per process, so each scenario runs in a child process
 * of this test binary.
 */
class QuitModalTests : public QObject
{
    Q_OBJECT
public:
    //! Environment variable that makes the test binary run one scenario.
    static constexpr const char* SCENARIO_ENV{"QBIT_QT_TEST_QUIT_SCENARIO"};

    //! Run one scenario on the application. Returns the number of failures.
    static int RunScenario(BitcoinApplication& app, const QString& scenario);

private Q_SLOTS:
    void pendingOnlyInNestedLoop();
    void quitDuringDialog_data();
    void quitDuringDialog();
};

//! One application lifecycle in a child process: start the app with a
//! synthetic wallet, request a quit while a dialog is open, then let the user
//! finish the dialog and check that the shutdown runs once afterwards.
class QuitModalScenario : public QObject
{
    Q_OBJECT
public:
    QuitModalScenario(BitcoinApplication& app, QString scenario);

private Q_SLOTS:
    void quitDuringDialog();

private:
    void start(BitcoinGUI* window);
    void startSendConfirmation();
    void startPSBTCopied();
    void startPQCWarning();
    void startPassphrase();
    void startSamePass();
    void startEncryption();
    void startPSBTSigning();
    void startUnloadUnderProgress();
    void startUnloadAsyncDialog();
    void startUnloadCoinControl();
    void startNativeDialog();
    void startPopups();
    void startUnloadRescanStop();

    //! Open the PSBT dialog on an unsigned PSBT from the clipboard.
    void openPSBTDialog();
    //! Fill in a payment and press Send.
    void pressSend();
    //! Run action once ready() holds, polling from whichever event loop runs.
    void when(const char* what, std::function<bool()> ready, std::function<void()> action);
    //! Run action after delay, from whichever event loop runs then.
    void after(std::chrono::milliseconds delay, std::function<void()> action);
    void sendQuitEvent();
    void triggerQuitAction();
    //! Check that the quit requested so far has not started the shutdown.
    void expectDeferred(const char* trigger);
    //! The last user action is done; expect the deferred shutdown next.
    void expectShutdown();

    BitcoinApplication& m_app;
    const QString m_scenario;
    BitcoinGUI* m_window{nullptr};
    QAction* m_quit_action{nullptr};
    std::shared_ptr<qt_test::SyntheticWalletState> m_state;
    QPointer<WalletModel> m_model;
    QPointer<WalletView> m_view;
    QPointer<SendCoinsDialog> m_send_dialog;
    //! Releases a held wallet worker if the scenario does not.
    std::thread m_latch_release;
    int m_shutdown_requests{0};
    int m_windows_shown{0};
    //! Set once the requests made during the node shutdown have been sent.
    bool m_shutdown_probed{false};
    int m_coins_sent{0};
    bool m_flow_finished{false};
};

#endif // QBIT_QT_TEST_QUITMODALTESTS_H
