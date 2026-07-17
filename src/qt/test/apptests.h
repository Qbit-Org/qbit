// Copyright (c) 2018-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_APPTESTS_H
#define QBIT_QT_TEST_APPTESTS_H

#include <QObject>
#include <QPointer>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <utility>

class BitcoinApplication;
class BitcoinGUI;
class RPCConsole;
class SendCoinsDialog;
class WalletModel;
class WalletView;

namespace qt_test {
struct SyntheticWalletState;
}

class AppTests : public QObject
{
    Q_OBJECT
public:
    explicit AppTests(BitcoinApplication& app) : m_app(app) {}

private Q_SLOTS:
    void appTests();
    void cleanup();
    void guiTests(BitcoinGUI* window);
    void consoleTests(RPCConsole* console);

private:
    //! Add expected callback name to list of pending callbacks.
    void expectCallback(std::string callback) { m_callbacks.emplace(std::move(callback)); }

    //! RAII helper to remove no-longer-pending callback.
    struct HandleCallback
    {
        std::string m_callback;
        AppTests& m_app_tests;
        ~HandleCallback();
    };

    //! Bitcoin application.
    BitcoinApplication& m_app;

    //! Set of pending callback names. Used to track expected callbacks and shut
    //! down the app after the last callback has been handled and all tests have
    //! either run or thrown exceptions. This could be a simple int counter
    //! instead of a set of names, but the names might be useful for debugging.
    std::multiset<std::string> m_callbacks;

    QPointer<WalletModel> m_shutdown_wallet_model;
    QPointer<WalletView> m_shutdown_wallet_view;
    QPointer<SendCoinsDialog> m_shutdown_send_dialog;
    std::shared_ptr<qt_test::SyntheticWalletState> m_shutdown_wallet_state;
    int64_t m_shutdown_elapsed_ms{-1};
    int m_shutdown_coins_sent{0};
    bool m_wallet_dependents_destroyed_before_model{false};
    bool m_remove_test_wallet_settings{false};
};

#endif // QBIT_QT_TEST_APPTESTS_H
