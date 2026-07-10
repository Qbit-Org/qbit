// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/apptests.h>

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <common/args.h>
#include <interfaces/wallet.h>
#include <key.h>
#include <logging.h>
#include <qt/bitcoin.h>
#include <qt/bitcoingui.h>
#include <qt/networkstyle.h>
#include <qt/rpcconsole.h>
#include <qt/sendcoinsdialog.h>
#include <qt/walletcontroller.h>
#include <qt/walletview.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <validation.h>
#include <wallet/wallet.h>

#include <QAction>
#include <QLineEdit>
#include <QRegularExpression>
#include <QScopedPointer>
#include <QSignalSpy>
#include <QString>
#include <QTest>
#include <QTextEdit>
#include <QtGlobal>
#include <QtTest/QtTestWidgets>
#include <QtTest/QtTestGui>

namespace {
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
#endif // ENABLE_WALLET
    m_app.requestShutdown();
#ifdef ENABLE_WALLET
    QVERIFY(m_shutdown_wallet_model.isNull());
    QVERIFY(m_shutdown_wallet_view.isNull());
    QVERIFY(m_shutdown_send_dialog.isNull());
    QVERIFY(m_wallet_dependents_destroyed_before_model);
#endif // ENABLE_WALLET
    m_app.exec();

#ifdef ENABLE_WALLET
    // WalletLoader::createWallet persists startup entries. Remove test-only
    // entries so later options tests see their original settings fixture.
    gArgs.LockSettings([](common::Settings& settings) {
        settings.rw_settings.erase("wallet");
    });
    QVERIFY(gArgs.WriteSettingsFile());
#endif // ENABLE_WALLET

    // Reset global state to avoid interfering with later tests.
    LogInstance().DisconnectTestLogger();
}

//! Entry point for BitcoinGUI tests.
void AppTests::guiTests(BitcoinGUI* window)
{
    HandleCallback callback{"guiTests", *this};

#ifdef ENABLE_WALLET
    WalletController* const controller{window->getWalletController()};
    QVERIFY(controller);

    for (const std::string name : {"qt-shutdown-lifetime-1", "qt-shutdown-lifetime-2"}) {
        std::vector<bilingual_str> warnings;
        auto wallet{m_app.node().walletLoader().createWallet(
            name,
            SecureString{},
            wallet::WALLET_FLAG_DESCRIPTORS | wallet::WALLET_FLAG_BLANK_WALLET,
            warnings)};
        QVERIFY(wallet);
        WalletModel* const wallet_model{controller->getOrCreateWallet(std::move(*wallet))};
        QVERIFY(wallet_model);

        if (!m_shutdown_wallet_model) {
            m_shutdown_wallet_model = wallet_model;
            for (WalletView* wallet_view : window->findChildren<WalletView*>()) {
                if (wallet_view->getWalletModel() == wallet_model) {
                    m_shutdown_wallet_view = wallet_view;
                    m_shutdown_send_dialog = wallet_view->findChild<SendCoinsDialog*>();
                    break;
                }
            }
            QVERIFY(m_shutdown_wallet_view);
            QVERIFY(m_shutdown_send_dialog);
            connect(wallet_model, &QObject::destroyed, this, [this] {
                m_wallet_dependents_destroyed_before_model =
                    m_shutdown_wallet_view.isNull() && m_shutdown_send_dialog.isNull();
            });
        }
    }
    QCOMPARE(window->findChildren<WalletView*>().size(), 2);
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
