// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/walletcontrollertests.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#include <util/chaintype.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <vector>

#include <QApplication>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QTest>
#include <QThread>

using namespace std::chrono_literals;
using wallet::WALLET_FLAG_DESCRIPTORS;

namespace {
template <typename Predicate>
bool WaitUntil(Predicate&& predicate, int timeout_ms = 5000)
{
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeout_ms) {
        if (predicate()) return true;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        QTest::qWait(10);
    }
    return predicate();
}

bool WaitForNotificationWithoutEvents(std::future<void>& notification)
{
    const bool completed_without_events{notification.wait_for(5s) == std::future_status::ready};
    if (!completed_without_events) {
        // Let the vulnerable implementation service its blocking GUI call so a
        // failed regression assertion does not strand the test process.
        QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
    }
    notification.wait();
    return completed_without_events;
}

util::Result<std::unique_ptr<interfaces::Wallet>> CreateTestWallet(interfaces::WalletLoader& loader, const std::string& name)
{
    std::vector<bilingual_str> warnings;
    return loader.createWallet(name, SecureString{}, WALLET_FLAG_DESCRIPTORS, warnings);
}
} // namespace

void WalletControllerTests::notificationDoesNotBlockGuiThread()
{
    wallet::WalletTestingSetup setup{ChainType::REGTEST};
    setup.m_node.wallet_loader = setup.m_wallet_loader.get();
    m_node.setContext(&setup.m_node);

    auto wallet_result{CreateTestWallet(m_node.walletLoader(), "wallet-controller-notification")};
    QVERIFY(wallet_result.has_value());
    wallet::WalletContext& context{*m_node.walletLoader().context()};
    const auto core_wallet{wallet::GetWallet(context, "wallet-controller-notification")};
    QVERIFY(core_wallet);

    OptionsModel options_model{m_node};
    bilingual_str error;
    QVERIFY(options_model.Init(error));
    ClientModel client_model{m_node, &options_model};
    const std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    auto controller{std::make_unique<WalletController>(client_model, platform_style.get(), nullptr)};

    int added_count{0};
    WalletModel* added_model{nullptr};
    connect(controller.get(), &WalletController::walletAdded, controller.get(), [&](WalletModel* model) {
        ++added_count;
        added_model = model;
    });

    auto notification{std::async(std::launch::async, [&] {
        wallet::NotifyWalletLoaded(context, core_wallet);
    })};
    const bool completed_without_events{WaitForNotificationWithoutEvents(notification)};
    QVERIFY2(completed_without_events, "Wallet notification synchronously waited for the GUI thread");

    QVERIFY(WaitUntil([&] { return added_count == 1; }));
    QCOMPARE(added_count, 1);
    QVERIFY(added_model);
    QCOMPARE(added_model->thread(), qApp->thread());
    QCOMPARE(added_model->parent(), controller.get());

    auto duplicate_notification{std::async(std::launch::async, [&] {
        wallet::NotifyWalletLoaded(context, core_wallet);
    })};
    QVERIFY(WaitForNotificationWithoutEvents(duplicate_notification));
    QCoreApplication::processEvents();
    QCOMPARE(added_count, 1);

    controller.reset();
    (*wallet_result)->remove();
}

void WalletControllerTests::shutdownDropsPendingAdoption()
{
    wallet::WalletTestingSetup setup{ChainType::REGTEST};
    setup.m_node.wallet_loader = setup.m_wallet_loader.get();
    m_node.setContext(&setup.m_node);

    auto wallet_result{CreateTestWallet(m_node.walletLoader(), "wallet-controller-shutdown")};
    QVERIFY(wallet_result.has_value());
    wallet::WalletContext& context{*m_node.walletLoader().context()};
    const auto core_wallet{wallet::GetWallet(context, "wallet-controller-shutdown")};
    QVERIFY(core_wallet);

    OptionsModel options_model{m_node};
    bilingual_str error;
    QVERIFY(options_model.Init(error));
    ClientModel client_model{m_node, &options_model};
    const std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    auto controller{std::make_unique<WalletController>(client_model, platform_style.get(), nullptr)};

    int added_count{0};
    connect(controller.get(), &WalletController::walletAdded, controller.get(), [&](WalletModel*) {
        ++added_count;
    });

    auto notification{std::async(std::launch::async, [&] {
        wallet::NotifyWalletLoaded(context, core_wallet);
    })};
    const bool completed_without_events{WaitForNotificationWithoutEvents(notification)};
    QVERIFY2(completed_without_events, "Wallet notification synchronously waited for the GUI thread");

    QElapsedTimer timer;
    timer.start();
    controller.reset();
    QVERIFY2(timer.elapsed() < 5000, "WalletController destruction exceeded the shutdown bound");

    QCoreApplication::processEvents();
    QCOMPARE(added_count, 0);

    (*wallet_result)->remove();
}

void WalletControllerTests::startupLoadFinishesAfterAdoption()
{
    wallet::WalletTestingSetup setup{ChainType::REGTEST};
    setup.m_node.wallet_loader = setup.m_wallet_loader.get();
    m_node.setContext(&setup.m_node);

    auto first_wallet{CreateTestWallet(m_node.walletLoader(), "wallet-controller-startup-one")};
    auto second_wallet{CreateTestWallet(m_node.walletLoader(), "wallet-controller-startup-two")};
    QVERIFY(first_wallet.has_value());
    QVERIFY(second_wallet.has_value());

    OptionsModel options_model{m_node};
    bilingual_str error;
    QVERIFY(options_model.Init(error));
    ClientModel client_model{m_node, &options_model};
    const std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    auto controller{std::make_unique<WalletController>(client_model, platform_style.get(), nullptr)};

    int added_count{0};
    int finished_count{0};
    int models_at_finish{-1};
    connect(controller.get(), &WalletController::walletAdded, controller.get(), [&](WalletModel*) {
        ++added_count;
    });

    auto activity = new LoadWalletsActivity(controller.get(), nullptr);
    connect(activity, &LoadWalletsActivity::finished, controller.get(), [&] {
        ++finished_count;
        models_at_finish = added_count;
    });
    activity->load(/*show_loading_minimized=*/false);

    QVERIFY(WaitUntil([&] { return finished_count == 1; }));
    QCOMPARE(finished_count, 1);
    QCOMPARE(added_count, 2);
    QCOMPARE(models_at_finish, 2);

    controller.reset();
    (*first_wallet)->remove();
    (*second_wallet)->remove();
}
