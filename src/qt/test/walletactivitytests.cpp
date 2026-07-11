// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/test/walletactivitytests.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#include <rpc/server.h>
#include <univalue.h>
#include <util/check.h>
#include <wallet/context.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <QCoreApplication>
#include <QDialog>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QPointer>
#include <QProgressDialog>
#include <QSignalSpy>
#include <QWidget>

namespace {
constexpr int WAIT_TIMEOUT_MS{30'000};
constexpr auto EXISTING_WALLET_NAME{"existing"};
constexpr auto CREATED_WALLET_NAME{"created"};

template <typename Predicate>
bool WaitUntil(Predicate&& predicate, int timeout_ms = WAIT_TIMEOUT_MS)
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

template <typename Predicate>
void WaitForActivityCompletion(Predicate&& completed)
{
    // Wallet creation is intentionally non-cancellable. If an assertion fails
    // while the worker is paused at a lifecycle latch, keep the GUI event loop
    // running until the activity has actually finished. Returning early would
    // let WalletController teardown wait on a worker that still needs queued
    // GUI work, masking the original failure with a test timeout.
    while (!completed()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        QTest::qWait(10);
    }
}

class CreateWalletStageLatch
{
public:
    explicit CreateWalletStageLatch(wallet::CreateWalletStage stage) : m_stage(stage) {}

    ~CreateWalletStageLatch() { release(); }

    void reach(wallet::CreateWalletStage stage)
    {
        if (stage != m_stage) return;

        std::unique_lock lock{m_mutex};
        m_reached = true;
        m_cv.notify_all();
        m_cv.wait(lock, [this] { return m_released; });
    }

    bool reached() const
    {
        std::lock_guard lock{m_mutex};
        return m_reached;
    }

    void release()
    {
        {
            std::lock_guard lock{m_mutex};
            m_released = true;
        }
        m_cv.notify_all();
    }

private:
    const wallet::CreateWalletStage m_stage;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_reached{false};
    bool m_released{false};
};

class TestProgressActivity final : public WalletControllerActivity
{
public:
    TestProgressActivity(WalletController* controller, QWidget* parent)
        : WalletControllerActivity(controller, parent)
    {
    }

    void show()
    {
        showProgressDialog(QStringLiteral("Test operation"), QStringLiteral("Testing operation…"));
    }
};

class ScopeExit
{
public:
    explicit ScopeExit(std::function<void()> cleanup) : m_cleanup(std::move(cleanup)) {}
    ~ScopeExit()
    {
        if (m_cleanup) m_cleanup();
    }

    void dismiss() { m_cleanup = {}; }

private:
    std::function<void()> m_cleanup;
};

std::set<std::string> RpcWalletNames(interfaces::Node& node, const std::string& command)
{
    UniValue result;
    try {
        result = node.executeRpc(command, UniValue{UniValue::VARR}, /*uri=*/"");
    } catch (const UniValue& error) {
        throw std::runtime_error{command + " RPC failed: " + error.write()};
    }
    const UniValue& wallets{command == "listwalletdir" ? result.find_value("wallets") : result};
    std::set<std::string> names;
    for (const UniValue& wallet : wallets.getValues()) {
        names.emplace(command == "listwalletdir" ? wallet.find_value("name").get_str() : wallet.get_str());
    }
    return names;
}

std::vector<std::string> StartupWalletNames(interfaces::Node& node)
{
    const common::SettingsValue setting{node.getPersistentSetting("wallet")};
    std::vector<std::string> names;
    if (!setting.isArray()) return names;
    for (const UniValue& wallet : setting.getValues()) {
        if (wallet.isStr()) names.push_back(wallet.get_str());
    }
    return names;
}

std::set<std::string> AsSet(const std::vector<std::string>& values)
{
    return {values.begin(), values.end()};
}

void ConfigureNode(interfaces::Node& node, wallet::WalletTestingSetup& setup)
{
    setup.m_node.wallet_loader = setup.m_wallet_loader.get();
    node.setContext(&setup.m_node);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
}

struct QtWalletModels {
    explicit QtWalletModels(interfaces::Node& node, const PlatformStyle* platform_style)
        : options_model{std::make_unique<OptionsModel>(node)}
    {
        bilingual_str error;
        if (!options_model->Init(error)) {
            throw std::runtime_error{"Failed to initialize Qt options: " + error.original};
        }
        client_model = std::make_unique<ClientModel>(node, options_model.get());
        controller = std::make_unique<WalletController>(*client_model, platform_style, nullptr);
    }

    void reset()
    {
        controller.reset();
        client_model.reset();
        options_model.reset();
    }

    std::unique_ptr<OptionsModel> options_model;
    std::unique_ptr<ClientModel> client_model;
    std::unique_ptr<WalletController> controller;
};
} // namespace

void WalletActivityTests::createWalletProgress_data()
{
    QTest::addColumn<int>("stage_value");
    QTest::addColumn<bool>("use_escape");

    const std::vector<std::pair<const char*, wallet::CreateWalletStage>> stages{
        {"before-database", wallet::CreateWalletStage::BEFORE_DATABASE_CREATION},
        {"during-encryption", wallet::CreateWalletStage::ENCRYPTION_COMMITTED_BEFORE_FINAL_DESCRIPTORS},
        {"before-load-notification", wallet::CreateWalletStage::BEFORE_LOAD_NOTIFICATION},
        {"before-created-signal", wallet::CreateWalletStage::MODEL_ADOPTED_BEFORE_CREATED_SIGNAL},
    };
    for (const auto& [name, stage] : stages) {
        QTest::newRow((std::string{name} + "-close").c_str()) << static_cast<int>(stage) << false;
        QTest::newRow((std::string{name} + "-escape").c_str()) << static_cast<int>(stage) << true;
    }
}

void WalletActivityTests::createWalletProgress()
{
    QFETCH(int, stage_value);
    QFETCH(bool, use_escape);
    const auto stage{static_cast<wallet::CreateWalletStage>(stage_value)};

    wallet::WalletTestingSetup setup{ChainType::REGTEST, {.extra_args = {"-p2mronly=0", "-keypool=1"}}};
    ConfigureNode(m_node, setup);

    std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    QVERIFY(platform_style);
    QWidget parent;
    parent.show();
    QtWalletModels models{m_node, platform_style.get()};

    WalletModel* existing_model{nullptr};
    QSignalSpy initial_wallet_added_spy{models.controller.get(), &WalletController::walletAdded};
    connect(models.controller.get(), &WalletController::walletAdded, models.controller.get(),
            [&existing_model](WalletModel* wallet_model) {
                if (!existing_model) existing_model = wallet_model;
            });
    std::vector<bilingual_str> warnings;
    auto existing_wallet{setup.m_wallet_loader->createWallet(
        EXISTING_WALLET_NAME, /*passphrase=*/{}, wallet::WALLET_FLAG_DESCRIPTORS, warnings)};
    QVERIFY(existing_wallet);
    QVERIFY(warnings.empty());
    QVERIFY(WaitUntil([&] { return initial_wallet_added_spy.count() == 1; }));
    QVERIFY(existing_model);
    std::unique_ptr<interfaces::Wallet> existing_wallet_interface{std::move(*existing_wallet)};
    existing_wallet_interface.reset();

    CreateWalletStageLatch latch{stage};
    wallet::WalletContext& context{*Assert(setup.m_wallet_loader->context())};
    context.create_wallet_stage_fn = [&latch](wallet::CreateWalletStage reached_stage) { latch.reach(reached_stage); };

    QSignalSpy wallet_added_spy{models.controller.get(), &WalletController::walletAdded};
    QPointer<CreateWalletActivity> activity{new CreateWalletActivity(models.controller.get(), &parent)};
    QSignalSpy created_spy{activity, &CreateWalletActivity::created};
    QSignalSpy finished_spy{activity, &CreateWalletActivity::finished};
    WalletModel* active_wallet{existing_model};
    connect(activity, &CreateWalletActivity::created, activity, [&active_wallet](WalletModel* wallet_model) {
        active_wallet = wallet_model;
    });
    ScopeExit creation_cleanup{[&] {
        latch.release();
        WaitForActivityCompletion([&] { return !activity || finished_spy.count() == 1; });
        context.create_wallet_stage_fn = {};
    }};

    activity->m_passphrase.assign("test-passphrase");
    activity->createWallet(QString::fromLatin1(CREATED_WALLET_NAME), wallet::WALLET_FLAG_DESCRIPTORS);

    QPointer<QProgressDialog> progress_dialog{
        parent.findChild<QProgressDialog*>(QStringLiteral("walletControllerProgressDialog"))};
    QVERIFY(progress_dialog);
    QVERIFY(WaitUntil([&] { return progress_dialog && progress_dialog->isVisible() && latch.reached(); }));
    QCOMPARE(progress_dialog->windowModality(), Qt::ApplicationModal);
    QVERIFY(!progress_dialog->windowFlags().testFlag(Qt::WindowCloseButtonHint));
    QVERIFY(progress_dialog->labelText().contains(QStringLiteral("cannot be canceled")));
    QSignalSpy canceled_spy{progress_dialog, &QProgressDialog::canceled};
    QSignalSpy rejected_spy{progress_dialog, &QDialog::rejected};

    if (use_escape) {
        QTest::keyClick(progress_dialog, Qt::Key_Escape);
    } else {
        QVERIFY(!progress_dialog->close());
    }
    QCoreApplication::processEvents();

    QVERIFY(progress_dialog);
    QVERIFY(progress_dialog->isVisible());
    QCOMPARE(canceled_spy.count(), 0);
    QCOMPARE(rejected_spy.count(), 0);
    QCOMPARE(created_spy.count(), 0);
    QCOMPARE(finished_spy.count(), 0);
    QCOMPARE(active_wallet, existing_model);

    const bool database_exists{stage != wallet::CreateWalletStage::BEFORE_DATABASE_CREATION};
    const bool model_adopted{stage == wallet::CreateWalletStage::MODEL_ADOPTED_BEFORE_CREATED_SIGNAL};
    const std::set<std::string> existing_only{EXISTING_WALLET_NAME};
    const std::set<std::string> both_wallets{EXISTING_WALLET_NAME, CREATED_WALLET_NAME};
    QVERIFY(RpcWalletNames(m_node, "listwalletdir") == (database_exists ? both_wallets : existing_only));
    QVERIFY(RpcWalletNames(m_node, "listwallets") == (model_adopted ? both_wallets : existing_only));
    QVERIFY(AsSet(StartupWalletNames(m_node)) == (model_adopted ? both_wallets : existing_only));
    QCOMPARE(wallet_added_spy.count(), model_adopted ? 1 : 0);

    latch.release();
    QVERIFY(WaitUntil([&] { return finished_spy.count() == 1; }));
    QCOMPARE(created_spy.count(), 1);
    QVERIFY(WaitUntil([&] { return progress_dialog.isNull(); }));
    QVERIFY(active_wallet);
    QCOMPARE(active_wallet->getWalletName(), QString::fromLatin1(CREATED_WALLET_NAME));
    QVERIFY(RpcWalletNames(m_node, "listwalletdir") == both_wallets);
    QVERIFY(RpcWalletNames(m_node, "listwallets") == both_wallets);
    QVERIFY(AsSet(StartupWalletNames(m_node)) == both_wallets);
    QCOMPARE(wallet_added_spy.count(), 1);
    context.create_wallet_stage_fn = {};
    creation_cleanup.dismiss();

    // Simulate shutdown and startup with the persisted wallet setting. Destroy
    // every GUI wallet wrapper before unloading the core wallets.
    models.reset();
    setup.m_wallet_loader->stop();
    QVERIFY(RpcWalletNames(m_node, "listwallets").empty());
    QVERIFY(RpcWalletNames(m_node, "listwalletdir") == both_wallets);
    QVERIFY(AsSet(StartupWalletNames(m_node)) == both_wallets);
    QVERIFY(setup.m_wallet_loader->verify());
    QVERIFY(setup.m_wallet_loader->load());
    QVERIFY(RpcWalletNames(m_node, "listwallets") == both_wallets);

    QtWalletModels restarted_models{m_node, platform_style.get()};
    WalletModel* startup_active_wallet{nullptr};
    connect(restarted_models.controller.get(), &WalletController::walletAdded,
            restarted_models.controller.get(), [&startup_active_wallet](WalletModel* wallet_model) {
                if (!startup_active_wallet) startup_active_wallet = wallet_model;
            });
    QPointer<LoadWalletsActivity> load_activity{
        new LoadWalletsActivity(restarted_models.controller.get(), &parent)};
    QSignalSpy load_finished_spy{load_activity, &LoadWalletsActivity::finished};
    load_activity->load(/*show_loading_minimized=*/false);
    QVERIFY(WaitUntil([&] { return load_finished_spy.count() == 1; }));
    QVERIFY(startup_active_wallet);
    QCOMPARE(startup_active_wallet->getWalletName(), QString::fromLatin1(EXISTING_WALLET_NAME));
    QVERIFY(RpcWalletNames(m_node, "listwalletdir") == both_wallets);
    QVERIFY(RpcWalletNames(m_node, "listwallets") == both_wallets);
    QVERIFY(AsSet(StartupWalletNames(m_node)) == both_wallets);
    const std::vector<std::string> startup_wallets{StartupWalletNames(m_node)};
    QCOMPARE(startup_wallets.size(), size_t{2});
    QCOMPARE(startup_wallets.front(), std::string{EXISTING_WALLET_NAME});

    restarted_models.reset();
    setup.m_wallet_loader->stop();
}

void WalletActivityTests::ordinaryLoadAndShutdown()
{
    wallet::WalletTestingSetup setup{ChainType::REGTEST, {.extra_args = {"-p2mronly=0", "-keypool=1"}}};
    ConfigureNode(m_node, setup);

    std::vector<bilingual_str> warnings;
    auto wallet{setup.m_wallet_loader->createWallet(
        EXISTING_WALLET_NAME, /*passphrase=*/{}, wallet::WALLET_FLAG_DESCRIPTORS, warnings)};
    QVERIFY(wallet);
    QVERIFY(warnings.empty());
    std::unique_ptr<interfaces::Wallet> wallet_interface{std::move(*wallet)};
    wallet_interface.reset();

    std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    QVERIFY(platform_style);
    QWidget parent;
    parent.show();
    QtWalletModels models{m_node, platform_style.get()};

    QSignalSpy wallet_added_spy{models.controller.get(), &WalletController::walletAdded};
    QPointer<LoadWalletsActivity> load_activity{new LoadWalletsActivity(models.controller.get(), &parent)};
    QSignalSpy load_finished_spy{load_activity, &LoadWalletsActivity::finished};
    load_activity->load(/*show_loading_minimized=*/false);
    QVERIFY(WaitUntil([&] { return load_finished_spy.count() == 1; }));
    QCOMPARE(wallet_added_spy.count(), 1);
    QVERIFY(WaitUntil([&] { return load_activity.isNull(); }));
    QVERIFY(parent.findChild<QProgressDialog*>(QStringLiteral("walletControllerProgressDialog")) == nullptr);

    QElapsedTimer shutdown_timer;
    shutdown_timer.start();
    models.reset();
    QVERIFY(shutdown_timer.elapsed() < 5'000);

    // A controller teardown also owns and destroys an unfinished activity and
    // its application-modal progress surface.
    QtWalletModels teardown_models{m_node, platform_style.get()};
    QPointer<TestProgressActivity> activity{
        new TestProgressActivity(teardown_models.controller.get(), &parent)};
    activity->show();
    QPointer<QProgressDialog> progress_dialog{
        parent.findChild<QProgressDialog*>(QStringLiteral("walletControllerProgressDialog"))};
    QVERIFY(progress_dialog);
    QVERIFY(WaitUntil([&] { return progress_dialog->isVisible(); }));
    teardown_models.reset();
    QVERIFY(activity.isNull());
    QVERIFY(progress_dialog.isNull());

    setup.m_wallet_loader->stop();
}
