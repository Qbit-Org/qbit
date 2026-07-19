// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/psbtoperationsdialogtests.h>

#include <consensus/amount.h>
#include <interfaces/node.h>
#include <key.h>
#include <outputtype.h>
#include <psbt.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/psbtoperationsdialog.h>
#include <qt/test/syntheticwallet.h>
#include <qt/walletmodel.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

#include <QApplication>
#include <QClipboard>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include <QProgressDialog>
#include <QSignalSpy>
#include <QTextEdit>
#include <QTimer>

namespace {
constexpr int WAIT_TIMEOUT_MS{5'000};

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
bool ReadState(const std::shared_ptr<qt_test::SyntheticWalletState>& state, Predicate&& predicate)
{
    std::lock_guard lock{state->mutex};
    return predicate(*state);
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

std::string SerializePSBT(const PartiallySignedTransaction& psbt)
{
    DataStream stream;
    stream << psbt;
    return stream.str();
}

class DialogFixture
{
public:
    DialogFixture(ClientModel& client_model,
                  const PlatformStyle* platform_style,
                  std::shared_ptr<qt_test::SyntheticWalletState> state)
        : state{std::move(state)},
          original_psbt{MakeUnsignedPSBT()},
          wallet_model{std::make_unique<WalletModel>(qt_test::MakeSyntheticWallet({}, this->state), client_model, platform_style)},
          dialog{std::make_unique<PSBTOperationsDialog>(nullptr, wallet_model.get(), &client_model)}
    {
        dialog->openWithPSBT(original_psbt);
    }

    ~DialogFixture()
    {
        releaseWorker();
        dialog.reset();
        wallet_model.reset();
    }

    void releaseWorker()
    {
        {
            std::lock_guard lock{state->mutex};
            state->allow_psbt_reservation = true;
            state->allow_psbt_completion = true;
        }
        state->condition.notify_all();
    }

    QLabel* statusLabel() const { return dialog->findChild<QLabel*>(QStringLiteral("statusBar")); }
    QTextEdit* description() const { return dialog->findChild<QTextEdit*>(QStringLiteral("transactionDescription")); }

    std::shared_ptr<qt_test::SyntheticWalletState> state;
    PartiallySignedTransaction original_psbt;
    std::unique_ptr<WalletModel> wallet_model;
    std::unique_ptr<PSBTOperationsDialog> dialog;
};
} // namespace

struct PSBTOperationsDialogTests::Context {
    Context(interfaces::Node& node)
        : chain{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}},
          platform_style{PlatformStyle::instantiate("other")}
    {
        node.setContext(&chain.m_node);
        options_model = std::make_unique<OptionsModel>(node);
        bilingual_str error;
        if (!options_model->Init(error)) throw std::runtime_error{error.original};
        client_model = std::make_unique<ClientModel>(node, options_model.get());
    }

    TestChain100Setup chain;
    std::unique_ptr<const PlatformStyle> platform_style;
    std::unique_ptr<OptionsModel> options_model;
    std::unique_ptr<ClientModel> client_model;
};

PSBTOperationsDialogTests::PSBTOperationsDialogTests(interfaces::Node& node)
    : m_node{node}
{
}

PSBTOperationsDialogTests::~PSBTOperationsDialogTests() = default;

void PSBTOperationsDialogTests::initTestCase()
{
    m_context = std::make_unique<Context>(m_node);
    QVERIFY(m_context->platform_style);
}

void PSBTOperationsDialogTests::cleanupTestCase()
{
    m_context.reset();
}

void PSBTOperationsDialogTests::eventLoopResponsiveWhileSigningPaused()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->allow_psbt_reservation = false;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};

    const std::thread::id gui_thread{std::this_thread::get_id()};
    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_sign_entered; }); }));
    QVERIFY(ReadState(state, [&](const auto& value) { return value.psbt_sign_thread != gui_thread; }));

    bool event_delivered{false};
    QTimer::singleShot(0, [&] { event_delivered = true; });
    QVERIFY(WaitUntil([&] { return event_delivered; }));
    QVERIFY(!ReadState(state, [](const auto& value) { return value.psbt_sign_finished; }));

    fixture.releaseWorker();
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("ready to broadcast")); }));
}

void PSBTOperationsDialogTests::successfulCompletionUpdatesDisplayOnce()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->allow_psbt_reservation = false;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    QVERIFY(fixture.description());
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};
    QVERIFY(display_updates.isValid());

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_sign_entered; }); }));
    fixture.releaseWorker();
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("ready to broadcast")); }));

    QCOMPARE(display_updates.count(), 1);
    QVERIFY(!fixture.description()->toPlainText().contains(QStringLiteral("unsigned input")));
    QCOMPARE(ReadState(state, [](const auto& value) { return value.psbt_sign_calls; }), 1);
}

void PSBTOperationsDialogTests::cancellationBeforeCounterReservation()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->allow_psbt_reservation = false;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_sign_entered; }); }));
    QVERIFY(QMetaObject::invokeMethod(fixture.dialog.get(), "cancelSignTransaction"));
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("canceled")); }));

    QVERIFY(ReadState(state, [](const auto& value) { return value.psbt_cancel_observed; }));
    QVERIFY(!ReadState(state, [](const auto& value) { return value.psbt_counters_reserved; }));
    QCOMPARE(display_updates.count(), 0);
}

void PSBTOperationsDialogTests::lateCancellationDoesNotDropCompletedPSBT()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};

    fixture.dialog->signTransaction();
    {
        std::unique_lock lock{state->mutex};
        QVERIFY(state->condition.wait_for(lock, std::chrono::milliseconds{WAIT_TIMEOUT_MS}, [&] {
            return state->psbt_sign_finished;
        }));
    }

    QVERIFY(QMetaObject::invokeMethod(fixture.dialog.get(), "cancelSignTransaction"));
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("ready to broadcast")); }));

    QVERIFY(!ReadState(state, [](const auto& value) { return value.psbt_cancel_observed; }));
    QCOMPARE(display_updates.count(), 1);
}

void PSBTOperationsDialogTests::cancellationAfterCounterReservationIsIgnored()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->psbt_simulate_pqc_reservation = true;
    state->allow_psbt_completion = false;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_counters_reserved; }); }));
    QCoreApplication::processEvents();
    QVERIFY(QMetaObject::invokeMethod(fixture.dialog.get(), "cancelSignTransaction"));
    QVERIFY(!ReadState(state, [](const auto& value) { return value.psbt_cancel_observed; }));

    fixture.releaseWorker();
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("ready to broadcast")); }));
    QVERIFY(!ReadState(state, [](const auto& value) { return value.psbt_cancel_observed; }));
    QCOMPARE(display_updates.count(), 1);
}

void PSBTOperationsDialogTests::dialogDestructionBeforeCompletion()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->allow_psbt_reservation = false;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    QPointer<PSBTOperationsDialog> dialog_guard{fixture.dialog.get()};

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_sign_entered; }); }));
    QElapsedTimer destruction_timer;
    destruction_timer.start();
    fixture.dialog.reset();

    QVERIFY(dialog_guard.isNull());
    QVERIFY(destruction_timer.elapsed() < WAIT_TIMEOUT_MS);
    QVERIFY(ReadState(state, [](const auto& value) { return value.psbt_cancel_observed && value.psbt_sign_finished; }));
    QVERIFY(ReadState(state, [](const auto& value) { return value.background_clone_destroyed; }));
    QCoreApplication::processEvents();
}

void PSBTOperationsDialogTests::walletUnloadDuringSigning()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->allow_psbt_completion = false;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_sign_entered; }); }));
    QPointer<WalletModel> model_guard{fixture.wallet_model.get()};
    fixture.wallet_model.reset();
    QVERIFY(model_guard.isNull());

    fixture.releaseWorker();
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("no longer loaded")); }));
    QCOMPARE(display_updates.count(), 0);
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.background_clone_destroyed; }); }));
}

void PSBTOperationsDialogTests::signingFailurePreservesOriginalPSBT()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->psbt_fail = true;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    const std::string original{SerializePSBT(fixture.original_psbt)};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().startsWith(QStringLiteral("Failed to sign transaction")); }));
    QCOMPARE(display_updates.count(), 0);

    fixture.dialog->copyToClipboard();
    const auto decoded{DecodeBase64(QApplication::clipboard()->text().toStdString())};
    QVERIFY(decoded);
    PartiallySignedTransaction clipboard_psbt;
    std::string error;
    QVERIFY(DecodeRawPSBT(clipboard_psbt, MakeByteSpan(*decoded), error));
    QCOMPARE(SerializePSBT(clipboard_psbt), original);
}
