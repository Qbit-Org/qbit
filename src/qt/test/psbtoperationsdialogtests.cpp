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
#include <qt/test/util.h>
#include <qt/walletmodel.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/pqc_usage.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <QAbstractButton>
#include <QAccessible>
#include <QApplication>
#include <QClipboard>
#include <QCloseEvent>
#include <QCoreApplication>
#include <QDialog>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include <QProgressDialog>
#include <QPushButton>
#include <QSignalSpy>
#include <QTextEdit>
#include <QThread>
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

//! The PSBT the synthetic wallet produces when it signs the given one.
PartiallySignedTransaction SyntheticSignedPSBT(PartiallySignedTransaction psbt)
{
    psbt.inputs.front().final_script_witness.stack = {{0x01}};
    return psbt;
}

std::string ClipboardPSBT()
{
    const auto decoded{DecodeBase64(QApplication::clipboard()->text().toStdString())};
    if (!decoded) return {};
    PartiallySignedTransaction psbt;
    std::string error;
    if (!DecodeRawPSBT(psbt, MakeByteSpan(*decoded), error)) return {};
    return SerializePSBT(psbt);
}

//! Check that a log line names the one PSBT file saved since before, that the
//! file holds the expected PSBT, and that the line itself does not.
void VerifyUnshownPSBTSaved(const std::string& line, const std::map<fs::path, std::string>& before, const std::string& expected)
{
    QVERIFY2(line.find("The signed PSBT was saved to ") != std::string::npos, line.c_str());
    QVERIFY2(line.find(EncodeBase64(expected)) == std::string::npos, line.c_str());
    const auto saved{NewUnshownPSBTFiles(before)};
    QCOMPARE(saved.size(), size_t{1});
    QVERIFY2(line.find(fs::PathToString(saved.begin()->first.filename())) != std::string::npos, line.c_str());
    QVERIFY(saved.begin()->second == expected);
}

QProgressDialog* FindSigningProgress(const PSBTOperationsDialog& dialog)
{
    return dialog.findChild<QProgressDialog*>(QStringLiteral("psbtSigningProgressDialog"));
}

wallet::PQCUsageReport MakePQCUsageReport(const CPQCPubKey& pubkey, uint32_t signature_count)
{
    wallet::PQCUsageReport report;
    report.key_states.push_back({
        .pubkey = pubkey,
        .signature_count = signature_count,
        .signature_limit = PQC_MAX_SIGNATURES,
        .signatures_remaining = PQC_MAX_SIGNATURES - signature_count,
        .limit_state = wallet::PQCSignatureLimitState::NORMAL,
    });
    report.overall_state = wallet::PQCSignatureLimitState::NORMAL;
    return report;
}

QString PQCPubKeyHex(const CPQCPubKey& pubkey)
{
    return QString::fromStdString(HexStr(std::span<const unsigned char>{pubkey.begin(), pubkey.end()}));
}

QString PQCStateLabel(wallet::PQCSignatureLimitState state)
{
    switch (state) {
    case wallet::PQCSignatureLimitState::NORMAL: return QStringLiteral("Normal");
    case wallet::PQCSignatureLimitState::WARNING: return QStringLiteral("Warning");
    case wallet::PQCSignatureLimitState::CRITICAL: return QStringLiteral("Critical");
    case wallet::PQCSignatureLimitState::EXHAUSTED: return QStringLiteral("Exhausted");
    }
    return {};
}

const QString CONSUMED_SENTENCE{QStringLiteral("PQC signature capacity was consumed during this signing attempt.")};
const QString FAILED_SENTENCE{QStringLiteral("The signing attempt failed after consuming PQC signature capacity.")};

//! Check that a status lists the overall state, every key and every warning of a report.
void VerifyStatusListsUsage(const QString& status, const wallet::PQCUsageReport& report)
{
    QVERIFY(report.overall_state.has_value());
    QVERIFY(status.contains(QStringLiteral("PQC usage state after this signing attempt: %1.").arg(PQCStateLabel(*report.overall_state))));
    for (const wallet::PQCUsageSnapshot& key_state : report.key_states) {
        QVERIFY2(status.contains(QStringLiteral("PQC key %1: %2 of %3 signatures used, %4 remaining; state: %5.")
                                     .arg(PQCPubKeyHex(key_state.pubkey))
                                     .arg(key_state.signature_count)
                                     .arg(key_state.signature_limit)
                                     .arg(key_state.signatures_remaining)
                                     .arg(PQCStateLabel(key_state.limit_state))),
                 qPrintable(status));
    }
    const std::vector<bilingual_str> warnings{wallet::FormatPQCUsageWarnings(report.warnings)};
    QCOMPARE(warnings.size(), report.warnings.size());
    for (const bilingual_str& warning : warnings) {
        QVERIFY2(status.contains(QString::fromStdString(warning.original)), qPrintable(status));
    }
}

class DialogFixture
{
public:
    DialogFixture(ClientModel& client_model,
                  const PlatformStyle* platform_style,
                  std::shared_ptr<qt_test::SyntheticWalletState> state,
                  wallet::PQCUsageReport pqc_usage = {})
        : state{std::move(state)},
          original_psbt{MakeUnsignedPSBT()},
          wallet_model{std::make_unique<WalletModel>(qt_test::MakeSyntheticWallet(std::move(pqc_usage), this->state), client_model, platform_style)},
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
            state->allow_psbt_counter_boundary = true;
            state->allow_psbt_completion = true;
            state->allow_psbt_post_signing = true;
        }
        state->condition.notify_all();
    }

    QLabel* statusLabel() const { return dialog->findChild<QLabel*>(QStringLiteral("statusBar")); }
    QAbstractButton* button(const char* name) const { return dialog->findChild<QAbstractButton*>(QLatin1String(name)); }
    //! Whether Sign, Copy and Save are enabled, for the dialog's unsigned PSBT.
    bool signingControlsEnabled() const
    {
        return button("signTransactionButton")->isEnabled() &&
               button("copyToClipboardButton")->isEnabled() &&
               button("saveButton")->isEnabled();
    }
    bool signingControlsDisabled() const
    {
        return !button("signTransactionButton")->isEnabled() &&
               !button("copyToClipboardButton")->isEnabled() &&
               !button("saveButton")->isEnabled() &&
               !button("broadcastTransactionButton")->isEnabled();
    }
    QTextEdit* description() const { return dialog->findChild<QTextEdit*>(QStringLiteral("transactionDescription")); }

    std::shared_ptr<qt_test::SyntheticWalletState> state;
    PartiallySignedTransaction original_psbt;
    std::unique_ptr<WalletModel> wallet_model;
    std::unique_ptr<PSBTOperationsDialog> dialog;
};

//! Press a button through its accessibility action, as VoiceOver or a UI
//! automation client does. Unlike mouse and keyboard input, this reaches
//! widgets in windows that a modal dialog blocks.
bool PressThroughAccessibility(QAbstractButton* button)
{
    QAccessibleInterface* const iface{QAccessible::queryAccessibleInterface(button)};
    if (!iface || !iface->actionInterface()) return false;
    iface->actionInterface()->doAction(QAccessibleActionInterface::pressAction());
    return true;
}

//! Record every thread that signs, to check that the dialog deletes each one.
//! Declare it before the fixture, so it outlives the signing threads.
class SignThreadRecorder
{
public:
    explicit SignThreadRecorder(std::shared_ptr<qt_test::SyntheticWalletState> state)
        : m_state{std::move(state)}
    {
        std::lock_guard lock{m_state->mutex};
        m_state->psbt_sign_started = [this] {
            std::lock_guard threads_lock{m_mutex};
            m_threads.emplace_back(QThread::currentThread());
        };
    }
    ~SignThreadRecorder()
    {
        std::lock_guard lock{m_state->mutex};
        m_state->psbt_sign_started = nullptr;
    }

    bool allDeleted() const
    {
        std::lock_guard lock{m_mutex};
        return std::ranges::all_of(m_threads, [](const QPointer<QThread>& thread) { return thread.isNull(); });
    }

private:
    const std::shared_ptr<qt_test::SyntheticWalletState> m_state;
    mutable std::mutex m_mutex;
    std::vector<QPointer<QThread>> m_threads;
};

//! Stand in for the passphrase dialog: unlock the wallet as it does.
void UnlockSyntheticWallet(const std::shared_ptr<qt_test::SyntheticWalletState>& state)
{
    std::lock_guard lock{state->mutex};
    state->locked = false;
}
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

void PSBTOperationsDialogTests::canceledUnlockDoesNotStartSigning()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->encrypted = true;
    state->locked = true;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    const std::string original{SerializePSBT(fixture.original_psbt)};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};

    fixture.dialog->signTransaction();

    QVERIFY(fixture.statusLabel()->text().contains(QStringLiteral("wallet is locked")));
    QCOMPARE(ReadState(state, [](const auto& value) { return value.psbt_sign_calls; }), 0);
    QCOMPARE(display_updates.count(), 0);
    QVERIFY(!fixture.dialog->findChild<QProgressDialog*>(QStringLiteral("psbtSigningProgressDialog")));
    // The canceled attempt is released, so Sign can be pressed again.
    QVERIFY(fixture.signingControlsEnabled());

    fixture.dialog->copyToClipboard();
    const auto decoded{DecodeBase64(QApplication::clipboard()->text().toStdString())};
    QVERIFY(decoded);
    PartiallySignedTransaction clipboard_psbt;
    std::string error;
    QVERIFY(DecodeRawPSBT(clipboard_psbt, MakeByteSpan(*decoded), error));
    QCOMPARE(SerializePSBT(clipboard_psbt), original);
}

//! Press Sign through accessibility just before the first Sign and while its
//! passphrase dialog is open on an encrypted, locked wallet, and call its slot
//! there. Exactly one signing attempt may run, the wallet may not be relocked
//! under it, and its thread may not be left behind.
void PSBTOperationsDialogTests::signDuringUnlockPromptIsIgnored()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->encrypted = true;
    state->locked = true;
    state->allow_psbt_reservation = false;
    const SignThreadRecorder sign_threads{state};
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    QAbstractButton* const sign_button{fixture.button("signTransactionButton")};
    QVERIFY(sign_button);
    QVERIFY(fixture.signingControlsEnabled());

    // A modal dialog's nested event loop stands in for the passphrase dialog.
    // A nested prompt, which only a second attempt could open, unlocks at once.
    int prompts{0};
    bool in_prompt{false};
    int clicks_in_prompt{0};
    bool pressed{false};
    bool disabled_during_prompt{false};
    QObject::connect(sign_button, &QAbstractButton::clicked, sign_button, [&] {
        if (in_prompt) ++clicks_in_prompt;
    });
    QObject::connect(fixture.wallet_model.get(), &WalletModel::requireUnlock, fixture.wallet_model.get(), [&] {
        if (++prompts == 1) {
            QDialog passphrase;
            passphrase.setWindowModality(Qt::ApplicationModal);
            QTimer::singleShot(0, &passphrase, [&] {
                disabled_during_prompt = fixture.signingControlsDisabled();
                pressed = PressThroughAccessibility(sign_button);
                fixture.dialog->signTransaction();
                // Leave time for the click armed before the prompt opened.
                QTimer::singleShot(500, &passphrase, &QDialog::accept);
            });
            in_prompt = true;
            passphrase.exec();
            in_prompt = false;
        }
        UnlockSyntheticWallet(state);
    });

    // An accessible press clicks after a delay, so one made just before Sign
    // is clicked clicks it again inside the prompt, after Sign was disabled.
    // Only the in-flight guard stops that click. The press made inside the
    // prompt finds Sign disabled and clicks nothing.
    QVERIFY(PressThroughAccessibility(sign_button));
    sign_button->click();
    QVERIFY(pressed);
    QCOMPARE(clicks_in_prompt, 1);
    QCOMPARE(prompts, 1);
    QVERIFY(disabled_during_prompt);

    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_sign_entered; }); }));
    // Leave time for a second attempt, had one started, to reach the wallet.
    QTest::qWait(200);
    QCOMPARE(ReadState(state, [](const auto& value) { return value.psbt_sign_calls; }), 1);
    QVERIFY(ReadState(state, [](const auto& value) { return !value.locked && value.lock_calls == 0; }));
    QVERIFY(fixture.signingControlsDisabled());

    fixture.releaseWorker();
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("ready to broadcast")); }));
    QVERIFY(ReadState(state, [](const auto& value) {
        return value.psbt_sign_calls == 1 && value.locked && value.lock_calls == 1;
    }));

    // Every signing thread is deleted once the dialog is: the dialog never
    // lost track of one.
    fixture.dialog.reset();
    QVERIFY(WaitUntil([&] { return sign_threads.allDeleted(); }));
}

//! An exception that escapes the unlock request must not leave Sign busy.
void PSBTOperationsDialogTests::unlockExceptionReleasesSigning()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->encrypted = true;
    state->locked = true;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};

    // Throw on the first request and unlock the wallet on the next.
    bool throw_on_unlock{true};
    const std::string_view test_name{__func__}; // __func__ inside the lambda would name its operator().
    QObject::connect(fixture.wallet_model.get(), &WalletModel::requireUnlock, fixture.wallet_model.get(), [&] {
        if (throw_on_unlock) {
            throw_on_unlock = false;
            throw NonFatalCheckError{"synthetic unlock failure", __FILE__, __LINE__, test_name};
        }
        UnlockSyntheticWallet(state);
    });

    QVERIFY_THROWS_EXCEPTION(NonFatalCheckError, fixture.dialog->signTransaction());
    QVERIFY(!throw_on_unlock);
    QVERIFY(fixture.signingControlsEnabled());
    QVERIFY(!fixture.dialog->findChild<QProgressDialog*>(QStringLiteral("psbtSigningProgressDialog")));

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("ready to broadcast")); }));
    QVERIFY(ReadState(state, [](const auto& value) {
        return value.psbt_sign_calls == 1 && value.locked && value.lock_calls == 1;
    }));
}

//! The passphrase dialog's nested event loop can close and delete the PSBT
//! dialog. Signing must not start, and the wallet must be relocked.
void PSBTOperationsDialogTests::dialogDeletedDuringUnlockPrompt()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->encrypted = true;
    state->locked = true;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    QPointer<PSBTOperationsDialog> dialog_guard{fixture.dialog.get()};

    QObject::connect(fixture.wallet_model.get(), &WalletModel::requireUnlock, fixture.wallet_model.get(), [&] {
        UnlockSyntheticWallet(state);
        fixture.dialog.reset();
    });

    dialog_guard->signTransaction();
    QVERIFY(dialog_guard.isNull());
    QCoreApplication::processEvents();
    QVERIFY(ReadState(state, [](const auto& value) {
        return value.psbt_sign_calls == 0 && value.locked && value.lock_calls == 1;
    }));
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
    state->psbt_simulate_pqc_reservation = true;
    CPQCKey key;
    key.MakeNewKey();
    const wallet::PQCUsageReport pqc_usage{MakePQCUsageReport(key.GetPubKey(), 1)};
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state, pqc_usage};
    QVERIFY(fixture.description());
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};
    QVERIFY(display_updates.isValid());

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_sign_entered; }); }));
    fixture.releaseWorker();
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("ready to broadcast")); }));

    QCOMPARE(display_updates.count(), 1);
    QVERIFY(!fixture.description()->toPlainText().contains(QStringLiteral("unsigned input")));
    QVERIFY(fixture.statusLabel()->text().contains(QStringLiteral("PQC signature capacity was consumed")));
    QVERIFY(fixture.statusLabel()->text().contains(PQCPubKeyHex(key.GetPubKey())));
    QVERIFY(fixture.statusLabel()->text().contains(QStringLiteral("1 of %1 signatures used").arg(PQC_MAX_SIGNATURES)));
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

void PSBTOperationsDialogTests::acceptedCancellationAfterSigningPreservesOriginalPSBT()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->allow_psbt_post_signing = false;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    const std::string original{SerializePSBT(fixture.original_psbt)};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_input_signed; }); }));
    QVERIFY(QMetaObject::invokeMethod(fixture.dialog.get(), "cancelSignTransaction"));
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("canceled")); }));

    QVERIFY(ReadState(state, [](const auto& value) { return value.psbt_cancel_observed; }));
    QCOMPARE(display_updates.count(), 0);

    fixture.dialog->copyToClipboard();
    const auto decoded{DecodeBase64(QApplication::clipboard()->text().toStdString())};
    QVERIFY(decoded);
    PartiallySignedTransaction clipboard_psbt;
    std::string error;
    QVERIFY(DecodeRawPSBT(clipboard_psbt, MakeByteSpan(*decoded), error));
    QCOMPARE(SerializePSBT(clipboard_psbt), original);
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

void PSBTOperationsDialogTests::closeIgnoredWhileSigning()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->psbt_simulate_pqc_reservation = true;
    state->allow_psbt_completion = false;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};
    fixture.dialog->show();

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_counters_reserved; }); }));

    // The Close button, Escape and the window manager must not hide the
    // dialog: deleting it would block the GUI thread on the worker and drop
    // the signed PSBT.
    QVERIFY(!fixture.dialog->close());
    fixture.dialog->reject();
    QCloseEvent close_event;
    QCoreApplication::sendEvent(fixture.dialog.get(), &close_event);
    QVERIFY(!close_event.isAccepted());
    QVERIFY(fixture.dialog->isVisible());

    // Its progress dialog stays up as well once Cancel is gone.
    QVERIFY(WaitUntil([&] { return FindSigningProgress(*fixture.dialog) && FindSigningProgress(*fixture.dialog)->isVisible(); }));
    QProgressDialog* const progress{FindSigningProgress(*fixture.dialog)};
    QVERIFY(!progress->findChild<QPushButton*>());
    progress->reject();
    QVERIFY(!progress->close());
    QVERIFY(progress->isVisible());

    fixture.releaseWorker();
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("ready to broadcast")); }));
    QCOMPARE(display_updates.count(), 1);
    QVERIFY(WaitUntil([&] { return fixture.dialog->close(); }));
    QVERIFY(!fixture.dialog->isVisible());
}

void PSBTOperationsDialogTests::canceledProgressStaysVisibleUntilWorkerReports()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->psbt_simulate_pqc_reservation = true;
    state->allow_psbt_counter_boundary = false;
    state->allow_psbt_completion = false;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};
    fixture.dialog->show();

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return FindSigningProgress(*fixture.dialog) && FindSigningProgress(*fixture.dialog)->isVisible(); }));
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_counter_boundary_entered; }); }));

    // Cancel arrives after the worker's last cancellable check, so it cannot
    // stop the reservation that follows. The progress must stay on screen,
    // and the dialog open, until the worker reports.
    QProgressDialog* const progress{FindSigningProgress(*fixture.dialog)};
    QPushButton* const cancel{progress->findChild<QPushButton*>()};
    QVERIFY(cancel);
    cancel->click();
    QVERIFY(progress->isVisible());
    QVERIFY(progress->labelText().contains(QStringLiteral("Canceling")));
    QVERIFY(!fixture.dialog->close());

    {
        std::lock_guard lock{state->mutex};
        state->allow_psbt_counter_boundary = true;
    }
    state->condition.notify_all();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_counters_reserved; }); }));
    QVERIFY(WaitUntil([&] { return progress->labelText().contains(QStringLiteral("Signing inputs")); }));
    QVERIFY(progress->isVisible());

    QPointer<QProgressDialog> progress_guard{progress};
    fixture.releaseWorker();
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("ready to broadcast")); }));
    QVERIFY(!ReadState(state, [](const auto& value) { return value.psbt_cancel_observed; }));
    QCOMPARE(display_updates.count(), 1);
    QVERIFY(progress_guard.isNull() || !progress_guard->isVisible());
}

void PSBTOperationsDialogTests::shutdownCancelsSigningBeforeReservation()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->psbt_simulate_pqc_reservation = true;
    state->allow_psbt_reservation = false;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};
    const LogCapture log;

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return FindSigningProgress(*fixture.dialog) && FindSigningProgress(*fixture.dialog)->isVisible(); }));
    QVERIFY(ReadState(state, [](const auto& value) { return value.psbt_sign_entered; }));

    QPointer<QProgressDialog> progress{FindSigningProgress(*fixture.dialog)};
    fixture.dialog->prepareForShutdown();
    QVERIFY(progress.isNull() || !progress->isVisible());
    {
        // The worker must stop without any event processing: shutdown runs
        // synchronously on the GUI thread.
        std::unique_lock lock{state->mutex};
        QVERIFY(state->condition.wait_for(lock, std::chrono::milliseconds{WAIT_TIMEOUT_MS}, [&] {
            return state->psbt_sign_finished;
        }));
        QVERIFY(state->psbt_cancel_observed);
        QVERIFY(!state->psbt_counters_reserved);
    }
    QVERIFY(WaitUntil([&] { return !log.find({"PSBT signing was canceled because its dialog was shut down or destroyed."}).empty(); }));
    QCOMPARE(display_updates.count(), 0);
}

void PSBTOperationsDialogTests::shutdownLogsSigningFinishedAfterReservation()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->psbt_simulate_pqc_reservation = true;
    state->allow_psbt_completion = false;
    CPQCKey key;
    key.MakeNewKey();
    const wallet::PQCUsageReport pqc_usage{MakePQCUsageReport(key.GetPubKey(), 3)};
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state, pqc_usage};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};
    const auto files_before{UnshownPSBTFiles()};
    const LogCapture log;

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_counters_reserved; }); }));
    fixture.dialog->prepareForShutdown();
    // Shutdown deletes the wallet model before the worker can report.
    fixture.wallet_model.reset();
    fixture.releaseWorker();

    // Nothing is shown during shutdown, so the outcome and the capacity it
    // consumed go to the debug log, and the signed PSBT to the data directory.
    const std::string finished{"PSBT signing finished after its dialog was shut down or destroyed, so the result was not shown"};
    QVERIFY(WaitUntil([&] { return !log.find({finished}).empty(); }));
    VerifyUnshownPSBTSaved(log.find({finished}), files_before, SerializePSBT(SyntheticSignedPSBT(fixture.original_psbt)));
    const std::string line{log.find({finished})};
    QVERIFY2(line.find("1 input(s) fully signed, transaction complete.") != std::string::npos, line.c_str());
    QVERIFY2(line.find(strprintf("PQC key %s: 3 of %u signatures used, %u remaining, state normal.",
                                 PQCPubKeyHex(key.GetPubKey()).toStdString(), PQC_MAX_SIGNATURES, PQC_MAX_SIGNATURES - 3)) != std::string::npos,
             line.c_str());
    QVERIFY(!ReadState(state, [](const auto& value) { return value.psbt_cancel_observed; }));
    QCOMPARE(display_updates.count(), 0);
}

void PSBTOperationsDialogTests::shutdownSavesPartialSignature()
{
    // One cosigner's signature on a multisig input finalizes nothing, so the
    // wallet counts no signed input, yet it consumed a counter.
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->psbt_simulate_pqc_reservation = true;
    state->psbt_partial_signature = true;
    state->allow_psbt_completion = false;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    const auto files_before{UnshownPSBTFiles()};
    const LogCapture log;

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_counters_reserved; }); }));
    fixture.dialog->prepareForShutdown();
    fixture.releaseWorker();

    const std::string finished{"PSBT signing finished after its dialog was shut down or destroyed, so the result was not shown"};
    QVERIFY(WaitUntil([&] { return !log.find({finished}).empty(); }));
    const std::string line{log.find({finished})};
    QVERIFY2(line.find("0 input(s) fully signed, transaction incomplete.") != std::string::npos, line.c_str());
    PartiallySignedTransaction produced;
    {
        std::lock_guard lock{state->mutex};
        produced = state->psbt_signed_result;
    }
    QVERIFY(!produced.inputs.front().partial_sigs.empty());
    VerifyUnshownPSBTSaved(line, files_before, SerializePSBT(produced));
}

void PSBTOperationsDialogTests::destructionAfterReservationSavesSignedPSBT()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->psbt_simulate_pqc_reservation = true;
    state->allow_psbt_completion = false;
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
    const auto files_before{UnshownPSBTFiles()};
    const LogCapture log;

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_counters_reserved; }); }));

    // The event loop is gone, as at application exit: the worker can no
    // longer deliver its result, and the destructor joins it.
    std::thread release{[&fixture] {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        fixture.releaseWorker();
    }};
    fixture.dialog.reset();
    release.join();

    const std::string finished{"PSBT signing finished after its dialog was shut down or destroyed, so the result was not shown"};
    QVERIFY(!log.find({finished}).empty());
    VerifyUnshownPSBTSaved(log.find({finished}), files_before, SerializePSBT(SyntheticSignedPSBT(fixture.original_psbt)));
    QVERIFY(!ReadState(state, [](const auto& value) { return value.psbt_cancel_observed; }));
    QCoreApplication::processEvents();
}

void PSBTOperationsDialogTests::shutdownLogsUnexportedSignedPSBT()
{
    const std::string closed{"PSBT dialog was shut down before its signed PSBT was copied, saved or broadcast."};
    // Kept in the dialog (signed, or only partially signed as one cosigner of
    // a multisig input), copied, or discarded by closing the dialog, which is
    // deleted only later and so is still found at shutdown.
    for (const std::string handling : {"kept", "partial", "copied", "closed"}) {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->psbt_partial_signature = handling == "partial";
        DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state};
        fixture.dialog->show();
        fixture.dialog->signTransaction();
        const QString done{handling == "partial" ? QStringLiteral("Could not sign any more inputs") : QStringLiteral("ready to broadcast")};
        QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(done); }));
        if (handling == "copied") fixture.dialog->copyToClipboard();
        if (handling == "closed") QVERIFY(WaitUntil([&] { return fixture.dialog->close(); }));

        const auto files_before{UnshownPSBTFiles()};
        const LogCapture log;
        fixture.dialog->prepareForShutdown();
        if (handling == "kept") {
            VerifyUnshownPSBTSaved(log.find({closed}), files_before, SerializePSBT(SyntheticSignedPSBT(fixture.original_psbt)));
        } else if (handling == "partial") {
            // The partial signature uses a fresh key, so compare against the
            // PSBT the wallet produced.
            PartiallySignedTransaction produced;
            {
                std::lock_guard lock{state->mutex};
                produced = state->psbt_signed_result;
            }
            QVERIFY(!produced.inputs.front().partial_sigs.empty());
            VerifyUnshownPSBTSaved(log.find({closed}), files_before, SerializePSBT(produced));
        } else {
            QVERIFY2(log.find({closed}).empty(), handling.c_str());
            QVERIFY2(NewUnshownPSBTFiles(files_before).empty(), handling.c_str());
        }
    }
}

void PSBTOperationsDialogTests::walletUnloadDuringSigning()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->psbt_simulate_pqc_reservation = true;
    state->allow_psbt_completion = false;
    CPQCKey key;
    key.MakeNewKey();
    const wallet::PQCUsageReport pqc_usage{MakePQCUsageReport(key.GetPubKey(), 1)};
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state, pqc_usage};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_counters_reserved; }); }));
    QPointer<WalletModel> model_guard{fixture.wallet_model.get()};
    fixture.wallet_model.reset();
    QVERIFY(model_guard.isNull());

    // The signatures do not need the wallet, so the signed PSBT is kept and
    // reported as signed, with the capacity it consumed.
    fixture.releaseWorker();
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("ready to broadcast")); }));
    const QString status{fixture.statusLabel()->text()};
    QVERIFY2(status.startsWith(QStringLiteral("Signed transaction successfully.")), qPrintable(status));
    QVERIFY2(status.contains(QStringLiteral("The wallet was unloaded while signing.")), qPrintable(status));
    QVERIFY2(status.contains(CONSUMED_SENTENCE), qPrintable(status));
    QVERIFY2(!status.contains(FAILED_SENTENCE), qPrintable(status));
    QCOMPARE(display_updates.count(), 1);
    QVERIFY(fixture.dialog->findChild<QPushButton*>(QStringLiteral("broadcastTransactionButton"))->isEnabled());
    QVERIFY(!fixture.dialog->findChild<QPushButton*>(QStringLiteral("signTransactionButton"))->isEnabled());

    fixture.dialog->copyToClipboard();
    QCOMPARE(ClipboardPSBT(), SerializePSBT(SyntheticSignedPSBT(fixture.original_psbt)));
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.background_clone_destroyed; }); }));
}

void PSBTOperationsDialogTests::signingFailurePreservesOriginalPSBT()
{
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->psbt_simulate_pqc_reservation = true;
    state->psbt_fail = true;
    const SignThreadRecorder sign_threads{state};
    CPQCKey key;
    key.MakeNewKey();
    const wallet::PQCUsageReport pqc_usage{MakePQCUsageReport(key.GetPubKey(), 2)};
    DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state, pqc_usage};
    const std::string original{SerializePSBT(fixture.original_psbt)};
    QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};

    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().startsWith(QStringLiteral("Failed to sign transaction")); }));
    QVERIFY(ReadState(state, [](const auto& value) { return value.psbt_counters_reserved; }));
    QVERIFY(fixture.statusLabel()->text().contains(QStringLiteral("failed after consuming PQC signature capacity")));
    QVERIFY(fixture.statusLabel()->text().contains(PQCPubKeyHex(key.GetPubKey())));
    QVERIFY(fixture.statusLabel()->text().contains(QStringLiteral("2 of %1 signatures used").arg(PQC_MAX_SIGNATURES)));
    QVERIFY(fixture.statusLabel()->text().contains(QStringLiteral("%1 remaining").arg(PQC_MAX_SIGNATURES - 2)));
    QCOMPARE(display_updates.count(), 0);

    fixture.dialog->copyToClipboard();
    const auto decoded{DecodeBase64(QApplication::clipboard()->text().toStdString())};
    QVERIFY(decoded);
    PartiallySignedTransaction clipboard_psbt;
    std::string error;
    QVERIFY(DecodeRawPSBT(clipboard_psbt, MakeByteSpan(*decoded), error));
    QCOMPARE(SerializePSBT(clipboard_psbt), original);

    // The failed attempt is released, so Sign starts another once its thread
    // is gone.
    QVERIFY(fixture.signingControlsEnabled());
    QVERIFY(WaitUntil([&] { return sign_threads.allDeleted(); }));
    fixture.dialog->signTransaction();
    QVERIFY(WaitUntil([&] { return ReadState(state, [](const auto& value) { return value.psbt_sign_calls == 2; }); }));
}

void PSBTOperationsDialogTests::usageStatesOnSuccessAndFailure()
{
    CPQCKey warning_key;
    warning_key.MakeNewKey();
    CPQCKey exhausted_key;
    exhausted_key.MakeNewKey();
    CPQCKey normal_key;
    normal_key.MakeNewKey();
    CPQCKey critical_key;
    critical_key.MakeNewKey();

    const wallet::PQCUsageReport warning_report{qt_test::MakeSyntheticPQCUsageReport({
        {warning_key.GetPubKey(), wallet::PQC_WARNING_SIGNATURE_THRESHOLD},
    })};
    const wallet::PQCUsageReport multi_key_report{qt_test::MakeSyntheticPQCUsageReport({
        {normal_key.GetPubKey(), 3},
        {warning_key.GetPubKey(), wallet::PQC_WARNING_SIGNATURE_THRESHOLD},
        {critical_key.GetPubKey(), wallet::PQC_CRITICAL_SIGNATURE_THRESHOLD},
        {exhausted_key.GetPubKey(), PQC_MAX_SIGNATURES},
    })};
    QCOMPARE(*multi_key_report.overall_state, wallet::PQCSignatureLimitState::EXHAUSTED);
    QCOMPARE(multi_key_report.warnings.size(), size_t{3});

    for (const wallet::PQCUsageReport* report : {&warning_report, &multi_key_report}) {
        // Success: the signed PSBT is displayed with the consumption sentence.
        {
            auto state{std::make_shared<qt_test::SyntheticWalletState>()};
            state->psbt_simulate_pqc_reservation = true;
            DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state, *report};
            fixture.dialog->signTransaction();
            QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().contains(QStringLiteral("ready to broadcast")); }));
            const QString status{fixture.statusLabel()->text()};
            QVERIFY(status.startsWith(QStringLiteral("Signed transaction successfully.")));
            QVERIFY(status.contains(CONSUMED_SENTENCE));
            QVERIFY(!status.contains(FAILED_SENTENCE));
            VerifyStatusListsUsage(status, *report);
            if (QTest::currentTestFailed()) return;

            // The portable PSBT carries only the signature, never wallet-local usage.
            fixture.dialog->copyToClipboard();
            const auto decoded{DecodeBase64(QApplication::clipboard()->text().toStdString())};
            QVERIFY(decoded);
            PartiallySignedTransaction clipboard_psbt;
            std::string error;
            QVERIFY(DecodeRawPSBT(clipboard_psbt, MakeByteSpan(*decoded), error));
            PartiallySignedTransaction expected{fixture.original_psbt};
            expected.inputs.front().final_script_witness.stack = {{0x01}};
            QCOMPARE(SerializePSBT(clipboard_psbt), SerializePSBT(expected));
            QVERIFY(clipboard_psbt.unknown.empty());
            QVERIFY(clipboard_psbt.m_proprietary.empty());
        }

        // Failure after reservation: original PSBT kept, failure sentence shown.
        {
            auto state{std::make_shared<qt_test::SyntheticWalletState>()};
            state->psbt_simulate_pqc_reservation = true;
            state->psbt_fail = true;
            DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state, *report};
            const std::string original{SerializePSBT(fixture.original_psbt)};
            fixture.dialog->signTransaction();
            QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().startsWith(QStringLiteral("Failed to sign transaction")); }));
            const QString status{fixture.statusLabel()->text()};
            QVERIFY(status.contains(FAILED_SENTENCE));
            QVERIFY(!status.contains(CONSUMED_SENTENCE));
            VerifyStatusListsUsage(status, *report);
            if (QTest::currentTestFailed()) return;

            fixture.dialog->copyToClipboard();
            const auto decoded{DecodeBase64(QApplication::clipboard()->text().toStdString())};
            QVERIFY(decoded);
            PartiallySignedTransaction clipboard_psbt;
            std::string error;
            QVERIFY(DecodeRawPSBT(clipboard_psbt, MakeByteSpan(*decoded), error));
            QCOMPARE(SerializePSBT(clipboard_psbt), original);
        }
    }

    // Failure before counter reservation: no usage is invented even though the
    // wallet would report usage had it reserved counters.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->psbt_simulate_pqc_reservation = true;
        state->psbt_fail_before_reservation = true;
        DialogFixture fixture{*m_context->client_model, m_context->platform_style.get(), state, multi_key_report};
        const std::string original{SerializePSBT(fixture.original_psbt)};
        QSignalSpy display_updates{fixture.description(), &QTextEdit::textChanged};
        fixture.dialog->signTransaction();
        QVERIFY(WaitUntil([&] { return fixture.statusLabel()->text().startsWith(QStringLiteral("Failed to sign transaction")); }));
        const QString status{fixture.statusLabel()->text()};
        QVERIFY(!ReadState(state, [](const auto& value) { return value.psbt_counters_reserved; }));
        QVERIFY2(!status.contains(QStringLiteral("PQC")), qPrintable(status));
        QVERIFY(!status.contains(QStringLiteral("consum")));
        QVERIFY(!status.contains(QStringLiteral("\n")));
        QCOMPARE(display_updates.count(), 0);

        fixture.dialog->copyToClipboard();
        const auto decoded{DecodeBase64(QApplication::clipboard()->text().toStdString())};
        QVERIFY(decoded);
        PartiallySignedTransaction clipboard_psbt;
        std::string error;
        QVERIFY(DecodeRawPSBT(clipboard_psbt, MakeByteSpan(*decoded), error));
        QCOMPARE(SerializePSBT(clipboard_psbt), original);
    }
}
