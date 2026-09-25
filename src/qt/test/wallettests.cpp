// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/wallettests.h>
#include <qt/test/util.h>

#include <wallet/coincontrol.h>
#include <common/p2mr_data_signature.h>
#include <crypto/pqc.h>
#include <interfaces/chain.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <node/interface_ui.h>
#include <qt/addresstablemodel.h>
#include <qt/askpassphrasedialog.h>
#include <qt/bitcoinamountfield.h>
#include <qt/qbitunits.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/pqcusageformat.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/receivecoinsdialog.h>
#include <qt/receiverequestdialog.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendcoinsentry.h>
#include <qt/signverifymessagedialog.h>
#include <qt/test/syntheticwallet.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletmodel.h>
#include <qt/walletmodeltransaction.h>
#include <outputtype.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <script/interpreter.h>
#include <script/p2mr.h>
#include <script/p2mr_sizing.h>
#include <script/solver.h>
#include <streams.h>
#include <consensus/consensus.h>
#include <test/util/setup_common.h>
#include <util/translation.h>
#include <validation.h>
#include <wallet/pqc_usage.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <array>
#include <chrono>
#include <functional>
#include <memory>
#include <set>
#include <stdexcept>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QElapsedTimer>
#include <QEvent>
#include <QLabel>
#include <QLineEdit>
#include <QObject>
#include <QPointer>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QProgressDialog>
#include <QPushButton>
#include <QSignalSpy>
#include <QTabWidget>
#include <QTimer>
#include <QTranslator>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QListView>
#include <QDialogButtonBox>

#include <univalue.h>

using wallet::AddWallet;
using wallet::CWallet;
using wallet::CreateMockableWalletDatabase;
using wallet::DuplicateMockDatabase;
using wallet::RemoveWallet;
using wallet::TestLoadWallet;
using wallet::TestUnloadWallet;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS;
using wallet::WalletContext;
using wallet::WalletDescriptor;
using wallet::WalletRescanReserver;

namespace
{
constexpr int QT_WALLET_FUNDING_TXS{5};
constexpr CAmount QT_WALLET_FUNDING_AMOUNT{210 * COIN - 1000};
constexpr std::array QT_WALLET_BECH32_DESCRIPTOR_OUTPUT_TYPES{OutputType::BECH32};
constexpr std::array QT_WALLET_P2MR_DESCRIPTOR_OUTPUT_TYPES{OutputType::P2MR};

QString MakeP2MRProofJson(std::string leaf_version)
{
    UniValue proof{UniValue::VOBJ};
    proof.pushKV("proof_mode", common::P2MR_DATA_SIGNATURE_PROOF_MODE);
    proof.pushKV("address", EncodeDestination(WitnessV2P2MR{}));
    proof.pushKV("message_hash", std::string(uint256::size() * 2, '0'));
    proof.pushKV("pubkey", std::string(PQC_PUBKEY_SIZE * 2, '0'));
    proof.pushKV("signature", std::string(PQC_SIG_SIZE * 2, '0'));
    proof.pushKV("leaf_script", std::string(P2MR_V1_PK_LEAF_SCRIPT_SIZE * 2, '0'));
    proof.pushKV("control_block", "c1");

    UniValue leaf_version_value;
    leaf_version_value.setNumStr(std::move(leaf_version));
    proof.pushKV("leaf_version", std::move(leaf_version_value));
    return QString::fromStdString(proof.write());
}

void TestP2MRProofLeafVersionValidation(SignVerifyMessageDialog& dialog)
{
    QPlainTextEdit* proof_input = dialog.findChild<QPlainTextEdit*>("messageIn_VM");
    QVERIFY(proof_input);
    QComboBox* verify_input_mode = dialog.findChild<QComboBox*>("p2mrVerifyInputMode_VM");
    QVERIFY(verify_input_mode);
    QLabel* status_label = dialog.findChild<QLabel*>("statusLabel_VM");
    QVERIFY(status_label);
    QPushButton* verify_button = dialog.findChild<QPushButton*>("verifyMessageButton_VM");
    QVERIFY(verify_button);

    dialog.showTab_VM(/*fShow=*/false);
    verify_input_mode->setCurrentIndex(2);

    const QString stale_success{"P2MR/PQC proof verified for a previous proof."};
    const QString leaf_version_error{"Proof field \"leaf_version\" must be an integer from 0 to 255."};
    const std::array invalid_leaf_versions{
        "192.0",
        "1e2",
        "-1",
        "256",
        "2147483648",
        "1e1000000",
    };
    for (const char* leaf_version : invalid_leaf_versions) {
        status_label->setStyleSheet("QLabel { color: green; }");
        status_label->setText(stale_success);
        proof_input->setPlainText(MakeP2MRProofJson(leaf_version));

        verify_button->click();

        QCOMPARE(status_label->text(), leaf_version_error);
        QVERIFY(status_label->styleSheet().contains("red"));
        QVERIFY(status_label->text() != stale_success);
        QVERIFY(verify_button->isEnabled());
        QVERIFY(QApplication::instance() != nullptr);
    }

    proof_input->setPlainText(MakeP2MRProofJson("192"));
    verify_button->click();
    QVERIFY(status_label->text().startsWith("P2MR/PQC proof verification failed:"));
    QVERIFY(status_label->styleSheet().contains("red"));
}

template <typename Predicate>
bool WaitUntil(Predicate&& predicate, int timeout_ms)
{
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeout_ms) {
        if (predicate()) return true;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        QTest::qWait(50);
    }
    return predicate();
}

template <typename Predicate>
bool SyntheticStateMatches(const std::shared_ptr<qt_test::SyntheticWalletState>& state, Predicate&& predicate)
{
    std::lock_guard lock{state->mutex};
    return predicate(*state);
}

QProgressDialog* FindBumpFeeProgressDialog()
{
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (widget->objectName() == QStringLiteral("bumpFeeProgressDialog")) {
            return qobject_cast<QProgressDialog*>(widget);
        }
    }
    return nullptr;
}

void ReleaseSyntheticBumpSigning(const std::shared_ptr<qt_test::SyntheticWalletState>& state)
{
    {
        std::lock_guard lock{state->mutex};
        state->allow_bump_sign = true;
    }
    state->condition.notify_all();
}

// Declare after the model so a failed assertion releases the worker before
// the model destructor joins it. Normal test paths still release each latch
// explicitly at the boundary being exercised.
struct ReleaseSyntheticBumpOnExit {
    std::shared_ptr<qt_test::SyntheticWalletState> state;

    ~ReleaseSyntheticBumpOnExit()
    {
        {
            std::lock_guard lock{state->mutex};
            state->allow_bump_prepare = true;
            state->allow_bump_reservation = true;
            state->allow_bump_counter_boundary = true;
            state->allow_external_bump_boundary = true;
            state->allow_bump_sign = true;
        }
        state->condition.notify_all();
    }
};

class SendConfirmationClicker : public QObject
{
public:
    SendConfirmationClicker(QString* text, QMessageBox::StandardButton confirm_type, std::function<void()> before_click = {})
        : QObject(QApplication::instance()), m_text(text), m_confirm_type(confirm_type), m_before_click(std::move(before_click))
    {
        QApplication::instance()->installEventFilter(this);
        m_timer.setInterval(50);
        connect(&m_timer, &QTimer::timeout, this, &SendConfirmationClicker::tryClickVisibleDialog);
        m_timer.start();
    }

    ~SendConfirmationClicker() override
    {
        QApplication::instance()->removeEventFilter(this);
    }

    bool eventFilter(QObject* watched, QEvent* event) override
    {
        if (event->type() == QEvent::Show && watched->inherits("SendConfirmationDialog")) {
            m_dialog = qobject_cast<SendConfirmationDialog*>(watched);
        }
        return QObject::eventFilter(watched, event);
    }

private:
    void tryClickVisibleDialog()
    {
        if (m_dialog) {
            click(m_dialog);
            return;
        }
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("SendConfirmationDialog") && widget->isVisible()) {
                click(qobject_cast<SendConfirmationDialog*>(widget));
                return;
            }
        }
    }

    void click(SendConfirmationDialog* dialog)
    {
        if (m_clicked || !dialog) return;
        m_clicked = true;
        if (m_text) *m_text = dialog->text();
        if (m_before_click) m_before_click();
        QAbstractButton* button = dialog->button(m_confirm_type);
        button->setEnabled(true);
        button->click();
        m_timer.stop();
        deleteLater();
    }

    QString* const m_text;
    const QMessageBox::StandardButton m_confirm_type;
    const std::function<void()> m_before_click;
    QTimer m_timer;
    QPointer<SendConfirmationDialog> m_dialog;
    bool m_clicked{false};
};

class MessageBoxClicker : public QObject
{
public:
    MessageBoxClicker(QString object_name, QMessageBox::StandardButton button, QString* text = nullptr, Qt::TextFormat* text_format = nullptr, std::function<void()> before_click = {})
        : QObject(QApplication::instance()), m_object_name(std::move(object_name)), m_button(button), m_text(text), m_text_format(text_format), m_before_click(std::move(before_click))
    {
        QApplication::instance()->installEventFilter(this);
        m_timer.setInterval(50);
        connect(&m_timer, &QTimer::timeout, this, &MessageBoxClicker::tryClickVisibleDialog);
        m_timer.start();
    }

    ~MessageBoxClicker() override
    {
        QApplication::instance()->removeEventFilter(this);
    }

    bool eventFilter(QObject* watched, QEvent* event) override
    {
        if (event->type() == QEvent::Show && watched->inherits("QMessageBox")) {
            QMessageBox* const dialog{qobject_cast<QMessageBox*>(watched)};
            if (matches(dialog)) m_dialog = dialog;
        }
        return QObject::eventFilter(watched, event);
    }

private:
    bool matches(QMessageBox* dialog) const
    {
        if (!dialog) return false;
        if (m_object_name.isEmpty()) return !dialog->inherits("SendConfirmationDialog");
        return dialog->objectName() == m_object_name;
    }

    void tryClickVisibleDialog()
    {
        if (m_dialog) {
            click(m_dialog);
            return;
        }
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("QMessageBox") && widget->isVisible()) {
                click(qobject_cast<QMessageBox*>(widget));
                if (m_clicked) return;
            }
        }
    }

    void click(QMessageBox* dialog)
    {
        if (m_clicked || m_click_pending || !matches(dialog)) return;
        QAbstractButton* button = dialog->button(m_button);
        if (!button) return;
        if (m_text) *m_text = dialog->text();
        if (m_text_format) *m_text_format = dialog->textFormat();
        if (m_before_click) {
            const std::function<void()> before_click{std::move(m_before_click)};
            m_before_click = {};
            before_click();
        }
        if (!m_finished_connected) {
            m_finished_connected = true;
            connect(dialog, &QMessageBox::finished, this, [this] {
                m_clicked = true;
                m_timer.stop();
                deleteLater();
            });
        }
        m_click_pending = true;
        button->setEnabled(true);
        button->click();
    }

    const QString m_object_name;
    const QMessageBox::StandardButton m_button;
    QString* const m_text;
    Qt::TextFormat* const m_text_format;
    std::function<void()> m_before_click;
    QTimer m_timer;
    QPointer<QMessageBox> m_dialog;
    bool m_clicked{false};
    bool m_click_pending{false};
    bool m_finished_connected{false};
};

//! Press "Yes" or "Cancel" buttons in modal send confirmation dialog.
void ConfirmSend(QString* text = nullptr, QMessageBox::StandardButton confirm_type = QMessageBox::Yes, std::function<void()> before_click = {})
{
    new SendConfirmationClicker(text, confirm_type, std::move(before_click));
}

//! Send coins to address and return txid.
Txid SendCoins(CWallet& wallet, SendCoinsDialog& sendCoinsDialog, const CTxDestination& address, CAmount amount, bool rbf,
               QMessageBox::StandardButton confirm_type = QMessageBox::Yes, QString* confirm_text = nullptr)
{
    QVBoxLayout* entries = sendCoinsDialog.findChild<QVBoxLayout*>("entries");
    SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(QString::fromStdString(EncodeDestination(address)));
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(amount);
    sendCoinsDialog.findChild<QFrame*>("frameFee")
        ->findChild<QFrame*>("frameFeeSelection")
        ->findChild<QCheckBox*>("optInRBF")
        ->setCheckState(rbf ? Qt::Checked : Qt::Unchecked);
    Txid txid;
    boost::signals2::scoped_connection c(wallet.NotifyTransactionChanged.connect([&txid](const Txid& hash, ChangeType status) {
        if (status == CT_NEW) txid = hash;
    }));
    QString send_error;
    const QMetaObject::Connection message_connection = QObject::connect(&sendCoinsDialog, &SendCoinsDialog::message, [&](const QString&, const QString& message, unsigned int style) {
        if (style & CClientUIInterface::MSG_ERROR) send_error = message;
    });
    const QString clipboard_before = QApplication::clipboard()->text();
    ConfirmSend(confirm_text, confirm_type);
    if (confirm_type == QMessageBox::Save) {
        new MessageBoxClicker(QStringLiteral("psbt_copied_message"), QMessageBox::Discard);
    }
    bool invoked = QMetaObject::invokeMethod(&sendCoinsDialog, "sendButtonClicked", Q_ARG(bool, false));
    assert(invoked);
    if (confirm_type == QMessageBox::Yes) {
        if (!WaitUntil([&txid, &send_error] { return !txid.IsNull() || !send_error.isEmpty(); }, 60000)) {
            QTest::qFail("Timed out waiting for sent transaction notification", __FILE__, __LINE__);
        }
        if (txid.IsNull() && !send_error.isEmpty()) {
            const QByteArray error = ("Send failed before transaction notification: " + send_error).toLocal8Bit();
            QTest::qFail(error.constData(), __FILE__, __LINE__);
        }
    } else if (confirm_type == QMessageBox::Save) {
        if (!WaitUntil([&clipboard_before, &send_error] {
                return (!QApplication::clipboard()->text().isEmpty() && QApplication::clipboard()->text() != clipboard_before) || !send_error.isEmpty();
            }, 60000)) {
            QTest::qFail("Timed out waiting for PSBT clipboard update", __FILE__, __LINE__);
        }
        if (!send_error.isEmpty()) {
            const QByteArray error = ("PSBT creation failed: " + send_error).toLocal8Bit();
            QTest::qFail(error.constData(), __FILE__, __LINE__);
        }
    }
    QObject::disconnect(message_connection);
    return txid;
}

//! Find index of txid in transaction list.
QModelIndex FindTx(const QAbstractItemModel& model, const Txid& txid)
{
    QString hash = QString::fromStdString(txid.ToString());
    int rows = model.rowCount({});
    for (int row = 0; row < rows; ++row) {
        QModelIndex index = model.index(row, 0, {});
        if (model.data(index, TransactionTableModel::TxHashRole) == hash) {
            return index;
        }
    }
    return {};
}

//! Invoke bumpfee on txid and check results.
void BumpFee(TransactionView& view, const Txid& txid, bool expectDisabled, std::string expectError, bool cancel)
{
    QTableView* table = view.findChild<QTableView*>("transactionView");
    QModelIndex index = FindTx(*table->selectionModel()->model(), txid);
    QVERIFY2(index.isValid(), "Could not find BumpFee txid");

    // Select row in table, invoke context menu, and make sure bumpfee action is
    // enabled or disabled as expected.
    QAction* action = view.findChild<QAction*>("bumpFeeAction");
    table->selectionModel()->select(index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    action->setEnabled(expectDisabled);
    table->customContextMenuRequested({});
    QCOMPARE(action->isEnabled(), !expectDisabled);

    action->setEnabled(true);
    QString text;
    QSignalSpy bumped{&view, &TransactionView::bumpedFee};
    QVERIFY(bumped.isValid());
    if (expectError.empty()) {
        ConfirmSend(&text, cancel ? QMessageBox::Cancel : QMessageBox::Yes);
    } else {
        new MessageBoxClicker({}, QMessageBox::Ok, &text);
    }
    action->trigger();
    if (!expectError.empty() || cancel) {
        QVERIFY2(WaitUntil([&text] { return !text.isEmpty(); }, 60000), "Timed out waiting for fee-bump dialog");
    } else {
        QVERIFY2(WaitUntil([&bumped] { return bumped.count() == 1; }, 60000), "Timed out waiting for fee-bump completion");
    }
    QVERIFY(text.indexOf(QString::fromStdString(expectError)) != -1);
}

void CompareBalance(WalletModel& walletModel, CAmount expected_balance, QLabel* balance_label_to_check,
                    QbitUnits::SeparatorStyle separators = QbitUnits::SeparatorStyle::ALWAYS)
{
    QbitUnit unit = walletModel.getOptionsModel()->getDisplayUnit();
    QString balanceComparison = QbitUnits::formatWithUnit(unit, expected_balance, false, separators);
    QCOMPARE(balance_label_to_check->text().trimmed(), balanceComparison);
}

// Verify the 'useAvailableBalance' functionality. With and without manually selected coins.
// Case 1: No coin control selected coins.
// 'useAvailableBalance' should fill the amount edit box with the total available balance
// Case 2: With coin control selected coins.
// 'useAvailableBalance' should fill the amount edit box with the sum of the selected coins values.
void VerifyUseAvailableBalance(SendCoinsDialog& sendCoinsDialog, const WalletModel& walletModel)
{
    // Verify first entry amount and "useAvailableBalance" button
    QVBoxLayout* entries = sendCoinsDialog.findChild<QVBoxLayout*>("entries");
    QVERIFY(entries->count() == 1); // only one entry
    SendCoinsEntry* send_entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    QVERIFY(send_entry->getValue().amount == 0);
    // Now click "useAvailableBalance", check updated balance (the entire wallet balance should be set)
    Q_EMIT send_entry->useAvailableBalance(send_entry);
    QVERIFY(send_entry->getValue().amount == walletModel.getCachedBalance().balance);

    // Now manually select two coins and click on "useAvailableBalance". Then check updated balance
    // (only the sum of the selected coins should be set).
    int COINS_TO_SELECT = 2;
    auto coins = walletModel.wallet().listCoins();
    CAmount sum_selected_coins = 0;
    int selected = 0;
    QVERIFY(coins.size() == 1); // context check, coins received only on one destination
    for (const auto& [outpoint, tx_out] : coins.begin()->second) {
        sendCoinsDialog.getCoinControl()->Select(outpoint);
        sum_selected_coins += tx_out.txout.nValue;
        if (++selected == COINS_TO_SELECT) break;
    }
    QVERIFY(selected == COINS_TO_SELECT);

    // Now that we have 2 coins selected, "useAvailableBalance" should update the balance label only with
    // the sum of them.
    Q_EMIT send_entry->useAvailableBalance(send_entry);
    QVERIFY(send_entry->getValue().amount == sum_selected_coins);
}

void SyncUpWallet(const std::shared_ptr<CWallet>& wallet, interfaces::Node& node, const uint256& start_block, int start_height)
{
    WalletRescanReserver reserver(*wallet);
    reserver.reserve();
    CWallet::ScanResult result = wallet->ScanForWalletTransactions(start_block, start_height, /*max_height=*/{}, reserver, /*fUpdate=*/true, /*save_progress=*/false);
    QCOMPARE(result.status, CWallet::ScanResult::SUCCESS);
    QCOMPARE(result.last_scanned_block, WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash()));
    QVERIFY(result.last_scanned_height.has_value());
    QVERIFY(result.last_failed_block.IsNull());
    {
        LOCK(wallet->cs_wallet);
        wallet->SetLastBlockProcessed(*result.last_scanned_height, result.last_scanned_block);
    }
}

void FundWalletFromCoinbase(interfaces::Node& node, TestChain100Setup& test, const std::shared_ptr<CWallet>& wallet, size_t coinbase_offset)
{
    for (int i = 0; i < QT_WALLET_FUNDING_TXS - 1; ++i) {
        test.CreateAndProcessBlock({}, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));
    }

    const uint256 funding_start_block = WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash());
    const int funding_start_height = WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Height());

    std::vector<CMutableTransaction> funding_txs;
    funding_txs.reserve(QT_WALLET_FUNDING_TXS);
    const CScript wallet_script = GetScriptForRawPubKey(test.coinbaseKey.GetPubKey());
    for (int i = 0; i < QT_WALLET_FUNDING_TXS; ++i) {
        funding_txs.push_back(test.CreateValidMempoolTransaction(
            test.m_coinbase_txns.at(coinbase_offset + i),
            /*input_vout=*/0,
            /*input_height=*/static_cast<int>(coinbase_offset) + i + 1,
            test.coinbaseKey,
            wallet_script,
            QT_WALLET_FUNDING_AMOUNT,
            /*submit=*/false));
    }

    const CBlock funding_block = test.CreateAndProcessBlock(funding_txs, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    {
        LOCK(wallet->cs_wallet);
        wallet->SetLastBlockProcessed(funding_start_height, funding_start_block);
    }
    SyncUpWallet(wallet, node, funding_block.GetHash(), funding_start_height + 1);
}

std::shared_ptr<CWallet> SetupDescriptorsWallet(interfaces::Node& node, TestChain100Setup& test, bool watch_only = false, size_t coinbase_offset = 0, std::span<const OutputType> descriptor_output_types = QT_WALLET_BECH32_DESCRIPTOR_OUTPUT_TYPES, bool fund_wallet = true)
{
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", CreateMockableWalletDatabase());
    wallet->LoadWallet();
    wallet->m_keypool_size = 1;
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        if (watch_only) {
            wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        } else {
            wallet->SetupDescriptorScriptPubKeyMans(descriptor_output_types);
        }

        // Add the coinbase key.
        FlatSigningProvider provider;
        std::string error;
        std::string key_str;
        if (watch_only) {
            key_str = HexStr(test.coinbaseKey.GetPubKey());
        } else {
            key_str = EncodeSecret(test.coinbaseKey);
        }
        auto descs = Parse("combo(" + key_str + ")", provider, error, /* require_checksum=*/ false);
        assert(!descs.empty());
        assert(descs.size() == 1);
        auto& desc = descs.at(0);
        WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
        Assert(wallet->AddWalletDescriptor(w_desc, provider, "", false));
        const PKHash dest{test.coinbaseKey.GetPubKey()};
        wallet->SetAddressBook(dest, "", wallet::AddressPurpose::RECEIVE);
    }
    if (fund_wallet) {
        FundWalletFromCoinbase(node, test, wallet, coinbase_offset);
    }
    wallet->SetBroadcastTransactions(true);
    return wallet;
}

struct MiniGUI {
public:
    SendCoinsDialog sendCoinsDialog;
    TransactionView transactionView;
    OptionsModel optionsModel;
    std::unique_ptr<ClientModel> clientModel;
    std::unique_ptr<WalletModel> walletModel;

    MiniGUI(interfaces::Node& node, const PlatformStyle* platformStyle) : sendCoinsDialog(platformStyle), transactionView(platformStyle), optionsModel(node) {
        bilingual_str error;
        QVERIFY(optionsModel.Init(error));
        clientModel = std::make_unique<ClientModel>(node, &optionsModel);
    }

    void initModelForWallet(interfaces::Node& node, const std::shared_ptr<CWallet>& wallet, const PlatformStyle* platformStyle)
    {
        WalletContext& context = *node.walletLoader().context();
        AddWallet(context, wallet);
        walletModel = std::make_unique<WalletModel>(interfaces::MakeWallet(context, wallet), *clientModel, platformStyle);
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);
        sendCoinsDialog.setModel(walletModel.get());
        transactionView.setModel(walletModel.get());
    }

    void initModel(std::unique_ptr<interfaces::Wallet> wallet, const PlatformStyle* platformStyle)
    {
        walletModel = std::make_unique<WalletModel>(std::move(wallet), *clientModel, platformStyle);
        sendCoinsDialog.setModel(walletModel.get());
        transactionView.setModel(walletModel.get());
    }

};

//! Simple qt wallet tests.
//
// Test widgets can be debugged interactively calling show() on them and
// manually running the event loop, e.g.:
//
//     sendCoinsDialog.show();
//     QEventLoop().exec();
//
// This also requires overriding the default minimal Qt platform:
//
//     QT_QPA_PLATFORM=xcb     build/bin/test_qbit-qt  # Linux
//     QT_QPA_PLATFORM=windows build/bin/test_qbit-qt  # Windows
//     QT_QPA_PLATFORM=cocoa   build/bin/test_qbit-qt  # macOS
void TestGUI(interfaces::Node& node, const std::shared_ptr<CWallet>& wallet)
{
    // Create widgets for sending coins and listing transactions.
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    MiniGUI mini_gui(node, platformStyle.get());
    mini_gui.initModelForWallet(node, wallet, platformStyle.get());
    WalletModel& walletModel = *mini_gui.walletModel;
    SendCoinsDialog& sendCoinsDialog = mini_gui.sendCoinsDialog;
    TransactionView& transactionView = mini_gui.transactionView;

    SignVerifyMessageDialog legacy_sign_verify_dialog(platformStyle.get(), nullptr);
    legacy_sign_verify_dialog.setModel(&walletModel);
    QLabel* expected_signer_label = legacy_sign_verify_dialog.findChild<QLabel*>("expectedSignerLabel_VM");
    QVERIFY(expected_signer_label);
    QVERIFY(expected_signer_label->isHidden());
    QValidatedLineEdit* legacy_verify_address = legacy_sign_verify_dialog.findChild<QValidatedLineEdit*>("addressIn_VM");
    QVERIFY(legacy_verify_address);
    QVERIFY(!legacy_verify_address->isHidden());

    // Update walletModel cached balance which will trigger an update for the 'labelBalance' QLabel.
    walletModel.pollBalanceChanged();
    // Check balance in send dialog
    CompareBalance(walletModel, walletModel.wallet().getBalance(), sendCoinsDialog.findChild<QLabel*>("labelBalance"),
                   QbitUnits::SeparatorStyle::STANDARD);

    // Check 'UseAvailableBalance' functionality
    VerifyUseAvailableBalance(sendCoinsDialog, walletModel);

    // Send two transactions, and verify they are added to transaction list.
    TransactionTableModel* transactionTableModel = walletModel.getTransactionTableModel();
    QCOMPARE(transactionTableModel->rowCount({}), QT_WALLET_FUNDING_TXS);
    Txid txid1 = SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 5 * COIN, /*rbf=*/false);
    Txid txid2 = SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 10 * COIN, /*rbf=*/true);
    // Transaction table model updates on a QueuedConnection, so process events to ensure it's updated.
    qApp->processEvents();
    QCOMPARE(transactionTableModel->rowCount({}), QT_WALLET_FUNDING_TXS + 2);
    QVERIFY(FindTx(*transactionTableModel, txid1).isValid());
    QVERIFY(FindTx(*transactionTableModel, txid2).isValid());

    // Call bumpfee. Test canceled fullrbf bump, canceled bip-125-rbf bump, passing bump, and then failing bump.
    BumpFee(transactionView, txid1, /*expectDisabled=*/false, /*expectError=*/{}, /*cancel=*/true);
    BumpFee(transactionView, txid2, /*expectDisabled=*/false, /*expectError=*/{}, /*cancel=*/true);
    BumpFee(transactionView, txid2, /*expectDisabled=*/false, /*expectError=*/{}, /*cancel=*/false);
    BumpFee(transactionView, txid2, /*expectDisabled=*/true, /*expectError=*/"already bumped", /*cancel=*/false);

    // Check current balance on OverviewPage
    OverviewPage overviewPage(platformStyle.get());
    overviewPage.setWalletModel(&walletModel);
    walletModel.pollBalanceChanged(); // Manual balance polling update
    CompareBalance(walletModel, walletModel.wallet().getBalance(), overviewPage.findChild<QLabel*>("labelBalance"));

    // Check Request Payment button
    ReceiveCoinsDialog receiveCoinsDialog(platformStyle.get());
    receiveCoinsDialog.setModel(&walletModel);
    RecentRequestsTableModel* requestTableModel = walletModel.getRecentRequestsTableModel();

    // Label input
    QLineEdit* labelInput = receiveCoinsDialog.findChild<QLineEdit*>("reqLabel");
    labelInput->setText("TEST_LABEL_1");

    // Amount input
    BitcoinAmountField* amountInput = receiveCoinsDialog.findChild<BitcoinAmountField*>("reqAmount");
    amountInput->setValue(1);

    // Message input
    QLineEdit* messageInput = receiveCoinsDialog.findChild<QLineEdit*>("reqMessage");
    messageInput->setText("TEST_MESSAGE_1");
    int initialRowCount = requestTableModel->rowCount({});
    QPushButton* requestPaymentButton = receiveCoinsDialog.findChild<QPushButton*>("receiveButton");
    requestPaymentButton->click();
    QString address;
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (widget->inherits("ReceiveRequestDialog")) {
            ReceiveRequestDialog* receiveRequestDialog = qobject_cast<ReceiveRequestDialog*>(widget);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("payment_header")->text(), QString("Payment information"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("uri_tag")->text(), QString("URI:"));
            QString uri = receiveRequestDialog->QObject::findChild<QLabel*>("uri_content")->text();
            QCOMPARE(uri.count("qbit:"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("address_tag")->text(), QString("Address:"));
            QVERIFY(address.isEmpty());
            address = receiveRequestDialog->QObject::findChild<QLabel*>("address_content")->text();
            QVERIFY(!address.isEmpty());

            QCOMPARE(uri.count("amount=0.00000001"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("amount_tag")->text(), QString("Amount:"));
            const QbitUnit display_unit{walletModel.getOptionsModel()->getDisplayUnit()};
            const QString expected_amount{
                QbitUnits::formatWithUnit(display_unit, CAmount{1}, /*plussign=*/false, QbitUnits::SeparatorStyle::NEVER)
            };
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("amount_content")->text(), expected_amount);

            QCOMPARE(uri.count("label=TEST_LABEL_1"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("label_tag")->text(), QString("Label:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("label_content")->text(), QString("TEST_LABEL_1"));

            QCOMPARE(uri.count("message=TEST_MESSAGE_1"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("message_tag")->text(), QString("Message:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("message_content")->text(), QString("TEST_MESSAGE_1"));
        }
    }

    // Clear button
    QPushButton* clearButton = receiveCoinsDialog.findChild<QPushButton*>("clearButton");
    clearButton->click();
    QCOMPARE(labelInput->text(), QString(""));
    QCOMPARE(amountInput->value(), CAmount(0));
    QCOMPARE(messageInput->text(), QString(""));

    // Check addition to history
    int currentRowCount = requestTableModel->rowCount({});
    QCOMPARE(currentRowCount, initialRowCount+1);

    // Check addition to wallet
    std::vector<std::string> requests = walletModel.wallet().getAddressReceiveRequests();
    QCOMPARE(requests.size(), size_t{1});
    RecentRequestEntry entry;
    DataStream{MakeUCharSpan(requests[0])} >> entry;
    QCOMPARE(entry.nVersion, int{1});
    QCOMPARE(entry.id, int64_t{1});
    QVERIFY(entry.date.isValid());
    QCOMPARE(entry.recipient.address, address);
    QCOMPARE(entry.recipient.label, QString{"TEST_LABEL_1"});
    QCOMPARE(entry.recipient.amount, CAmount{1});
    QCOMPARE(entry.recipient.message, QString{"TEST_MESSAGE_1"});
    QCOMPARE(entry.recipient.sPaymentRequest, std::string{});
    QCOMPARE(entry.recipient.authenticatedMerchant, QString{});

    // Check Remove button
    QTableView* table = receiveCoinsDialog.findChild<QTableView*>("recentRequestsView");
    table->selectRow(currentRowCount-1);
    QPushButton* removeRequestButton = receiveCoinsDialog.findChild<QPushButton*>("removeRequestButton");
    removeRequestButton->click();
    QCOMPARE(requestTableModel->rowCount({}), currentRowCount-1);

    // Check removal from wallet
    QCOMPARE(walletModel.wallet().getAddressReceiveRequests().size(), size_t{0});
}

void TestGUIWatchOnly(interfaces::Node& node, TestChain100Setup& test)
{
    const std::shared_ptr<CWallet>& wallet = SetupDescriptorsWallet(node, test, /*watch_only=*/true, /*coinbase_offset=*/QT_WALLET_FUNDING_TXS);

    // Create widgets and init models
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    MiniGUI mini_gui(node, platformStyle.get());
    mini_gui.initModelForWallet(node, wallet, platformStyle.get());

    WalletModel& walletModel = *mini_gui.walletModel;
    SendCoinsDialog& sendCoinsDialog = mini_gui.sendCoinsDialog;

    // Update walletModel cached balance which will trigger an update for the 'labelBalance' QLabel.
    walletModel.pollBalanceChanged();
    // Check balance in send dialog
    CompareBalance(walletModel, walletModel.wallet().getBalances().balance,
                   sendCoinsDialog.findChild<QLabel*>("labelBalance"),
                   QbitUnits::SeparatorStyle::STANDARD);

    // Set change address
    sendCoinsDialog.getCoinControl()->destChange = PKHash{test.coinbaseKey.GetPubKey()};

    // Send tx and verify PSBT copied to the clipboard.
    SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 5 * COIN, /*rbf=*/false, QMessageBox::Save);
    const std::string& psbt_string = QApplication::clipboard()->text().toStdString();
    QVERIFY(!psbt_string.empty());

    // Decode psbt
    std::optional<std::vector<unsigned char>> decoded_psbt = DecodeBase64(psbt_string);
    QVERIFY(decoded_psbt);
    PartiallySignedTransaction psbt;
    std::string err;
    QVERIFY(DecodeRawPSBT(psbt, MakeByteSpan(*decoded_psbt), err));
}

UniValue CopyProofWithout(const UniValue& proof, std::string_view omitted_key)
{
    UniValue copy(UniValue::VOBJ);
    const std::vector<std::string>& keys{proof.getKeys()};
    const std::vector<UniValue>& values{proof.getValues()};
    for (size_t i{0}; i < keys.size(); ++i) {
        if (keys[i] != omitted_key) copy.pushKVEnd(keys[i], values[i]);
    }
    return copy;
}

UniValue ProofWithControlDepth(const UniValue& proof, size_t depth)
{
    assert(depth <= P2MR_CONTROL_MAX_NODE_COUNT);

    UniValue result{proof};
    std::vector<unsigned char> control_block{ParseHex(proof.find_value("control_block").get_str())};
    control_block.resize(P2MR_CONTROL_BASE_SIZE);
    for (size_t node{0}; node < depth; ++node) {
        for (size_t byte{0}; byte < P2MR_CONTROL_NODE_SIZE; ++byte) {
            control_block.push_back(static_cast<unsigned char>(node + byte + 1));
        }
    }

    const std::vector<unsigned char> leaf_script{ParseHex(proof.find_value("leaf_script").get_str())};
    const uint8_t leaf_version{proof.find_value("leaf_version").getInt<uint8_t>()};
    const uint256 leaf_hash{ComputeP2MRLeafHash(leaf_version, leaf_script)};
    const uint256 merkle_root{ComputeP2MRMerkleRoot(control_block, leaf_hash)};
    result.pushKV("control_block", HexStr(control_block));
    result.pushKV("address", EncodeDestination(WitnessV2P2MR{merkle_root}));
    return result;
}

QString ProofWithNestedArrays(const UniValue& proof, size_t array_count)
{
    std::string json{proof.write()};
    assert(!json.empty() && json.back() == '}');
    json.pop_back();
    json += ",\"nested\":";
    json.append(array_count, '[');
    json += '0';
    json.append(array_count, ']');
    json += '}';
    return QString::fromStdString(json);
}

//! Shared inputs for the P2MR sign-path cases where the wallet signs the
//! data hash but the dialog's own local verification then rejects the proof.
//! The key material and the valid synthetic result are built once inside
//! TestP2MRReceiveAddressTypes and borrowed here by reference.
struct P2MRProofDialogFixture {
    const PlatformStyle* platform_style;
    ClientModel& client_model;
    const WitnessV2P2MR& output;
    const uint256& message_hash;
    const interfaces::P2MRDataSignatureResult& valid_result;
    const CPQCPubKey& selected_pubkey;
    const CPQCPubKey& alternate_pubkey;
};

struct P2MRSignDialogWidgets {
    QValidatedLineEdit* address{nullptr};
    QComboBox* sign_mode{nullptr};
    QPlainTextEdit* message{nullptr};
    QPushButton* sign_button{nullptr};
    QPlainTextEdit* proof_output{nullptr};
    QLabel* status_label{nullptr};
    QPushButton* copy_button{nullptr};

    bool valid() const
    {
        return address && sign_mode && message && sign_button && proof_output && status_label && copy_button;
    }
};

P2MRSignDialogWidgets FindP2MRSignDialogWidgets(SignVerifyMessageDialog& dialog)
{
    return {
        .address = dialog.findChild<QValidatedLineEdit*>("addressIn_SM"),
        .sign_mode = dialog.findChild<QComboBox*>("p2mrDataInputMode_SM"),
        .message = dialog.findChild<QPlainTextEdit*>("messageIn_SM"),
        .sign_button = dialog.findChild<QPushButton*>("signMessageButton_SM"),
        .proof_output = dialog.findChild<QPlainTextEdit*>("signatureOut_SM"),
        .status_label = dialog.findChild<QLabel*>("statusLabel_SM"),
        .copy_button = dialog.findChild<QPushButton*>("copySignatureButton_SM"),
    };
}

//! Fill the sign tab in data-hash mode for the fixture output and click Sign.
void SignP2MRDataHashInDialog(const P2MRSignDialogWidgets& widgets, const P2MRProofDialogFixture& fixture)
{
    widgets.address->setText(QString::fromStdString(EncodeDestination(CTxDestination{fixture.output})));
    widgets.sign_mode->setCurrentIndex(1);
    widgets.message->setPlainText(QString::fromStdString(HexStr(std::span<const unsigned char>{fixture.message_hash.begin(), fixture.message_hash.end()})));
    widgets.sign_button->click();
}

//! A copy of the valid synthetic result whose signature no longer verifies.
//! The wallet stub still reports success, so the dialog reaches the real
//! verifier, which rejects the proof deterministically.
interfaces::P2MRDataSignatureResult CorruptedP2MRResult(const P2MRProofDialogFixture& fixture)
{
    interfaces::P2MRDataSignatureResult corrupted{fixture.valid_result};
    assert(!corrupted.signature.empty());
    corrupted.signature[0] ^= 0x01;
    return corrupted;
}

QString PubKeyHex(const CPQCPubKey& pubkey)
{
    return QString::fromStdString(HexStr(std::span<const unsigned char>{pubkey.begin(), pubkey.end()}));
}

//! Issue #129: when the wallet signs but the generated proof fails the
//! dialog's local verification, the red status must still show the
//! wallet-local PQC usage the attempt consumed, exactly like the ordinary
//! wallet-error branch, while nothing is written to or exported from the
//! proof output.
void TestGeneratedProofVerificationFailureShowsUsage(const P2MRProofDialogFixture& fixture)
{
    const interfaces::P2MRDataSignatureResult corrupted_result{CorruptedP2MRResult(fixture)};
    const QString selected_pubkey_hex{PubKeyHex(fixture.selected_pubkey)};
    const QString alternate_pubkey_hex{PubKeyHex(fixture.alternate_pubkey)};

    // Case A: a single NORMAL key with no warnings.
    wallet::PQCUsageReport normal_report;
    normal_report.key_states.push_back({
        .pubkey = fixture.selected_pubkey,
        .signature_count = 1,
        .signature_limit = PQC_MAX_SIGNATURES,
        .signatures_remaining = PQC_MAX_SIGNATURES - 1,
        .limit_state = wallet::PQCSignatureLimitState::NORMAL,
    });
    normal_report.overall_state = wallet::PQCSignatureLimitState::NORMAL;
    QVERIFY(normal_report.warnings.empty());

    {
        WalletModel wallet_model(qt_test::MakeSyntheticWallet(corrupted_result, normal_report), fixture.client_model, fixture.platform_style);
        SignVerifyMessageDialog dialog(fixture.platform_style, nullptr);
        dialog.setModel(&wallet_model);
        const P2MRSignDialogWidgets widgets{FindP2MRSignDialogWidgets(dialog)};
        QVERIFY(widgets.valid());

        SignP2MRDataHashInDialog(widgets, fixture);

        const QString status{widgets.status_label->text()};
        QVERIFY(widgets.proof_output->toPlainText().isEmpty());
        QVERIFY(widgets.status_label->styleSheet().contains("color: red"));
        QVERIFY(status.contains("Generated proof failed local verification: signature does not verify"));
        QVERIFY(status.contains("failed after consuming PQC signature capacity"));
        QVERIFY(status.contains("PQC usage state after this signing attempt: normal."));
        QVERIFY(status.contains(QString("PQC key %1: 1 of %2 signatures used, %3 remaining; state: normal.")
                                    .arg(selected_pubkey_hex)
                                    .arg(PQC_MAX_SIGNATURES)
                                    .arg(PQC_MAX_SIGNATURES - 1)));
        QCOMPARE(status.count("PQC key "), 1);
        QVERIFY(!status.contains(alternate_pubkey_hex));
        QVERIFY(!status.contains("entered "));
        QVERIFY(!status.contains("reached the signature limit"));
        QVERIFY(!status.contains("remains in "));
        QVERIFY(!status.contains("proof signed"));

        // The rejected proof is never exported.
        QApplication::clipboard()->clear();
        widgets.copy_button->click();
        QCOMPARE(QApplication::clipboard()->text(), QString{});
    }

    // Case B: multi-key report with the selected key exhausted (same shape as
    // the ordinary wallet-error case).
    wallet::PQCUsageReport exhausted_report;
    exhausted_report.key_states.push_back({
        .pubkey = fixture.alternate_pubkey,
        .signature_count = 1,
        .signature_limit = PQC_MAX_SIGNATURES,
        .signatures_remaining = PQC_MAX_SIGNATURES - 1,
        .limit_state = wallet::PQCSignatureLimitState::NORMAL,
    });
    exhausted_report.key_states.push_back({
        .pubkey = fixture.selected_pubkey,
        .signature_count = PQC_MAX_SIGNATURES,
        .signature_limit = PQC_MAX_SIGNATURES,
        .signatures_remaining = 0,
        .limit_state = wallet::PQCSignatureLimitState::EXHAUSTED,
    });
    exhausted_report.overall_state = wallet::PQCSignatureLimitState::EXHAUSTED;
    exhausted_report.warnings.push_back({
        .pubkey = fixture.selected_pubkey,
        .previous_count = PQC_MAX_SIGNATURES - 1,
        .new_count = PQC_MAX_SIGNATURES,
        .previous_state = wallet::PQCSignatureLimitState::CRITICAL,
        .current_state = wallet::PQCSignatureLimitState::EXHAUSTED,
        .kind = wallet::PQCUsageWarningKind::TRANSITION,
    });

    {
        WalletModel wallet_model(qt_test::MakeSyntheticWallet(corrupted_result, exhausted_report), fixture.client_model, fixture.platform_style);
        SignVerifyMessageDialog dialog(fixture.platform_style, nullptr);
        dialog.setModel(&wallet_model);
        const P2MRSignDialogWidgets widgets{FindP2MRSignDialogWidgets(dialog)};
        QVERIFY(widgets.valid());

        SignP2MRDataHashInDialog(widgets, fixture);

        const QString status{widgets.status_label->text()};
        QVERIFY(widgets.proof_output->toPlainText().isEmpty());
        QVERIFY(widgets.status_label->styleSheet().contains("color: red"));
        QVERIFY(status.contains("Generated proof failed local verification: signature does not verify"));
        QVERIFY(status.contains("failed after consuming PQC signature capacity"));
        QVERIFY(status.contains("PQC usage state after this signing attempt: exhausted."));
        QVERIFY(status.contains(QString("PQC key %1: 1 of %2 signatures used, %3 remaining; state: normal.")
                                    .arg(alternate_pubkey_hex)
                                    .arg(PQC_MAX_SIGNATURES)
                                    .arg(PQC_MAX_SIGNATURES - 1)));
        QVERIFY(status.contains(QString("PQC key %1: %2 of %2 signatures used, 0 remaining; state: exhausted.")
                                    .arg(selected_pubkey_hex)
                                    .arg(PQC_MAX_SIGNATURES)));
        QVERIFY(status.contains(QString("PQC key %1 reached the signature limit (%2 of %2 signatures used, 0 remaining). Rotate to a new key/address.")
                                    .arg(selected_pubkey_hex)
                                    .arg(PQC_MAX_SIGNATURES)));
        QCOMPARE(status.count("PQC key "), 3);
        QVERIFY(!status.contains("proof signed"));

        QApplication::clipboard()->clear();
        widgets.copy_button->click();
        QCOMPARE(QApplication::clipboard()->text(), QString{});
    }
}

//! Issue #129: an empty usage report must produce exactly the verification
//! error, and a prior attempt's report must never leak into the new status.
void TestGeneratedProofFailureWithoutUsage(const P2MRProofDialogFixture& fixture)
{
    const interfaces::P2MRDataSignatureResult corrupted_result{CorruptedP2MRResult(fixture)};
    const QString selected_pubkey_hex{PubKeyHex(fixture.selected_pubkey)};
    const QString alternate_pubkey_hex{PubKeyHex(fixture.alternate_pubkey)};

    wallet::PQCUsageReport prior_report;
    prior_report.key_states.push_back({
        .pubkey = fixture.selected_pubkey,
        .signature_count = 1,
        .signature_limit = PQC_MAX_SIGNATURES,
        .signatures_remaining = PQC_MAX_SIGNATURES - 1,
        .limit_state = wallet::PQCSignatureLimitState::NORMAL,
    });
    prior_report.overall_state = wallet::PQCSignatureLimitState::NORMAL;

    SignVerifyMessageDialog dialog(fixture.platform_style, nullptr);
    const P2MRSignDialogWidgets widgets{FindP2MRSignDialogWidgets(dialog)};
    QVERIFY(widgets.valid());

    // A prior attempt in the same dialog displays a non-empty usage report.
    WalletModel prior_wallet_model(qt_test::MakeSyntheticWallet(corrupted_result, prior_report), fixture.client_model, fixture.platform_style);
    dialog.setModel(&prior_wallet_model);
    SignP2MRDataHashInDialog(widgets, fixture);
    QVERIFY(widgets.status_label->text().contains("PQC key "));
    QVERIFY(widgets.status_label->text().contains(selected_pubkey_hex));

    // The next attempt fails verification with an empty report: only the
    // verification error is shown, with nothing carried over.
    WalletModel empty_report_wallet_model(qt_test::MakeSyntheticWallet(corrupted_result, wallet::PQCUsageReport{}), fixture.client_model, fixture.platform_style);
    dialog.setModel(&empty_report_wallet_model);
    SignP2MRDataHashInDialog(widgets, fixture);

    const QString status{widgets.status_label->text()};
    QVERIFY(widgets.proof_output->toPlainText().isEmpty());
    QVERIFY(widgets.status_label->styleSheet().contains("color: red"));
    QCOMPARE(status, QString("Generated proof failed local verification: signature does not verify"));
    QVERIFY(!status.contains("failed after consuming PQC signature capacity"));
    QVERIFY(!status.contains("PQC key "));
    QVERIFY(!status.contains("PQC usage state"));
    QVERIFY(!status.contains(selected_pubkey_hex));
    QVERIFY(!status.contains(alternate_pubkey_hex));

    QApplication::clipboard()->clear();
    widgets.copy_button->click();
    QCOMPARE(QApplication::clipboard()->text(), QString{});
}

void TestP2MRReceiveAddressTypes(interfaces::Node& node)
{
    TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=1"}}};
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    node.setContext(&test.m_node);

    const std::shared_ptr<CWallet>& wallet = SetupDescriptorsWallet(node, test, /*watch_only=*/false, /*coinbase_offset=*/0, QT_WALLET_P2MR_DESCRIPTOR_OUTPUT_TYPES, /*fund_wallet=*/false);

    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    MiniGUI mini_gui(node, platformStyle.get());
    mini_gui.initModelForWallet(node, wallet, platformStyle.get());

    QVERIFY(wallet->TopUpKeyPool(2));
    const CTxDestination expected_signer_dest{*Assert(wallet->GetNewDestination(OutputType::P2MR, ""))};
    const CTxDestination proof_signer_dest{*Assert(wallet->GetNewDestination(OutputType::P2MR, ""))};
    QVERIFY(expected_signer_dest != proof_signer_dest);
    const QString expected_signer_address{QString::fromStdString(EncodeDestination(expected_signer_dest))};
    const QString proof_signer_address{QString::fromStdString(EncodeDestination(proof_signer_dest))};

    ReceiveCoinsDialog receiveCoinsDialog(platformStyle.get());
    receiveCoinsDialog.setModel(mini_gui.walletModel.get());
    QComboBox* address_type = receiveCoinsDialog.findChild<QComboBox*>("addressType");
    QVERIFY(address_type);
    QCOMPARE(address_type->count(), 1);
    QCOMPARE(address_type->currentData().toInt(), static_cast<int>(OutputType::P2MR));
    QCOMPARE(address_type->itemText(0), QString("P2MR"));
    QVERIFY(!address_type->isVisibleTo(&receiveCoinsDialog));

    SignVerifyMessageDialog sign_verify_dialog(platformStyle.get(), nullptr);
    sign_verify_dialog.setModel(mini_gui.walletModel.get());

    QTabWidget* tab_widget = sign_verify_dialog.findChild<QTabWidget*>("tabWidget");
    QVERIFY(tab_widget);
    QCOMPARE(tab_widget->tabText(0), QString("&Sign Data"));
    QCOMPARE(tab_widget->tabText(1), QString("&Verify Proof"));

    QLabel* signature_label = sign_verify_dialog.findChild<QLabel*>("signatureLabel_SM");
    QVERIFY(signature_label);
    QCOMPARE(signature_label->text(), QString("Proof JSON"));

    QComboBox* sign_input_mode = sign_verify_dialog.findChild<QComboBox*>("p2mrDataInputMode_SM");
    QVERIFY(sign_input_mode);
    QCOMPARE(sign_input_mode->count(), 2);
    QCOMPARE(sign_input_mode->currentText(), QString("Text"));

    QPlainTextEdit* sign_input = sign_verify_dialog.findChild<QPlainTextEdit*>("messageIn_SM");
    QVERIFY(sign_input);
    QVERIFY(sign_input->placeholderText().contains("UTF-8 text"));

    QValidatedLineEdit* sign_address = sign_verify_dialog.findChild<QValidatedLineEdit*>("addressIn_SM");
    QVERIFY(sign_address);

    QLineEdit* sign_hash_preview = sign_verify_dialog.findChild<QLineEdit*>("p2mrMessageHash_SM");
    QVERIFY(sign_hash_preview);
    QCOMPARE(sign_hash_preview->text(), QString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    sign_input->setPlainText("abc");
    QCOMPARE(sign_hash_preview->text(), QString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    sign_input_mode->setCurrentIndex(1);
    QVERIFY(sign_input->placeholderText().contains("64 hex"));
    sign_input->setPlainText(QString(64, '0'));
    QCOMPARE(sign_hash_preview->text(), QString(64, '0'));

    QPushButton* sign_button = sign_verify_dialog.findChild<QPushButton*>("signMessageButton_SM");
    QVERIFY(sign_button);
    QCOMPARE(sign_button->text(), QString("Sign Data &Hash"));

    QPlainTextEdit* proof_output = sign_verify_dialog.findChild<QPlainTextEdit*>("signatureOut_SM");
    QVERIFY(proof_output);
    QVERIFY(proof_output->minimumHeight() >= 96);
    QVERIFY(proof_output->placeholderText().contains("Sign Data"));

    QPlainTextEdit* proof_input = sign_verify_dialog.findChild<QPlainTextEdit*>("messageIn_VM");
    QVERIFY(proof_input);
    QVERIFY(proof_input->placeholderText().contains("proof JSON"));

    QComboBox* verify_input_mode = sign_verify_dialog.findChild<QComboBox*>("p2mrVerifyInputMode_VM");
    QVERIFY(verify_input_mode);
    QCOMPARE(verify_input_mode->count(), 3);
    QCOMPARE(verify_input_mode->currentText(), QString("Text + proof"));

    QPlainTextEdit* verify_data_input = sign_verify_dialog.findChild<QPlainTextEdit*>("p2mrDataIn_VM");
    QVERIFY(verify_data_input);

    QLineEdit* verify_hash_preview = sign_verify_dialog.findChild<QLineEdit*>("p2mrVerifyMessageHash_VM");
    QVERIFY(verify_hash_preview);
    QCOMPARE(verify_hash_preview->text(), QString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    verify_data_input->setPlainText("abc");
    QCOMPARE(verify_hash_preview->text(), QString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    verify_input_mode->setCurrentIndex(2);
    QVERIFY(verify_data_input->isHidden());
    QVERIFY(verify_hash_preview->isHidden());

    QLabel* expected_signer_label = sign_verify_dialog.findChild<QLabel*>("expectedSignerLabel_VM");
    QVERIFY(expected_signer_label);
    QVERIFY(!expected_signer_label->isHidden());

    QValidatedLineEdit* verify_address = sign_verify_dialog.findChild<QValidatedLineEdit*>("addressIn_VM");
    QVERIFY(verify_address);
    QVERIFY(!verify_address->isHidden());

    QPushButton* verify_address_book = sign_verify_dialog.findChild<QPushButton*>("addressBookButton_VM");
    QVERIFY(verify_address_book);
    QVERIFY(!verify_address_book->isHidden());

    QValidatedLineEdit* verify_signature = sign_verify_dialog.findChild<QValidatedLineEdit*>("signatureIn_VM");
    QVERIFY(verify_signature);
    QVERIFY(verify_signature->isHidden());

    QPushButton* verify_button = sign_verify_dialog.findChild<QPushButton*>("verifyMessageButton_VM");
    QVERIFY(verify_button);
    QCOMPARE(verify_button->text(), QString("Verify &Proof"));

    TestP2MRProofLeafVersionValidation(sign_verify_dialog);

    QLabel* verify_status = sign_verify_dialog.findChild<QLabel*>("statusLabel_VM");
    QVERIFY(verify_status);

    sign_input_mode->setCurrentIndex(0);
    sign_address->setText(proof_signer_address);
    const QString signed_text{"expected signer binding test"};
    sign_input->setPlainText(signed_text);
    const QString signed_message_hash{sign_hash_preview->text()};
    sign_button->click();
    const QString proof_json{proof_output->toPlainText()};
    QVERIFY(!proof_json.isEmpty());

    sign_verify_dialog.showTab_VM(/*fShow=*/false);
    proof_input->setPlainText(proof_json);

    const auto verify = [&](const QString& expected_address, int input_mode, const QString& data) {
        verify_address->setText(expected_address);
        verify_input_mode->setCurrentIndex(input_mode);
        verify_data_input->setPlainText(data);
        proof_input->setPlainText(proof_json);
        verify_button->click();
    };

    verify(proof_signer_address, /*input_mode=*/0, signed_text);
    QVERIFY(verify_status->styleSheet().contains("green"));
    QVERIFY(verify_status->text().contains("authenticated for the expected signer"));
    QVERIFY(verify_status->text().contains(proof_signer_address));
    QVERIFY(verify_status->text().contains(signed_message_hash));

    verify(expected_signer_address, /*input_mode=*/0, signed_text);
    QVERIFY(verify_status->styleSheet().contains("red"));
    QVERIFY(verify_status->text().contains(expected_signer_address));
    QVERIFY(verify_status->text().contains(proof_signer_address));
    QVERIFY(verify_address->isValid());

    const QString wrong_text{"different text"};
    verify(proof_signer_address, /*input_mode=*/0, wrong_text);
    const QString wrong_message_hash{verify_hash_preview->text()};
    QVERIFY(verify_status->styleSheet().contains("red"));
    QVERIFY(verify_status->text().contains(wrong_message_hash));
    QVERIFY(verify_status->text().contains(signed_message_hash));

    const QString wrong_network_address{"qb1zt39mp8jjcqd7pyh7qgz93gmhh2qlqppq8c3j4qy02chzfzp8c7sqkcq5ga"};
    verify(wrong_network_address, /*input_mode=*/0, signed_text);
    QVERIFY(verify_status->styleSheet().contains("red"));
    QVERIFY(verify_status->text().contains("invalid for the active network"));
    QVERIFY(!verify_address->isValid());
    QVERIFY(verify_status->text().contains(proof_signer_address));
    QVERIFY(verify_status->text().contains(signed_message_hash));

    verify(/*expected_address=*/{}, /*input_mode=*/0, signed_text);
    QVERIFY(verify_status->styleSheet().isEmpty());
    QVERIFY(verify_status->text().contains("cryptographically valid"));
    QVERIFY(verify_status->text().contains("No expected signer was provided"));
    QVERIFY(verify_status->text().contains(proof_signer_address));
    QVERIFY(verify_status->text().contains(signed_message_hash));

    verify(/*expected_address=*/{}, /*input_mode=*/2, /*data=*/{});
    QVERIFY(verify_status->styleSheet().isEmpty());
    QVERIFY(verify_status->text().contains("No expected signer was provided"));
    QVERIFY(verify_status->text().contains("Proof-only mode"));
    QVERIFY(verify_status->text().contains(proof_signer_address));
    QVERIFY(verify_status->text().contains(signed_message_hash));

    verify(proof_signer_address, /*input_mode=*/2, /*data=*/{});
    QVERIFY(verify_status->styleSheet().isEmpty());
    QVERIFY(verify_status->text().contains("Expected signer matches"));
    QVERIFY(verify_status->text().contains("Proof-only mode"));

    QPushButton* verify_clear = sign_verify_dialog.findChild<QPushButton*>("clearButton_VM");
    QVERIFY(verify_clear);
    verify_clear->click();
    QVERIFY(verify_address->text().isEmpty());
    QVERIFY(proof_input->toPlainText().isEmpty());
    QVERIFY(verify_data_input->toPlainText().isEmpty());

    UniValue valid_proof;
    QVERIFY(valid_proof.read(proof_json.toStdString()));
    QVERIFY(valid_proof.isObject());

    const auto verify_json = [&](const QString& json) {
        verify_address->clear();
        verify_input_mode->setCurrentIndex(2);
        proof_input->setPlainText(json);
        verify_button->click();
        return verify_status->text();
    };
    const auto write_proof = [](const UniValue& proof) {
        return QString::fromStdString(proof.write());
    };
    const auto proof_with_field = [&](const UniValue& proof, const char* name, std::string value) {
        UniValue modified{proof};
        modified.pushKV(name, std::move(value));
        return write_proof(modified);
    };
    const auto expect_valid = [&](const QString& json) {
        const QString status{verify_json(json)};
        QVERIFY2(status.contains("cryptographically valid"), status.toLocal8Bit().constData());
        QVERIFY(verify_status->styleSheet().isEmpty());
    };
    const auto expect_error = [&](const QString& json, const QString& expected) {
        const QString status{verify_json(json)};
        QVERIFY2(status.contains(expected), status.toLocal8Bit().constData());
        QVERIFY(verify_status->styleSheet().contains("red"));
    };

    expect_valid(write_proof(valid_proof));

    struct ExactHexField {
        const char* name;
        size_t bytes;
    };
    const std::array exact_hex_fields{
        ExactHexField{"message_hash", uint256::size()},
        ExactHexField{"pubkey", PQC_PUBKEY_SIZE},
        ExactHexField{"signature", PQC_SIG_SIZE},
        ExactHexField{"leaf_script", P2MR_V1_PK_LEAF_SCRIPT_SIZE},
    };
    // The genuine proof above is simultaneously the at-limit case for every
    // exact-size field. Exercise one byte below/above, odd, and same-size
    // non-hex inputs independently for each field.
    for (const ExactHexField& field : exact_hex_fields) {
        expect_error(proof_with_field(valid_proof, field.name, std::string((field.bytes - 1) * 2, '0')), "must be exactly");
        expect_error(proof_with_field(valid_proof, field.name, std::string(field.bytes * 2 + 2, '0')), "must be exactly");
        expect_error(proof_with_field(valid_proof, field.name, std::string(field.bytes * 2 - 1, '0')), "must be exactly");
        expect_error(proof_with_field(valid_proof, field.name, std::string(field.bytes * 2, 'g')), "must be hex");
    }
    // A large non-hex value must fail on its size before the decoder scans it.
    expect_error(proof_with_field(valid_proof, "signature", std::string(20'000, 'g')), "must be exactly");

    const std::array valid_control_depths{size_t{0}, size_t{1}, P2MR_CONTROL_MAX_NODE_COUNT};
    for (const size_t depth : valid_control_depths) {
        const UniValue proof{ProofWithControlDepth(valid_proof, depth)};
        QCOMPARE(proof.find_value("control_block").get_str().size(), GetP2MRControlBlockSize(depth) * 2);
        expect_valid(write_proof(proof));
    }
    // Boundaries around the minimum, first node, and protocol maximum:
    // 0/1/2, 32/33/34, and 4096/4097/4098 serialized bytes.
    const std::array invalid_control_sizes{size_t{0}, size_t{2}, size_t{32}, size_t{34}, P2MR_CONTROL_MAX_SIZE - 1, P2MR_CONTROL_MAX_SIZE + 1};
    for (const size_t byte_count : invalid_control_sizes) {
        expect_error(proof_with_field(valid_proof, "control_block", std::string(byte_count * 2, '0')), "must be 1 + 32*n bytes");
    }
    expect_error(proof_with_field(valid_proof, "control_block", std::string(P2MR_CONTROL_MAX_SIZE * 2, 'g')), "must be hex");

    const std::string valid_address{valid_proof.find_value("address").get_str()};
    QCOMPARE(valid_address.size(), size_t{64});
    expect_error(proof_with_field(valid_proof, "address", std::string(63, 'q')), "address is invalid");
    expect_valid(write_proof(valid_proof));
    expect_error(proof_with_field(valid_proof, "address", std::string(65, 'q')), "address is too long");

    const std::array required_fields{
        "proof_mode", "address", "message_hash", "pubkey", "signature", "leaf_version", "leaf_script", "control_block",
    };
    UniValue minimal_rpc_proof(UniValue::VOBJ);
    for (const char* field : required_fields) {
        minimal_rpc_proof.pushKVEnd(field, valid_proof.find_value(field));
    }
    expect_valid(write_proof(minimal_rpc_proof));

    for (const char* field : required_fields) {
        expect_error(write_proof(CopyProofWithout(valid_proof, field)), QString::fromLatin1(field));
    }

    std::vector<UniValue> invalid_string_types;
    invalid_string_types.emplace_back();
    UniValue number;
    number.setInt(1);
    invalid_string_types.push_back(number);
    invalid_string_types.emplace_back(UniValue::VARR);
    invalid_string_types.emplace_back(UniValue::VOBJ);
    for (const UniValue& invalid_type : invalid_string_types) {
        UniValue proof{valid_proof};
        proof.pushKV("message_hash", invalid_type);
        expect_error(write_proof(proof), "must be a string");
    }

    for (const char* leaf_version : {"-1", "256", "1.5", "999999999999999999999999"}) {
        UniValue proof{valid_proof};
        UniValue version;
        version.setNumStr(leaf_version);
        proof.pushKV("leaf_version", version);
        expect_error(write_proof(proof), "integer from 0 to 255");
    }
    for (const int leaf_version : {0, 255}) {
        UniValue proof{valid_proof};
        proof.pushKV("leaf_version", leaf_version);
        expect_error(write_proof(proof), "proof verification failed");
    }

    expect_error("[]", "JSON object");
    expect_error("{", "JSON object");
    expect_error(write_proof(valid_proof) + " trailing", "JSON object");

    UniValue nested_value(UniValue::VOBJ);
    UniValue nested_array(UniValue::VARR);
    nested_array.push_back("compatible metadata");
    nested_value.pushKV("array", std::move(nested_array));
    UniValue proof_with_unknown{valid_proof};
    proof_with_unknown.pushKV("unknown", std::move(nested_value));
    expect_valid(write_proof(proof_with_unknown));

    // UniValue permits at most 512 simultaneously open containers. The proof
    // object consumes one level, so 510/511/512 nested arrays cover below, at,
    // and above the parser's limit.
    expect_valid(ProofWithNestedArrays(valid_proof, 510));
    expect_valid(ProofWithNestedArrays(valid_proof, 511));
    expect_error(ProofWithNestedArrays(valid_proof, 512), "JSON object");

    for (const char* field : required_fields) {
        UniValue duplicate{valid_proof};
        duplicate.pushKVEnd(field, valid_proof.find_value(field));
        expect_error(write_proof(duplicate), "duplicated");
    }
    UniValue duplicate_first(UniValue::VOBJ);
    duplicate_first.pushKVEnd("signature", valid_proof.find_value("signature"));
    duplicate_first.pushKVs(valid_proof);
    expect_error(write_proof(duplicate_first), "duplicated");
    UniValue duplicate_unknown{valid_proof};
    duplicate_unknown.pushKVEnd("unknown", 1);
    duplicate_unknown.pushKVEnd("unknown", 2);
    expect_error(write_proof(duplicate_unknown), "duplicated");

    const UniValue maximum_control_proof{ProofWithControlDepth(valid_proof, P2MR_CONTROL_MAX_NODE_COUNT)};
    const QString maximum_json{QString::fromStdString(maximum_control_proof.write(2))};
    QCOMPARE(maximum_json.size(), qsizetype{15'988});
    QVERIFY(maximum_json.size() < SignVerifyMessageDialog::MAX_P2MR_PROOF_DOCUMENT_CHARS - 1);
    for (const int document_size : {SignVerifyMessageDialog::MAX_P2MR_PROOF_DOCUMENT_CHARS - 1,
                                    SignVerifyMessageDialog::MAX_P2MR_PROOF_DOCUMENT_CHARS}) {
        QString padded{maximum_json};
        padded.append(QString(document_size - padded.size(), ' '));
        QCOMPARE(padded.size(), static_cast<qsizetype>(document_size));
        expect_valid(padded);
    }

    // Editing after a success must clear both the old message and status style.
    proof_input->setPlainText(QString(SignVerifyMessageDialog::MAX_P2MR_PROOF_DOCUMENT_CHARS + 1, ' '));
    QVERIFY(verify_status->text().isEmpty());
    QVERIFY(verify_status->styleSheet().isEmpty());
    bool heartbeat{false};
    QTimer::singleShot(0, [&] { heartbeat = true; });
    QElapsedTimer rejection_timer;
    rejection_timer.start();
    verify_button->click();
    QVERIFY2(rejection_timer.elapsed() < 1000, "Oversized proof rejection blocked the GUI thread");
    QCoreApplication::processEvents();
    QVERIFY(heartbeat);
    QVERIFY(verify_status->text().contains("maximum size"));
    QVERIFY(!verify_status->text().contains("cryptographically valid"));
    QVERIFY(verify_status->styleSheet().contains("red"));

    // Malformed input after the oversized error also replaces the status, and
    // any subsequent edit clears it instead of leaving a stale failure/success.
    proof_input->setPlainText("{");
    QVERIFY(verify_status->text().isEmpty());
    verify_button->click();
    QVERIFY(verify_status->text().contains("JSON object"));
    proof_input->setPlainText(write_proof(valid_proof));
    QVERIFY(verify_status->text().isEmpty());
    QVERIFY(verify_status->styleSheet().isEmpty());

    CPQCKey selected_key;
    selected_key.MakeNewKey();
    QVERIFY(selected_key.IsValid());
    const CPQCPubKey selected_pubkey{selected_key.GetPubKey()};

    std::array<unsigned char, PQC_PUBKEY_SIZE> alternate_pubkey_bytes;
    alternate_pubkey_bytes.fill(0x5a);
    const CPQCPubKey alternate_pubkey{std::span<const unsigned char>{alternate_pubkey_bytes}};
    QVERIFY(alternate_pubkey.IsValid());
    QVERIFY(alternate_pubkey != selected_pubkey);

    const CScript selected_leaf{p2mr::BuildPKScript(selected_pubkey)};
    const CScript alternate_leaf{p2mr::BuildPKScript(alternate_pubkey)};
    const std::vector<unsigned char> selected_leaf_bytes{selected_leaf.begin(), selected_leaf.end()};
    const std::vector<unsigned char> alternate_leaf_bytes{alternate_leaf.begin(), alternate_leaf.end()};

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/1, selected_leaf_bytes, P2MR_LEAF_VERSION_V1)
        .AddP2MR(/*depth=*/1, alternate_leaf_bytes, P2MR_LEAF_VERSION_V1)
        .FinalizeP2MR();
    const P2MRSpendData spend_data{builder.GetP2MRSpendData()};
    const auto selected_leaf_it{spend_data.scripts.find({selected_leaf_bytes, P2MR_LEAF_VERSION_V1})};
    QVERIFY(selected_leaf_it != spend_data.scripts.end());
    QVERIFY(!selected_leaf_it->second.empty());
    std::vector<unsigned char> selected_control_block{*selected_leaf_it->second.begin()};
    selected_control_block.resize(P2MR_CONTROL_BASE_SIZE);
    for (size_t node{0}; node < P2MR_CONTROL_MAX_NODE_COUNT; ++node) {
        for (size_t byte{0}; byte < P2MR_CONTROL_NODE_SIZE; ++byte) {
            selected_control_block.push_back(static_cast<unsigned char>(node + byte + 1));
        }
    }
    const uint256 selected_leaf_hash{ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, selected_leaf_bytes)};
    const WitnessV2P2MR output{ComputeP2MRMerkleRoot(selected_control_block, selected_leaf_hash)};

    const uint256 message_hash{uint256::ONE};
    const uint256 datasig_hash{ComputeQbitDataSigPQCHash(std::span<const unsigned char>{message_hash.begin(), message_hash.end()})};
    std::vector<unsigned char> signature;
    uint32_t signature_counter{0};
    QVERIFY(selected_key.Sign(datasig_hash, signature, signature_counter));
    QCOMPARE(signature_counter, 1U);

    // The old rich exporter exceeded the 32 KiB verifier limit with this many
    // advanced retry keys and exhaustion warnings. The portable proof must be
    // independent of the wallet-local report's cardinality.
    constexpr size_t FAILED_RETRY_KEY_COUNT{37};
    std::set<CPQCPubKey> failed_retry_pubkeys{alternate_pubkey};
    for (unsigned char marker{1}; failed_retry_pubkeys.size() < FAILED_RETRY_KEY_COUNT; ++marker) {
        std::array<unsigned char, PQC_PUBKEY_SIZE> pubkey_bytes;
        pubkey_bytes.fill(marker);
        const CPQCPubKey pubkey{std::span<const unsigned char>{pubkey_bytes}};
        if (pubkey.IsValid() && pubkey != selected_pubkey) failed_retry_pubkeys.insert(pubkey);
    }

    wallet::PQCUsageReport retry_report;
    for (const CPQCPubKey& failed_pubkey : failed_retry_pubkeys) {
        retry_report.key_states.push_back({
            .pubkey = failed_pubkey,
            .signature_count = PQC_MAX_SIGNATURES,
            .signature_limit = PQC_MAX_SIGNATURES,
            .signatures_remaining = 0,
            .limit_state = wallet::PQCSignatureLimitState::EXHAUSTED,
        });
        retry_report.warnings.push_back({
            .pubkey = failed_pubkey,
            .previous_count = PQC_MAX_SIGNATURES - 1,
            .new_count = PQC_MAX_SIGNATURES,
            .previous_state = wallet::PQCSignatureLimitState::CRITICAL,
            .current_state = wallet::PQCSignatureLimitState::EXHAUSTED,
            .kind = wallet::PQCUsageWarningKind::TRANSITION,
        });
    }
    retry_report.key_states.push_back({
        .pubkey = selected_pubkey,
        .signature_count = 1,
        .signature_limit = PQC_MAX_SIGNATURES,
        .signatures_remaining = PQC_MAX_SIGNATURES - 1,
        .limit_state = wallet::PQCSignatureLimitState::NORMAL,
    });
    retry_report.overall_state = wallet::PQCSignatureLimitState::EXHAUSTED;
    QCOMPARE(retry_report.key_states.size(), FAILED_RETRY_KEY_COUNT + 1);
    QCOMPARE(retry_report.warnings.size(), FAILED_RETRY_KEY_COUNT);

    interfaces::P2MRDataSignatureResult synthetic_result{
        .output = output,
        .message_hash = message_hash,
        .datasig_hash = datasig_hash,
        .pubkey = std::vector<unsigned char>{selected_pubkey.begin(), selected_pubkey.end()},
        .signature = signature,
        .leaf_script = selected_leaf,
        .control_block = selected_control_block,
        .leaf_version = P2MR_LEAF_VERSION_V1,
    };

    WalletModel proof_wallet_model(qt_test::MakeSyntheticWallet(synthetic_result, retry_report), *mini_gui.clientModel, platformStyle.get());
    SignVerifyMessageDialog proof_dialog(platformStyle.get(), nullptr);
    proof_dialog.setModel(&proof_wallet_model);

    QValidatedLineEdit* proof_address = proof_dialog.findChild<QValidatedLineEdit*>("addressIn_SM");
    QComboBox* proof_sign_mode = proof_dialog.findChild<QComboBox*>("p2mrDataInputMode_SM");
    QPlainTextEdit* proof_message = proof_dialog.findChild<QPlainTextEdit*>("messageIn_SM");
    QPushButton* proof_sign_button = proof_dialog.findChild<QPushButton*>("signMessageButton_SM");
    QPlainTextEdit* generated_proof = proof_dialog.findChild<QPlainTextEdit*>("signatureOut_SM");
    QLabel* proof_status = proof_dialog.findChild<QLabel*>("statusLabel_SM");
    QPushButton* proof_copy_button = proof_dialog.findChild<QPushButton*>("copySignatureButton_SM");
    QVERIFY(proof_address && proof_sign_mode && proof_message && proof_sign_button && generated_proof && proof_status && proof_copy_button);

    proof_address->setText(QString::fromStdString(EncodeDestination(CTxDestination{output})));
    proof_sign_mode->setCurrentIndex(1);
    proof_message->setPlainText(QString::fromStdString(HexStr(std::span<const unsigned char>{message_hash.begin(), message_hash.end()})));
    proof_sign_button->click();

    const QString proof_text{generated_proof->toPlainText()};
    QVERIFY(!proof_text.isEmpty());
    QCOMPARE(proof_text.size(), qsizetype{15'988});
    QVERIFY(proof_text.size() <= SignVerifyMessageDialog::MAX_P2MR_PROOF_DOCUMENT_CHARS);
    UniValue proof_object;
    QVERIFY(proof_object.read(proof_text.toStdString()));
    QVERIFY(proof_object.isObject());
    const std::set<std::string> portable_fields{
        "address",
        "message_hash",
        "pubkey",
        "signature",
        "leaf_script",
        "control_block",
        "leaf_version",
        "proof_mode",
    };
    QCOMPARE(proof_object.getKeys().size(), portable_fields.size());
    for (const std::string& field : portable_fields) {
        QVERIFY(proof_object.exists(field));
    }

    const std::array<const char*, 13> local_or_informational_fields{
        "message_hash_source",
        "message_hash_algorithm",
        "datasig_hash",
        "domain",
        "algorithm",
        "p2mr_merkle_root",
        "pqc_key_states",
        "pqc_overall_limit_state",
        "pqc_signature_count",
        "pqc_signature_limit",
        "pqc_signatures_remaining",
        "pqc_limit_state",
        "warnings",
    };
    for (const char* field : local_or_informational_fields) {
        QVERIFY(!proof_object.exists(field));
    }
    const QString alternate_pubkey_hex{QString::fromStdString(HexStr(std::span<const unsigned char>{alternate_pubkey.begin(), alternate_pubkey.end()}))};
    QVERIFY(!proof_text.contains(alternate_pubkey_hex));
    QVERIFY(proof_status->text().contains(alternate_pubkey_hex));
    QVERIFY(proof_status->text().contains("PQC usage state after this signing attempt: exhausted."));

    QApplication::clipboard()->clear();
    proof_copy_button->click();
    QCOMPARE(QApplication::clipboard()->text(), proof_text);

    QComboBox* proof_verify_mode = proof_dialog.findChild<QComboBox*>("p2mrVerifyInputMode_VM");
    QPlainTextEdit* proof_verify_input = proof_dialog.findChild<QPlainTextEdit*>("messageIn_VM");
    QPushButton* proof_verify_button = proof_dialog.findChild<QPushButton*>("verifyMessageButton_VM");
    QLabel* proof_verify_status = proof_dialog.findChild<QLabel*>("statusLabel_VM");
    QVERIFY(proof_verify_mode && proof_verify_input && proof_verify_button && proof_verify_status);
    proof_verify_mode->setCurrentIndex(2);
    proof_verify_input->setPlainText(proof_text);
    proof_verify_button->click();
    QVERIFY(proof_verify_status->text().contains("P2MR/PQC proof is cryptographically valid"));

    JSONRPCRequest request;
    request.context = &test.m_node;
    request.strMethod = "verifydatapqchash";
    request.params = UniValue{UniValue::VARR};
    request.params.push_back(proof_object);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    const UniValue rpc_result{tableRPC.execute(request)};
    QVERIFY(rpc_result["valid"].get_bool());

    UniValue legacy_proof{proof_object};
    legacy_proof.pushKV("datasig_hash", HexStr(std::span<const unsigned char>{datasig_hash.begin(), datasig_hash.end()}));
    legacy_proof.pushKV("domain", common::P2MR_DATA_SIGNATURE_DOMAIN);
    legacy_proof.pushKV("algorithm", common::P2MR_DATA_SIGNATURE_ALGORITHM);
    const uint256 merkle_root{output.GetMerkleRoot()};
    legacy_proof.pushKV("p2mr_merkle_root", HexStr(std::span<const unsigned char>{merkle_root.begin(), merkle_root.end()}));
    UniValue legacy_key_states{UniValue::VARR};
    UniValue legacy_key_state{UniValue::VOBJ};
    legacy_key_state.pushKV("pubkey", alternate_pubkey_hex.toStdString());
    legacy_key_state.pushKV("pqc_signature_count", static_cast<int64_t>(wallet::PQC_WARNING_SIGNATURE_THRESHOLD));
    legacy_key_state.pushKV("pqc_signature_limit", static_cast<int64_t>(PQC_MAX_SIGNATURES));
    legacy_key_state.pushKV("pqc_signatures_remaining", static_cast<int64_t>(PQC_MAX_SIGNATURES - wallet::PQC_WARNING_SIGNATURE_THRESHOLD));
    legacy_key_state.pushKV("pqc_limit_state", "warning");
    legacy_key_states.push_back(std::move(legacy_key_state));
    legacy_proof.pushKV("pqc_key_states", std::move(legacy_key_states));
    legacy_proof.pushKV("pqc_overall_limit_state", "warning");
    UniValue legacy_warnings{UniValue::VARR};
    legacy_warnings.push_back("legacy local PQC warning");
    legacy_proof.pushKV("warnings", std::move(legacy_warnings));

    proof_verify_input->setPlainText(QString::fromStdString(legacy_proof.write(2)));
    proof_verify_button->click();
    QVERIFY(proof_verify_status->text().contains("P2MR/PQC proof is cryptographically valid"));

    wallet::PQCUsageReport single_key_report;
    single_key_report.key_states.push_back({
        .pubkey = selected_pubkey,
        .signature_count = wallet::PQC_WARNING_SIGNATURE_THRESHOLD,
        .signature_limit = PQC_MAX_SIGNATURES,
        .signatures_remaining = PQC_MAX_SIGNATURES - wallet::PQC_WARNING_SIGNATURE_THRESHOLD,
        .limit_state = wallet::PQCSignatureLimitState::WARNING,
    });
    single_key_report.overall_state = wallet::PQCSignatureLimitState::WARNING;
    single_key_report.warnings.push_back({
        .pubkey = selected_pubkey,
        .previous_count = wallet::PQC_WARNING_SIGNATURE_THRESHOLD - 1,
        .new_count = wallet::PQC_WARNING_SIGNATURE_THRESHOLD,
        .previous_state = wallet::PQCSignatureLimitState::NORMAL,
        .current_state = wallet::PQCSignatureLimitState::WARNING,
        .kind = wallet::PQCUsageWarningKind::TRANSITION,
    });
    WalletModel single_key_wallet_model(qt_test::MakeSyntheticWallet(synthetic_result, single_key_report), *mini_gui.clientModel, platformStyle.get());
    SignVerifyMessageDialog single_key_dialog(platformStyle.get(), nullptr);
    single_key_dialog.setModel(&single_key_wallet_model);
    QValidatedLineEdit* single_key_address = single_key_dialog.findChild<QValidatedLineEdit*>("addressIn_SM");
    QComboBox* single_key_sign_mode = single_key_dialog.findChild<QComboBox*>("p2mrDataInputMode_SM");
    QPlainTextEdit* single_key_message = single_key_dialog.findChild<QPlainTextEdit*>("messageIn_SM");
    QPushButton* single_key_sign_button = single_key_dialog.findChild<QPushButton*>("signMessageButton_SM");
    QLabel* single_key_status_label = single_key_dialog.findChild<QLabel*>("statusLabel_SM");
    QPlainTextEdit* single_key_proof_output = single_key_dialog.findChild<QPlainTextEdit*>("signatureOut_SM");
    QVERIFY(single_key_address && single_key_sign_mode && single_key_message && single_key_sign_button && single_key_status_label && single_key_proof_output);
    single_key_address->setText(QString::fromStdString(EncodeDestination(CTxDestination{output})));
    single_key_sign_mode->setCurrentIndex(1);
    single_key_message->setPlainText(QString::fromStdString(HexStr(std::span<const unsigned char>{message_hash.begin(), message_hash.end()})));
    single_key_sign_button->click();

    const QString single_key_status{single_key_status_label->text()};
    const uint32_t signatures_remaining{PQC_MAX_SIGNATURES - wallet::PQC_WARNING_SIGNATURE_THRESHOLD};
    QVERIFY(single_key_status.contains(QString("%1 of %2 signatures used, %3 remaining; state: warning.")
                                           .arg(wallet::PQC_WARNING_SIGNATURE_THRESHOLD)
                                           .arg(PQC_MAX_SIGNATURES)
                                           .arg(signatures_remaining)));
    QVERIFY(single_key_status.contains(QString("%1 of %2 signatures used, %3 remaining")
                                           .arg(wallet::PQC_WARNING_SIGNATURE_THRESHOLD)
                                           .arg(PQC_MAX_SIGNATURES)
                                           .arg(signatures_remaining)));
    UniValue single_key_proof;
    QVERIFY(single_key_proof.read(single_key_proof_output->toPlainText().toStdString()));
    QCOMPARE(single_key_proof.getKeys().size(), portable_fields.size());
    for (const char* field : local_or_informational_fields) {
        QVERIFY(!single_key_proof.exists(field));
    }

    wallet::PQCUsageReport failed_report;
    failed_report.key_states.push_back({
        .pubkey = alternate_pubkey,
        .signature_count = 1,
        .signature_limit = PQC_MAX_SIGNATURES,
        .signatures_remaining = PQC_MAX_SIGNATURES - 1,
        .limit_state = wallet::PQCSignatureLimitState::NORMAL,
    });
    failed_report.key_states.push_back({
        .pubkey = selected_pubkey,
        .signature_count = PQC_MAX_SIGNATURES,
        .signature_limit = PQC_MAX_SIGNATURES,
        .signatures_remaining = 0,
        .limit_state = wallet::PQCSignatureLimitState::EXHAUSTED,
    });
    failed_report.overall_state = wallet::PQCSignatureLimitState::EXHAUSTED;
    failed_report.warnings.push_back({
        .pubkey = selected_pubkey,
        .previous_count = PQC_MAX_SIGNATURES - 1,
        .new_count = PQC_MAX_SIGNATURES,
        .previous_state = wallet::PQCSignatureLimitState::CRITICAL,
        .current_state = wallet::PQCSignatureLimitState::EXHAUSTED,
        .kind = wallet::PQCUsageWarningKind::TRANSITION,
    });

    WalletModel failed_wallet_model(
        qt_test::MakeSyntheticP2MRFailureWallet(Untranslated("PQC data-hash signing failed"), failed_report),
        *mini_gui.clientModel,
        platformStyle.get());
    SignVerifyMessageDialog failed_dialog(platformStyle.get(), nullptr);
    failed_dialog.setModel(&failed_wallet_model);
    QValidatedLineEdit* failed_address = failed_dialog.findChild<QValidatedLineEdit*>("addressIn_SM");
    QComboBox* failed_sign_mode = failed_dialog.findChild<QComboBox*>("p2mrDataInputMode_SM");
    QPlainTextEdit* failed_message = failed_dialog.findChild<QPlainTextEdit*>("messageIn_SM");
    QPushButton* failed_sign_button = failed_dialog.findChild<QPushButton*>("signMessageButton_SM");
    QLabel* failed_status_label = failed_dialog.findChild<QLabel*>("statusLabel_SM");
    QPlainTextEdit* failed_proof_output = failed_dialog.findChild<QPlainTextEdit*>("signatureOut_SM");
    QVERIFY(failed_address && failed_sign_mode && failed_message && failed_sign_button && failed_status_label && failed_proof_output);

    failed_address->setText(QString::fromStdString(EncodeDestination(CTxDestination{output})));
    failed_sign_mode->setCurrentIndex(1);
    failed_message->setPlainText(QString::fromStdString(HexStr(std::span<const unsigned char>{message_hash.begin(), message_hash.end()})));
    failed_sign_button->click();

    const QString failed_status{failed_status_label->text()};
    const QString selected_pubkey_hex{QString::fromStdString(HexStr(std::span<const unsigned char>{selected_pubkey.begin(), selected_pubkey.end()}))};
    QVERIFY(failed_proof_output->toPlainText().isEmpty());
    QVERIFY(failed_status_label->styleSheet().contains("color: red"));
    QVERIFY(failed_status.contains("PQC data-hash signing failed"));
    QVERIFY(failed_status.contains("failed after consuming PQC signature capacity"));
    QVERIFY(failed_status.contains("PQC usage state after this signing attempt: exhausted."));
    QVERIFY(failed_status.contains(alternate_pubkey_hex));
    QVERIFY(failed_status.contains(selected_pubkey_hex));
    QVERIFY(failed_status.contains(QString("1 of %1 signatures used, %2 remaining; state: normal.")
                                       .arg(PQC_MAX_SIGNATURES)
                                       .arg(PQC_MAX_SIGNATURES - 1)));
    QVERIFY(failed_status.contains(QString("%1 of %1 signatures used, 0 remaining; state: exhausted.").arg(PQC_MAX_SIGNATURES)));
    QVERIFY(failed_status.contains("reached the signature limit"));

    // Issue #129: proofs the wallet signs but local verification rejects.
    const P2MRProofDialogFixture proof_failure_fixture{
        .platform_style = platformStyle.get(),
        .client_model = *mini_gui.clientModel,
        .output = output,
        .message_hash = message_hash,
        .valid_result = synthetic_result,
        .selected_pubkey = selected_pubkey,
        .alternate_pubkey = alternate_pubkey,
    };
    TestGeneratedProofVerificationFailureShowsUsage(proof_failure_fixture);
    TestGeneratedProofFailureWithoutUsage(proof_failure_fixture);
}

void TestSendPQCReportPropagation(interfaces::Node& node)
{
    TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}};
    node.setContext(&test.m_node);

    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    OptionsModel options_model(node);
    bilingual_str error;
    QVERIFY(options_model.Init(error));
    ClientModel client_model(node, &options_model);

    CPQCKey key;
    key.MakeNewKey();
    wallet::PQCUsageReport expected_report;
    expected_report.key_states.push_back({
        .pubkey = key.GetPubKey(),
        .signature_count = 7,
        .signature_limit = PQC_MAX_SIGNATURES,
        .signatures_remaining = PQC_MAX_SIGNATURES - 7,
        .limit_state = wallet::PQCSignatureLimitState::NORMAL,
    });
    expected_report.overall_state = wallet::PQCSignatureLimitState::NORMAL;

    WalletModel wallet_model(qt_test::MakeSyntheticWallet(expected_report), client_model, platformStyle.get());
    wallet::CCoinControl coin_control;
    coin_control.Select(COutPoint{Txid{}, 0});

    const QList<SendCoinsRecipient> recipients{SendCoinsRecipient(QString::fromStdString(EncodeDestination(PKHash{})), "", COIN, "")};
    WalletModelTransaction transaction(recipients);
    const WalletModel::SendCoinsReturn result = wallet_model.prepareTransaction(transaction, coin_control);
    QCOMPARE(result.status, WalletModel::OK);
    QVERIFY(transaction.getWtx());
    const auto& pqc_usage = transaction.getPQCUsageReport();
    QCOMPARE(pqc_usage.key_states.size(), size_t{1});
    QVERIFY(pqc_usage.overall_state.has_value());
    QCOMPARE(*pqc_usage.overall_state, wallet::PQCSignatureLimitState::NORMAL);
    QCOMPARE(pqc_usage.key_states.front().signature_count, 7U);
    QCOMPARE(pqc_usage.key_states.front().signatures_remaining, PQC_MAX_SIGNATURES - 7);
}

void TestAsyncFeeBumpLifecycle(interfaces::Node& node)
{
    TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}};
    node.setContext(&test.m_node);

    std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    OptionsModel options_model{node};
    bilingual_str error;
    QVERIFY(options_model.Init(error));
    ClientModel client_model{node, &options_model};

    const auto make_model = [&](const std::shared_ptr<qt_test::SyntheticWalletState>& state) {
        return std::make_unique<WalletModel>(
            qt_test::MakeSyntheticWallet(wallet::PQCUsageReport{}, state),
            client_model,
            platform_style.get());
    };
    const auto start_bump = [](WalletModel& model) {
        ConfirmSend(nullptr, QMessageBox::Yes);
        return model.bumpFee(Txid{});
    };

    // Preparation cancellation is observed cooperatively while the cloned
    // wallet is still preparing the replacement. Cleanup leaves the model
    // ready for a later fee bump.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        {
            std::lock_guard lock{state->mutex};
            state->bump_enabled = true;
            state->allow_bump_prepare = false;
        }
        auto model{make_model(state)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QVERIFY(model->bumpFee(Txid{}));
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) { return value.bump_prepare_entered; });
        }, 5000));

        QPointer<QProgressDialog> progress;
        QVERIFY(WaitUntil([&] {
            progress = FindBumpFeeProgressDialog();
            return progress && progress->isVisible() && !progress->findChildren<QPushButton*>().empty();
        }, 5000));
        progress->findChildren<QPushButton*>().front()->click();
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) {
                return value.bump_prepare_cancel_observed && value.background_clone_destroyed;
            });
        }, 5000));
        QCOMPARE(completed.count(), 0);
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
            return !value.bump_sign_entered && !value.bump_commit_entered;
        }));

        {
            std::lock_guard lock{state->mutex};
            state->allow_bump_prepare = true;
        }
        state->condition.notify_all();
        TransactionView view{platform_style.get()};
        view.setModel(model.get());
        view.setModel(model.get());
        QSignalSpy view_completed{&view, &TransactionView::bumpedFee};
        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&completed] { return completed.count() == 1; }, 5000));
        QCOMPARE(view_completed.count(), 1);
    }

    // Shutdown requested from the confirmation dialog must not be cleared by
    // the transition to signing. The canceled activity is fully cleaned up and
    // does not block a later fee bump.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        {
            std::lock_guard lock{state->mutex};
            state->bump_enabled = true;
        }
        auto model{make_model(state)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        ConfirmSend(nullptr, QMessageBox::Yes, [&] { model->prepareForShutdown(); });
        QVERIFY(model->bumpFee(Txid{}));
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; });
        }, 5000));
        QCOMPARE(completed.count(), 0);
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
            return !value.bump_sign_entered && !value.bump_commit_entered;
        }));

        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&completed] { return completed.count() == 1; }, 5000));
    }

    // Internal P2MR signing stays off the GUI thread. Once counters are
    // durably reserved, an attempted cancellation is ignored and the
    // replacement proceeds to commit.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        {
            std::lock_guard lock{state->mutex};
            state->bump_enabled = true;
            state->allow_bump_sign = false;
        }
        auto model{make_model(state)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QVERIFY(completed.isValid());

        int gui_ticks{0};
        QTimer gui_latch;
        QObject::connect(&gui_latch, &QTimer::timeout, [&gui_ticks] { ++gui_ticks; });
        gui_latch.start(0);
        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) {
                return value.bump_sign_entered && value.bump_counters_reserved;
            });
        }, 5000));

        QPointer<QProgressDialog> progress;
        QVERIFY(WaitUntil([&] {
            progress = FindBumpFeeProgressDialog();
            return progress && progress->isVisible() && progress->findChildren<QPushButton*>().empty();
        }, 5000));
        QVERIFY(WaitUntil([&gui_ticks] { return gui_ticks >= 3; }, 5000));

        // Exercise the cancel/reservation race from the UI side. Escape can
        // still produce a cancel event after the button has disappeared.
        Q_EMIT progress->canceled();
        QCoreApplication::processEvents();
        QVERIFY(!SyntheticStateMatches(state, [](const auto& value) { return value.bump_cancel_observed; }));

        ReleaseSyntheticBumpSigning(state);
        QVERIFY(WaitUntil([&completed] { return completed.count() == 1; }, 5000));
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; });
        }, 5000));
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
            return value.bump_commit_entered && value.bump_committed && !value.bump_cancel_observed;
        }));
    }

    // Cancellation that lands after the last cancellable progress update but
    // before durable counter reservation wins the atomic boundary. No counter
    // is consumed and no replacement is committed.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        {
            std::lock_guard lock{state->mutex};
            state->bump_enabled = true;
            state->allow_bump_counter_boundary = false;
        }
        auto model{make_model(state)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) { return value.bump_counter_boundary_entered; });
        }, 5000));

        QPointer<QProgressDialog> progress;
        QVERIFY(WaitUntil([&] {
            progress = FindBumpFeeProgressDialog();
            return progress && progress->isVisible() && !progress->findChildren<QPushButton*>().empty();
        }, 5000));
        progress->findChildren<QPushButton*>().front()->click();
        {
            std::lock_guard lock{state->mutex};
            state->allow_bump_counter_boundary = true;
        }
        state->condition.notify_all();
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) {
                return value.bump_cancel_observed && value.background_clone_destroyed;
            });
        }, 5000));
        QCOMPARE(completed.count(), 0);
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
            return !value.bump_counters_reserved && !value.bump_commit_entered && !value.bump_committed;
        }));
    }

    // Shutdown cannot invalidate the completion callback after counter
    // reservation. The irreversible replacement commits and is still reported.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        {
            std::lock_guard lock{state->mutex};
            state->bump_enabled = true;
            state->allow_bump_sign = false;
        }
        auto model{make_model(state)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) {
                return value.bump_sign_entered && value.bump_counters_reserved;
            });
        }, 5000));

        model->prepareForShutdown();
        ReleaseSyntheticBumpSigning(state);
        QVERIFY(WaitUntil([&completed] { return completed.count() == 1; }, 5000));
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; });
        }, 5000));
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
            return value.bump_commit_entered && value.bump_committed;
        }));
    }

    // Before counter reservation, cancellation reaches the signer and no
    // commit is attempted.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        {
            std::lock_guard lock{state->mutex};
            state->bump_enabled = true;
            state->allow_bump_reservation = false;
        }
        auto model{make_model(state)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) { return value.bump_sign_entered; });
        }, 5000));

        QPointer<QProgressDialog> progress;
        QVERIFY(WaitUntil([&] {
            progress = FindBumpFeeProgressDialog();
            return progress && progress->isVisible() && !progress->findChildren<QPushButton*>().empty();
        }, 5000));
        const QList<QPushButton*> cancel_buttons{progress->findChildren<QPushButton*>()};
        QVERIFY(!cancel_buttons.empty());
        // Removing the cancel button can re-enter shutdown and clear the
        // dialog before cancelBumpFee resumes updating it.
        QObject::connect(cancel_buttons.front(), &QObject::destroyed, model.get(), [&] {
            model->prepareForShutdown();
        });
        Q_EMIT progress->canceled();
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) { return value.bump_cancel_observed; });
        }, 5000));
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; });
        }, 5000));
        QCOMPARE(completed.count(), 0);
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
            return !value.bump_commit_entered && !value.bump_committed;
        }));
    }

    // Cancellation and the external-signer command boundary race through one
    // atomic state transition. If cancellation wins, the command is not run
    // and no replacement is committed.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        {
            std::lock_guard lock{state->mutex};
            state->bump_enabled = true;
            state->external_signer = true;
            state->bump_use_counters = false;
            state->allow_external_bump_boundary = false;
        }
        auto model{make_model(state)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) { return value.external_bump_boundary_entered; });
        }, 5000));

        QPointer<QProgressDialog> progress;
        QVERIFY(WaitUntil([&] {
            progress = FindBumpFeeProgressDialog();
            return progress && progress->isVisible() && !progress->findChildren<QPushButton*>().empty();
        }, 5000));
        progress->findChildren<QPushButton*>().front()->click();
        {
            std::lock_guard lock{state->mutex};
            state->allow_external_bump_boundary = true;
        }
        state->condition.notify_all();
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) {
                return value.bump_cancel_observed && value.background_clone_destroyed;
            });
        }, 5000));
        QCOMPARE(completed.count(), 0);
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
            return !value.bump_commit_entered && !value.bump_committed;
        }));
    }

    // A state change discovered by the worker's final commit revalidation is
    // surfaced, and a signed-but-stale replacement is not reported as bumped.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        {
            std::lock_guard lock{state->mutex};
            state->bump_enabled = true;
            state->bump_commit_success = false;
        }
        auto model{make_model(state)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QString commit_error;
        new MessageBoxClicker({}, QMessageBox::Ok, &commit_error);
        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&commit_error] { return commit_error.contains("Original transaction changed while signing"); }, 5000));
        QCOMPARE(completed.count(), 0);
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
            return value.bump_commit_entered && !value.bump_committed;
        }));
    }

    // The model owns the activity, so deleting a view and the progress dialog
    // during an external-signer command does not invalidate the worker.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        {
            std::lock_guard lock{state->mutex};
            state->bump_enabled = true;
            state->external_signer = true;
            state->bump_use_counters = false;
            state->allow_bump_sign = false;
        }
        auto model{make_model(state)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        auto view{std::make_unique<TransactionView>(platform_style.get())};
        view->setModel(model.get());
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) { return value.bump_sign_entered; });
        }, 5000));

        QPointer<QProgressDialog> progress;
        QVERIFY(WaitUntil([&] {
            progress = FindBumpFeeProgressDialog();
            return progress && progress->isVisible() && progress->findChildren<QPushButton*>().empty();
        }, 5000));
        progress->deleteLater();
        view.reset();
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QVERIFY(progress.isNull());

        ReleaseSyntheticBumpSigning(state);
        QVERIFY(WaitUntil([&completed] { return completed.count() == 1; }, 5000));
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return value.bump_committed; }));
    }

    // Wallet-model teardown waits for an irreversible signing operation and
    // destroys the cloned wallet before returning, preventing queued callbacks
    // from observing an unloaded wallet.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        {
            std::lock_guard lock{state->mutex};
            state->bump_enabled = true;
            state->allow_bump_sign = false;
        }
        auto model{make_model(state)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) {
                return value.bump_sign_entered && value.bump_counters_reserved;
            });
        }, 5000));

        std::thread signer_release{[state] {
            std::this_thread::sleep_for(100ms);
            ReleaseSyntheticBumpSigning(state);
        }};
        QPointer<WalletModel> model_guard{model.get()};
        model.reset();
        signer_release.join();
        QVERIFY(model_guard.isNull());
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
            return value.background_clone_destroyed && value.bump_committed;
        }));
        QCoreApplication::sendPostedEvents(nullptr, QEvent::MetaCall);
        QCoreApplication::processEvents();
    }
}

void TestSendCompletionAfterModelDestruction(interfaces::Node& node)
{
    TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}};
    node.setContext(&test.m_node);

    std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    MiniGUI mini_gui{node, platform_style.get()};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    mini_gui.initModel(qt_test::MakeSyntheticWallet(wallet::PQCUsageReport{}, state), platform_style.get());
    mini_gui.walletModel->pollBalanceChanged();

    SendCoinsDialog& send_dialog{mini_gui.sendCoinsDialog};
    QVBoxLayout* const entries{send_dialog.findChild<QVBoxLayout*>("entries")};
    QVERIFY(entries);
    SendCoinsEntry* const entry{qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget())};
    QVERIFY(entry);
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(QString::fromStdString(EncodeDestination(PKHash{})));
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(COIN);
    send_dialog.getCoinControl()->Select(COutPoint{Txid{}, 0});

    QSignalSpy coins_sent{&send_dialog, &SendCoinsDialog::coinsSent};
    QVERIFY(coins_sent.isValid());
    QVERIFY(QMetaObject::invokeMethod(&send_dialog, "sendButtonClicked", Q_ARG(bool, false)));

    {
        std::unique_lock lock{state->mutex};
        QVERIFY(state->condition.wait_for(lock, std::chrono::seconds{5}, [state] {
            return state->background_clone_destroyed;
        }));
        QVERIFY(state->create_entered);
    }

    QPointer<WalletModel> model_guard{mini_gui.walletModel.get()};
    mini_gui.walletModel.reset();
    QVERIFY(model_guard.isNull());

    // The worker destroyed its cloned wallet only after queueing completion.
    // Deliver that completion while the dialog is alive but its model is gone.
    QCoreApplication::sendPostedEvents(&send_dialog, QEvent::MetaCall);
    QCoreApplication::processEvents();

    QCOMPARE(coins_sent.count(), 0);
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        QVERIFY(!widget->inherits("SendConfirmationDialog"));
    }
}

void TestUnlockContextModelLifetime(interfaces::Node& node)
{
    TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}};
    node.setContext(&test.m_node);

    std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    OptionsModel options_model{node};
    bilingual_str error;
    QVERIFY(options_model.Init(error));
    ClientModel client_model{node, &options_model};

    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    {
        std::lock_guard lock{state->mutex};
        state->encrypted = true;
        state->locked = false;
    }
    auto wallet_model{std::make_unique<WalletModel>(
        qt_test::MakeSyntheticWallet(wallet::PQCUsageReport{}, state),
        client_model,
        platform_style.get())};

    auto lock_calls = [state] {
        std::lock_guard lock{state->mutex};
        return state->lock_calls;
    };

    {
        WalletModel::UnlockContext live_context{wallet_model.get(), /*valid=*/true, /*relock=*/true};
    }
    QCOMPARE(lock_calls(), 1);

    auto stale_context{std::make_unique<WalletModel::UnlockContext>(
        wallet_model.get(), /*valid=*/true, /*relock=*/true)};
    wallet_model.reset();
    stale_context.reset();
    QCOMPARE(lock_calls(), 1);
}

void TestCanGetAddressesNotificationIsQueued(interfaces::Node& node)
{
    TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}};
    node.setContext(&test.m_node);

    std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    OptionsModel options_model{node};
    bilingual_str error;
    QVERIFY(options_model.Init(error));
    ClientModel client_model{node, &options_model};

    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    WalletModel wallet_model{
        qt_test::MakeSyntheticWallet(wallet::PQCUsageReport{}, state),
        client_model,
        platform_style.get()};
    QSignalSpy notification_spy{&wallet_model, &WalletModel::canGetAddressesChanged};
    QVERIFY(notification_spy.isValid());

    std::function<void()> notify;
    {
        std::lock_guard lock{state->mutex};
        notify = state->can_get_addresses_changed;
    }
    QVERIFY(notify);

    notify();
    QCOMPARE(notification_spy.count(), 0);

    QCoreApplication::sendPostedEvents(&wallet_model, QEvent::MetaCall);
    QCoreApplication::processEvents();
    QCOMPARE(notification_spy.count(), 1);
}

void TestSendPQCWarningFormatting()
{
    CPQCKey key;
    key.MakeNewKey();

    wallet::PQCUsageReport report;
    report.key_states.push_back({
        .pubkey = key.GetPubKey(),
        .signature_count = wallet::PQC_WARNING_SIGNATURE_THRESHOLD,
        .signature_limit = PQC_MAX_SIGNATURES,
        .signatures_remaining = PQC_MAX_SIGNATURES - wallet::PQC_WARNING_SIGNATURE_THRESHOLD,
        .limit_state = wallet::PQCSignatureLimitState::WARNING,
    });
    report.overall_state = wallet::PQCSignatureLimitState::WARNING;
    report.warnings.push_back({
        .pubkey = key.GetPubKey(),
        .previous_count = wallet::PQC_WARNING_SIGNATURE_THRESHOLD - 1,
        .new_count = wallet::PQC_WARNING_SIGNATURE_THRESHOLD,
        .previous_state = wallet::PQCSignatureLimitState::NORMAL,
        .current_state = wallet::PQCSignatureLimitState::WARNING,
        .kind = wallet::PQCUsageWarningKind::TRANSITION,
    });

    const QString html = FormatPQCUsageWarningHtml(report);
    const QString message = FormatPQCUsageWarningMessage(report);
    QVERIFY(html.contains("PQC usage"));
    QVERIFY(html.contains("Most advanced PQC state after signing: <b>Warning</b>.<br />Signatures remaining for this key:"));
    QVERIFY(html.contains("entered warning usage range"));
    QVERIFY(html.contains("Rotate to a new receive address after this transaction."));
    QVERIFY(message.contains("Most advanced PQC state after signing: Warning."));
    QVERIFY(message.contains("entered warning usage range"));
    QVERIFY(message.contains("Rotate to a new receive address after this transaction."));
}

// Issue #141: transaction-signing flows preserve and display the wallet-local
// PQC usage report of the attempt that consumed signature capacity.
const QString USAGE_CONSUMED_SENTENCE{"PQC signature capacity was consumed during this signing attempt."};
const QString USAGE_FAILED_SENTENCE{"The signing attempt failed after consuming PQC signature capacity."};

QString UsageStateLabel(wallet::PQCSignatureLimitState state)
{
    switch (state) {
    case wallet::PQCSignatureLimitState::NORMAL: return "Normal";
    case wallet::PQCSignatureLimitState::WARNING: return "Warning";
    case wallet::PQCSignatureLimitState::CRITICAL: return "Critical";
    case wallet::PQCSignatureLimitState::EXHAUSTED: return "Exhausted";
    }
    return {};
}

//! Check that text lists the overall state, every key with all of its
//! capacity fields, and every warning of the report.
void VerifyUsageListed(const QString& text, const wallet::PQCUsageReport& report)
{
    QVERIFY(!report.key_states.empty());
    QVERIFY(report.overall_state.has_value());
    QVERIFY2(text.contains(QString{"PQC usage state after this signing attempt: %1."}.arg(UsageStateLabel(*report.overall_state))), qPrintable(text));
    for (const wallet::PQCUsageSnapshot& key_state : report.key_states) {
        QVERIFY2(text.contains(QString{"PQC key %1: %2 of %3 signatures used, %4 remaining; state: %5."}
                                   .arg(PubKeyHex(key_state.pubkey))
                                   .arg(key_state.signature_count)
                                   .arg(key_state.signature_limit)
                                   .arg(key_state.signatures_remaining)
                                   .arg(UsageStateLabel(key_state.limit_state))),
                 qPrintable(text));
    }
    const std::vector<bilingual_str> warnings{wallet::FormatPQCUsageWarnings(report.warnings)};
    QCOMPARE(warnings.size(), report.warnings.size());
    for (const bilingual_str& warning : warnings) {
        QVERIFY2(text.contains(QString::fromStdString(warning.original)), qPrintable(text));
    }
}

CPQCPubKey NewPQCPubKey()
{
    CPQCKey key;
    key.MakeNewKey();
    return key.GetPubKey();
}

std::string SerializeTransaction(const CTransaction& tx)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(tx);
    return stream.str();
}

//! Translator that injects markup into one state label so escaping of
//! dynamic strings is observable.
class MarkupStateTranslator : public QTranslator
{
public:
    QString translate(const char* context, const char* source_text, const char*, int) const override
    {
        if (std::string_view{context} == "PQCUsageFormat" && std::string_view{source_text} == "Warning") {
            return "<b>Warning & more</b>";
        }
        return {};
    }
    bool isEmpty() const override { return false; }
};

void TestTransactionUsageFormatting()
{
    const CPQCPubKey normal_key{NewPQCPubKey()};
    const CPQCPubKey warning_key{NewPQCPubKey()};
    const CPQCPubKey critical_key{NewPQCPubKey()};
    const CPQCPubKey exhausted_key{NewPQCPubKey()};
    const std::vector<std::pair<wallet::PQCUsageReport, wallet::PQCSignatureLimitState>> reports{
        {qt_test::MakeSyntheticPQCUsageReport({{normal_key, 1}}), wallet::PQCSignatureLimitState::NORMAL},
        {qt_test::MakeSyntheticPQCUsageReport({{warning_key, wallet::PQC_WARNING_SIGNATURE_THRESHOLD}}), wallet::PQCSignatureLimitState::WARNING},
        {qt_test::MakeSyntheticPQCUsageReport({{critical_key, wallet::PQC_CRITICAL_SIGNATURE_THRESHOLD}}), wallet::PQCSignatureLimitState::CRITICAL},
        {qt_test::MakeSyntheticPQCUsageReport({{exhausted_key, PQC_MAX_SIGNATURES}}), wallet::PQCSignatureLimitState::EXHAUSTED},
        {qt_test::MakeSyntheticPQCUsageReport({
             {normal_key, 5},
             {warning_key, wallet::PQC_WARNING_SIGNATURE_THRESHOLD},
             {critical_key, wallet::PQC_CRITICAL_SIGNATURE_THRESHOLD},
             {exhausted_key, PQC_MAX_SIGNATURES},
         }),
         wallet::PQCSignatureLimitState::EXHAUSTED},
    };

    for (const auto& [report, expected_state] : reports) {
        QCOMPARE(*report.overall_state, expected_state);
        const QString plain{FormatPQCSigningUsagePlain(report)};
        VerifyUsageListed(plain, report);
        QVERIFY(plain.startsWith(QString{"PQC usage state after this signing attempt: %1."}.arg(UsageStateLabel(expected_state))));
        const qsizetype line_count{static_cast<qsizetype>(1 + report.key_states.size() + report.warnings.size())};
        QCOMPARE(plain.split('\n').size(), line_count);
        if (expected_state != wallet::PQCSignatureLimitState::NORMAL) QVERIFY(!report.warnings.empty());

        QCOMPARE(FormatPQCSigningOutcomePlain(report, PQCSigningOutcome::FailedAfterConsumption), USAGE_FAILED_SENTENCE + "\n" + plain);
        QCOMPARE(FormatPQCSigningOutcomePlain(report, PQCSigningOutcome::Consumed), USAGE_CONSUMED_SENTENCE + "\n" + plain);
    }

    // An absent report is never shown as zero consumption.
    const wallet::PQCUsageReport empty;
    QVERIFY(FormatPQCSigningUsagePlain(empty).isEmpty());
    QVERIFY(FormatPQCSigningOutcomePlain(empty, PQCSigningOutcome::FailedAfterConsumption).isEmpty());
    QVERIFY(FormatPQCSigningOutcomePlain(empty, PQCSigningOutcome::Consumed).isEmpty());

    // Translated strings reach the user literally; nothing is re-interpreted as markup.
    MarkupStateTranslator translator;
    QVERIFY(QCoreApplication::installTranslator(&translator));
    const wallet::PQCUsageReport warning_report{reports.at(1).first};
    const QString plain{FormatPQCSigningUsagePlain(warning_report)};
    QVERIFY(QCoreApplication::removeTranslator(&translator));
    QVERIFY2(plain.contains("state: <b>Warning & more</b>."), qPrintable(plain));
}

//! Qt models backed by a synthetic wallet on a regtest chain.
struct SyntheticModelEnvironment {
    explicit SyntheticModelEnvironment(interfaces::Node& node)
        : test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}}
    {
        node.setContext(&test.m_node);
        platform_style.reset(PlatformStyle::instantiate("other"));
        options_model = std::make_unique<OptionsModel>(node);
        bilingual_str error;
        if (!options_model->Init(error)) throw std::runtime_error{error.original};
        client_model = std::make_unique<ClientModel>(node, options_model.get());
    }

    std::unique_ptr<WalletModel> makeModel(const std::shared_ptr<qt_test::SyntheticWalletState>& state, wallet::PQCUsageReport report = {})
    {
        return std::make_unique<WalletModel>(qt_test::MakeSyntheticWallet(std::move(report), state), *client_model, platform_style.get());
    }

    TestChain100Setup test;
    std::unique_ptr<const PlatformStyle> platform_style;
    std::unique_ptr<OptionsModel> options_model;
    std::unique_ptr<ClientModel> client_model;
};

struct SentMessage {
    QString title;
    QString text;
    unsigned int style{0};
};

SentMessage MessageAt(const QSignalSpy& spy, qsizetype index)
{
    const QList<QVariant>& args{spy.at(index)};
    return {args.at(0).toString(), args.at(1).toString(), args.at(2).toUInt()};
}

// Declare after the GUI objects so a failed assertion releases the Send worker
// before they are destroyed.
struct ReleaseSyntheticCreateOnExit {
    std::shared_ptr<qt_test::SyntheticWalletState> state;

    ~ReleaseSyntheticCreateOnExit()
    {
        {
            std::lock_guard lock{state->mutex};
            state->allow_create = true;
            state->allow_create_completion = true;
        }
        state->condition.notify_all();
    }
};

//! Fill the first send entry and click Send without confirming anything.
void ClickSend(SendCoinsDialog& send_dialog)
{
    QVBoxLayout* const entries{send_dialog.findChild<QVBoxLayout*>("entries")};
    QVERIFY(entries);
    SendCoinsEntry* const entry{qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget())};
    QVERIFY(entry);
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(QString::fromStdString(EncodeDestination(PKHash{})));
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(COIN);
    send_dialog.getCoinControl()->Select(COutPoint{Txid{}, 0});
    QVERIFY(QMetaObject::invokeMethod(&send_dialog, "sendButtonClicked", Q_ARG(bool, false)));
}

void VerifyNoSendConfirmation()
{
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        QVERIFY(!widget->inherits("SendConfirmationDialog"));
    }
}

void TestSendFailureShowsAllConsumedKeys(interfaces::Node& node)
{
    const CPQCPubKey normal_key{NewPQCPubKey()};
    const CPQCPubKey exhausted_key{NewPQCPubKey()};
    const wallet::PQCUsageReport single_report{qt_test::MakeSyntheticPQCUsageReport({{normal_key, 1}})};
    const wallet::PQCUsageReport multi_report{qt_test::MakeSyntheticPQCUsageReport({{normal_key, 2}, {exhausted_key, PQC_MAX_SIGNATURES}})};
    QVERIFY(single_report.warnings.empty());
    QCOMPARE(multi_report.warnings.size(), size_t{1});
    QCOMPARE(multi_report.warnings.front().kind, wallet::PQCUsageWarningKind::TRANSITION);

    for (const wallet::PQCUsageReport* report : {&single_report, &multi_report}) {
        // Model level: the failed creation keeps the consumed report.
        {
            SyntheticModelEnvironment env{node};
            auto state{std::make_shared<qt_test::SyntheticWalletState>()};
            state->create_simulate_pqc_reservation = true;
            state->create_success = false;
            auto model{env.makeModel(state, *report)};
            wallet::CCoinControl coin_control;
            coin_control.Select(COutPoint{Txid{}, 0});
            const QList<SendCoinsRecipient> recipients{SendCoinsRecipient(QString::fromStdString(EncodeDestination(PKHash{})), "", COIN, "")};
            WalletModelTransaction transaction{recipients};
            const WalletModel::SendCoinsReturn result{model->prepareTransaction(transaction, coin_control)};
            QCOMPARE(result.status, WalletModel::TransactionCreationFailed);
            QVERIFY(!transaction.getWtx());
            QCOMPARE(transaction.getPQCUsageReport().key_states.size(), report->key_states.size());
        }

        // Dialog level: the real completion handler presents the report.
        std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
        TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}};
        node.setContext(&test.m_node);
        MiniGUI mini_gui{node, platform_style.get()};
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->create_simulate_pqc_reservation = true;
        state->create_success = false;
        mini_gui.initModel(qt_test::MakeSyntheticWallet(*report, state), platform_style.get());
        SendCoinsDialog& send_dialog{mini_gui.sendCoinsDialog};
        QSignalSpy messages{&send_dialog, &SendCoinsDialog::message};
        QSignalSpy coins_sent{&send_dialog, &SendCoinsDialog::coinsSent};

        ClickSend(send_dialog);
        QVERIFY(WaitUntil([&] { return messages.count() == 1; }, 5000));
        const SentMessage sent{MessageAt(messages, 0)};
        QCOMPARE(sent.title, QString{"Send Coins"});
        QCOMPARE(sent.style, static_cast<unsigned int>(CClientUIInterface::MSG_ERROR));
        QVERIFY(sent.text.startsWith("Transaction creation failed: Signing transaction failed\n\n" + USAGE_FAILED_SENTENCE + "\n"));
        VerifyUsageListed(sent.text, *report);
        QVERIFY(!sent.text.contains(USAGE_CONSUMED_SENTENCE));
        QCOMPARE(coins_sent.count(), 0);
        VerifyNoSendConfirmation();
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return value.create_counters_reserved; }));
    }

    // A cancel requested after counter reservation must not hide the report.
    {
        std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
        TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}};
        node.setContext(&test.m_node);
        MiniGUI mini_gui{node, platform_style.get()};
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->create_simulate_pqc_reservation = true;
        state->create_success = false;
        state->allow_create_completion = false;
        const ReleaseSyntheticCreateOnExit release_on_exit{state};
        mini_gui.initModel(qt_test::MakeSyntheticWallet(multi_report, state), platform_style.get());
        SendCoinsDialog& send_dialog{mini_gui.sendCoinsDialog};
        QSignalSpy messages{&send_dialog, &SendCoinsDialog::message};
        QSignalSpy coins_sent{&send_dialog, &SendCoinsDialog::coinsSent};

        ClickSend(send_dialog);
        QVERIFY(WaitUntil([&] { return SyntheticStateMatches(state, [](const auto& value) { return value.create_counters_reserved; }); }, 5000));
        QProgressDialog* const progress{send_dialog.findChild<QProgressDialog*>()};
        QVERIFY(progress);
        Q_EMIT progress->canceled();
        QCoreApplication::processEvents();
        QCOMPARE(messages.count(), 0);
        {
            std::lock_guard lock{state->mutex};
            state->allow_create_completion = true;
        }
        state->condition.notify_all();
        QVERIFY(WaitUntil([&] { return messages.count() == 1; }, 5000));
        const SentMessage sent{MessageAt(messages, 0)};
        QCOMPARE(sent.style, static_cast<unsigned int>(CClientUIInterface::MSG_ERROR));
        QVERIFY(sent.text.startsWith("Transaction creation failed: Signing transaction failed\n\n" + USAGE_FAILED_SENTENCE));
        VerifyUsageListed(sent.text, multi_report);
        QCOMPARE(coins_sent.count(), 0);
        VerifyNoSendConfirmation();
    }

    // Failing before reservation keeps the original reason and severity and
    // does not invent usage, even though the wallet has a report to give.
    {
        std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
        TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}};
        node.setContext(&test.m_node);
        MiniGUI mini_gui{node, platform_style.get()};
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->create_simulate_pqc_reservation = true;
        state->create_fail_before_reservation = true;
        mini_gui.initModel(qt_test::MakeSyntheticWallet(multi_report, state), platform_style.get());
        SendCoinsDialog& send_dialog{mini_gui.sendCoinsDialog};
        QSignalSpy messages{&send_dialog, &SendCoinsDialog::message};

        ClickSend(send_dialog);
        QVERIFY(WaitUntil([&] { return messages.count() == 1; }, 5000));
        const SentMessage sent{MessageAt(messages, 0)};
        QCOMPARE(sent.title, QString{"Send Coins"});
        QCOMPARE(sent.style, static_cast<unsigned int>(CClientUIInterface::MSG_ERROR));
        QCOMPARE(sent.text, QString{"Transaction creation failed: Transaction preparation failed"});
        QVERIFY(!sent.text.contains("PQC"));
        QVERIFY(!SyntheticStateMatches(state, [](const auto& value) { return value.create_counters_reserved; }));
        VerifyNoSendConfirmation();
    }
}

void TestFeeBumpFailureShowsConsumedUsage(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    const wallet::PQCUsageReport report{qt_test::MakeSyntheticPQCUsageReport({
        {NewPQCPubKey(), 9},
        {NewPQCPubKey(), wallet::PQC_CRITICAL_SIGNATURE_THRESHOLD},
    })};
    const auto start_bump = [](WalletModel& model) {
        ConfirmSend(nullptr, QMessageBox::Yes);
        return model.bumpFee(Txid{});
    };

    // Signing fails after counter reservation.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->bump_enabled = true;
        state->bump_sign_success = false;
        auto model{env.makeModel(state, report)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QSignalSpy messages{model.get(), &WalletModel::message};
        QString text;
        Qt::TextFormat text_format{Qt::AutoText};
        new MessageBoxClicker({}, QMessageBox::Ok, &text, &text_format);
        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&text] { return !text.isEmpty(); }, 5000));
        QVERIFY2(text.startsWith("Can't sign transaction.\n\n" + USAGE_FAILED_SENTENCE + "\n"), qPrintable(text));
        VerifyUsageListed(text, report);
        QCOMPARE(text_format, Qt::PlainText);
        QVERIFY(WaitUntil([&] { return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; }); }, 5000));
        QCOMPARE(completed.count(), 0);
        QCOMPARE(messages.count(), 0);
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
            return value.bump_counters_reserved && !value.bump_commit_entered && !value.bump_committed;
        }));
    }

    // Signing fails before counter reservation: the error has no usage.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->bump_enabled = true;
        state->bump_fail_before_reservation = true;
        auto model{env.makeModel(state, report)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QSignalSpy messages{model.get(), &WalletModel::message};
        QString text;
        new MessageBoxClicker({}, QMessageBox::Ok, &text);
        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&text] { return !text.isEmpty(); }, 5000));
        QCOMPARE(text, QString{"Can't sign transaction."});
        QVERIFY(WaitUntil([&] { return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; }); }, 5000));
        QCOMPARE(completed.count(), 0);
        QCOMPARE(messages.count(), 0);
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return !value.bump_counters_reserved && !value.bump_commit_entered; }));
    }

    // Cancellation that wins the reservation boundary stays silent.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->bump_enabled = true;
        state->allow_bump_counter_boundary = false;
        auto model{env.makeModel(state, report)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QSignalSpy messages{model.get(), &WalletModel::message};
        QString text;
        QPointer<MessageBoxClicker> clicker{new MessageBoxClicker({}, QMessageBox::Ok, &text)};
        QVERIFY(start_bump(*model));
        QVERIFY(WaitUntil([&] { return SyntheticStateMatches(state, [](const auto& value) { return value.bump_counter_boundary_entered; }); }, 5000));
        QPointer<QProgressDialog> progress;
        QVERIFY(WaitUntil([&] {
            progress = FindBumpFeeProgressDialog();
            return progress && progress->isVisible() && !progress->findChildren<QPushButton*>().empty();
        }, 5000));
        progress->findChildren<QPushButton*>().front()->click();
        {
            std::lock_guard lock{state->mutex};
            state->allow_bump_counter_boundary = true;
        }
        state->condition.notify_all();
        QVERIFY(WaitUntil([&] {
            return SyntheticStateMatches(state, [](const auto& value) { return value.bump_cancel_observed && value.background_clone_destroyed; });
        }, 5000));
        QCoreApplication::processEvents();
        QVERIFY(text.isEmpty());
        QCOMPARE(messages.count(), 0);
        QCOMPARE(completed.count(), 0);
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return !value.bump_counters_reserved && !value.bump_commit_entered; }));
        delete clicker.data();
    }
}

void TestFeeBumpCommitFailureKeepsUsage(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    const wallet::PQCUsageReport report{qt_test::MakeSyntheticPQCUsageReport({{NewPQCPubKey(), 4}})};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->bump_enabled = true;
    state->bump_commit_success = false;
    state->bump_commit_error = "Original transaction changed while signing <b>bold</b> & more";
    auto model{env.makeModel(state, report)};
    const ReleaseSyntheticBumpOnExit release_on_exit{state};
    QSignalSpy completed{model.get(), &WalletModel::feeBumped};
    QSignalSpy messages{model.get(), &WalletModel::message};
    QString text;
    Qt::TextFormat text_format{Qt::AutoText};
    new MessageBoxClicker({}, QMessageBox::Ok, &text, &text_format);
    ConfirmSend(nullptr, QMessageBox::Yes);
    QVERIFY(model->bumpFee(Txid{}));
    QVERIFY(WaitUntil([&text] { return !text.isEmpty(); }, 5000));
    QVERIFY2(text.startsWith("Could not commit transaction\n(Original transaction changed while signing <b>bold</b> & more)\n\n" + USAGE_FAILED_SENTENCE + "\n"), qPrintable(text));
    VerifyUsageListed(text, report);
    // The error is shown literally rather than interpreted as markup.
    QCOMPARE(text_format, Qt::PlainText);
    QVERIFY(WaitUntil([&] { return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; }); }, 5000));
    QCOMPARE(completed.count(), 0);
    QCOMPARE(messages.count(), 0);
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return value.bump_commit_entered && !value.bump_committed; }));
}

CMutableTransaction ExpectedSyntheticBump()
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid{}, 0});
    mtx.vout.emplace_back(COIN - 2000, CScript{} << OP_TRUE);
    mtx.vin.front().scriptWitness.stack.emplace_back(1, 1);
    return mtx;
}

void TestFeeBumpSuccessShowsUsage(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    const std::vector<std::pair<wallet::PQCUsageReport, unsigned int>> cases{
        {qt_test::MakeSyntheticPQCUsageReport({{NewPQCPubKey(), 1}}), CClientUIInterface::MSG_INFORMATION},
        {qt_test::MakeSyntheticPQCUsageReport({{NewPQCPubKey(), 3}, {NewPQCPubKey(), wallet::PQC_WARNING_SIGNATURE_THRESHOLD}}), CClientUIInterface::MSG_WARNING},
    };
    for (const auto& [report, expected_style] : cases) {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->bump_enabled = true;
        auto model{env.makeModel(state, report)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QSignalSpy messages{model.get(), &WalletModel::message};
        std::vector<std::string> events;
        QObject::connect(model.get(), &WalletModel::message, [&events] { events.emplace_back("message"); });
        QObject::connect(model.get(), &WalletModel::feeBumped, [&events] { events.emplace_back("feeBumped"); });
        ConfirmSend(nullptr, QMessageBox::Yes);
        QVERIFY(model->bumpFee(Txid{}));
        QVERIFY(WaitUntil([&completed] { return completed.count() == 1; }, 5000));
        QCOMPARE(messages.count(), 1);
        QVERIFY(events == (std::vector<std::string>{"message", "feeBumped"}));
        const SentMessage sent{MessageAt(messages, 0)};
        QCOMPARE(sent.title, QString{"Fee bump"});
        QCOMPARE(sent.style, expected_style);
        QVERIFY(sent.text.startsWith(USAGE_CONSUMED_SENTENCE + "\n"));
        QVERIFY(!sent.text.contains(USAGE_FAILED_SENTENCE));
        VerifyUsageListed(sent.text, report);
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return value.bump_committed; }));
    }

    // A bump that never reserves counters publishes no usage message, even
    // though the wallet holds a report it could have supplied.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->bump_enabled = true;
        state->bump_use_counters = false;
        auto model{env.makeModel(state, cases.front().first)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QSignalSpy messages{model.get(), &WalletModel::message};
        ConfirmSend(nullptr, QMessageBox::Yes);
        QVERIFY(model->bumpFee(Txid{}));
        QVERIFY(WaitUntil([&completed] { return completed.count() == 1; }, 5000));
        QCOMPARE(messages.count(), 0);
    }

    // The usage message can run a nested event loop that deletes the model.
    // Completion must not touch or emit through the destroyed model.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->bump_enabled = true;
        const wallet::PQCUsageReport report{qt_test::MakeSyntheticPQCUsageReport({{NewPQCPubKey(), 2}})};
        auto model{env.makeModel(state, report)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QPointer<WalletModel> model_guard{model.get()};
        int completed{0};
        int messages{0};
        QObject::connect(model.get(), &WalletModel::feeBumped, [&completed] { ++completed; });
        QObject::connect(model.get(), &WalletModel::message, [&] {
            ++messages;
            model.reset();
        });
        ConfirmSend(nullptr, QMessageBox::Yes);
        QVERIFY(model->bumpFee(Txid{}));
        QVERIFY(WaitUntil([&model_guard] { return model_guard.isNull(); }, 5000));
        QCoreApplication::processEvents();
        QCOMPARE(messages, 1);
        QCOMPARE(completed, 0);
        QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return value.bump_committed && value.background_clone_destroyed; }));
    }
}

void TestUsageIsAttemptLocal(interfaces::Node& node)
{
    const wallet::PQCUsageReport report{qt_test::MakeSyntheticPQCUsageReport({{NewPQCPubKey(), 6}, {NewPQCPubKey(), PQC_MAX_SIGNATURES}})};

    // Send: a presented failure does not leak into the next attempt.
    {
        std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
        TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}};
        node.setContext(&test.m_node);
        MiniGUI mini_gui{node, platform_style.get()};
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->create_simulate_pqc_reservation = true;
        state->create_success = false;
        mini_gui.initModel(qt_test::MakeSyntheticWallet(report, state), platform_style.get());
        SendCoinsDialog& send_dialog{mini_gui.sendCoinsDialog};
        QSignalSpy messages{&send_dialog, &SendCoinsDialog::message};

        ClickSend(send_dialog);
        QVERIFY(WaitUntil([&] { return messages.count() == 1; }, 5000));
        QVERIFY(MessageAt(messages, 0).text.contains(USAGE_FAILED_SENTENCE));

        {
            std::lock_guard lock{state->mutex};
            state->create_simulate_pqc_reservation = false;
            state->create_fail_before_reservation = true;
        }
        ClickSend(send_dialog);
        QVERIFY(WaitUntil([&] { return messages.count() == 2; }, 5000));
        const SentMessage second{MessageAt(messages, 1)};
        QCOMPARE(second.text, QString{"Transaction creation failed: Transaction preparation failed"});
        QCOMPARE(second.style, static_cast<unsigned int>(CClientUIInterface::MSG_ERROR));
    }

    // Send: a completion delivered after its model is gone presents nothing.
    {
        std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
        TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}};
        node.setContext(&test.m_node);
        MiniGUI mini_gui{node, platform_style.get()};
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->create_simulate_pqc_reservation = true;
        state->create_success = false;
        mini_gui.initModel(qt_test::MakeSyntheticWallet(report, state), platform_style.get());
        SendCoinsDialog& send_dialog{mini_gui.sendCoinsDialog};
        QSignalSpy messages{&send_dialog, &SendCoinsDialog::message};
        QSignalSpy coins_sent{&send_dialog, &SendCoinsDialog::coinsSent};

        ClickSend(send_dialog);
        {
            std::unique_lock lock{state->mutex};
            QVERIFY(state->condition.wait_for(lock, std::chrono::seconds{5}, [state] { return state->background_clone_destroyed; }));
            QVERIFY(state->create_counters_reserved);
        }
        QPointer<WalletModel> model_guard{mini_gui.walletModel.get()};
        mini_gui.walletModel.reset();
        QVERIFY(model_guard.isNull());
        QCoreApplication::sendPostedEvents(&send_dialog, QEvent::MetaCall);
        QCoreApplication::processEvents();
        QCOMPARE(messages.count(), 0);
        QCOMPARE(coins_sent.count(), 0);
        VerifyNoSendConfirmation();
    }

    // Fee bump: a later attempt without reservation shows no earlier usage.
    {
        SyntheticModelEnvironment env{node};
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->bump_enabled = true;
        state->bump_sign_success = false;
        auto model{env.makeModel(state, report)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};

        QString first;
        new MessageBoxClicker({}, QMessageBox::Ok, &first);
        ConfirmSend(nullptr, QMessageBox::Yes);
        QVERIFY(model->bumpFee(Txid{}));
        QVERIFY(WaitUntil([&first] { return !first.isEmpty(); }, 5000));
        QVERIFY(first.contains(USAGE_FAILED_SENTENCE));
        QVERIFY(WaitUntil([&] { return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; }); }, 5000));

        {
            std::lock_guard lock{state->mutex};
            state->bump_fail_before_reservation = true;
            state->background_clone_destroyed = false;
        }
        QString second;
        new MessageBoxClicker({}, QMessageBox::Ok, &second);
        ConfirmSend(nullptr, QMessageBox::Yes);
        QVERIFY(WaitUntil([&] { return model->bumpFee(Txid{}); }, 5000));
        QVERIFY(WaitUntil([&second] { return !second.isEmpty(); }, 5000));
        QCOMPARE(second, QString{"Can't sign transaction."});
        QVERIFY(WaitUntil([&] { return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; }); }, 5000));
    }
}

void TestUsageStaysOutOfPortableArtifacts(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    const wallet::PQCUsageReport report{qt_test::MakeSyntheticPQCUsageReport({{NewPQCPubKey(), wallet::PQC_WARNING_SIGNATURE_THRESHOLD}})};

    // Send: the created transaction carries the report beside it, never in it.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->create_simulate_pqc_reservation = true;
        auto model{env.makeModel(state, report)};
        wallet::CCoinControl coin_control;
        coin_control.Select(COutPoint{Txid{}, 0});
        const QList<SendCoinsRecipient> recipients{SendCoinsRecipient(QString::fromStdString(EncodeDestination(PKHash{})), "", COIN, "")};
        WalletModelTransaction transaction{recipients};
        QCOMPARE(model->prepareTransaction(transaction, coin_control).status, WalletModel::OK);
        QVERIFY(transaction.getWtx());
        QCOMPARE(transaction.getPQCUsageReport().key_states.size(), size_t{1});
        CMutableTransaction expected;
        expected.vout.emplace_back(COIN, CScript{} << OP_TRUE);
        QCOMPARE(SerializeTransaction(*transaction.getWtx()), SerializeTransaction(CTransaction{expected}));
    }

    // Fee bump: the committed replacement is exactly the signed transaction.
    {
        auto state{std::make_shared<qt_test::SyntheticWalletState>()};
        state->bump_enabled = true;
        auto model{env.makeModel(state, report)};
        const ReleaseSyntheticBumpOnExit release_on_exit{state};
        QSignalSpy completed{model.get(), &WalletModel::feeBumped};
        QSignalSpy messages{model.get(), &WalletModel::message};
        Txid bumped_txid;
        QObject::connect(model.get(), &WalletModel::feeBumped, [&bumped_txid](const Txid&, const Txid& bumped) { bumped_txid = bumped; });
        ConfirmSend(nullptr, QMessageBox::Yes);
        QVERIFY(model->bumpFee(Txid{}));
        QVERIFY(WaitUntil([&completed] { return completed.count() == 1; }, 5000));
        QCOMPARE(messages.count(), 1);
        const CTransaction expected{ExpectedSyntheticBump()};
        CMutableTransaction committed;
        {
            std::lock_guard lock{state->mutex};
            committed = state->bump_committed_tx;
        }
        QCOMPARE(SerializeTransaction(CTransaction{committed}), SerializeTransaction(expected));
        QVERIFY(bumped_txid == expected.GetHash());
    }
}

//! The "Increasing transaction fee failed" box is the first nested loop in
//! bumpFeePrepared(). Losing the model inside it must not reset state through
//! the deleted object.
void TestFeeBumpModelDestroyedDuringPrepareFailure(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->bump_enabled = true;
    state->bump_prepare_success = false;
    auto model{env.makeModel(state)};
    const ReleaseSyntheticBumpOnExit release_on_exit{state};
    QSignalSpy completed{model.get(), &WalletModel::feeBumped};
    QSignalSpy messages{model.get(), &WalletModel::message};
    QPointer<WalletModel> model_guard{model.get()};

    QString text;
    new MessageBoxClicker({}, QMessageBox::Ok, &text, nullptr, [&model] { model.reset(); });
    QVERIFY(model->bumpFee(Txid{}));
    QVERIFY(WaitUntil([&model_guard] { return model_guard.isNull(); }, 5000));
    QCoreApplication::processEvents();

    QVERIFY2(text.startsWith("Increasing transaction fee failed"), qPrintable(text));
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
        return value.bump_prepare_entered && !value.bump_sign_entered && !value.bump_commit_entered;
    }));
    QCOMPARE(completed.count(), 0);
    QCOMPARE(messages.count(), 0);
    QVERIFY(!FindBumpFeeProgressDialog());
}

//! Unloading the wallet while the fee-bump confirmation dialog runs its nested
//! event loop deletes the model underneath the waiting call. The attempt has to
//! be abandoned on the spot: no member of the deleted model may be read, no
//! signal emitted, and signing must never start.
void TestFeeBumpModelDestroyedDuringConfirmation(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->bump_enabled = true;
    auto model{env.makeModel(state)};
    const ReleaseSyntheticBumpOnExit release_on_exit{state};
    QSignalSpy completed{model.get(), &WalletModel::feeBumped};
    QSignalSpy messages{model.get(), &WalletModel::message};
    QVERIFY(completed.isValid());
    QVERIFY(messages.isValid());
    QPointer<WalletModel> model_guard{model.get()};

    // Destroy the model from inside the nested loop, then let the dialog
    // return into the frame that no longer has an object to return to.
    ConfirmSend(nullptr, QMessageBox::Yes, [&model] { model.reset(); });
    QVERIFY(model->bumpFee(Txid{}));
    QVERIFY(WaitUntil([&model_guard] { return model_guard.isNull(); }, 5000));

    // The abandoned attempt still releases the worker's cloned wallet.
    QVERIFY(WaitUntil([&state] {
        return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; });
    }, 5000));
    QCoreApplication::processEvents();
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
        return value.bump_prepare_entered && !value.bump_sign_entered && !value.bump_commit_entered && !value.bump_committed;
    }));
    QCOMPARE(completed.count(), 0);
    QCOMPARE(messages.count(), 0);
    QVERIFY(!FindBumpFeeProgressDialog());
    VerifyNoSendConfirmation();
}

//! "Create Unsigned" on a watch-only wallet reports a failed draft in a third
//! nested loop. The model can be gone by the time that box closes.
void TestFeeBumpModelDestroyedDuringDraftFailure(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->bump_enabled = true;
    state->private_keys_disabled = true;
    state->psbt_draft_complete = true;
    auto model{env.makeModel(state)};
    const ReleaseSyntheticBumpOnExit release_on_exit{state};
    QSignalSpy completed{model.get(), &WalletModel::feeBumped};
    QSignalSpy messages{model.get(), &WalletModel::message};
    QPointer<WalletModel> model_guard{model.get()};

    QString text;
    new MessageBoxClicker({}, QMessageBox::Ok, &text, nullptr, [&model] { model.reset(); });
    ConfirmSend(nullptr, QMessageBox::Save);
    QVERIFY(model->bumpFee(Txid{}));
    QVERIFY(WaitUntil([&model_guard] { return model_guard.isNull(); }, 5000));
    QCoreApplication::processEvents();

    QCOMPARE(text, QString{"Can't draft transaction."});
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
        return value.bump_prepare_entered && !value.bump_sign_entered && !value.bump_commit_entered;
    }));
    QCOMPARE(completed.count(), 0);
    QCOMPARE(messages.count(), 0);
    QVERIFY(!FindBumpFeeProgressDialog());
}

//! requestUnlock() presents the passphrase dialog in the fourth nested loop.
//! The unlock request stands in for it here: the model dies while the request
//! is being serviced, so the acquired context must be released rather than
//! handed to, or read back from, the deleted model.
void TestFeeBumpModelDestroyedDuringUnlock(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->bump_enabled = true;
    state->encrypted = true;
    state->locked = true;
    auto model{env.makeModel(state)};
    const ReleaseSyntheticBumpOnExit release_on_exit{state};
    QSignalSpy completed{model.get(), &WalletModel::feeBumped};
    QSignalSpy messages{model.get(), &WalletModel::message};
    QPointer<WalletModel> model_guard{model.get()};
    QObject::connect(model.get(), &WalletModel::requireUnlock, model.get(), [&model] { model.reset(); });

    ConfirmSend(nullptr, QMessageBox::Yes);
    QVERIFY(model->bumpFee(Txid{}));
    QVERIFY(WaitUntil([&model_guard] { return model_guard.isNull(); }, 5000));
    QCoreApplication::processEvents();

    QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
        // The wallet was never unlocked, so nothing may relock it either.
        return value.bump_prepare_entered && !value.bump_sign_entered && value.unlock_calls == 0 && value.lock_calls == 0;
    }));
    QCOMPARE(completed.count(), 0);
    QCOMPARE(messages.count(), 0);
    QVERIFY(!FindBumpFeeProgressDialog());
}

void ReleaseSyntheticEncryption(const std::shared_ptr<qt_test::SyntheticWalletState>& state)
{
    {
        std::lock_guard lock{state->mutex};
        state->allow_encrypt = true;
    }
    state->condition.notify_all();
}

// Declare after the model so a failed assertion releases the worker before
// the model destructor joins it.
struct ReleaseSyntheticEncryptionOnExit {
    std::shared_ptr<qt_test::SyntheticWalletState> state;

    ~ReleaseSyntheticEncryptionOnExit() { ReleaseSyntheticEncryption(state); }
};

//! Join a helper thread when an assertion returns early.
struct JoinOnExit {
    std::thread& thread;

    ~JoinOnExit()
    {
        if (thread.joinable()) thread.join();
    }
};

//! Click the given button on the next visible message box that offers it.
//! Unlike MessageBoxClicker this never latches onto a box without the button,
//! so an "Ok" clicker created ahead of the encryption confirmation still
//! reaches the result box a synchronous implementation shows inside accept().
class VisibleMessageBoxClicker : public QObject
{
public:
    explicit VisibleMessageBoxClicker(QMessageBox::StandardButton button, QString* text = nullptr)
        : m_button(button), m_text(text)
    {
        m_timer.setInterval(50);
        connect(&m_timer, &QTimer::timeout, this, &VisibleMessageBoxClicker::tryClickVisibleDialog);
        m_timer.start();
    }

    bool clicked() const { return m_clicked; }

private:
    void tryClickVisibleDialog()
    {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (!widget->isVisible() || !widget->inherits("QMessageBox") || widget->inherits("SendConfirmationDialog")) continue;
            QMessageBox* const dialog{qobject_cast<QMessageBox*>(widget)};
            QAbstractButton* const button{dialog ? dialog->button(m_button) : nullptr};
            if (!button) continue;
            if (m_text) *m_text = dialog->text();
            m_clicked = true;
            m_timer.stop();
            button->click();
            return;
        }
    }

    const QMessageBox::StandardButton m_button;
    QString* const m_text;
    QTimer m_timer;
    bool m_clicked{false};
};

//! Fill in both passphrase fields and submit the encryption dialog, answering
//! "Continue" to the confirmation it shows.
void SubmitEncryption(AskPassphraseDialog& dialog, const QString& passphrase)
{
    dialog.findChild<QLineEdit*>("passEdit2")->setText(passphrase);
    dialog.findChild<QLineEdit*>("passEdit3")->setText(passphrase);
    VisibleMessageBoxClicker confirm{QMessageBox::Yes};
    dialog.accept();
    QVERIFY(confirm.clicked());
}

bool DialogShowsEncryptionInProgress(AskPassphraseDialog& dialog)
{
    QProgressBar* const progress{dialog.findChild<QProgressBar*>("progressBar")};
    QDialogButtonBox* const buttons{dialog.findChild<QDialogButtonBox*>("buttonBox")};
    return dialog.isVisible() && progress && progress->isVisible() && buttons && !buttons->isEnabled();
}

//! Encryption of an existing wallet runs on a worker thread while the GUI
//! thread keeps servicing events. Notifications the wallet raises while it
//! holds its locks are held back until the worker returns, so listeners that
//! read the wallet never block the GUI, and incompatible wallet actions are
//! refused instead of queueing behind the locks. The dialog is the progress
//! indicator: it cannot be dismissed or resubmitted until the result arrives.
void TestEncryptWalletKeepsGuiResponsive(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->allow_encrypt = false;
    auto model{env.makeModel(state)};
    const ReleaseSyntheticEncryptionOnExit release_on_exit{state};
    model->startPollBalance();

    QSignalSpy status_changed{model.get(), &WalletModel::encryptionStatusChanged};
    QSignalSpy addresses_changed{model.get(), &WalletModel::canGetAddressesChanged};
    QSignalSpy messages{model.get(), &WalletModel::message};
    QVERIFY(status_changed.isValid());
    QVERIFY(addresses_changed.isValid());
    QVERIFY(messages.isValid());
    // Query the wallet from the notifications the way the main window and the
    // receive page do. The synthetic wallet blocks these calls while its
    // encryption latch is held, so a premature delivery stalls this thread.
    QObject::connect(model.get(), &WalletModel::encryptionStatusChanged, model.get(), [&model] { model->getEncryptionStatus(); });
    QObject::connect(model.get(), &WalletModel::pqcKeyValidationChanged, model.get(), [&model] { model->getPQCKeyValidationInfo(); });
    QObject::connect(model.get(), &WalletModel::canGetAddressesChanged, model.get(), [&model] { model->wallet().canGetAddresses(); });

    int gui_ticks{0};
    QTimer gui_latch;
    QObject::connect(&gui_latch, &QTimer::timeout, [&gui_ticks] { ++gui_ticks; });
    gui_latch.start(0);

    // Release the latch if the GUI thread stops servicing events, so a
    // synchronous implementation fails the assertions below instead of
    // hanging the test.
    bool gui_alive{false};
    std::thread watchdog{[state, &gui_alive] {
        std::unique_lock lock{state->mutex};
        if (!state->condition.wait_for(lock, std::chrono::seconds{5}, [&] { return gui_alive || state->encrypt_finished; })) {
            state->watchdog_released = true;
            state->allow_encrypt = true;
            lock.unlock();
            state->condition.notify_all();
        }
    }};
    const JoinOnExit join_watchdog{watchdog};

    auto* dialog{new AskPassphraseDialog(AskPassphraseDialog::Encrypt, nullptr)};
    QPointer<AskPassphraseDialog> dialog_guard{dialog};
    dialog->setModel(model.get());
    GUIUtil::ShowModalDialogAsynchronously(dialog);
    QString result_text;
    VisibleMessageBoxClicker result{QMessageBox::Ok, &result_text};
    SubmitEncryption(*dialog, QStringLiteral("test-passphrase"));

    const int ticks_at_submit{gui_ticks};
    const bool responsive{WaitUntil([&] {
        return gui_ticks > ticks_at_submit + 3 && SyntheticStateMatches(state, [](const auto& value) {
            return value.encrypt_entered && value.encrypt_in_progress;
        });
    }, 5000)};
    {
        std::lock_guard lock{state->mutex};
        gui_alive = true;
    }
    state->condition.notify_all();
    watchdog.join();
    QVERIFY2(!SyntheticStateMatches(state, [](const auto& value) { return value.watchdog_released; }),
             "GUI thread stopped processing events while the wallet was being encrypted");
    QVERIFY(responsive);
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return value.encrypt_thread != std::this_thread::get_id(); }));

    // The wallet notified from inside the encryption; the keypool change is
    // raised the same way. Neither reaches a listener until the worker returns.
    std::function<void()> notify_addresses;
    {
        std::lock_guard lock{state->mutex};
        notify_addresses = state->can_get_addresses_changed;
    }
    QVERIFY(notify_addresses);
    notify_addresses();
    QVERIFY(WaitUntil([&gui_ticks, ticks_at_submit] { return gui_ticks > ticks_at_submit + 20; }, 5000));
    QCOMPARE(status_changed.count(), 0);
    QCOMPARE(addresses_changed.count(), 0);

    QVERIFY(dialog_guard);
    QVERIFY(DialogShowsEncryptionInProgress(*dialog));
    dialog->reject();
    dialog->close();
    QTest::keyClick(dialog, Qt::Key_Escape);
    dialog->accept();
    QCoreApplication::processEvents();
    QVERIFY(dialog_guard);
    QVERIFY(DialogShowsEncryptionInProgress(*dialog));
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return value.encrypt_calls == 1 && value.encrypt_in_progress; }));

    // Anything that would use the keys is refused rather than left to block
    // on the wallet locks behind the modal dialog.
    QVERIFY(!model->requestUnlock().isValid());
    QVERIFY(!model->bumpFee(Txid{}));
    QCOMPARE(messages.count(), 2);
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return value.unlock_calls == 0 && !value.bump_prepare_entered; }));

    ReleaseSyntheticEncryption(state);
    QVERIFY(WaitUntil([&dialog_guard] { return dialog_guard.isNull(); }, 5000));
    QVERIFY(result.clicked());
    QVERIFY2(result_text.startsWith("<qt>Your wallet is now encrypted."), qPrintable(result_text));
    QCOMPARE(model->getEncryptionStatus(), WalletModel::Locked);
    QCOMPARE(status_changed.count(), 1);
    QCOMPARE(addresses_changed.count(), 1);
    QVERIFY(WaitUntil([&state] {
        return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; });
    }, 5000));
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
        return value.encrypted && value.locked && value.encrypt_calls == 1 && !value.encrypt_in_progress;
    }));
}

//! The wallet announces a new transaction through the event loop, and the
//! table model reads it from the wallet on arrival. Delivered while the
//! encryption worker holds the wallet locks, that read would block the GUI
//! thread, so the update is held back and the row appears once the worker
//! has returned.
void TestEncryptWalletDefersTransactionUpdates(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->allow_encrypt = false;
    auto model{env.makeModel(state)};
    const ReleaseSyntheticEncryptionOnExit release_on_exit{state};
    TransactionTableModel* const table{model->getTransactionTableModel()};
    QSignalSpy rows_inserted{table, &QAbstractItemModel::rowsInserted};
    QVERIFY(rows_inserted.isValid());
    QCOMPARE(table->rowCount({}), 0);

    // A payment received from elsewhere, arriving after the model loaded the
    // wallet's history.
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid{}, 0});
    mtx.vout.emplace_back(COIN, CScript{} << OP_TRUE);
    const CTransactionRef tx{MakeTransactionRef(mtx)};
    std::vector<interfaces::Wallet::TransactionChangedFn> notify_transaction;
    {
        std::lock_guard lock{state->mutex};
        state->wallet_tx = interfaces::WalletTx{
            .tx = tx,
            .txin_is_mine = {false},
            .txout_is_mine = {true},
            .txout_is_change = {false},
            .txout_address = {CNoDestination{}},
            .txout_address_is_mine = {false},
            .credit = COIN,
            .debit = 0,
            .change = 0,
            .time = 1,
            .value_map = {},
            .is_coinbase = false,
        };
        for (const auto& [id, notify] : state->transaction_changed) notify_transaction.push_back(notify);
    }
    QVERIFY(!notify_transaction.empty());

    int gui_ticks{0};
    QTimer gui_latch;
    QObject::connect(&gui_latch, &QTimer::timeout, [&gui_ticks] { ++gui_ticks; });
    gui_latch.start(0);

    // Release the latch if the GUI thread stops servicing events, so an
    // update that reads the encrypting wallet fails the assertions below
    // instead of hanging the test.
    bool gui_alive{false};
    std::thread watchdog{[state, &gui_alive] {
        std::unique_lock lock{state->mutex};
        if (!state->condition.wait_for(lock, std::chrono::seconds{5}, [&] { return gui_alive || state->encrypt_finished; })) {
            state->watchdog_released = true;
            state->allow_encrypt = true;
            lock.unlock();
            state->condition.notify_all();
        }
    }};
    const JoinOnExit join_watchdog{watchdog};

    auto* dialog{new AskPassphraseDialog(AskPassphraseDialog::Encrypt, nullptr)};
    QPointer<AskPassphraseDialog> dialog_guard{dialog};
    dialog->setModel(model.get());
    GUIUtil::ShowModalDialogAsynchronously(dialog);
    QString result_text;
    VisibleMessageBoxClicker result{QMessageBox::Ok, &result_text};
    SubmitEncryption(*dialog, QStringLiteral("test-passphrase"));
    QVERIFY(WaitUntil([&state] {
        return SyntheticStateMatches(state, [](const auto& value) { return value.encrypt_entered && value.encrypt_in_progress; });
    }, 5000));

    // Announce the transaction the way the wallet does. The table model's
    // update is queued to the event loop and dispatched while the worker
    // holds the locks.
    for (const auto& notify : notify_transaction) notify(tx->GetHash(), CT_NEW);
    const int ticks_at_notify{gui_ticks};
    const bool responsive{WaitUntil([&gui_ticks, ticks_at_notify] { return gui_ticks > ticks_at_notify + 20; }, 5000)};
    {
        std::lock_guard lock{state->mutex};
        gui_alive = true;
    }
    state->condition.notify_all();
    watchdog.join();
    QVERIFY2(!SyntheticStateMatches(state, [](const auto& value) { return value.watchdog_released; }),
             "GUI thread blocked on the encrypting wallet while adding a transaction to the table");
    QVERIFY(responsive);
    QCOMPARE(rows_inserted.count(), 0);
    QCOMPARE(table->rowCount({}), 0);
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return value.encrypt_calls == 1 && value.encrypt_in_progress; }));

    ReleaseSyntheticEncryption(state);
    QVERIFY(WaitUntil([&dialog_guard] { return dialog_guard.isNull(); }, 5000));
    QVERIFY(result.clicked());
    QVERIFY2(result_text.startsWith("<qt>Your wallet is now encrypted."), qPrintable(result_text));
    QCOMPARE(rows_inserted.count(), 1);
    QCOMPARE(table->rowCount({}), 1);
    QCOMPARE(table->index(0, 0).data(TransactionTableModel::TxHashRole).toString(), QString::fromStdString(tx->GetHash().GetHex()));
    QVERIFY(WaitUntil([&state] {
        return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; });
    }, 5000));
}

//! BitcoinGUI::updateWalletStatus reads the current wallet whenever any wallet
//! reports a status change, so another wallet's notification while the
//! current one is being encrypted must not send the GUI thread into the
//! encrypting wallet's locks. The model answers those queries from the values
//! it took before the worker started.
void TestEncryptWalletOtherWalletStatusChange(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->allow_encrypt = false;
    auto model{env.makeModel(state)};
    const ReleaseSyntheticEncryptionOnExit release_on_exit{state};
    auto other_state{std::make_shared<qt_test::SyntheticWalletState>()};
    auto other{env.makeModel(other_state)};

    QSignalSpy status_changed{model.get(), &WalletModel::encryptionStatusChanged};
    QVERIFY(status_changed.isValid());
    // What BitcoinGUI::updateWalletStatus does for the current wallet when any
    // wallet's status changes.
    int refreshes{0};
    WalletModel::EncryptionStatus refreshed_status{WalletModel::NoKeys};
    const auto refresh_current_wallet = [&] {
        refreshed_status = model->getEncryptionStatus();
        model->getPQCKeyValidationInfo();
        ++refreshes;
    };
    QObject::connect(other.get(), &WalletModel::encryptionStatusChanged, other.get(), refresh_current_wallet);
    QObject::connect(other.get(), &WalletModel::pqcKeyValidationChanged, other.get(), refresh_current_wallet);

    int gui_ticks{0};
    QTimer gui_latch;
    QObject::connect(&gui_latch, &QTimer::timeout, [&gui_ticks] { ++gui_ticks; });
    gui_latch.start(0);

    // Release the latch if the GUI thread stops servicing events, so a query
    // that reaches the encrypting wallet fails the assertions below instead
    // of hanging the test.
    bool gui_alive{false};
    std::thread watchdog{[state, &gui_alive] {
        std::unique_lock lock{state->mutex};
        if (!state->condition.wait_for(lock, std::chrono::seconds{5}, [&] { return gui_alive || state->encrypt_finished; })) {
            state->watchdog_released = true;
            state->allow_encrypt = true;
            lock.unlock();
            state->condition.notify_all();
        }
    }};
    const JoinOnExit join_watchdog{watchdog};

    auto* dialog{new AskPassphraseDialog(AskPassphraseDialog::Encrypt, nullptr)};
    QPointer<AskPassphraseDialog> dialog_guard{dialog};
    dialog->setModel(model.get());
    GUIUtil::ShowModalDialogAsynchronously(dialog);
    QString result_text;
    VisibleMessageBoxClicker result{QMessageBox::Ok, &result_text};
    SubmitEncryption(*dialog, QStringLiteral("test-passphrase"));
    QVERIFY(WaitUntil([&state] {
        return SyntheticStateMatches(state, [](const auto& value) { return value.encrypt_entered && value.encrypt_in_progress; });
    }, 5000));

    // The other wallet reports a status change, as its plaintext PQC key
    // validation or a relock does, and the GUI refreshes the current wallet.
    std::function<void()> other_status_changed;
    {
        std::lock_guard lock{other_state->mutex};
        other_status_changed = other_state->status_changed;
    }
    QVERIFY(other_status_changed);
    const int ticks_before{gui_ticks};
    other_status_changed();
    const bool responsive{WaitUntil([&] { return refreshes > 0 && gui_ticks > ticks_before + 3; }, 5000)};
    {
        std::lock_guard lock{state->mutex};
        gui_alive = true;
    }
    state->condition.notify_all();
    watchdog.join();
    QVERIFY2(!SyntheticStateMatches(state, [](const auto& value) { return value.watchdog_released; }),
             "GUI thread blocked on the encrypting wallet while refreshing the status for another wallet");
    QVERIFY(responsive);
    QCOMPARE(refreshed_status, WalletModel::Unencrypted);
    QCOMPARE(model->getEncryptionStatus(), WalletModel::Unencrypted);
    QCOMPARE(status_changed.count(), 0);
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return value.encrypt_in_progress; }));

    ReleaseSyntheticEncryption(state);
    QVERIFY(WaitUntil([&dialog_guard] { return dialog_guard.isNull(); }, 5000));
    QVERIFY(result.clicked());
    QVERIFY2(result_text.startsWith("<qt>Your wallet is now encrypted."), qPrintable(result_text));
    QCOMPARE(model->getEncryptionStatus(), WalletModel::Locked);
    QCOMPARE(status_changed.count(), 1);
}

//! A failed encryption reports the error, leaves the wallet unencrypted, and
//! releases the model so a later attempt can run.
void TestEncryptWalletFailureReportsError(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->encrypt_success = false;
    auto model{env.makeModel(state)};
    QSignalSpy status_changed{model.get(), &WalletModel::encryptionStatusChanged};
    QVERIFY(status_changed.isValid());

    const auto encrypt = [&](QString& result_text) {
        auto* dialog{new AskPassphraseDialog(AskPassphraseDialog::Encrypt, nullptr)};
        QPointer<AskPassphraseDialog> dialog_guard{dialog};
        dialog->setModel(model.get());
        GUIUtil::ShowModalDialogAsynchronously(dialog);
        VisibleMessageBoxClicker result{QMessageBox::Ok, &result_text};
        SubmitEncryption(*dialog, QStringLiteral("test-passphrase"));
        QVERIFY(WaitUntil([&dialog_guard] { return dialog_guard.isNull(); }, 5000));
        QVERIFY(result.clicked());
    };

    QString result_text;
    encrypt(result_text);
    QCOMPARE(result_text, QString{"Wallet encryption failed due to an internal error. Your wallet was not encrypted."});
    QCOMPARE(model->getEncryptionStatus(), WalletModel::Unencrypted);
    QCOMPARE(status_changed.count(), 0);
    QVERIFY(WaitUntil([&state] {
        return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; });
    }, 5000));
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
        return value.encrypt_calls == 1 && !value.encrypt_in_progress && !value.encrypted && !value.locked;
    }));

    {
        std::lock_guard lock{state->mutex};
        state->encrypt_success = true;
    }
    encrypt(result_text);
    QVERIFY2(result_text.startsWith("<qt>Your wallet is now encrypted."), qPrintable(result_text));
    QCOMPARE(model->getEncryptionStatus(), WalletModel::Locked);
    QCOMPARE(status_changed.count(), 1);
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return value.encrypt_calls == 2; }));
}

//! CWallet::EncryptWallet can throw after its database transaction has
//! committed, so an exception is neither a success nor a clean failure: the
//! wallet on disk may already need the new passphrase. The model rethrows it
//! on the GUI thread, where it escapes the event loop into the application's
//! runaway-exception handler and ends the process the way the synchronous
//! call did, instead of telling the user the wallet was not encrypted.
void TestEncryptWalletExceptionEscapes(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->encrypt_throw = true;
    auto model{env.makeModel(state)};
    QSignalSpy finished{model.get(), &WalletModel::encryptWalletFinished};
    QSignalSpy status_changed{model.get(), &WalletModel::encryptionStatusChanged};
    QVERIFY(finished.isValid());
    QVERIFY(status_changed.isValid());

    auto* dialog{new AskPassphraseDialog(AskPassphraseDialog::Encrypt, nullptr)};
    QPointer<AskPassphraseDialog> dialog_guard{dialog};
    dialog->setModel(model.get());
    GUIUtil::ShowModalDialogAsynchronously(dialog);
    QString result_text;
    VisibleMessageBoxClicker result{QMessageBox::Ok, &result_text};
    SubmitEncryption(*dialog, QStringLiteral("test-passphrase"));

    QString escaped;
    try {
        WaitUntil([&dialog_guard] { return dialog_guard.isNull(); }, 5000);
    } catch (const std::runtime_error& e) {
        escaped = QString::fromUtf8(e.what());
    }
    QCOMPARE(escaped, QStringLiteral("synthetic encryption failure after commit"));
    QCOMPARE(finished.count(), 0);
    QCOMPARE(status_changed.count(), 0);
    QVERIFY(!result.clicked());
    QVERIFY(dialog_guard);
    QVERIFY(DialogShowsEncryptionInProgress(*dialog));
    // The outcome stays unknown, so nothing may use the keys.
    QVERIFY(model->isEncryptingWallet());
    QVERIFY(!model->requestUnlock().isValid());
    QVERIFY(WaitUntil([&state] {
        return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; });
    }, 5000));
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) {
        return value.encrypt_calls == 1 && !value.encrypt_in_progress && value.encrypted && value.locked;
    }));

    // The handler ends the process; here the model goes away instead, and the
    // dialog closes without reporting a result.
    model.reset();
    QVERIFY(WaitUntil([&dialog_guard] { return dialog_guard.isNull(); }, 5000));
    QVERIFY(!result.clicked());
}

//! Wallet unload and shutdown delete the model. Encryption cannot be
//! cancelled, so the model waits for the worker to finish and the operation
//! completes; the worker then touches nothing of the deleted model and the
//! dialog closes without a result to report and without finished(), whose
//! listeners would refresh the wallet status from the dying model.
void TestEncryptWalletModelDestroyedWhileEncrypting(interfaces::Node& node)
{
    SyntheticModelEnvironment env{node};
    auto state{std::make_shared<qt_test::SyntheticWalletState>()};
    state->allow_encrypt = false;
    auto model{env.makeModel(state)};
    const ReleaseSyntheticEncryptionOnExit release_on_exit{state};
    QPointer<WalletModel> model_guard{model.get()};

    // Release the latch only once this thread is inside the model destructor,
    // so the sequence check below proves the destructor waited for the
    // worker. A synchronous implementation never gets there; the bound keeps
    // it from hanging instead of failing.
    bool destroying{false};
    std::thread release{[state, &destroying] {
        {
            std::unique_lock lock{state->mutex};
            state->condition.wait_for(lock, std::chrono::seconds{5}, [&destroying] { return destroying; });
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        ReleaseSyntheticEncryption(state);
    }};
    const JoinOnExit join_release{release};

    auto* dialog{new AskPassphraseDialog(AskPassphraseDialog::Encrypt, nullptr)};
    QPointer<AskPassphraseDialog> dialog_guard{dialog};
    dialog->setModel(model.get());
    GUIUtil::ShowModalDialogAsynchronously(dialog);
    QString result_text;
    VisibleMessageBoxClicker result{QMessageBox::Ok, &result_text};
    QSignalSpy finished{dialog, &QDialog::finished};
    QVERIFY(finished.isValid());
    SubmitEncryption(*dialog, QStringLiteral("test-passphrase"));
    QVERIFY(WaitUntil([&state] {
        return SyntheticStateMatches(state, [](const auto& value) { return value.encrypt_entered; });
    }, 5000));
    QVERIFY(dialog_guard);
    QVERIFY(DialogShowsEncryptionInProgress(*dialog));

    {
        std::lock_guard lock{state->mutex};
        destroying = true;
    }
    state->condition.notify_all();
    model.reset();
    uint64_t destroyed_sequence{0};
    {
        std::lock_guard lock{state->mutex};
        destroyed_sequence = ++state->event_sequence;
    }
    release.join();
    QVERIFY(model_guard.isNull());

    uint64_t finished_sequence{0};
    {
        std::lock_guard lock{state->mutex};
        finished_sequence = state->encrypt_finished_sequence;
    }
    QVERIFY2(finished_sequence != 0 && finished_sequence < destroyed_sequence,
             "Model destruction returned before the encryption worker finished");
    QVERIFY(WaitUntil([&state] {
        return SyntheticStateMatches(state, [](const auto& value) { return value.background_clone_destroyed; });
    }, 5000));
    QVERIFY(WaitUntil([&dialog_guard] { return dialog_guard.isNull(); }, 5000));
    QVERIFY(!result.clicked());
    QCOMPARE(finished.count(), 0);
    QVERIFY(SyntheticStateMatches(state, [](const auto& value) { return value.encrypted && value.locked; }));
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        QVERIFY(!widget->isVisible() || !widget->inherits("QMessageBox"));
    }
}

//! Encrypting a real, funded descriptor wallet through the dialog leaves it
//! encrypted and locked with its history and address book intact, and the
//! keys stay usable through an unlock, spend and relock. Reopened from its
//! records, as after a restart or from a backup, the wallet is encrypted and
//! locked, still has the history and addresses, and unlocks with the
//! passphrase.
void TestEncryptWalletRealWallet(interfaces::Node& node)
{
    TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0", "-keypool=1"}}};
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    node.setContext(&test.m_node);

    const std::shared_ptr<CWallet> wallet{SetupDescriptorsWallet(node, test)};
    std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    MiniGUI mini_gui{node, platform_style.get()};
    mini_gui.initModelForWallet(node, wallet, platform_style.get());
    WalletModel& wallet_model{*mini_gui.walletModel};
    wallet_model.pollBalanceChanged();

    TransactionTableModel* const transactions{wallet_model.getTransactionTableModel()};
    AddressTableModel* const addresses{wallet_model.getAddressTableModel()};
    QCOMPARE(transactions->rowCount({}), QT_WALLET_FUNDING_TXS);
    const int address_rows{addresses->rowCount({})};
    QVERIFY(address_rows > 0);
    QCOMPARE(wallet_model.getEncryptionStatus(), WalletModel::Unencrypted);
    QSignalSpy status_changed{&wallet_model, &WalletModel::encryptionStatusChanged};
    QVERIFY(status_changed.isValid());

    const SecureString passphrase{"test-passphrase"};
    AskPassphraseDialog dialog{AskPassphraseDialog::Encrypt, nullptr};
    dialog.setModel(&wallet_model);
    QSignalSpy finished{&dialog, &QDialog::finished};
    QVERIFY(finished.isValid());
    QString result_text;
    VisibleMessageBoxClicker result{QMessageBox::Ok, &result_text};
    SubmitEncryption(dialog, QString::fromStdString(std::string{passphrase}));
    QVERIFY2(WaitUntil([&finished] { return finished.count() == 1; }, 60000), "Timed out waiting for wallet encryption");
    QVERIFY(result.clicked());
    QVERIFY2(result_text.startsWith("<qt>Your wallet is now encrypted."), qPrintable(result_text));
    QCOMPARE(finished.front().front().toInt(), static_cast<int>(QDialog::Accepted));

    QVERIFY(wallet->IsCrypted());
    QVERIFY(wallet->IsLocked());
    QCOMPARE(wallet_model.getEncryptionStatus(), WalletModel::Locked);
    QCOMPARE(status_changed.count(), 1);
    qApp->processEvents();
    QCOMPARE(transactions->rowCount({}), QT_WALLET_FUNDING_TXS);
    QCOMPARE(addresses->rowCount({}), address_rows);

    QVERIFY(wallet_model.setWalletLocked(false, passphrase));
    QCOMPARE(wallet_model.getEncryptionStatus(), WalletModel::Unlocked);
    const Txid txid{SendCoins(*wallet, mini_gui.sendCoinsDialog, PKHash{}, 5 * COIN, /*rbf=*/false)};
    QVERIFY(!txid.IsNull());
    QVERIFY(wallet_model.setWalletLocked(true));
    QCOMPARE(wallet_model.getEncryptionStatus(), WalletModel::Locked);
    qApp->processEvents();
    QCOMPARE(transactions->rowCount({}), QT_WALLET_FUNDING_TXS + 1);
    QVERIFY(FindTx(*transactions, txid).isValid());

    const auto count_address_book = [](const CWallet& w) {
        LOCK(w.cs_wallet);
        size_t entries{0};
        w.ForEachAddrBookEntry([&entries](const CTxDestination&, const std::string&, bool, const std::optional<wallet::AddressPurpose>) { ++entries; });
        return entries;
    };
    const size_t address_book_entries{count_address_book(*wallet)};
    QVERIFY(address_book_entries > 0);

    WalletContext& context{*node.walletLoader().context()};
    std::shared_ptr<CWallet> reopened{TestLoadWallet(DuplicateMockDatabase(wallet->GetDatabase()), context, WALLET_FLAG_DESCRIPTORS)};
    QVERIFY(reopened);
    QVERIFY(reopened->IsCrypted());
    QVERIFY(reopened->IsLocked());
    QCOMPARE(WITH_LOCK(reopened->cs_wallet, return reopened->mapWallet.size()), static_cast<size_t>(QT_WALLET_FUNDING_TXS + 1));
    QCOMPARE(count_address_book(*reopened), address_book_entries);
    const wallet::PQCKeyValidationInfo reopened_pqc{reopened->GetPQCKeyValidationInfo()};
    QCOMPARE(reopened_pqc.pending_records, size_t{0});
    QCOMPARE(reopened_pqc.failed_records, size_t{0});
    QVERIFY(reopened->Unlock(passphrase));
    QVERIFY(!reopened->IsLocked());
    QVERIFY(reopened->Lock());
    QVERIFY(reopened->IsLocked());
    TestUnloadWallet(std::move(reopened));
}

void TestGUI(interfaces::Node& node)
{
    // Set up a small funded wallet history instead of importing the full mature chain.
    TestChain100Setup test{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}};
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    node.setContext(&test.m_node);

    // "Full" GUI tests, use descriptor wallet
    const std::shared_ptr<CWallet>& desc_wallet = SetupDescriptorsWallet(node, test, /*watch_only=*/false, /*coinbase_offset=*/0);
    TestGUI(node, desc_wallet);

    // Legacy watch-only wallet test
    // Verify PSBT creation.
    TestGUIWatchOnly(node, test);
}

} // namespace

void WalletTests::walletTests()
{
    // Modal test clickers need Qt dialogs so their timers remain active while
    // the Cocoa platform plugin is running a nested dialog event loop.
    QApplication::setAttribute(Qt::AA_DontUseNativeDialogs);
#ifdef Q_OS_MACOS
    if (QApplication::platformName() == "minimal") {
        // Disable for mac on "minimal" platform to avoid crashes inside the Qt
        // framework when it tries to look up unimplemented cocoa functions,
        // and fails to handle returned nulls
        // (https://bugreports.qt.io/browse/QTBUG-49686).
        qWarning() << "Skipping WalletTests on mac build with 'minimal' platform set due to Qt bugs. To run AppTests, invoke "
                      "with 'QT_QPA_PLATFORM=cocoa test_qbit-qt' on mac, or else use a linux or windows build.";
        return;
    }
#endif
    TestGUI(m_node);
    TestP2MRReceiveAddressTypes(m_node);
    TestSendPQCReportPropagation(m_node);
    TestAsyncFeeBumpLifecycle(m_node);
    TestSendCompletionAfterModelDestruction(m_node);
    TestUnlockContextModelLifetime(m_node);
    TestCanGetAddressesNotificationIsQueued(m_node);
    TestSendPQCWarningFormatting();
    TestTransactionUsageFormatting();
    TestSendFailureShowsAllConsumedKeys(m_node);
    TestFeeBumpFailureShowsConsumedUsage(m_node);
    TestFeeBumpCommitFailureKeepsUsage(m_node);
    TestFeeBumpSuccessShowsUsage(m_node);
    TestUsageIsAttemptLocal(m_node);
    TestUsageStaysOutOfPortableArtifacts(m_node);
    TestFeeBumpModelDestroyedDuringPrepareFailure(m_node);
    TestFeeBumpModelDestroyedDuringConfirmation(m_node);
    TestFeeBumpModelDestroyedDuringDraftFailure(m_node);
    TestFeeBumpModelDestroyedDuringUnlock(m_node);
    TestEncryptWalletKeepsGuiResponsive(m_node);
    TestEncryptWalletDefersTransactionUpdates(m_node);
    TestEncryptWalletOtherWalletStatusChange(m_node);
    TestEncryptWalletFailureReportsError(m_node);
    TestEncryptWalletExceptionEscapes(m_node);
    TestEncryptWalletModelDestroyedWhileEncrypting(m_node);
    TestEncryptWalletRealWallet(m_node);
}
