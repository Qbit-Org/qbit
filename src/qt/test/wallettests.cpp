// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/wallettests.h>
#include <qt/test/util.h>

#include <wallet/coincontrol.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <node/interface_ui.h>
#include <qt/bitcoinamountfield.h>
#include <qt/qbitunits.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/receivecoinsdialog.h>
#include <qt/receiverequestdialog.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendcoinsentry.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletmodel.h>
#include <qt/walletmodeltransaction.h>
#include <outputtype.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/solver.h>
#include <consensus/consensus.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/pqc_usage.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <chrono>
#include <memory>
#include <span>
#include <utility>

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QElapsedTimer>
#include <QEvent>
#include <QObject>
#include <QPointer>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QListView>
#include <QDialogButtonBox>

using wallet::AddWallet;
using wallet::CWallet;
using wallet::CreateMockableWalletDatabase;
using wallet::RemoveWallet;
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

class SendConfirmationClicker : public QObject
{
public:
    SendConfirmationClicker(QString* text, QMessageBox::StandardButton confirm_type)
        : QObject(QApplication::instance()), m_text(text), m_confirm_type(confirm_type)
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
            click(qobject_cast<SendConfirmationDialog*>(watched));
        }
        return QObject::eventFilter(watched, event);
    }

private:
    void tryClickVisibleDialog()
    {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("SendConfirmationDialog")) {
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
        QAbstractButton* button = dialog->button(m_confirm_type);
        button->setEnabled(true);
        QMetaObject::invokeMethod(dialog, "done", Qt::QueuedConnection, Q_ARG(int, static_cast<int>(m_confirm_type)));
        m_timer.stop();
        deleteLater();
    }

    QString* const m_text;
    const QMessageBox::StandardButton m_confirm_type;
    QTimer m_timer;
    bool m_clicked{false};
};

class MessageBoxClicker : public QObject
{
public:
    MessageBoxClicker(QString object_name, QMessageBox::StandardButton button)
        : QObject(QApplication::instance()), m_object_name(std::move(object_name)), m_button(button)
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
            click(qobject_cast<QMessageBox*>(watched));
        }
        return QObject::eventFilter(watched, event);
    }

private:
    void tryClickVisibleDialog()
    {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("QMessageBox")) {
                click(qobject_cast<QMessageBox*>(widget));
                if (m_clicked) return;
            }
        }
    }

    void click(QMessageBox* dialog)
    {
        if (m_clicked || m_click_pending || !dialog || dialog->objectName() != m_object_name) return;
        QAbstractButton* button = dialog->button(m_button);
        if (!button) return;
        if (!m_finished_connected) {
            m_finished_connected = true;
            connect(dialog, &QMessageBox::finished, this, [this] {
                m_clicked = true;
                m_timer.stop();
                deleteLater();
            });
        }
        m_click_pending = true;
        QPointer<QAbstractButton> button_ptr{button};
        QTimer::singleShot(50, this, [this, button_ptr] {
            m_click_pending = false;
            if (m_clicked || !button_ptr) return;
            button_ptr->setEnabled(true);
            button_ptr->click();
        });
    }

    const QString m_object_name;
    const QMessageBox::StandardButton m_button;
    QTimer m_timer;
    bool m_clicked{false};
    bool m_click_pending{false};
    bool m_finished_connected{false};
};

//! Press "Yes" or "Cancel" buttons in modal send confirmation dialog.
void ConfirmSend(QString* text = nullptr, QMessageBox::StandardButton confirm_type = QMessageBox::Yes)
{
    new SendConfirmationClicker(text, confirm_type);
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
    if (expectError.empty()) {
        ConfirmSend(&text, cancel ? QMessageBox::Cancel : QMessageBox::Yes);
    } else {
        ConfirmMessage(&text, 0ms);
    }
    action->trigger();
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

};

class SyntheticPQCReportWallet : public interfaces::Wallet
{
public:
    explicit SyntheticPQCReportWallet(wallet::PQCUsageReport report) : m_report(std::move(report)) {}

    bool encryptWallet(const SecureString&) override { return false; }
    bool isCrypted() override { return false; }
    bool lock() override { return false; }
    bool unlock(const SecureString&) override { return true; }
    bool isLocked() override { return false; }
    bool changeWalletPassphrase(const SecureString&, const SecureString&) override { return false; }
    void abortRescan() override {}
    bool backupWallet(const std::string&) override { return false; }
    std::string getWalletName() override { return "synthetic-pqc-report"; }
    util::Result<CTxDestination> getNewDestination(const OutputType, const std::string&) override { return CTxDestination{PKHash{}}; }
    bool getPubKey(const CScript&, const CKeyID&, CPubKey&) override { return false; }
    SigningResult signMessage(const std::string&, const PKHash&, std::string&) override { return SigningResult::PRIVATE_KEY_NOT_AVAILABLE; }
    bool isSpendable(const CTxDestination&) override { return false; }
    bool setAddressBook(const CTxDestination&, const std::string&, const std::optional<wallet::AddressPurpose>&) override { return false; }
    bool delAddressBook(const CTxDestination&) override { return false; }
    bool getAddress(const CTxDestination&, std::string*, wallet::AddressPurpose*) override { return false; }
    std::vector<interfaces::WalletAddress> getAddresses() override { return {}; }
    std::vector<OutputType> getAvailableAddressTypes() override { return {OutputType::P2MR}; }
    std::vector<std::string> getAddressReceiveRequests() override { return {}; }
    bool setAddressReceiveRequest(const CTxDestination&, const std::string&, const std::string&) override { return false; }
    util::Result<void> displayAddress(const CTxDestination&) override { return {}; }
    bool lockCoin(const COutPoint&, const bool) override { return false; }
    bool unlockCoin(const COutPoint&) override { return false; }
    bool isLockedCoin(const COutPoint&) override { return false; }
    void listLockedCoins(std::vector<COutPoint>&) override {}
    util::Result<CTransactionRef> createTransaction(const std::vector<wallet::CRecipient>& recipients,
        const wallet::CCoinControl&,
        bool,
        int& change_pos,
        CAmount& fee,
        wallet::PQCUsageReport* pqc_usage,
        const SigningProgressCallback&) override
    {
        CMutableTransaction tx;
        if (!recipients.empty()) {
            tx.vout.emplace_back(recipients.front().nAmount, CScript{} << OP_TRUE);
        }
        change_pos = -1;
        fee = 1000;
        if (pqc_usage) {
            *pqc_usage = m_report;
        }
        return MakeTransactionRef(std::move(tx));
    }
    void commitTransaction(CTransactionRef, interfaces::WalletValueMap, interfaces::WalletOrderForm) override {}
    bool transactionCanBeAbandoned(const Txid&) override { return false; }
    bool abandonTransaction(const Txid&) override { return false; }
    bool transactionCanBeBumped(const Txid&) override { return false; }
    bool createBumpTransaction(const Txid&, const wallet::CCoinControl&, std::vector<bilingual_str>&, CAmount&, CAmount&, CMutableTransaction&) override { return false; }
    bool signBumpTransaction(CMutableTransaction&) override { return false; }
    bool commitBumpTransaction(const Txid&, CMutableTransaction&&, std::vector<bilingual_str>&, Txid&) override { return false; }
    CTransactionRef getTx(const Txid&) override { return {}; }
    interfaces::WalletTx getWalletTx(const Txid&) override { return {}; }
    std::set<interfaces::WalletTx> getWalletTxs() override { return {}; }
    bool tryGetTxStatus(const Txid&, interfaces::WalletTxStatus&, int&, int64_t&) override { return false; }
    interfaces::WalletTx getWalletTxDetails(const Txid&, interfaces::WalletTxStatus&, interfaces::WalletOrderForm&, bool&, int&) override { return {}; }
    std::optional<common::PSBTError> fillPSBT(std::optional<int>, bool, bool, size_t*, PartiallySignedTransaction&, bool&, wallet::PQCUsageReport*) override { return std::nullopt; }
    interfaces::WalletBalances getBalances() override { return {.balance = 50 * COIN}; }
    bool tryGetBalances(interfaces::WalletBalances& balances, uint256&) override
    {
        balances = getBalances();
        return true;
    }
    CAmount getBalance() override { return 50 * COIN; }
    CAmount getAvailableBalance(const wallet::CCoinControl&) override { return 50 * COIN; }
    bool txinIsMine(const CTxIn&) override { return false; }
    bool txoutIsMine(const CTxOut&) override { return false; }
    CAmount getDebit(const CTxIn&) override { return 0; }
    CAmount getCredit(const CTxOut&) override { return 0; }
    CoinsList listCoins() override { return {}; }
    std::vector<interfaces::WalletTxOut> getCoins(const std::vector<COutPoint>&) override { return {}; }
    CAmount getRequiredFee(unsigned int) override { return 0; }
    CAmount getMinimumFee(unsigned int, const wallet::CCoinControl&, int* returned_target, FeeReason* reason) override
    {
        if (returned_target) *returned_target = 6;
        if (reason) *reason = FeeReason::NONE;
        return 0;
    }
    unsigned int getConfirmTarget() override { return 6; }
    bool hdEnabled() override { return true; }
    bool canGetAddresses() override { return true; }
    bool privateKeysDisabled() override { return false; }
    bool taprootEnabled() override { return false; }
    bool hasExternalSigner() override { return false; }
    OutputType getDefaultAddressType() override { return OutputType::P2MR; }
    CAmount getDefaultMaxTxFee() override { return MAX_MONEY; }
    wallet::PQCKeyValidationInfo getPQCKeyValidationInfo() const override { return {}; }
    void remove() override {}
    std::unique_ptr<interfaces::Handler> handleUnload(UnloadFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleShowProgress(ShowProgressFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleStatusChanged(StatusChangedFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleAddressBookChanged(AddressBookChangedFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleTransactionChanged(TransactionChangedFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn) override { return interfaces::MakeCleanupHandler([] {}); }

private:
    wallet::PQCUsageReport m_report;
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

    ReceiveCoinsDialog receiveCoinsDialog(platformStyle.get());
    receiveCoinsDialog.setModel(mini_gui.walletModel.get());
    QComboBox* address_type = receiveCoinsDialog.findChild<QComboBox*>("addressType");
    QVERIFY(address_type);
    QCOMPARE(address_type->count(), 1);
    QCOMPARE(address_type->currentData().toInt(), static_cast<int>(OutputType::P2MR));
    QCOMPARE(address_type->itemText(0), QString("P2MR"));
    QVERIFY(!address_type->isVisibleTo(&receiveCoinsDialog));
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

    WalletModel wallet_model(std::make_unique<SyntheticPQCReportWallet>(expected_report), client_model, platformStyle.get());
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
    TestSendPQCWarningFormatting();
}
