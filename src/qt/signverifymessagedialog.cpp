// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/signverifymessagedialog.h>
#include <qt/forms/ui_signverifymessagedialog.h>

#include <qt/addressbookpage.h>
#include <qt/guiutil.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <common/p2mr_data_signature.h>
#include <common/signmessage.h>
#include <crypto/sha256.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <outputtype.h>
#include <script/interpreter.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/pqc_usage.h>
#include <wallet/wallet.h>

#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include <QByteArray>
#include <QClipboard>
#include <QComboBox>
#include <QPlainTextEdit>
#include <QStringList>

#include <univalue.h>

namespace {

QString BilingualToQString(const bilingual_str& message)
{
    return QString::fromStdString(message.translated.empty() ? message.original : message.translated);
}

std::string HashToHexString(const uint256& hash)
{
    return HexStr(std::span<const unsigned char>{hash.begin(), hash.end()});
}

QString ToQString(const std::string& text)
{
    return QString::fromStdString(text);
}

constexpr int P2MR_SIGN_INPUT_HASH{1};
constexpr int P2MR_VERIFY_INPUT_TEXT{0};
constexpr int P2MR_VERIFY_INPUT_HASH{1};
constexpr int P2MR_VERIFY_INPUT_PROOF_ONLY{2};
constexpr const char* P2MR_MESSAGE_HASH_SOURCE_UTF8_TEXT{"utf8-text"};
constexpr const char* P2MR_MESSAGE_HASH_SOURCE_HEX_HASH{"hex-hash"};
constexpr const char* P2MR_MESSAGE_HASH_ALGORITHM_SHA256{"sha256"};

struct P2MRMessageHashMetadata {
    std::optional<std::string> source;
    std::optional<std::string> algorithm;
};

uint256 HashP2MRUtf8Text(const QString& text)
{
    const QByteArray bytes{text.toUtf8()};
    uint256 hash;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(bytes.constData()), static_cast<size_t>(bytes.size()))
        .Finalize(hash.begin());
    return hash;
}

bool ParseHexBytes(const QString& text, std::string_view name, size_t expected_size, std::vector<unsigned char>& bytes, QString& error)
{
    const std::string value{text.trimmed().toStdString()};
    if (!IsHex(value)) {
        error = SignVerifyMessageDialog::tr("%1 must be hex.").arg(QString::fromStdString(std::string{name}));
        return false;
    }
    bytes = ParseHex(value);
    if (bytes.size() != expected_size) {
        error = SignVerifyMessageDialog::tr("%1 must be exactly %2 bytes.").arg(QString::fromStdString(std::string{name})).arg(expected_size);
        return false;
    }
    return true;
}

bool ParseDataHash(const QString& text, uint256& hash, QString& error)
{
    std::vector<unsigned char> bytes;
    if (!ParseHexBytes(text, "message_hash", uint256::size(), bytes, error)) {
        return false;
    }
    hash = uint256{std::span<const unsigned char>{bytes.data(), bytes.size()}};
    return true;
}

bool ReadRequiredString(const UniValue& object, const char* name, std::string& value, QString& error)
{
    const UniValue& field{object.find_value(name)};
    if (!field.isStr()) {
        error = SignVerifyMessageDialog::tr("Proof field \"%1\" must be a string.").arg(name);
        return false;
    }
    value = field.get_str();
    return true;
}

bool ParseProofHexField(const UniValue& object, const char* name, size_t expected_size, std::vector<unsigned char>& bytes, QString& error)
{
    std::string text;
    if (!ReadRequiredString(object, name, text, error)) return false;
    return ParseHexBytes(QString::fromStdString(text), name, expected_size, bytes, error);
}

bool ParseProofScriptField(const UniValue& object, const char* name, CScript& script, QString& error)
{
    std::string text;
    if (!ReadRequiredString(object, name, text, error)) return false;
    if (!IsHex(text)) {
        error = SignVerifyMessageDialog::tr("Proof field \"%1\" must be hex.").arg(name);
        return false;
    }
    const std::vector<unsigned char> bytes{ParseHex(text)};
    script = CScript{bytes.begin(), bytes.end()};
    return true;
}

bool ParseP2MRProofJson(const QString& proof_json, common::P2MRDataSignatureProof& proof, QString& error)
{
    UniValue object;
    if (!object.read(proof_json.toStdString()) || !object.isObject()) {
        error = SignVerifyMessageDialog::tr("Proof must be a JSON object.");
        return false;
    }

    std::string proof_mode;
    if (!ReadRequiredString(object, "proof_mode", proof_mode, error)) return false;
    if (proof_mode != common::P2MR_DATA_SIGNATURE_PROOF_MODE) {
        error = SignVerifyMessageDialog::tr("Unsupported proof_mode.");
        return false;
    }

    std::string address;
    if (!ReadRequiredString(object, "address", address, error)) return false;
    const CTxDestination dest{DecodeDestination(address)};
    if (!IsValidDestination(dest)) {
        error = SignVerifyMessageDialog::tr("Proof address is invalid.");
        return false;
    }
    const auto* output{std::get_if<WitnessV2P2MR>(&dest)};
    if (!output) {
        error = SignVerifyMessageDialog::tr("Proof address is not a P2MR address.");
        return false;
    }
    proof.output = *output;

    std::vector<unsigned char> bytes;
    if (!ParseProofHexField(object, "message_hash", uint256::size(), bytes, error)) return false;
    proof.message_hash = uint256{std::span<const unsigned char>{bytes.data(), bytes.size()}};

    const UniValue& datasig_hash_field{object.find_value("datasig_hash")};
    if (datasig_hash_field.isNull()) {
        proof.datasig_hash = ComputeQbitDataSigPQCHash(std::span<const unsigned char>{proof.message_hash.begin(), proof.message_hash.end()});
    } else {
        if (!datasig_hash_field.isStr()) {
            error = SignVerifyMessageDialog::tr("Proof field \"datasig_hash\" must be a string.");
            return false;
        }
        if (!ParseHexBytes(QString::fromStdString(datasig_hash_field.get_str()), "datasig_hash", uint256::size(), bytes, error)) return false;
        proof.datasig_hash = uint256{std::span<const unsigned char>{bytes.data(), bytes.size()}};
    }

    if (!ParseProofHexField(object, "pubkey", PQC_PUBKEY_SIZE, bytes, error)) return false;
    proof.pubkey = CPQCPubKey{bytes};

    if (!ParseProofHexField(object, "signature", PQC_SIG_SIZE, proof.signature, error)) return false;

    if (!ParseProofScriptField(object, "leaf_script", proof.leaf_script, error)) return false;

    std::string control_block;
    if (!ReadRequiredString(object, "control_block", control_block, error)) return false;
    if (!IsHex(control_block)) {
        error = SignVerifyMessageDialog::tr("Proof field \"control_block\" must be hex.");
        return false;
    }
    proof.control_block = ParseHex(control_block);

    const UniValue& leaf_version{object.find_value("leaf_version")};
    if (!leaf_version.isNum()) {
        error = SignVerifyMessageDialog::tr("Proof field \"leaf_version\" must be a number.");
        return false;
    }
    const int leaf_version_int{leaf_version.getInt<int>()};
    if (leaf_version_int < 0 || leaf_version_int > 0xff) {
        error = SignVerifyMessageDialog::tr("Proof field \"leaf_version\" is out of range.");
        return false;
    }
    proof.leaf_version = static_cast<uint8_t>(leaf_version_int);
    return true;
}

void AppendPQCUsageJson(UniValue& object, const wallet::PQCUsageReport& report)
{
    if (report.key_states.empty()) return;

    UniValue key_states(UniValue::VARR);
    for (const wallet::PQCUsageSnapshot& key_state : report.key_states) {
        UniValue state(UniValue::VOBJ);
        state.pushKV("pubkey", HexStr(std::span<const unsigned char>{key_state.pubkey.begin(), key_state.pubkey.end()}));
        state.pushKV("pqc_signature_count", static_cast<int64_t>(key_state.signature_count));
        state.pushKV("pqc_signature_limit", static_cast<int64_t>(key_state.signature_limit));
        state.pushKV("pqc_signatures_remaining", static_cast<int64_t>(key_state.signatures_remaining));
        state.pushKV("pqc_limit_state", std::string{wallet::PQCSignatureLimitStateName(key_state.limit_state)});
        key_states.push_back(std::move(state));
    }
    object.pushKV("pqc_key_states", std::move(key_states));

    if (report.overall_state.has_value()) {
        object.pushKV("pqc_overall_limit_state", std::string{wallet::PQCSignatureLimitStateName(*report.overall_state)});
    }
    if (report.key_states.size() == 1) {
        const wallet::PQCUsageSnapshot& key_state{report.key_states.front()};
        object.pushKV("pqc_signature_count", static_cast<int64_t>(key_state.signature_count));
        object.pushKV("pqc_signature_limit", static_cast<int64_t>(key_state.signature_limit));
        object.pushKV("pqc_signatures_remaining", static_cast<int64_t>(key_state.signatures_remaining));
        object.pushKV("pqc_limit_state", std::string{wallet::PQCSignatureLimitStateName(key_state.limit_state)});
    }

    const std::vector<bilingual_str> warnings{wallet::FormatPQCUsageWarnings(report.warnings)};
    if (!warnings.empty()) {
        UniValue warning_values(UniValue::VARR);
        for (const bilingual_str& warning : warnings) {
            warning_values.push_back(warning.translated.empty() ? warning.original : warning.translated);
        }
        object.pushKV("warnings", std::move(warning_values));
    }
}

QString FormatPQCUsageStatus(const wallet::PQCUsageReport& report)
{
    QStringList lines;
    if (report.overall_state.has_value()) {
        lines.append(SignVerifyMessageDialog::tr("PQC usage state after signing: %1.")
            .arg(QString::fromStdString(std::string{wallet::PQCSignatureLimitStateName(*report.overall_state)})));
    }
    if (report.key_states.size() == 1) {
        const wallet::PQCUsageSnapshot& key_state{report.key_states.front()};
        lines.append(SignVerifyMessageDialog::tr("Signatures remaining for this key: %1 of %2.")
            .arg(key_state.signatures_remaining)
            .arg(key_state.signature_limit));
    }
    for (const bilingual_str& warning : wallet::FormatPQCUsageWarnings(report.warnings)) {
        lines.append(BilingualToQString(warning));
    }
    return lines.join("\n");
}

common::P2MRDataSignatureProof MakeP2MRDataSignatureProof(const interfaces::P2MRDataSignatureResult& result)
{
    return {
        .output = result.output,
        .message_hash = result.message_hash,
        .datasig_hash = result.datasig_hash,
        .pubkey = CPQCPubKey{std::span<const unsigned char>{result.pubkey.data(), result.pubkey.size()}},
        .signature = result.signature,
        .leaf_script = result.leaf_script,
        .control_block = result.control_block,
        .leaf_version = result.leaf_version,
    };
}

UniValue BuildP2MRProofJson(const interfaces::P2MRDataSignatureResult& result, const P2MRMessageHashMetadata& metadata)
{
    const common::P2MRDataSignatureProof proof{MakeP2MRDataSignatureProof(result)};
    UniValue object(UniValue::VOBJ);
    object.pushKV("address", EncodeDestination(CTxDestination{proof.output}));
    object.pushKV("message_hash", HashToHexString(proof.message_hash));
    if (metadata.source.has_value()) {
        object.pushKV("message_hash_source", *metadata.source);
    }
    if (metadata.algorithm.has_value()) {
        object.pushKV("message_hash_algorithm", *metadata.algorithm);
    }
    object.pushKV("datasig_hash", HashToHexString(proof.datasig_hash));
    object.pushKV("domain", common::P2MR_DATA_SIGNATURE_DOMAIN);
    object.pushKV("algorithm", common::P2MR_DATA_SIGNATURE_ALGORITHM);
    object.pushKV("proof_mode", common::P2MR_DATA_SIGNATURE_PROOF_MODE);
    object.pushKV("pubkey", HexStr(std::span<const unsigned char>{proof.pubkey.begin(), proof.pubkey.end()}));
    object.pushKV("signature", HexStr(proof.signature));
    object.pushKV("leaf_version", static_cast<int>(proof.leaf_version));
    object.pushKV("leaf_script", HexStr(proof.leaf_script));
    object.pushKV("control_block", HexStr(proof.control_block));
    object.pushKV("p2mr_merkle_root", HashToHexString(proof.output.GetMerkleRoot()));
    if (result.pqc_usage) {
        AppendPQCUsageJson(object, *result.pqc_usage);
    }
    return object;
}

} // namespace

SignVerifyMessageDialog::SignVerifyMessageDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::SignVerifyMessageDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    ui->addressBookButton_SM->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
    ui->pasteButton_SM->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
    ui->copySignatureButton_SM->setIcon(platformStyle->SingleColorIcon(":/icons/editcopy"));
    ui->signMessageButton_SM->setIcon(platformStyle->SingleColorIcon(":/icons/edit"));
    ui->clearButton_SM->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));
    ui->addressBookButton_VM->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
    ui->verifyMessageButton_VM->setIcon(platformStyle->SingleColorIcon(":/icons/transaction_0"));
    ui->clearButton_VM->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));

    GUIUtil::setupAddressWidget(ui->addressIn_SM, this);
    GUIUtil::setupAddressWidget(ui->addressIn_VM, this);

    ui->addressIn_SM->installEventFilter(this);
    ui->messageIn_SM->installEventFilter(this);
    ui->signatureOut_SM->installEventFilter(this);
    ui->addressIn_VM->installEventFilter(this);
    ui->messageIn_VM->installEventFilter(this);
    ui->signatureIn_VM->installEventFilter(this);

    ui->signatureOut_SM->setFont(GUIUtil::fixedPitchFont());
    ui->signatureIn_VM->setFont(GUIUtil::fixedPitchFont());
    ui->p2mrMessageHash_SM->setFont(GUIUtil::fixedPitchFont());
    ui->p2mrVerifyMessageHash_VM->setFont(GUIUtil::fixedPitchFont());

    connect(ui->p2mrDataInputMode_SM, qOverload<int>(&QComboBox::currentIndexChanged), this, [this] {
        updateP2MRSignModeUi();
    });
    connect(ui->messageIn_SM, &QPlainTextEdit::textChanged, this, &SignVerifyMessageDialog::updateP2MRSignHashPreview);
    connect(ui->p2mrVerifyInputMode_VM, qOverload<int>(&QComboBox::currentIndexChanged), this, [this] {
        updateP2MRVerifyModeUi();
    });
    connect(ui->p2mrDataIn_VM, &QPlainTextEdit::textChanged, this, &SignVerifyMessageDialog::updateP2MRVerifyHashPreview);

    updateP2MRDataModeUi();

    GUIUtil::handleCloseWindowShortcut(this);
}

SignVerifyMessageDialog::~SignVerifyMessageDialog()
{
    delete ui;
}

void SignVerifyMessageDialog::setModel(WalletModel *_model)
{
    this->model = _model;
    updateP2MRDataModeUi();
}

bool SignVerifyMessageDialog::isP2MRDataMode() const
{
    return IsP2MROnlyOutputChain();
}

void SignVerifyMessageDialog::updateP2MRDataModeUi()
{
    const bool p2mr_mode{isP2MRDataMode()};
    if (p2mr_mode) {
        setWindowTitle(tr("P2MR/PQC Data Signatures"));
        ui->tabWidget->setTabText(0, tr("&Sign Data"));
        ui->tabWidget->setTabText(1, tr("&Verify Proof"));
        ui->infoLabel_SM->setText(tr("Sign UTF-8 text by hashing it with SHA256, or sign a caller-supplied 32-byte hash, "
                                     "using a PQC key committed by a wallet-owned P2MR address. Signing consumes PQC "
                                     "signature budget for that key."));
        ui->addressIn_SM->setToolTip(tr("The wallet-owned P2MR address to sign with"));
        ui->signatureLabel_SM->setText(tr("Proof JSON"));
        ui->signatureOut_SM->setPlaceholderText(tr("Click \"Sign Data\" to generate proof JSON"));
        ui->copySignatureButton_SM->setToolTip(tr("Copy the current proof JSON to the clipboard"));
        ui->clearButton_SM->setToolTip(tr("Reset all sign data fields"));
        ui->p2mrInputModeLabel_SM->setVisible(true);
        ui->p2mrDataInputMode_SM->setVisible(true);
        ui->p2mrMessageHashLabel_SM->setVisible(true);
        ui->p2mrMessageHash_SM->setVisible(true);

        ui->infoLabel_VM->setText(tr("Verify a P2MR/PQC data-signature proof JSON object. When original text or a 32-byte "
                                     "hash is entered, it must match the proof's message_hash before the P2MR commitment "
                                     "and PQC signature are verified."));
        ui->addressIn_VM->setVisible(false);
        ui->addressBookButton_VM->setVisible(false);
        ui->signatureIn_VM->setVisible(false);
        ui->messageIn_VM->setToolTip(tr("Paste proof JSON to verify"));
        ui->messageIn_VM->setPlaceholderText(tr("Paste proof JSON to verify"));
        ui->verifyMessageButton_VM->setText(tr("Verify &Proof"));
        ui->verifyMessageButton_VM->setToolTip(tr("Verify the P2MR/PQC proof JSON"));
        ui->clearButton_VM->setToolTip(tr("Reset the proof and data fields"));
        ui->p2mrVerifyModeLabel_VM->setVisible(true);
        ui->p2mrVerifyInputMode_VM->setVisible(true);
        ui->p2mrProofLabel_VM->setVisible(true);

        updateP2MRSignModeUi();
        updateP2MRVerifyModeUi();
    } else {
        setWindowTitle(tr("Signatures - Sign / Verify a Message"));
        ui->tabWidget->setTabText(0, tr("&Sign Message"));
        ui->tabWidget->setTabText(1, tr("&Verify Message"));
        ui->infoLabel_SM->setText(tr("You can sign messages/agreements with your legacy (P2PKH) addresses to prove you can "
                                     "receive QBT sent to them. Be careful not to sign anything vague or random, as phishing "
                                     "attacks may try to trick you into signing your identity over to them. Only sign "
                                     "fully-detailed statements you agree to."));
        ui->addressIn_SM->setToolTip(tr("The qbit address to sign the message with"));
        ui->messageIn_SM->setToolTip(tr("Enter the message you want to sign here"));
        ui->messageIn_SM->setPlaceholderText(tr("Enter the message you want to sign here"));
        ui->signatureLabel_SM->setText(tr("Signature"));
        ui->signatureOut_SM->setPlaceholderText(tr("Click \"Sign Message\" to generate signature"));
        ui->copySignatureButton_SM->setToolTip(tr("Copy the current signature to the clipboard"));
        ui->signMessageButton_SM->setText(tr("Sign &Message"));
        ui->signMessageButton_SM->setToolTip(tr("Sign the message to prove you own this qbit address"));
        ui->clearButton_SM->setToolTip(tr("Reset all sign message fields"));
        ui->p2mrInputModeLabel_SM->setVisible(false);
        ui->p2mrDataInputMode_SM->setVisible(false);
        ui->p2mrMessageHashLabel_SM->setVisible(false);
        ui->p2mrMessageHash_SM->setVisible(false);

        ui->infoLabel_VM->setText(tr("Enter the receiver's address, message (ensure you copy line breaks, spaces, tabs, etc. "
                                     "exactly) and signature below to verify the message. Be careful not to read more into "
                                     "the signature than what is in the signed message itself, to avoid being tricked by a "
                                     "man-in-the-middle attack. Note that this only proves the signing party receives with "
                                     "the address, it cannot prove sendership of any transaction!"));
        ui->addressIn_VM->setVisible(true);
        ui->addressBookButton_VM->setVisible(true);
        ui->signatureIn_VM->setVisible(true);
        ui->messageIn_VM->setToolTip(tr("The signed message to verify"));
        ui->messageIn_VM->setPlaceholderText(tr("The signed message to verify"));
        ui->verifyMessageButton_VM->setText(tr("Verify &Message"));
        ui->verifyMessageButton_VM->setToolTip(tr("Verify the message to ensure it was signed with the specified qbit address"));
        ui->clearButton_VM->setToolTip(tr("Reset all verify message fields"));
        ui->p2mrVerifyModeLabel_VM->setVisible(false);
        ui->p2mrVerifyInputMode_VM->setVisible(false);
        ui->p2mrVerifyMessageHashLabel_VM->setVisible(false);
        ui->p2mrVerifyMessageHash_VM->setVisible(false);
        ui->p2mrVerifyDataLabel_VM->setVisible(false);
        ui->p2mrDataIn_VM->setVisible(false);
        ui->p2mrProofLabel_VM->setVisible(false);
    }
}

void SignVerifyMessageDialog::updateP2MRSignModeUi()
{
    if (!isP2MRDataMode()) return;

    const bool hash_mode{ui->p2mrDataInputMode_SM->currentIndex() == P2MR_SIGN_INPUT_HASH};
    if (hash_mode) {
        ui->messageIn_SM->setToolTip(tr("Enter the 32-byte message hash as 64 hex characters"));
        ui->messageIn_SM->setPlaceholderText(tr("Enter the 32-byte message hash as 64 hex characters"));
        ui->signMessageButton_SM->setText(tr("Sign Data &Hash"));
        ui->signMessageButton_SM->setToolTip(tr("Sign the caller-supplied data hash with the selected P2MR/PQC key"));
    } else {
        ui->messageIn_SM->setToolTip(tr("Enter the UTF-8 text data to sign"));
        ui->messageIn_SM->setPlaceholderText(tr("Enter the UTF-8 text data to sign"));
        ui->signMessageButton_SM->setText(tr("Sign &Data"));
        ui->signMessageButton_SM->setToolTip(tr("Hash the text with SHA256, then sign the hash with the selected P2MR/PQC key"));
    }
    updateP2MRSignHashPreview();
}

void SignVerifyMessageDialog::updateP2MRSignHashPreview()
{
    if (!isP2MRDataMode()) return;

    uint256 message_hash;
    if (ui->p2mrDataInputMode_SM->currentIndex() == P2MR_SIGN_INPUT_HASH) {
        QString parse_error;
        if (!ParseDataHash(ui->messageIn_SM->document()->toPlainText(), message_hash, parse_error)) {
            ui->p2mrMessageHash_SM->clear();
            return;
        }
    } else {
        if (ui->messageIn_SM->document()->isEmpty()) {
            ui->p2mrMessageHash_SM->clear();
            return;
        }
        message_hash = HashP2MRUtf8Text(ui->messageIn_SM->document()->toPlainText());
    }

    ui->p2mrMessageHash_SM->setText(QString::fromStdString(HashToHexString(message_hash)));
}

void SignVerifyMessageDialog::updateP2MRVerifyModeUi()
{
    if (!isP2MRDataMode()) return;

    const int mode{ui->p2mrVerifyInputMode_VM->currentIndex()};
    const bool proof_only{mode == P2MR_VERIFY_INPUT_PROOF_ONLY};
    const bool hash_mode{mode == P2MR_VERIFY_INPUT_HASH};

    ui->p2mrVerifyDataLabel_VM->setVisible(!proof_only);
    ui->p2mrDataIn_VM->setVisible(!proof_only);
    ui->p2mrVerifyMessageHashLabel_VM->setVisible(!proof_only);
    ui->p2mrVerifyMessageHash_VM->setVisible(!proof_only);

    if (hash_mode) {
        ui->p2mrVerifyDataLabel_VM->setText(tr("Message hash"));
        ui->p2mrDataIn_VM->setToolTip(tr("Enter the 32-byte message hash as 64 hex characters"));
        ui->p2mrDataIn_VM->setPlaceholderText(tr("Enter the 32-byte message hash as 64 hex characters"));
    } else {
        ui->p2mrVerifyDataLabel_VM->setText(tr("Data"));
        ui->p2mrDataIn_VM->setToolTip(tr("Enter the signed UTF-8 text data to bind to the proof JSON"));
        ui->p2mrDataIn_VM->setPlaceholderText(tr("Enter the signed UTF-8 text data to bind to the proof JSON"));
    }
    updateP2MRVerifyHashPreview();
}

void SignVerifyMessageDialog::updateP2MRVerifyHashPreview()
{
    if (!isP2MRDataMode()) return;

    const int mode{ui->p2mrVerifyInputMode_VM->currentIndex()};
    if (mode == P2MR_VERIFY_INPUT_PROOF_ONLY) {
        ui->p2mrVerifyMessageHash_VM->clear();
        return;
    }

    uint256 message_hash;
    if (mode == P2MR_VERIFY_INPUT_HASH) {
        QString parse_error;
        if (!ParseDataHash(ui->p2mrDataIn_VM->document()->toPlainText(), message_hash, parse_error)) {
            ui->p2mrVerifyMessageHash_VM->clear();
            return;
        }
    } else {
        if (ui->p2mrDataIn_VM->document()->isEmpty()) {
            ui->p2mrVerifyMessageHash_VM->clear();
            return;
        }
        message_hash = HashP2MRUtf8Text(ui->p2mrDataIn_VM->document()->toPlainText());
    }

    ui->p2mrVerifyMessageHash_VM->setText(QString::fromStdString(HashToHexString(message_hash)));
}

void SignVerifyMessageDialog::setAddress_SM(const QString &address)
{
    ui->addressIn_SM->setText(address);
    ui->messageIn_SM->setFocus();
}

void SignVerifyMessageDialog::setAddress_VM(const QString &address)
{
    ui->addressIn_VM->setText(address);
    ui->messageIn_VM->setFocus();
}

void SignVerifyMessageDialog::showTab_SM(bool fShow)
{
    ui->tabWidget->setCurrentIndex(0);
    if (fShow)
        this->show();
}

void SignVerifyMessageDialog::showTab_VM(bool fShow)
{
    ui->tabWidget->setCurrentIndex(1);
    if (fShow)
        this->show();
}

void SignVerifyMessageDialog::on_addressBookButton_SM_clicked()
{
    if (model && model->getAddressTableModel())
    {
        model->refresh(/*pk_hash_only=*/!isP2MRDataMode());
        AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::ReceivingTab, this);
        dlg.setModel(model->getAddressTableModel());
        if (dlg.exec())
        {
            setAddress_SM(dlg.getReturnValue());
        }
    }
}

void SignVerifyMessageDialog::on_pasteButton_SM_clicked()
{
    setAddress_SM(QApplication::clipboard()->text());
}

void SignVerifyMessageDialog::on_signMessageButton_SM_clicked()
{
    if (!model)
        return;

    /* Clear old signature to ensure users don't get confused on error with an old signature displayed */
    ui->signatureOut_SM->clear();

    CTxDestination destination = DecodeDestination(ui->addressIn_SM->text().toStdString());
    if (!IsValidDestination(destination)) {
        ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_SM->setText(tr("The entered address is invalid.") + QString(" ") + tr("Please check the address and try again."));
        return;
    }

    if (isP2MRDataMode()) {
        if (!std::holds_alternative<WitnessV2P2MR>(destination)) {
            ui->addressIn_SM->setValid(false);
            ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_SM->setText(tr("The entered address is not a P2MR address. Please check the address and try again."));
            return;
        }

        uint256 message_hash;
        P2MRMessageHashMetadata metadata;
        if (ui->p2mrDataInputMode_SM->currentIndex() == P2MR_SIGN_INPUT_HASH) {
            QString parse_error;
            if (!ParseDataHash(ui->messageIn_SM->document()->toPlainText(), message_hash, parse_error)) {
                ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
                ui->statusLabel_SM->setText(parse_error);
                return;
            }
            metadata.source = P2MR_MESSAGE_HASH_SOURCE_HEX_HASH;
        } else {
            message_hash = HashP2MRUtf8Text(ui->messageIn_SM->document()->toPlainText());
            metadata.source = P2MR_MESSAGE_HASH_SOURCE_UTF8_TEXT;
            metadata.algorithm = P2MR_MESSAGE_HASH_ALGORITHM_SHA256;
        }
        ui->p2mrMessageHash_SM->setText(QString::fromStdString(HashToHexString(message_hash)));

        WalletModel::UnlockContext ctx(model->requestUnlock());
        if (!ctx.isValid())
        {
            ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_SM->setText(tr("Wallet unlock was cancelled."));
            return;
        }

        util::Result<interfaces::P2MRDataSignatureResult> result{model->wallet().signP2MRDataHash(destination, message_hash)};
        if (!result) {
            ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_SM->setText(BilingualToQString(util::ErrorString(result)));
            return;
        }

        const common::P2MRDataSignatureProof proof{MakeP2MRDataSignatureProof(*result)};
        const common::P2MRDataSignatureVerification verification{common::VerifyP2MRDataSignatureProof(proof)};
        if (!verification.valid) {
            ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_SM->setText(tr("Generated proof failed local verification: %1").arg(ToQString(verification.error)));
            return;
        }

        ui->signatureOut_SM->setPlainText(QString::fromStdString(BuildP2MRProofJson(*result, metadata).write(2)));
        QString status{metadata.algorithm.has_value() ?
            tr("P2MR/PQC data proof signed.") :
            tr("P2MR/PQC data-hash proof signed.")};
        const QString pqc_usage_status{result->pqc_usage ? FormatPQCUsageStatus(*result->pqc_usage) : QString{}};
        if (!pqc_usage_status.isEmpty()) {
            status.append("\n");
            status.append(pqc_usage_status);
        }
        ui->statusLabel_SM->setStyleSheet("QLabel { color: green; }");
        ui->statusLabel_SM->setText(status);
        return;
    }

    const PKHash* pkhash = std::get_if<PKHash>(&destination);
    if (!pkhash) {
        ui->addressIn_SM->setValid(false);
        ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_SM->setText(tr("The entered address does not refer to a legacy (P2PKH) key. Legacy message signing does not support this address type. Please check the address and try again."));
        return;
    }

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
    {
        ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_SM->setText(tr("Wallet unlock was cancelled."));
        return;
    }

    const std::string& message = ui->messageIn_SM->document()->toPlainText().toStdString();
    std::string signature;
    SigningResult res = model->wallet().signMessage(message, *pkhash, signature);

    QString error;
    switch (res) {
        case SigningResult::OK:
            error = tr("No error");
            break;
        case SigningResult::PRIVATE_KEY_NOT_AVAILABLE:
            error = tr("Private key for the entered address is not available.");
            break;
        case SigningResult::SIGNING_FAILED:
            error = tr("Message signing failed.");
            break;
        // no default case, so the compiler can warn about missing cases
    }

    if (res != SigningResult::OK) {
        ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_SM->setText(QString("<nobr>") + error + QString("</nobr>"));
        return;
    }

    ui->statusLabel_SM->setStyleSheet("QLabel { color: green; }");
    ui->statusLabel_SM->setText(QString("<nobr>") + tr("Message signed.") + QString("</nobr>"));

    ui->signatureOut_SM->setPlainText(QString::fromStdString(signature));
}

void SignVerifyMessageDialog::on_copySignatureButton_SM_clicked()
{
    GUIUtil::setClipboard(ui->signatureOut_SM->toPlainText());
}

void SignVerifyMessageDialog::on_clearButton_SM_clicked()
{
    ui->addressIn_SM->clear();
    ui->messageIn_SM->clear();
    ui->signatureOut_SM->clear();
    ui->statusLabel_SM->clear();
    ui->p2mrMessageHash_SM->clear();

    ui->addressIn_SM->setFocus();
}

void SignVerifyMessageDialog::on_addressBookButton_VM_clicked()
{
    if (model && model->getAddressTableModel())
    {
        AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::SendingTab, this);
        dlg.setModel(model->getAddressTableModel());
        if (dlg.exec())
        {
            setAddress_VM(dlg.getReturnValue());
        }
    }
}

void SignVerifyMessageDialog::on_verifyMessageButton_VM_clicked()
{
    if (isP2MRDataMode()) {
        common::P2MRDataSignatureProof proof;
        QString parse_error;
        if (!ParseP2MRProofJson(ui->messageIn_VM->document()->toPlainText(), proof, parse_error)) {
            ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_VM->setText(parse_error);
            return;
        }

        std::optional<uint256> expected_message_hash;
        const int verify_mode{ui->p2mrVerifyInputMode_VM->currentIndex()};
        if (verify_mode == P2MR_VERIFY_INPUT_HASH) {
            uint256 parsed_hash;
            if (!ParseDataHash(ui->p2mrDataIn_VM->document()->toPlainText(), parsed_hash, parse_error)) {
                ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
                ui->statusLabel_VM->setText(parse_error);
                return;
            }
            expected_message_hash = parsed_hash;
        } else if (verify_mode == P2MR_VERIFY_INPUT_TEXT) {
            expected_message_hash = HashP2MRUtf8Text(ui->p2mrDataIn_VM->document()->toPlainText());
        }

        if (expected_message_hash.has_value() && *expected_message_hash != proof.message_hash) {
            ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_VM->setText(
                tr("Entered data hashes to %1, but the proof signed %2.")
                    .arg(QString::fromStdString(HashToHexString(*expected_message_hash)))
                    .arg(QString::fromStdString(HashToHexString(proof.message_hash)))
            );
            return;
        }

        const common::P2MRDataSignatureVerification result{common::VerifyP2MRDataSignatureProof(proof)};
        if (result.valid) {
            ui->statusLabel_VM->setStyleSheet("QLabel { color: green; }");
            QString status{tr("P2MR/PQC proof verified for %1.")
                .arg(QString::fromStdString(EncodeDestination(CTxDestination{proof.output})))};
            if (expected_message_hash.has_value()) {
                status.append("\n");
                status.append(tr("Entered data matches message hash %1.")
                    .arg(QString::fromStdString(HashToHexString(*expected_message_hash))));
            }
            ui->statusLabel_VM->setText(status);
        } else {
            ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_VM->setText(tr("P2MR/PQC proof verification failed: %1").arg(ToQString(result.error)));
        }
        return;
    }

    const std::string& address = ui->addressIn_VM->text().toStdString();
    const std::string& signature = ui->signatureIn_VM->text().toStdString();
    const std::string& message = ui->messageIn_VM->document()->toPlainText().toStdString();

    const auto result = MessageVerify(address, signature, message);

    if (result == MessageVerificationResult::OK) {
        ui->statusLabel_VM->setStyleSheet("QLabel { color: green; }");
    } else {
        ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
    }

    switch (result) {
    case MessageVerificationResult::OK:
        ui->statusLabel_VM->setText(
            QString("<nobr>") + tr("Message verified.") + QString("</nobr>")
        );
        return;
    case MessageVerificationResult::ERR_INVALID_ADDRESS:
        ui->statusLabel_VM->setText(
            tr("The entered address is invalid.") + QString(" ") +
            tr("Please check the address and try again.")
        );
        return;
    case MessageVerificationResult::ERR_ADDRESS_NO_KEY:
        ui->addressIn_VM->setValid(false);
        ui->statusLabel_VM->setText(tr("The entered address does not refer to a legacy (P2PKH) key. Legacy message verification does not support this address type. Please check the address and try again."));
        return;
    case MessageVerificationResult::ERR_MALFORMED_SIGNATURE:
        ui->signatureIn_VM->setValid(false);
        ui->statusLabel_VM->setText(
            tr("The signature could not be decoded.") + QString(" ") +
            tr("Please check the signature and try again.")
        );
        return;
    case MessageVerificationResult::ERR_PUBKEY_NOT_RECOVERED:
        ui->signatureIn_VM->setValid(false);
        ui->statusLabel_VM->setText(
            tr("The signature did not match the message digest.") + QString(" ") +
            tr("Please check the signature and try again.")
        );
        return;
    case MessageVerificationResult::ERR_NOT_SIGNED:
        ui->statusLabel_VM->setText(
            QString("<nobr>") + tr("Message verification failed.") + QString("</nobr>")
        );
        return;
    }
}

void SignVerifyMessageDialog::on_clearButton_VM_clicked()
{
    ui->addressIn_VM->clear();
    ui->signatureIn_VM->clear();
    ui->messageIn_VM->clear();
    ui->p2mrDataIn_VM->clear();
    ui->p2mrVerifyMessageHash_VM->clear();
    ui->statusLabel_VM->clear();

    if (isP2MRDataMode()) {
        ui->messageIn_VM->setFocus();
    } else {
        ui->addressIn_VM->setFocus();
    }
}

bool SignVerifyMessageDialog::eventFilter(QObject *object, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonPress || event->type() == QEvent::FocusIn)
    {
        if (ui->tabWidget->currentIndex() == 0)
        {
            /* Clear status message on focus change */
            ui->statusLabel_SM->clear();

            /* Select generated signature */
            if (object == ui->signatureOut_SM)
            {
                ui->signatureOut_SM->selectAll();
                return true;
            }
        }
        else if (ui->tabWidget->currentIndex() == 1)
        {
            /* Clear status message on focus change */
            ui->statusLabel_VM->clear();
        }
    }
    return QDialog::eventFilter(object, event);
}

void SignVerifyMessageDialog::changeEvent(QEvent* e)
{
    if (e->type() == QEvent::PaletteChange) {
        ui->addressBookButton_SM->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/address-book")));
        ui->pasteButton_SM->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/editpaste")));
        ui->copySignatureButton_SM->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/editcopy")));
        ui->signMessageButton_SM->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/edit")));
        ui->clearButton_SM->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/remove")));
        ui->addressBookButton_VM->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/address-book")));
        ui->verifyMessageButton_VM->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/transaction_0")));
        ui->clearButton_VM->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/remove")));
    }

    QDialog::changeEvent(e);
}
