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
#include <script/p2mr_sizing.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/pqc_usage.h>
#include <wallet/wallet.h>

#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <QByteArray>
#include <QClipboard>
#include <QComboBox>
#include <QPlainTextEdit>
#include <QStringList>
#include <QTextDocument>

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

constexpr size_t P2MR_PROOF_MAX_ADDRESS_CHARS{64};
constexpr size_t P2MR_PROOF_REQUIRED_HEX_CHARS{
    2 * (uint256::size() + PQC_PUBKEY_SIZE + PQC_SIG_SIZE + P2MR_V1_PK_LEAF_SCRIPT_SIZE + P2MR_CONTROL_MAX_SIZE)};
static_assert(P2MR_PROOF_REQUIRED_HEX_CHARS == 15'750);

// The portable proof has eight fields. At their protocol maxima, the address,
// fixed-size hex fields, proof mode, and decimal leaf version use 15,828 value
// characters. UniValue::write(2) adds exactly 160 JSON syntax characters.
// Keeping the input limit at the next power of two leaves room for compatible
// legacy/RPC informational fields while strictly bounding GUI-thread work.
constexpr size_t P2MR_PROOF_MODE_CHARS{std::string_view{common::P2MR_DATA_SIGNATURE_PROOF_MODE}.size()};
constexpr size_t P2MR_MAX_LEAF_VERSION_CHARS{3};
constexpr size_t P2MR_MAX_GENERATED_PROOF_VALUE_CHARS{
    P2MR_PROOF_MAX_ADDRESS_CHARS + P2MR_PROOF_REQUIRED_HEX_CHARS + P2MR_PROOF_MODE_CHARS + P2MR_MAX_LEAF_VERSION_CHARS};
constexpr size_t P2MR_GENERATED_PROOF_JSON_SYNTAX_CHARS{160};
constexpr size_t P2MR_MAX_GENERATED_PROOF_JSON_CHARS{
    P2MR_MAX_GENERATED_PROOF_VALUE_CHARS + P2MR_GENERATED_PROOF_JSON_SYNTAX_CHARS};
static_assert(P2MR_MAX_GENERATED_PROOF_VALUE_CHARS == 15'828);
static_assert(P2MR_MAX_GENERATED_PROOF_JSON_CHARS == 15'988);
static_assert(SignVerifyMessageDialog::MAX_P2MR_PROOF_DOCUMENT_CHARS == 32'768);
static_assert(SignVerifyMessageDialog::MAX_P2MR_PROOF_DOCUMENT_CHARS >= P2MR_MAX_GENERATED_PROOF_JSON_CHARS);

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
    const QString trimmed{text.trimmed()};
    if (static_cast<size_t>(trimmed.size()) != expected_size * 2) {
        error = SignVerifyMessageDialog::tr("%1 must be exactly %2 bytes.").arg(QString::fromStdString(std::string{name})).arg(expected_size);
        return false;
    }

    const QByteArray value{trimmed.toLatin1()};
    const std::string_view value_view{value.constData(), static_cast<size_t>(value.size())};
    if (!IsHex(value_view)) {
        error = SignVerifyMessageDialog::tr("%1 must be hex.").arg(QString::fromStdString(std::string{name}));
        return false;
    }
    bytes = ParseHex(value_view);
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

const std::string* GetRequiredString(const UniValue& object, const char* name, QString& error)
{
    const UniValue& field{object.find_value(name)};
    if (!field.isStr()) {
        error = SignVerifyMessageDialog::tr("Proof field \"%1\" must be a string.").arg(name);
        return nullptr;
    }
    return &field.get_str();
}

bool RejectDuplicateProofFields(const UniValue& object, QString& error)
{
    std::set<std::string_view> fields;
    for (const std::string& key : object.getKeys()) {
        if (!fields.insert(key).second) {
            error = SignVerifyMessageDialog::tr("Proof field \"%1\" is duplicated.").arg(QString::fromStdString(key));
            return false;
        }
    }
    return true;
}

bool ParseExactProofHex(const UniValue& object, const char* name, size_t expected_size, std::vector<unsigned char>& bytes, QString& error)
{
    const std::string* text{GetRequiredString(object, name, error)};
    if (!text) return false;
    if (text->size() != expected_size * 2) {
        error = SignVerifyMessageDialog::tr("%1 must be exactly %2 bytes.").arg(name).arg(expected_size);
        return false;
    }
    if (!IsHex(*text)) {
        error = SignVerifyMessageDialog::tr("Proof field \"%1\" must be hex.").arg(name);
        return false;
    }
    bytes = ParseHex(*text);
    return true;
}

bool ParseControlBlock(const UniValue& object, std::vector<unsigned char>& control_block, QString& error)
{
    const std::string* text{GetRequiredString(object, "control_block", error)};
    if (!text) return false;

    constexpr size_t MIN_HEX_CHARS{P2MR_CONTROL_BASE_SIZE * 2};
    constexpr size_t MAX_HEX_CHARS{P2MR_CONTROL_MAX_SIZE * 2};
    constexpr size_t NODE_HEX_CHARS{P2MR_CONTROL_NODE_SIZE * 2};
    if (text->size() < MIN_HEX_CHARS || text->size() > MAX_HEX_CHARS ||
        (text->size() - MIN_HEX_CHARS) % NODE_HEX_CHARS != 0) {
        error = SignVerifyMessageDialog::tr("Proof field \"control_block\" must be 1 + 32*n bytes for n from 0 to 128.");
        return false;
    }
    if (!IsHex(*text)) {
        error = SignVerifyMessageDialog::tr("Proof field \"control_block\" must be hex.");
        return false;
    }
    control_block = ParseHex(*text);
    return true;
}

bool ParseP2MRProofJson(const QString& proof_json, common::P2MRDataSignatureProof& proof, QString& error)
{
    const QByteArray proof_utf8{proof_json.toUtf8()};
    UniValue object;
    if (!object.read(std::string_view{proof_utf8.constData(), static_cast<size_t>(proof_utf8.size())}) || !object.isObject()) {
        error = SignVerifyMessageDialog::tr("Proof must be a JSON object.");
        return false;
    }
    if (!RejectDuplicateProofFields(object, error)) return false;

    const std::string* proof_mode{GetRequiredString(object, "proof_mode", error)};
    if (!proof_mode) return false;
    if (*proof_mode != common::P2MR_DATA_SIGNATURE_PROOF_MODE) {
        error = SignVerifyMessageDialog::tr("Unsupported proof_mode.");
        return false;
    }

    const std::string* address{GetRequiredString(object, "address", error)};
    if (!address) return false;
    if (address->size() > P2MR_PROOF_MAX_ADDRESS_CHARS) {
        error = SignVerifyMessageDialog::tr("Proof address is too long.");
        return false;
    }
    const CTxDestination dest{DecodeDestination(*address)};
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
    if (!ParseExactProofHex(object, "message_hash", uint256::size(), bytes, error)) return false;
    proof.message_hash = uint256{std::span<const unsigned char>{bytes.data(), bytes.size()}};
    proof.datasig_hash = ComputeQbitDataSigPQCHash(
        std::span<const unsigned char>{proof.message_hash.begin(), proof.message_hash.end()});

    if (!ParseExactProofHex(object, "pubkey", PQC_PUBKEY_SIZE, bytes, error)) return false;
    proof.pubkey = CPQCPubKey{bytes};

    if (!ParseExactProofHex(object, "signature", PQC_SIG_SIZE, proof.signature, error)) return false;

    if (!ParseExactProofHex(object, "leaf_script", P2MR_V1_PK_LEAF_SCRIPT_SIZE, bytes, error)) return false;
    proof.leaf_script = CScript{bytes.begin(), bytes.end()};

    if (!ParseControlBlock(object, proof.control_block, error)) return false;

    const UniValue& leaf_version{object.find_value("leaf_version")};
    if (!leaf_version.isNum()) {
        error = SignVerifyMessageDialog::tr("Proof field \"leaf_version\" must be an integer from 0 to 255.");
        return false;
    }
    const auto leaf_version_int{ToIntegral<uint8_t>(leaf_version.getValStr())};
    if (!leaf_version_int.has_value()) {
        error = SignVerifyMessageDialog::tr("Proof field \"leaf_version\" must be an integer from 0 to 255.");
        return false;
    }
    proof.leaf_version = *leaf_version_int;
    return true;
}

bool ParseExpectedP2MRSigner(const QString& address_text, std::optional<WitnessV2P2MR>& expected_signer, QString& error)
{
    expected_signer.reset();
    const QString trimmed_address{address_text.trimmed()};
    if (trimmed_address.isEmpty()) return true;

    const CTxDestination destination{DecodeDestination(trimmed_address.toStdString())};
    if (!IsValidDestination(destination)) {
        error = SignVerifyMessageDialog::tr("The expected signer address is invalid for the active network.");
        return false;
    }

    const auto* output{std::get_if<WitnessV2P2MR>(&destination)};
    if (!output) {
        error = SignVerifyMessageDialog::tr("The expected signer address is not a P2MR address.");
        return false;
    }

    expected_signer = *output;
    return true;
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

// Keep the portable proof limited to fields consumed by both Qt and RPC
// verification. Wallet-local usage belongs in the signer status only.
UniValue BuildP2MRProofJson(const common::P2MRDataSignatureProof& proof)
{
    UniValue object(UniValue::VOBJ);
    object.pushKV("address", EncodeDestination(CTxDestination{proof.output}));
    object.pushKV("message_hash", HashToHexString(proof.message_hash));
    object.pushKV("proof_mode", common::P2MR_DATA_SIGNATURE_PROOF_MODE);
    object.pushKV("pubkey", HexStr(std::span<const unsigned char>{proof.pubkey.begin(), proof.pubkey.end()}));
    object.pushKV("signature", HexStr(proof.signature));
    object.pushKV("leaf_version", static_cast<int>(proof.leaf_version));
    object.pushKV("leaf_script", HexStr(proof.leaf_script));
    object.pushKV("control_block", HexStr(proof.control_block));
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
        clearVerifyStatus();
        updateP2MRVerifyModeUi();
    });
    connect(ui->p2mrDataIn_VM, &QPlainTextEdit::textChanged, this, &SignVerifyMessageDialog::updateP2MRVerifyHashPreview);
    connect(ui->addressIn_VM, &QLineEdit::textChanged, this, &SignVerifyMessageDialog::clearVerifyStatus);
    connect(ui->messageIn_VM, &QPlainTextEdit::textChanged, this, &SignVerifyMessageDialog::clearVerifyStatus);
    connect(ui->signatureIn_VM, &QLineEdit::textChanged, this, &SignVerifyMessageDialog::clearVerifyStatus);
    connect(ui->p2mrDataIn_VM, &QPlainTextEdit::textChanged, this, &SignVerifyMessageDialog::clearVerifyStatus);

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

        ui->infoLabel_VM->setText(tr("Enter an expected signer address from a trusted source to authenticate a P2MR/PQC "
                                     "proof. Entered text or a 32-byte hash must also match the proof's message_hash. "
                                     "Without an expected signer, or in proof-only mode, verification reports only "
                                     "cryptographic validity with a neutral result."));
        ui->expectedSignerLabel_VM->setVisible(true);
        ui->addressIn_VM->setVisible(true);
        ui->addressIn_VM->setToolTip(tr("The expected P2MR signer address from a trusted source; leave blank for neutral proof validation"));
        ui->addressBookButton_VM->setVisible(true);
        ui->addressBookButton_VM->setToolTip(tr("Choose an expected signer address"));
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
        ui->expectedSignerLabel_VM->setVisible(false);
        ui->addressIn_VM->setVisible(true);
        ui->addressIn_VM->setToolTip(tr("The qbit address the message was signed with"));
        ui->addressBookButton_VM->setVisible(true);
        ui->addressBookButton_VM->setToolTip(tr("Choose previously used address"));
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
        message_hash = HashP2MRUtf8Text(ui->p2mrDataIn_VM->document()->toPlainText());
    }

    ui->p2mrVerifyMessageHash_VM->setText(QString::fromStdString(HashToHexString(message_hash)));
}

void SignVerifyMessageDialog::clearVerifyStatus()
{
    ui->statusLabel_VM->clear();
    ui->statusLabel_VM->setStyleSheet({});
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
        const bool hash_input{ui->p2mrDataInputMode_SM->currentIndex() == P2MR_SIGN_INPUT_HASH};
        if (hash_input) {
            QString parse_error;
            if (!ParseDataHash(ui->messageIn_SM->document()->toPlainText(), message_hash, parse_error)) {
                ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
                ui->statusLabel_SM->setText(parse_error);
                return;
            }
        } else {
            message_hash = HashP2MRUtf8Text(ui->messageIn_SM->document()->toPlainText());
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

        ui->signatureOut_SM->setPlainText(QString::fromStdString(BuildP2MRProofJson(proof).write(2)));
        QString status{hash_input ?
            tr("P2MR/PQC data-hash proof signed.") :
            tr("P2MR/PQC data proof signed.")};
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
    clearVerifyStatus();

    if (isP2MRDataMode()) {
        const auto set_error = [this](const QString& text) {
            ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_VM->setText(text);
        };
        const auto set_neutral = [this](const QString& text) {
            ui->statusLabel_VM->setStyleSheet("");
            ui->statusLabel_VM->setText(text);
        };
        const auto set_authenticated = [this](const QString& text) {
            ui->statusLabel_VM->setStyleSheet("QLabel { color: green; }");
            ui->statusLabel_VM->setText(text);
        };

        const int proof_character_count{ui->messageIn_VM->document()->characterCount() - 1};
        if (proof_character_count > MAX_P2MR_PROOF_DOCUMENT_CHARS) {
            set_error(tr("Proof JSON exceeds the maximum size of %1 characters.").arg(MAX_P2MR_PROOF_DOCUMENT_CHARS));
            return;
        }

        common::P2MRDataSignatureProof proof;
        QString parse_error;
        if (!ParseP2MRProofJson(ui->messageIn_VM->document()->toPlainText(), proof, parse_error)) {
            set_error(parse_error);
            return;
        }

        const QString embedded_signer{QString::fromStdString(EncodeDestination(CTxDestination{proof.output}))};
        const QString signed_message_hash{QString::fromStdString(HashToHexString(proof.message_hash))};
        const auto proof_context = [&] {
            return QStringList{
                tr("Proof-supplied signer: %1.").arg(embedded_signer),
                tr("Signed message hash: %1.").arg(signed_message_hash),
            };
        };

        std::optional<WitnessV2P2MR> expected_signer;
        if (!ParseExpectedP2MRSigner(ui->addressIn_VM->text(), expected_signer, parse_error)) {
            ui->addressIn_VM->setValid(false);
            QStringList status{parse_error};
            status.append(proof_context());
            set_error(status.join("\n"));
            return;
        }

        std::optional<uint256> expected_message_hash;
        const int verify_mode{ui->p2mrVerifyInputMode_VM->currentIndex()};
        if (verify_mode == P2MR_VERIFY_INPUT_HASH) {
            uint256 parsed_hash;
            if (!ParseDataHash(ui->p2mrDataIn_VM->document()->toPlainText(), parsed_hash, parse_error)) {
                QStringList status{parse_error};
                status.append(proof_context());
                set_error(status.join("\n"));
                return;
            }
            expected_message_hash = parsed_hash;
        } else if (verify_mode == P2MR_VERIFY_INPUT_TEXT) {
            expected_message_hash = HashP2MRUtf8Text(ui->p2mrDataIn_VM->document()->toPlainText());
        }

        if (expected_signer.has_value() && *expected_signer != proof.output) {
            const QString expected_address{QString::fromStdString(EncodeDestination(CTxDestination{*expected_signer}))};
            QStringList status{
                tr("The proof contains signer %1, but the expected signer is %2.").arg(embedded_signer, expected_address),
                tr("Signed message hash: %1.").arg(signed_message_hash),
            };
            set_error(status.join("\n"));
            return;
        }

        if (expected_message_hash.has_value() && *expected_message_hash != proof.message_hash) {
            QStringList status{
                tr("Entered data hashes to %1, but the proof contains message hash %2.")
                    .arg(QString::fromStdString(HashToHexString(*expected_message_hash)), signed_message_hash),
                tr("Proof-supplied signer: %1.").arg(embedded_signer),
            };
            set_error(status.join("\n"));
            return;
        }

        const common::P2MRDataSignatureVerification result{common::VerifyP2MRDataSignatureProof(proof)};
        if (result.valid) {
            const bool identity_bound{expected_signer.has_value()};
            const bool data_bound{expected_message_hash.has_value()};
            QStringList status{
                identity_bound && data_bound ?
                    tr("P2MR/PQC proof authenticated for the expected signer.") :
                    tr("P2MR/PQC proof is cryptographically valid."),
                tr("Embedded signer: %1.").arg(embedded_signer),
                tr("Signed message hash: %1.").arg(signed_message_hash),
            };
            if (identity_bound) {
                status.append(tr("Expected signer matches the embedded signer."));
            } else {
                status.append(tr("No expected signer was provided; signer identity was not independently authenticated."));
            }
            if (expected_message_hash.has_value()) {
                status.append(tr("Entered data matches the signed message hash."));
            } else {
                status.append(tr("Proof-only mode did not independently bind the signed data."));
            }
            if (identity_bound && data_bound) {
                set_authenticated(status.join("\n"));
            } else {
                set_neutral(status.join("\n"));
            }
        } else {
            QStringList status{
                tr("P2MR/PQC proof verification failed: %1").arg(ToQString(result.error)),
            };
            status.append(proof_context());
            set_error(status.join("\n"));
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
    clearVerifyStatus();

    ui->addressIn_VM->setFocus();
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
            clearVerifyStatus();
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
