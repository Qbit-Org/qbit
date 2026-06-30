// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <interfaces/node.h>
#include <qt/createwalletdialog.h>
#include <qt/forms/ui_createwalletdialog.h>

#include <qt/guiutil.h>

#include <QPushButton>

CreateWalletDialog::CreateWalletDialog(QWidget* parent) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::CreateWalletDialog)
{
    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Create"));
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    ui->wallet_name_line_edit->setFocus(Qt::ActiveWindowFocusReason);

    connect(ui->wallet_name_line_edit, &QLineEdit::textEdited, [this](const QString& text) {
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(!text.isEmpty());
    });

    const auto update_encrypt_wallet_options = [this](bool checked) {
        // Disable the disable_privkeys_checkbox and external_signer_checkbox when isEncryptWalletChecked is
        // set to true, enable it when isEncryptWalletChecked is false.
        ui->disable_privkeys_checkbox->setEnabled(!checked);
#ifdef ENABLE_EXTERNAL_SIGNER
        ui->external_signer_checkbox->setEnabled(m_has_signers && !checked);
#endif
        // When the disable_privkeys_checkbox is disabled, uncheck it.
        if (!ui->disable_privkeys_checkbox->isEnabled()) {
            ui->disable_privkeys_checkbox->setChecked(false);
        }

        // When the external_signer_checkbox box is disabled, uncheck it.
        if (!ui->external_signer_checkbox->isEnabled()) {
            ui->external_signer_checkbox->setChecked(false);
        }

    };
    connect(ui->encrypt_wallet_checkbox, &QCheckBox::toggled, update_encrypt_wallet_options);

    connect(ui->external_signer_checkbox, &QCheckBox::toggled, [this](bool checked) {
        // The external signer checkbox is only enabled when a device is detected.
        // Toggling it restores the normal wallet defaults, including recommended
        // encryption when external signing is disabled.
        ui->encrypt_wallet_checkbox->setChecked(!checked);
        ui->disable_privkeys_checkbox->setChecked(checked);
        ui->blank_wallet_checkbox->setChecked(false);

        ui->encrypt_wallet_checkbox->setEnabled(!checked);
        ui->blank_wallet_checkbox->setEnabled(!checked);
        ui->disable_privkeys_checkbox->setEnabled(!checked && !ui->encrypt_wallet_checkbox->isChecked());
    });

    connect(ui->disable_privkeys_checkbox, &QCheckBox::toggled, [this](bool checked) {
        // Disable the encrypt_wallet_checkbox when isDisablePrivateKeysChecked is
        // set to true, enable it when isDisablePrivateKeysChecked is false.
        ui->encrypt_wallet_checkbox->setEnabled(!checked);

        // Wallets without private keys cannot set blank
        ui->blank_wallet_checkbox->setEnabled(!checked);
        if (checked) {
            ui->blank_wallet_checkbox->setChecked(false);
        }

        // When the encrypt_wallet_checkbox is disabled, uncheck it.
        if (!ui->encrypt_wallet_checkbox->isEnabled()) {
            ui->encrypt_wallet_checkbox->setChecked(false);
        }
    });

    connect(ui->blank_wallet_checkbox, &QCheckBox::toggled, [this](bool checked) {
        // Disable the disable_privkeys_checkbox when blank_wallet_checkbox is checked
        // as blank-ness only pertains to wallets with private keys. Keep it
        // disabled while wallet encryption is selected as well.
        ui->disable_privkeys_checkbox->setEnabled(!checked && !ui->encrypt_wallet_checkbox->isChecked());
        if (!ui->disable_privkeys_checkbox->isEnabled()) {
            ui->disable_privkeys_checkbox->setChecked(false);
        }
    });

#ifndef ENABLE_EXTERNAL_SIGNER
        //: "External signing" means using devices such as hardware wallets.
        ui->external_signer_checkbox->setToolTip(tr("Compiled without external signing support (required for external signing)"));
        ui->external_signer_checkbox->setEnabled(false);
        ui->external_signer_checkbox->setChecked(false);
#endif

    update_encrypt_wallet_options(ui->encrypt_wallet_checkbox->isChecked());
}

CreateWalletDialog::~CreateWalletDialog()
{
    delete ui;
}

void CreateWalletDialog::setSigners(const std::vector<std::unique_ptr<interfaces::ExternalSigner>>& signers)
{
    m_has_signers = !signers.empty();
    if (m_has_signers) {
        ui->external_signer_checkbox->setEnabled(true);
        ui->external_signer_checkbox->setChecked(true);
        ui->encrypt_wallet_checkbox->setEnabled(false);
        ui->encrypt_wallet_checkbox->setChecked(false);
        // The order matters, because connect() is called when toggling a checkbox:
        ui->blank_wallet_checkbox->setEnabled(false);
        ui->blank_wallet_checkbox->setChecked(false);
        ui->disable_privkeys_checkbox->setEnabled(false);
        ui->disable_privkeys_checkbox->setChecked(true);
        const std::string label = signers[0]->getName();
        ui->wallet_name_line_edit->setText(QString::fromStdString(label));
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
    } else {
        ui->external_signer_checkbox->setEnabled(false);
    }
}

QString CreateWalletDialog::walletName() const
{
    return ui->wallet_name_line_edit->text();
}

bool CreateWalletDialog::isEncryptWalletChecked() const
{
    return ui->encrypt_wallet_checkbox->isChecked();
}

bool CreateWalletDialog::isDisablePrivateKeysChecked() const
{
    return ui->disable_privkeys_checkbox->isChecked();
}

bool CreateWalletDialog::isMakeBlankWalletChecked() const
{
    return ui->blank_wallet_checkbox->isChecked();
}

bool CreateWalletDialog::isExternalSignerChecked() const
{
    return ui->external_signer_checkbox->isChecked();
}
