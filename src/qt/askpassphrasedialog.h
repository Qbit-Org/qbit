// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_ASKPASSPHRASEDIALOG_H
#define QBIT_QT_ASKPASSPHRASEDIALOG_H

#include <QDialog>
#include <QPointer>

#include <support/allocators/secure.h>

class WalletModel;

namespace Ui {
    class AskPassphraseDialog;
}

/** Multifunctional dialog to ask for passphrases. Used for encryption, unlocking, and changing the passphrase.
 */
class AskPassphraseDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        Encrypt,    /**< Ask passphrase twice and encrypt */
        Unlock,     /**< Ask passphrase and unlock */
        ChangePass, /**< Ask old passphrase + new passphrase twice */
        UnlockMigration, /**< Ask passphrase for unlocking during migration */
    };

    explicit AskPassphraseDialog(Mode mode, QWidget *parent, SecureString* passphrase_out = nullptr);
    ~AskPassphraseDialog();

    void accept() override;
    //! Ignored while an encryption is running: the dialog is the in-progress
    //! indicator and the operation cannot be cancelled.
    void reject() override;

    void setModel(WalletModel *model);

private:
    Ui::AskPassphraseDialog *ui;
    Mode mode;
    QPointer<WalletModel> model;
    bool fCapsLock{false};
    SecureString* m_passphrase_out;
    bool m_encryption_in_progress{false};

    void showEncryptionInProgress();
    void showEncryptionResult(bool success);

private Q_SLOTS:
    void textChanged();
    void secureClearPassFields();
    void toggleShowPassword(bool);
    void encryptWalletFinished(bool success);

protected:
    bool event(QEvent *event) override;
    bool eventFilter(QObject *object, QEvent *event) override;
};

#endif // QBIT_QT_ASKPASSPHRASEDIALOG_H
