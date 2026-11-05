GUI responsiveness during wallet encryption started outside the GUI
=================================================================

Encrypting a wallet with the `encryptwallet` RPC (for example from
`qbit-cli` or the GUI's console) while `qbit-qt` has the wallet open stalled
the GUI until the encryption finished. Encryption generates new keys while it
holds the wallet locks, which can take minutes with a large `-keypool`. During
that time, status bar updates, the overview page, the transaction list and
the receive page waited for those locks, so the window stopped repainting and
responding. Encryption started from the GUI's Encrypt Wallet dialog was not
affected.

The wallet now announces when an encryption starts and finishes, whoever
started it. While an encryption runs, the GUI handles it the same way it
handles encryption from the dialog:

- The window keeps repainting and responding.
- The encryption status, the PQC key validation status and address labels are
  shown as they were before the encryption.
- New transactions, keypool changes and status changes are applied once the
  encryption has finished.
- Unlocking, sending, signing and fee bumping are refused with a "Wallet
  encryption in progress" message.

When the encryption finishes, whether it succeeds or fails, the GUI reads the
wallet again and shows it as encrypted and locked, or as it was before.

Known limitation: these GUI actions still need the wallet and wait for an
encryption started outside the GUI to finish, as in v1.0.0. The window does
not respond until it does.

- Creating a new receiving address, and adding, editing or deleting an
  address book entry
- Opening the coin control dialog, or changing the amounts on the Send page
  while coins are selected in coin control
- Opening the details of a transaction, or its context menu in the
  transaction list
- Loading a PSBT
- Backing up the wallet
- Closing the wallet
