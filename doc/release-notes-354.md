Quitting the GUI while a dialog is open no longer crashes it
============================================================

`qbit-qt` could crash, or use freed memory, when it was asked to quit while a
dialog was waiting for an answer. Examples are the send confirmation, the
"PSBT copied" box, the warning shown after a send, and the passphrase prompt.
The quit could come from the platform (on macOS: Dock > Quit, logout, or a
Quit Apple event), or from File > Exit pressed through accessibility tools
behind the dialog. Shutdown then deleted the wallet views while the dialog's
code was still running.

A quit from the platform or from File > Exit now waits until the user has
answered every message box or dialog whose code is still waiting for that
answer, and the GUI shuts down right after that. The same rule applies when
the node unloads a wallet, for example after `unloadwallet`, while such a
dialog is open. This holds even when a progress dialog covers that dialog.

- Nothing is sent or signed because of the quit. Cancelling the dialog
  cancels the operation, as before.
- Dialogs that stay open without holding up the code that opened them, such
  as the PSBT dialog, Coin Control, the options dialog and progress dialogs,
  do not delay a platform or menu quit. Shutdown still cancels transaction
  preparation and fee bumps that can be cancelled, and waits for those that
  cannot.
- Wallet encryption and PSBT signing cannot be cancelled once they have
  started. A platform or menu quit during either starts the shutdown at once,
  and the shutdown waits for the work to finish. The "Wallet encrypted" box
  is not shown then. A PSBT signed this way is saved to the data directory,
  as described in the release note for #344.
- While a quit waits, the GUI shows its main window and brings the dialog
  it waits for to the front.
- A second quit request while one is waiting, or while the node is shutting
  down, is ignored. Before, a second Quit from the platform requested the
  node shutdown again.
- A platform quit made while the first-run data directory dialog is open
  is carried out once that dialog has closed and startup has created the
  main window. Before, it crashed `qbit-qt`.
- On macOS, a logout started while such a dialog is open is cancelled, as
  before, and `qbit-qt` now quits once the dialog is closed. On Windows,
  logging off already waited for open dialogs.
- RPC `stop` and SIGTERM keep their old rule, as in Bitcoin Core: the GUI
  shuts down only while no modal dialog is open, including progress dialogs
  and dialogs such as the PSBT dialog. Close open dialogs before stopping an
  unattended GUI node.
- Most context menus, such as those of the address book and the peers
  table, hold a quit until they close. RPC `stop` and SIGTERM now also wait
  for them.
- A wallet's rescan progress dialog no longer stays open after the wallet is
  unloaded. Before, it kept RPC `stop` and SIGTERM from shutting the GUI down
  until the user cancelled it.
