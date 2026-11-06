Quitting the GUI while a dialog is open no longer crashes it
============================================================

`qbit-qt` could crash, or use freed memory, when it was asked to quit while a
dialog was waiting for an answer. Examples are the send confirmation, the
"PSBT copied" box, the warning shown after a send, and the passphrase prompt.
The quit could come from the platform (on macOS: Dock > Quit, logout, or a
Quit Apple event), or from File > Exit pressed through accessibility tools
behind the dialog. Shutdown then deleted the wallet views while the dialog's
code was still running.

A quit request now waits until the user has closed every dialog that needs an
answer, and the GUI shuts down right after that. The same rule applies when
the node unloads a wallet, for example after `unloadwallet`, while a dialog
is open. This holds even when a progress dialog covers that dialog.

- Nothing is sent or signed because of the quit. Cancelling the dialog
  cancels the operation, as before.
- Wallet encryption and PSBT signing cannot be cancelled once they have
  started. The GUI waits for them, shows their result, and then shuts down.
- Progress dialogs alone do not delay a quit. Shutdown still cancels
  transaction preparation and fee bumps that can be cancelled, and waits for
  those that cannot.
- While a quit waits, the GUI shows its main window and brings the dialog
  it waits for to the front.
- On macOS, a logout started while such a dialog is open is cancelled, as
  before, and `qbit-qt` now quits once the dialog is closed. On Windows,
  logging off already waited for open dialogs.
- RPC `stop` and SIGTERM, which already waited for open dialogs, now also
  wait while a context menu is open.
- A wallet's rescan progress dialog no longer stays open after the wallet is
  unloaded. Before, it kept RPC `stop` and SIGTERM from shutting the GUI down
  until the user cancelled it.
- A second quit request while the node is shutting down is now ignored, for
  example a second Quit from the platform. Before, it requested the node
  shutdown again.
