Listing wallets no longer releases the lock on loaded wallets
=============================================================

On Linux, macOS and other POSIX systems, `listwalletdir` and the GUI's Open
Wallet menu released the exclusive lock that the node holds on each loaded
wallet, and so did loading a loaded wallet's file again through a symlink or
hard link. A second `qbitd`, `qbit-qt` or `qbit-wallet` process could then
open a wallet that was still in use. With two processes writing to one wallet,
PQC signature counter updates could be lost and the wallet file corrupted.

The node now keeps track of the wallet files it has open, by device and inode,
and recognizes them without opening them, so their locks stay held.
`listwalletdir` output is unchanged.

Windows behavior is unchanged: closing a file there does not release locks
held through other handles.
