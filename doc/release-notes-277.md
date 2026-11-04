Wallet encryption and background keypool refills
================================================

Two bugs, present since v1.0.0, affected encrypting a wallet while a
background P2MR keypool refill was running, for example soon after the wallet
was created or once enough addresses had been handed out to start a refill.

- `encryptwallet` could deadlock with the refill. The call never returned, and
  the wallet stopped responding.
- A refill that had read its keys before encryption could write them after it,
  unencrypted. The wallet then reported itself as encrypted and locked while
  its database held unencrypted PQC private keys (`walletdescriptorpqckey`
  records), and loading the wallet accepted them.

Encryption now waits for a refill that is already writing keys. A refill that
read its keys before encryption stops without writing them, as a refill of a
locked wallet does. Keys added after encryption, including by later refills,
are stored encrypted. The wallet file format is unchanged.

This release does not detect or re-encrypt unencrypted PQC keys that v1.0.0
already wrote. If you encrypted a wallet with v1.0.0, especially soon after
creating it, consider creating a new wallet with a passphrase using this
release and moving your funds to it.
