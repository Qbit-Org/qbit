# qbit Mainnet Release-Key Policy Transition

This approval payload authorizes `qbit-release-keys-mainnet-000002`, policy
sequence 2, effective from `v1.0.0`.

The transition retains the existing testnet 2-of-3 policy and adds a mainnet
3-of-5 policy over operators 01 through 05. Mainnet release signatures,
builder attestations, and later policy changes each require three active
operators. Every mainnet operator is eligible for the `core` and `photon`
artifact sets.

The previous policy exact-byte SHA256 is
`3084240d8589bb53d376bbf409683871c60d7d154c50b8a192308a61f4f9b2b2`.
The candidate policy exact-byte SHA256 is
`f04ae262bd40cdda5c481fc18cef29b405878e66d06c33b49865ea42b38eaf9f`.

Detached approval signatures cover `policy.SHA256`. At least two distinct
active signers from the previous policy must approve this transition.
