IPC block submission checks the coinbase witness
================================================

`submitSolution` on the IPC mining interface (`qbit-node -ipcbind`) now
checks the witness commitment of the coinbase the client submits. The block
template kept the result of the witness checks run when the template was
created, so those checks were skipped for the client's coinbase: the size of
the witness reserved value, the match between the commitment and the block's
transactions, and the rule against witness data in a block without a
commitment. A coinbase that failed any of them could make the node accept a
block as its tip that its peers reject. Such a block is now rejected and
`submitSolution` returns false. This is a backport of bitcoin/bitcoin#33745.

IPC clients must submit the complete coinbase, including its witness. Unlike
the `submitblock` RPC, `submitSolution` does not add the witness reserved value.

The `submitblock` RPC is unchanged. Consensus rules are unchanged.
