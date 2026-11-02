Headers messages stay within the message size limit
===================================================

A block header carries its whole AuxPoW proof, including the parent chain's
coinbase transaction, so a run of blocks with large AuxPoW payloads could make
a reply to `getheaders` larger than the 4,000,000 bytes a peer accepts in one
message. The receiving peer dropped the connection, so new or catching-up
nodes could not sync headers past those blocks.

Nodes now end a `headers` message before it would exceed that limit, always
sending at least one header, and announce new blocks with `inv` when their
headers do not fit in one message. A node keeps requesting headers after a
`headers` message with 2,000 headers, as before, or of at least 2,000,000
bytes, since such a message may have been cut short to fit the limit. This
applies to normal headers sync and to low-work headers sync (presync and
redownload). Replies made of ordinary headers are unchanged: 2,000 headers
per message, byte for byte as before. Consensus rules are unchanged.

Known limitations, deferred to later releases:

- No consensus rule limits the size of an AuxPoW payload yet. Adding one
  needs an activated soft fork.
- The block index still keeps every AuxPoW payload in memory.
- Nodes running v1.0.0 still stall or abort headers sync through ranges with
  large AuxPoW headers. They take a message cut short for size as the end of
  the peer's headers, and when they serve headers they still send the
  oversized message, which upgraded nodes also reject.
- Low-work headers sync still gives up on a peer if the AuxPoW payloads it
  holds while redownloading exceed its existing 36 MB per-peer bound.
