# qbit-photon Runbook

## Overview

`qbit-photon` relays block data between geographically separated qbitd nodes using authenticated UDP links between relay daemons.

High-level path:

`qbitd (ZMQ + RPC) <-> qbit-photon <-> qbit-photon <-> qbitd (RPC submit)`

Each relay node:
- Subscribes to local qbitd `-zmqpubhashblock` events
- Fetches full blocks over qbitd RPC
- Relays encoded block data to configured peers
- Submits reconstructed blocks to its local qbitd

## Deployment Checklist

1. Build or install a qbitd binary with ZeroMQ notifications enabled.
   Core qbit builds leave ZeroMQ off by default; PHOTON requires a ZMQ-enabled
   qbitd so it can subscribe to local `hashblock` announcements.
   ```bash
   cmake -B build -DWITH_ZMQ=ON
   cmake --build build
   ```
   Confirm the binary exposes the required startup option:
   ```bash
   qbitd -help | grep zmqpubhashblock
   ```
2. Build qbit-photon.
   ```bash
   cmake -S contrib/photon -B contrib/photon/build
   cmake --build contrib/photon/build
   ```
3. Configure qbitd to publish block hashes via ZMQ.
   Example: `-zmqpubhashblock=tcp://127.0.0.1:28332`
   After qbitd starts with that option, confirm the active notification:
   ```bash
   qbit-cli getzmqnotifications
   ```
4. Create relay config from [`relay.conf.example`](./relay.conf.example).
5. Generate one 32-byte HMAC key per peer relationship.
   ```bash
   openssl rand -hex 32
   ```
6. Ensure each peer uses the same key for that link.
7. Install binary and service unit.
   - Binary: `/usr/local/bin/qbit-photon`
   - Unit: [`relay-node.service`](./relay-node.service)
8. Start and enable service.
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now relay-node.service
   ```
9. Verify startup.
   ```bash
   sudo systemctl status relay-node.service
   journalctl -u relay-node.service -n 100 --no-pager
   ```

## Monitoring With `getorphanmetrics`

Use `getorphanmetrics` on each qbitd behind a relay.

```bash
qbit-cli -rpcclienttimeout=30 getorphanmetrics
qbit-cli -rpcclienttimeout=30 getorphanmetrics 1000
```

Fields to track:
- `orphan_rate`: stale/orphan ratio over the selected window
- `alert`: instantaneous stale rate alert flag
- `persistent_stale_tip_count`: non-active tips accumulating over time
- `deepest_reorg`: maximum observed reorg depth
- `lifetime_stale_blocks`: cumulative stale block count

Threshold guidance:
- `orphan_rate > 0.10` sustained: investigate relay health and add capacity.
- `alert == true`: immediate investigation required.
- Rapidly rising `persistent_stale_tip_count`: likely relay outage or partition.
- `deepest_reorg > 2`: investigate for attack or severe partition.

## Freshness And Inbound Bounds

- Accepted inbound traffic is the freshness signal. With the current defaults, a peer sends keepalives every 5 seconds, becomes stale after 15 seconds without an accepted packet, is disconnected 5 seconds later if it stays stale, and is then retried after the 1 second initial backoff.
- Within one remote session, inbound counters must advance monotonically. Counter `0`, lower counters, and replayed packets are dropped before peer liveness refreshes. Counter wrap from `2^32 - 1` back to `1` is accepted. A reconnect can reset the counter only through a new nonzero-session-bearing `Syn` or `SynAck`; non-handshake packets are MAC-bound to the active remote session, and the first post-reset non-handshake packet must continue from that new baseline.
- A valid authenticated inbound `Syn` from a configured endpoint is a deterministic restart signal. PHOTON accepts the new remote session while the local slot is still active, stale, or disconnected, retires the old identity, and replies with `SynAck` immediately. Retired old-session handshakes and session-MAC-bound packets must not refresh liveness.
- The relay engine also bounds incomplete inbound block state, in total and per configured peer (peer slot). Current builds cap inbound original size at 2,000,000 bytes; incomplete blocks at 128 in total and 4 per peer; pre-header buffered chunks at 64 per block and 1024 in total (`1,222,656` bytes); and incomplete relay age at 2 minutes since last activity.
- Inbound decoder memory is charged at what the FEC codec actually allocates for the announced parameters (codec work buffers included, not only the block payload), before the decoder is built. Charged decoder memory is capped at 5 MiB per block, 10 MiB per peer, and 64 MiB in total. A default-parameter 2,000,000-byte block is charged about 4.8 MiB. Headers whose decoder would exceed the per-block cap are refused.
- When a peer reaches its own entry or decoder cap, PHOTON drops that peer's oldest incomplete block. When a total cap is reached, PHOTON first drops the requesting peer's own oldest incomplete blocks, then another peer's incomplete block only if it has made no progress for 10 seconds; a block that is still receiving new chunks is never displaced by another peer, and the new block is refused instead. Nothing is dropped for a block that would be refused anyway. Only new chunks count as progress, for this rule and for the 2-minute age limit; repeated headers or chunks, before or after the header, do not keep a block alive. When the global pre-header byte cap is full, PHOTON rejects the new chunk instead of evicting an existing decoder.
- PHOTON announces a block under the low-order 64 bits of its hash (the last 16 hex digits of the hash as qbitd prints it), which proof of work does not constrain. Earlier versions announced the leading 64 bits. A relay accepts a block announced under either form and keeps track of blocks by the low-order bits of the hash, so a block that arrives under both forms is used once. Relays running an earlier version use the identifier only as a key and accept blocks announced under the new form; after their qbitd accepts such a block they may send it on once more under the earlier form, and relays running this version recognise that copy as a block they already have. The packet format and protocol version are unchanged.
- Before submitting a reconstructed block, PHOTON checks that the block's header hash matches the identifier it was announced under, and asks qbitd where the block's parent is: it must be the best block, an ancestor of it at most 6 blocks deep, or a block on a competing branch with no more chain work than the best block, at most 6 blocks below it in height, and with at least as much chain work as the best chain's block 6 below the tip (so children of competing tips are still relayed). This takes one `getbestblockhash` call in the common case and at most six calls (`getblockheader`, `getblockhash`) otherwise, all within one `rpc_timeout_ms`. Blocks that fail these checks are dropped without calling `submitblock`. A block qbitd already has on its best chain within 6 blocks of the tip is treated as known; one deeper counts as too far from the tip. If qbitd knows the parent only as a header on a branch with more chain work than its best block, at most 6 blocks above the best block, it has not connected the parent yet: the block is submitted anyway and qbitd connects it after the parent (`block_parent_pending`). A parent further ahead means qbitd is still catching up, and the block is dropped (`block_node_behind`). A block whose parent qbitd does not know is dropped (`block_parent_rejected`). If qbitd does not answer the parent check (`block_check_unavailable`) or `submitblock` (`submit_timeout`), PHOTON keeps the block and tries it once more after qbitd next answers a call or announces a block, for up to 2 minutes (`node_retries`); it keeps one such block at a time, and a newer one replaces it. None of these count against the sending peer.
- Once a block from a peer has been submitted, dropped or refused, the rest of that block's chunks from the same peer are ignored for 10 seconds instead of starting a new incomplete block. Answers that depend only on the block's header (qbitd already has the block, stored it, has already marked it invalid, or finds it too far from the tip), or that qbitd could not give (no answer, timeout, error), also apply to other peers' copies of the same block for 10 seconds, under either identifier form, so they are not sent to qbitd again; this does not stop the relay from sending the block on when its own qbitd announces it. A rejection can concern one copy's contents only, so another peer's copy is still tried; an unknown parent, or qbitd still catching up, likewise ends only that peer's copy. An accepted block is marked as seen, as before.
- Each peer has a fault score. A malformed header or one above the per-block limits, a block that does not match its identifier, whose parent is too far from the tip (or that is itself deep in qbitd's best chain), that fails to decode or carries a chunk that does not fit the announced block, or that qbitd returns as `inconclusive` (unless qbitd had not connected its parent yet) or rejects adds one point; a block qbitd accepts removes two points; one point decays every 60 seconds. Duplicates, timeouts, other qbitd errors and parents qbitd does not know are neutral. At 8 points PHOTON refuses that peer's inbound blocks for 60 seconds and frees its incomplete blocks; each repeat doubles the pause up to 30 minutes, and the pause length starts over after 30 minutes without one. Occasional failed blocks from stale races decay before the threshold. If every block from a peer fails (for example because its node follows a chain the local qbitd does not use), the peer is paused from time to time; those blocks could not be used anyway. Other peers are unaffected.
- Memory: inbound decoders are bounded at 64 MiB, pre-header buffers at about 1.2 MiB of chunk data (up to about twice that in allocated capacity), submitting or relaying one block holds up to about 20 MiB of transient buffers (block bytes, hex encoding, RPC request and response copies), and a block kept for one more try holds up to 2,000,000 bytes. Together with the process baseline this stays well under 128 MiB. [`relay-node.service`](./relay-node.service) sets `MemoryMax=256M`, so a fault cannot grow the relay into memory that a co-located qbitd needs; raise it only together with the caps above.
- Verification anchors: `contrib/photon/src/peer_manager.cpp`, `contrib/photon/src/relay_engine.h`, `contrib/photon/src/relay_engine.cpp`, `contrib/photon/src/fec.cpp` (`Decoder::MemoryBytes`), `contrib/photon/src/rpc_client.cpp` (`CheckParent`, `SubmitBlock`); `contrib/photon/test/peer_manager_tests.cpp` (`inbound_zero_counter_rejected`, `lower_inbound_counter_rejected`, `replayed_synack_rejected_before_stats`, `replayed_keepalive_does_not_refresh_stale_or_disconnected_peer`, `reconnect_accepts_new_synack_session_with_reset_counter`, `restarted_peer_syn_replaces_active_session_and_sends_synack`, `restarted_peer_syn_replaces_stale_session_before_disconnect`, `restarted_peer_syn_replaces_disconnected_session_before_retry`); `contrib/photon/test/relay_engine_tests.cpp` (`oversized_inbound_header_rejected`, `cm256_header_accepted_within_decoder_budget`, `post_header_chunk_failure_erases_decoder`, `mismatched_coding_group_count_rejected`, `default_fec_header_accepted_within_decoder_budget`, `inbound_entry_limit_evicts_oldest_prefix`, `inbound_age_limit_evicts_incomplete_relay`, `inbound_age_limit_uses_last_activity`, `inbound_preheader_buffered_byte_limit`, `rejected_new_prefix_chunk_does_not_evict_existing_relay`, `mismatched_identifier_not_submitted`, `block_with_parent_away_from_tip_not_submitted`, `unavailable_parent_check_drops_without_penalty`, `submit_outcomes_counted_separately`, `repeated_rejected_blocks_suspend_peer`, `accepted_block_lowers_fault_score_without_resetting`, `peer_flood_does_not_evict_other_peers_block`, `per_peer_entry_quota_boundary`, `per_peer_decoder_quota_boundary`, `global_limit_spares_other_peers_recent_progress`, `failed_reservation_evicts_nothing`, `combined_limits_evict_nothing_when_refused`, `repeated_chunks_do_not_keep_block_alive`, `refused_header_remaining_chunks_ignored`, `unavailable_check_not_repeated_for_copies`, `node_answered_block_still_relayed_out`, `rejected_copy_does_not_block_other_peers_copy`, `known_invalid_block_settled_for_all_copies`, `handled_block_timed_after_node_calls`, `malformed_headers_count_against_peer`, `buffered_chunks_checked_before_eviction`, `node_behind_drops_without_penalty`, `remaining_chunks_of_handled_block_ignored`, `default_block_decoder_fits_entry_limit`, `worst_case_inbound_decoders_stay_within_bound`, `block_identifier_forms`, `blocks_sharing_leading_hash_bits_all_relayed`, `earlier_form_identifier_accepted_without_fault`, `block_identifier_accepted`, `block_announced_under_both_forms_used_once`, `mainnet_hash_sequence_relayed_without_suppression`, `identifier_keyed_receiver_gets_every_block`, `parent_known_only_as_header_submitted`, `unknown_parent_not_counted_against_peer`, `unanswered_block_tried_once_more`); `contrib/photon/test/fibre_fec_tests.cpp` (`decoder_memory_charge_covers_heap`); `contrib/photon/test/rpc_client_tests.cpp` (`submitblock_outcomes`, `check_parent_active_chain_depth`, `check_parent_competing_branch_near_tip`, `check_parent_node_behind`, `check_parent_not_connected`, `check_parent_unavailable`, `check_parent_shares_one_deadline`, `relay_submits_child_of_competing_tip`, `relay_submits_child_of_unconnected_parent`).

## Escalation Procedures

1. Check relay logs for transport/auth failures.
   ```bash
   journalctl -u relay-node.service -n 200 --no-pager
   ```
2. Verify UDP connectivity to all configured peers on relay port (default `8144`).
3. Verify qbitd RPC health (`getblockchaininfo`, `getzmqnotifications`).
4. Check relay peer count plus `submit_fail` (and its breakdown), `block_mismatch`, `block_parent_rejected`, `inbound_rejected`, `inbound_evicted`, and `peer_suspensions` in the stats logs, and the `peer relay stats` lines to see which peer they come from.
5. Add additional relay nodes if links are saturated or unstable.
6. Expand relay placement to additional regions to reduce single-path risk.
7. Re-check FEC overhead ratio if packet loss is recurring.

## Troubleshooting

Common failures and checks:

- Firewall blocks UDP `8144`
  - Ensure inbound and outbound UDP is open between relay peers.
- HMAC key mismatch
  - Confirm peer sections use the exact same 64-hex key on both sides.
- Missing `-zmqpubhashblock` in qbitd
  - Confirm the qbitd binary was built with `-DWITH_ZMQ=ON`, then confirm
    qbitd startup args and `getzmqnotifications` output.
- Wrong RPC cookie path
  - Confirm `rpc_cookiefile` points to the active chain cookie file.
    Mainnet under the shipped qbitd service defaults uses `/var/lib/qbit/.cookie`.
- RPC timeout
  - `rpc_timeout_ms` bounds each RPC call in total (sending and receiving; resolving a non-numeric `rpc_host` is not included), and the whole pre-submission parent check. Increase it and check local qbitd load/latency.

## Log Analysis

`qbit-photon` emits a periodic stats line every 60 seconds:

- `peers_active` / `peers_stale` / `peers_connecting` / `peers_disconnected`: configured peer liveness state counts
- `peer_syn_sent` / `peer_syn_recv` / `peer_synack_sent` / `peer_synack_recv`: handshake traffic counters
- `peer_keepalive_sent` / `peer_keepalive_recv`: keepalive counters
- `peer_mac_failures`: authenticated packet MAC failures
- `peer_replay_rejects`: zero, replayed, or non-monotonic inbound counters rejected before liveness refresh
- `peer_session_replacements`: accepted restart/session replacement handshakes
- `peer_session_replacement_rejects`: changed or retired handshakes rejected before liveness refresh
- `peer_resolve_failures`: configured endpoint resolution failures
- `blocks_out` / `blocks_in`: blocks relayed outbound/inbound
- `known`: duplicate/known block announcements, including blocks qbitd already had, the remaining chunks of blocks already handled, and copies of a block already handled that were announced under the other identifier form
- `chunks_sent` / `chunks_recv`: chunk-level transfer counters
- `submit_ok` / `submit_fail`: block submission outcomes to local qbitd; `submit_fail` counts blocks handed to qbitd that it did not accept (the breakdown below) plus reconstructed blocks that failed to decode; blocks dropped before submission are counted separately below
- `submit_duplicate`: qbitd already had the block
- `submit_inconclusive`: qbitd stored the block but did not make it part of its best chain (for example a competing block at the same height, or a block whose parent qbitd has not connected yet)
- `submit_rejected`: qbitd rejected the block as invalid, including blocks it had already marked invalid
- `submit_timeout`: no usable answer from qbitd (timeout, connection failure or a malformed HTTP reply); the block is tried once more (see `node_retries`)
- `submit_error`: qbitd answered with an error that is not a verdict on the block (for example while still loading)
- `block_mismatch`: reconstructed blocks dropped because their header hash did not match the identifier they were announced under, or no header could be read
- `block_parent_rejected`: reconstructed blocks dropped because qbitd does not know their parent (not counted against the peer) or the parent is too far below the best block
- `block_check_unavailable`: parent checks qbitd could not answer; the block is tried once more (see `node_retries`)
- `block_node_behind`: reconstructed blocks dropped because qbitd knows their parent only as a header more than 6 blocks above its own best block (it is still catching up)
- `block_parent_pending`: reconstructed blocks submitted while qbitd had their parent's header but had not connected the parent yet
- `node_retries`: blocks tried once more after qbitd did not answer the parent check or `submitblock`
- `inbound_rejected`: cumulative inbound block headers or chunks refused by the relay engine after authentication and freshness checks, typically because the header is oversized, a decoder or buffering cap was hit, or the sending peer is paused
- `inbound_evicted`: cumulative incomplete inbound blocks dropped because they exceeded the age bound or were displaced at an entry or decoder cap
- `inbound_entries` / `inbound_decoder_bytes`: incomplete inbound blocks and charged decoder memory held right now
- `peer_suspensions`: times a peer's inbound blocks were paused after its fault score reached the threshold

A reconstructed block that is not used for a reason worth investigating (identifier mismatch, parent check, rejection, no answer or an error from qbitd) is also logged as `relay inbound block <hash> from peer slot <n> not used: <reason>`, at most once a minute per reason with a count of suppressed lines.

After each stats line, one `peer relay stats` line per peer that has sent block traffic reports, for that peer: `blocks_in`, `faults` (events that added to its fault score), `inbound_rejected`, `inbound_evicted`, the current `fault_score`, `suspensions`, whether it is `suspended` now, and its current `inbound_entries` and `inbound_decoder_bytes`.

Watch for:
- `peers_active=0` for sustained periods
- `peer_session_replacements` increasing after a controlled daemon restart; absence of this counter during restart means the new `Syn` is not reaching or authenticating at the peer manager
- Rising `peer_session_replacement_rejects`, `peer_replay_rejects`, or `peer_mac_failures` during restart recovery
- Increasing `submit_fail`; use the breakdown to tell qbitd trouble (`submit_timeout`, `submit_error`) from blocks qbitd would not use (`submit_rejected`, `submit_inconclusive`)
- Any `block_mismatch`, or rising `block_parent_rejected` or `peer_suspensions`: check the `peer relay stats` lines for the peer concerned; a peer whose node is far behind or on another chain produces parent rejections
- `blocks_out` advancing on one side while `blocks_in` is flat on peers
- Rising `inbound_rejected` with flat `blocks_in`: malformed or over-limit inbound traffic, or pre-header buffer pressure. This counter does not include replayed control packets rejected earlier by `PeerManager`.
- Rising `inbound_evicted`: incomplete relays are aging out or being displaced under prefix pressure. Sustained growth usually means packet loss or overloaded links; if it is concentrated on one peer in the `peer relay stats` lines, that peer is announcing more concurrent blocks than its quota and only its own blocks are displaced.
