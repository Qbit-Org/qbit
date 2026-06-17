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
- The relay engine also bounds incomplete inbound block state. Current builds cap inbound original size at 2,000,000 bytes, incomplete prefixes at 128, pre-header buffered chunks at 64 per prefix, global pre-header buffering at 1024 chunks (`1,222,656` bytes), implied post-header decoder chunk storage at 3 MiB per prefix, and incomplete relay age at 2 minutes since last activity.
- When the entry or age bound is hit, PHOTON evicts an incomplete inbound prefix. When the global pre-header byte cap is full, PHOTON rejects the new chunk instead of evicting an existing decoder.
- Verification anchors: `contrib/photon/src/peer_manager.cpp`, `contrib/photon/src/relay_engine.h`, `contrib/photon/src/relay_engine.cpp`; `contrib/photon/test/peer_manager_tests.cpp` (`inbound_zero_counter_rejected`, `lower_inbound_counter_rejected`, `replayed_synack_rejected_before_stats`, `replayed_keepalive_does_not_refresh_stale_or_disconnected_peer`, `reconnect_accepts_new_synack_session_with_reset_counter`, `restarted_peer_syn_replaces_active_session_and_sends_synack`, `restarted_peer_syn_replaces_stale_session_before_disconnect`, `restarted_peer_syn_replaces_disconnected_session_before_retry`); `contrib/photon/test/relay_engine_tests.cpp` (`oversized_inbound_header_rejected`, `cm256_header_accepted_within_decoder_budget`, `post_header_chunk_failure_erases_decoder`, `mismatched_coding_group_count_rejected`, `default_fec_header_accepted_within_decoder_budget`, `inbound_entry_limit_evicts_oldest_prefix`, `inbound_age_limit_evicts_incomplete_relay`, `inbound_age_limit_uses_last_activity`, `inbound_preheader_buffered_byte_limit`, `rejected_new_prefix_chunk_does_not_evict_existing_relay`).

## Escalation Procedures

1. Check relay logs for transport/auth failures.
   ```bash
   journalctl -u relay-node.service -n 200 --no-pager
   ```
2. Verify UDP connectivity to all configured peers on relay port (default `8144`).
3. Verify qbitd RPC health (`getblockchaininfo`, `getzmqnotifications`).
4. Check relay peer count plus `submit_fail`, `inbound_rejected`, and `inbound_evicted` in the stats logs.
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
  - Increase `rpc_timeout_ms` and check local qbitd load/latency.

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
- `known`: duplicate/known block announcements
- `chunks_sent` / `chunks_recv`: chunk-level transfer counters
- `submit_ok` / `submit_fail`: block submission outcomes to local qbitd
- `inbound_rejected`: cumulative inbound block headers or chunks refused by the relay engine after authentication and freshness checks, typically because the header is oversized or pre-header buffering hit a hard cap
- `inbound_evicted`: cumulative incomplete inbound prefixes dropped because they exceeded the age bound or were the oldest prefix at the entry cap

Watch for:
- `peers_active=0` for sustained periods
- `peer_session_replacements` increasing after a controlled daemon restart; absence of this counter during restart means the new `Syn` is not reaching or authenticating at the peer manager
- Rising `peer_session_replacement_rejects`, `peer_replay_rejects`, or `peer_mac_failures` during restart recovery
- Increasing `submit_fail`
- `blocks_out` advancing on one side while `blocks_in` is flat on peers
- Rising `inbound_rejected` with flat `blocks_in`: malformed or over-limit inbound traffic, or pre-header buffer pressure. This counter does not include replayed control packets rejected earlier by `PeerManager`.
- Rising `inbound_evicted`: incomplete relays are aging out or being displaced under prefix pressure. Sustained growth usually means packet loss, overloaded links, or a peer spraying too many concurrent incomplete prefixes.
