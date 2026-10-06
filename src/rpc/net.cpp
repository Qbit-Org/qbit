// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>

#include <addrman.h>
#include <addrman_impl.h>
#include <banman.h>
#include <chainparams.h>
#include <clientversion.h>
#include <core_io.h>
#include <crypto/mlkem.h>
#include <net_permissions.h>
#include <net_processing.h>
#include <net_types.h>
#include <netbase.h>
#include <node/context.h>
#include <node/protocol_version.h>
#include <node/warnings.h>
#include <policy/settings.h>
#include <protocol.h>
#include <rpc/blockchain.h>
#include <rpc/protocol.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <sync.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

using node::NodeContext;
using util::Join;
using util::TrimString;

const std::vector<std::string> CONNECTION_TYPE_DOC{
        "outbound-full-relay (default automatic connections)",
        "block-relay-only (does not relay transactions or addresses)",
        "inbound (initiated by the peer)",
        "manual (added via addnode RPC or -addnode/-connect configuration options)",
        "addr-fetch (short-lived automatic connection for soliciting addresses)",
        "feeler (short-lived automatic connection for testing addresses)"
};

const std::vector<std::string> TRANSPORT_TYPE_DOC{
    "detecting (peer could be v1 or v2)",
    "v1 (plaintext transport protocol)",
    "v2 (BIP324 encrypted transport protocol)"
};

const std::vector<std::string> PQ_STATUS_DOC{
    "pending (negotiating, or closing: a connection that closes on any hybrid failure reports pending until it is removed)",
    "hybrid (the peer's key confirmation verified: the session keys are hybrid)",
    "legacy_peer (the peer's version packet carried no usable offer or accept: ECDH keys)",
    "fallback (plain v2 to an endpoint in the fallback set after repeated hybrid failures)",
    "off (plain v2: -v2pqtransport is off, the offer was shed, or a local ML-KEM fault happened before anything was committed)",
    "v1 (v1 transport protocol)"
};

static RPCHelpMan getconnectioncount()
{
    return RPCHelpMan{
        "getconnectioncount",
        "Returns the number of connections to other nodes.\n",
                {},
                RPCResult{
                    RPCResult::Type::NUM, "", "The connection count"
                },
                RPCExamples{
                    HelpExampleCli("getconnectioncount", "")
            + HelpExampleRpc("getconnectioncount", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CConnman& connman = EnsureConnman(node);

    return connman.GetNodeCount(ConnectionDirection::Both);
},
    };
}

static RPCHelpMan ping()
{
    return RPCHelpMan{
        "ping",
        "Requests that a ping be sent to all other nodes, to measure ping time.\n"
                "Results are provided in getpeerinfo.\n"
                "Ping command is handled in queue with all other commands, so it measures processing backlog, not just network ping.\n",
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("ping", "")
            + HelpExampleRpc("ping", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    PeerManager& peerman = EnsurePeerman(node);

    // Request that each node send a ping during next message processing pass
    peerman.SendPings();
    return UniValue::VNULL;
},
    };
}

/** Returns, given services flags, a list of humanly readable (known) network services */
static UniValue GetServicesNames(ServiceFlags services)
{
    UniValue servicesNames(UniValue::VARR);

    for (const auto& flag : serviceFlagsToStr(services)) {
        servicesNames.push_back(flag);
    }

    return servicesNames;
}

/** A peer getpeerinfo lists, with its node state. */
struct ListedPeer {
    CNodeStats stats;
    CNodeStateStats statestats;
};

/** The peers getpeerinfo lists; getnetworkinfo counts over the same ones. */
static std::vector<ListedPeer> GetListedPeers(const CConnman& connman, const PeerManager& peerman)
{
    std::vector<CNodeStats> vstats;
    connman.GetNodeStats(vstats);
    std::vector<ListedPeer> peers;
    peers.reserve(vstats.size());
    for (CNodeStats& stats : vstats) {
        CNodeStateStats statestats;
        // GetNodeStateStats() requires the existence of a CNodeState and a Peer object
        // to succeed for this peer. These are created at connection initialisation and
        // exist for the duration of the connection - except if there is a race where the
        // peer got disconnected in between the GetNodeStats() and the GetNodeStateStats()
        // calls. In this case, the peer doesn't need to be reported here.
        if (!peerman.GetNodeStateStats(stats.nodeid, statestats)) continue;
        peers.push_back({std::move(stats), std::move(statestats)});
    }
    return peers;
}

static RPCHelpMan getpeerinfo()
{
    return RPCHelpMan{
        "getpeerinfo",
        "Returns data about each connected network peer as a json array of objects.",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {
                    {RPCResult::Type::NUM, "id", "Peer index"},
                    {RPCResult::Type::STR, "addr", "(host:port) The IP address and port of the peer"},
                    {RPCResult::Type::STR, "addrbind", /*optional=*/true, "(ip:port) Bind address of the connection to the peer"},
                    {RPCResult::Type::STR, "addrlocal", /*optional=*/true, "(ip:port) Local address as reported by the peer"},
                    {RPCResult::Type::STR, "network", "Network (" + Join(GetNetworkNames(/*append_unroutable=*/true), ", ") + ")"},
                    {RPCResult::Type::NUM, "mapped_as", /*optional=*/true, "Mapped AS (Autonomous System) number at the end of the BGP route to the peer, used for diversifying\n"
                                                        "peer selection (only displayed if the -asmap config option is set)"},
                    {RPCResult::Type::STR_HEX, "services", "The services offered"},
                    {RPCResult::Type::ARR, "servicesnames", "the services offered, in human-readable form",
                    {
                        {RPCResult::Type::STR, "SERVICE_NAME", "the service name if it is recognised"}
                    }},
                    {RPCResult::Type::BOOL, "relaytxes", "Whether we relay transactions to this peer"},
                    {RPCResult::Type::NUM_TIME, "lastsend", "The " + UNIX_EPOCH_TIME + " of the last send"},
                    {RPCResult::Type::NUM_TIME, "lastrecv", "The " + UNIX_EPOCH_TIME + " of the last receive"},
                    {RPCResult::Type::NUM_TIME, "last_transaction", "The " + UNIX_EPOCH_TIME + " of the last valid transaction received from this peer"},
                    {RPCResult::Type::NUM_TIME, "last_block", "The " + UNIX_EPOCH_TIME + " of the last block received from this peer"},
                    {RPCResult::Type::NUM, "bytessent", "The total bytes sent"},
                    {RPCResult::Type::NUM, "bytesrecv", "The total bytes received"},
                    {RPCResult::Type::NUM_TIME, "conntime", "The " + UNIX_EPOCH_TIME + " of the connection"},
                    {RPCResult::Type::NUM, "timeoffset", "The time offset in seconds"},
                    {RPCResult::Type::NUM, "pingtime", /*optional=*/true, "The last ping time in seconds, if any"},
                    {RPCResult::Type::NUM, "minping", /*optional=*/true, "The minimum observed ping time in seconds, if any"},
                    {RPCResult::Type::NUM, "pingwait", /*optional=*/true, "The duration in seconds of an outstanding ping (if non-zero)"},
                    {RPCResult::Type::NUM, "version", "The peer version, such as 70001"},
                    {RPCResult::Type::STR, "subver", "The string version"},
                    {RPCResult::Type::BOOL, "inbound", "Inbound (true) or Outbound (false)"},
                    {RPCResult::Type::BOOL, "bip152_hb_to", "Whether we selected peer as (compact blocks) high-bandwidth peer"},
                    {RPCResult::Type::BOOL, "bip152_hb_from", "Whether peer selected us as (compact blocks) high-bandwidth peer"},
                    {RPCResult::Type::NUM, "startingheight", "The starting height (block) of the peer"},
                    {RPCResult::Type::NUM, "presynced_headers", "The current height of header pre-synchronization with this peer, or -1 if no low-work sync is in progress"},
                    {RPCResult::Type::NUM, "synced_headers", "The last header we have in common with this peer"},
                    {RPCResult::Type::NUM, "synced_blocks", "The last block we have in common with this peer"},
                    {RPCResult::Type::ARR, "inflight", "",
                    {
                        {RPCResult::Type::NUM, "n", "The heights of blocks we're currently asking from this peer"},
                    }},
                    {RPCResult::Type::BOOL, "addr_relay_enabled", "Whether we participate in address relay with this peer"},
                    {RPCResult::Type::NUM, "addr_processed", "The total number of addresses processed, excluding those dropped due to rate limiting"},
                    {RPCResult::Type::NUM, "addr_rate_limited", "The total number of addresses dropped due to rate limiting"},
                    {RPCResult::Type::ARR, "permissions", "Any special permissions that have been granted to this peer",
                    {
                        {RPCResult::Type::STR, "permission_type", Join(NET_PERMISSIONS_DOC, ",\n") + ".\n"},
                    }},
                    {RPCResult::Type::NUM, "minfeefilter", "The minimum fee rate for transactions this peer accepts"},
                    {RPCResult::Type::OBJ_DYN, "bytessent_per_msg", "",
                    {
                        {RPCResult::Type::NUM, "msg", "The total bytes sent aggregated by message type\n"
                                                      "When a message type is not listed in this json object, the bytes sent are 0.\n"
                                                      "Only known message types can appear as keys in the object."}
                    }},
                    {RPCResult::Type::OBJ_DYN, "bytesrecv_per_msg", "",
                    {
                        {RPCResult::Type::NUM, "msg", "The total bytes received aggregated by message type\n"
                                                      "When a message type is not listed in this json object, the bytes received are 0.\n"
                                                      "Only known message types can appear as keys in the object and all bytes received\n"
                                                      "of unknown message types are listed under '"+NET_MESSAGE_TYPE_OTHER+"'."}
                    }},
                    {RPCResult::Type::STR, "connection_type", "Type of connection: \n" + Join(CONNECTION_TYPE_DOC, ",\n") + ".\n"
                                                              "Please note this output is unlikely to be stable in upcoming releases as we iterate to\n"
                                                              "best capture connection behaviors."},
                    {RPCResult::Type::STR, "transport_protocol_type", "Type of transport protocol: \n" + Join(TRANSPORT_TYPE_DOC, ",\n") + ".\n"},
                    {RPCResult::Type::STR, "session_id", "The session ID for this connection, or \"\" if there is none (\"v2\" transport protocol only).\n"
                                                         "With hybrid post-quantum session keys (transport_pq), the hybrid session ID.\n"},
                    {RPCResult::Type::BOOL, "transport_pq", "Whether the session keys are hybrid post-quantum (ML-KEM-1024 and ECDH): true once the peer's key confirmation verified"},
                    {RPCResult::Type::STR, "transport_pq_status", "Status of the hybrid post-quantum key exchange: \n" + Join(PQ_STATUS_DOC, ",\n") + ".\n"
                                                                  "There is no failed status: every hybrid negotiation failure that closes the connection reports pending until the peer is removed.\n"},
                }},
            }},
        },
        RPCExamples{
            HelpExampleCli("getpeerinfo", "")
            + HelpExampleRpc("getpeerinfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CConnman& connman = EnsureConnman(node);
    const PeerManager& peerman = EnsurePeerman(node);

    UniValue ret(UniValue::VARR);

    for (const auto& [stats, statestats] : GetListedPeers(connman, peerman)) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("id", stats.nodeid);
        obj.pushKV("addr", stats.m_addr_name);
        if (stats.addrBind.IsValid()) {
            obj.pushKV("addrbind", stats.addrBind.ToStringAddrPort());
        }
        if (!(stats.addrLocal.empty())) {
            obj.pushKV("addrlocal", stats.addrLocal);
        }
        obj.pushKV("network", GetNetworkName(stats.m_network));
        if (stats.m_mapped_as != 0) {
            obj.pushKV("mapped_as", uint64_t(stats.m_mapped_as));
        }
        ServiceFlags services{statestats.their_services};
        obj.pushKV("services", strprintf("%016x", services));
        obj.pushKV("servicesnames", GetServicesNames(services));
        obj.pushKV("relaytxes", statestats.m_relay_txs);
        obj.pushKV("lastsend", count_seconds(stats.m_last_send));
        obj.pushKV("lastrecv", count_seconds(stats.m_last_recv));
        obj.pushKV("last_transaction", count_seconds(stats.m_last_tx_time));
        obj.pushKV("last_block", count_seconds(stats.m_last_block_time));
        obj.pushKV("bytessent", stats.nSendBytes);
        obj.pushKV("bytesrecv", stats.nRecvBytes);
        obj.pushKV("conntime", count_seconds(stats.m_connected));
        obj.pushKV("timeoffset", Ticks<std::chrono::seconds>(statestats.time_offset));
        if (stats.m_last_ping_time > 0us) {
            obj.pushKV("pingtime", Ticks<SecondsDouble>(stats.m_last_ping_time));
        }
        if (stats.m_min_ping_time < std::chrono::microseconds::max()) {
            obj.pushKV("minping", Ticks<SecondsDouble>(stats.m_min_ping_time));
        }
        if (statestats.m_ping_wait > 0s) {
            obj.pushKV("pingwait", Ticks<SecondsDouble>(statestats.m_ping_wait));
        }
        obj.pushKV("version", stats.nVersion);
        // Use the sanitized form of subver here, to avoid tricksy remote peers from
        // corrupting or modifying the JSON output by putting special characters in
        // their ver message.
        obj.pushKV("subver", stats.cleanSubVer);
        obj.pushKV("inbound", stats.fInbound);
        obj.pushKV("bip152_hb_to", stats.m_bip152_highbandwidth_to);
        obj.pushKV("bip152_hb_from", stats.m_bip152_highbandwidth_from);
        obj.pushKV("startingheight", statestats.m_starting_height);
        obj.pushKV("presynced_headers", statestats.presync_height);
        obj.pushKV("synced_headers", statestats.nSyncHeight);
        obj.pushKV("synced_blocks", statestats.nCommonHeight);
        UniValue heights(UniValue::VARR);
        for (const int height : statestats.vHeightInFlight) {
            heights.push_back(height);
        }
        obj.pushKV("inflight", std::move(heights));
        obj.pushKV("addr_relay_enabled", statestats.m_addr_relay_enabled);
        obj.pushKV("addr_processed", statestats.m_addr_processed);
        obj.pushKV("addr_rate_limited", statestats.m_addr_rate_limited);
        UniValue permissions(UniValue::VARR);
        for (const auto& permission : NetPermissions::ToStrings(stats.m_permission_flags)) {
            permissions.push_back(permission);
        }
        obj.pushKV("permissions", std::move(permissions));
        obj.pushKV("minfeefilter", ValueFromAmount(statestats.m_fee_filter_received));

        UniValue sendPerMsgType(UniValue::VOBJ);
        for (const auto& i : stats.mapSendBytesPerMsgType) {
            if (i.second > 0)
                sendPerMsgType.pushKV(i.first, i.second);
        }
        obj.pushKV("bytessent_per_msg", std::move(sendPerMsgType));

        UniValue recvPerMsgType(UniValue::VOBJ);
        for (const auto& i : stats.mapRecvBytesPerMsgType) {
            if (i.second > 0)
                recvPerMsgType.pushKV(i.first, i.second);
        }
        obj.pushKV("bytesrecv_per_msg", std::move(recvPerMsgType));
        obj.pushKV("connection_type", ConnectionTypeAsString(stats.m_conn_type));
        obj.pushKV("transport_protocol_type", TransportTypeAsString(stats.m_transport_type));
        obj.pushKV("session_id", stats.m_session_id);
        obj.pushKV("transport_pq", stats.m_transport_pq);
        obj.pushKV("transport_pq_status", std::string{PQStatusString(stats.m_transport_pq_status)});

        ret.push_back(std::move(obj));
    }

    return ret;
},
    };
}

static RPCHelpMan getarchivepeers()
{
    return RPCHelpMan{
        "getarchivepeers",
        "Returns archive-relevant peer state for bootstrap, fallback debugging, and monitoring.\n"
        "This RPC reports observed and configured state only. NODE_ARCHIVE is a peer advertisement,\n"
        "not proof that the peer can serve all historical data.\n",
        {
            {"view", RPCArg::Type::STR, RPCArg::Default{"all"}, "Return view: \"all\", \"summary\", \"connected\", or \"configured\"."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::OBJ, "summary", "",
                {
                    {RPCResult::Type::NUM, "connected_advertised_archive_peers", "Currently connected peers whose observed service bits include NODE_ARCHIVE"},
                    {RPCResult::Type::NUM, "connected_archive_connections", "Currently connected peers opened through -connectarchive"},
                    {RPCResult::Type::NUM, "configured_archive_targets", "Configured -connectarchive entries"},
                    {RPCResult::Type::NUM, "connected_configured_archive_targets", "Configured -connectarchive entries currently connected"},
                }},
                {RPCResult::Type::ARR, "connected", /*optional=*/true, "Archive-relevant connected peers, included for view \"all\" or \"connected\"",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "nodeid", "Connected peer id"},
                        {RPCResult::Type::STR, "address", "(host:port) The IP address and port of the peer"},
                        {RPCResult::Type::STR, "connection_type", "Type of connection"},
                        {RPCResult::Type::BOOL, "archive_connection", "Whether this connection was opened from -connectarchive"},
                        {RPCResult::Type::BOOL, "advertises_archive", "Whether observed services include NODE_ARCHIVE"},
                        {RPCResult::Type::STR_HEX, "services", "The observed services offered"},
                        {RPCResult::Type::ARR, "servicesnames", "The observed services offered, in human-readable form",
                        {
                            {RPCResult::Type::STR, "SERVICE_NAME", "The service name if it is recognised"}
                        }},
                    }},
                }},
                {RPCResult::Type::ARR, "configured", /*optional=*/true, "Configured -connectarchive targets, included for view \"all\" or \"configured\"",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "target", "Configured -connectarchive target as provided by the operator"},
                        {RPCResult::Type::STR, "source", "Configuration source, always \"connectarchive\" in this version"},
                        {RPCResult::Type::BOOL, "connected", "Whether this configured target currently has a matching connected peer"},
                        {RPCResult::Type::NUM, "nodeid", /*optional=*/true, "Connected peer id when connected=true"},
                    }},
                }},
            },
        },
        RPCExamples{
            HelpExampleCli("getarchivepeers", "")
            + HelpExampleCli("getarchivepeers", "\"summary\"")
            + HelpExampleRpc("getarchivepeers", "\"connected\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string view{request.params[0].isNull() ? "all" : request.params[0].get_str()};
    const bool include_connected{view == "all" || view == "connected"};
    const bool include_configured{view == "all" || view == "configured"};
    if (view != "all" && view != "summary" && view != "connected" && view != "configured") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid view, expected one of: all, summary, connected, configured");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CConnman& connman = EnsureConnman(node);
    const PeerManager& peerman = EnsurePeerman(node);

    uint64_t connected_advertised_archive_peers{0};
    uint64_t connected_archive_connections{0};
    uint64_t configured_archive_targets{0};
    uint64_t connected_configured_archive_targets{0};

    UniValue connected(UniValue::VARR);
    std::vector<CNodeStats> vstats;
    connman.GetNodeStats(vstats);
    for (const CNodeStats& stats : vstats) {
        CNodeStateStats statestats;
        if (!peerman.GetNodeStateStats(stats.nodeid, statestats)) {
            continue;
        }

        const ServiceFlags services{statestats.their_services};
        const bool advertises_archive{static_cast<bool>(services & NODE_ARCHIVE)};
        const bool archive_connection{stats.m_is_archive_connection};
        if (advertises_archive) {
            ++connected_advertised_archive_peers;
        }
        if (archive_connection) {
            ++connected_archive_connections;
        }
        if (!include_connected || (!advertises_archive && !archive_connection)) {
            continue;
        }

        UniValue obj(UniValue::VOBJ);
        obj.pushKV("nodeid", stats.nodeid);
        obj.pushKV("address", stats.m_addr_name);
        obj.pushKV("connection_type", ConnectionTypeAsString(stats.m_conn_type));
        obj.pushKV("archive_connection", archive_connection);
        obj.pushKV("advertises_archive", advertises_archive);
        obj.pushKV("services", strprintf("%016x", services));
        obj.pushKV("servicesnames", GetServicesNames(services));
        connected.push_back(std::move(obj));
    }

    UniValue configured(UniValue::VARR);
    const std::vector<AddedNodeInfo> added_nodes{connman.GetAddedNodeInfo(/*include_connected=*/true)};
    for (const AddedNodeInfo& info : added_nodes) {
        if (!info.m_params.m_require_archive) {
            continue;
        }
        ++configured_archive_targets;
        if (info.fConnected) {
            ++connected_configured_archive_targets;
        }
        if (!include_configured) {
            continue;
        }

        UniValue obj(UniValue::VOBJ);
        obj.pushKV("target", info.m_params.m_added_node);
        obj.pushKV("source", "connectarchive");
        obj.pushKV("connected", info.fConnected);
        if (info.nodeid) {
            obj.pushKV("nodeid", *info.nodeid);
        }
        configured.push_back(std::move(obj));
    }

    UniValue summary(UniValue::VOBJ);
    summary.pushKV("connected_advertised_archive_peers", connected_advertised_archive_peers);
    summary.pushKV("connected_archive_connections", connected_archive_connections);
    summary.pushKV("configured_archive_targets", configured_archive_targets);
    summary.pushKV("connected_configured_archive_targets", connected_configured_archive_targets);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("summary", std::move(summary));
    if (include_connected) {
        ret.pushKV("connected", std::move(connected));
    }
    if (include_configured) {
        ret.pushKV("configured", std::move(configured));
    }
    return ret;
},
    };
}

static RPCHelpMan addnode()
{
    return RPCHelpMan{
        "addnode",
        "Attempts to add or remove a node from the addnode list.\n"
                "Or try a connection to a node once.\n"
                "Nodes added using addnode (or -connect) are protected from DoS disconnection and are not required to be\n"
                "full nodes/support SegWit as other outbound peers are (though such peers will not be synced from).\n" +
                strprintf("Addnode connections are limited to %u at a time", MAX_ADDNODE_CONNECTIONS) +
                " and are counted separately from the -maxconnections limit.\n",
                {
                    {"node", RPCArg::Type::STR, RPCArg::Optional::NO, "The address of the peer to connect to"},
                    {"command", RPCArg::Type::STR, RPCArg::Optional::NO, "'add' to add a node to the list, 'remove' to remove a node from the list, 'onetry' to try a connection to the node once"},
                    {"v2transport", RPCArg::Type::BOOL, RPCArg::DefaultHint{"set by -v2transport"}, "Attempt to connect using BIP324 v2 transport protocol (ignored for 'remove' command)"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("addnode", "\"192.168.0.6:8333\" \"onetry\" true")
            + HelpExampleRpc("addnode", "\"192.168.0.6:8333\", \"onetry\" true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto command{self.Arg<std::string>("command")};
    if (command != "onetry" && command != "add" && command != "remove") {
        throw std::runtime_error(
            self.ToString());
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    CConnman& connman = EnsureConnman(node);

    const auto node_arg{self.Arg<std::string>("node")};
    bool node_v2transport = connman.GetLocalServices() & NODE_P2P_V2;
    bool use_v2transport = self.MaybeArg<bool>("v2transport").value_or(node_v2transport);

    if (use_v2transport && !node_v2transport) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Error: v2transport requested but not enabled (see -v2transport)");
    }

    if (command == "onetry")
    {
        CAddress addr;
        connman.OpenNetworkConnection(addr, /*fCountFailure=*/false, /*grant_outbound=*/{}, node_arg.c_str(), ConnectionType::MANUAL, use_v2transport);
        return UniValue::VNULL;
    }

    if (command == "add")
    {
        if (!connman.AddNode({node_arg, use_v2transport})) {
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: Node already added");
        }
    }
    else if (command == "remove")
    {
        if (!connman.RemoveAddedNode(node_arg)) {
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node could not be removed. It has not been added previously.");
        }
    }

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan addconnection()
{
    return RPCHelpMan{
        "addconnection",
        "Open an outbound connection to a specified node. This RPC is for testing only.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The IP address and port to attempt connecting to."},
            {"connection_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Type of connection to open (\"outbound-full-relay\", \"block-relay-only\", \"addr-fetch\" or \"feeler\")."},
            {"v2transport", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Attempt to connect using BIP324 v2 transport protocol"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                { RPCResult::Type::STR, "address", "Address of newly added connection." },
                { RPCResult::Type::STR, "connection_type", "Type of connection opened." },
            }},
        RPCExamples{
            HelpExampleCli("addconnection", "\"192.168.0.6:8333\" \"outbound-full-relay\" true")
            + HelpExampleRpc("addconnection", "\"192.168.0.6:8333\" \"outbound-full-relay\" true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (Params().GetChainType() != ChainType::REGTEST) {
        throw std::runtime_error("addconnection is for regression testing (-regtest mode) only.");
    }

    const std::string address = request.params[0].get_str();
    const std::string conn_type_in{TrimString(request.params[1].get_str())};
    ConnectionType conn_type{};
    if (conn_type_in == "outbound-full-relay") {
        conn_type = ConnectionType::OUTBOUND_FULL_RELAY;
    } else if (conn_type_in == "block-relay-only") {
        conn_type = ConnectionType::BLOCK_RELAY;
    } else if (conn_type_in == "addr-fetch") {
        conn_type = ConnectionType::ADDR_FETCH;
    } else if (conn_type_in == "feeler") {
        conn_type = ConnectionType::FEELER;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, self.ToString());
    }
    bool use_v2transport{self.Arg<bool>("v2transport")};

    NodeContext& node = EnsureAnyNodeContext(request.context);
    CConnman& connman = EnsureConnman(node);

    if (use_v2transport && !(connman.GetLocalServices() & NODE_P2P_V2)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Error: Adding v2transport connections requires -v2transport init flag to be set.");
    }

    const bool success = connman.AddConnection(address, conn_type, use_v2transport);
    if (!success) {
        throw JSONRPCError(RPC_CLIENT_NODE_CAPACITY_REACHED, "Error: Already at capacity for specified connection type.");
    }

    UniValue info(UniValue::VOBJ);
    info.pushKV("address", address);
    info.pushKV("connection_type", conn_type_in);

    return info;
},
    };
}

static RPCHelpMan disconnectnode()
{
    return RPCHelpMan{
        "disconnectnode",
        "Immediately disconnects from the specified peer node.\n"
                "\nStrictly one out of 'address' and 'nodeid' can be provided to identify the node.\n"
                "\nTo disconnect by nodeid, either set 'address' to the empty string, or call using the named 'nodeid' argument only.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::DefaultHint{"fallback to nodeid"}, "The IP address/port of the node"},
                    {"nodeid", RPCArg::Type::NUM, RPCArg::DefaultHint{"fallback to address"}, "The node ID (see getpeerinfo for node IDs)"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("disconnectnode", "\"192.168.0.6:8333\"")
            + HelpExampleCli("disconnectnode", "\"\" 1")
            + HelpExampleRpc("disconnectnode", "\"192.168.0.6:8333\"")
            + HelpExampleRpc("disconnectnode", "\"\", 1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    CConnman& connman = EnsureConnman(node);

    bool success;
    const UniValue &address_arg = request.params[0];
    const UniValue &id_arg = request.params[1];

    if (!address_arg.isNull() && id_arg.isNull()) {
        /* handle disconnect-by-address */
        success = connman.DisconnectNode(address_arg.get_str());
    } else if (!id_arg.isNull() && (address_arg.isNull() || (address_arg.isStr() && address_arg.get_str().empty()))) {
        /* handle disconnect-by-id */
        NodeId nodeid = (NodeId) id_arg.getInt<int64_t>();
        success = connman.DisconnectNode(nodeid);
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Only one of address and nodeid should be provided.");
    }

    if (!success) {
        throw JSONRPCError(RPC_CLIENT_NODE_NOT_CONNECTED, "Node not found in connected nodes");
    }

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan getaddednodeinfo()
{
    return RPCHelpMan{
        "getaddednodeinfo",
        "Returns information about the given added node, or all added nodes\n"
                "(note that onetry addnodes are not listed here)\n",
                {
                    {"node", RPCArg::Type::STR, RPCArg::DefaultHint{"all nodes"}, "If provided, return information about this specific node, otherwise all nodes are returned."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "addednode", "The node IP address or name (as provided to addnode)"},
                            {RPCResult::Type::BOOL, "connected", "If connected"},
                            {RPCResult::Type::ARR, "addresses", "Only when connected = true",
                            {
                                {RPCResult::Type::OBJ, "", "",
                                {
                                    {RPCResult::Type::STR, "address", "The bitcoin server IP and port we're connected to"},
                                    {RPCResult::Type::STR, "connected", "connection, inbound or outbound"},
                                }},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getaddednodeinfo", "\"192.168.0.201\"")
            + HelpExampleRpc("getaddednodeinfo", "\"192.168.0.201\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CConnman& connman = EnsureConnman(node);

    std::vector<AddedNodeInfo> vInfo = connman.GetAddedNodeInfo(/*include_connected=*/true);

    if (!request.params[0].isNull()) {
        bool found = false;
        for (const AddedNodeInfo& info : vInfo) {
            if (info.m_params.m_added_node == request.params[0].get_str()) {
                vInfo.assign(1, info);
                found = true;
                break;
            }
        }
        if (!found) {
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
        }
    }

    UniValue ret(UniValue::VARR);

    for (const AddedNodeInfo& info : vInfo) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("addednode", info.m_params.m_added_node);
        obj.pushKV("connected", info.fConnected);
        UniValue addresses(UniValue::VARR);
        if (info.fConnected) {
            UniValue address(UniValue::VOBJ);
            address.pushKV("address", info.resolvedAddress.ToStringAddrPort());
            address.pushKV("connected", info.fInbound ? "inbound" : "outbound");
            addresses.push_back(std::move(address));
        }
        obj.pushKV("addresses", std::move(addresses));
        ret.push_back(std::move(obj));
    }

    return ret;
},
    };
}

static RPCHelpMan getnettotals()
{
    return RPCHelpMan{"getnettotals",
        "Returns information about network traffic, including bytes in, bytes out,\n"
        "and current system time.",
        {},
                RPCResult{
                   RPCResult::Type::OBJ, "", "",
                   {
                       {RPCResult::Type::NUM, "totalbytesrecv", "Total bytes received"},
                       {RPCResult::Type::NUM, "totalbytessent", "Total bytes sent"},
                       {RPCResult::Type::NUM_TIME, "timemillis", "Current system " + UNIX_EPOCH_TIME + " in milliseconds"},
                       {RPCResult::Type::OBJ, "uploadtarget", "",
                       {
                           {RPCResult::Type::NUM, "timeframe", "Length of the measuring timeframe in seconds"},
                           {RPCResult::Type::NUM, "target", "Target in bytes"},
                           {RPCResult::Type::BOOL, "target_reached", "True if target is reached"},
                           {RPCResult::Type::BOOL, "serve_historical_blocks", "True if serving historical blocks"},
                           {RPCResult::Type::NUM, "bytes_left_in_cycle", "Bytes left in current time cycle"},
                           {RPCResult::Type::NUM, "time_left_in_cycle", "Seconds left in current time cycle"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getnettotals", "")
            + HelpExampleRpc("getnettotals", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CConnman& connman = EnsureConnman(node);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("totalbytesrecv", connman.GetTotalBytesRecv());
    obj.pushKV("totalbytessent", connman.GetTotalBytesSent());
    obj.pushKV("timemillis", TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now()));

    UniValue outboundLimit(UniValue::VOBJ);
    outboundLimit.pushKV("timeframe", count_seconds(connman.GetMaxOutboundTimeframe()));
    outboundLimit.pushKV("target", connman.GetMaxOutboundTarget());
    outboundLimit.pushKV("target_reached", connman.OutboundTargetReached(false));
    outboundLimit.pushKV("serve_historical_blocks", !connman.OutboundTargetReached(true));
    outboundLimit.pushKV("bytes_left_in_cycle", connman.GetOutboundTargetBytesLeft());
    outboundLimit.pushKV("time_left_in_cycle", count_seconds(connman.GetMaxOutboundTimeLeftInCycle()));
    obj.pushKV("uploadtarget", std::move(outboundLimit));
    return obj;
},
    };
}

static UniValue GetNetworksInfo()
{
    UniValue networks(UniValue::VARR);
    for (int n = 0; n < NET_MAX; ++n) {
        enum Network network = static_cast<enum Network>(n);
        if (network == NET_UNROUTABLE || network == NET_INTERNAL) continue;
        Proxy proxy;
        UniValue obj(UniValue::VOBJ);
        GetProxy(network, proxy);
        obj.pushKV("name", GetNetworkName(network));
        obj.pushKV("limited", !g_reachable_nets.Contains(network));
        obj.pushKV("reachable", g_reachable_nets.Contains(network));
        obj.pushKV("proxy", proxy.IsValid() ? proxy.ToString() : std::string());
        obj.pushKV("proxy_randomize_credentials", proxy.m_tor_stream_isolation);
        networks.push_back(std::move(obj));
    }
    return networks;
}

static RPCHelpMan getnetworkinfo()
{
    return RPCHelpMan{"getnetworkinfo",
                "Returns an object containing various state info regarding P2P networking.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "version", "the server version"},
                        {RPCResult::Type::STR, "subversion", "the server subversion string"},
                        {RPCResult::Type::NUM, "protocolversion", "the protocol version"},
                        {RPCResult::Type::STR_HEX, "localservices", "the services we offer to the network"},
                        {RPCResult::Type::ARR, "localservicesnames", "the services we offer to the network, in human-readable form",
                        {
                            {RPCResult::Type::STR, "SERVICE_NAME", "the service name"},
                        }},
                        {RPCResult::Type::BOOL, "localrelay", "true if transaction relay is requested from peers"},
                        {RPCResult::Type::NUM, "timeoffset", "the time offset"},
                        {RPCResult::Type::NUM, "connections", "the total number of connections"},
                        {RPCResult::Type::NUM, "connections_in", "the number of inbound connections"},
                        {RPCResult::Type::NUM, "connections_out", "the number of outbound connections"},
                        {RPCResult::Type::NUM, "connections_pq", "the number of connections with hybrid post-quantum session keys: the peers getpeerinfo lists with transport_pq true"},
                        {RPCResult::Type::BOOL, "networkactive", "whether p2p networking is enabled"},
                        {RPCResult::Type::ARR, "networks", "information per network",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "name", "network (" + Join(GetNetworkNames(), ", ") + ")"},
                                {RPCResult::Type::BOOL, "limited", "is the network limited using -onlynet?"},
                                {RPCResult::Type::BOOL, "reachable", "is the network reachable?"},
                                {RPCResult::Type::STR, "proxy", "(\"host:port\") the proxy that is used for this network, or empty if none"},
                                {RPCResult::Type::BOOL, "proxy_randomize_credentials", "Whether randomized credentials are used"},
                            }},
                        }},
                        {RPCResult::Type::NUM, "relayfee", "minimum relay fee rate for transactions in " + CURRENCY_UNIT + "/kvB"},
                        {RPCResult::Type::NUM, "incrementalfee", "minimum fee rate increment for mempool limiting or replacement in " + CURRENCY_UNIT + "/kvB"},
                        {RPCResult::Type::ARR, "localaddresses", "list of local addresses",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "address", "network address"},
                                {RPCResult::Type::NUM, "port", "network port"},
                                {RPCResult::Type::NUM, "score", "relative score"},
                            }},
                        }},
                        (IsDeprecatedRPCEnabled("warnings") ?
                            RPCResult{RPCResult::Type::STR, "warnings", "any network and blockchain warnings (DEPRECATED)"} :
                            RPCResult{RPCResult::Type::ARR, "warnings", "any network and blockchain warnings (run with `-deprecatedrpc=warnings` to return the latest warning as a single string)",
                            {
                                {RPCResult::Type::STR, "", "warning"},
                            }
                            }
                        ),
                    }
                },
                RPCExamples{
                    HelpExampleCli("getnetworkinfo", "")
            + HelpExampleRpc("getnetworkinfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    // Counted before cs_main is taken, as getpeerinfo lists the peers.
    int connections_pq{0};
    if (node.connman && node.peerman) {
        for (const ListedPeer& peer : GetListedPeers(*node.connman, *node.peerman)) {
            if (peer.stats.m_transport_pq) ++connections_pq;
        }
    }
    LOCK(cs_main);
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version",       CLIENT_VERSION);
    obj.pushKV("subversion",    strSubVersion);
    obj.pushKV("protocolversion",PROTOCOL_VERSION);
    if (node.connman) {
        ServiceFlags services = node.connman->GetLocalServices();
        obj.pushKV("localservices", strprintf("%016x", services));
        obj.pushKV("localservicesnames", GetServicesNames(services));
    }
    if (node.peerman) {
        auto peerman_info{node.peerman->GetInfo()};
        obj.pushKV("localrelay", !peerman_info.ignores_incoming_txs);
        obj.pushKV("timeoffset", Ticks<std::chrono::seconds>(peerman_info.median_outbound_time_offset));
    }
    if (node.connman) {
        obj.pushKV("networkactive", node.connman->GetNetworkActive());
        obj.pushKV("connections", node.connman->GetNodeCount(ConnectionDirection::Both));
        obj.pushKV("connections_in", node.connman->GetNodeCount(ConnectionDirection::In));
        obj.pushKV("connections_out", node.connman->GetNodeCount(ConnectionDirection::Out));
        obj.pushKV("connections_pq", connections_pq);
    }
    obj.pushKV("networks",      GetNetworksInfo());
    if (node.mempool) {
        // Those fields can be deprecated, to be replaced by the getmempoolinfo fields
        obj.pushKV("relayfee", ValueFromAmount(node.mempool->m_opts.min_relay_feerate.GetFeePerK()));
        obj.pushKV("incrementalfee", ValueFromAmount(node.mempool->m_opts.incremental_relay_feerate.GetFeePerK()));
    }
    UniValue localAddresses(UniValue::VARR);
    {
        LOCK(g_maplocalhost_mutex);
        for (const std::pair<const CNetAddr, LocalServiceInfo> &item : mapLocalHost)
        {
            UniValue rec(UniValue::VOBJ);
            rec.pushKV("address", item.first.ToStringAddr());
            rec.pushKV("port", item.second.nPort);
            rec.pushKV("score", item.second.nScore);
            localAddresses.push_back(std::move(rec));
        }
    }
    obj.pushKV("localaddresses", std::move(localAddresses));
    obj.pushKV("warnings", node::GetWarningsForRpc(*CHECK_NONFATAL(node.warnings), IsDeprecatedRPCEnabled("warnings")));
    return obj;
},
    };
}

static RPCHelpMan setban()
{
    return RPCHelpMan{
        "setban",
        "Attempts to add or remove an IP/Subnet from the banned list.\n",
                {
                    {"subnet", RPCArg::Type::STR, RPCArg::Optional::NO, "The IP/Subnet (see getpeerinfo for nodes IP) with an optional netmask (default is /32 = single IP)"},
                    {"command", RPCArg::Type::STR, RPCArg::Optional::NO, "'add' to add an IP/Subnet to the list, 'remove' to remove an IP/Subnet from the list"},
                    {"bantime", RPCArg::Type::NUM, RPCArg::Default{0}, "time in seconds how long (or until when if [absolute] is set) the IP is banned (0 or empty means using the default time of 24h which can also be overwritten by the -bantime startup argument)"},
                    {"absolute", RPCArg::Type::BOOL, RPCArg::Default{false}, "If set, the bantime must be an absolute timestamp expressed in " + UNIX_EPOCH_TIME},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("setban", "\"192.168.0.6\" \"add\" 86400")
                            + HelpExampleCli("setban", "\"192.168.0.0/24\" \"add\"")
                            + HelpExampleRpc("setban", "\"192.168.0.6\", \"add\", 86400")
                },
        [&](const RPCHelpMan& help, const JSONRPCRequest& request) -> UniValue
{
    std::string strCommand;
    if (!request.params[1].isNull())
        strCommand = request.params[1].get_str();
    if (strCommand != "add" && strCommand != "remove") {
        throw std::runtime_error(help.ToString());
    }
    NodeContext& node = EnsureAnyNodeContext(request.context);
    BanMan& banman = EnsureBanman(node);

    CSubNet subNet;
    CNetAddr netAddr;
    bool isSubnet = false;

    if (request.params[0].get_str().find('/') != std::string::npos)
        isSubnet = true;

    if (!isSubnet) {
        const std::optional<CNetAddr> addr{LookupHost(request.params[0].get_str(), false)};
        if (addr.has_value()) {
            netAddr = static_cast<CNetAddr>(MaybeFlipIPv6toCJDNS(CService{addr.value(), /*port=*/0}));
        }
    }
    else
        subNet = LookupSubNet(request.params[0].get_str());

    if (! (isSubnet ? subNet.IsValid() : netAddr.IsValid()) )
        throw JSONRPCError(RPC_CLIENT_INVALID_IP_OR_SUBNET, "Error: Invalid IP/Subnet");

    if (strCommand == "add")
    {
        if (isSubnet ? banman.IsBanned(subNet) : banman.IsBanned(netAddr)) {
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: IP/Subnet already banned");
        }

        int64_t banTime = 0; //use standard bantime if not specified
        if (!request.params[2].isNull())
            banTime = request.params[2].getInt<int64_t>();

        const bool absolute{request.params[3].isNull() ? false : request.params[3].get_bool()};

        if (absolute && banTime < GetTime()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Error: Absolute timestamp is in the past");
        }

        if (isSubnet) {
            banman.Ban(subNet, banTime, absolute);
            if (node.connman) {
                node.connman->DisconnectNode(subNet);
            }
        } else {
            banman.Ban(netAddr, banTime, absolute);
            if (node.connman) {
                node.connman->DisconnectNode(netAddr);
            }
        }
    }
    else if(strCommand == "remove")
    {
        if (!( isSubnet ? banman.Unban(subNet) : banman.Unban(netAddr) )) {
            throw JSONRPCError(RPC_CLIENT_INVALID_IP_OR_SUBNET, "Error: Unban failed. Requested address/subnet was not previously manually banned.");
        }
    }
    return UniValue::VNULL;
},
    };
}

static RPCHelpMan listbanned()
{
    return RPCHelpMan{
        "listbanned",
        "List all manually banned IPs/Subnets.\n",
                {},
        RPCResult{RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The IP/Subnet of the banned node"},
                        {RPCResult::Type::NUM_TIME, "ban_created", "The " + UNIX_EPOCH_TIME + " the ban was created"},
                        {RPCResult::Type::NUM_TIME, "banned_until", "The " + UNIX_EPOCH_TIME + " the ban expires"},
                        {RPCResult::Type::NUM_TIME, "ban_duration", "The ban duration, in seconds"},
                        {RPCResult::Type::NUM_TIME, "time_remaining", "The time remaining until the ban expires, in seconds"},
                    }},
            }},
                RPCExamples{
                    HelpExampleCli("listbanned", "")
                            + HelpExampleRpc("listbanned", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    BanMan& banman = EnsureAnyBanman(request.context);

    banmap_t banMap;
    banman.GetBanned(banMap);
    const int64_t current_time{GetTime()};

    UniValue bannedAddresses(UniValue::VARR);
    for (const auto& entry : banMap)
    {
        const CBanEntry& banEntry = entry.second;
        UniValue rec(UniValue::VOBJ);
        rec.pushKV("address", entry.first.ToString());
        rec.pushKV("ban_created", banEntry.nCreateTime);
        rec.pushKV("banned_until", banEntry.nBanUntil);
        rec.pushKV("ban_duration", (banEntry.nBanUntil - banEntry.nCreateTime));
        rec.pushKV("time_remaining", (banEntry.nBanUntil - current_time));

        bannedAddresses.push_back(std::move(rec));
    }

    return bannedAddresses;
},
    };
}

static RPCHelpMan clearbanned()
{
    return RPCHelpMan{
        "clearbanned",
        "Clear all banned IPs.\n",
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("clearbanned", "")
                            + HelpExampleRpc("clearbanned", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    BanMan& banman = EnsureAnyBanman(request.context);

    banman.ClearBanned();

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan setnetworkactive()
{
    return RPCHelpMan{
        "setnetworkactive",
        "Disable/enable all p2p network activity.\n",
                {
                    {"state", RPCArg::Type::BOOL, RPCArg::Optional::NO, "true to enable networking, false to disable"},
                },
                RPCResult{RPCResult::Type::BOOL, "", "The value that was passed in"},
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    CConnman& connman = EnsureConnman(node);

    connman.SetNetworkActive(request.params[0].get_bool());

    return connman.GetNetworkActive();
},
    };
}

static RPCHelpMan getnodeaddresses()
{
    return RPCHelpMan{"getnodeaddresses",
                "Return known addresses, after filtering for quality and recency.\n"
                "These can potentially be used to find new peers in the network.\n"
                "The total number of addresses known to the node may be higher.",
                {
                    {"count", RPCArg::Type::NUM, RPCArg::Default{1}, "The maximum number of addresses to return. Specify 0 to return all known addresses."},
                    {"network", RPCArg::Type::STR, RPCArg::DefaultHint{"all networks"}, "Return only addresses of the specified network. Can be one of: " + Join(GetNetworkNames(), ", ") + "."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::NUM_TIME, "time", "The " + UNIX_EPOCH_TIME + " when the node was last seen"},
                            {RPCResult::Type::NUM, "services", "The services offered by the node"},
                            {RPCResult::Type::STR, "address", "The address of the node"},
                            {RPCResult::Type::NUM, "port", "The port number of the node"},
                            {RPCResult::Type::STR, "network", "The network (" + Join(GetNetworkNames(), ", ") + ") the node connected through"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getnodeaddresses", "8")
                    + HelpExampleCli("getnodeaddresses", "4 \"i2p\"")
                    + HelpExampleCli("-named getnodeaddresses", "network=onion count=12")
                    + HelpExampleRpc("getnodeaddresses", "8")
                    + HelpExampleRpc("getnodeaddresses", "4, \"i2p\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CConnman& connman = EnsureConnman(node);

    const int count{request.params[0].isNull() ? 1 : request.params[0].getInt<int>()};
    if (count < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Address count out of range");

    const std::optional<Network> network{request.params[1].isNull() ? std::nullopt : std::optional<Network>{ParseNetwork(request.params[1].get_str())}};
    if (network == NET_UNROUTABLE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Network not recognized: %s", request.params[1].get_str()));
    }

    // returns a shuffled list of CAddress
    const std::vector<CAddress> vAddr{connman.GetAddressesUnsafe(count, /*max_pct=*/0, network)};
    UniValue ret(UniValue::VARR);

    for (const CAddress& addr : vAddr) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("time", int64_t{TicksSinceEpoch<std::chrono::seconds>(addr.nTime)});
        obj.pushKV("services", (uint64_t)addr.nServices);
        obj.pushKV("address", addr.ToStringAddr());
        obj.pushKV("port", addr.GetPort());
        obj.pushKV("network", GetNetworkName(addr.GetNetClass()));
        ret.push_back(std::move(obj));
    }
    return ret;
},
    };
}

static RPCHelpMan addpeeraddress()
{
    return RPCHelpMan{"addpeeraddress",
        "Add the address of a potential peer to an address manager table. This RPC is for testing only.",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The IP address of the peer"},
            {"port", RPCArg::Type::NUM, RPCArg::Optional::NO, "The port of the peer"},
            {"tried", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, attempt to add the peer to the tried addresses table"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "whether the peer address was successfully added to the address manager table"},
                {RPCResult::Type::STR, "error", /*optional=*/true, "error description, if the address could not be added"},
            },
        },
        RPCExamples{
            HelpExampleCli("addpeeraddress", "\"1.2.3.4\" 8333 true")
    + HelpExampleRpc("addpeeraddress", "\"1.2.3.4\", 8333, true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    AddrMan& addrman = EnsureAnyAddrman(request.context);

    const std::string& addr_string{request.params[0].get_str()};
    const auto port{request.params[1].getInt<uint16_t>()};
    const bool tried{request.params[2].isNull() ? false : request.params[2].get_bool()};

    UniValue obj(UniValue::VOBJ);
    std::optional<CNetAddr> net_addr{LookupHost(addr_string, false)};
    bool success{false};

    if (net_addr.has_value()) {
        CService service{net_addr.value(), port};
        CAddress address{MaybeFlipIPv6toCJDNS(service), ServiceFlags{NODE_NETWORK | NODE_WITNESS}};
        address.nTime = Now<NodeSeconds>();
        // The source address is set equal to the address. This is equivalent to the peer
        // announcing itself.
        if (addrman.Add({address}, address)) {
            success = true;
            if (tried) {
                // Attempt to move the address to the tried addresses table.
                if (!addrman.Good(address)) {
                    success = false;
                    obj.pushKV("error", "failed-adding-to-tried");
                }
            }
        } else {
            obj.pushKV("error", "failed-adding-to-new");
        }
    }

    obj.pushKV("success", success);
    return obj;
},
    };
}

static RPCHelpMan sendmsgtopeer()
{
    return RPCHelpMan{
        "sendmsgtopeer",
        "Send a p2p message to a peer specified by id.\n"
        "The message type and body must be provided, the message header will be generated.\n"
        "This RPC is for testing only.",
        {
            {"peer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The peer to send the message to."},
            {"msg_type", RPCArg::Type::STR, RPCArg::Optional::NO, strprintf("The message type (maximum length %i)", CMessageHeader::MESSAGE_TYPE_SIZE)},
            {"msg", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The serialized message body to send, in hex, without a message header"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", std::vector<RPCResult>{}},
        RPCExamples{
            HelpExampleCli("sendmsgtopeer", "0 \"addr\" \"ffffff\"") + HelpExampleRpc("sendmsgtopeer", "0 \"addr\" \"ffffff\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const NodeId peer_id{request.params[0].getInt<int64_t>()};
            const std::string& msg_type{request.params[1].get_str()};
            if (msg_type.size() > CMessageHeader::MESSAGE_TYPE_SIZE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Error: msg_type too long, max length is %i", CMessageHeader::MESSAGE_TYPE_SIZE));
            }
            auto msg{TryParseHex<unsigned char>(request.params[2].get_str())};
            if (!msg.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Error parsing input for msg");
            }

            NodeContext& node = EnsureAnyNodeContext(request.context);
            CConnman& connman = EnsureConnman(node);

            CSerializedNetMsg msg_ser;
            msg_ser.data = msg.value();
            msg_ser.m_type = msg_type;

            bool success = connman.ForNode(peer_id, [&](CNode* node) {
                connman.PushMessage(node, std::move(msg_ser));
                return true;
            });

            if (!success) {
                throw JSONRPCError(RPC_MISC_ERROR, "Error: Could not send message to peer");
            }

            UniValue ret{UniValue::VOBJ};
            return ret;
        },
    };
}

static RPCHelpMan getaddrmaninfo()
{
    return RPCHelpMan{
        "getaddrmaninfo",
        "Provides information about the node's address manager by returning the number of "
        "addresses in the `new` and `tried` tables and their sum for all networks.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ_DYN, "", "json object with network type as keys", {
                {RPCResult::Type::OBJ, "network", "the network (" + Join(GetNetworkNames(), ", ") + ", all_networks)", {
                {RPCResult::Type::NUM, "new", "number of addresses in the new table, which represent potential peers the node has discovered but hasn't yet successfully connected to."},
                {RPCResult::Type::NUM, "tried", "number of addresses in the tried table, which represent peers the node has successfully connected to in the past."},
                {RPCResult::Type::NUM, "total", "total number of addresses in both new/tried tables"},
            }},
        }},
        RPCExamples{HelpExampleCli("getaddrmaninfo", "") + HelpExampleRpc("getaddrmaninfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            AddrMan& addrman = EnsureAnyAddrman(request.context);

            UniValue ret(UniValue::VOBJ);
            for (int n = 0; n < NET_MAX; ++n) {
                enum Network network = static_cast<enum Network>(n);
                if (network == NET_UNROUTABLE || network == NET_INTERNAL) continue;
                UniValue obj(UniValue::VOBJ);
                obj.pushKV("new", addrman.Size(network, true));
                obj.pushKV("tried", addrman.Size(network, false));
                obj.pushKV("total", addrman.Size(network));
                ret.pushKV(GetNetworkName(network), std::move(obj));
            }
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("new", addrman.Size(std::nullopt, true));
            obj.pushKV("tried", addrman.Size(std::nullopt, false));
            obj.pushKV("total", addrman.Size());
            ret.pushKV("all_networks", std::move(obj));
            return ret;
        },
    };
}

UniValue AddrmanEntryToJSON(const AddrInfo& info, const CConnman& connman)
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("address", info.ToStringAddr());
    const uint32_t mapped_as{connman.GetMappedAS(info)};
    if (mapped_as) {
        ret.pushKV("mapped_as", mapped_as);
    }
    ret.pushKV("port", info.GetPort());
    ret.pushKV("services", (uint64_t)info.nServices);
    ret.pushKV("time", int64_t{TicksSinceEpoch<std::chrono::seconds>(info.nTime)});
    ret.pushKV("network", GetNetworkName(info.GetNetClass()));
    ret.pushKV("source", info.source.ToStringAddr());
    ret.pushKV("source_network", GetNetworkName(info.source.GetNetClass()));
    const uint32_t source_mapped_as{connman.GetMappedAS(info.source)};
    if (source_mapped_as) {
        ret.pushKV("source_mapped_as", source_mapped_as);
    }
    return ret;
}

UniValue AddrmanTableToJSON(const std::vector<std::pair<AddrInfo, AddressPosition>>& tableInfos, const CConnman& connman)
{
    UniValue table(UniValue::VOBJ);
    for (const auto& e : tableInfos) {
        AddrInfo info = e.first;
        AddressPosition location = e.second;
        std::ostringstream key;
        key << location.bucket << "/" << location.position;
        // Address manager tables have unique entries so there is no advantage
        // in using UniValue::pushKV, which checks if the key already exists
        // in O(N). UniValue::pushKVEnd is used instead which currently is O(1).
        table.pushKVEnd(key.str(), AddrmanEntryToJSON(info, connman));
    }
    return table;
}

static RPCHelpMan getrawaddrman()
{
    return RPCHelpMan{"getrawaddrman",
        "EXPERIMENTAL warning: this call may be changed in future releases.\n"
        "\nReturns information on all address manager entries for the new and tried tables.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ_DYN, "", "", {
                {RPCResult::Type::OBJ_DYN, "table", "buckets with addresses in the address manager table ( new, tried )", {
                    {RPCResult::Type::OBJ, "bucket/position", "the location in the address manager table (<bucket>/<position>)", {
                        {RPCResult::Type::STR, "address", "The address of the node"},
                        {RPCResult::Type::NUM, "mapped_as", /*optional=*/true, "Mapped AS (Autonomous System) number at the end of the BGP route to the peer, used for diversifying peer selection (only displayed if the -asmap config option is set)"},
                        {RPCResult::Type::NUM, "port", "The port number of the node"},
                        {RPCResult::Type::STR, "network", "The network (" + Join(GetNetworkNames(), ", ") + ") of the address"},
                        {RPCResult::Type::NUM, "services", "The services offered by the node"},
                        {RPCResult::Type::NUM_TIME, "time", "The " + UNIX_EPOCH_TIME + " when the node was last seen"},
                        {RPCResult::Type::STR, "source", "The address that relayed the address to us"},
                        {RPCResult::Type::STR, "source_network", "The network (" + Join(GetNetworkNames(), ", ") + ") of the source address"},
                        {RPCResult::Type::NUM, "source_mapped_as", /*optional=*/true, "Mapped AS (Autonomous System) number at the end of the BGP route to the source, used for diversifying peer selection (only displayed if the -asmap config option is set)"}
                    }}
                }}
            }
        },
        RPCExamples{
            HelpExampleCli("getrawaddrman", "")
            + HelpExampleRpc("getrawaddrman", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            AddrMan& addrman = EnsureAnyAddrman(request.context);
            NodeContext& node_context = EnsureAnyNodeContext(request.context);
            CConnman& connman = EnsureConnman(node_context);

            UniValue ret(UniValue::VOBJ);
            ret.pushKV("new", AddrmanTableToJSON(addrman.GetEntries(false), connman));
            ret.pushKV("tried", AddrmanTableToJSON(addrman.GetEntries(true), connman));
            return ret;
        },
    };
}

/** The getpqtransportinfo help of an endpoint. */
static std::vector<RPCResult> PQEndpointDoc()
{
    return {
        {RPCResult::Type::STR, "kind", "\"address\" (a resolved destination, or an inbound peer) or \"name_proxy\" (a hostname connected through a proxy that resolves it)"},
        {RPCResult::Type::STR, "network", "ipv4, ipv6, onion, i2p, cjdns or name_proxy"},
        {RPCResult::Type::STR, "address", "The canonical address, or the normalized hostname, without the port"},
        {RPCResult::Type::NUM, "port", "The port; for an inbound peer, its source port"},
    };
}

/** The getpqtransportinfo help of one direction's counters. */
static std::vector<RPCResult> PQCountsDoc(bool inbound)
{
    std::vector<RPCResult> doc{
        {RPCResult::Type::NUM, "switched", "Switches to hybrid keys, including those whose key confirmation then failed"},
        {RPCResult::Type::NUM, "legacy_peer", "Peers whose version packet carried no usable offer or accept"},
        {RPCResult::Type::NUM, "malformed_record", "Peers whose first hybrid record was malformed"},
        {RPCResult::Type::NUM, "first_packet_failed", "Key confirmations of the peer that failed"},
        {RPCResult::Type::NUM, "abandoned", "Offers whose initiator sent no authenticated version packet before the connection closed (only responders offer: 0 outbound)"},
        {RPCResult::Type::NUM, "internal_error", "Local ML-KEM or cipher state errors"},
    };
    if (inbound) {
        doc.push_back({RPCResult::Type::NUM, "shed", "Offers not made because of load shedding"});
    } else {
        doc.push_back({RPCResult::Type::NUM, "closed_after_switch", "Connections the peer closed, or that timed out, after we switched and before its key confirmation verified"});
        doc.push_back({RPCResult::Type::NUM, "fallback", "Entries of an endpoint into the fallback set (not the plain v2 connections it gives)"});
    }
    return doc;
}

/** The getpqtransportinfo help of one direction's failure ring. */
static RPCResult PQRingDoc(const std::string& name, const std::string& description)
{
    return {RPCResult::Type::OBJ, name, description,
        {
            {RPCResult::Type::NUM, "last_sequence", "The sequence of the newest entry ever added (the first is 1), or 0 if none"},
            {RPCResult::Type::NUM, "dropped", strprintf("How many entries were evicted to keep at most %u", PQ_FAILURE_RING_SIZE)},
            {RPCResult::Type::ARR, "entries", "The most recent failures, oldest first",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "sequence", "The entry's sequence in this ring"},
                    {RPCResult::Type::NUM_TIME, "time", "The " + UNIX_EPOCH_TIME + " of the outcome"},
                    {RPCResult::Type::OBJ, "endpoint", "The endpoint the outcome is accounted to", PQEndpointDoc()},
                    {RPCResult::Type::STR, "direction", "\"inbound\" or \"outbound\""},
                    {RPCResult::Type::STR, "connection_type", "The connection type, as in getpeerinfo"},
                    {RPCResult::Type::NUM, "peer_id", "The peer index, as in getpeerinfo"},
                    {RPCResult::Type::STR, "outcome", "legacy_peer, malformed_record, first_packet_failed, abandoned, closed_after_switch, fallback or internal_error"},
                    {RPCResult::Type::STR, "reason", "The outcome's reason (see above)"},
                }},
            }},
        }};
}

/** The network of an endpoint's address, as getpqtransportinfo names it. */
static std::string PQEndpointNetwork(const CService& service)
{
    // The address's own network: a local or private address is still ipv4 or ipv6.
    if (service.IsIPv4()) return "ipv4";
    if (service.IsIPv6()) return "ipv6";
    if (service.IsTor()) return "onion";
    if (service.IsI2P()) return "i2p";
    if (service.IsCJDNS()) return "cjdns";
    // Internal addresses are never connected to.
    return GetNetworkName(service.GetNetwork());
}

static UniValue PQEndpointToUniv(const PQEndpointKey& endpoint)
{
    UniValue obj(UniValue::VOBJ);
    if (const CService* service{std::get_if<CService>(&endpoint)}) {
        obj.pushKV("kind", "address");
        obj.pushKV("network", PQEndpointNetwork(*service));
        obj.pushKV("address", service->ToStringAddr());
        obj.pushKV("port", service->GetPort());
    } else {
        const PQNameEndpoint& name{std::get<PQNameEndpoint>(endpoint)};
        obj.pushKV("kind", "name_proxy");
        obj.pushKV("network", "name_proxy");
        obj.pushKV("address", name.hostname);
        obj.pushKV("port", name.port);
    }
    return obj;
}

static UniValue PQCountsToUniv(const PQCounts& counts, bool inbound)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("switched", counts.switched);
    obj.pushKV("legacy_peer", counts.legacy_peer);
    obj.pushKV("malformed_record", counts.malformed_record);
    obj.pushKV("first_packet_failed", counts.first_packet_failed);
    obj.pushKV("abandoned", counts.abandoned);
    obj.pushKV("internal_error", counts.internal_error);
    if (inbound) {
        obj.pushKV("shed", counts.shed);
    } else {
        obj.pushKV("closed_after_switch", counts.closed_after_switch);
        obj.pushKV("fallback", counts.fallback);
    }
    return obj;
}

static UniValue PQRingToUniv(const PQFailureRing& ring)
{
    UniValue entries(UniValue::VARR);
    for (const PQFailureEntry& entry : ring.entries) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("sequence", entry.sequence);
        obj.pushKV("time", TicksSinceEpoch<std::chrono::seconds>(entry.time));
        obj.pushKV("endpoint", PQEndpointToUniv(entry.endpoint));
        obj.pushKV("direction", entry.inbound ? "inbound" : "outbound");
        obj.pushKV("connection_type", ConnectionTypeAsString(entry.connection_type));
        obj.pushKV("peer_id", entry.peer_id);
        obj.pushKV("outcome", std::string{PQOutcomeString(entry.outcome)});
        obj.pushKV("reason", entry.reason);
        entries.push_back(std::move(obj));
    }
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("last_sequence", ring.last_sequence);
    obj.pushKV("dropped", ring.dropped);
    obj.pushKV("entries", std::move(entries));
    return obj;
}

static RPCHelpMan getpqtransportinfo()
{
    const std::string causes{"malformed_record, first_packet_failed or closed_after_switch"};
    const std::string windows{"3600, 14400 or 86400"};
    return RPCHelpMan{
        "getpqtransportinfo",
        "Returns the state of the hybrid post-quantum key exchange (ML-KEM-1024 and ECDH) in v2 transport:\n"
        "its configuration, the handshake outcomes since startup, load shedding, the fallback set, failure\n"
        "streaks and the most recent failures. Every field is always present.\n"
        "\n"
        "-v2transport and -v2pqtransport are read once, at startup. A non-numeric -v2pqtransport value\n"
        "(true reads as 0), or a double negative such as -nov2pqtransport=0 (read as 1), warns there and\n"
        "states how it was read.\n"
        "\n"
        "Counters count events, not exclusive outcomes: switched counts key installations, even if the key\n"
        "confirmation then fails; fallback counts entries into the fallback set, not plain v2 connections;\n"
        "abandoned counts offers whose initiator sent no authenticated version packet before the connection\n"
        "closed. Counters, rings and endpoint history are kept in memory only, and start over when\n"
        "instance_id changes.\n"
        "\n"
        "A connection that closes on a hybrid failure reports transport_pq_status \"pending\" in getpeerinfo\n"
        "until it is removed; its outcome is counted here.\n"
        "\n"
        "Reasons, by outcome:\n"
        "legacy_peer: no_features, parse_error\n"
        "malformed_record: ek_length, ek_modulus, ct_length\n"
        "first_packet_failed: length, tag, not_decoy\n"
        "closed_after_switch: eof, reset, timeout\n"
        "abandoned: eof, reset, timeout, send_error, local, garbage_terminator, version_length, version_tag\n"
        "fallback: malformed_record, first_packet_failed, closed_after_switch (the failure that completed the streak)\n"
        "internal_error: keygen, check_public_key, encaps, decaps, cipher_state\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "enabled", "Whether new v2 connections negotiate hybrid keys: -v2transport and -v2pqtransport are both on"},
                {RPCResult::Type::STR, "status", "enabled, disabled_v2pqtransport (-v2pqtransport=0) or disabled_v2transport (-v2transport=0, whatever -v2pqtransport is)"},
                {RPCResult::Type::STR_HEX, "instance_id", "Random per process start"},
                {RPCResult::Type::STR, "arith_backend", "The ML-KEM-1024 arithmetic code that runs: x86_64-avx2, aarch64-neon or portable"},
                {RPCResult::Type::STR, "keccak_backend", "The Keccak code that runs: x86_64-avx2, aarch64 or portable"},
                {RPCResult::Type::NUM_TIME, "since", "The " + UNIX_EPOCH_TIME + " of startup, from which the counters count"},
                {RPCResult::Type::OBJ, "handshakes", "Hybrid negotiation events",
                {
                    {RPCResult::Type::OBJ, "inbound", "Of inbound connections", PQCountsDoc(/*inbound=*/true)},
                    {RPCResult::Type::OBJ, "outbound", "Of outbound connections, manual ones included", PQCountsDoc(/*inbound=*/false)},
                }},
                {RPCResult::Type::OBJ, "load_shedding", "Inbound offer load shedding",
                {
                    {RPCResult::Type::BOOL, "active", "Whether responders stop offering, because more than threshold_per_s inbound offers were attempted in one second"},
                    {RPCResult::Type::NUM, "threshold_per_s", "The threshold, in offers attempted per second"},
                    {RPCResult::Type::NUM_TIME, "since", "The " + UNIX_EPOCH_TIME + " the current shedding period started, or 0 when inactive"},
                }},
                {RPCResult::Type::ARR, "fallback_set", "Endpoints that outbound connections reach with plain v2, after repeated hybrid failures",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::OBJ, "endpoint", "", PQEndpointDoc()},
                        {RPCResult::Type::STR, "cause", "The failure that completed the streak: " + causes},
                        {RPCResult::Type::STR, "reason", "Its reason"},
                        {RPCResult::Type::NUM, "streak", "Consecutive counted failures"},
                        {RPCResult::Type::NUM_TIME, "entered", "The " + UNIX_EPOCH_TIME + " the endpoint entered the set"},
                        {RPCResult::Type::NUM_TIME, "expires", "The " + UNIX_EPOCH_TIME + " the window ends"},
                        {RPCResult::Type::NUM, "window_seconds", "The window: " + windows},
                    }},
                }},
                {RPCResult::Type::ARR, "failure_streaks", "Outbound endpoints with counted failures, not in the fallback set",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::OBJ, "endpoint", "", PQEndpointDoc()},
                        {RPCResult::Type::STR, "cause", "The latest counted failure: " + causes},
                        {RPCResult::Type::STR, "reason", "Its reason"},
                        {RPCResult::Type::NUM, "streak", strprintf("Consecutive counted failures, below %u", PQ_FAILURE_THRESHOLD)},
                        {RPCResult::Type::NUM_TIME, "last_failure", "The " + UNIX_EPOCH_TIME + " of the latest counted failure"},
                        {RPCResult::Type::NUM, "next_window_seconds", "The window the endpoint enters at the threshold: " + windows},
                    }},
                }},
                {RPCResult::Type::OBJ, "recent_failures", "The most recent non-success outcomes",
                {
                    PQRingDoc("inbound", "Of inbound connections"),
                    PQRingDoc("outbound", "Of outbound connections, manual ones included"),
                }},
            }},
        RPCExamples{
            HelpExampleCli("getpqtransportinfo", "")
            + HelpExampleRpc("getpqtransportinfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CConnman& connman = EnsureConnman(node);
    const PQTransportConfig& config{connman.GetPQTransportConfig()};
    const PQTransportStats stats{connman.GetPQTransportStats()};
    const mlkem::BackendNames backends{mlkem::GetBackendNames()};

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("enabled", config.Enabled());
    obj.pushKV("status", !config.v2_enabled ? "disabled_v2transport" : !config.pq_requested ? "disabled_v2pqtransport" : "enabled");
    obj.pushKV("instance_id", HexStr(stats.instance_id));
    obj.pushKV("arith_backend", std::string{backends.arith});
    obj.pushKV("keccak_backend", std::string{backends.keccak});
    obj.pushKV("since", TicksSinceEpoch<std::chrono::seconds>(stats.since));

    UniValue handshakes(UniValue::VOBJ);
    handshakes.pushKV("inbound", PQCountsToUniv(stats.inbound, /*inbound=*/true));
    handshakes.pushKV("outbound", PQCountsToUniv(stats.outbound, /*inbound=*/false));
    obj.pushKV("handshakes", std::move(handshakes));

    UniValue load_shedding(UniValue::VOBJ);
    load_shedding.pushKV("active", stats.load_shedding.active);
    load_shedding.pushKV("threshold_per_s", stats.load_shedding.threshold_per_s);
    load_shedding.pushKV("since", TicksSinceEpoch<std::chrono::seconds>(stats.load_shedding.since));
    obj.pushKV("load_shedding", std::move(load_shedding));

    UniValue fallback_set(UniValue::VARR);
    for (const PQFallbackStats& fallback : stats.fallback_set) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("endpoint", PQEndpointToUniv(fallback.endpoint));
        entry.pushKV("cause", std::string{PQOutcomeString(fallback.cause)});
        entry.pushKV("reason", fallback.reason);
        entry.pushKV("streak", uint64_t{fallback.streak});
        entry.pushKV("entered", TicksSinceEpoch<std::chrono::seconds>(fallback.entered));
        entry.pushKV("expires", TicksSinceEpoch<std::chrono::seconds>(fallback.expires));
        entry.pushKV("window_seconds", Ticks<std::chrono::seconds>(fallback.expires - fallback.entered));
        fallback_set.push_back(std::move(entry));
    }
    obj.pushKV("fallback_set", std::move(fallback_set));

    UniValue failure_streaks(UniValue::VARR);
    for (const PQStreakStats& streak : stats.failure_streaks) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("endpoint", PQEndpointToUniv(streak.endpoint));
        entry.pushKV("cause", std::string{PQOutcomeString(streak.cause)});
        entry.pushKV("reason", streak.reason);
        entry.pushKV("streak", uint64_t{streak.streak});
        entry.pushKV("last_failure", TicksSinceEpoch<std::chrono::seconds>(streak.last_failure));
        entry.pushKV("next_window_seconds", Ticks<std::chrono::seconds>(streak.next_window));
        failure_streaks.push_back(std::move(entry));
    }
    obj.pushKV("failure_streaks", std::move(failure_streaks));

    UniValue recent_failures(UniValue::VOBJ);
    recent_failures.pushKV("inbound", PQRingToUniv(stats.inbound_failures));
    recent_failures.pushKV("outbound", PQRingToUniv(stats.outbound_failures));
    obj.pushKV("recent_failures", std::move(recent_failures));
    return obj;
},
    };
}

void RegisterNetRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"network", &getconnectioncount},
        {"network", &ping},
        {"network", &getpeerinfo},
        {"network", &getarchivepeers},
        {"network", &addnode},
        {"network", &disconnectnode},
        {"network", &getaddednodeinfo},
        {"network", &getnettotals},
        {"network", &getnetworkinfo},
        {"network", &setban},
        {"network", &listbanned},
        {"network", &clearbanned},
        {"network", &setnetworkactive},
        {"network", &getnodeaddresses},
        {"network", &getaddrmaninfo},
        {"network", &getpqtransportinfo},
        {"hidden", &addconnection},
        {"hidden", &addpeeraddress},
        {"hidden", &sendmsgtopeer},
        {"hidden", &getrawaddrman},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
