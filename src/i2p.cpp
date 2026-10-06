// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/args.h>
#include <compat/compat.h>
#include <compat/endian.h>
#include <crypto/sha256.h>
#include <i2p.h>
#include <logging.h>
#include <netaddress.h>
#include <netbase.h>
#include <random.h>
#include <script/parsing.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/readwritefile.h>
#include <util/sock.h>
#include <util/strencodings.h>
#include <util/threadinterrupt.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

using util::Split;

namespace i2p {

/**
 * Swap Standard Base64 <-> I2P Base64.
 * Standard Base64 uses `+` and `/` as last two characters of its alphabet.
 * I2P Base64 uses `-` and `~` respectively.
 * So it is easy to detect in which one is the input and convert to the other.
 * @param[in] from Input to convert.
 * @return converted `from`
 */
static std::string SwapBase64(const std::string& from)
{
    std::string to;
    to.resize(from.size());
    for (size_t i = 0; i < from.size(); ++i) {
        switch (from[i]) {
        case '-':
            to[i] = '+';
            break;
        case '~':
            to[i] = '/';
            break;
        case '+':
            to[i] = '-';
            break;
        case '/':
            to[i] = '~';
            break;
        default:
            to[i] = from[i];
            break;
        }
    }
    return to;
}

/**
 * Decode an I2P-style Base64 string.
 * @param[in] i2p_b64 I2P-style Base64 string.
 * @return decoded `i2p_b64`
 * @throw std::runtime_error if decoding fails
 */
static Binary DecodeI2PBase64(const std::string& i2p_b64)
{
    const std::string& std_b64 = SwapBase64(i2p_b64);
    auto decoded = DecodeBase64(std_b64);
    if (!decoded) {
        throw std::runtime_error(strprintf("Cannot decode Base64: \"%s\"", i2p_b64));
    }
    return std::move(*decoded);
}

/**
 * Derive the .b32.i2p address of an I2P destination (binary).
 * @param[in] dest I2P destination.
 * @return the address that corresponds to `dest`
 * @throw std::runtime_error if conversion fails
 */
static CNetAddr DestBinToAddr(const Binary& dest)
{
    CSHA256 hasher;
    hasher.Write(dest.data(), dest.size());
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(hash);

    CNetAddr addr;
    const std::string addr_str = EncodeBase32(hash, false) + ".b32.i2p";
    if (!addr.SetSpecial(addr_str)) {
        throw std::runtime_error(strprintf("Cannot parse I2P address: \"%s\"", addr_str));
    }

    return addr;
}

/**
 * Derive the .b32.i2p address of an I2P destination (I2P-style Base64).
 * @param[in] dest I2P destination.
 * @return the address that corresponds to `dest`
 * @throw std::runtime_error if conversion fails
 */
static CNetAddr DestB64ToAddr(const std::string& dest)
{
    const Binary& decoded = DecodeI2PBase64(dest);
    return DestBinToAddr(decoded);
}

namespace sam {

namespace {
/**
 * i2cp.leaseSetEncType for new sessions: the post-quantum hybrid MLKEM768-X25519 (6), and
 * ECIES-X25519 (4) for peers without it.
 */
constexpr std::string_view LEASESET_ENC_TYPES_HYBRID{"6,4"};

/**
 * i2cp.leaseSetEncType for routers that reject the hybrid type: ECIES-X25519 (4) and ElGamal (0).
 */
constexpr std::string_view LEASESET_ENC_TYPES_LEGACY{"4,0"};

/**
 * Longest part of a router-supplied RESULT= or MESSAGE= value that is logged.
 */
constexpr size_t MAX_LOGGED_REPLY_VALUE{200};

/**
 * qbit-only: what is known about a SAM router's support for i2cp.leaseSetEncType=6,4.
 */
struct RouterHybridState {
    /**
     * Sessions in a row in which the router rejected 6,4 naming the encryption type and accepted
     * 4,0. Sessions in which the rejection did not name it are not counted and do not break the row.
     */
    unsigned fallbacks{0};
    /** Whether the warning about the router was logged. */
    bool warned{false};
    /** Position of the latest update among all updates, to forget the oldest router. */
    uint64_t updated{0};
};

/**
 * qbit-only: `RouterHybridState` of SAM routers, by `Proxy::ToString()` (TCP endpoint or Unix
 * socket path). Kept for the process lifetime and shared by all sessions, so that later sessions
 * through a router (e.g. transient ones) start with 4,0 once it has rejected 6,4 naming the
 * encryption type in `SAM_HYBRID_FALLBACKS_TO_REMEMBER` sessions in a row. Only such rejections
 * add a router. At most `SAM_MAX_REMEMBERED_ROUTERS` routers are kept, so a forgotten router may
 * be warned about again.
 */
GlobalMutex g_router_hybrid_mutex;
std::map<std::string, RouterHybridState> g_router_hybrid GUARDED_BY(g_router_hybrid_mutex);
uint64_t g_router_hybrid_updates GUARDED_BY(g_router_hybrid_mutex){0};

/**
 * Whether sessions through `router` start with 4,0 without asking for 6,4.
 */
bool RouterLacksHybrid(const std::string& router)
{
    LOCK(g_router_hybrid_mutex);
    const auto it{g_router_hybrid.find(router)};
    return it != g_router_hybrid.end() && it->second.fallbacks >= SAM_HYBRID_FALLBACKS_TO_REMEMBER;
}

/**
 * A session through `router` was created with 6,4: its rejections so far were not in a row.
 */
void NoteHybridAccepted(const std::string& router)
{
    LOCK(g_router_hybrid_mutex);
    const auto it{g_router_hybrid.find(router)};
    if (it != g_router_hybrid.end()) {
        it->second.fallbacks = 0;
        it->second.updated = ++g_router_hybrid_updates;
    }
}

struct HybridFallbackNoted {
    /** This is the first such session through the router: warn about it. */
    bool warn;
    /** From now on sessions through the router start with 4,0. */
    bool remembered;
};

/**
 * A session through `router` was created with 4,0 after the router rejected 6,4 naming the
 * encryption type (see `NamesEncType()`), evidence that it lacks 6,4. A rejection that does not
 * name it may be a passing router error and must not be noted here.
 */
HybridFallbackNoted NoteHybridFallback(const std::string& router)
{
    LOCK(g_router_hybrid_mutex);
    auto it{g_router_hybrid.find(router)};
    if (it == g_router_hybrid.end()) {
        if (g_router_hybrid.size() >= SAM_MAX_REMEMBERED_ROUTERS) {
            g_router_hybrid.erase(std::ranges::min_element(g_router_hybrid, {}, [](const auto& entry) { return entry.second.updated; }));
        }
        it = g_router_hybrid.emplace(router, RouterHybridState{}).first;
    }
    RouterHybridState& state{it->second};
    state.updated = ++g_router_hybrid_updates;
    const bool was_remembered{state.fallbacks >= SAM_HYBRID_FALLBACKS_TO_REMEMBER};
    state.fallbacks = std::min(state.fallbacks + 1, SAM_HYBRID_FALLBACKS_TO_REMEMBER);
    return {.warn = !std::exchange(state.warned, true),
            .remembered = !was_remembered && state.fallbacks >= SAM_HYBRID_FALLBACKS_TO_REMEMBER};
}

/**
 * Whether a non-OK RESULT of "SESSION STATUS" can be about the leaseset encryption type.
 * These cannot: the session id or the destination is the problem.
 */
bool MayBeEncTypeRejection(std::string_view result)
{
    return result != "DUPLICATED_ID" && result != "DUPLICATED_DEST" && result != "INVALID_ID" &&
           result != "INVALID_KEY";
}

/**
 * `result` if it is one of the RESULT values of the SAM v3 protocol, otherwise "other".
 */
std::string_view KnownSamResult(std::string_view result)
{
    static constexpr std::array known{
        "OK", "CANT_REACH_PEER", "DUPLICATED_ID", "DUPLICATED_DEST", "I2P_ERROR",
        "INVALID_ID", "INVALID_KEY", "KEY_NOT_FOUND", "PEER_NOT_FOUND", "TIMEOUT",
        "NOVERSION", "LEASESET_NOT_FOUND", "ALREADY_ACCEPTING"};
    return std::ranges::find(known, result) != known.end() ? result : "other";
}

/**
 * Router-supplied text, made safe and short enough for the log.
 */
std::string LoggableReplyValue(std::string_view value)
{
    return SanitizeString(value.substr(0, MAX_LOGGED_REPLY_VALUE));
}

/**
 * The MESSAGE= value of a SAM reply, which may be quoted and contain spaces. It is router text, not
 * safe for the log as is.
 */
std::string_view ReplyMessage(std::string_view reply)
{
    static constexpr std::string_view key{" MESSAGE="};
    const auto pos{reply.find(key)};
    if (pos == std::string_view::npos) {
        return "";
    }
    std::string_view value{reply.substr(pos + key.size())};
    if (value.starts_with('"')) {
        value.remove_prefix(1);
        return value.substr(0, value.find('"'));
    }
    return value.substr(0, value.find(' '));
}

/**
 * The MESSAGE= value of a SAM reply, which may be quoted and contain spaces, ready for the log.
 */
std::string LoggableReplyMessage(std::string_view reply)
{
    return LoggableReplyValue(ReplyMessage(reply));
}

/**
 * Whether the MESSAGE= value of a rejection names the encryption type, as Java I2P older than
 * 2.10.0 does when asked for 6,4: "... Unsupported crypto type: 6". Only that is evidence that
 * the router lacks 6,4; another rejection may be a passing router error. Matched before the
 * value is sanitized or capped for the log, and case-insensitively for ASCII.
 */
bool NamesEncType(std::string_view message)
{
    static constexpr std::array<std::string_view, 4> phrases{"crypto type", "encryption type", "enc type", "enctype"};
    const std::string lower{ToLower(message)};
    return std::ranges::any_of(phrases, [&](std::string_view phrase) { return lower.find(phrase) != std::string::npos; });
}
} // namespace

void ResetRouterHybridStateForTest()
{
    LOCK(g_router_hybrid_mutex);
    g_router_hybrid.clear();
    g_router_hybrid_updates = 0;
}

Session::Session(const fs::path& private_key_file,
                 const Proxy& control_host,
                 CThreadInterrupt* interrupt,
                 std::chrono::steady_clock::duration create_timeout)
    : m_private_key_file{private_key_file},
      m_control_host{control_host},
      m_interrupt{interrupt},
      m_create_timeout{create_timeout},
      m_transient{false}
{
}

Session::Session(const Proxy& control_host,
                 CThreadInterrupt* interrupt,
                 std::chrono::steady_clock::duration create_timeout)
    : m_control_host{control_host},
      m_interrupt{interrupt},
      m_create_timeout{create_timeout},
      m_transient{true}
{
}

Session::~Session()
{
    LOCK(m_mutex);
    Disconnect();
}

bool Session::Listen(Connection& conn)
{
    try {
        LOCK(m_mutex);
        CreateIfNotCreatedAlready();
        conn.me = m_my_addr;
        conn.sock = StreamAccept();
        return true;
    } catch (const std::runtime_error& e) {
        LogPrintLevel(BCLog::I2P, BCLog::Level::Error, "Couldn't listen: %s\n", e.what());
        CheckControlSock();
    }
    return false;
}

bool Session::Accept(Connection& conn)
{
    AssertLockNotHeld(m_mutex);

    std::string errmsg;
    bool disconnect{false};

    while (!*m_interrupt) {
        Sock::Event occurred;
        if (!conn.sock->Wait(MAX_WAIT_FOR_IO, Sock::RECV, &occurred)) {
            errmsg = "wait on socket failed";
            break;
        }

        if (occurred == 0) {
            // Timeout, no incoming connections or errors within MAX_WAIT_FOR_IO.
            continue;
        }

        std::string peer_dest;
        try {
            peer_dest = conn.sock->RecvUntilTerminator('\n', MAX_WAIT_FOR_IO, *m_interrupt, MAX_MSG_SIZE);
        } catch (const std::runtime_error& e) {
            errmsg = e.what();
            break;
        }

        CNetAddr peer_addr;
        try {
            peer_addr = DestB64ToAddr(peer_dest);
        } catch (const std::runtime_error& e) {
            // The I2P router is expected to send the Base64 of the connecting peer,
            // but it may happen that something like this is sent instead:
            // STREAM STATUS RESULT=I2P_ERROR MESSAGE="Session was closed"
            // In that case consider the session damaged and close it right away,
            // even if the control socket is alive.
            if (peer_dest.find("RESULT=I2P_ERROR") != std::string::npos) {
                errmsg = strprintf("unexpected reply that hints the session is unusable: %s", peer_dest);
                disconnect = true;
            } else {
                errmsg = e.what();
            }
            break;
        }

        conn.peer = CService(peer_addr, I2P_SAM31_PORT);

        return true;
    }

    if (*m_interrupt) {
        LogPrintLevel(BCLog::I2P, BCLog::Level::Debug, "Accept was interrupted\n");
    } else {
        LogPrintLevel(BCLog::I2P, BCLog::Level::Debug, "Error accepting%s: %s\n", disconnect ? " (will close the session)" : "", errmsg);
    }
    if (disconnect) {
        LOCK(m_mutex);
        Disconnect();
    } else {
        CheckControlSock();
    }
    return false;
}

bool Session::Connect(const CService& to, Connection& conn, bool& proxy_error)
{
    // Refuse connecting to arbitrary ports. We don't specify any destination port to the SAM proxy
    // when connecting (SAM 3.1 does not use ports) and it forces/defaults it to I2P_SAM31_PORT.
    if (to.GetPort() != I2P_SAM31_PORT) {
        LogPrintLevel(BCLog::I2P, BCLog::Level::Debug, "Error connecting to %s, connection refused due to arbitrary port %s\n", to.ToStringAddrPort(), to.GetPort());
        proxy_error = false;
        return false;
    }

    proxy_error = true;

    std::string session_id;
    std::unique_ptr<Sock> sock;
    conn.peer = to;

    try {
        {
            LOCK(m_mutex);
            CreateIfNotCreatedAlready();
            session_id = m_session_id;
            conn.me = m_my_addr;
            sock = Hello();
        }

        const Reply& lookup_reply =
            SendRequestAndGetReply(*sock, strprintf("NAMING LOOKUP NAME=%s", to.ToStringAddr()));

        const std::string& dest = lookup_reply.Get("VALUE");

        const Reply& connect_reply = SendRequestAndGetReply(
            *sock, strprintf("STREAM CONNECT ID=%s DESTINATION=%s SILENT=false", session_id, dest),
            false);

        const std::string& result = connect_reply.Get("RESULT");

        if (result == "OK") {
            conn.sock = std::move(sock);
            return true;
        }

        if (result == "INVALID_ID") {
            LOCK(m_mutex);
            Disconnect();
            throw std::runtime_error("Invalid session id");
        }

        if (result == "CANT_REACH_PEER" || result == "TIMEOUT") {
            proxy_error = false;
        }

        throw std::runtime_error(strprintf("\"%s\"", connect_reply.full));
    } catch (const std::runtime_error& e) {
        LogPrintLevel(BCLog::I2P, BCLog::Level::Debug, "Error connecting to %s: %s\n", to.ToStringAddrPort(), e.what());
        CheckControlSock();
        return false;
    }
}

// Private methods

std::string Session::Reply::Get(const std::string& key) const
{
    const auto& pos = keys.find(key);
    if (pos == keys.end() || !pos->second.has_value()) {
        throw std::runtime_error(
            strprintf("Missing %s= in the reply to \"%s\": \"%s\"", key, request, full));
    }
    return pos->second.value();
}

Session::Reply Session::SendRequestAndGetReply(const Sock& sock,
                                               const std::string& request,
                                               bool check_result_ok) const
{
    return SendRequestAndGetReply(sock, request, check_result_ok, SAMDeadline::max());
}

Session::Reply Session::SendRequestAndGetReply(const Sock& sock,
                                               const std::string& request,
                                               bool check_result_ok,
                                               SAMDeadline deadline) const
{
    Reply reply;

    // Don't log the full "SESSION CREATE ..." because it contains our private key.
    reply.request = request.starts_with("SESSION CREATE") ? "SESSION CREATE ..." : request;

    const auto time_left = [&]() -> std::chrono::milliseconds {
        const auto now{std::chrono::steady_clock::now()};
        if (now >= deadline) {
            throw std::runtime_error(strprintf("Timed out during \"%s\"", reply.request));
        }
        return std::chrono::ceil<std::chrono::milliseconds>(deadline - now);
    };

    sock.SendComplete(request + "\n", std::min<std::chrono::milliseconds>(MAX_WAIT_FOR_IO, time_left()), *m_interrupt);

    // It could take a few minutes for the I2P router to reply as it is querying the I2P network
    // (when doing name lookup, for example). Notice: `RecvUntilTerminator()` is checking
    // `m_interrupt` more often, so we would not be stuck here for long if `m_interrupt` is
    // signaled.
    static constexpr auto recv_timeout = 3min;

    reply.full = sock.RecvUntilTerminator('\n', std::min<std::chrono::milliseconds>(recv_timeout, time_left()), *m_interrupt, MAX_MSG_SIZE);

    for (const auto& kv : Split(reply.full, ' ')) {
        const auto pos{std::ranges::find(kv, '=')};
        if (pos != kv.end()) {
            reply.keys.emplace(std::string{kv.begin(), pos}, std::string{pos + 1, kv.end()});
        } else {
            reply.keys.emplace(std::string{kv.begin(), kv.end()}, std::nullopt);
        }
    }

    if (check_result_ok && reply.Get("RESULT") != "OK") {
        throw std::runtime_error(
            strprintf("Unexpected reply to \"%s\": \"%s\"", reply.request, reply.full));
    }

    return reply;
}

std::unique_ptr<Sock> Session::Hello() const
{
    auto sock = m_control_host.Connect();

    if (!sock) {
        throw std::runtime_error(strprintf("Cannot connect to %s", m_control_host.ToString()));
    }

    SendRequestAndGetReply(*sock, "HELLO VERSION MIN=3.1 MAX=3.1");

    return sock;
}

std::unique_ptr<Sock> Session::Hello(SAMDeadline deadline) const
{
    // Like Proxy::Connect() without a deadline, give up connecting after -timeout.
    const SAMDeadline connect_deadline{
        std::min(deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds{nConnectTimeout})};

    auto sock = m_control_host.Connect(connect_deadline, *m_interrupt);

    if (!sock) {
        if (*m_interrupt) {
            throw std::runtime_error(strprintf("Interrupted while connecting to %s", m_control_host.ToString()));
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            throw std::runtime_error(strprintf("Timed out connecting to %s", m_control_host.ToString()));
        }
        throw std::runtime_error(strprintf("Cannot connect to %s", m_control_host.ToString()));
    }

    SendRequestAndGetReply(*sock, "HELLO VERSION MIN=3.1 MAX=3.1", /*check_result_ok=*/true, deadline);

    return sock;
}

void Session::CheckControlSock()
{
    LOCK(m_mutex);

    std::string errmsg;
    if (m_control_sock && !m_control_sock->IsConnected(errmsg)) {
        LogPrintLevel(BCLog::I2P, BCLog::Level::Debug, "Control socket error: %s\n", errmsg);
        Disconnect();
    }
}

void Session::DestGenerate(const Sock& sock, SAMDeadline deadline)
{
    // https://geti2p.net/spec/common-structures#key-certificates
    // "7" or "EdDSA_SHA512_Ed25519" - "Recent Router Identities and Destinations".
    // Use "7" because i2pd <2.24.0 does not recognize the textual form.
    // If SIGNATURE_TYPE is not specified, then the default one is DSA_SHA1.
    const Reply& reply = SendRequestAndGetReply(sock, "DEST GENERATE SIGNATURE_TYPE=7", false, deadline);

    m_private_key = DecodeI2PBase64(reply.Get("PRIV"));
}

void Session::GenerateAndSavePrivateKey(const Sock& sock, SAMDeadline deadline)
{
    DestGenerate(sock, deadline);

    // umask is set to 0077 in common/system.cpp, which is ok.
    if (!WriteBinaryFile(m_private_key_file,
                         std::string(m_private_key.begin(), m_private_key.end()))) {
        throw std::runtime_error(
            strprintf("Cannot save I2P private key to %s", fs::quoted(fs::PathToString(m_private_key_file))));
    }
}

Binary Session::MyDestination() const
{
    // From https://geti2p.net/spec/common-structures#destination:
    // "They are 387 bytes plus the certificate length specified at bytes 385-386, which may be
    // non-zero"
    static constexpr size_t DEST_LEN_BASE = 387;
    static constexpr size_t CERT_LEN_POS = 385;

    uint16_t cert_len;

    if (m_private_key.size() < CERT_LEN_POS + sizeof(cert_len)) {
        throw std::runtime_error(strprintf("The private key is too short (%d < %d)",
                                           m_private_key.size(),
                                           CERT_LEN_POS + sizeof(cert_len)));
    }

    memcpy(&cert_len, &m_private_key.at(CERT_LEN_POS), sizeof(cert_len));
    cert_len = be16toh_internal(cert_len);

    const size_t dest_len = DEST_LEN_BASE + cert_len;

    if (dest_len > m_private_key.size()) {
        throw std::runtime_error(strprintf("Certificate length (%d) designates that the private key should "
                                           "be %d bytes, but it is only %d bytes",
                                           cert_len,
                                           dest_len,
                                           m_private_key.size()));
    }

    return Binary{m_private_key.begin(), m_private_key.begin() + dest_len};
}

void Session::CreateIfNotCreatedAlready()
{
    std::string errmsg;
    if (m_control_sock && m_control_sock->IsConnected(errmsg)) {
        return;
    }

    const auto session_type = m_transient ? "transient" : "persistent";
    const SAMDeadline deadline{std::chrono::steady_clock::now() + m_create_timeout};
    const std::string router{m_control_host.ToString()};

    bool hybrid{!RouterLacksHybrid(router)};
    if (!hybrid) {
        LogPrintLevel(BCLog::I2P, BCLog::Level::Debug, "%s rejected leaseSetEncType=%s in earlier sessions, using %s\n",
                      router, LEASESET_ENC_TYPES_HYBRID, LEASESET_ENC_TYPES_LEGACY);
    }
    // The rejection of 6,4, if this is the retry with 4,0.
    struct HybridRejection {
        std::string result;
        /** MESSAGE=, ready for the log. */
        std::string message;
        /** Whether MESSAGE= names the encryption type, see `NamesEncType()`. */
        bool names_enc_type;
    };
    std::optional<HybridRejection> hybrid_rejection;

    // Our persistent destination (private key), read or generated once and kept for a retry.
    std::optional<std::string> private_key_b64;

    for (unsigned attempt{1};; ++attempt) {
        const auto session_id = GetRandHash().GetHex().substr(0, 10); // full is overkill, too verbose in the logs
        const std::string_view enc_types{hybrid ? LEASESET_ENC_TYPES_HYBRID : LEASESET_ENC_TYPES_LEGACY};

        LogPrintLevel(BCLog::I2P, BCLog::Level::Debug, "Creating %s SAM session %s with %s\n", session_type, session_id, router);

        auto sock = Hello(deadline);

        std::string request;
        if (m_transient) {
            // The destination (private key) is generated upon session creation and returned
            // in the reply in DESTINATION=.
            request = strprintf("SESSION CREATE STYLE=STREAM ID=%s DESTINATION=TRANSIENT SIGNATURE_TYPE=7 "
                                "i2cp.leaseSetEncType=%s inbound.quantity=1 outbound.quantity=1",
                                session_id,
                                enc_types);
        } else {
            if (!private_key_b64) {
                // Read our persistent destination (private key) from disk or generate
                // one and save it to disk. Then use it when creating the session.
                const auto& [read_ok, data] = ReadBinaryFile(m_private_key_file);
                if (read_ok) {
                    m_private_key.assign(data.begin(), data.end());
                } else {
                    GenerateAndSavePrivateKey(*sock, deadline);
                }
                private_key_b64 = SwapBase64(EncodeBase64(m_private_key));
            }
            request = strprintf("SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s "
                                "i2cp.leaseSetEncType=%s inbound.quantity=3 outbound.quantity=3",
                                session_id,
                                *private_key_b64,
                                enc_types);
        }

        const Reply reply = SendRequestAndGetReply(*sock, request, /*check_result_ok=*/false, deadline);

        // A reply without RESULT= is not a rejection, this throws.
        const std::string result{reply.Get("RESULT")};

        if (result == "OK") {
            if (m_transient) {
                m_private_key = DecodeI2PBase64(reply.Get("DESTINATION"));
            }
            const CService my_addr{DestBinToAddr(MyDestination()), I2P_SAM31_PORT};

            m_my_addr = my_addr;
            m_session_id = session_id;
            m_control_sock = std::move(sock);
            break;
        }

        // qbit-only, upstream Bitcoin Core does not retry: Java I2P older than 2.10.0 fails the
        // session if asked for the hybrid type, so retry once without it. Any explicit rejection,
        // a well-formed "SESSION STATUS" whose RESULT may be about the encryption type (including
        // RESULT=TIMEOUT), is retried; whether it counts against the router is decided below. No
        // reply (a timeout waiting for one, EOF, a socket error) or a malformed reply never is.
        const bool retry{hybrid && attempt < SAM_CREATE_MAX_ATTEMPTS &&
                         reply.full.starts_with("SESSION STATUS ") && !result.empty() &&
                         MayBeEncTypeRejection(result)};
        if (!retry) {
            throw std::runtime_error(strprintf("Unexpected reply to \"%s\": \"%s\"", reply.request, reply.full));
        }

        hybrid_rejection = HybridRejection{.result = result,
                                           .message = LoggableReplyMessage(reply.full),
                                           .names_enc_type = NamesEncType(ReplyMessage(reply.full))};

        LogPrintLevel(BCLog::I2P, BCLog::Level::Debug,
                      "%s rejected SAM session %s with leaseSetEncType=%s: RESULT=%s MESSAGE=\"%s\", retrying with %s\n",
                      router,
                      session_id,
                      LEASESET_ENC_TYPES_HYBRID,
                      LoggableReplyValue(result),
                      hybrid_rejection->message,
                      LEASESET_ENC_TYPES_LEGACY);

        hybrid = false;
        // `sock` is closed here, the retry uses a fresh connection, HELLO and session id.
    }

    if (hybrid_rejection && hybrid_rejection->names_enc_type) {
        // Only such rejections in a row turn 6,4 off for the router: one may be a transient error.
        const auto noted{NoteHybridFallback(router)};
        if (noted.warn) {
            LogWarning("I2P: the router rejected leaseSetEncType=6,4 (RESULT=%s) and accepted 4,0, so this session has no post-quantum leaseset. Java I2P older than 2.10.0 does this; upgrade the router to get it.\n",
                       KnownSamResult(hybrid_rejection->result));
        }
        if (noted.remembered) {
            LogPrintLevel(BCLog::I2P, BCLog::Level::Info,
                          "%s rejected leaseSetEncType=%s and accepted %s in %u sessions in a row, later sessions through it use %s until qbit restarts\n",
                          router,
                          LEASESET_ENC_TYPES_HYBRID,
                          LEASESET_ENC_TYPES_LEGACY,
                          SAM_HYBRID_FALLBACKS_TO_REMEMBER,
                          LEASESET_ENC_TYPES_LEGACY);
        }
    } else if (hybrid_rejection) {
        // A rejection that does not name the encryption type may be a passing router error
        // (e.g. failing to build tunnels): it is no evidence either way, so the count of
        // rejections in a row neither grows nor starts anew, and there is no warning.
        LogPrintLevel(BCLog::I2P, BCLog::Level::Info,
                      "%s SAM session %s uses leaseSetEncType=%s because %s rejected %s with RESULT=%s MESSAGE=\"%s\", which does not name the encryption type; the next session asks for %s again\n",
                      Capitalize(session_type),
                      m_session_id,
                      LEASESET_ENC_TYPES_LEGACY,
                      router,
                      LEASESET_ENC_TYPES_HYBRID,
                      KnownSamResult(hybrid_rejection->result),
                      hybrid_rejection->message,
                      LEASESET_ENC_TYPES_HYBRID);
    } else if (hybrid) {
        NoteHybridAccepted(router);
    }

    LogPrintLevel(BCLog::I2P, BCLog::Level::Info, "%s SAM session %s created, my address=%s\n",
        Capitalize(session_type),
        m_session_id,
        m_my_addr.ToStringAddrPort());
}

std::unique_ptr<Sock> Session::StreamAccept()
{
    auto sock = Hello();

    const Reply& reply = SendRequestAndGetReply(
        *sock, strprintf("STREAM ACCEPT ID=%s SILENT=false", m_session_id), false);

    const std::string& result = reply.Get("RESULT");

    if (result == "OK") {
        return sock;
    }

    if (result == "INVALID_ID") {
        // If our session id is invalid, then force session re-creation on next usage.
        Disconnect();
    }

    throw std::runtime_error(strprintf("\"%s\"", reply.full));
}

void Session::Disconnect()
{
    if (m_control_sock) {
        if (m_session_id.empty()) {
            LogPrintLevel(BCLog::I2P, BCLog::Level::Info, "Destroying incomplete SAM session\n");
        } else {
            LogPrintLevel(BCLog::I2P, BCLog::Level::Info, "Destroying SAM session %s\n", m_session_id);
        }
        m_control_sock.reset();
    }
    m_session_id.clear();
}
} // namespace sam
} // namespace i2p
