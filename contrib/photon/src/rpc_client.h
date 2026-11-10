#ifndef QBIT_PHOTON_SRC_RPC_CLIENT_H
#define QBIT_PHOTON_SRC_RPC_CLIENT_H

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace photon {

/// Result of handing a block to the node with submitblock.
enum class SubmitOutcome : std::uint8_t {
    kAccepted,     ///< The node accepted the block (null result).
    kDuplicate,    ///< The node already had the block.
    kInconclusive, ///< The node stored the block but did not (yet) make it part of its best chain.
    kRejected,     ///< The node rejected the block (BIP22 reason or block decode error).
    kTimeout,      ///< No usable response: timeout, connection failure or a malformed HTTP reply.
    kError,        ///< The node answered with an error that is not a verdict on the block.
};

/// Where a block's parent sits relative to the node's best chain.
enum class ParentCheck : std::uint8_t {
    kNearTip,     ///< The parent is the best block, or close enough to it by depth and chain work.
    kTooFar,      ///< The parent is known but too far below the best block.
    kUnknown,      ///< The node does not know the parent.
    kUnavailable,  ///< The node could not be queried; nothing is known about the parent.
    kAlreadyKnown, ///< The node already has the block itself on its best chain.
    kNodeBehind,   ///< The parent is above the node's best block on a branch with more work: the node is catching up.
};

[[nodiscard]] const char* SubmitOutcomeName(SubmitOutcome outcome);
[[nodiscard]] const char* ParentCheckName(ParentCheck check);

struct RpcClientOptions {
    std::string host{"127.0.0.1"};
    std::uint16_t port{8352};
    std::string cookie_file{};
    std::chrono::milliseconds timeout{std::chrono::milliseconds{5000}};
};

class RpcClient {
public:
    explicit RpcClient(RpcClientOptions options);

    bool Probe();
    std::optional<std::vector<std::uint8_t>> GetBlock(const std::string& hash_hex);
    SubmitOutcome SubmitBlock(std::span<const std::uint8_t> block_data);

    /// Locates block `block_hash_hex`'s parent `prev_hash_hex` (both 64 hex digits, display order)
    /// relative to the node's best chain. kNearTip means the parent is the best block, an ancestor
    /// of it at most `max_depth` blocks deep, or a block on another branch, not above the best
    /// block, with at least as much chain work as the best chain's block `max_depth` below the
    /// best block. Takes one call when the parent is the best block and at most six otherwise,
    /// all within one RPC timeout.
    ParentCheck CheckParent(const std::string& block_hash_hex, const std::string& prev_hash_hex, std::uint32_t max_depth);

private:
    struct HttpResponse {
        int status_code{0};
        std::string body{};
    };

    struct RpcReply {
        enum class Status {
            kResult,      ///< HTTP 200 with a null error; body holds the reply.
            kRpcError,    ///< The node returned a JSON-RPC error object.
            kNoResponse,  ///< Connection, send or receive failure, or timeout.
            kBadResponse, ///< A reply that is neither a result nor a JSON-RPC error.
        };

        Status status{Status::kNoResponse};
        std::string body{};
        std::optional<std::int64_t> error_code{};
    };

    struct HeaderInfo {
        std::int64_t confirmations{0};
        std::int64_t height{0};
        std::string chainwork{};
    };

    using Deadline = std::chrono::steady_clock::time_point;

    RpcReply Call(const std::string& method, const std::string& params_json);
    RpcReply Call(const std::string& method, const std::string& params_json, Deadline deadline);
    std::optional<std::string> CallForHash(const std::string& method, const std::string& params_json, Deadline deadline);
    std::optional<HeaderInfo> ParseHeaderInfo(const RpcReply& reply) const;

    std::optional<HttpResponse> SendJsonRpc(const std::string& method, const std::string& params_json);
    std::optional<HttpResponse> SendJsonRpc(const std::string& method, const std::string& params_json, Deadline deadline);
    std::optional<HttpResponse> SendHttpRequest(const std::string& request_body, Deadline deadline);
    bool LoadCookie();

    RpcClientOptions m_options;
    std::string m_cookie_auth;
    bool m_cookie_loaded{false};
    std::uint64_t m_request_id{0};
};

} // namespace photon

#endif // QBIT_PHOTON_SRC_RPC_CLIENT_H
