#include <config.h>

#include <algorithm>
#include <cctype>
#include <exception>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <unordered_map>

namespace photon {
namespace {

enum class SectionKind {
    kNone,
    kUnknown,
    kLocal,
    kQbitd,
    kPeer,
};

struct SectionState {
    SectionKind kind{SectionKind::kNone};
    std::string raw_name{};
    std::string peer_name{};
};

struct PeerBuilder {
    PeerConfig peer{};
    bool has_host{false};
    bool has_port{false};
    bool has_hmac_key{false};
};

std::string Trim(std::string value)
{
    const auto not_space = [](unsigned char ch) { return !std::isspace(ch); };

    auto begin = std::find_if(value.begin(), value.end(), not_space);
    auto end = std::find_if(value.rbegin(), value.rend(), not_space).base();

    if (begin >= end) {
        return {};
    }

    return std::string(begin, end);
}

bool ParseUint16(const std::string& raw, std::uint16_t& out)
{
    try {
        std::size_t parsed = 0;
        const auto value = std::stoul(raw, &parsed, 10);
        if (parsed != raw.size() || value > std::numeric_limits<std::uint16_t>::max()) {
            return false;
        }
        out = static_cast<std::uint16_t>(value);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool ParseUint32(const std::string& raw, std::uint32_t& out)
{
    try {
        std::size_t parsed = 0;
        const auto value = std::stoull(raw, &parsed, 10);
        if (parsed != raw.size() || value > std::numeric_limits<std::uint32_t>::max()) {
            return false;
        }
        out = static_cast<std::uint32_t>(value);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool HexNibble(char ch, std::uint8_t& nibble)
{
    if (ch >= '0' && ch <= '9') {
        nibble = static_cast<std::uint8_t>(ch - '0');
        return true;
    }
    if (ch >= 'a' && ch <= 'f') {
        nibble = static_cast<std::uint8_t>(ch - 'a' + 10);
        return true;
    }
    if (ch >= 'A' && ch <= 'F') {
        nibble = static_cast<std::uint8_t>(ch - 'A' + 10);
        return true;
    }

    return false;
}

bool ParseHex64(const std::string& raw, std::array<std::uint8_t, 32>& out)
{
    if (raw.size() != 64) {
        return false;
    }

    for (std::size_t i = 0; i < out.size(); ++i) {
        std::uint8_t high = 0;
        std::uint8_t low = 0;
        if (!HexNibble(raw[i * 2], high) || !HexNibble(raw[i * 2 + 1], low)) {
            return false;
        }
        out[i] = static_cast<std::uint8_t>((high << 4) | low);
    }

    return true;
}

std::string MakeError(std::size_t line_number, const std::string& message)
{
    return "line " + std::to_string(line_number) + ": " + message;
}

ConfigLoadResult Fail(std::size_t line_number, const std::string& message)
{
    ConfigLoadResult result{};
    result.error = MakeError(line_number, message);
    result.ok = false;
    return result;
}

ConfigLoadResult FailFinal(const std::string& message)
{
    ConfigLoadResult result{};
    result.error = message;
    result.ok = false;
    return result;
}

void WarnUnknownKey(const std::string& section_name, const std::string& key)
{
    LOG_WARN("Unknown key '" + key + "' in [" + section_name + "]");
}

} // namespace

ConfigLoadResult LoadConfig(const std::string& path)
{
    std::ifstream input(path);
    if (!input.is_open()) {
        return FailFinal("failed to open config file: " + path);
    }

    Config config{};
    SectionState section{};

    bool has_zmq_hashblock = false;
    bool has_rpc_host = false;
    bool has_rpc_port = false;
    bool has_rpc_cookiefile = false;

    std::unordered_map<std::string, std::size_t> peer_indices{};
    std::vector<PeerBuilder> peers{};

    std::string raw_line{};
    std::size_t line_number = 0;

    while (std::getline(input, raw_line)) {
        ++line_number;

        std::string line = Trim(raw_line);
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        if (line.front() == '[') {
            if (line.back() != ']') {
                return Fail(line_number, "invalid section header");
            }

            const std::string section_name = Trim(line.substr(1, line.size() - 2));
            if (section_name.empty()) {
                return Fail(line_number, "empty section name");
            }

            section.raw_name = section_name;
            section.peer_name.clear();

            if (section_name == "local") {
                section.kind = SectionKind::kLocal;
            } else if (section_name == "qbitd") {
                section.kind = SectionKind::kQbitd;
            } else if (section_name.rfind("peer.", 0) == 0) {
                const std::string peer_name = section_name.substr(5);
                if (peer_name.empty()) {
                    return Fail(line_number, "peer section must include a name");
                }

                section.kind = SectionKind::kPeer;
                section.peer_name = peer_name;

                if (peer_indices.find(peer_name) == peer_indices.end()) {
                    PeerBuilder builder{};
                    builder.peer.name = peer_name;
                    peers.push_back(builder);
                    peer_indices.emplace(peer_name, peers.size() - 1);
                }
            } else {
                section.kind = SectionKind::kUnknown;
                LOG_WARN("Unknown section [" + section_name + "] ignored");
            }

            continue;
        }

        const auto equal_pos = line.find('=');
        if (equal_pos == std::string::npos) {
            return Fail(line_number, "expected key=value assignment");
        }

        const std::string key = Trim(line.substr(0, equal_pos));
        const std::string value = Trim(line.substr(equal_pos + 1));

        if (key.empty()) {
            return Fail(line_number, "empty key");
        }

        if (value.empty()) {
            return Fail(line_number, "empty value for key '" + key + "'");
        }

        switch (section.kind) {
        case SectionKind::kLocal: {
            if (key == "bind_port") {
                std::uint16_t parsed_port = 0;
                if (!ParseUint16(value, parsed_port) || parsed_port == 0) {
                    return Fail(line_number, "invalid [local].bind_port");
                }
                config.local.bind_port = parsed_port;
            } else if (key == "log_level") {
                const auto parsed_level = logging::ParseLogLevel(value);
                if (!parsed_level.has_value()) {
                    return Fail(line_number, "invalid [local].log_level");
                }
                config.local.log_level = *parsed_level;
            } else {
                WarnUnknownKey(section.raw_name, key);
            }
            break;
        }
        case SectionKind::kQbitd: {
            if (key == "zmq_hashblock") {
                config.qbitd.zmq_hashblock = value;
                has_zmq_hashblock = true;
            } else if (key == "zmq_sequence") {
                config.qbitd.zmq_sequence = value;
            } else if (key == "rpc_host") {
                config.qbitd.rpc_host = value;
                has_rpc_host = true;
            } else if (key == "rpc_port") {
                std::uint16_t parsed_port = 0;
                if (!ParseUint16(value, parsed_port) || parsed_port == 0) {
                    return Fail(line_number, "invalid [qbitd].rpc_port");
                }
                config.qbitd.rpc_port = parsed_port;
                has_rpc_port = true;
            } else if (key == "rpc_cookiefile") {
                config.qbitd.rpc_cookiefile = value;
                has_rpc_cookiefile = true;
            } else if (key == "rpc_timeout_ms") {
                std::uint32_t timeout_ms = 0;
                if (!ParseUint32(value, timeout_ms) || timeout_ms == 0) {
                    return Fail(line_number, "invalid [qbitd].rpc_timeout_ms");
                }
                config.qbitd.rpc_timeout_ms = timeout_ms;
            } else {
                WarnUnknownKey(section.raw_name, key);
            }
            break;
        }
        case SectionKind::kPeer: {
            auto it = peer_indices.find(section.peer_name);
            if (it == peer_indices.end()) {
                return Fail(line_number, "internal error: unknown peer section");
            }

            PeerBuilder& builder = peers[it->second];
            if (key == "host") {
                builder.peer.host = value;
                builder.has_host = true;
            } else if (key == "port") {
                std::uint16_t parsed_port = 0;
                if (!ParseUint16(value, parsed_port) || parsed_port == 0) {
                    return Fail(line_number, "invalid [peer." + section.peer_name + "].port");
                }
                builder.peer.port = parsed_port;
                builder.has_port = true;
            } else if (key == "hmac_key") {
                if (!ParseHex64(value, builder.peer.hmac_key)) {
                    return Fail(line_number, "invalid [peer." + section.peer_name + "].hmac_key (expected 64 hex chars)");
                }
                builder.has_hmac_key = true;
            } else {
                WarnUnknownKey(section.raw_name, key);
            }
            break;
        }
        case SectionKind::kUnknown:
            WarnUnknownKey(section.raw_name, key);
            break;
        case SectionKind::kNone:
            return Fail(line_number, "key/value before first section");
        }
    }

    if (!has_zmq_hashblock) {
        return FailFinal("missing required field: [qbitd].zmq_hashblock");
    }
    if (!has_rpc_host) {
        return FailFinal("missing required field: [qbitd].rpc_host");
    }
    if (!has_rpc_port) {
        return FailFinal("missing required field: [qbitd].rpc_port");
    }
    if (!has_rpc_cookiefile) {
        return FailFinal("missing required field: [qbitd].rpc_cookiefile");
    }

    config.peers.reserve(peers.size());
    for (const PeerBuilder& builder : peers) {
        if (!builder.has_host) {
            return FailFinal("missing required field: [peer." + builder.peer.name + "].host");
        }
        if (!builder.has_port) {
            return FailFinal("missing required field: [peer." + builder.peer.name + "].port");
        }
        if (!builder.has_hmac_key) {
            return FailFinal("missing required field: [peer." + builder.peer.name + "].hmac_key");
        }

        config.peers.push_back(builder.peer);
    }

    ConfigLoadResult result{};
    result.config = std::move(config);
    result.ok = true;
    return result;
}

} // namespace photon
