#include <rpc_client.h>

#include <logging.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <charconv>
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace photon {
namespace {

enum class JsonFieldKind {
    kMissing,
    kNull,
    kString,
    kOther,
};

struct JsonField {
    JsonFieldKind kind{JsonFieldKind::kMissing};
    std::string string_value{};
};

std::string Trim(std::string value)
{
    const auto is_not_space = [](unsigned char ch) { return !std::isspace(ch); };
    auto begin = std::find_if(value.begin(), value.end(), is_not_space);
    auto end = std::find_if(value.rbegin(), value.rend(), is_not_space).base();
    if (begin >= end) {
        return {};
    }

    return std::string(begin, end);
}

std::string Base64Encode(std::string_view input)
{
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 2 < input.size()) {
        const std::uint32_t chunk =
            (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16)
            | (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1])) << 8)
            | static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 2]));

        out.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 6) & 0x3F]);
        out.push_back(kAlphabet[chunk & 0x3F]);
        i += 3;
    }

    const std::size_t tail = input.size() - i;
    if (tail == 1) {
        const std::uint32_t chunk = static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16;
        out.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (tail == 2) {
        const std::uint32_t chunk =
            (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16)
            | (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1])) << 8);
        out.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 6) & 0x3F]);
        out.push_back('=');
    }

    return out;
}

char HexDigit(std::uint8_t value)
{
    static constexpr char kHex[] = "0123456789abcdef";
    return kHex[value & 0x0F];
}

std::string HexEncode(std::span<const std::uint8_t> bytes)
{
    std::string out;
    out.reserve(bytes.size() * 2);

    for (const std::uint8_t byte : bytes) {
        out.push_back(HexDigit(byte >> 4));
        out.push_back(HexDigit(byte));
    }

    return out;
}

bool ParseHexByte(char ch, std::uint8_t& out)
{
    if (ch >= '0' && ch <= '9') {
        out = static_cast<std::uint8_t>(ch - '0');
        return true;
    }
    if (ch >= 'a' && ch <= 'f') {
        out = static_cast<std::uint8_t>(ch - 'a' + 10);
        return true;
    }
    if (ch >= 'A' && ch <= 'F') {
        out = static_cast<std::uint8_t>(ch - 'A' + 10);
        return true;
    }

    return false;
}

std::optional<std::vector<std::uint8_t>> HexDecode(const std::string& hex)
{
    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        std::uint8_t high = 0;
        std::uint8_t low = 0;
        if (!ParseHexByte(hex[i * 2], high) || !ParseHexByte(hex[i * 2 + 1], low)) {
            return std::nullopt;
        }

        out[i] = static_cast<std::uint8_t>((high << 4) | low);
    }

    return out;
}

int ParseStatusCode(const std::string& response)
{
    const auto line_end = response.find("\r\n");
    if (line_end == std::string::npos) {
        return 0;
    }

    const std::string status_line = response.substr(0, line_end);
    const auto first_space = status_line.find(' ');
    if (first_space == std::string::npos) {
        return 0;
    }

    const auto second_space = status_line.find(' ', first_space + 1);
    const std::string code =
        status_line.substr(first_space + 1, second_space == std::string::npos ? std::string::npos : second_space - first_space - 1);

    int status = 0;
    const auto parse_result = std::from_chars(code.data(), code.data() + code.size(), status);
    if (parse_result.ec != std::errc{}) {
        return 0;
    }

    return status;
}

std::optional<std::string> ParseJsonString(const std::string& json, std::size_t& cursor)
{
    if (cursor >= json.size() || json[cursor] != '"') {
        return std::nullopt;
    }

    ++cursor;
    std::string out;

    while (cursor < json.size()) {
        const char ch = json[cursor++];
        if (ch == '"') {
            return out;
        }

        if (ch != '\\') {
            out.push_back(ch);
            continue;
        }

        if (cursor >= json.size()) {
            return std::nullopt;
        }

        const char esc = json[cursor++];
        switch (esc) {
        case '"':
            out.push_back('"');
            break;
        case '\\':
            out.push_back('\\');
            break;
        case '/':
            out.push_back('/');
            break;
        case 'b':
            out.push_back('\b');
            break;
        case 'f':
            out.push_back('\f');
            break;
        case 'n':
            out.push_back('\n');
            break;
        case 'r':
            out.push_back('\r');
            break;
        case 't':
            out.push_back('\t');
            break;
        case 'u':
            if (cursor + 4 > json.size()) {
                return std::nullopt;
            }
            cursor += 4;
            out.push_back('?');
            break;
        default:
            return std::nullopt;
        }
    }

    return std::nullopt;
}

JsonField ExtractJsonField(const std::string& json, const std::string& field_name)
{
    const std::string key = '"' + field_name + '"';
    const auto key_pos = json.find(key);
    if (key_pos == std::string::npos) {
        return JsonField{JsonFieldKind::kMissing, {}};
    }

    auto colon_pos = json.find(':', key_pos + key.size());
    if (colon_pos == std::string::npos) {
        return JsonField{JsonFieldKind::kMissing, {}};
    }

    ++colon_pos;
    while (colon_pos < json.size() && std::isspace(static_cast<unsigned char>(json[colon_pos]))) {
        ++colon_pos;
    }

    if (colon_pos >= json.size()) {
        return JsonField{JsonFieldKind::kMissing, {}};
    }

    if (json.compare(colon_pos, 4, "null") == 0) {
        return JsonField{JsonFieldKind::kNull, {}};
    }

    if (json[colon_pos] == '"') {
        std::size_t cursor = colon_pos;
        const auto parsed = ParseJsonString(json, cursor);
        if (!parsed.has_value()) {
            return JsonField{JsonFieldKind::kMissing, {}};
        }
        return JsonField{JsonFieldKind::kString, *parsed};
    }

    return JsonField{JsonFieldKind::kOther, {}};
}

bool SendAll(int fd, const std::string& payload)
{
    std::size_t sent = 0;

#if defined(MSG_NOSIGNAL)
    constexpr int kSendFlags = MSG_NOSIGNAL;
#else
    constexpr int kSendFlags = 0;
#endif

    while (sent < payload.size()) {
        const ssize_t bytes = send(fd, payload.data() + sent, payload.size() - sent, kSendFlags);
        if (bytes < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (bytes == 0) {
            return false;
        }
        sent += static_cast<std::size_t>(bytes);
    }

    return true;
}

std::optional<std::string> ReadResponse(int fd)
{
    std::string out;
    std::array<char, 4096> buffer{};

    while (true) {
        const ssize_t bytes = recv(fd, buffer.data(), buffer.size(), 0);
        if (bytes == 0) {
            break;
        }
        if (bytes < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return std::nullopt;
            }
            return std::nullopt;
        }

        out.append(buffer.data(), static_cast<std::size_t>(bytes));
    }

    return out;
}

} // namespace

RpcClient::RpcClient(RpcClientOptions options)
    : m_options(std::move(options))
{
}

bool RpcClient::Probe()
{
    const auto response = SendJsonRpc("getblockchaininfo", "[]");
    if (!response.has_value()) {
        return false;
    }

    if (response->status_code != 200) {
        LOG_WARN("RPC probe received HTTP status " + std::to_string(response->status_code));
        return false;
    }

    const JsonField error_field = ExtractJsonField(response->body, "error");
    if (error_field.kind != JsonFieldKind::kNull) {
        LOG_WARN("RPC probe returned non-null error");
        return false;
    }

    const JsonField result_field = ExtractJsonField(response->body, "result");
    return result_field.kind != JsonFieldKind::kMissing;
}

std::optional<std::vector<std::uint8_t>> RpcClient::GetBlock(const std::string& hash_hex)
{
    const std::string params = "[\"" + hash_hex + "\",0]";
    const auto response = SendJsonRpc("getblock", params);
    if (!response.has_value()) {
        return std::nullopt;
    }

    if (response->status_code != 200) {
        LOG_WARN("getblock HTTP status " + std::to_string(response->status_code));
        return std::nullopt;
    }

    const JsonField error_field = ExtractJsonField(response->body, "error");
    if (error_field.kind != JsonFieldKind::kNull) {
        LOG_WARN("getblock RPC error returned");
        return std::nullopt;
    }

    const JsonField result_field = ExtractJsonField(response->body, "result");
    if (result_field.kind != JsonFieldKind::kString) {
        LOG_WARN("getblock result was not a string");
        return std::nullopt;
    }

    return HexDecode(result_field.string_value);
}

bool RpcClient::SubmitBlock(std::span<const std::uint8_t> block_data)
{
    const std::string block_hex = HexEncode(block_data);
    const std::string params = "[\"" + block_hex + "\"]";

    const auto response = SendJsonRpc("submitblock", params);
    if (!response.has_value()) {
        return false;
    }

    if (response->status_code != 200) {
        LOG_WARN("submitblock HTTP status " + std::to_string(response->status_code));
        return false;
    }

    const JsonField error_field = ExtractJsonField(response->body, "error");
    if (error_field.kind != JsonFieldKind::kNull) {
        return false;
    }

    const JsonField result_field = ExtractJsonField(response->body, "result");
    return result_field.kind == JsonFieldKind::kNull;
}

std::optional<RpcClient::HttpResponse> RpcClient::SendJsonRpc(const std::string& method, const std::string& params_json)
{
    if (!m_cookie_loaded && !LoadCookie()) {
        return std::nullopt;
    }

    const std::uint64_t request_id = ++m_request_id;
    const std::string request_body =
        "{\"jsonrpc\":\"1.0\",\"id\":\"qbit-photon-" + std::to_string(request_id)
        + "\",\"method\":\"" + method + "\",\"params\":" + params_json + "}";

    auto response = SendHttpRequest(request_body);
    if (!response.has_value()) {
        return std::nullopt;
    }

    if (response->status_code == 401) {
        m_cookie_loaded = false;
        if (!LoadCookie()) {
            LOG_WARN("RPC returned 401 and cookie reload failed");
            return response;
        }

        response = SendHttpRequest(request_body);
    }

    return response;
}

std::optional<RpcClient::HttpResponse> RpcClient::SendHttpRequest(const std::string& request_body)
{
    if (!m_cookie_loaded) {
        return std::nullopt;
    }

    const std::string authorization = Base64Encode(m_cookie_auth);
    const std::string request =
        "POST / HTTP/1.1\r\n"
        "Host: " + m_options.host + ":" + std::to_string(m_options.port) + "\r\n"
        "Authorization: Basic " + authorization + "\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "Content-Length: " + std::to_string(request_body.size()) + "\r\n\r\n"
        + request_body;

    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* addresses = nullptr;
    const int gai_result = getaddrinfo(
        m_options.host.c_str(),
        std::to_string(m_options.port).c_str(),
        &hints,
        &addresses);

    if (gai_result != 0) {
        LOG_WARN(std::string("getaddrinfo failed: ") + gai_strerror(gai_result));
        return std::nullopt;
    }

    int connected_fd = -1;
    for (const addrinfo* addr = addresses; addr != nullptr; addr = addr->ai_next) {
        const int fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (fd < 0) {
            continue;
        }

#ifdef SO_NOSIGPIPE
        const int disable_sigpipe = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &disable_sigpipe, sizeof(disable_sigpipe)) != 0) {
            LOG_WARN("failed to set SO_NOSIGPIPE on RPC socket");
        }
#endif

        timeval timeout{};
        timeout.tv_sec = static_cast<long>(m_options.timeout.count() / 1000);
        timeout.tv_usec = static_cast<suseconds_t>((m_options.timeout.count() % 1000) * 1000);
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        int connect_rc = -1;
        do {
            connect_rc = connect(fd, addr->ai_addr, addr->ai_addrlen);
        } while (connect_rc != 0 && errno == EINTR);

        if (connect_rc == 0) {
            connected_fd = fd;
            break;
        }

        close(fd);
    }

    freeaddrinfo(addresses);

    if (connected_fd < 0) {
        LOG_WARN("failed to connect to RPC endpoint");
        return std::nullopt;
    }

    if (!SendAll(connected_fd, request)) {
        LOG_WARN("failed to send RPC request");
        close(connected_fd);
        return std::nullopt;
    }

    const auto raw_response = ReadResponse(connected_fd);
    close(connected_fd);

    if (!raw_response.has_value()) {
        LOG_WARN("failed to read RPC response (timeout or socket error)");
        return std::nullopt;
    }

    const std::string& response_text = *raw_response;
    const auto header_end = response_text.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        LOG_WARN("RPC response missing header terminator");
        return std::nullopt;
    }

    HttpResponse parsed{};
    parsed.status_code = ParseStatusCode(response_text);
    parsed.body = response_text.substr(header_end + 4);
    return parsed;
}

bool RpcClient::LoadCookie()
{
    std::ifstream cookie_file(m_options.cookie_file);
    if (!cookie_file.is_open()) {
        LOG_WARN("failed to open RPC cookie file: " + m_options.cookie_file);
        return false;
    }

    std::string line;
    if (!std::getline(cookie_file, line)) {
        LOG_WARN("RPC cookie file is empty");
        return false;
    }

    line = Trim(line);
    const auto separator = line.find(':');
    if (separator == std::string::npos || separator == 0 || separator + 1 >= line.size()) {
        LOG_WARN("RPC cookie malformed (expected __cookie__:<token>)");
        return false;
    }

    m_cookie_auth = line;
    m_cookie_loaded = true;
    return true;
}

} // namespace photon
