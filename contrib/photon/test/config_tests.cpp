#include <config.h>

#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <unistd.h>

namespace {

void Require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::filesystem::path WriteTempConfig(const std::string& body)
{
    const auto temp_dir = std::filesystem::temp_directory_path();
    const auto file_path = temp_dir / std::filesystem::path(
        "qbit_photon_config_test_" + std::to_string(::getpid()) + "_" + std::to_string(std::rand()) + ".conf");

    std::ofstream out(file_path);
    out << body;
    out.close();

    return file_path;
}

void RemoveTempFile(const std::filesystem::path& path)
{
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

void TestFullValidConfig()
{
    const std::filesystem::path path = WriteTempConfig(R"INI(
[local]
bind_port=9000
log_level=warn

[qbitd]
zmq_hashblock=tcp://127.0.0.1:28332
zmq_sequence=tcp://127.0.0.1:28333
rpc_host=127.0.0.1
rpc_port=8352
rpc_cookiefile=/tmp/qbit.cookie
rpc_timeout_ms=4500

[peer.alpha]
host=203.0.113.10
port=8144
hmac_key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

[peer.beta]
host=203.0.113.11
port=8145
hmac_key=ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100
)INI");

    const photon::ConfigLoadResult result = photon::LoadConfig(path.string());
    RemoveTempFile(path);

    Require(result.ok, "expected valid config to parse");
    Require(result.config.local.bind_port == 9000, "bind_port mismatch");
    Require(result.config.local.log_level == photon::logging::LogLevel::kWarn, "log_level mismatch");
    Require(result.config.qbitd.rpc_timeout_ms == 4500, "rpc_timeout_ms mismatch");
    Require(result.config.qbitd.zmq_sequence.has_value(), "expected zmq_sequence");
    Require(result.config.peers.size() == 2, "expected two peers");
    Require(result.config.peers[0].name == "alpha", "peer order/name mismatch");
    Require(result.config.peers[1].name == "beta", "peer order/name mismatch");
}

void TestMissingRequiredField()
{
    const std::filesystem::path path = WriteTempConfig(R"INI(
[qbitd]
zmq_hashblock=tcp://127.0.0.1:28332
rpc_host=127.0.0.1
rpc_port=8352

[peer.alpha]
host=203.0.113.10
port=8144
hmac_key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
)INI");

    const photon::ConfigLoadResult result = photon::LoadConfig(path.string());
    RemoveTempFile(path);

    Require(!result.ok, "expected missing required field failure");
    Require(result.error.find("rpc_cookiefile") != std::string::npos, "missing-field error not specific");
}

void TestInvalidPeerHmacKey()
{
    const std::filesystem::path path = WriteTempConfig(R"INI(
[qbitd]
zmq_hashblock=tcp://127.0.0.1:28332
rpc_host=127.0.0.1
rpc_port=8352
rpc_cookiefile=/tmp/qbit.cookie

[peer.alpha]
host=203.0.113.10
port=8144
hmac_key=not-hex
)INI");

    const photon::ConfigLoadResult result = photon::LoadConfig(path.string());
    RemoveTempFile(path);

    Require(!result.ok, "expected invalid hmac key failure");
    Require(result.error.find("hmac_key") != std::string::npos, "hmac_key error missing context");
}

void TestMultiplePeers()
{
    const std::filesystem::path path = WriteTempConfig(R"INI(
[qbitd]
zmq_hashblock=tcp://127.0.0.1:28332
rpc_host=127.0.0.1
rpc_port=8352
rpc_cookiefile=/tmp/qbit.cookie

[peer.one]
host=203.0.113.1
port=8144
hmac_key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

[peer.two]
host=203.0.113.2
port=8145
hmac_key=ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100

[peer.three]
host=203.0.113.3
port=8146
hmac_key=1111111111111111111111111111111111111111111111111111111111111111
)INI");

    const photon::ConfigLoadResult result = photon::LoadConfig(path.string());
    RemoveTempFile(path);

    Require(result.ok, "expected multiple peers config to parse");
    Require(result.config.peers.size() == 3, "expected three peers");
}

void TestUnknownKeysTolerated()
{
    const std::filesystem::path path = WriteTempConfig(R"INI(
[local]
log_level=info
unknown_local_key=something

[qbitd]
zmq_hashblock=tcp://127.0.0.1:28332
rpc_host=127.0.0.1
rpc_port=8352
rpc_cookiefile=/tmp/qbit.cookie
mystery_field=true

[peer.alpha]
host=203.0.113.10
port=8144
hmac_key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
unknown_peer_key=ignored

[unknown.section]
foo=bar
)INI");

    const photon::ConfigLoadResult result = photon::LoadConfig(path.string());
    RemoveTempFile(path);

    Require(result.ok, "unknown keys should be tolerated");
    Require(result.config.peers.size() == 1, "expected one peer");
}

int RunAllTests()
{
    const std::vector<std::pair<std::string, std::function<void()>>> tests = {
        {"full_valid_config", TestFullValidConfig},
        {"missing_required_field", TestMissingRequiredField},
        {"invalid_peer_hmac_key", TestInvalidPeerHmacKey},
        {"multiple_peers", TestMultiplePeers},
        {"unknown_keys_tolerated", TestUnknownKeysTolerated},
    };

    int failures = 0;
    for (const auto& [name, fn] : tests) {
        try {
            fn();
            std::cout << "[PASS] " << name << '\n';
        } catch (const std::exception& e) {
            ++failures;
            std::cout << "[FAIL] " << name << ": " << e.what() << '\n';
        }
    }

    return failures;
}

} // namespace

int main()
{
    return RunAllTests() == 0 ? 0 : 1;
}
