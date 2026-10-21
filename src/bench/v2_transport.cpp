// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <bench/bench.h>
#include <bip324_pq.h>
#include <crypto/mlkem.h>
#include <key.h>
#include <net.h>
#include <random.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace {

enum class Backend { DETECTED, PORTABLE };

/** Rounds of delivery in both directions that any handshake needs fewer of. */
constexpr int MAX_ROUNDS{8};

/** Hand everything `from` has to send to `to`. Returns the bytes moved. */
size_t Deliver(Transport& from, Transport& to)
{
    size_t moved{0};
    while (true) {
        const auto [bytes, more, msg_type] = from.GetBytesToSend(/*have_next_message=*/false);
        if (bytes.empty()) return moved;
        std::span<const uint8_t> remaining{bytes};
        while (!remaining.empty()) {
            const bool ok{to.ReceivedBytes(remaining)};
            assert(ok);
            // The handshake delivers no application message.
            assert(!to.ReceivedMessageComplete());
        }
        moved += bytes.size();
        from.MarkBytesSent(bytes.size());
    }
}

/**
 * One complete handshake between an in-memory initiator and responder, as a node creates them for
 * a connection (fresh keys, production entropy and ML-KEM code) but without garbage, so that the
 * bytes on the wire are the same every time. It is complete when both sides report v2, the same
 * session id and, for hybrid, the peer's verified key confirmation. Returns the bytes on the wire,
 * both directions together.
 */
size_t Handshake(bool hybrid)
{
    const V2PQOptions pq{.mode = hybrid ? PQMode::NEGOTIATE : PQMode::OFF};
    V2Transport initiator{/*nodeid=*/0, /*initiating=*/true, GenerateRandomKey(), MakeByteSpan(GetRandHash()),
                          /*garbage=*/{}, pq, DefaultPQRandomSource(), DefaultPQKemOps()};
    V2Transport responder{/*nodeid=*/1, /*initiating=*/false, GenerateRandomKey(), MakeByteSpan(GetRandHash()),
                          /*garbage=*/{}, pq, DefaultPQRandomSource(), DefaultPQKemOps()};
    size_t bytes{0};
    for (int round{0}; round < MAX_ROUNDS; ++round) {
        const size_t moved{Deliver(initiator, responder) + Deliver(responder, initiator)};
        if (moved == 0) break;
        bytes += moved;
    }
    const Transport::Info initiator_info{initiator.GetInfo()};
    const Transport::Info responder_info{responder.GetInfo()};
    assert(initiator_info.transport_type == TransportProtocolType::V2);
    assert(responder_info.transport_type == TransportProtocolType::V2);
    assert(initiator_info.session_id == responder_info.session_id);
    assert(initiator_info.transport_pq == hybrid && responder_info.transport_pq == hybrid);
    return bytes;
}

/**
 * Time complete handshakes on the detected ML-KEM-1024 backend, or with portable C forced, and
 * name the benchmark after the transport, the bytes on the wire per handshake and the backend that
 * runs. Legacy v2 runs no ML-KEM code, so its two runs only show the backend selection costs
 * nothing there. Auto-detection is restored afterwards.
 */
void HandshakeBench(benchmark::Bench& bench, bool hybrid, Backend backend)
{
    const auto testing_setup{MakeNoLogFileContext<const BasicTestingSetup>(ChainType::MAIN)};
    std::optional<mlkem::ForcePortableForTesting> portable;
    if (backend == Backend::PORTABLE) portable.emplace();
    const mlkem::BackendNames names{mlkem::GetBackendNames()};
    const size_t bytes{Handshake(hybrid)};
    bench.name(strprintf("V2TransportHandshake %s, %u bytes on the wire, %s the '%s/%s' ML-KEM-1024 backend",
                         hybrid ? "hybrid" : "legacy v2", bytes, hybrid ? "using" : "not using", names.arith, names.keccak));
    bench.batch(1).unit("handshake").run([&] {
        const size_t moved{Handshake(hybrid)};
        assert(moved == bytes);
    });
}

} // namespace

static void V2_TRANSPORT_HANDSHAKE_LEGACY_DETECTED(benchmark::Bench& bench) { HandshakeBench(bench, /*hybrid=*/false, Backend::DETECTED); }
static void V2_TRANSPORT_HANDSHAKE_LEGACY_PORTABLE(benchmark::Bench& bench) { HandshakeBench(bench, /*hybrid=*/false, Backend::PORTABLE); }
static void V2_TRANSPORT_HANDSHAKE_HYBRID_DETECTED(benchmark::Bench& bench) { HandshakeBench(bench, /*hybrid=*/true, Backend::DETECTED); }
static void V2_TRANSPORT_HANDSHAKE_HYBRID_PORTABLE(benchmark::Bench& bench) { HandshakeBench(bench, /*hybrid=*/true, Backend::PORTABLE); }

BENCHMARK(V2_TRANSPORT_HANDSHAKE_LEGACY_DETECTED, benchmark::PriorityLevel::HIGH);
BENCHMARK(V2_TRANSPORT_HANDSHAKE_LEGACY_PORTABLE, benchmark::PriorityLevel::HIGH);
BENCHMARK(V2_TRANSPORT_HANDSHAKE_HYBRID_DETECTED, benchmark::PriorityLevel::HIGH);
BENCHMARK(V2_TRANSPORT_HANDSHAKE_HYBRID_PORTABLE, benchmark::PriorityLevel::HIGH);
