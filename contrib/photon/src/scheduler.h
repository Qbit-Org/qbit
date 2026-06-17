#ifndef QBIT_PHOTON_SRC_SCHEDULER_H
#define QBIT_PHOTON_SRC_SCHEDULER_H

#include <fec.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace photon {

struct ScheduledChunk {
    std::uint16_t group_idx{0};
    fec::Chunk chunk{};
};

class ChunkScheduler {
public:
    explicit ChunkScheduler(std::vector<fec::EncodedBlock> groups);

    std::optional<ScheduledChunk> Next();
    std::size_t total_chunks() const;

private:
    std::vector<ScheduledChunk> m_schedule{};
    std::size_t m_cursor{0};
};

} // namespace photon

#endif // QBIT_PHOTON_SRC_SCHEDULER_H
