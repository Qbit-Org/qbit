#include <scheduler.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace photon {
namespace {

struct GroupData {
    std::uint16_t data_chunks{0};
    std::uint16_t total_chunks{0};
    std::vector<std::optional<fec::Chunk>> chunks_by_id{};
};

std::vector<GroupData> FlattenGroups(const std::vector<fec::EncodedBlock>& encoded_blocks)
{
    std::vector<GroupData> flattened;

    for (const fec::EncodedBlock& encoded : encoded_blocks) {
        if (encoded.params.total_chunks == 0) {
            continue;
        }

        std::map<std::uint16_t, GroupData> groups_by_id;

        for (const fec::Chunk& chunk : encoded.chunks) {
            if (chunk.chunk_id >= encoded.params.total_chunks) {
                continue;
            }

            GroupData& group = groups_by_id[chunk.coding_group_id];
            if (group.chunks_by_id.empty()) {
                group.data_chunks = encoded.params.data_chunks;
                group.total_chunks = encoded.params.total_chunks;
                group.chunks_by_id.resize(encoded.params.total_chunks);
            }

            group.chunks_by_id[chunk.chunk_id] = chunk;
        }

        for (auto& [group_id, group] : groups_by_id) {
            (void)group_id;
            flattened.push_back(std::move(group));
        }
    }

    return flattened;
}

} // namespace

ChunkScheduler::ChunkScheduler(std::vector<fec::EncodedBlock> groups)
{
    std::vector<GroupData> flattened_groups = FlattenGroups(groups);
    if (flattened_groups.empty()) {
        return;
    }

    std::size_t total = 0;
    std::uint16_t max_data_chunks = 0;
    std::uint16_t max_parity_chunks = 0;

    for (const GroupData& group : flattened_groups) {
        total += group.chunks_by_id.size();
        max_data_chunks = std::max(max_data_chunks, group.data_chunks);

        if (group.total_chunks >= group.data_chunks) {
            max_parity_chunks = std::max<std::uint16_t>(
                max_parity_chunks,
                static_cast<std::uint16_t>(group.total_chunks - group.data_chunks));
        }
    }

    m_schedule.reserve(total);

    for (std::uint16_t data_idx = 0; data_idx < max_data_chunks; ++data_idx) {
        for (std::size_t group_idx = 0; group_idx < flattened_groups.size(); ++group_idx) {
            const GroupData& group = flattened_groups[group_idx];
            if (data_idx >= group.data_chunks || data_idx >= group.chunks_by_id.size()) {
                continue;
            }

            if (!group.chunks_by_id[data_idx].has_value()) {
                continue;
            }

            m_schedule.push_back(ScheduledChunk{static_cast<std::uint16_t>(group_idx), *group.chunks_by_id[data_idx]});
        }
    }

    for (std::uint16_t parity_idx = 0; parity_idx < max_parity_chunks; ++parity_idx) {
        for (std::size_t group_idx = 0; group_idx < flattened_groups.size(); ++group_idx) {
            const GroupData& group = flattened_groups[group_idx];
            const std::uint16_t chunk_id = static_cast<std::uint16_t>(group.data_chunks + parity_idx);
            if (chunk_id >= group.total_chunks || chunk_id >= group.chunks_by_id.size()) {
                continue;
            }

            if (!group.chunks_by_id[chunk_id].has_value()) {
                continue;
            }

            m_schedule.push_back(ScheduledChunk{static_cast<std::uint16_t>(group_idx), *group.chunks_by_id[chunk_id]});
        }
    }
}

std::optional<ScheduledChunk> ChunkScheduler::Next()
{
    if (m_cursor >= m_schedule.size()) {
        return std::nullopt;
    }

    return m_schedule[m_cursor++];
}

std::size_t ChunkScheduler::total_chunks() const
{
    return m_schedule.size();
}

} // namespace photon
