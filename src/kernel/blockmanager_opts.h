// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_KERNEL_BLOCKMANAGER_OPTS_H
#define QBIT_KERNEL_BLOCKMANAGER_OPTS_H

#include <consensus/consensus.h>
#include <dbwrapper.h>
#include <kernel/notifications_interface.h>
#include <util/fs.h>

#include <cstdint>

class CChainParams;

namespace kernel {

static constexpr bool DEFAULT_XOR_BLOCKSDIR{true};

/**
 * An options struct for `BlockManager`, more ergonomically referred to as
 * `BlockManager::Options` due to the using-declaration in `BlockManager`.
 */
struct BlockManagerOpts {
    const CChainParams& chainparams;
    bool use_xor{DEFAULT_XOR_BLOCKSDIR};
    uint64_t prune_target{0};
    bool fast_prune{false};
    bool prune_witnesses{false};
    bool witness_pruning_enabled{true};
    int witness_prune_depth{COINBASE_MATURITY};
    const fs::path blocks_dir;
    Notifications& notifications;
    DBParams block_tree_db_params;
};

} // namespace kernel

#endif // QBIT_KERNEL_BLOCKMANAGER_OPTS_H
