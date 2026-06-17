// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_TEST_UTIL_VALIDATION_H
#define QBIT_TEST_UTIL_VALIDATION_H

#include <validation.h>

class CValidationInterface;

struct TestChainstateManager : public ChainstateManager {
    /** Disable the next write of all chainstates */
    void DisableNextWrite();
    /** Reset the ibd cache to its initial state */
    void ResetIbd();
    /** Toggle IsInitialBlockDownload from true to false */
    void JumpOutOfIbd();
    /** Expose assumevalid script-skip policy to unit tests. */
    bool CanSkipScriptChecksForTest(const CBlockIndex& block_index, bool witness_unavailable) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

class ValidationInterfaceTest
{
public:
    static void BlockConnected(
        ChainstateRole role,
        CValidationInterface& obj,
        const std::shared_ptr<const CBlock>& block,
        const CBlockIndex* pindex);
};

#endif // QBIT_TEST_UTIL_VALIDATION_H
