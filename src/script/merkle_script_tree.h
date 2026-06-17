// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_SCRIPT_MERKLE_SCRIPT_TREE_H
#define QBIT_SCRIPT_MERKLE_SCRIPT_TREE_H

#include <script/interpreter.h>

#include <memory>
#include <optional>
#include <tuple>
#include <vector>

namespace merkle_tree_inference {

using InferredScriptTree = std::vector<std::tuple<int, std::vector<unsigned char>, int>>;

template <typename Scripts, typename MatchesControlBlock, typename ComputeLeafHash, typename ComputeBranchHash>
std::optional<InferredScriptTree> InferMerkleScriptTree(const uint256& merkle_root, const Scripts& scripts,
                                                        size_t control_base_size, size_t control_max_size, size_t control_node_size,
                                                        MatchesControlBlock matches_control_block,
                                                        ComputeLeafHash compute_leaf_hash,
                                                        ComputeBranchHash compute_branch_hash)
{
    // If the Merkle root is 0, the tree is empty, and we're done.
    InferredScriptTree ret;
    if (merkle_root.IsNull()) return ret;

    using ScriptLeaf = typename Scripts::key_type;

    /** Data structure to represent the nodes of the tree we're going to build. */
    struct TreeNode {
        /** Hash of this node, if known; 0 otherwise. */
        uint256 hash;
        /** The left and right subtrees (note that their order is irrelevant). */
        std::unique_ptr<TreeNode> sub[2];
        /** If this is known to be a leaf node, a pointer to the (script, leaf_ver) pair.
         *  nullptr otherwise. */
        const ScriptLeaf* leaf = nullptr;
        /** Whether or not this node has been explored (is known to be a leaf, or known to have children). */
        bool explored = false;
        /** Whether or not this node is an inner node (unknown until explored = true). */
        bool inner = false;
        /** Whether or not we have produced output for this subtree. */
        bool done = false;
    };

    // Build tree from the provided branches.
    TreeNode root;
    root.hash = merkle_root;
    for (const auto& [key, control_blocks] : scripts) {
        const auto& [script, leaf_ver] = key;
        for (const auto& control : control_blocks) {
            // Skip script records with nonsensical leaf version.
            if (leaf_ver < 0 || leaf_ver >= 0x100 || leaf_ver & 1) continue;
            // Skip script records with invalid control block sizes.
            if (control.size() < control_base_size || control.size() > control_max_size ||
                ((control.size() - control_base_size) % control_node_size) != 0) continue;
            // Skip script records that don't match the control block.
            if ((control[0] & TAPROOT_LEAF_MASK) != leaf_ver) continue;
            const uint256 leaf_hash = compute_leaf_hash(leaf_ver, script);
            if (!matches_control_block(control, leaf_hash, merkle_root)) continue;

            TreeNode* node = &root;
            size_t levels = (control.size() - control_base_size) / control_node_size;
            for (size_t depth = 0; depth < levels; ++depth) {
                // Can't descend into a node which we already know is a leaf.
                if (node->explored && !node->inner) return std::nullopt;

                // Extract partner hash from Merkle branch in control block.
                uint256 hash;
                std::copy(control.begin() + control_base_size + (levels - 1 - depth) * control_node_size,
                          control.begin() + control_base_size + (levels - depth) * control_node_size,
                          hash.begin());

                if (node->sub[0]) {
                    // Descend into the existing left or right branch.
                    bool desc = false;
                    for (int i = 0; i < 2; ++i) {
                        if (node->sub[i]->hash == hash || (node->sub[i]->hash.IsNull() && node->sub[1 - i]->hash != hash)) {
                            node->sub[i]->hash = hash;
                            node = &*node->sub[1 - i];
                            desc = true;
                            break;
                        }
                    }
                    if (!desc) return std::nullopt; // This probably requires a hash collision to hit.
                } else {
                    // We're in an unexplored node. Create subtrees and descend.
                    node->explored = true;
                    node->inner = true;
                    node->sub[0] = std::make_unique<TreeNode>();
                    node->sub[1] = std::make_unique<TreeNode>();
                    node->sub[1]->hash = hash;
                    node = &*node->sub[0];
                }
            }
            // Cannot turn a known inner node into a leaf.
            if (node->sub[0]) return std::nullopt;
            node->explored = true;
            node->inner = false;
            node->leaf = &key;
            node->hash = leaf_hash;
        }
    }

    // Recursive processing to turn the tree into flattened output. Use an explicit stack here to avoid
    // overflowing the call stack (the tree may be 128 levels deep).
    std::vector<TreeNode*> stack{&root};
    while (!stack.empty()) {
        TreeNode& node = *stack.back();
        if (!node.explored) {
            // Unexplored node, which means the tree is incomplete.
            return std::nullopt;
        } else if (!node.inner) {
            // Leaf node; produce output.
            ret.emplace_back(stack.size() - 1, node.leaf->first, node.leaf->second);
            node.done = true;
            stack.pop_back();
        } else if (node.sub[0]->done && !node.sub[1]->done && !node.sub[1]->explored && !node.sub[1]->hash.IsNull() &&
                   compute_branch_hash(node.sub[1]->hash, node.sub[1]->hash) == node.hash) {
            // Whenever there are nodes with two identical subtrees under it, we run into a problem:
            // the control blocks for the leaves underneath those will be identical as well, and thus
            // they will all be matched to the same path in the tree. The result is that at the location
            // where the duplicate occurred, the left child will contain a normal tree that can be explored
            // and processed, but the right one will remain unexplored.
            //
            // This situation can be detected, by encountering an inner node with unexplored right subtree
            // with known hash, and the selected branch hash of (hash, hash) equals this node's hash.
            //
            // To deal with this, simply process the left tree a second time (set its done flag to false;
            // noting that the done flag of its children have already been set to false after processing
            // those). To avoid ending up in an infinite loop, set the done flag of the right (unexplored)
            // subtree to true.
            node.sub[0]->done = false;
            node.sub[1]->done = true;
        } else if (node.sub[0]->done && node.sub[1]->done) {
            // An internal node which we're finished with.
            node.sub[0]->done = false;
            node.sub[1]->done = false;
            node.done = true;
            stack.pop_back();
        } else if (!node.sub[0]->done) {
            // An internal node whose left branch hasn't been processed yet. Do so first.
            stack.push_back(&*node.sub[0]);
        } else if (!node.sub[1]->done) {
            // An internal node whose right branch hasn't been processed yet. Do so first.
            stack.push_back(&*node.sub[1]);
        }
    }

    return ret;
}

} // namespace merkle_tree_inference

#endif // QBIT_SCRIPT_MERKLE_SCRIPT_TREE_H
