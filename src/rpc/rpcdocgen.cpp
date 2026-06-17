// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <rpc/docgen.h>
#include <util/fs.h>
#include <util/translation.h>

#include <cstdlib>
#include <exception>
#include <iostream>
#include <optional>
#include <string_view>

namespace {
constexpr std::string_view USAGE{
    "Usage: qbit-rpcdocgen --output <path>\n"
};

std::optional<fs::path> ParseOutputPath(int argc, char* argv[])
{
    std::optional<fs::path> output_path;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "-h" || arg == "--help") {
            std::cout << USAGE;
            std::exit(EXIT_SUCCESS);
        }
        if (arg == "--output" && i + 1 < argc) {
            output_path = fs::path{argv[++i]};
            continue;
        }
        return std::nullopt;
    }
    return output_path;
}
} // namespace

const TranslateFn G_TRANSLATION_FUN{nullptr};

int main(int argc, char* argv[])
{
    const std::optional<fs::path> output_path{ParseOutputPath(argc, argv)};
    if (!output_path) {
        std::cerr << USAGE;
        return EXIT_FAILURE;
    }

    try {
        SelectParams(ChainType::MAIN);
        GenerateRPCDocs(*output_path);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
