cmake_minimum_required(VERSION 3.10)
project(libbitcoinpqc C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(CTest)
find_package(Threads REQUIRED)

option(SPX_ENABLE_ARM_SHA "Enable ARM SHA acceleration" OFF)
option(SPX_HARDENING "Enable compiler hardening flags" ON)
option(BITCOINPQC_ENABLE_TEST_HELPERS "Build test-only helper APIs" OFF)
set(BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS "1835008" CACHE STRING "Maximum FORS+C signing grind attempts")
set(BITCOINPQC_WOTSC_MAX_COUNTER "65535" CACHE STRING "Maximum WOTS+C signing counter value")
option(SPX_ENABLE_TEST_BENCH_ENV_KNOBS "Enable test/benchmark-only runtime SPHINCS+ environment knobs" OFF)

# Set version
set(BITCOINPQC_VERSION_MAJOR 0)
set(BITCOINPQC_VERSION_MINOR 3)
set(BITCOINPQC_VERSION_PATCH 0)

# Library output settings
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/sphincsplus/ref
)

# Custom randombytes implementation
set(CUSTOM_RANDOMBYTES
    sphincsplus/ref/randombytes_custom.c
)

# SLH-DSA-SHA2-128s-bounded30 (SPHINCS+) source files
set(SLH_DSA_SOURCES
    sphincsplus/ref/address.c
    sphincsplus/ref/fors.c
    sphincsplus/ref/hash_sha2.c
    sphincsplus/ref/merkle.c
    sphincsplus/ref/sha2.c
    sphincsplus/ref/sha2_armv8_sha.c
    sphincsplus/ref/sha2_x86_shani.c
    sphincsplus/ref/sign.c
    sphincsplus/ref/sign_stats.c
    sphincsplus/ref/thash_sha2_simple.c
    sphincsplus/ref/utils.c
    sphincsplus/ref/utilsx1.c
    sphincsplus/ref/wots.c
    sphincsplus/ref/wotsx1.c
)

set(SLH_DSA_AVX2_SOURCES)
set(SLH_DSA_AVX2_COMPILE_FLAG)
if(
    CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|X86_64|amd64|AMD64|i[3-6]86)$"
    AND CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$"
    AND NOT MSVC
)
    list(APPEND SLH_DSA_AVX2_SOURCES
        sphincsplus/sha2-avx2/hash_sha2x8.c
        sphincsplus/sha2-avx2/thash_sha2_simplex8.c
        sphincsplus/sha2-avx2/utilsx8.c
        sphincsplus/sha2-avx2/sha256x8.c
        sphincsplus/sha2-avx2/sha256avx.c
    )
    set(SLH_DSA_AVX2_COMPILE_FLAG "-mavx2")
endif()

# libbitcoinpqc source files
set(BITCOINPQC_SOURCES
    src/bitcoinpqc.c
    src/slh_dsa/utils.c
    src/slh_dsa/keygen.c
    src/slh_dsa/validate.c
    src/slh_dsa/sign.c
    src/slh_dsa/verify.c
)

if(BITCOINPQC_ENABLE_TEST_HELPERS)
    list(APPEND BITCOINPQC_SOURCES
        src/test_helpers.c
    )
endif()

# Define the main library target
add_library(bitcoinpqc STATIC
    ${BITCOINPQC_SOURCES}
    ${SLH_DSA_SOURCES}
    ${SLH_DSA_AVX2_SOURCES}
    ${CUSTOM_RANDOMBYTES}
)
target_link_libraries(bitcoinpqc PUBLIC Threads::Threads)

if(BUILD_TESTING)
    find_program(SH_EXECUTABLE sh)
    if(SH_EXECUTABLE)
        add_test(
            NAME source_inventory
            COMMAND ${SH_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-source-inventory.sh
        )
        set_tests_properties(source_inventory
            PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
    endif()

    add_executable(bitcoinpqc_c_api_contract_test
        tests/c/c_api_contract_test.c
    )
    target_link_libraries(bitcoinpqc_c_api_contract_test PRIVATE bitcoinpqc)
    add_test(
        NAME bitcoinpqc_c_api_contract_test
        COMMAND bitcoinpqc_c_api_contract_test
    )

    add_executable(slh_dsa_secret_key_validate_test
        tests/c/slh_dsa_secret_key_validate_test.c
    )
    target_link_libraries(slh_dsa_secret_key_validate_test PRIVATE bitcoinpqc)
    add_test(
        NAME slh_dsa_secret_key_validate_test
        COMMAND slh_dsa_secret_key_validate_test
    )

    add_executable(slh_dsa_sign_failure_cleanup_test
        tests/c/slh_dsa_sign_failure_cleanup_test.c
    )
    target_compile_definitions(slh_dsa_sign_failure_cleanup_test PRIVATE
        BITCOINPQC_WOTSC_MAX_COUNTER=${BITCOINPQC_WOTSC_MAX_COUNTER}
    )
    target_link_libraries(slh_dsa_sign_failure_cleanup_test PRIVATE bitcoinpqc)
    add_test(
        NAME slh_dsa_sign_failure_cleanup_test
        COMMAND slh_dsa_sign_failure_cleanup_test
    )
endif()

# Set include directories for the library
target_include_directories(bitcoinpqc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
if(SLH_DSA_AVX2_SOURCES)
    target_include_directories(bitcoinpqc PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/sphincsplus/sha2-avx2
    )
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|AARCH64|arm64|ARM64)$" AND NOT APPLE)
    set_source_files_properties(
        sphincsplus/ref/sha2_armv8_sha.c
        PROPERTIES COMPILE_OPTIONS "-march=armv8-a+crypto"
    )
endif()

# Set compile definitions for the library
target_compile_definitions(bitcoinpqc PRIVATE
    PARAMS=sphincs-sha2-128s-bounded30
    CUSTOM_RANDOMBYTES=1
    BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS=${BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS}
    BITCOINPQC_WOTSC_MAX_COUNTER=${BITCOINPQC_WOTSC_MAX_COUNTER}
)
if(SPX_ENABLE_TEST_BENCH_ENV_KNOBS)
    target_compile_definitions(bitcoinpqc PRIVATE
        SPX_ENABLE_TEST_BENCH_ENV_KNOBS=1
    )
else()
    target_compile_definitions(bitcoinpqc PRIVATE
        SPX_PRODUCTION_BUILD=1
    )
endif()
if(SLH_DSA_AVX2_SOURCES)
    target_compile_definitions(bitcoinpqc PRIVATE
        SPX_AVX2=1
    )
    set_source_files_properties(${SLH_DSA_AVX2_SOURCES}
        PROPERTIES COMPILE_OPTIONS "${SLH_DSA_AVX2_COMPILE_FLAG}"
    )
endif()

if(SPX_ENABLE_ARM_SHA)
    target_compile_definitions(bitcoinpqc PRIVATE
        SPX_ENABLE_ARM_SHA=1
    )
endif()

if(BITCOINPQC_ENABLE_TEST_HELPERS)
    target_compile_definitions(bitcoinpqc PRIVATE
        BITCOINPQC_ENABLE_TEST_HELPERS=1
    )
endif()

if(SPX_HARDENING AND CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang)$")
    target_compile_options(bitcoinpqc PRIVATE
        -fstack-protector-strong
        -Wall
        -Wextra
        -Werror=implicit-function-declaration
    )
    target_compile_definitions(bitcoinpqc PRIVATE
        _FORTIFY_SOURCE=2
    )
endif()

# Configure install paths
install(TARGETS bitcoinpqc
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
