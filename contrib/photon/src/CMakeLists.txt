find_package(OpenSSL REQUIRED)
get_filename_component(QBIT_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
list(APPEND CMAKE_MODULE_PATH "${QBIT_REPO_ROOT}/cmake/module")
find_package(ZeroMQ 4.0.0 MODULE REQUIRED)

set(PHOTON_VENDOR_FEC_SOURCES
    vendor/cm256.cpp
    vendor/gf256.cpp
    vendor/wirehair.cpp
    vendor/WirehairCodec.cpp
    vendor/WirehairTools.cpp
)

add_library(photon_vendor_fec STATIC ${PHOTON_VENDOR_FEC_SOURCES})

target_include_directories(photon_vendor_fec
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/vendor
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|i[3-6]86)$")
        target_compile_options(photon_vendor_fec PRIVATE -mssse3)
    endif()
endif()

add_library(photon_fec STATIC fec.cpp)

target_include_directories(photon_fec
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(photon_fec
    PUBLIC
        photon_vendor_fec
)

add_library(photon_core
    app.cpp
    config.cpp
    peer_manager.cpp
    protocol.cpp
    relay_engine.cpp
    rpc_client.cpp
    scheduler.cpp
    udp_transport.cpp
    zmq_listener.cpp
)

target_include_directories(photon_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_BINARY_DIR}
)

target_link_libraries(photon_core
    PUBLIC
        OpenSSL::Crypto
        zeromq
        photon_fec
)

target_compile_options(photon_core
    PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
