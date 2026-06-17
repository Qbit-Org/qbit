cmake_minimum_required(VERSION 3.22)
set(QBIT_PHOTON_VERSION "dev" CACHE STRING "qbit-photon release version")
project(qbit-photon LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(PHOTON_BUILD_TESTS      "Build qbit-photon tests"             ON)
option(PHOTON_BUILD_BENCHMARKS "Build qbit-photon benchmark targets" ON)
option(PHOTON_ENABLE_FUZZ      "Build qbit-photon fuzz targets"      OFF)
option(PHOTON_USE_LIBFUZZER    "Link fuzz targets with libFuzzer"    OFF)
include(GNUInstallDirs)

get_filename_component(QBIT_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
configure_file(src/version.h.in "${CMAKE_BINARY_DIR}/version.h" @ONLY)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(OBJCOPY "${CMAKE_OBJCOPY}")
    set(STRIP "${CMAKE_STRIP}")
    configure_file(
        "${QBIT_REPO_ROOT}/contrib/devtools/split-debug.sh.in"
        "${CMAKE_BINARY_DIR}/split-debug.sh"
        FILE_PERMISSIONS OWNER_READ OWNER_EXECUTE
                         GROUP_READ GROUP_EXECUTE
                         WORLD_READ WORLD_EXECUTE
        @ONLY
    )
endif()

add_subdirectory(src)

add_executable(qbit-photon src/main.cpp)
target_link_libraries(qbit-photon
    PRIVATE
        photon_core
)

install(TARGETS qbit-photon RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES relay.conf.example relay-node.service
        DESTINATION ${CMAKE_INSTALL_DATADIR}/qbit-photon)
install(FILES RUNBOOK.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR})

if(PHOTON_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
