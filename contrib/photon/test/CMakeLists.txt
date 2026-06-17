add_executable(photon_protocol_tests
    protocol_tests.cpp
)

target_include_directories(photon_protocol_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(photon_protocol_tests
    PRIVATE
        photon_core
)

add_test(NAME photon_protocol_tests COMMAND photon_protocol_tests)

add_executable(photon_udp_transport_tests
    udp_transport_tests.cpp
)

target_include_directories(photon_udp_transport_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(photon_udp_transport_tests
    PRIVATE
        photon_core
)

add_test(NAME photon_udp_transport_tests COMMAND photon_udp_transport_tests)

find_package(Threads REQUIRED)

add_executable(photon_config_tests
    config_tests.cpp
)
target_link_libraries(photon_config_tests
    PRIVATE
        photon_core
        Threads::Threads
)
add_test(NAME photon_config_tests COMMAND photon_config_tests)

add_executable(photon_rpc_client_tests
    rpc_client_tests.cpp
)
target_link_libraries(photon_rpc_client_tests
    PRIVATE
        photon_core
        Threads::Threads
)
add_test(NAME photon_rpc_client_tests COMMAND photon_rpc_client_tests)

add_executable(photon_zmq_listener_tests
    zmq_listener_tests.cpp
)
target_link_libraries(photon_zmq_listener_tests
    PRIVATE
        photon_core
        Threads::Threads
)
add_test(NAME photon_zmq_listener_tests COMMAND photon_zmq_listener_tests)

add_executable(photon_main_tests
    main_tests.cpp
)
target_include_directories(photon_main_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(photon_main_tests
    PRIVATE
        photon_core
        Threads::Threads
)
add_test(NAME photon_main_tests COMMAND photon_main_tests)

add_executable(photon_fec_tests fibre_fec_tests.cpp)

target_link_libraries(photon_fec_tests
    PRIVATE
        photon_fec
)

add_test(
    NAME photon_fec_tests
    COMMAND photon_fec_tests
)

add_executable(photon_scheduler_tests scheduler_tests.cpp)
target_link_libraries(photon_scheduler_tests
    PRIVATE
        photon_core
)
add_test(
    NAME photon_scheduler_tests
    COMMAND photon_scheduler_tests
)

add_executable(photon_peer_manager_tests peer_manager_tests.cpp)
target_link_libraries(photon_peer_manager_tests
    PRIVATE
        photon_core
)
add_test(
    NAME photon_peer_manager_tests
    COMMAND photon_peer_manager_tests
)

add_executable(photon_relay_engine_tests relay_engine_tests.cpp)
target_link_libraries(photon_relay_engine_tests
    PRIVATE
        photon_core
)
add_test(
    NAME photon_relay_engine_tests
    COMMAND photon_relay_engine_tests
)

if(PHOTON_BUILD_BENCHMARKS)
    add_executable(photon_fec_bench ../bench/fec_bench.cpp)

    target_link_libraries(photon_fec_bench
        PRIVATE
            photon_fec
    )
endif()

if(PHOTON_ENABLE_FUZZ)
    add_subdirectory(fuzz)
endif()
