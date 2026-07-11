# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

enable_language(C)

function(add_libbitcoinpqc subdir)
  message("")
  message("Configuring libbitcoinpqc subtree...")

  if(SPX_ENABLE_TEST_BENCH_ENV_KNOBS)
    message(FATAL_ERROR
      "SPX_ENABLE_TEST_BENCH_ENV_KNOBS is test/benchmark-only and cannot "
      "be enabled in an integrated qbit build. Configure src/libbitcoinpqc "
      "as a standalone project for backend experiments."
    )
  endif()

  set(BUILD_SHARED_LIBS OFF)
  set(CMAKE_EXPORT_COMPILE_COMMANDS OFF)
  set(SPX_ENABLE_TEST_BENCH_ENV_KNOBS OFF CACHE BOOL
    "Unavailable in integrated qbit builds." FORCE
  )
  mark_as_advanced(FORCE SPX_ENABLE_TEST_BENCH_ENV_KNOBS)

  include(GetTargetInterface)
  # -fsanitize and related flags apply to both C++ and C,
  # so we can pass them down to libbitcoinpqc as CFLAGS.
  get_target_interface(LIBBITCOINPQC_APPEND_CFLAGS "" sanitize_interface COMPILE_OPTIONS)
  string(STRIP "${LIBBITCOINPQC_APPEND_CFLAGS} ${APPEND_CPPFLAGS}" LIBBITCOINPQC_APPEND_CFLAGS)
  string(STRIP "${LIBBITCOINPQC_APPEND_CFLAGS} ${APPEND_CFLAGS}" LIBBITCOINPQC_APPEND_CFLAGS)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBBITCOINPQC_APPEND_CFLAGS}")

  # We want to build libbitcoinpqc with the most tested RelWithDebInfo configuration.
  foreach(config IN LISTS CMAKE_BUILD_TYPE CMAKE_CONFIGURATION_TYPES)
    if(config STREQUAL "")
      continue()
    endif()
    string(TOUPPER "${config}" config)
    set(CMAKE_C_FLAGS_${config} "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
  endforeach()

  # If the CFLAGS environment variable is defined during building depends
  # and configuring this build system, its content might be duplicated.
  if(DEFINED ENV{CFLAGS})
    deduplicate_flags(CMAKE_C_FLAGS)
  endif()

  set(BUILD_TESTING_SAVED "${BUILD_TESTING}")
  set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
  add_subdirectory(${subdir})
  set(BUILD_TESTING "${BUILD_TESTING_SAVED}" CACHE BOOL "" FORCE)

  # Enforce qbit's production policy independently of the subtree default.
  # If the test-only macro is injected through compiler flags, opt_flags.h
  # rejects the conflicting definitions while compiling the actual library.
  target_compile_definitions(bitcoinpqc PRIVATE
    SPX_PRODUCTION_BUILD=1
  )

  # Keep this subtree out of "all" unless linked.
  set_target_properties(bitcoinpqc PROPERTIES
    EXCLUDE_FROM_ALL TRUE
  )
endfunction()
