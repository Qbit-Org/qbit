# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

enable_language(C)

function(add_libbitcoinpqc subdir)
  message("")
  message("Configuring libbitcoinpqc subtree...")
  set(BUILD_SHARED_LIBS OFF)
  set(CMAKE_EXPORT_COMPILE_COMMANDS OFF)

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

  add_subdirectory(${subdir})

  # Keep this subtree out of "all" unless linked.
  set_target_properties(bitcoinpqc PROPERTIES
    EXCLUDE_FROM_ALL TRUE
  )
endfunction()
