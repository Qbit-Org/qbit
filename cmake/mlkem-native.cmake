# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Builds the vendored mlkem-native library (src/mlkem-native) as ML-KEM-1024.
# See doc/subtrees/mlkem-native.md and src/crypto/mlkem_config.h.
#
# Native backends (x86_64 AVX2 and AArch64 assembly) are selected at run time,
# so no source is ever compiled with an AVX2 flag and the portable C fallback
# runs on every CPU. WITH_MLKEM_NATIVE chooses whether they are built:
#   AUTO  build them where supported (the default);
#   ON    like AUTO, but a target that cannot build them is a configure error;
#   OFF   portable C only.

include_guard(GLOBAL)

# Decide whether native backends are built. This depends on its arguments only,
# so ci/checks/test_mlkem_build_policy.py can run it for any target in script
# mode.
#   mode        WITH_MLKEM_NATIVE: AUTO, ON or OFF
#   arch        from mlkem_native_detect_arch: x86_64, aarch64-macho,
#               aarch64-elf, or a description of another target
#   msvc        true for MSVC-style toolchains, which cannot assemble GNU syntax
#   sanitizers  the SANITIZERS value
#
# AArch64 ELF targets (Linux and the BSDs) are portable only: mlkem-native's
# AArch64 assembly has no BTI landing pads and no GNU property note, so linking
# it would strip the BTI and PAC marking from the whole binary. Hardening wins;
# see doc/subtrees/mlkem-native.md for the evidence and when to revisit.
# Sets MLKEM_NATIVE_ENABLED, MLKEM_NATIVE_NO_ASM and MLKEM_NATIVE_REASON in the
# caller's scope. An invalid mode, or ON where native code is impossible, is a
# configure error.
function(mlkem_native_policy mode arch msvc sanitizers)
  string(TOUPPER "${mode}" mode)
  if(NOT mode MATCHES "^(AUTO|ON|OFF)$")
    message(FATAL_ERROR "WITH_MLKEM_NATIVE must be AUTO, ON or OFF, not \"${mode}\".")
  endif()

  set(no_asm FALSE)
  set(blocker "")
  if(msvc)
    set(no_asm TRUE)
    set(blocker "MSVC toolchains cannot assemble mlkem-native's GNU-syntax assembly")
  elseif(arch STREQUAL "aarch64-elf")
    set(blocker "mlkem-native AArch64 assembly has no BTI landing pads or GNU property note")
  elseif(NOT arch STREQUAL "x86_64" AND NOT arch STREQUAL "aarch64-macho")
    set(blocker "mlkem-native has no native backend qbit enables for ${arch}")
  elseif(sanitizers MATCHES "(^|,)memory($|,)")
    set(blocker "MemorySanitizer cannot see writes made by assembly")
  endif()

  if(mode STREQUAL "OFF")
    set(enabled FALSE)
    set(reason "WITH_MLKEM_NATIVE=OFF")
  elseif(blocker)
    if(mode STREQUAL "ON")
      message(FATAL_ERROR
        "WITH_MLKEM_NATIVE=ON, but ${blocker}. "
        "Configure with WITH_MLKEM_NATIVE=AUTO or OFF to build portable C."
      )
    endif()
    set(enabled FALSE)
    set(reason "${blocker}")
  else()
    set(enabled TRUE)
    set(reason "WITH_MLKEM_NATIVE=${mode} on ${arch}")
  endif()

  set(MLKEM_NATIVE_ENABLED ${enabled} PARENT_SCOPE)
  set(MLKEM_NATIVE_NO_ASM ${no_asm} PARENT_SCOPE)
  set(MLKEM_NATIVE_REASON "${reason}" PARENT_SCOPE)
endfunction()

# Name the target for mlkem_native_policy by asking the C compiler, with the
# flags in use, which architecture it generates code for. The tests mirror the
# conditions under which src/crypto/mlkem_config.h enables a backend.
function(mlkem_native_detect_arch var)
  include(CheckCSourceCompiles)
  set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
  check_c_source_compiles("
    #if !((defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)) && !defined(__ILP32__))
    #error not LP64 x86_64
    #endif
    int main(void) { return 0; }
    " MLKEM_NATIVE_TARGET_X86_64
  )
  check_c_source_compiles("
    #if !((defined(__AARCH64EL__) || defined(_M_ARM64)) && defined(__ARM_NEON) && !defined(__ILP32__))
    #error not little-endian LP64 AArch64 with NEON
    #endif
    #if !defined(__APPLE__)
    #error not Mach-O
    #endif
    int main(void) { return 0; }
    " MLKEM_NATIVE_TARGET_AARCH64_MACHO
  )
  check_c_source_compiles("
    #if !((defined(__AARCH64EL__) || defined(_M_ARM64)) && defined(__ELF__))
    #error not AArch64 ELF
    #endif
    int main(void) { return 0; }
    " MLKEM_NATIVE_TARGET_AARCH64_ELF
  )
  if(MLKEM_NATIVE_TARGET_X86_64)
    set(${var} "x86_64" PARENT_SCOPE)
  elseif(MLKEM_NATIVE_TARGET_AARCH64_MACHO)
    set(${var} "aarch64-macho" PARENT_SCOPE)
  elseif(MLKEM_NATIVE_TARGET_AARCH64_ELF)
    set(${var} "aarch64-elf" PARENT_SCOPE)
  else()
    set(${var} "this target (${CMAKE_SYSTEM_PROCESSOR})" PARENT_SCOPE)
  endif()
endfunction()

# Apply WITH_MLKEM_NATIVE to this build. Call from the top-level directory, at
# file scope, after SANITIZERS is final. Sets MLKEM_NATIVE_ENABLED,
# MLKEM_NATIVE_NO_ASM, MLKEM_NATIVE_REASON and MLKEM_NATIVE_SUMMARY. A macro,
# because enable_language() must run at file scope.
macro(mlkem_native_configure)
  enable_language(C)
  if(MSVC)
    set(_mlkem_native_arch "MSVC")
  else()
    mlkem_native_detect_arch(_mlkem_native_arch)
  endif()
  mlkem_native_policy("${WITH_MLKEM_NATIVE}" "${_mlkem_native_arch}" "${MSVC}" "${SANITIZERS}")
  if(MLKEM_NATIVE_ENABLED)
    # Assemble with exactly the C compiler invocation, including the arguments
    # and target that cross toolchains (depends) give it.
    set(CMAKE_ASM_COMPILER "${CMAKE_C_COMPILER}")
    set(CMAKE_ASM_COMPILER_ARG1 "${CMAKE_C_COMPILER_ARG1}")
    if(DEFINED CMAKE_C_COMPILER_TARGET)
      set(CMAKE_ASM_COMPILER_TARGET "${CMAKE_C_COMPILER_TARGET}")
    endif()
    # enable_language(ASM) appends CMake's defaults to a toolchain's
    # CMAKE_ASM_FLAGS_<CONFIG>_INIT, so note now which ones the toolchain set.
    foreach(_mlkem_native_config IN ITEMS DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
      set(_mlkem_native_init_${_mlkem_native_config} FALSE)
      if(DEFINED CMAKE_ASM_FLAGS_${_mlkem_native_config}_INIT)
        set(_mlkem_native_init_${_mlkem_native_config} TRUE)
      endif()
    endforeach()
    enable_language(ASM)
    # The C flags come first, then the ASM flags CMake initialized from
    # -DCMAKE_ASM_FLAGS, the ASMFLAGS environment variable or the toolchain
    # (target, sysroot or hardening flags), which win on conflict. Normal
    # variables shadow the cache without changing it, so a reconfigure starts
    # again from the same values.
    string(STRIP "${CMAKE_C_FLAGS} ${CMAKE_ASM_FLAGS}" CMAKE_ASM_FLAGS)
    # Per configuration, CMake's own ASM default (its _INIT value) gives way to
    # the C flags; a value the user or the toolchain set is kept.
    foreach(_mlkem_native_config IN ITEMS DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
      string(STRIP "${CMAKE_ASM_FLAGS_${_mlkem_native_config}}" _mlkem_native_value)
      string(STRIP "${CMAKE_ASM_FLAGS_${_mlkem_native_config}_INIT}" _mlkem_native_default)
      if(NOT _mlkem_native_init_${_mlkem_native_config} AND _mlkem_native_value STREQUAL _mlkem_native_default)
        set(CMAKE_ASM_FLAGS_${_mlkem_native_config} "${CMAKE_C_FLAGS_${_mlkem_native_config}}")
      endif()
      unset(_mlkem_native_init_${_mlkem_native_config})
    endforeach()
    unset(_mlkem_native_value)
    unset(_mlkem_native_default)
    unset(_mlkem_native_config)
    if(_mlkem_native_arch STREQUAL "x86_64")
      set(MLKEM_NATIVE_SUMMARY "native x86_64-avx2 if the CPU has AVX2, SSSE3, SSE4.1, POPCNT and BMI2, else portable (${MLKEM_NATIVE_REASON})")
    else()
      set(MLKEM_NATIVE_SUMMARY "native aarch64-neon (${MLKEM_NATIVE_REASON})")
    endif()
  else()
    set(MLKEM_NATIVE_SUMMARY "portable (${MLKEM_NATIVE_REASON})")
  endif()
  unset(_mlkem_native_arch)
  # For bitcoin-build-config.h.
  set(ENABLE_MLKEM_NATIVE ${MLKEM_NATIVE_ENABLED})
endmacro()

# Create the mlkem_native static library from the vendored tree in
# ${PROJECT_SOURCE_DIR}/src/mlkem-native, as configured by
# mlkem_native_configure(). Link it PRIVATE into bitcoin_node only; its
# interface lets bitcoin_node's ML-KEM wrapper include mlkem/mlkem_native.h.
#
# The library is C and assembly, so it takes core_interface's own compile
# options and definitions (hardening flags such as -fcf-protection and
# -mbranch-protection) and the sanitizer flags, but not qbit's C++ warning
# set: the vendored code is never edited to silence warnings.
function(add_mlkem_native)
  set(vendor_dir ${PROJECT_SOURCE_DIR}/src/mlkem-native)
  add_library(mlkem_native STATIC EXCLUDE_FROM_ALL
    ${vendor_dir}/mlkem/mlkem_native.c
    ${PROJECT_SOURCE_DIR}/src/crypto/mlkem_backend.c
  )
  if(MLKEM_NATIVE_ENABLED)
    target_sources(mlkem_native PRIVATE ${vendor_dir}/mlkem/mlkem_native_asm.S)
    target_compile_definitions(mlkem_native PRIVATE QBIT_MLKEM_NATIVE)
  endif()
  if(MLKEM_NATIVE_NO_ASM)
    target_compile_definitions(mlkem_native PRIVATE MLK_CONFIG_NO_ASM)
  endif()

  # core_interface's own options and definitions, read directly: a
  # $<TARGET_PROPERTY> expression would also pull in warn_interface.
  get_target_property(core_options core_interface INTERFACE_COMPILE_OPTIONS)
  get_target_property(core_definitions core_interface INTERFACE_COMPILE_DEFINITIONS)
  target_compile_definitions(mlkem_native
    PUBLIC
      "MLK_CONFIG_FILE=\"crypto/mlkem_config.h\""
  )
  if(core_definitions)
    target_compile_definitions(mlkem_native PRIVATE ${core_definitions})
  endif()
  if(core_options)
    # On MinGW, core_interface passes -Wa,-muse-unaligned-vector-move, which
    # would make gas encode the assembly's aligned vector moves (vmovdqa) as
    # unaligned ones: not the encoding the HOL-Light proofs cover. The assembly
    # needs no such protection, because its aligned moves touch only 32-byte
    # aligned data, so the flag applies to the C sources only. See
    # doc/subtrees/mlkem-native.md.
    list(TRANSFORM core_options REPLACE "^(-Wa,-muse-unaligned-vector-move)$" "$<$<COMPILE_LANGUAGE:C>:\\1>")
    target_compile_options(mlkem_native PRIVATE ${core_options})
  endif()
  # APPEND_CPPFLAGS and APPEND_CFLAGS reach the C and assembly compiles last,
  # after core_interface's options, as for the other C libraries
  # (cmake/secp256k1.cmake). The MSan jobs rely on this to undo
  # core_interface's -D_FORTIFY_SOURCE with -U_FORTIFY_SOURCE. One SHELL:
  # group, because CMake drops an option that repeats an earlier one, and
  # core_interface already passes -U_FORTIFY_SOURCE before its -D.
  string(STRIP "${APPEND_CPPFLAGS} ${APPEND_CFLAGS}" append_flags)
  if(append_flags)
    target_compile_options(mlkem_native PRIVATE "SHELL:${append_flags}")
  endif()
  target_include_directories(mlkem_native
    PUBLIC
      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
      $<BUILD_INTERFACE:${vendor_dir}>
  )
  target_link_libraries(mlkem_native PRIVATE sanitize_interface)
  set_target_properties(mlkem_native PROPERTIES
    EXPORT_COMPILE_COMMANDS OFF
  )
endfunction()
