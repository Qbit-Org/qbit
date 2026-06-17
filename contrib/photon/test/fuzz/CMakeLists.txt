add_executable(photon_fuzz_protocol
    fibre_protocol.cpp
)
target_link_libraries(photon_fuzz_protocol
    PRIVATE
        photon_core
)
target_compile_options(photon_fuzz_protocol
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

if(PHOTON_USE_LIBFUZZER)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        include(CheckCXXSourceCompiles)
        set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
        check_cxx_source_compiles("int main() { return 0; }" PHOTON_CAN_LINK_LIBFUZZER)
        unset(CMAKE_REQUIRED_FLAGS)

        if(NOT PHOTON_CAN_LINK_LIBFUZZER)
            message(WARNING "PHOTON_USE_LIBFUZZER requested, but this toolchain cannot link libFuzzer; building harness without sanitizer flags")
            return()
        endif()

        target_compile_definitions(photon_fuzz_protocol PRIVATE PHOTON_WITH_LIBFUZZER=1)
        target_compile_options(photon_fuzz_protocol
            PRIVATE
                -fsanitize=fuzzer,address
                -fno-omit-frame-pointer
        )
        target_link_options(photon_fuzz_protocol
            PRIVATE
                -fsanitize=fuzzer,address
        )
    else()
        message(WARNING "PHOTON_USE_LIBFUZZER requested but compiler does not support libFuzzer flags")
    endif()
endif()
