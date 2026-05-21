cmake_minimum_required(VERSION 3.10)
project(NanoScanARM C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(NANOSCAN_NATIVE "Build with -march=native (host-only, GCC/Clang)" OFF)

if(MSVC)
    # /W4 is the highest reasonable warning level; /permissive- enforces
    # standard C; /utf-8 forces UTF-8 source so escape sequences in tests
    # behave the same way as on POSIX.
    add_compile_options(/O2 /W4 /permissive- /utf-8)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-O3 -Wall -Wextra -Wpedantic)
    if(NANOSCAN_NATIVE)
        add_compile_options(-march=native)
    endif()
endif()

include_directories(include src)

add_library(nanoscan STATIC
    src/compiler.c
    src/shift_and.c
    src/multi_scan.c
    src/serialize.c
    src/hs_compat.c
)
target_include_directories(nanoscan PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)

# Emit libhs.a / hs.lib alongside libnanoscan.a so business projects that
# link `-lhs` (Unix) or `hs.lib` (Windows MSVC) keep working unchanged.
add_custom_command(TARGET nanoscan POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:nanoscan>
        $<TARGET_FILE_DIR:nanoscan>/${CMAKE_STATIC_LIBRARY_PREFIX}hs${CMAKE_STATIC_LIBRARY_SUFFIX}
    VERBATIM)

add_executable(nanoscan_demo  examples/main.c)
target_link_libraries(nanoscan_demo nanoscan)

add_executable(hs_compat_demo examples/hs_compat_demo.c)
target_link_libraries(hs_compat_demo nanoscan)

enable_testing()
foreach(t shift_and multi_scan hs_compat hs_diff hs_serialize hs_stress hs_regex hs_many_patterns)
    add_executable(${t}_test tests/${t}.c)
    target_link_libraries(${t}_test nanoscan)
    add_test(NAME ${t}_test COMMAND ${t}_test)
endforeach()
