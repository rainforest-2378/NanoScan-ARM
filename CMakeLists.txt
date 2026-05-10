cmake_minimum_required(VERSION 3.10)
project(NanoScanARM C)

# 自动开启 ARM NEON 支持 (大部分现代编译器在 ARM 架构下默认开启)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native")

include_directories(include)

add_library(nanoscan STATIC src/compiler.c src/scanner.c)

add_executable(nanoscan_demo examples/main.c)
target_link_libraries(nanoscan_demo nanoscan)
