# SPDX-License-Identifier: MIT
# The C++ adapter of the lws-client driver (driver/PROTOCOL.md). It builds the library of ../../../cpp
# as a subproject and links the adapter to it:
#
#   cmake -S driver/adapters/cpp -B <build> -G Ninja && cmake --build <build>
#   node driver/adapters/check.mjs -- <build>/lws-driver-adapter-cpp

cmake_minimum_required(VERSION 3.21)

project(lws-driver-adapter-cpp
    DESCRIPTION "lws-driver/1 adapter for the C++ lws-client"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The library, without its tests and examples.
set(LWS_BUILD_TESTS OFF CACHE BOOL "Build the lws-client GoogleTest suite" FORCE)
set(LWS_BUILD_EXAMPLES OFF CACHE BOOL "Build the lws-client example programs" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../cpp ${CMAKE_BINARY_DIR}/lws-client)

add_executable(lws-driver-adapter-cpp adapter.cpp)
target_link_libraries(lws-driver-adapter-cpp PRIVATE lws::client)
if(MSVC)
    target_compile_options(lws-driver-adapter-cpp PRIVATE /W4 /permissive-)
else()
    target_compile_options(lws-driver-adapter-cpp PRIVATE -Wall -Wextra -Wpedantic)
endif()
