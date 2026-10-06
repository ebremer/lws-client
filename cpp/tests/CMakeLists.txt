# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Erich Bremer and the lws-client contributors

find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    if(NOT LWS_FETCH_DEPS)
        message(FATAL_ERROR "GoogleTest not found and LWS_FETCH_DEPS is OFF")
    endif()
    include(FetchContent)
    FetchContent_Declare(googletest
        URL https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

include(GoogleTest)

set(LWS_FIXTURES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../conformance/fixtures")

add_executable(lws-client-tests
    test_main.cpp
    test_parsers.cpp
    test_models.cpp
    test_client.cpp
    test_auth.cpp
    test_crypto.cpp
    test_webhook.cpp
    test_interop.cpp
)
target_compile_definitions(lws-client-tests PRIVATE LWS_FIXTURES_DIR="${LWS_FIXTURES_DIR}")
target_link_libraries(lws-client-tests PRIVATE lws::client GTest::gtest)
if(LWS_WITH_OPENSSL)
    target_link_libraries(lws-client-tests PRIVATE OpenSSL::Crypto)
endif()
if(NOT MSVC)
    target_compile_options(lws-client-tests PRIVATE -Wall -Wextra)
endif()

gtest_discover_tests(lws-client-tests DISCOVERY_TIMEOUT 60)
