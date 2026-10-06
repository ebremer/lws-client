# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Erich Bremer and the lws-client contributors

cmake_minimum_required(VERSION 3.21)

project(lws-client
    VERSION 0.1.0
    DESCRIPTION "C++20 client for the W3C Linked Web Storage (LWS) protocol"
    HOMEPAGE_URL "https://github.com/ebremer/lws-client"
    LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(LWS_WITH_CURL "Build the default libcurl HTTP transport" ON)
option(LWS_WITH_OPENSSL "Build cryptography support (self-signed credentials, did:key keys, webhook verification) with OpenSSL 3" ON)
option(LWS_BUILD_TESTS "Build the GoogleTest suite" ${PROJECT_IS_TOP_LEVEL})
option(LWS_BUILD_EXAMPLES "Build the example programs" ${PROJECT_IS_TOP_LEVEL})
option(LWS_FETCH_DEPS "Fall back to FetchContent for nlohmann_json / GoogleTest when not found" ON)

if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
find_package(nlohmann_json 3.11 QUIET)
if(NOT nlohmann_json_FOUND)
    if(NOT LWS_FETCH_DEPS)
        message(FATAL_ERROR "nlohmann_json not found and LWS_FETCH_DEPS is OFF")
    endif()
    include(FetchContent)
    FetchContent_Declare(nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
    set(JSON_Install ON CACHE INTERNAL "")
    FetchContent_MakeAvailable(nlohmann_json)
endif()

if(LWS_WITH_CURL)
    find_package(CURL CONFIG QUIET)
    if(NOT CURL_FOUND)
        find_package(CURL REQUIRED)
    endif()
endif()

if(LWS_WITH_OPENSSL)
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
endif()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
configure_file(cmake/config.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/generated/lws/config.hpp @ONLY)

add_library(lws-client
    src/access.cpp
    src/auth.cpp
    src/client.cpp
    src/encoding.cpp
    src/errors.cpp
    src/http.cpp
    src/json_patch.cpp
    src/keys.cpp
    src/link.cpp
    src/models.cpp
    src/notifications.cpp
    src/structured_fields.cpp
    src/type_index.cpp
    src/url.cpp
)
if(LWS_WITH_CURL)
    target_sources(lws-client PRIVATE src/curl_transport.cpp)
    target_link_libraries(lws-client PRIVATE CURL::libcurl)
endif()
if(LWS_WITH_OPENSSL)
    target_sources(lws-client PRIVATE src/crypto.cpp src/webhook.cpp)
    target_link_libraries(lws-client PRIVATE OpenSSL::Crypto)
endif()

add_library(lws::client ALIAS lws-client)
set_target_properties(lws-client PROPERTIES
    OUTPUT_NAME lws-client
    EXPORT_NAME client
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
target_compile_features(lws-client PUBLIC cxx_std_20)
target_include_directories(lws-client PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(lws-client PUBLIC nlohmann_json::nlohmann_json)
if(MSVC)
    target_compile_options(lws-client PRIVATE /W4 /permissive-)
else()
    target_compile_options(lws-client PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------------------
# Install / package
# ---------------------------------------------------------------------------
install(TARGETS lws-client EXPORT lws-client-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/lws DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/generated/lws/config.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/lws)
install(EXPORT lws-client-targets
    NAMESPACE lws::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/lws-client)
configure_package_config_file(cmake/lws-clientConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/lws-clientConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/lws-client)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/lws-clientConfigVersion.cmake
    COMPATIBILITY SameMinorVersion)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/lws-clientConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/lws-clientConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/lws-client)
install(FILES ../LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/lws-client OPTIONAL)

# ---------------------------------------------------------------------------
# Tests / examples
# ---------------------------------------------------------------------------
if(LWS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
if(LWS_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
