# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Erich Bremer and the lws-client contributors

if(LWS_WITH_CURL)
    add_executable(lws-quickstart quickstart.cpp)
    target_link_libraries(lws-quickstart PRIVATE lws::client)
endif()

if(LWS_WITH_CURL AND LWS_WITH_OPENSSL)
    add_executable(lws-did-key-auth did_key_auth.cpp)
    target_link_libraries(lws-did-key-auth PRIVATE lws::client)
endif()

if(LWS_WITH_OPENSSL)
    add_executable(lws-verify-webhook verify_webhook.cpp)
    target_link_libraries(lws-verify-webhook PRIVATE lws::client)
endif()
