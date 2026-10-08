# Copyright (C) 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Project: https://github.com/fmuecke/wfp-lock.git

cmake_minimum_required(VERSION 3.25)

project(
	wfp-lock 
	VERSION 0.10.0
	LANGUAGES CXX RC
)

set(APP_VERSION "${PROJECT_VERSION}")
set(APP_VERSION_TWEAK 0)

if(NOT WIN32)
    message(FATAL_ERROR "wfp-lock supports Windows only")
endif()

function(configure_app_version_resource output description internal_name original_filename)
    set(APP_FILE_DESCRIPTION "${description}")
    set(APP_INTERNAL_NAME "${internal_name}")
    set(APP_ORIGINAL_FILENAME "${original_filename}")
    configure_file(
        res/AppVersion.rc.in
        "${CMAKE_CURRENT_BINARY_DIR}/${output}"
        @ONLY
    )
endfunction()

configure_app_version_resource(
    AppVersion.rc
    "Restrict user traffic to allowed TCP endpoints"
    "wfp-lock"
    "wfp-lock.exe"
)
configure_file(
    res/AppVersion.h.in
    "${CMAKE_CURRENT_BINARY_DIR}/AppVersion.h"
    @ONLY
)
#configure_file(
#    res/App.manifest
#    "${CMAKE_CURRENT_BINARY_DIR}/App.manifest"
#    COPYONLY
#)

add_library(wfp-lock_lib STATIC
    src/wfp_lock.cpp
)
target_include_directories(wfp-lock_lib PUBLIC src)
target_compile_features(wfp-lock_lib PUBLIC cxx_std_23)
target_compile_definitions(wfp-lock_lib PUBLIC
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
)
target_compile_options(wfp-lock_lib PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /EHsc>
)
target_link_libraries(wfp-lock_lib PUBLIC
    advapi32
    fwpuclnt
    ole32
    ws2_32
)

add_executable(wfp-lock 
	src/main.cpp
	"${CMAKE_CURRENT_BINARY_DIR}/AppVersion.rc"
)
	
target_link_libraries(wfp-lock PRIVATE wfp-lock_lib)

include(CTest)
if(BUILD_TESTING)
    add_executable(wfp-lock-tests tests/tests.cpp)
    target_link_libraries(wfp-lock-tests PRIVATE wfp-lock_lib)
    add_test(NAME wfp-lock-tests COMMAND wfp-lock-tests)

    add_executable(wfp-lock-integration-tests tests/wfp_integration_tests.cpp)
    target_link_libraries(wfp-lock-integration-tests PRIVATE wfp-lock_lib)

    add_executable(wfp-lock-traffic-integration-tests tests/wfp_traffic_integration_tests.cpp)
    target_link_libraries(wfp-lock-traffic-integration-tests PRIVATE wfp-lock_lib iphlpapi netapi32)
    if(DEFINED ENV{WFP_LOCK_INTEGRATION_USER} AND NOT "$ENV{WFP_LOCK_INTEGRATION_USER}" STREQUAL ""
       AND DEFINED ENV{WFP_LOCK_INTEGRATION_OTHER_USER} AND NOT "$ENV{WFP_LOCK_INTEGRATION_OTHER_USER}" STREQUAL "")
        add_test(NAME wfp-lock-integration-tests
                 COMMAND wfp-lock-integration-tests "$ENV{WFP_LOCK_INTEGRATION_USER}"
                                                   "$ENV{WFP_LOCK_INTEGRATION_OTHER_USER}")
        set_tests_properties(wfp-lock-integration-tests PROPERTIES
            LABELS integration
            RUN_SERIAL TRUE
        )
    endif()
endif()

if(MSVC)
    set(runtime_targets
        wfp-lock_lib
        wfp-lock
    )
    if(BUILD_TESTING)
        list(APPEND runtime_targets wfp-lock-tests)
        list(APPEND runtime_targets wfp-lock-integration-tests)
        list(APPEND runtime_targets wfp-lock-traffic-integration-tests)
    endif()
    set_property(TARGET ${runtime_targets}
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
