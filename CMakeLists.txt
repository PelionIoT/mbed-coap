#################################################################################
## Copyright 2020-2021 Pelion.
##
## SPDX-License-Identifier: Apache-2.0
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
#################################################################################

cmake_minimum_required (VERSION 3.14)
SET(CMAKE_SYSTEM_NAME Generic)

include(FindUnixCommands)

project(mbedcoap)

option(enable_coverage_data "Enable Coverage data" OFF)

include(repositories.cmake)

add_library(mbedcoap STATIC)

target_sources(mbedcoap PRIVATE
    source/sn_coap_builder.c
    source/sn_coap_header_check.c
    source/sn_coap_parser.c
    source/sn_coap_protocol.c
)

target_include_directories(mbedcoap PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(mbedcoap PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/mbed-coap)
target_include_directories(mbedcoap PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/source/include)

target_link_libraries(mbedcoap nanostack-libservice mbedRandLib mbedTrace)

# Tests after this line
enable_testing()

if (enable_coverage_data)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif ()

add_executable(libCoap_builder_test
    source/sn_coap_builder.c
    test/sn_coap_builder/libCoap_builder_test.cpp
    test/stubs/sn_coap_header_check_stub.c)

target_include_directories(libCoap_builder_test PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/source/include
    ${CMAKE_CURRENT_SOURCE_DIR}/test/stubs)

target_link_libraries(
    libCoap_builder_test
    gtest_main
    mbedcoap
)

add_executable(libCoap_header_check_test
    source/sn_coap_header_check.c
    test/sn_coap_header_check/libCoap_header_test.cpp)

target_include_directories(libCoap_header_check_test PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/source/include
    ${CMAKE_CURRENT_SOURCE_DIR}/test/stubs)

target_link_libraries(
    libCoap_header_check_test
    gtest_main
    mbedcoap
)

add_executable(libCoap_parser_test
    source/sn_coap_parser.c
    test/sn_coap_parser/sn_coap_parsertest.cpp
    test/sn_coap_parser/test_sn_coap_parser.c)

target_include_directories(libCoap_parser_test PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/source/include
    ${CMAKE_CURRENT_SOURCE_DIR}/test/stubs)

target_link_libraries(
    libCoap_parser_test
    gtest_main
    mbedcoap
)

add_executable(sn_coap_protocol_test
    source/sn_coap_protocol.c
    test/sn_coap_protocol/libCoap_protocol_test.cpp
    test/stubs/sn_coap_parser_stub.c
    test/stubs/sn_coap_builder_stub.c
    test/stubs/sn_coap_header_check_stub.c)

target_compile_definitions(sn_coap_protocol_test PRIVATE 
    MBED_CONF_MBED_CLIENT_SN_COAP_DUPLICATION_MAX_MSGS_COUNT=1
    ENABLE_RESENDINGS=1
    MBED_CONF_MBED_CLIENT_SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE=16
    SN_COAP_MAX_INCOMING_BLOCK_MESSAGE_SIZE=65535
    )

target_include_directories(sn_coap_protocol_test PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/source/include
    ${CMAKE_CURRENT_SOURCE_DIR}/test/stubs)

target_link_libraries(
    sn_coap_protocol_test
    gtest_main
    mbedcoap
)

# GTest framework requires C++ version 11
set_target_properties(libCoap_builder_test libCoap_header_check_test libCoap_parser_test sn_coap_protocol_test
PROPERTIES
    CXX_STANDARD 11
)

include(GoogleTest)
gtest_discover_tests(libCoap_builder_test)
gtest_discover_tests(libCoap_header_check_test)
gtest_discover_tests(libCoap_parser_test)
gtest_discover_tests(sn_coap_protocol_test)

if (enable_coverage_data AND ${CMAKE_PROJECT_NAME} STREQUAL "mbedcoap")
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/html")

    add_test(NAME coap_cov WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND ${BASH} -c "gcovr -r . -e ${CMAKE_CURRENT_SOURCE_DIR}/build -e '.*test.*' --html --html-details -o build/html/example-html-details.html"
    )
endif ()
