cmake_minimum_required (VERSION 3.11)
SET(CMAKE_SYSTEM_NAME Generic)

project(mbedcoap)

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

add_dependencies(mbedcoap nanostack-libservice mbedRandLib)
target_link_libraries(mbedcoap nanostack-libservice mbedRandLib)