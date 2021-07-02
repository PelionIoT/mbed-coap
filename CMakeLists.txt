cmake_minimum_required (VERSION 3.11)
SET(CMAKE_SYSTEM_NAME Generic)

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

#add_dependencies(mbedcoap nanostack-libservice mbedRandLib)
target_link_libraries(mbedcoap nanostack-libservice mbedRandLib)

# Tests after this line
enable_testing()

if (enable_coverage_data)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif ()

add_executable(libCoap_builder_test
    source/sn_coap_builder.c
    test/sn_coap_builder/libCoap_builder_test.cpp)

target_include_directories(libCoap_builder_test PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/mbed-coap)

target_link_libraries(
    libCoap_builder_test
    gtest_main
    mbedcoap
)

# GTest framework requires C++ version 11
set_target_properties(libCoap_builder_test
PROPERTIES
    CXX_STANDARD 11
)

include(GoogleTest)
gtest_discover_tests(libCoap_builder_test)

if (enable_coverage_data AND ${CMAKE_PROJECT_NAME} EQUAL mbedcoap)
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/html")

    add_test(NAME ls_cov WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND ${BASH} -c "gcovr -r . -e ${CMAKE_CURRENT_SOURCE_DIR}/build -e '.*test.*' --html --html-details -o build/html/example-html-details.html"
    )
endif ()
