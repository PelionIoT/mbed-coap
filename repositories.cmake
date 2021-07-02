
option(use_https "Use https" OFF)

message("Cloning repositories")
if (use_https)
    set(nanostack_libservice_repo       https://github.com/PelionIoT/nanostack-libservice.git)
    set(mbed_randlib_repo               https://github.com/PelionIoT/mbed-client-randlib.git)
else()
    set(nanostack_libservice_repo       git@github.com:PelionIoT/nanostack-libservice.git)
    set(mbed_randlib_repo               git@github.com:PelionIoT/mbed-client-randlib.git)
endif()

#Googletest for testing
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.10.x.zip
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

FetchContent_Declare(nanostack_libservice_decl
    GIT_REPOSITORY      ${nanostack_libservice_repo}
    GIT_TAG             "cmake_refactor"
)

FetchContent_Declare(mbed_randlib_decl
    GIT_REPOSITORY      ${mbed_randlib_repo}
    GIT_TAG             "cmake_refactor_mbed_coap_ut"
)

message("Project name " ${CMAKE_PROJECT_NAME})

if (${CMAKE_PROJECT_NAME} STREQUAL mbedcoap)
    message("Fetching content for mbedcoap")
    FetchContent_MakeAvailable(nanostack_libservice_decl)
    FetchContent_MakeAvailable(mbed_randlib_decl)
endif()
