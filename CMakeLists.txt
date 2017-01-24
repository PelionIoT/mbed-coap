INCLUDE(CMakeForceCompiler)
# CROSS COMPILER SETTING
cmake_minimum_required (VERSION 2.8)
SET(CMAKE_SYSTEM_NAME Generic)

project(mbedClientC)



include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/source/libNsdl/src/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/source/libNsdl/src/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/source/libCoap/src/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/source/libCoap/src/include/)

set(LINUX_PORT_LIBS_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../Linux_port_libs/)

message(STATUS ************11111*****${LINUX_PORT_LIBS_PATH})

include_directories(${LINUX_PORT_LIBS_PATH}/)
include_directories(${LINUX_PORT_LIBS_PATH}/mbed-client-c/)
include_directories(${LINUX_PORT_LIBS_PATH}/mbed-client-c/nsdl-c/)
include_directories(${LINUX_PORT_LIBS_PATH}/mbed-trace/)
include_directories(${LINUX_PORT_LIBS_PATH}/nanostack-libservice/)
include_directories(${LINUX_PORT_LIBS_PATH}/nanostack-libservice/mbed-client-libservice/)



FILE(GLOB MBED_CLIENT_C_SRC
	"${CMAKE_CURRENT_SOURCE_DIR}/source/libNsdl/src/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/libNsdl/src/include/*.h"
	
 	"${CMAKE_CURRENT_SOURCE_DIR}/source/libCoap/src/*.c"
 	"${CMAKE_CURRENT_SOURCE_DIR}/source/libCoap/src/include/*.h"
	)

CREATE_LIBRARY(mbedClientC "${MBED_CLIENT_C_SRC}" "") 


