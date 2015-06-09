include ../makefile_defines.txt

COMPONENT_NAME = libCoap_unit
SRC_FILES = \
        ../../../../source/libCoap/src/sn_coap_builder.c

TEST_SRC_FILES = \
	main.cpp \
        libCoap_builder_test.cpp \
        ../stubs/stubs.c

include ../MakefileWorker.mk

CPPUTESTFLAGS += -DFEA_TRACE_SUPPORT

