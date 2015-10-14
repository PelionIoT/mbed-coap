#
# Makefile for combined NSDL+COAP library
#

# Define compiler toolchain with CC or PLATFORM variables
# Example (GCC toolchains, default $CC and $AR are used)
# make
#
# OR (Cross-compile GCC toolchain)
# make PLATFORM=arm-linux-gnueabi-
#
# OR (armcc/Keil)
# make CC=armcc AR=ArmAR
#
# OR (IAR-ARM)
# make CC=iccarm

LIB = libnsdl.a
SRCS := \
	source/libNsdl/src/sn_grs.c \
	source/libNsdl/src/sn_nsdl.c \
	source/libCoap/src/sn_coap_protocol.c \
	source/libCoap/src/sn_coap_parser.c \
	source/libCoap/src/sn_coap_header_check.c \
	source/libCoap/src/sn_coap_builder.c \

override CFLAGS += -DVERSION='"$(VERSION)"'

override CFLAGS += -Isource/libNsdl/src/include/
override CFLAGS += -Isource/libCoap/src/include/
SERVLIB_DIR := ../libService
override CFLAGS += -I$(SERVLIB_DIR)/libService
override CFLAGS += -Insdl-c/

# List of subdirectories to build
TEST_FOLDER := ./test/
# List of unit test directories for libraries
UNITTESTS := $(sort $(dir $(wildcard $(TEST_FOLDER)*/unittest/*)))
TESTDIRS := $(UNITTESTS:%=build-%)
CLEANTESTDIRS := $(UNITTESTS:%=clean-%)
COVERAGEFILE := ./lcov/coverage.info

$(TESTDIRS):
	@make -C $(@:build-%=%)

$(CLEANDIRS):
	@make -C $(@:clean-%=%) clean

$(CLEANTESTDIRS):
	@make -C $(@:clean-%=%) clean

#include ../libService/toolchain_rules.mk

$(eval $(call generate_rules,$(LIB),$(SRCS)))

.PHONY: release
release:
	7z a nsdl-c_$(VERSION).zip *.a *.lib include

# Extend default clean rule
clean: clean-extra

.PHONY: test
test: $(TESTDIRS)
	@rm -rf ./lcov
	@rm -rf ./coverage
	@mkdir -p lcov
	@mkdir -p lcov/results
	@mkdir coverage
	@find ./test -name '*.xml' | xargs cp -t ./lcov/results/
	@rm -f lcov/index.xml
	@./xsl_script.sh
	@cp junit_xsl.xslt lcov/.
	@xsltproc -o lcov/testresults.html lcov/junit_xsl.xslt lcov/index.xml
	@rm -f lcov/junit_xsl.xslt
	@rm -f lcov/index.xml
	@find ./ -name '*.gcno' | xargs cp --backup=numbered -t ./coverage/
	@find ./ -name '*.gcda' | xargs cp --backup=numbered -t ./coverage/
	@gcovr --object-directory ./coverage -e '.*/builds/.*' -e '.*/test/.*' -e '.*/yotta_modules/.*' -e '.*/stubs/.*' -e '.*/mbed-client-c/.*' -x -o ./lcov/gcovr.xml
	@lcov -d test/. -c -o $(COVERAGEFILE)
	@lcov -q -r $(COVERAGEFILE) "/usr*" -o $(COVERAGEFILE)
	@lcov -q -r $(COVERAGEFILE) "/test*" -o $(COVERAGEFILE)
	@lcov -q -r $(COVERAGEFILE) "/mbed-client-libservice*" -o $(COVERAGEFILE)
	@genhtml -q $(COVERAGEFILE) --show-details --output-directory lcov/html
	@echo mbed-client-c module unit tests built

.PHONY: deploy_to
deploy_to: all
	tar --transform 's,^,nsdl-c/,' --append -f $(TO) *.a

clean-extra: $(CLEANDIRS) \
	$(CLEANTESTDIRS)
