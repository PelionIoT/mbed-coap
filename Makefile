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
# OR (ArmCC/Keil)
# make CC=ArmCC AR=ArmAR
#
# OR (IAR-ARM)
# make CC=iccarm

LIB = libnsdl.a
SRCS := \
	libNsdl/src/sn_grs.c \
	libNsdl/src/sn_nsdl.c \
	libCoap/src/sn_coap_protocol.c \
	libCoap/src/sn_coap_parser.c \
	libCoap/src/sn_coap_header_check.c \
	libCoap/src/sn_coap_builder.c \

override CFLAGS += -IlibNsdl/src/Include/
override CFLAGS += -IlibCoap/src/include/
SERVLIB_DIR := ../libService
override CFLAGS += -I$(SERVLIB_DIR)/include

override CFLAGS += -DREAL_EMBEDDED

include ../libService/toolchain_rules.mk

.PHONY: all
all: $(LIB)
	@echo Built $(LIB)

#
# Define build dir outside from src folders
#
BUILD_DIR := output/$(CC)
ifneq (,$(CPU))
BUILD_DIR := $(BUILD_DIR)_$(CPU)
endif
OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)
$(OBJS): $(BUILD_DIR)/%.o: %.c
	@$(MKDIR) -p -p $(shell dirname $@)
	$(CC) $(CFLAGS) -o $@ $<

$(LIB): $(OBJS)
	$(AR) $(AROPTS)

clean:
	@$(RM) -r output
