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

TARGET = libnsdl.a
SRCS := \
	libNsdl/src/sn_grs.c \
	libNsdl/src/sn_nsdl.c \
	libCoap/src/sn_coap_protocol.c \
	libCoap/src/sn_coap_parser.c \
	libCoap/src/sn_coap_header_check.c \
	libCoap/src/sn_coap_builder.c \

CFLAGS += -IlibNsdl/src/Include/
CFLAGS += -IlibCoap/src/include/
SERVLIB_DIR := ../libService
CFLAGS += -I$(SERVLIB_DIR)/include

CFLAGS += -DREAL_EMBEDDED

ifneq ($(strip $(PLATFORM)),)
CC:=$(PLATFORM)gcc
AR:=$(PLATFORM)ar
endif

ifneq (,$(findstring iccarm,$(CC)))
	# Define flags for IAR-ARM
	CFLAGS += --cpu Cortex-M4 --diag_suppress Pa50
else
ifneq (,$(findstring ArmCC,$(CC)))
	# Define flags for ArmCC (Keil)
	CFLAGS += --cpu=Cortex-M4 --c99 --no_wrap_diagnostics
	TARGET := $(TARGET:%.a=%.lib)
else
	# Flags for common toolchain, usually GCC or CC
	CFLAGS += -Wall -std=gnu99 -pedantic-errors
endif
endif

OBJECTS := $(SRCS:.c=.o)

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJECTS)
ifneq (,$(findstring iccarm,$(CC)))
	iarchive.exe $^ --create -o $@
else
	$(AR) -rsc  $@ $(OBJECTS)
endif

clean:
	@$(RM) $(TARGET) $(OBJECTS)
