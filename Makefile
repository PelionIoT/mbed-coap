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

ifneq ($(strip $(PLATFORM)),)
CC:=$(PLATFORM)gcc
AR:=$(PLATFORM)ar
endif

ifneq (,$(findstring iccarm,$(CC)))
	# Define flags for IAR-ARM
	override CFLAGS += --cpu Cortex-M4 --diag_suppress Pa50
else
ifneq (,$(findstring ArmCC,$(CC)))
	# Define flags for ArmCC (Keil)
	override CFLAGS += --c99 --no_wrap_diagnostics
ifneq (,$(CPU))
	override CFLAGS += --cpu=$(CPU)
	LIB := $(LIB:%.a=%_$(CPU).lib)
else
	LIB := $(LIB:%.a=%.lib)
endif
else
	# Flags for common toolchain, usually GCC or CC
	override CFLAGS += -Wall -std=gnu99 -pedantic-errors
endif
endif

OBJECTS := $(SRCS:.c=.o)

.PHONY: all
all: $(LIB)

$(LIB): $(OBJECTS)
ifneq (,$(findstring iccarm,$(CC)))
	iarchive.exe $^ --create -o $@
else
	$(AR) -rsc  $@ $(OBJECTS)
endif

clean:
	@$(RM) $(TARGET) $(OBJECTS)
