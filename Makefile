#
# Makefile for combined NSDL library
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

override CFLAGS += -DVERSION='"$(VERSION)"'

override CFLAGS += -Isource/libNsdl/src/include/
SERVLIB_DIR := ../libService
override CFLAGS += -I$(SERVLIB_DIR)/libService
override CFLAGS += -Insdl-c/
override CFLAGS += -I../libcoap/libcoap/
override CFLAGS += -I../libcoap/source/include/

include ../libService/toolchain_rules.mk

$(eval $(call generate_rules,$(LIB),$(SRCS)))

.PHONY: release
release:
	7z a nsdl-c_$(VERSION).zip *.a *.lib include

.PHONY: deploy_to
deploy_to: all
	tar --transform 's,^,nsdl-c/,' --append -f $(TO) *.a nsdl-c
