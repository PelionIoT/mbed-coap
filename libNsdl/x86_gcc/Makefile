TARGET = libNsdl.a
OBJECTS = ../src/sn_grs.o ../src/sn_nsdl.o
AR_OBJECTS = sn_grs.o sn_nsdl.o

SOURCE = ../src

CFLAGS	= -Wall -D_REENTRANT -D x86 -I ../src/Include -I ../../libCoap/src/include -I ../../../libService/include -I -g -std=c99
LDFLAGS = -L. -D_REENTRANT -lpthread

ifdef USE_TEMPLATE
CFLAGS += -DREG_TEMPLATE
endif

CC = $(PLATFORM)gcc

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(PLATFORM)ar rcs $(TARGET) $(OBJECTS)

clean:
	rm -f $(TARGET) $(OBJECTS)
