PLATFORM =
TARGET = libNsdl.a
OBJECTS = ../src/sn_grs.o ../src/sn_nsdl.o
AR_OBJECTS = sn_grs.o sn_nsdl.o

SOURCE = ../src

CFLAGS	= -std=gnu99 -Wall -D_REENTRANT -I ../src/Include -I ../../libCoap/src/include -I ../../../libService/include -g
LDFLAGS = -L. -D_REENTRANT -lpthread

all: clean $(TARGET)

$(TARGET): $(OBJECTS)
	ar rcs $(TARGET) $(AR_OBJECTS)
	
.c.o:
	$(PLATFORM) /opt/rtems-4.11/bin/arm-rtemseabi4.11-gcc -march=armv7-m -mthumb -g -c -O2 -Wall $(CFLAGS) $<

clean:
	rm -f $(TARGET) $(OBJECTS)
