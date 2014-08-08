PLATFORM =
TARGET = libNsdl.a
OBJECTS = ../src/sn_grs.o ../src/sn_nsdl.o
AR_OBJECTS = sn_grs.o sn_nsdl.o

SOURCE = ../src

CFLAGS	= -Wall -D_REENTRANT -I ../src/Include -I ../../libCoap/src/include -I ../../../libService/include -g
LDFLAGS = -L. -D_REENTRANT -lpthread

all: clean $(TARGET)

$(TARGET): $(OBJECTS)
	ar rcs $(TARGET) $(AR_OBJECTS)
	
.c.o:
	$(PLATFORM) /opt/SOM9260-OE_SDK-1.3.1.eabi/gcc-4.1.1-arm-linux-gnueabi/bin/arm-linux-gnueabi-gcc -g -c -O2 -Wall $(CFLAGS) $<

clean:
	rm -f $(TARGET) $(OBJECTS)
