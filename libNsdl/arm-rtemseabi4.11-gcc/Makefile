PLATFORM =
TARGET = libNsdl.a
OBJECTS = ../src/sn_grs.o ../src/sn_nsdl.o ../src/sn_linked_list.o 
AR_OBJECTS = sn_grs.o sn_nsdl.o sn_linked_list.o 

SOURCE = ../src

CFLAGS	= -Wall -D_REENTRANT -I ../src/Include -I ../../libCoap/src/include -I -g 
LDFLAGS = -L. -D_REENTRANT -lpthread

all: clean $(TARGET)

$(TARGET): $(OBJECTS)
	ar rcs $(TARGET) $(AR_OBJECTS)
	
.c.o:
	$(PLATFORM) /opt/rtems-4.11/bin/arm-rtemseabi4.11-gcc -g -c -O2 -Wall $(CFLAGS) $<

clean:
	rm -f $(TARGET) $(OBJECTS)
