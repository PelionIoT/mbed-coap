PLATFORM =
TARGET = libNsdl.a
OBJECTS = ../src/sn_grs.o ../src/sn_nsdl.o ../src/sn_linked_list.o 
AR_OBJECTS = sn_grs.o sn_nsdl.o sn_linked_list.o 

SOURCE = ../src

CFLAGS	= -Wall -D_REENTRANT -D x86 -I ../src/Include -I ../../libCoap/src/include -I -g -std=c99
LDFLAGS = -L. -D_REENTRANT -lpthread

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(PLATFORM)ar rcs $(TARGET) $(AR_OBJECTS)
	
.c.o:
	$(PLATFORM)gcc -g -c -O2 -Wall $(CFLAGS) $<

clean:
	rm -f $(TARGET) $(OBJECTS)
