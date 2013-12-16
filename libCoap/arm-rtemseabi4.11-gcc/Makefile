PLATFORM =
TARGET = libCoap.a
OBJECTS = ../src/sn_coap_builder.o ../src/sn_coap_parser.o ../src/sn_coap_header_check.o ../src/sn_coap_protocol.o ../src/sn_linked_list.o 
AR_OBJECTS = sn_coap_builder.o sn_coap_parser.o sn_coap_header_check.o sn_coap_protocol.o sn_linked_list.o 

SOURCE = ../src

CFLAGS	= -Wall -D_REENTRANT -I ../src/include -I -g -Dx86
LDFLAGS = -L. -D_REENTRANT -lpthread

all: clean $(TARGET)

$(TARGET): $(OBJECTS)
	ar rcs $(TARGET) $(AR_OBJECTS)
	
.c.o:
	$(PLATFORM) /opt/rtems-4.11/bin/arm-rtemseabi4.11-gcc -march=armv7-m -mthumb -g -c -O2 -Wall $(CFLAGS) $<

clean:
	rm -f $(TARGET) $(OBJECTS)
