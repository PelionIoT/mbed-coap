TARGET = libCoap.a
OBJECTS = ../src/sn_coap_builder.o ../src/sn_coap_parser.o ../src/sn_coap_header_check.o ../src/sn_coap_protocol.o ../src/sn_linked_list.o 

SOURCE = ../src

CFLAGS	= -Wall -D_REENTRANT -I ../src/include -I ../src/x86_include -g -Dx86 -std=c99
LDFLAGS = -L. -D_REENTRANT -lpthread

CC = $(PLATFORM)gcc

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(PLATFORM)ar rcs $(TARGET) $(OBJECTS)

clean:
	rm -f $(TARGET) $(OBJECTS)
