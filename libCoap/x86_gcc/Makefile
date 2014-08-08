TARGET = libCoap.a
OBJECTS = ../src/sn_coap_builder.o ../src/sn_coap_parser.o ../src/sn_coap_header_check.o ../src/sn_coap_protocol.o

SOURCE = ../src

CFLAGS	= -std=gnu99 -Wall -D_REENTRANT -I ../src/include -I ../src/x86_include -I ../../../libService/include -g -Dx86
LDFLAGS = -L. -D_REENTRANT -lpthread

CC = $(PLATFORM)gcc

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(PLATFORM)ar rcs $(TARGET) $(OBJECTS)

clean:
	rm -f $(TARGET) $(OBJECTS)
