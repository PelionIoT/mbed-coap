TARGET = libCoap.a
OBJECTS = ../src/sn_coap_builder.o ../src/sn_coap_parser.o ../src/sn_coap_header_check.o ../src/sn_coap_protocol.o

SOURCE = ../src

CFLAGS	= -std=gnu99 -Wall -D_REENTRANT -I ../src/include -I ../../../libService/libService -g
LDFLAGS = -L. -D_REENTRANT

CC = $(PLATFORM)gcc

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(PLATFORM)ar rcs $(TARGET) $(OBJECTS)

clean:
	rm -f $(TARGET) $(OBJECTS)
