PLATFORM =
TARGET = libCoap.a
OBJECTS = ../src/sn_coap_builder_ietf_draft_12.o ../src/sn_coap_parser_ietf_draft_12.o ../src/sn_coap_header_validity_check_ietf_draft_12.o ../src/sn_coap_protocol_ietf_draft_12.o ../src/sn_linked_list.o 
AR_OBJECTS = sn_coap_builder_ietf_draft_12.o sn_coap_parser_ietf_draft_12.o sn_coap_header_validity_check_ietf_draft_12.o sn_coap_protocol_ietf_draft_12.o sn_linked_list.o 

SOURCE = ../src

CFLAGS	= -Wall -D_REENTRANT -I ../src/include -I -g -Dx86
LDFLAGS = -L. -D_REENTRANT -lpthread

all: clean $(TARGET)

$(TARGET): $(OBJECTS)
	ar rcs $(TARGET) $(AR_OBJECTS)
	
.c.o:
	$(PLATFORM) /opt/rtems-4.11/bin/arm-rtemseabi4.11-gcc -g -c -O2 -Wall $(CFLAGS) $<

clean:
	rm -f $(TARGET) $(OBJECTS)
