PLATFORM =
TARGET = libCoap.a
OBJECTS = ../sn_coap_builder_ietf_draft_09.o ../sn_coap_parser_ietf_draft_09.o ../sn_coap_header_validity_check_ietf_draft_09.o ../sn_coap_protocol_ietf_draft_09.o ../sn_linked_list.o 
AR_OBJECTS = sn_coap_builder_ietf_draft_09.o sn_coap_parser_ietf_draft_09.o sn_coap_header_validity_check_ietf_draft_09.o sn_coap_protocol_ietf_draft_09.o sn_linked_list.o 

CFLAGS	= -Wall -D_REENTRANT -I. -g
LDFLAGS = -L. -D_REENTRANT -lpthread

all: clean $(TARGET)

$(TARGET): $(OBJECTS)
	ar rcs $(TARGET) $(AR_OBJECTS)
	
.c.o:
	$(PLATFORM)gcc -g -c -O2 -Wall $<

clean:
	rm -f $(TARGET) $(OBJECTS)
