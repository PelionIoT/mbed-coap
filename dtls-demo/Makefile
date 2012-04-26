PLATFORM= 
OS = MACOSX
TARGET	= coap_server
OBJECTS = main.o coap_server.o dtls_udp_client.o
CFLAGS	= -Wall -D_REENTRANT -D$(OS) -I ../libCoap -DHAVE_DEBUG -DHAVE_DTLS
LDFLAGS = -L../libCoap/ -D_REENTRANT -lpthread -lssl -lcrypto -lCoap

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	rm *.o
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

