PLATFORM= 
OS = MACOSX
TARGET	= etsi_server
OBJECTS = main.o etsi_server.o 
#dtls_udp_client.o
CFLAGS	= -Wall -D_REENTRANT -D$(OS) -I ../libCoap -DHAVE_DEBUG
#-DHAVE_DTLS
LDFLAGS = -L../libCoap/ -D_REENTRANT -lpthread -lCoap
#-lssl -lcrypto

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	rm *.o
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

