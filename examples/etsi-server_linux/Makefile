PLATFORM= 
OS = LINUX
TARGET	= etsi_server
OBJECTS = main.o etsi_server.o 
CFLAGS	= -Wall -D_REENTRANT -D$(OS) -I ../libCoap -DHAVE_DEBUG
LDFLAGS = -L../libCoap/x86_gcc/ -D_REENTRANT -lpthread -lCoap

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	rm *.o
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

