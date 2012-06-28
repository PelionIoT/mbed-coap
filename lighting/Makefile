PLATFORM= 
OS = MACOSX
TARGET	= lighting
OBJECTS = main.o lighting.o 
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

