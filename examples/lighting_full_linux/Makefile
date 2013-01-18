PLATFORM= 
OS = LINUX
TARGET	= lighting_full
OBJECTS = main.o lighting_full.o 
CFLAGS	= -Wall -D_REENTRANT -D$(OS) -I ../../libCoap/src/include -I ../../libNsdl/src/Include  -DHAVE_DEBUG
LDFLAGS = -L../../libCoap/x86_gcc/ -L../../libNsdl/x86_gcc/ -D_REENTRANT -lpthread -lNsdl -lCoap 

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	rm *.o
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

